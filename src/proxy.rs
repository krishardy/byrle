//! The reverse proxy: forward every request, normalise the packuments on the way back.
//!
//! Lives in the library rather than in `main.rs` so it can be tested against a fake
//! registry. `main.rs` reads the environment and serves [`Proxy::router`].
//!
//! # Bodies
//!
//! Tarballs stream straight through. Packuments are buffered, decoded into a scratch
//! copy and normalised, and then the **original encoded bytes** are forwarded unchanged.
//! Nothing the client receives is re-encoded.
//!
//! For a packument request the proxy replaces the client's `Accept-Encoding` with gzip
//! or identity, whichever the client accepts ([`crate::http::encoding_to_request`]).
//! registry.npmjs.org serves brotli when it is offered and npm 9 offers `gzip,deflate`,
//! so narrowing the request means one decompressor here instead of three, and the client
//! still receives an encoding it asked for.
//!
//! Normalising happens before the response is forwarded, not in a spawned task. Stage 2
//! has to decide before forwarding, so the shape does not change, and a background task
//! would make the smoke assertions racy. Measured cost, logged as `parse_ms`: 2 ms for
//! lodash (117 versions), 7 ms for @babel/core (230), 252 ms for the full typescript
//! packument (3,822 versions, 15.7 MB decoded).

use crate::http::{
    DecodeError, RequestedEncoding, decode_for_parsing, encoding_to_request, is_hop_by_hop,
};
use crate::identity::PackageKey;
use crate::npm::{self, NormalizeError, NormalizedPackument, RequestTarget};
use crate::record::PackumentDetail;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use std::pin::Pin;
use std::time::Instant;
use tracing::{error, info, warn};

/// Default ceiling on a packument body, applied both to the bytes buffered and to the
/// bytes decompression is allowed to produce.
///
/// The largest packument measured is typescript: 8.7 MB as the abbreviated document,
/// 15.7 MB as the full one, 2.0 MB gzipped. This is roughly 2x headroom on that. Over
/// the limit the response is forwarded without being normalised, because an install must
/// not fail on account of what the proxy could not inspect.
pub const DEFAULT_MAX_PACKUMENT_BYTES: usize = 32 * 1024 * 1024;

/// What reading a packument body produced.
#[derive(Debug)]
pub enum PackumentOutcome {
    Normalized(Box<NormalizedPackument>),
    /// The body could not be decoded: an encoding we do not handle, a corrupt stream, or
    /// output past the limit.
    Undecodable(DecodeError),
    /// The body decoded but is not a shape we model. Our gap, not an upstream outage.
    Unreadable(NormalizeError),
}

/// Decode a packument body and normalise it.
///
/// Separate from the handler because it is the part worth testing directly: the handler
/// around it only decides what to forward.
pub fn inspect_packument(
    body: &[u8],
    content_encoding: Option<&str>,
    detail: PackumentDetail,
    limit: usize,
) -> PackumentOutcome {
    let decoded = match decode_for_parsing(body, content_encoding, limit) {
        Ok(d) => d,
        Err(e) => return PackumentOutcome::Undecodable(e),
    };
    match npm::normalize_packument(&decoded, detail) {
        Ok(p) => PackumentOutcome::Normalized(Box::new(p)),
        Err(e) => PackumentOutcome::Unreadable(e),
    }
}

#[derive(Clone)]
pub struct Proxy {
    client: reqwest::Client,
    /// Upstream registry base, no trailing slash.
    upstream: String,
    /// THROWAWAY. One hardcoded package, to prove interception happens before anything
    /// is fetched. Stage 2 replaces this with the policy engine; there is deliberately
    /// no config file behind it, so it cannot quietly become a feature.
    blocked: Option<PackageKey>,
    max_packument_bytes: usize,
}

impl Proxy {
    pub fn new(client: reqwest::Client, upstream: impl Into<String>) -> Self {
        Self {
            client,
            upstream: upstream.into().trim_end_matches('/').to_owned(),
            blocked: None,
            max_packument_bytes: DEFAULT_MAX_PACKUMENT_BYTES,
        }
    }

    pub fn with_blocked(mut self, blocked: Option<PackageKey>) -> Self {
        self.blocked = blocked;
        self
    }

    pub fn with_max_packument_bytes(mut self, limit: usize) -> Self {
        self.max_packument_bytes = limit;
        self
    }

    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/{*path}", axum::routing::any(handle))
            .route("/", axum::routing::any(handle))
            .with_state(self)
    }
}

type ByteStream = Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send>>;

/// The outcome of reading a response body up to a limit.
enum Buffered {
    /// The whole body, within the limit.
    Complete(Bytes),
    /// The body passed the limit. Carries what was read plus the rest of the stream, so
    /// it can still be forwarded; it just will not be parsed.
    Oversized { prefix: Bytes, rest: ByteStream },
    /// The body could not be read to completion.
    Failed(reqwest::Error),
}

async fn buffer_to_limit(mut stream: ByteStream, limit: usize) -> Buffered {
    let mut buf = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => {
                buf.extend_from_slice(&chunk);
                if buf.len() > limit {
                    return Buffered::Oversized {
                        prefix: buf.freeze(),
                        rest: stream,
                    };
                }
            }
            Err(e) => return Buffered::Failed(e),
        }
    }
    Buffered::Complete(buf.freeze())
}

async fn handle(State(proxy): State<Proxy>, req: Request) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();

    // The client's own user-agent tells us which package manager is talking, which is
    // what the status-code table in §5 will key off later.
    let client_ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    let target = npm::classify_path(&path_and_query);

    // The block is evaluated on the way in, so it fires on the packument request and the
    // tarball is never fetched. 403 is correct here and only here: it means policy denied
    // you. Not-ready states use 502/503/429 (§5), never a 4xx.
    let requested_key = match &target {
        RequestTarget::Packument(key) | RequestTarget::Tarball { key, .. } => Some(key),
        RequestTarget::Other => None,
    };
    if let (Some(blocked), Some(key)) = (&proxy.blocked, requested_key)
        && blocked == key
    {
        info!(
            %method,
            path = %path_and_query,
            status = 403u16,
            purl = %key,
            client = %client_ua,
            "blocked"
        );
        return (
            StatusCode::FORBIDDEN,
            format!("waharoa: {key} is blocked by policy\n"),
        )
            .into_response();
    }

    let client_accept_encoding = req
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let chosen_encoding = encoding_to_request(client_accept_encoding.as_deref());

    // A packument body is only read on a GET, and only when the client's encodings allow
    // asking for one this can decode.
    let read_packument = method == Method::GET
        && matches!(target, RequestTarget::Packument(_))
        && chosen_encoding != RequestedEncoding::Unreadable;

    let url = format!("{}{}", proxy.upstream, path_and_query);
    let mut outbound = proxy.client.request(method.clone(), &url);
    for (name, value) in req.headers() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST {
            continue;
        }
        if read_packument && name == header::ACCEPT_ENCODING {
            continue;
        }
        outbound = outbound.header(name, value);
    }
    if read_packument && let Some(value) = chosen_encoding.header_value() {
        outbound = outbound.header(header::ACCEPT_ENCODING, value);
    }

    let upstream_response = match outbound.send().await {
        Ok(r) => r,
        Err(e) => {
            // §5: upstream unreachable or malformed is 502. Never a 4xx, which from a
            // registry proxy reads as "policy denied you".
            error!(%method, path = %path_and_query, error = %e, "upstream request failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("waharoa: upstream request failed: {e}\n"),
            )
                .into_response();
        }
    };

    let status = upstream_response.status();
    let upstream_len = upstream_response.content_length();

    let mut headers = HeaderMap::new();
    for (name, value) in upstream_response.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    let content_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let detail = npm::detail_from_content_type(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    );

    // A warm npm cache sends If-None-Match, and 304 carries no body. Saying so is the
    // difference between "this package was not seen" and "this package was served from
    // the client's own cache".
    if status == reqwest::StatusCode::NOT_MODIFIED
        && let RequestTarget::Packument(key) = &target
    {
        info!(
            path = %path_and_query,
            purl = %key,
            etag = headers.get(header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("-"),
            "packument not modified, nothing to normalize"
        );
    }

    let forward_status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let log_proxied = |bytes: u64| {
        info!(
            %method,
            path = %path_and_query,
            status = status.as_u16(),
            bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            client = %client_ua,
            "proxied"
        );
    };

    // Tarball requests are where the resolved graph becomes visible: the packument lists
    // every version ever published, and this names the one being installed.
    if let RequestTarget::Tarball {
        key,
        claimed_version,
    } = &target
        && status.is_success()
    {
        match key.at_version(claimed_version) {
            Ok(reference) => info!(
                path = %path_and_query,
                claimed_purl = %reference,
                "artifact requested"
            ),
            Err(e) => {
                warn!(path = %path_and_query, error = %e, "tarball path has no usable version")
            }
        }
    }

    let body_stream: ByteStream = Box::pin(upstream_response.bytes_stream());

    let Some(detail) = detail.filter(|_| read_packument && status.is_success()) else {
        log_proxied(upstream_len.unwrap_or(0));
        return (forward_status, headers, Body::from_stream(body_stream)).into_response();
    };

    let body = match buffer_to_limit(body_stream, proxy.max_packument_bytes).await {
        Buffered::Complete(body) => body,
        Buffered::Oversized { prefix, rest } => {
            warn!(
                path = %path_and_query,
                limit = proxy.max_packument_bytes,
                "packument exceeds the size limit; forwarding without normalizing"
            );
            log_proxied(upstream_len.unwrap_or(0));
            let spliced = stream::iter(std::iter::once(Ok(prefix))).chain(rest);
            return (forward_status, headers, Body::from_stream(spliced)).into_response();
        }
        Buffered::Failed(e) => {
            error!(%method, path = %path_and_query, error = %e, "upstream body failed mid-stream");
            return (
                StatusCode::BAD_GATEWAY,
                format!("waharoa: upstream body failed: {e}\n"),
            )
                .into_response();
        }
    };

    let parse_started = Instant::now();
    match inspect_packument(
        &body,
        content_encoding.as_deref(),
        detail,
        proxy.max_packument_bytes,
    ) {
        PackumentOutcome::Normalized(p) => info!(
            path = %path_and_query,
            purl = %p.key,
            detail = ?detail,
            versions = p.records.len(),
            skipped = p.skipped.len(),
            with_install_scripts = p.records.iter().filter(|r| r.has_install_scripts).count(),
            latest = %p.latest.as_deref().unwrap_or("-"),
            encoded_bytes = body.len(),
            parse_ms = parse_started.elapsed().as_millis() as u64,
            "packument normalized"
        ),
        PackumentOutcome::Unreadable(e) => {
            warn!(path = %path_and_query, error = %e, "packument did not normalize")
        }
        PackumentOutcome::Undecodable(e) => {
            warn!(path = %path_and_query, error = %e, "packument body could not be decoded")
        }
    }

    log_proxied(body.len() as u64);
    (forward_status, headers, Body::from(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;
    use axum::routing::{any, get};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    fn fixture(name: &str) -> Vec<u8> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
        std::fs::read(format!("{dir}{name}")).expect("fixture is missing")
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
    }

    /// Everything a fake upstream saw, so a test can assert on the request the proxy
    /// made rather than only on the response it returned.
    #[derive(Default)]
    struct Seen {
        paths: Vec<String>,
        accept_encoding: Vec<Option<String>>,
        headers: Vec<HeaderMap>,
    }

    type Recorder = Arc<Mutex<Seen>>;

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    /// A fake registry that records what it was asked and answers with one canned
    /// response for every path.
    async fn upstream_serving(
        status: StatusCode,
        content_type: &'static str,
        content_encoding: Option<&'static str>,
        body: Vec<u8>,
    ) -> (String, Recorder) {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().fallback(any(move |req: Request| {
            let seen = recorder.clone();
            let body = body.clone();
            async move {
                {
                    let mut s = seen.lock().unwrap();
                    s.paths.push(req.uri().to_string());
                    s.accept_encoding.push(
                        req.headers()
                            .get(header::ACCEPT_ENCODING)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                    );
                    s.headers.push(req.headers().clone());
                }
                let mut response = Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, content_type);
                if let Some(encoding) = content_encoding {
                    response = response.header(header::CONTENT_ENCODING, encoding);
                }
                response.body(Body::from(body)).unwrap()
            }
        }));
        (serve(router).await, seen)
    }

    async fn proxy_serving(
        status: StatusCode,
        content_type: &'static str,
        content_encoding: Option<&'static str>,
        body: Vec<u8>,
    ) -> (String, Recorder) {
        let (upstream, seen) = upstream_serving(status, content_type, content_encoding, body).await;
        let base = serve(Proxy::new(reqwest::Client::new(), upstream).router()).await;
        (base, seen)
    }

    // -----------------------------------------------------------------------
    // inspect_packument, the part the handler only decides what to do with
    // -----------------------------------------------------------------------

    #[test]
    fn inspect_normalises_identity_and_gzip_bodies_alike() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        for (encoding, bytes) in [(None, body.clone()), (Some("gzip"), gzip(&body))] {
            let outcome = inspect_packument(
                &bytes,
                encoding,
                PackumentDetail::Abbreviated,
                DEFAULT_MAX_PACKUMENT_BYTES,
            );
            let PackumentOutcome::Normalized(p) = outcome else {
                panic!("{encoding:?} should normalise, got {outcome:?}");
            };
            assert_eq!(p.key, key("lodash"));
            assert_eq!(p.records.len(), 1);
        }
    }

    /// The three failure modes stay apart: a body we cannot decode, a body we cannot
    /// model, and a body past the limit are different problems with different fixes.
    #[test]
    fn inspect_distinguishes_its_failure_modes() {
        assert!(matches!(
            inspect_packument(b"{}", Some("br"), PackumentDetail::Full, 1024),
            PackumentOutcome::Undecodable(DecodeError::UnsupportedEncoding(_))
        ));
        assert!(matches!(
            inspect_packument(b"<html>", None, PackumentDetail::Full, 1024),
            PackumentOutcome::Unreadable(_)
        ));
        assert!(matches!(
            inspect_packument(
                &gzip(&vec![b'A'; 5000]),
                Some("gzip"),
                PackumentDetail::Full,
                100
            ),
            PackumentOutcome::Undecodable(DecodeError::TooLarge(100))
        ));
    }

    // -----------------------------------------------------------------------
    // Forwarding
    // -----------------------------------------------------------------------

    /// The client gets the upstream bytes unchanged. A packument is buffered and read on
    /// the way past, and reading it must not alter it.
    #[tokio::test]
    async fn a_packument_body_is_forwarded_byte_for_byte() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let encoded = gzip(&body);
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            Some("gzip"),
            encoded.clone(),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "gzip,deflate")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip",
            "the body is still gzipped, so Content-Encoding must still say so"
        );
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            encoded.as_slice(),
            "forwarded bytes differ from what upstream sent"
        );
    }

    /// npm 9 offers `gzip,deflate` and registry.npmjs.org answers brotli whenever br is
    /// offered. The proxy narrows the outbound request so only gzip has to be decoded.
    #[tokio::test]
    async fn accept_encoding_is_narrowed_on_packument_requests() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let client = reqwest::Client::new();

        client
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
            .send()
            .await
            .unwrap();
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("gzip"),
            "br was on offer and would not be decodable here"
        );

        client
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "br")
            .send()
            .await
            .unwrap();
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("identity"),
            "the client does not accept gzip, so ask for something it does"
        );
    }

    /// A client that accepts neither gzip nor identity keeps its own header, and its
    /// body is left alone. Rewriting it to an encoding the client refused would break
    /// the install for the sake of our inspection.
    #[tokio::test]
    async fn a_client_refusing_both_encodings_is_passed_through_untouched() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;

        reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "br, identity;q=0")
            .send()
            .await
            .unwrap();
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("br, identity;q=0"),
            "the client's own header has to survive"
        );
    }

    /// Tarballs are not packuments: no rewriting, no buffering.
    #[tokio::test]
    async fn tarball_requests_keep_the_clients_encoding() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/octet-stream",
            None,
            b"tarball bytes".to_vec(),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash/-/lodash-4.17.21.tgz"))
            .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"tarball bytes");
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("gzip, deflate, br")
        );
    }

    /// A body past the limit is forwarded whole rather than truncated or refused. The
    /// prefix already read has to be spliced back in front of the rest of the stream.
    #[tokio::test]
    async fn an_oversized_packument_is_forwarded_intact_without_being_parsed() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body.clone(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_max_packument_bytes(16)
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            body.as_slice(),
            "the whole body has to arrive, including the prefix already buffered"
        );
    }

    /// Hop-by-hop headers describe one connection and must not cross to the next.
    #[tokio::test]
    async fn hop_by_hop_headers_do_not_cross_the_proxy() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/octet-stream",
            None,
            b"x".to_vec(),
        )
        .await;

        reqwest::Client::new()
            .get(format!("{base}/lodash/-/lodash-4.17.21.tgz"))
            .header("te", "trailers")
            .header("proxy-authorization", "Basic c2VjcmV0")
            .send()
            .await
            .unwrap();

        let seen = seen.lock().unwrap();
        let forwarded = seen.headers.last().unwrap();
        assert!(forwarded.get("te").is_none());
        assert!(
            forwarded.get("proxy-authorization").is_none(),
            "a proxy credential must not be handed to the upstream"
        );
        assert_ne!(
            forwarded.get(header::HOST).map(|v| v.to_str().unwrap()),
            Some(base.trim_start_matches("http://")),
            "Host has to name the upstream, not the proxy"
        );
    }

    // -----------------------------------------------------------------------
    // Status handling
    // -----------------------------------------------------------------------

    /// The block fires before anything is fetched, so the upstream never sees the
    /// request at all.
    #[tokio::test]
    async fn a_blocked_package_is_refused_before_the_upstream_is_asked() {
        let (upstream, seen) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_blocked(Some(key("lodash")))
                .router(),
        )
        .await;

        for path in ["/lodash", "/lodash/-/lodash-4.17.21.tgz"] {
            let response = reqwest::get(format!("{base}{path}")).await.unwrap();
            assert_eq!(response.status(), 403, "{path}");
            assert!(response.text().await.unwrap().contains("pkg:npm/lodash"));
        }
        assert!(
            seen.lock().unwrap().paths.is_empty(),
            "the upstream was contacted for a package policy refused"
        );
    }

    /// The block is on identity, not on the spelling of the path. `@babel%2fcore` and
    /// `@babel/core` are the same package.
    #[tokio::test]
    async fn the_block_matches_both_spellings_of_a_scoped_name() {
        let (upstream, _) =
            upstream_serving(StatusCode::OK, "application/json", None, b"{}".to_vec()).await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_blocked(Some(key("@babel/core")))
                .router(),
        )
        .await;

        for path in [
            "/@babel%2fcore",
            "/@babel/core",
            "/@babel/core/-/core-7.0.0.tgz",
        ] {
            assert_eq!(
                reqwest::get(format!("{base}{path}"))
                    .await
                    .unwrap()
                    .status(),
                403,
                "{path}"
            );
        }
    }

    /// An unreachable upstream is 502. §5 forbids any 4xx for a not-ready state, because
    /// a 4xx from a registry proxy reads as "policy denied you".
    #[tokio::test]
    async fn an_unreachable_upstream_is_502() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let base =
            serve(Proxy::new(reqwest::Client::new(), format!("http://{addr}")).router()).await;
        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 502);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("upstream request failed")
        );
    }

    /// A 404 from the registry is the registry's answer and passes through as itself.
    #[tokio::test]
    async fn upstream_statuses_pass_through_unchanged() {
        for status in [StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE] {
            let (base, _) = proxy_serving(status, "application/json", None, b"{}".to_vec()).await;
            assert_eq!(
                reqwest::get(format!("{base}/lodash"))
                    .await
                    .unwrap()
                    .status(),
                status
            );
        }
    }

    /// A warm npm cache sends If-None-Match and gets 304 with no body. There is nothing
    /// to normalise, and the response still has to reach the client.
    #[tokio::test]
    async fn a_304_passes_through_with_no_body_to_read() {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().fallback(get(move |req: Request| {
            let seen = recorder.clone();
            async move {
                seen.lock().unwrap().headers.push(req.headers().clone());
                Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, "W/\"abc123\"")
                    .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                    .body(Body::empty())
                    .unwrap()
            }
        }));
        let upstream = serve(router).await;
        let base = serve(Proxy::new(reqwest::Client::new(), upstream).router()).await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, "W/\"abc123\"")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 304);
        assert_eq!(
            seen.lock()
                .unwrap()
                .headers
                .last()
                .unwrap()
                .get(header::IF_NONE_MATCH)
                .map(|v| v.to_str().unwrap()),
            Some("W/\"abc123\""),
            "the conditional request has to reach the registry, or it can never 304"
        );
    }

    /// A registry endpoint is not a package document and is forwarded without being
    /// read, whatever its content type.
    #[tokio::test]
    async fn registry_endpoints_are_not_treated_as_packuments() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/json",
            None,
            b"{\"objects\":[]}".to_vec(),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/-/v1/search?text=lodash"))
            .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("gzip, deflate, br"),
            "only packument requests get their encoding narrowed"
        );
    }

    /// A non-GET is forwarded without its body being read. Publishing is not something
    /// Stage 1 inspects.
    #[tokio::test]
    async fn non_get_methods_are_forwarded_without_inspection() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/json",
            None,
            b"{\"ok\":true}".to_vec(),
        )
        .await;

        let response = reqwest::Client::new()
            .put(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "gzip, deflate, br")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            seen.lock()
                .unwrap()
                .accept_encoding
                .last()
                .unwrap()
                .as_deref(),
            Some("gzip, deflate, br")
        );
    }

    /// A 200 carrying something unreadable does not become a 502 and does not stop the
    /// install: it is our gap, not an upstream outage.
    #[tokio::test]
    async fn an_unreadable_packument_still_reaches_the_client() {
        let junk = b"<html>maintenance</html>".to_vec();
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            junk.clone(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().await.unwrap().as_ref(), junk.as_slice());
    }

    /// Likewise a body in an encoding this cannot decode.
    #[tokio::test]
    async fn an_undecodable_packument_still_reaches_the_client() {
        let body = b"\x1b[brotli bytes]".to_vec();
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            Some("br"),
            body.clone(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_slice());
    }

    #[test]
    fn the_upstream_base_drops_a_trailing_slash() {
        let proxy = Proxy::new(reqwest::Client::new(), "https://registry.npmjs.org/");
        assert_eq!(proxy.upstream(), "https://registry.npmjs.org");
    }
}
