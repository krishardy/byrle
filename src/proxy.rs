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
use crate::integrity::{Sri, Verifier};
use crate::npm::{self, NormalizeError, NormalizedPackument, RequestTarget};
use crate::record::PackumentDetail;
use crate::store::{DEFAULT_MAX_RECORDS, Lookup, RecordStore};
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
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
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
    /// Records from packuments already seen, so a tarball request can find the digest
    /// its packument published. Bounded; see [`crate::store`].
    store: Arc<Mutex<RecordStore>>,
    /// Used to fetch a packument the client never asked for. See [`fill_store`].
    registry: npm::Client,
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
        let upstream = upstream.into().trim_end_matches('/').to_owned();
        Self {
            registry: npm::Client::new(client.clone(), upstream.clone()),
            client,
            store: Arc::new(Mutex::new(RecordStore::new(DEFAULT_MAX_RECORDS))),
            upstream,
            blocked: None,
            max_packument_bytes: DEFAULT_MAX_PACKUMENT_BYTES,
        }
    }

    pub fn with_max_records(self, max_records: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(RecordStore::new(max_records))),
            ..self
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

/// Any error a forwarded body can end with.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A body being forwarded while its digest is checked, with the last chunk held back.
///
/// The digest cannot be compared until the final byte has gone past, and the status and
/// headers left long before that. Forwarding every chunk as it arrives would mean the
/// client already holds a complete, correct-length body by the time the check fails.
/// Worse, it would not fail: hyper stops polling a body once `Content-Length` is
/// satisfied, so the end of the stream is never reached and the comparison never runs.
/// Measured on a real tarball fetch, which forwarded all 318,961 bytes and verified
/// nothing.
///
/// So one chunk is always held back. Each chunk is hashed on arrival and released only
/// when the next one arrives; the last is released only after the digest matches. On a
/// mismatch the body ends in an error instead, the response is short of its declared
/// `Content-Length`, and the client sees a failed download. Holding one chunk also keeps
/// hyper polling, because the declared length is not yet satisfied.
///
/// Extra memory is one chunk, not the artifact. Plan §5: there is no mid-stream branch
/// into buffering, because the digest is known before the fetch.
struct VerifyingStream {
    inner: ByteStream,
    /// Taken when the stream ends, which is the only place it can be used.
    verifier: Option<Verifier>,
    /// The most recent chunk, released when the next one arrives or the digest matches.
    held: Option<Bytes>,
    finished: bool,
    bytes: u64,
    path: String,
    purl: String,
}

impl VerifyingStream {
    fn new(inner: ByteStream, sri: &Sri, path: String, purl: String) -> Self {
        Self {
            inner,
            verifier: Some(sri.verifier()),
            held: None,
            finished: false,
            bytes: 0,
            path,
            purl,
        }
    }

    /// Compare, and decide what the body ends with.
    fn finish(&mut self) -> Poll<Option<Result<Bytes, BoxError>>> {
        self.finished = true;
        let Some(verifier) = self.verifier.take() else {
            return Poll::Ready(None);
        };
        match verifier.finish(self.bytes) {
            Ok(()) => {
                info!(
                    path = %self.path,
                    purl = %self.purl,
                    bytes = self.bytes,
                    "artifact digest verified"
                );
                Poll::Ready(self.held.take().map(Ok))
            }
            // A mismatch is a finding, not a cache error: the registry served bytes its
            // own packument does not describe. The held chunk is dropped, so the client
            // never receives a complete body that failed the check.
            Err(mismatch) => {
                error!(
                    path = %self.path,
                    purl = %self.purl,
                    expected = %mismatch.expected,
                    actual = %mismatch.actual,
                    bytes = mismatch.bytes,
                    "ARTIFACT DIGEST MISMATCH"
                );
                self.held = None;
                Poll::Ready(Some(Err(Box::new(mismatch) as BoxError)))
            }
        }
    }
}

impl futures_util::Stream for VerifyingStream {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.finished {
                return Poll::Ready(None);
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(verifier) = this.verifier.as_mut() {
                        verifier.update(&chunk);
                    }
                    this.bytes += chunk.len() as u64;
                    // An empty chunk carries nothing and must not count as "the next
                    // chunk arrived": reqwest ends a tarball stream with one, and letting
                    // it displace the held chunk releases the whole body before the
                    // digest is compared. Measured on a real fetch, where the final
                    // chunk was 0 bytes and all 318,961 bytes reached the client
                    // unverified.
                    if chunk.is_empty() {
                        continue;
                    }
                    // Release the previous chunk, keep this one.
                    if let Some(previous) = this.held.replace(chunk) {
                        return Poll::Ready(Some(Ok(previous)));
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    this.finished = true;
                    return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                }
                Poll::Ready(None) => return this.finish(),
            }
        }
    }
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

/// Find the record for an artifact, fetching its packument if the client never asked for
/// one.
///
/// `npm ci` is the reason this exists. It reads `resolved` and `integrity` out of
/// `package-lock.json` and requests **no packuments at all**: measured through the proxy,
/// 69 tarballs and zero packument requests, so every digest was unknown and nothing was
/// verified. A warm npm cache, a restarted proxy, and an evicted entry all produce the
/// same gap. Fetching the packument here closes all four.
///
/// It happens once per package per proxy lifetime, on the request path rather than in the
/// background, because the digest has to be in hand before the artifact is forwarded.
async fn lookup_or_fetch(proxy: &Proxy, key: &PackageKey, version: &str, path: &str) -> Lookup {
    // The guard is dropped before the await: nothing holds the lock across a fetch.
    let first = proxy
        .store
        .lock()
        .expect("record store lock")
        .lookup(key, version);
    if first != Lookup::Unknown {
        return first;
    }

    let started = Instant::now();
    match proxy
        .registry
        .packument(key, PackumentDetail::Abbreviated)
        .await
    {
        Ok(Ok(packument)) => {
            let versions = packument.records.len();
            proxy
                .store
                .lock()
                .expect("record store lock")
                .insert(packument);
            info!(
                path = %path,
                purl = %key,
                versions,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "fetched packument on our own behalf, which the client never requested"
            );
        }
        // Not fatal. The artifact is forwarded unverified and said to be unverified,
        // which is Stage 1 behaviour; Stage 2 has to decide whether that is allowed.
        Ok(Err(e)) => {
            warn!(path = %path, purl = %key, error = %e, "packument fetched but did not normalize")
        }
        Err(e) => warn!(path = %path, purl = %key, error = %e, "could not fetch packument"),
    }

    proxy
        .store
        .lock()
        .expect("record store lock")
        .lookup(key, version)
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
    // every version ever published, and this names the one being installed. It is also
    // where the digest has to already be known, because it decides whether this artifact
    // has been analysed before anything is fetched (plan §5).
    let mut expected_digest: Option<Sri> = None;
    let mut artifact_purl = String::new();
    if let RequestTarget::Tarball {
        key,
        claimed_version,
    } = &target
        && status.is_success()
    {
        let purl = key
            .at_version(claimed_version)
            .map(|r| r.to_string())
            .unwrap_or_else(|_| format!("{key}@{claimed_version}"));
        artifact_purl = purl.clone();
        let lookup = lookup_or_fetch(&proxy, key, claimed_version, &path_and_query).await;
        match lookup {
            Lookup::Found(record) => {
                info!(
                    path = %path_and_query,
                    claimed_purl = %purl,
                    integrity = record.artifact.integrity.as_deref().unwrap_or("-"),
                    has_install_scripts = record.has_install_scripts,
                    "artifact requested, digest known"
                );
                match record.artifact.integrity.as_deref().map(Sri::parse) {
                    Some(Ok(sri)) => expected_digest = Some(sri),
                    Some(Err(e)) => warn!(
                        path = %path_and_query,
                        claimed_purl = %purl,
                        error = %e,
                        "packument integrity string is unusable; not verifying"
                    ),
                    // Two versions in 24,852 offer only SHA-1, which is
                    // collision-broken and not verified here.
                    None => warn!(
                        path = %path_and_query,
                        claimed_purl = %purl,
                        "packument publishes no strong digest; not verifying"
                    ),
                }
            }
            // The packument was read and does not name this version. A tarball filename
            // that spells the version differently lands here: `express@3.0.0-rc1` is
            // served at `express-3.0.0rc1.tgz`.
            Lookup::NoSuchVersion => warn!(
                path = %path_and_query,
                claimed_purl = %purl,
                "artifact requested, but its packument does not name this version"
            ),
            // Nothing was observed for this package. A warm npm cache produces this: the
            // client's conditional request is answered 304 with no body.
            Lookup::Unknown => warn!(
                path = %path_and_query,
                claimed_purl = %purl,
                "artifact requested, no packument seen for it"
            ),
        }
    }

    let body_stream: ByteStream = Box::pin(upstream_response.bytes_stream());

    let Some(detail) = detail.filter(|_| read_packument && status.is_success()) else {
        log_proxied(upstream_len.unwrap_or(0));
        let Some(sri) = expected_digest else {
            return (forward_status, headers, Body::from_stream(body_stream)).into_response();
        };
        let verified =
            VerifyingStream::new(body_stream, &sri, path_and_query.clone(), artifact_purl);
        return (forward_status, headers, Body::from_stream(verified)).into_response();
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
        PackumentOutcome::Normalized(p) => {
            // Artifacts on an origin the proxy does not front are fetched directly by
            // the client, so nothing about them is observed: not the digest check below,
            // not the policy engine later. The packument is the only place this is
            // visible, because by the time the artifact is fetched the request has
            // already gone elsewhere.
            let bypassing = p.bypassing_origins(&proxy.upstream);
            if !bypassing.is_empty() {
                let versions: usize = bypassing.values().sum();
                warn!(
                    path = %path_and_query,
                    purl = %p.key,
                    versions,
                    origins = ?bypassing.keys().collect::<Vec<_>>(),
                    "ARTIFACTS PUBLISHED OFF THIS REGISTRY, which the client fetches directly"
                );
            }
            let (held_packages, held_records) = {
                let mut store = proxy.store.lock().expect("record store lock");
                store.insert((*p).clone());
                (store.len(), store.records())
            };
            info!(
            path = %path_and_query,
            purl = %p.key,
            detail = ?detail,
            versions = p.records.len(),
            skipped = p.skipped.len(),
            // Every version in the document, not the one being installed. Stage 2
            // needs the resolved version's answer, which needs the tarball request
            // correlated against these records.
            versions_with_install_scripts = p.records.iter().filter(|r| r.has_install_scripts).count(),
            latest = %p.latest.as_deref().unwrap_or("-"),
            encoded_bytes = body.len(),
            parse_ms = parse_started.elapsed().as_millis() as u64,
            offsite_versions = bypassing.values().sum::<usize>(),
            held_packages,
            held_records,
            "packument normalized"
            );
        }
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
    ///
    /// The assertion picks the tarball request out of what the upstream saw rather than
    /// taking the last one, because the proxy also fetches a packument of its own here.
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

        let seen = seen.lock().unwrap();
        let tarball = seen
            .paths
            .iter()
            .position(|p| p.ends_with(".tgz"))
            .expect("the upstream saw the tarball request");
        assert_eq!(
            seen.accept_encoding[tarball].as_deref(),
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

    // -----------------------------------------------------------------------
    // Digest verification
    // -----------------------------------------------------------------------

    /// Serve a packument and a tarball, so a test can walk the real sequence: the
    /// packument publishes the digest, the tarball request finds it, the body is checked
    /// on the way past.
    async fn registry_with(integrity: &str, tarball: Vec<u8>) -> String {
        let packument = format!(
            r#"{{"name":"widget","dist-tags":{{"latest":"1.0.0"}},"versions":{{
                "1.0.0":{{"version":"1.0.0","dist":{{
                    "tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
                    "integrity":"{integrity}"}}}}}}}}"#
        );
        let router = Router::new()
            .route(
                "/widget",
                get(move || {
                    let packument = packument.clone();
                    async move {
                        (
                            [(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")],
                            packument,
                        )
                    }
                }),
            )
            .route(
                "/widget/-/widget-1.0.0.tgz",
                get(move || {
                    let tarball = tarball.clone();
                    async move {
                        (
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            tarball,
                        )
                    }
                }),
            );
        serve(Proxy::new(reqwest::Client::new(), serve(router).await).router()).await
    }

    fn sri_of(data: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha512};
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data))
        )
    }

    /// The whole point: the digest comes from a packument seen earlier, and the tarball
    /// is checked against it without being buffered.
    #[tokio::test]
    async fn a_tarball_matching_its_packument_digest_is_forwarded_whole() {
        let tarball: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let base = registry_with(&sri_of(&tarball), tarball.clone()).await;

        // The packument has to go past first, or there is no digest to check against.
        reqwest::get(format!("{base}/widget")).await.unwrap();

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            tarball.as_slice(),
            "a verified body must arrive complete and unchanged"
        );
    }

    /// A registry serving bytes its own packument does not describe. The client must not
    /// end up with a complete body: the response ends in an error instead.
    ///
    /// Checked against a real `npm install`, which reported ECONNRESET, retried twice
    /// with backoff, and failed the install. Nothing was written to `node_modules`.
    #[tokio::test]
    async fn a_tampered_tarball_never_arrives_complete() {
        let honest: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut tampered = honest.clone();
        tampered[25_000] ^= 0xFF;

        let base = registry_with(&sri_of(&honest), tampered).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();

        assert_no_complete_body(&format!("{base}/widget/-/widget-1.0.0.tgz")).await;
    }

    /// A tarball request with no packument behind it still gets verified, because the
    /// proxy fetches the packument itself.
    ///
    /// This is the `npm ci` case. Measured through the proxy before this existed: 69
    /// tarballs, zero packument requests, nothing verified. A warm npm cache, a restarted
    /// proxy and an evicted entry produce the same gap.
    #[tokio::test]
    async fn a_tarball_with_no_packument_seen_is_verified_anyway() {
        let honest: Vec<u8> = vec![9u8; 1_000];
        let mut tampered = honest.clone();
        tampered[500] ^= 0xFF;
        let base = registry_with(&sri_of(&honest), tampered).await;

        // No packument request first: straight to the artifact, as `npm ci` does.
        assert_no_complete_body(&format!("{base}/widget/-/widget-1.0.0.tgz")).await;
    }

    /// A failed digest must not deliver a whole artifact. Where the failure surfaces
    /// depends on chunking: a body that arrives in several chunks fails while being read,
    /// and one that fits in a single chunk fails before the client sees a response at
    /// all, because the proxy is still holding the only chunk there was.
    async fn assert_no_complete_body(url: &str) {
        let Ok(response) = reqwest::get(url).await else {
            return;
        };
        assert_eq!(
            response.status(),
            200,
            "the status left before a byte was hashed; only the body can carry the failure"
        );
        if let Ok(body) = response.bytes().await {
            panic!(
                "the body completed with {} bytes; a failed digest must not deliver a \
                 whole artifact",
                body.len()
            );
        }
    }

    /// When the packument cannot be fetched either, the artifact is forwarded and said to
    /// be unverified. Stage 1 does not fail an install over what it could not inspect.
    #[tokio::test]
    async fn an_artifact_whose_packument_cannot_be_fetched_is_forwarded() {
        let tarball = vec![4u8; 300];
        let body = tarball.clone();
        let router = Router::new().route(
            "/widget/-/widget-1.0.0.tgz",
            get(move || {
                let body = body.clone();
                async move { ([(header::CONTENT_TYPE, "application/octet-stream")], body) }
            }),
        );
        // Every other path, the packument included, 404s.
        let base = serve(Proxy::new(reqwest::Client::new(), serve(router).await).router()).await;

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().await.unwrap().as_ref(), tarball.as_slice());
    }

    /// An empty body still has to terminate and still has to be checked. reqwest ends a
    /// stream with an empty chunk, and an artifact of zero bytes has a digest like any
    /// other.
    #[tokio::test]
    async fn an_empty_tarball_is_verified_rather_than_hanging() {
        let base = registry_with(&sri_of(b""), Vec::new()).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.bytes().await.unwrap().is_empty());
    }

    /// Two versions in 24,852 publish only SHA-1, which is collision-broken. Those
    /// artifacts are forwarded without a digest check rather than being checked weakly.
    #[tokio::test]
    async fn a_version_with_no_strong_digest_is_forwarded_unverified() {
        let tarball = vec![3u8; 500];
        let base = registry_with("sha1-2KoFEwbCVDvbCxC5dXgvFkSlpwc=", tarball.clone()).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), tarball.as_slice());
    }

    /// A packument stored on one request answers the tarball request that follows it.
    #[tokio::test]
    async fn the_store_carries_the_digest_from_packument_to_tarball() {
        let tarball = vec![1u8; 100];
        let base = registry_with(&sri_of(&tarball), tarball.clone()).await;

        reqwest::get(format!("{base}/widget")).await.unwrap();
        for _ in 0..3 {
            let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
                .await
                .unwrap();
            assert_eq!(response.bytes().await.unwrap().len(), 100);
        }
    }

    /// A packument whose artifacts live somewhere the proxy does not front. The client
    /// fetches those directly, so the packument is the only place it is visible.
    ///
    /// The artifact request never arrives, which is the whole point: this asserts the
    /// proxy sees the packument and is left holding no tarball request for it.
    #[tokio::test]
    async fn artifacts_published_off_the_registry_are_visible_in_the_packument() {
        let packument = r#"{"name":"widget","dist-tags":{"latest":"1.0.0"},"versions":{
            "1.0.0":{"version":"1.0.0","dist":{
                "tarball":"https://elsewhere.example/widget-1.0.0.tgz",
                "integrity":"sha512-AAAA"}}}}"#;
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            packument.as_bytes().to_vec(),
        )
        .await;

        let response = reqwest::get(format!("{base}/widget")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.unwrap(),
            packument,
            "the packument is still forwarded unchanged; Stage 1 observes, it does not refuse"
        );
        assert_eq!(
            seen.lock().unwrap().paths,
            vec!["/widget"],
            "no artifact request follows, because the client goes straight to the other host"
        );
    }

    #[test]
    fn the_upstream_base_drops_a_trailing_slash() {
        let proxy = Proxy::new(reqwest::Client::new(), "https://registry.npmjs.org/");
        assert_eq!(proxy.upstream(), "https://registry.npmjs.org");
    }
}
