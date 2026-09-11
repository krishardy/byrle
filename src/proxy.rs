//! The reverse proxy: forward every request, normalise the packuments on the way back.
//!
//! Lives in the library rather than in `main.rs` so it can be tested against a fake
//! registry. `main.rs` reads the environment and serves [`Proxy::router`].
//!
//! # Bodies
//!
//! Tarballs stream straight through, hashed on the way past. Packuments are buffered,
//! decoded, normalised, and then **rewritten**: every artifact URL the proxy can serve is
//! pointed at the proxy itself, and the document is re-compressed.
//!
//! The rewrite replaces URLs in the text rather than rebuilding the document, so what the
//! client receives is byte-identical to the upstream's apart from those URLs. See
//! [`crate::npm::rewrite_artifact_origins`] for why, and what it costs.
//!
//! The rewrite exists because clients disagree about `dist.tarball`. npm rewrites it to
//! the configured registry; pnpm 10 and yarn 1 use it verbatim and fetch from whatever
//! host it names, so without this their artifacts never reach the proxy at all. See
//! `docs/engineering_decisions/packument-tarball-url-rewriting.md`.
//!
//! Normalising reads the decoded original, never the rewritten copy. Records built from
//! the rewritten document would carry the proxy's own origin as the registry's claim, and
//! would make [`crate::npm::bypassing_origin`] report every package.
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
//!
//! # When a packument is forwarded unrewritten
//!
//! Every such path logs `UNINSPECTED`, because each one leaves that package's artifacts
//! to be fetched wherever the document says. They are: the client accepts no encoding
//! this can decode; there is no `Host` and no configured public base; the body passes the
//! size cap; it cannot be decoded; it cannot be normalised; it cannot be re-serialised;
//! and, per version, an artifact on an origin the proxy does not front. Stage 1 forwards
//! in all of them rather than failing an install. Stage 2 has to decide whether that
//! stays acceptable, because for pnpm and yarn it means the bytes are never seen.

use crate::http::{
    DEFAULT_MAX_PACKUMENT_BYTES, DecodeError, RequestedEncoding, decode_for_parsing,
    encoding_to_request, gzip, is_hop_by_hop, mark_etag, unmark_if_none_match,
};
use crate::identity::PackageKey;
use crate::integrity::{Sri, Verifier};
use crate::npm::{
    self, Disposition, NormalizeError, NormalizedPackument, OriginPolicy, ReachableOrigins,
    RequestTarget,
};
use crate::record::PackumentDetail;
use crate::refusal::RefusalStatus;
use crate::store::{DEFAULT_MAX_RECORDS, Lookup, RecordStore};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default ceiling on how many packuments are decoded and rewritten at once.
///
/// Reading a packument costs far more than the bytes on the wire: the decoded copy, the
/// JSON value tree the rewrite walks, the re-serialised output, and the gzip buffer are
/// all live together. Measured with 24 simultaneous requests for the largest full
/// packuments (typescript, @types/node, react, next, @angular/core, eslint, webpack,
/// aws-sdk), the proxy peaked at 1,348 MB while the encoded bodies totalled 27.6 MB.
/// That is roughly 56 MB per request in flight, and nothing bounded how many there were.
///
/// Eight keeps the worst case near half a gigabyte. A normal install does not reach it:
/// npm's own request parallelism held a six-package install with 165 packuments to a
/// 141 MB peak.
pub const DEFAULT_MAX_CONCURRENT_PACKUMENTS: usize = 8;

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
    match decode_for_parsing(body, content_encoding, limit) {
        Ok(decoded) => inspect_decoded(&decoded, detail),
        Err(e) => PackumentOutcome::Undecodable(e),
    }
}

/// Normalise an already decoded body.
fn inspect_decoded(decoded: &[u8], detail: PackumentDetail) -> PackumentOutcome {
    match npm::normalize_packument(decoded, detail) {
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
    /// Used to fetch a packument the client never asked for. See [`lookup_or_fetch`].
    registry: npm::Client,
    /// Bounds how many packuments are decoded and rewritten at once. See
    /// [`DEFAULT_MAX_CONCURRENT_PACKUMENTS`].
    packument_slots: Arc<Semaphore>,
    /// Which origins this proxy serves, and which it permits a client to fetch directly.
    /// One source of truth for rewriting, for the report, and for the refusal.
    origins: Arc<OriginPolicy>,
    /// What a policy refusal answers with, per ecosystem and client.
    refusal: Arc<RefusalStatus>,
    /// Whether to drop versions whose artifacts this proxy cannot serve.
    refuse_unservable: bool,
    /// Upstream registry base, no trailing slash.
    upstream: String,
    /// THROWAWAY. One hardcoded package, to prove interception happens before anything
    /// is fetched. Stage 2 replaces this with the policy engine; there is deliberately
    /// no config file behind it, so it cannot quietly become a feature.
    blocked: Option<PackageKey>,
    max_packument_bytes: usize,
    /// Point artifact URLs at the proxy so every client fetches through it. See
    /// [`rewrite_packument`].
    rewrite_artifacts: bool,
    /// The address to write into artifact URLs, when it must not be taken from the
    /// request's `Host`. Needed behind a load balancer, and for a stable name in
    /// lockfiles.
    public_base: Option<String>,
}

impl Proxy {
    pub fn new(client: reqwest::Client, upstream: impl Into<String>) -> Self {
        let upstream = upstream.into().trim_end_matches('/').to_owned();
        // The upstream is a URL the operator already gave us, so this only fails if that
        // is unusable, in which case nothing else would work either.
        let reachable = ReachableOrigins::new(&upstream, std::iter::empty())
            .unwrap_or_else(|e| panic!("upstream is not a usable origin: {e}"));
        let origins = OriginPolicy::new(reachable, std::iter::empty())
            .expect("an empty allow list is always valid");
        Self {
            origins: Arc::new(origins),
            registry: npm::Client::new(client.clone(), upstream.clone()),
            client,
            store: Arc::new(Mutex::new(RecordStore::new(DEFAULT_MAX_RECORDS))),
            upstream,
            blocked: None,
            max_packument_bytes: DEFAULT_MAX_PACKUMENT_BYTES,
            rewrite_artifacts: true,
            public_base: None,
            packument_slots: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_PACKUMENTS)),
            refusal: Arc::new(RefusalStatus::default()),
            refuse_unservable: true,
        }
    }

    pub fn with_refusal_status(mut self, refusal: RefusalStatus) -> Self {
        self.refusal = Arc::new(refusal);
        self
    }

    /// Whether versions whose artifacts this proxy cannot serve are removed from the
    /// packument. On by default; see [`crate::npm::filter_unservable_versions`].
    pub fn with_refuse_unservable(mut self, refuse: bool) -> Self {
        self.refuse_unservable = refuse;
        self
    }

    pub fn with_max_concurrent_packuments(mut self, limit: usize) -> Self {
        self.packument_slots = Arc::new(Semaphore::new(limit.max(1)));
        self
    }

    /// Additional origins whose artifacts this proxy serves, beyond the upstream and the
    /// default registry, and origins it permits a client to fetch directly.
    pub fn with_origin_policy<'a>(
        mut self,
        served: impl IntoIterator<Item = &'a str>,
        allowed_direct: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, npm::OriginError> {
        let reachable = ReachableOrigins::new(&self.upstream, served)?;
        self.origins = Arc::new(OriginPolicy::new(reachable, allowed_direct)?);
        Ok(self)
    }

    pub fn origin_policy(&self) -> &OriginPolicy {
        &self.origins
    }

    pub fn with_artifact_rewriting(mut self, rewrite: bool) -> Self {
        self.rewrite_artifacts = rewrite;
        self
    }

    /// Override the address written into artifact URLs. Without it the request's `Host`
    /// is used, which is what the client already reached the proxy on.
    pub fn with_public_base(mut self, base: Option<String>) -> Self {
        self.public_base = base.map(|b| b.trim_end_matches('/').to_owned());
        self
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
        // The proxy's own fetches decode under the same ceiling as the bodies it
        // forwards, so one setting means one limit.
        self.registry =
            npm::Client::new(self.client.clone(), self.upstream.clone()).with_max_bytes(limit);
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

/// The status a refusal answers with for this client.
fn refusal_status(proxy: &Proxy, user_agent: Option<&str>) -> StatusCode {
    let code = proxy
        .refusal
        .for_client(crate::identity::Ecosystem::Npm, user_agent);
    StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN)
}

/// The address to write into artifact URLs.
///
/// The request's `Host` is the address the client actually reached the proxy on, which is
/// what its next request has to go to. `X-Forwarded-Proto` covers TLS terminated in front
/// of us. An explicit override wins over both, for a load balancer whose `Host` is not
/// what clients use, and for pinning a stable name into lockfiles.
///
/// `None` when there is nothing usable, which means the packument is forwarded as it
/// came.
fn public_base(headers: &HeaderMap, configured: Option<&str>) -> Option<String> {
    if let Some(base) = configured {
        return Some(base.trim_end_matches('/').to_owned());
    }
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or(v).trim())
        .filter(|v| !v.is_empty())
        .unwrap_or("http");
    Some(format!("{scheme}://{host}"))
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

    fetch_and_store(proxy, key, path).await;

    proxy
        .store
        .lock()
        .expect("record store lock")
        .lookup(key, version)
}

/// Fetch a packument the client did not ask for, and keep its records.
///
/// Failure is not fatal and is not propagated. The artifact is forwarded unverified and
/// said to be unverified, which is Stage 1 behaviour; Stage 2 has to decide whether that
/// stays allowed.
async fn fetch_and_store(proxy: &Proxy, key: &PackageKey, path: &str) {
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
        Ok(Err(e)) => {
            warn!(path = %path, purl = %key, error = %e, "packument fetched but did not normalize")
        }
        Err(e) => warn!(path = %path, purl = %key, error = %e, "could not fetch packument"),
    }
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
        let status = refusal_status(&proxy, Some(&client_ua));
        info!(
            %method,
            path = %path_and_query,
            status = status.as_u16(),
            purl = %key,
            client = %client_ua,
            "blocked"
        );
        return (status, format!("waharoa: {key} is blocked by policy\n")).into_response();
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
    let rewrite_base = public_base(req.headers(), proxy.public_base.as_deref());
    let rewriting = read_packument && proxy.rewrite_artifacts && rewrite_base.is_some();

    // Every path that forwards a packument without rewriting it leaves this package's
    // artifacts to be fetched wherever the document says, which for pnpm and yarn means
    // not through the proxy. They all carry the same marker so one grep finds them.
    if matches!(target, RequestTarget::Packument(_)) && method == Method::GET && !rewriting {
        if chosen_encoding == RequestedEncoding::Unreadable {
            warn!(
                path = %path_and_query,
                accept_encoding = client_accept_encoding.as_deref().unwrap_or("-"),
                "UNINSPECTED: client accepts no encoding this can read"
            );
        } else if rewrite_base.is_none() {
            warn!(
                path = %path_and_query,
                "UNINSPECTED: no Host header and no configured public base, so artifact \
                 URLs cannot be pointed at the proxy"
            );
        }
    }

    // The digest has to be known before the artifact is fetched, not after: that is what
    // decides whether this exact artifact has been analysed (plan §5). Looking it up here
    // also says which origin the packument published it on, so the request goes there
    // rather than assuming the upstream serves it.
    let mut expected_digest: Option<Sri> = None;
    let mut artifact_purl = String::new();
    let mut artifact_origin: Option<String> = None;
    let mut unservable_origin: Option<String> = None;
    if let RequestTarget::Tarball {
        key,
        claimed_version,
    } = &target
        && method == Method::GET
    {
        let purl = key
            .at_version(claimed_version)
            .map(|r| r.to_string())
            .unwrap_or_else(|_| format!("{key}@{claimed_version}"));
        artifact_purl = purl.clone();
        match lookup_or_fetch(&proxy, key, claimed_version, &path_and_query).await {
            Lookup::Found(record) => {
                info!(
                    path = %path_and_query,
                    claimed_purl = %purl,
                    integrity = record.artifact.integrity.as_deref().unwrap_or("-"),
                    has_install_scripts = record.has_install_scripts,
                    "artifact requested, digest known"
                );
                // Where the packument said the artifact lives, when that is an origin
                // the operator added. Rewriting pointed the client at the proxy, so the
                // proxy has to know where "here" stood for. Everything else goes to the
                // upstream, including artifacts advertised on the default registry: a
                // private mirror publishes those URLs and is the reason the proxy was
                // pointed at it.
                artifact_origin = npm::origin_of_url(&record.artifact.url)
                    .filter(|origin| proxy.origins.reachable().routes_directly(origin));
                unservable_origin = match proxy.origins.disposition(&record.artifact.url) {
                    Disposition::Refused(origin) => Some(origin),
                    _ => None,
                };
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
            // Nothing was observed for this package, and fetching its packument did not
            // help either.
            Lookup::Unknown => warn!(
                path = %path_and_query,
                claimed_purl = %purl,
                "artifact requested, no packument seen for it"
            ),
        }

        // A pinned fetch of a version the packument filter removes. Decision #4: filter
        // on resolution, hard fail on a pinned fetch, because there is no resolution step
        // left to influence.
        if let Some(origin) = &unservable_origin
            && proxy.refuse_unservable
        {
            let status = refusal_status(&proxy, Some(&client_ua));
            info!(
                %method,
                path = %path_and_query,
                status = status.as_u16(),
                claimed_purl = %purl,
                origin = %origin,
                client = %client_ua,
                "refused: this artifact is published on an origin the proxy does not serve"
            );
            return (
                status,
                format!(
                    "waharoa: {purl} is published at {origin}, which this proxy does not \
                     serve, so it cannot be examined\n"
                ),
            )
                .into_response();
        }
    }

    let origin = artifact_origin.as_deref().unwrap_or(&proxy.upstream);
    let url = format!("{origin}{path_and_query}");
    let mut outbound = proxy.client.request(method.clone(), &url);
    for (name, value) in req.headers() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST {
            continue;
        }
        if read_packument && name == header::ACCEPT_ENCODING {
            continue;
        }
        if rewriting && name == header::IF_NONE_MATCH {
            continue;
        }
        outbound = outbound.header(name, value);
    }
    if read_packument && let Some(value) = chosen_encoding.header_value() {
        outbound = outbound.header(header::ACCEPT_ENCODING, value);
    }
    // An `If-None-Match` the client got from us names our rewritten body, not the
    // upstream's. Turn it back, or drop it when it came from a proxy at another address.
    if rewriting
        && let Some(inm) = req
            .headers()
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
        && let Some(base) = rewrite_base.as_deref()
    {
        outbound = match unmark_if_none_match(inm, base) {
            Some(value) => outbound.header(header::IF_NONE_MATCH, value),
            // A 304 would let the client serve a body this proxy did not produce here,
            // whose artifact URLs were never pointed at it. Dropping the header makes
            // the registry send a body to rewrite afresh.
            None => {
                info!(
                    path = %path_and_query,
                    "dropped a conditional request for a body this proxy did not rewrite"
                );
                outbound
            }
        };
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

    // A warm client cache sends If-None-Match, and 304 carries no body, so there is
    // nothing to normalise from this response. The client is about to resolve against a
    // document the proxy cannot see.
    //
    // When the records are still held that does not matter: the 304 only revalidates a
    // body this proxy produced, so it was normalised when it was first served. When they
    // are not, because the proxy restarted or the entry was evicted, the packument is
    // fetched here so the metadata is in hand before the artifact requests arrive rather
    // than one lazy fetch at a time.
    if status == reqwest::StatusCode::NOT_MODIFIED
        && let RequestTarget::Packument(key) = &target
    {
        let held = proxy.store.lock().expect("record store lock").holds(key);
        info!(
            path = %path_and_query,
            purl = %key,
            etag = headers.get(header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("-"),
            held,
            "packument not modified, nothing to normalize"
        );
        if !held {
            fetch_and_store(&proxy, key, &path_and_query).await;
        }
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
                "UNINSPECTED: packument exceeds the size limit, forwarded without rewriting"
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

    // Queue here, not before the body is read. The encoded body is already in hand and
    // the upstream connection is finished, so waiting costs only time. Waiting with the
    // response still streaming stalls it until it times out: measured with the acquire
    // placed before the read, 18 of 24 concurrent requests failed with "error decoding
    // response body".
    //
    // What this bounds is the expensive part. The decoded copy, the value tree the
    // rewrite walks, the re-serialised output and the gzip buffer are live together, and
    // 24 simultaneous large packuments reached 1,348 MB while the encoded bodies totalled
    // 27.6 MB.
    let queued = Instant::now();
    let _slot = proxy
        .packument_slots
        .clone()
        .acquire_owned()
        .await
        .expect("the semaphore is never closed");
    let waited = queued.elapsed();
    if waited.as_millis() > 0 {
        debug!(
            path = %path_and_query,
            waited_ms = waited.as_millis() as u64,
            "waited for a packument slot"
        );
    }

    // Decoded once. Normalising and the store read these bytes; the rewrite below works
    // on a copy. Building records from the rewritten document instead would set every
    // artifact URL to the proxy's own origin, which is both the wrong thing to store as
    // the upstream's claim and enough to make the offsite check report every package.
    let parse_started = Instant::now();
    let decoded = match decode_for_parsing(
        &body,
        content_encoding.as_deref(),
        proxy.max_packument_bytes,
    ) {
        Ok(decoded) => Some(decoded),
        Err(e) => {
            warn!(path = %path_and_query, error = %e, "UNINSPECTED: packument body could not be decoded");
            None
        }
    };

    // Nothing to normalise when decoding failed; it was logged above.
    let mut normalized: Option<Box<NormalizedPackument>> = None;
    match decoded.as_deref().map(|d| inspect_decoded(d, detail)) {
        None => {}
        Some(PackumentOutcome::Normalized(p)) => {
            // Reported by `rewrite_packument` below, which is where it is acted on.
            let (allowed_direct, refused) = p.unserved_origins(&proxy.origins);
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
            offsite_versions = refused.values().sum::<usize>() + allowed_direct.values().sum::<usize>(),
            held_packages,
            held_records,
            "packument normalized"
            );
            normalized = Some(p);
        }
        Some(PackumentOutcome::Unreadable(e)) => {
            warn!(path = %path_and_query, error = %e, "UNINSPECTED: packument did not normalize")
        }
        Some(PackumentOutcome::Undecodable(_)) => {}
    }

    // The rewrite. Every client in the npm ecosystem has to fetch artifacts through the
    // proxy, and they do not agree about `dist.tarball`: npm rewrites it to the
    // configured registry, pnpm 10 and yarn 1 use it verbatim. Pointing it here makes
    // them behave alike.
    //
    // It needs the records, so a document that did not normalise is not rewritten either.
    // That is the honest outcome: without records there is nothing to gate on anyway, and
    // it is already logged as UNINSPECTED above.
    let forwarded = match (decoded.as_deref(), normalized.as_deref()) {
        (Some(decoded), Some(packument)) if rewriting => {
            let base = rewrite_base.as_deref().expect("rewriting implies a base");
            rewrite_packument(
                decoded,
                packument,
                base,
                &proxy.origins,
                proxy.refuse_unservable,
                &path_and_query,
            )
        }
        _ => None,
    };

    let body = match forwarded {
        Some(rewritten) => {
            // The body is ours now, so its length, its encoding and its entity tag all
            // have to describe it rather than the upstream's.
            let encoded = match chosen_encoding {
                RequestedEncoding::Gzip => match gzip(&rewritten) {
                    Ok(encoded) => {
                        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                        encoded
                    }
                    Err(e) => {
                        warn!(path = %path_and_query, error = %e, "could not re-compress; sending identity");
                        headers.remove(header::CONTENT_ENCODING);
                        rewritten
                    }
                },
                _ => {
                    headers.remove(header::CONTENT_ENCODING);
                    rewritten
                }
            };
            if let Ok(value) = HeaderValue::from_str(&encoded.len().to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }
            if let Some(etag) = headers
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|etag| mark_etag(etag, rewrite_base.as_deref().unwrap_or_default()))
                && let Ok(value) = HeaderValue::from_str(&etag)
            {
                headers.insert(header::ETAG, value);
            }
            Bytes::from(encoded)
        }
        None => body,
    };

    log_proxied(body.len() as u64);
    (forward_status, headers, Body::from(body)).into_response()
}

/// Point a packument's artifacts at the proxy, or explain why it was left alone.
///
/// Returns `None` when the document is forwarded as it came, which always means some
/// artifacts for this package will be fetched without the proxy seeing them.
fn rewrite_packument(
    decoded: &[u8],
    packument: &NormalizedPackument,
    base: &str,
    policy: &OriginPolicy,
    refuse_unservable: bool,
    path: &str,
) -> Option<Vec<u8>> {
    let (allowed_direct, refused) = packument.unserved_origins(policy);

    // An accepted gap has to stay visible. One that stops being reported outlives the
    // reason it was added.
    if !allowed_direct.is_empty() {
        warn!(
            path = %path,
            versions = allowed_direct.values().sum::<usize>(),
            origins = ?allowed_direct.keys().collect::<Vec<_>>(),
            "UNINSPECTED: artifacts fetched directly by the client, allowed by configuration"
        );
    }

    if !refused.is_empty() {
        let versions: usize = refused.values().sum();
        let origins: Vec<&String> = refused.keys().collect();

        // The only control that works on these. The client fetches `dist.tarball` from
        // whatever host it names, so refusing the artifact request never happens: the
        // request goes somewhere else. Decision #4 settles the shape, filter on
        // resolution and hard fail on a pinned fetch.
        if refuse_unservable {
            let artifacts = packument
                .records
                .iter()
                .map(|r| (r.package.version().to_owned(), r.artifact.url.clone()));
            return match npm::filter_unservable_versions(decoded, artifacts, policy, base) {
                Ok(filtered) => {
                    warn!(
                        path = %path,
                        removed = filtered.removed.len(),
                        kept = filtered.rewritten,
                        allowed = filtered.allowed,
                        origins = ?origins,
                        "REFUSED versions whose artifacts are published where this proxy \
                         cannot see them"
                    );
                    // Always the filtered body, even when nothing survived. Returning
                    // None here forwards the original, which would put every refused
                    // version straight back into the document.
                    Some(filtered.body)
                }
                Err(e) => {
                    warn!(path = %path, error = %e, "UNINSPECTED: packument could not be filtered");
                    None
                }
            };
        }

        // Every artifact being off-origin is not the same exposure as some of them being
        // off-origin, and it is the shape someone would construct.
        if versions == packument.records.len() {
            warn!(
                path = %path,
                versions,
                origins = ?origins,
                "UNINSPECTED: every artifact in this packument is on an origin the proxy \
                 does not front"
            );
        } else {
            warn!(
                path = %path,
                versions,
                origins = ?origins,
                "UNINSPECTED: some artifacts left on an origin the proxy does not front"
            );
        }
    }

    let artifacts = packument
        .records
        .iter()
        .map(|record| record.artifact.url.as_str());
    match npm::rewrite_artifact_origins(decoded, artifacts, policy.reachable(), base) {
        Ok(rewritten) => (rewritten.rewritten > 0).then_some(rewritten.body),
        Err(e) => {
            warn!(path = %path, error = %e, "UNINSPECTED: packument could not be rewritten");
            None
        }
    }
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
    /// A packument is rewritten, and everything except the artifact URLs has to survive
    /// it intact. `dist.integrity` above all: npm checks the bytes it downloads against
    /// it, and the registry signature covers `<name>@<version>:<integrity>`.
    #[tokio::test]
    async fn a_rewritten_packument_changes_only_the_artifact_urls() {
        let original = fixture("lodash-4.17.21.abbrev.json");
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            Some("gzip"),
            gzip(&original),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip",
            "the body is re-compressed, so Content-Encoding still applies"
        );
        let body = response.bytes().await.unwrap();
        let served: serde_json::Value =
            serde_json::from_slice(&decode_for_parsing(&body, Some("gzip"), 1 << 20).unwrap())
                .unwrap();
        let mut expected: serde_json::Value = serde_json::from_slice(&original).unwrap();

        let host = base.trim_start_matches("http://");
        assert_eq!(
            served["versions"]["4.17.21"]["dist"]["tarball"],
            serde_json::json!(format!("http://{host}/lodash/-/lodash-4.17.21.tgz")),
            "the artifact has to point at the proxy"
        );

        // Put the original URL back, and nothing else may differ.
        expected["versions"]["4.17.21"]["dist"]["tarball"] =
            served["versions"]["4.17.21"]["dist"]["tarball"].clone();
        assert_eq!(served, expected, "something other than the URL changed");
    }

    /// The length has to describe the body actually sent, or the client reads the wrong
    /// number of bytes.
    #[tokio::test]
    async fn a_rewritten_body_carries_its_own_length() {
        let original = fixture("lodash-4.17.21.abbrev.json");
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            original.clone(),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .unwrap();
        let declared: usize = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("a length is declared")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let body = response.bytes().await.unwrap();
        assert_eq!(declared, body.len());
        assert_ne!(
            body.len(),
            original.len(),
            "this fixture does change length, so the test would pass vacuously otherwise"
        );
    }

    /// Turning rewriting off restores byte-for-byte forwarding.
    #[tokio::test]
    async fn rewriting_can_be_turned_off() {
        let original = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            original.clone(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_artifact_rewriting(false)
                .router(),
        )
        .await;

        let body = reqwest::get(format!("{base}/lodash"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.as_ref(), original.as_slice());
    }

    const OFFSITE_PACKUMENT: &str = r#"{"name":"widget","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{
            "version":"1.0.0","dist":{
            "tarball":"https://elsewhere.example/widget-1.0.0.tgz","integrity":"sha512-AAAA"}}}}"#;

    /// An artifact the proxy cannot serve is removed from the packument, so a resolver
    /// picks a version that can be examined. It is the only control that works: the
    /// client would fetch that URL from `elsewhere.example` and never ask the proxy.
    #[tokio::test]
    async fn versions_the_proxy_cannot_serve_are_removed_from_the_packument() {
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            OFFSITE_PACKUMENT.as_bytes().to_vec(),
        )
        .await;

        let body = reqwest::get(format!("{base}/widget"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            !body.contains("elsewhere.example"),
            "the version should be gone, not forwarded: {body}"
        );
        let served: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(served["versions"].as_object().unwrap().is_empty());
        assert!(
            served["dist-tags"].as_object().unwrap().is_empty(),
            "a tag naming a removed version resolves to nothing"
        );
    }

    /// Turning the refusal off forwards them instead, and the artifact URL stays as it
    /// was: rewriting it would mean the proxy fetching from an arbitrary host.
    #[tokio::test]
    async fn refusal_can_be_turned_off_and_then_they_are_forwarded() {
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            OFFSITE_PACKUMENT.as_bytes().to_vec(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_refuse_unservable(false)
                .router(),
        )
        .await;

        let body = reqwest::get(format!("{base}/widget"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            body.contains("https://elsewhere.example/widget-1.0.0.tgz"),
            "an unreachable origin stays as it is: {body}"
        );
    }

    /// A pinned fetch of a version the filter removes. Decision #4: filter on
    /// resolution, hard fail on a pinned fetch, because there is no resolution left to
    /// influence. The status is the configured one.
    #[tokio::test]
    async fn a_pinned_fetch_of_an_unservable_artifact_is_refused() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            OFFSITE_PACKUMENT.as_bytes().to_vec(),
        )
        .await;

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let body = response.text().await.unwrap();
        assert!(body.contains("elsewhere.example"), "got: {body}");
        assert!(
            !seen
                .lock()
                .unwrap()
                .paths
                .iter()
                .any(|p| p.ends_with(".tgz")),
            "a refused artifact must not be fetched"
        );
    }

    /// Clients bucket status codes differently, so the refusal is configurable by
    /// (ecosystem, client). pnpm and yarn both carry `npm/` in their user-agent, so this
    /// also checks the client is read from the first token.
    #[tokio::test]
    async fn the_refusal_status_is_configurable_per_client() {
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            OFFSITE_PACKUMENT.as_bytes().to_vec(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_refusal_status(
                    crate::refusal::RefusalStatus::parse("default=403,npm/pnpm=451").unwrap(),
                )
                .router(),
        )
        .await;

        for (agent, expected) in [
            ("pnpm/10.33.0 npm/? node/v20.11.1 linux x64", 451),
            ("npm/9.9.4 node/v16.20.1 linux x64", 403),
            ("yarn/1.22.22 npm/? node/v16.20.1 linux x64", 403),
        ] {
            let response = reqwest::Client::new()
                .get(format!("{base}/widget/-/widget-1.0.0.tgz"))
                .header(header::USER_AGENT, agent)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected, "{agent}");
        }
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

    /// A conditional request for a body this proxy did not rewrite is not forwarded. A
    /// 304 authorises the client to serve what it cached, and that copy has artifact URLs
    /// that were never pointed here.
    ///
    /// Measured: after enabling rewriting at an address that previously ran without it,
    /// npm sent the upstream's own tag, the registry answered 304, and the client stayed
    /// on its unrewritten copy.
    #[tokio::test]
    async fn a_conditional_request_for_a_body_we_did_not_rewrite_is_dropped() {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let body = fixture("lodash-4.17.21.abbrev.json");
        let router = Router::new().route(
            "/lodash",
            get(move |req: Request| {
                let seen = recorder.clone();
                let body = body.clone();
                async move {
                    seen.lock().unwrap().headers.push(req.headers().clone());
                    if req.headers().contains_key(header::IF_NONE_MATCH) {
                        return Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, "W/\"abc123\"")
                            .body(Body::empty())
                            .unwrap();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                        .header(header::ETAG, "W/\"abc123\"")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let upstream = serve(router).await;
        let base = serve(Proxy::new(reqwest::Client::new(), upstream).router()).await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, "W/\"abc123\"")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "the registry has to send a body, so it can be rewritten"
        );
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("/lodash/-/lodash-4.17.21.tgz"),
            "and the body that arrives has to be the rewritten one"
        );
        assert!(
            !seen
                .lock()
                .unwrap()
                .headers
                .last()
                .unwrap()
                .contains_key(header::IF_NONE_MATCH),
            "the foreign tag must not reach the registry"
        );
    }

    /// A 304 leaves the proxy nothing to normalise, so when it holds no records for that
    /// package it fetches the packument itself. Without this a restarted proxy meets a
    /// warm client cache and observes nothing at all.
    #[tokio::test]
    async fn a_304_with_no_records_makes_the_proxy_fetch_the_packument() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().route(
            "/lodash",
            get(move |req: Request| {
                let seen = recorder.clone();
                let body = body.clone();
                async move {
                    seen.lock().unwrap().headers.push(req.headers().clone());
                    // Anything with a conditional header gets a 304, so the only 200 is
                    // the proxy's own unconditional fetch.
                    if req.headers().contains_key(header::IF_NONE_MATCH) {
                        return Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, "W/\"abc123\"")
                            .body(Body::empty())
                            .unwrap();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                        .header(header::ETAG, "W/\"abc123\"")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let base = serve(Proxy::new(reqwest::Client::new(), serve(router).await).router()).await;

        // A tag this proxy issued, so the conditional is forwarded rather than dropped.
        let ours = crate::http::mark_etag("W/\"abc123\"", &base);
        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, ours)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 304);

        // Having fetched it, the proxy can answer for the artifact without another fetch.
        let response = reqwest::get(format!("{base}/lodash/-/lodash-4.17.21.tgz"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            404,
            "the fake registry serves no tarball"
        );

        let conditional = seen
            .lock()
            .unwrap()
            .headers
            .iter()
            .filter(|h| h.contains_key(header::IF_NONE_MATCH))
            .count();
        let unconditional = seen.lock().unwrap().headers.len() - conditional;
        assert_eq!(conditional, 1, "the client's revalidation");
        assert_eq!(
            unconditional, 1,
            "one unconditional fetch by the proxy, and not a second one for the artifact"
        );
    }

    /// A 304 the proxy does allow, on a tag it issued, carries no body to read.
    #[tokio::test]
    async fn a_304_on_our_own_tag_passes_through() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let router = Router::new().route(
            "/lodash",
            get(move |req: Request| {
                let body = body.clone();
                async move {
                    if req.headers().get(header::IF_NONE_MATCH).is_some() {
                        return Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, "W/\"abc123\"")
                            .body(Body::empty())
                            .unwrap();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                        .header(header::ETAG, "W/\"abc123\"")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let base = serve(Proxy::new(reqwest::Client::new(), serve(router).await).router()).await;

        let first = reqwest::get(format!("{base}/lodash")).await.unwrap();
        let ours = first
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        first.bytes().await.unwrap();

        let second = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, ours)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 304);
        assert!(second.bytes().await.unwrap().is_empty());
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

    /// With the refusal off, the packument is forwarded byte for byte, and no artifact
    /// request follows because the client goes straight to the other host. That is the
    /// exposure the refusal exists to close.
    #[tokio::test]
    async fn without_the_refusal_an_offsite_packument_is_forwarded_unchanged() {
        let (upstream, seen) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            OFFSITE_PACKUMENT.as_bytes().to_vec(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_refuse_unservable(false)
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/widget")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), OFFSITE_PACKUMENT);
        assert_eq!(
            seen.lock().unwrap().paths,
            vec!["/widget"],
            "no artifact request follows, because the client goes straight to the other host"
        );
    }

    /// A client that caches a rewritten packument revalidates against a tag we issued,
    /// not the upstream's. The proxy has to translate it back, or the registry never
    /// answers 304 and the conditional request buys nothing.
    #[tokio::test]
    async fn a_conditional_request_round_trips_through_the_rewrite() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().route(
            "/lodash",
            get(move |req: Request| {
                let seen = recorder.clone();
                let body = body.clone();
                async move {
                    let inm = req
                        .headers()
                        .get(header::IF_NONE_MATCH)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    seen.lock().unwrap().headers.push(req.headers().clone());
                    if inm.as_deref() == Some("\"upstream-tag\"") {
                        return Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .header(header::ETAG, "\"upstream-tag\"")
                            .body(Body::empty())
                            .unwrap();
                    }
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                        .header(header::ETAG, "\"upstream-tag\"")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
        );
        let base = serve(Proxy::new(reqwest::Client::new(), serve(router).await).router()).await;

        let first = reqwest::get(format!("{base}/lodash")).await.unwrap();
        let tag = first
            .headers()
            .get(header::ETAG)
            .expect("a rewritten body needs a tag")
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(
            tag, "\"upstream-tag\"",
            "the tag has to name our body, not the upstream's"
        );
        first.bytes().await.unwrap();

        let second = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, &tag)
            .send()
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            304,
            "the registry should have answered 304"
        );
        assert_eq!(
            seen.lock()
                .unwrap()
                .headers
                .last()
                .unwrap()
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok()),
            Some("\"upstream-tag\""),
            "the upstream has to receive its own tag back, not ours"
        );
    }

    /// A tag issued when the proxy answered on another address must not revalidate: a 304
    /// would leave the client serving artifact URLs pointing at an address nobody
    /// listens on. Dropping the header makes the registry send a body to rewrite afresh.
    #[tokio::test]
    async fn a_tag_from_another_proxy_address_does_not_revalidate() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;

        let stale = crate::http::mark_etag("\"upstream-tag\"", "http://some-old-address:9999");
        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, stale)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            seen.lock()
                .unwrap()
                .headers
                .last()
                .unwrap()
                .get(header::IF_NONE_MATCH),
            None,
            "the stale conditional header must not reach the registry"
        );
    }

    /// The address written into artifact URLs comes from the `Host` the client used, so
    /// a proxy reachable by several names points each client back at its own.
    #[tokio::test]
    async fn artifact_urls_use_the_host_the_client_reached_us_on() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (base, _) = proxy_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;

        let text = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::HOST, "npm.corp.example")
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            text.contains("https://npm.corp.example/lodash/-/lodash-4.17.21.tgz"),
            "artifact URL did not follow Host and X-Forwarded-Proto: {text}"
        );
    }

    /// An explicit public base wins over `Host`, which is what a deployment behind a load
    /// balancer needs, and what pins a stable name into lockfiles.
    #[tokio::test]
    async fn a_configured_public_base_overrides_the_host_header() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_public_base(Some("https://npm.corp.example/".into()))
                .router(),
        )
        .await;

        let text = reqwest::get(format!("{base}/lodash"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            text.contains("https://npm.corp.example/lodash/-/lodash-4.17.21.tgz"),
            "the configured base was not used: {text}"
        );
    }

    /// Concurrent packument requests all have to be served, however tight the limit.
    ///
    /// The slot is taken after the body is buffered, not before it is read. With the
    /// acquire placed before the read, waiting held the upstream response open until it
    /// timed out: 18 of 24 concurrent requests failed with "error decoding response
    /// body". At a limit of one, every request here queues behind another, which is the
    /// condition that exposed it.
    #[tokio::test]
    async fn a_tight_concurrency_limit_still_serves_every_request() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_max_concurrent_packuments(1)
                .router(),
        )
        .await;

        let mut requests = Vec::new();
        for _ in 0..8 {
            let url = format!("{base}/lodash");
            requests.push(tokio::spawn(async move {
                let response = reqwest::get(url).await.expect("request should complete");
                assert_eq!(response.status(), 200);
                response.text().await.expect("body should arrive")
            }));
        }

        for request in requests {
            let body = request.await.expect("task should not panic");
            assert!(
                body.contains("/lodash/-/lodash-4.17.21.tgz"),
                "every queued request still gets a rewritten body"
            );
        }
    }

    /// A limit of zero would deadlock every packument request, so it is raised to one.
    #[tokio::test]
    async fn a_limit_of_zero_is_treated_as_one() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new(), upstream)
                .with_max_concurrent_packuments(0)
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("/lodash/-/lodash-4.17.21.tgz")
        );
    }

    #[test]
    fn the_upstream_base_drops_a_trailing_slash() {
        let proxy = Proxy::new(reqwest::Client::new(), "https://registry.npmjs.org/");
        assert_eq!(proxy.upstream(), "https://registry.npmjs.org");
    }
}
