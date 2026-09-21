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
//! [`crate::origin::rewrite_artifact_origins`] for why, and what it costs.
//!
//! The rewrite exists because clients disagree about `dist.tarball`. npm rewrites it to
//! the configured registry; pnpm 10, yarn 1, yarn 4 and bun 1.3 use it verbatim and
//! fetch from whatever host it names, so without this their artifacts never reach the
//! proxy at all. See
//! `docs/engineering_decisions/packument-tarball-url-rewriting.md`.
//!
//! Normalising reads the decoded original, never the rewritten copy. Records built from
//! the rewritten document would carry the proxy's own origin as the registry's claim, and
//! would make [`crate::origin::bypassing_origin`] report every package.
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
//! stays acceptable, because for every client except npm it means the bytes are never
//! seen.

use crate::audit::{self, AuditLog};
#[cfg(debug_assertions)]
use crate::defer::DeferTest;
use crate::ecosystem::{self, Clients, UncoveredMetadata, Upstreams};
use crate::ecosystem::{npm, pypi};
use crate::env::{
    DEFAULT_MAX_CONCURRENT_METADATA, DEFAULT_MAX_METADATA_BYTES, DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_VERIFIED,
};
use crate::http::{
    RequestedEncoding, decode_for_parsing, encoding_to_request, gzip, is_conditional,
    is_hop_by_hop, mark_etag, unmark_if_none_match,
};
use crate::identity::{Ecosystem, PackageKey};
use crate::integrity::{Sri, Verifier};
use crate::intel::store::{Intel, LoadedSnapshot, PackageIntel};
use crate::origin::{Disposition, OriginPolicy, ReachableOrigins};
use crate::policy::{Policy, enforce, facts};
use crate::record::{PackageMetadata, PackageRecord};
use crate::refusal::RefusalStatus;
use crate::route::{DocumentKind, RequestTarget};
use crate::store::{Lookup, RecordStore};
use crate::verified::VerifiedArtifacts;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// The path the proxy answers for itself rather than forwarding.
///
/// Under `/-/`, which is the registry's own namespace and where a package name can never
/// live, so it cannot collide with anything a client asks for.
pub const HEALTH_PATH: &str = "/-/waharoa/health";

/// Where the proxy says whether it can decide on packages now, for an orchestrator's
/// readiness probe. Under `/-/` for the same reason as [`HEALTH_PATH`].
pub const READY_PATH: &str = "/-/waharoa/ready";

/// How many versions the policy took out of a metadata document, on the response carrying
/// it. Absent when it took none.
///
/// Decision #4 filters on resolution, so the client resolves against a document this proxy
/// changed. `docs/engineering_decisions/enforcement-tiers.md` calls changing it silently a
/// trust problem of its own, and these two headers are what a client, a CI log or a person
/// with `curl -I` can see it by.
pub const FILTERED_VERSIONS: header::HeaderName =
    header::HeaderName::from_static("x-waharoa-filtered-versions");

/// Which checks took them out, comma separated, in name order. Beside
/// [`FILTERED_VERSIONS`].
pub const FILTERED_CHECKS: header::HeaderName =
    header::HeaderName::from_static("x-waharoa-filtered-checks");

/// Whether the proxy can decide on a package now. Served at [`READY_PATH`].
///
/// 200 when ready and 503 when not, so a probe needs only the status. Ready exactly when a
/// package request would not be answered with the intel 503. No percentage: `waharoa
/// refresh` loads in one transaction, so the store holds the previous snapshot or the new
/// one and never part of one. See `docs/engineering_decisions/readiness-endpoint.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Readiness {
    pub ready: bool,
    pub intel: IntelState,
    /// The snapshot decisions use, when the store holds one.
    pub snapshot: Option<LoadedSnapshot>,
}

/// What the intel store means for readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelState {
    /// No policy, or no store: nothing asks the store, so nothing waits on it.
    NotConsulted,
    /// The store answers and holds a snapshot.
    Loaded,
    /// The store answers and holds no snapshot: `waharoa refresh` has not loaded one.
    Empty,
    /// The store cannot answer. The cause is logged, not served.
    Unavailable,
}

/// What the proxy is, and what it is configured to do.
///
/// Served at [`HEALTH_PATH`] so a client can tell a waharoa from any other registry, and
/// so the settings that decide what gets examined are visible without reading the
/// environment of a running process. `waharoa doctor` reads it.
///
/// Deliberately no secrets: the CA bundle's contents, the upstream's credentials if it
/// ever has any, and the throwaway block are all absent. What is here is what an operator
/// needs to answer "is this thing doing what I think".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// Always "waharoa", so a response from something else is recognisable as such.
    pub service: String,
    pub version: String,
    /// Each ecosystem's upstream, by purl type.
    pub upstreams: BTreeMap<String, String>,
    /// The address written into artifact URLs, when one is configured. `None` means each
    /// request's own `Host` is used, and that address is what lockfiles record.
    pub public_base: Option<String>,
    /// Whether artifact URLs are pointed at this proxy. With this off, pnpm and yarn
    /// fetch artifacts without the proxy seeing them.
    pub rewrite_artifacts: bool,
    /// Whether versions whose artifacts this proxy cannot serve are removed.
    pub refuse_unservable: bool,
    /// Origins whose artifacts this proxy serves.
    pub served_origins: Vec<String>,
    /// Origins it does not serve and permits a client to fetch directly.
    pub allowed_direct_origins: Vec<String>,
    /// Packages whose metadata is held, and the records in them.
    pub packages_held: usize,
    pub records_held: usize,
    /// Artifacts fetched and verified since the proxy started. See [`crate::verified`].
    pub artifacts_verified: usize,
}

#[derive(Clone)]
pub struct Proxy {
    /// Set by the builders and read while serving. Behind one `Arc`, because axum clones
    /// the proxy for every request and several of these fields are heap allocations.
    config: Arc<Config>,
    /// Records from packuments already seen, so a tarball request can find the digest
    /// its packument published. Bounded; see [`crate::store`].
    store: Arc<Mutex<RecordStore>>,
    /// Artifacts already fetched and verified, keyed by content digest. The fetch path
    /// branches on this (plan §5). See [`crate::verified`].
    verified: Arc<Mutex<VerifiedArtifacts>>,
    /// Bounds how many packuments are decoded and rewritten at once. See
    /// [`DEFAULT_MAX_CONCURRENT_METADATA`].
    metadata_slots: Arc<Semaphore>,
    /// The intel snapshot [`intel_for`] last read coverage from. See [`snapshot_named`].
    coverage: Arc<Mutex<Option<LoadedSnapshot>>>,
}

/// What the builders set. Nothing here changes once the proxy is serving.
#[derive(Clone)]
struct Config {
    client: reqwest::Client,
    /// Fetches the metadata a client never asked for. See [`lookup_or_fetch`].
    clients: Clients,
    /// Which origins this proxy serves, and which it permits a client to fetch directly.
    /// One source of truth for rewriting, for the report, and for the refusal.
    origins: OriginPolicy,
    /// What a policy refusal answers with, per ecosystem and client.
    refusal: RefusalStatus,
    /// Whether to drop versions whose artifacts this proxy cannot serve.
    refuse_unservable: bool,
    /// Origins the operator added, beyond the upstreams, as `with_origin_policy` accepted
    /// them. Kept so a later upstream change rebuilds `origins` without losing them.
    served_origins: Vec<String>,
    /// Origins a client may fetch from directly, kept for the same reason.
    allowed_direct: Vec<String>,
    /// Where each ecosystem's requests are forwarded. A PyPI client asks this proxy for
    /// `/simple/<name>/` and the request goes to `{pypi upstream}/<name>/`, because the base
    /// already names the index.
    upstreams: Upstreams,
    /// The policy, when one is configured. `None` is Stage 1 behaviour and is a distinct
    /// state from a policy that allows everything: nothing was asked, rather than asked
    /// and answered yes.
    policy: Option<Arc<Policy>>,
    /// One line per policy decision, when a path is configured.
    audit: Option<Arc<AuditLog>>,
    /// The intel store, when one is configured. With a policy, every decision consults it,
    /// and a store that cannot answer is a 503 rather than a serve. See [`intel_for`].
    intel: Option<Arc<dyn Intel>>,
    max_metadata_bytes: usize,
    /// Point artifact URLs at the proxy so every client fetches through it. See
    /// [`npm::rewrite_packument`] and [`pypi::rewrite::rewrite_index`].
    rewrite_artifacts: bool,
    /// The address to write into artifact URLs, when it must not be taken from the
    /// request's `Host`. Needed behind a load balancer, and for a stable name in
    /// lockfiles.
    public_base: Option<String>,
    /// Debug builds only: answer with a deferral instead of fetching, so client retry
    /// behaviour can be measured before the thing that would cause one exists. See
    /// [`crate::defer`].
    #[cfg(debug_assertions)]
    defer_test: Option<(DeferTest, Instant)>,
}

impl Proxy {
    /// A proxy for each ecosystem's public registry. `with_upstream` points one elsewhere.
    pub fn new(client: reqwest::Client) -> Self {
        let proxy = Self {
            config: Arc::new(Config {
                origins: OriginPolicy::new(
                    ReachableOrigins::new(std::iter::empty(), std::iter::empty())
                        .expect("the table's own origins are valid"),
                    std::iter::empty(),
                )
                .expect("an empty allow list is always valid"),
                served_origins: Vec::new(),
                allowed_direct: Vec::new(),
                clients: Clients::new(
                    client.clone(),
                    &Upstreams::defaults(),
                    DEFAULT_MAX_METADATA_BYTES,
                ),
                client,
                upstreams: Upstreams::defaults(),
                policy: None,
                audit: None,
                intel: None,
                max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
                rewrite_artifacts: true,
                public_base: None,
                refusal: RefusalStatus::default(),
                refuse_unservable: true,
                #[cfg(debug_assertions)]
                defer_test: None,
            }),
            store: Arc::new(Mutex::new(RecordStore::new(DEFAULT_MAX_RECORDS))),
            verified: Arc::new(Mutex::new(VerifiedArtifacts::new(DEFAULT_MAX_VERIFIED))),
            coverage: Arc::new(Mutex::new(None)),
            metadata_slots: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_METADATA)),
        };
        proxy.rebuilt()
    }

    /// Where `ecosystem`'s requests are forwarded. Defaults to its public registry.
    ///
    /// Panics on an address that is not a URL with a host. `env::Env::upstreams` refuses
    /// the same addresses, so only a caller that skips it reaches the panic, and nothing
    /// else would work with that upstream either.
    pub fn with_upstream(mut self, ecosystem: Ecosystem, upstream: impl AsRef<str>) -> Self {
        let upstreams = self
            .config
            .upstreams
            .clone()
            .with(ecosystem, upstream.as_ref());
        self.config_mut().upstreams = upstreams;
        self.rebuilt()
    }

    /// Every upstream at once, as `env::Env::upstreams` reads them.
    pub fn with_upstreams(mut self, upstreams: Upstreams) -> Self {
        self.config_mut().upstreams = upstreams;
        self.rebuilt()
    }

    /// Debug builds only. See [`crate::defer`].
    #[cfg(debug_assertions)]
    pub fn with_defer_test(mut self, defer_test: Option<DeferTest>) -> Self {
        // The instant is taken here rather than at parse, so a bounded deferral is
        // measured from when the proxy started rather than from when the spec was read.
        self.config_mut().defer_test = defer_test.map(|d| (d, Instant::now()));
        self
    }

    pub fn with_refusal_status(mut self, refusal: RefusalStatus) -> Self {
        self.config_mut().refusal = refusal;
        self
    }

    /// Whether versions whose artifacts this proxy cannot serve are removed from the
    /// packument. On by default; see [`crate::ecosystem::npm::filter_unservable_versions`].
    pub fn with_refuse_unservable(mut self, refuse: bool) -> Self {
        self.config_mut().refuse_unservable = refuse;
        self
    }

    pub fn with_max_concurrent_documents(mut self, limit: usize) -> Self {
        self.metadata_slots = Arc::new(Semaphore::new(limit.max(1)));
        self
    }

    /// Additional origins whose artifacts this proxy serves, beyond the upstream and the
    /// default registry, and origins it permits a client to fetch directly.
    pub fn with_origin_policy<'a>(
        mut self,
        served: impl IntoIterator<Item = &'a str>,
        allowed_direct: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, crate::origin::OriginError> {
        let served: Vec<String> = served.into_iter().map(str::to_owned).collect();
        let allowed_direct: Vec<String> = allowed_direct.into_iter().map(str::to_owned).collect();
        self.config_mut().origins = self.origin_policy_for(&served, &allowed_direct)?;
        self.config_mut().served_origins = served;
        self.config_mut().allowed_direct = allowed_direct;
        Ok(self)
    }

    /// The policy every decision reads, when one is configured.
    pub fn policy(&self) -> Option<&Policy> {
        self.config.policy.as_deref()
    }

    pub fn origin_policy(&self) -> &OriginPolicy {
        &self.config.origins
    }

    /// What this proxy is and how it is configured. Served at [`HEALTH_PATH`].
    pub fn health(&self) -> Health {
        let (packages_held, records_held) = {
            let store = self.store.lock().expect("record store lock");
            (store.len(), store.records())
        };
        Health {
            service: "waharoa".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            upstreams: self
                .config
                .upstreams
                .iter()
                .map(|(ecosystem, base)| (ecosystem.as_str().to_owned(), base.to_owned()))
                .collect(),
            public_base: self.config.public_base.clone(),
            rewrite_artifacts: self.config.rewrite_artifacts,
            refuse_unservable: self.config.refuse_unservable,
            served_origins: self.config.origins.reachable().as_slice().to_vec(),
            allowed_direct_origins: self.config.origins.allowed_direct().to_vec(),
            packages_held,
            records_held,
            artifacts_verified: self.verified.lock().expect("verified artifacts lock").len(),
        }
    }

    /// The store every decision asks, when a policy is there to ask it. See [`intel_for`].
    fn consulted_intel(&self) -> Option<&dyn Intel> {
        self.config.policy.as_ref()?;
        self.config.intel.as_deref()
    }

    /// Whether every package can be decided on now. Served at [`READY_PATH`].
    pub async fn readiness(&self) -> Readiness {
        let Some(store) = self.consulted_intel() else {
            return Readiness {
                ready: true,
                intel: IntelState::NotConsulted,
                snapshot: None,
            };
        };
        let (intel, snapshot) = match store.snapshot().await {
            Ok(Some(snapshot)) => (IntelState::Loaded, Some(snapshot)),
            Ok(None) => (IntelState::Empty, None),
            Err(e) => {
                // Logged, not sent, as in `intel_for`.
                error!(why = %e, "intel store cannot answer; not ready");
                (IntelState::Unavailable, None)
            }
        };
        Readiness {
            ready: intel == IntelState::Loaded,
            intel,
            snapshot,
        }
    }

    pub fn with_artifact_rewriting(mut self, rewrite: bool) -> Self {
        self.config_mut().rewrite_artifacts = rewrite;
        self
    }

    /// Override the address written into artifact URLs. Without it the request's `Host`
    /// is used, which is what the client already reached the proxy on.
    pub fn with_public_base(mut self, base: Option<String>) -> Self {
        self.config_mut().public_base = base.map(|b| b.trim_end_matches('/').to_owned());
        self
    }

    /// How many verified artifact digests are remembered. See [`crate::verified`].
    pub fn with_max_verified(mut self, max_verified: usize) -> Self {
        self.verified = Arc::new(Mutex::new(VerifiedArtifacts::new(max_verified)));
        self
    }

    pub fn with_max_records(self, max_records: usize) -> Self {
        Self {
            store: Arc::new(Mutex::new(RecordStore::new(max_records))),
            ..self
        }
    }

    pub fn with_audit_log(mut self, audit: Option<Arc<AuditLog>>) -> Self {
        self.config_mut().audit = audit;
        self
    }

    pub fn with_policy(mut self, policy: Option<Arc<Policy>>) -> Self {
        self.config_mut().policy = policy;
        self
    }

    pub fn with_intel(mut self, intel: Option<Arc<dyn Intel>>) -> Self {
        self.config_mut().intel = intel;
        self
    }

    pub fn with_max_metadata_bytes(mut self, limit: usize) -> Self {
        self.config_mut().max_metadata_bytes = limit;
        // The proxy's own fetches decode under the same ceiling as the bodies it
        // forwards, so one setting means one limit.
        self.rebuilt()
    }

    /// The clients and origin policy for the configured upstreams, origins and body limit.
    /// Every builder that changes one of those ends here, so the order they are called in
    /// does not matter.
    fn rebuilt(mut self) -> Self {
        let clients = Clients::new(
            self.config.client.clone(),
            &self.config.upstreams,
            self.config.max_metadata_bytes,
        );
        let origins = self
            .origin_policy_for(&self.config.served_origins, &self.config.allowed_direct)
            .unwrap_or_else(|e| panic!("upstream is not a usable origin: {e}"));
        let config = self.config_mut();
        config.clients = clients;
        config.origins = origins;
        self
    }

    /// The configuration, for a builder to change. Builders run before the proxy serves, so
    /// the copy-on-write copies nothing.
    fn config_mut(&mut self) -> &mut Config {
        Arc::make_mut(&mut self.config)
    }

    fn origin_policy_for(
        &self,
        served: &[String],
        allowed_direct: &[String],
    ) -> Result<OriginPolicy, crate::origin::OriginError> {
        let reachable = ReachableOrigins::new(
            self.config.upstreams.bases(),
            served.iter().map(String::as_str),
        )?;
        OriginPolicy::new(reachable, allowed_direct.iter().map(String::as_str))
    }

    pub fn upstreams(&self) -> &Upstreams {
        &self.config.upstreams
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
    /// The claim being proved, recorded as verified once the bytes match.
    sri: Sri,
    verified: Arc<Mutex<VerifiedArtifacts>>,
}

impl VerifyingStream {
    fn new(
        inner: ByteStream,
        sri: &Sri,
        path: String,
        purl: String,
        verified: Arc<Mutex<VerifiedArtifacts>>,
    ) -> Self {
        Self {
            inner,
            verifier: Some(sri.verifier()),
            held: None,
            finished: false,
            bytes: 0,
            path,
            purl,
            sri: sri.clone(),
            verified,
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
                // Recorded here and nowhere else: the digest is a claim until bytes have
                // been hashed against it.
                self.verified
                    .lock()
                    .expect("verified artifacts lock")
                    .record(self.sri.clone());
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
///
/// Keyed by ecosystem as well as client, because the same client name means different
/// things across them and an operator tunes one without moving the other. Before both
/// ecosystems were served this passed npm unconditionally, which made a `pypi/...` entry
/// unreachable.
fn refusal_status(proxy: &Proxy, ecosystem: Ecosystem, user_agent: Option<&str>) -> StatusCode {
    let code = proxy.config.refusal.for_client(ecosystem, user_agent);
    // Unreachable: `RefusalStatus` is only ever built by `parse`, which refuses anything
    // outside 400..=599, or by `default`, which is 403. Kept rather than unwrapped
    // because a panic here would take down a request handler, and 403 is what the
    // default would have been anyway.
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

/// Fetch the metadata document the client did not ask for, and keep its records.
///
/// Each ecosystem asks its own registry: npm the abbreviated packument, PyPI the simple
/// index. `key` carries the ecosystem, and [`Clients::metadata`] chooses by it.
///
/// Failure is not fatal and is not propagated. The artifact is forwarded unverified and
/// said to be unverified, which is Stage 1 behaviour; Stage 2 has to decide whether that
/// stays allowed.
async fn fetch_and_store(proxy: &Proxy, key: &PackageKey, path: &str) {
    let started = Instant::now();
    match proxy.config.clients.metadata(key).await {
        Ok(Ok(metadata)) => {
            let versions = metadata.records.len();
            proxy
                .store
                .lock()
                .expect("record store lock")
                .insert(metadata);
            info!(
                path = %path,
                purl = %key,
                versions,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "fetched metadata on our own behalf, which the client never requested"
            );
        }
        Ok(Err(e)) => {
            warn!(path = %path, purl = %key, error = %e, "metadata fetched but did not normalize")
        }
        Err(e) => warn!(path = %path, purl = %key, error = %e, "could not fetch metadata"),
    }
}

/// Why a metadata document is forwarded without the proxy being able to see what a client
/// does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Uninspected {
    /// The client accepts no encoding this build can decode, so the body cannot be read.
    Unreadable,
    /// No `Host` header and no configured public base, so there is no address to point
    /// artifact URLs at.
    NoBase,
}

impl Uninspected {
    fn reason(self) -> &'static str {
        match self {
            Self::Unreadable => "client accepts no encoding this can read",
            Self::NoBase => {
                "no Host header and no configured public base, so artifact URLs cannot be \
                 pointed at the proxy"
            }
        }
    }
}

/// Whether this request leaves a package's artifacts unexamined, and why.
///
/// `None` on every request that is not a metadata GET, and on a packument the proxy is
/// about to rewrite. An operator who turned rewriting off is also `None`: that is a
/// configured choice, not a case the proxy failed to handle.
///
/// Measured 2026-09-16 with pip 26.1.1 installing `requests` through this proxy before the
/// index was rewritten: five `/simple/` pages arrived and no `/packages/` request did. The
/// index gives each file's URL in full on `files.pythonhosted.org` and pip uses it as
/// written, so every file was fetched around the proxy. That is the PyPI shape of
/// `docs/engineering_decisions/packument-tarball-url-rewriting.md`, and it is why both
/// document kinds reach this check.
fn uninspected(
    target: &RequestTarget,
    method: &Method,
    encoding: RequestedEncoding,
    rewrite_base: Option<&str>,
    rewriting: bool,
) -> Option<Uninspected> {
    if method != Method::GET || !matches!(target, RequestTarget::Metadata(_)) {
        return None;
    }
    if rewriting {
        return None;
    }
    if encoding == RequestedEncoding::Unreadable {
        return Some(Uninspected::Unreadable);
    }
    if rewrite_base.is_none() {
        return Some(Uninspected::NoBase);
    }
    None
}

/// Whether this request is the resolver looking rather than the client installing.
///
/// A PyPI request that is neither a project index nor a file is a PEP 658
/// `<file>.metadata` probe, and there are two orders of magnitude more of them than
/// installs: measured 2026-09-16, `pip install boto3 'botocore<1.34' s3transfer` made 679
/// of them and fetched 7 artifacts. At INFO they bury the 7 lines an operator needs, so
/// they are logged at DEBUG.
///
/// Nothing else changes. A probe names a file the resolver is considering, not one it is
/// installing, so it gets no record lookup, no policy decision and no audit entry: of the
/// 679, zero produced any of the three.
///
/// Which ecosystem's unclassified requests are probes is its row's `other_is_probe`.
fn resolver_probe(ecosystem: Ecosystem, target: &RequestTarget) -> bool {
    crate::ecosystem::of(ecosystem).other_is_probe && matches!(target, RequestTarget::Other)
}

/// Where a request goes upstream: an origin the operator added for artifacts, else the
/// ecosystem's own rule, its row's `upstream_url`, applied to its configured base.
fn upstream_url(
    proxy: &Proxy,
    ecosystem: Ecosystem,
    path_and_query: &str,
    artifact_origin: Option<&str>,
) -> String {
    // An origin the operator added for artifacts wins for either ecosystem: that is what
    // the additional-origins list is for.
    if let Some(origin) = artifact_origin {
        return format!("{origin}{path_and_query}");
    }
    (ecosystem::of(ecosystem).upstream_url)(proxy.config.upstreams.get(ecosystem), path_and_query)
}

/// The upstream response's headers, less the hop-by-hop ones.
fn upstream_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in upstream {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    headers
}

/// A 304 for a metadata document: refill the store if its records are gone, and mark the
/// `ETag` the client is told to keep.
async fn revalidated(
    proxy: &Proxy,
    target: &RequestTarget,
    negotiation: &Negotiation,
    headers: &mut HeaderMap,
    path: &str,
) {
    // A warm client cache sends If-None-Match, and 304 carries no body, so there is
    // nothing to normalise from this response. The client is about to resolve against a
    // document the proxy cannot see.
    //
    // When the records are still held that does not matter: the 304 only revalidates a
    // body this proxy produced, so it was normalised when it was first served. When they
    // are not, because the proxy restarted or the entry was evicted, the packument is
    // fetched here so the metadata is in hand before the artifact requests arrive rather
    // than one lazy fetch at a time.
    if let RequestTarget::Metadata(key) = target {
        let held = proxy.store.lock().expect("record store lock").holds(key);
        info!(
            path = %path,
            purl = %key,
            etag = headers.get(header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("-"),
            held,
            "metadata not modified, nothing to normalize"
        );
        if !held {
            fetch_and_store(proxy, key, path).await;
        }
    }

    // A 304 carries the upstream's own `ETag`, and the client stores whatever comes back.
    // Left alone it replaces the marked tag with the upstream's, `unmark_if_none_match`
    // drops that tag on the next revalidation, and the client gets a full body. Measured
    // over four requests for lodash before this: 200 (68,970 bytes), 304, 200, 304. After:
    // 200, then 304 every time.
    //
    // The body the client is being told to keep is one this proxy rewrote at this base,
    // because that is the only tag the request could have carried to get a 304 here.
    if negotiation.rewriting
        && let Some(base) = negotiation.rewrite_base.as_deref()
        && let Some(marked) = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|etag| mark_etag(etag, base))
        && let Ok(value) = HeaderValue::from_str(&marked)
    {
        headers.insert(header::ETAG, value);
    }
}

/// Wait for a slot to decode, read and rewrite a metadata document in.
///
/// Queue after the body is read, not before. The encoded body is already in hand and the
/// upstream connection is finished, so waiting costs only time. Waiting with the response
/// still streaming stalls it until it times out: measured with the acquire placed before
/// the read, 18 of 24 concurrent requests failed with "error decoding response body".
///
/// What this bounds is the expensive part. The decoded copy, the value tree the rewrite
/// walks, the re-serialised output and the gzip buffer are live together, and 24
/// simultaneous large packuments reached 1,348 MB while the encoded bodies totalled
/// 27.6 MB.
async fn metadata_slot(proxy: &Proxy, path: &str) -> tokio::sync::OwnedSemaphorePermit {
    let queued = Instant::now();
    let slot = proxy
        .metadata_slots
        .clone()
        .acquire_owned()
        .await
        .expect("the semaphore is never closed");
    let waited = queued.elapsed();
    if waited.as_millis() > 0 {
        debug!(
            path = %path,
            waited_ms = waited.as_millis() as u64,
            "waited for a metadata slot"
        );
    }
    slot
}

/// The versions a policy removed from one document, and which checks removed them.
#[derive(Default)]
struct Refused {
    versions: HashSet<String>,
    /// Each check that removed at least one version, in name order.
    checks: Vec<String>,
}

/// What the proxy does with a metadata document it has read.
enum DocumentStep {
    /// The proxy answers in place of the document: no intel to filter it with.
    Answer(Response),
    /// Send the document on, saying what the policy took out of it.
    Forward {
        /// The rewritten document, or `None` to forward the upstream's bytes.
        body: Option<Vec<u8>>,
        refused: Refused,
    },
}

/// Decode, read, filter by policy and rewrite a metadata document.
async fn filtered_document(
    proxy: &Proxy,
    document: DocumentKind,
    body: &Bytes,
    content_encoding: Option<&str>,
    negotiation: &Negotiation,
    path: &str,
) -> DocumentStep {
    // Decoded once. Normalising and the store read these bytes; the rewrite below works
    // on a copy. Building records from the rewritten document instead would set every
    // artifact URL to the proxy's own origin, which is both the wrong thing to store as
    // the upstream's claim and enough to make the offsite check report every package.
    let parse_started = Instant::now();
    let decoded = match decode_for_parsing(body, content_encoding, proxy.config.max_metadata_bytes)
    {
        Ok(decoded) => decoded,
        Err(e) => {
            warn!(path = %path, error = %e, "UNINSPECTED: metadata body could not be decoded");
            return DocumentStep::Forward {
                body: None,
                refused: Refused::default(),
            };
        }
    };

    // Each document kind is read by its own normaliser, and a `match` rather than a test
    // and a fall-through: a third kind has to answer this rather than reach whichever arm
    // was written last.
    let read = match document {
        DocumentKind::Packument(detail) => npm::read_packument(
            &decoded,
            detail,
            &proxy.store,
            &proxy.config.origins,
            body.len(),
            parse_started,
            path,
        )
        .map(Read::Packument),
        DocumentKind::SimpleIndex(format) => {
            // The page's own URL, because a PEP 503 href may be relative to it. It is the
            // URL this body was fetched from, which `upstream_url` built for the request.
            let page = upstream_url(proxy, Ecosystem::PyPI, path, None);
            pypi::read_index(&decoded, format, &page, &proxy.store, path).map(Read::SimpleIndex)
        }
    };
    let Some(read) = read else {
        return DocumentStep::Forward {
            body: None,
            refused: Refused::default(),
        };
    };
    report_undated(proxy, &read, path);
    let normalized = read.metadata();

    // Asked once per document rather than once per version: typescript has 3,823.
    let intel = match normalized {
        Some(metadata) => match intel_for(proxy, &metadata.key, path).await {
            Ok(intel) => intel,
            Err(IntelUnavailable::Uncovered(uncovered))
                if ecosystem::of(uncovered).uncovered_metadata
                    == UncoveredMetadata::FilterWithoutIntel =>
            {
                warn!(
                    path = %path,
                    "filtering without intel; the artifact request answers 503"
                );
                None
            }
            Err(unavailable) => return DocumentStep::Answer(unavailable.response()),
        },
        None => None,
    };

    // Not gated on `rewriting`. Filtering refused versions is a policy question and
    // repointing artifact URLs is a transport one, and tying them together meant that
    // turning rewriting off, which `docs/engineering_decisions/enforcement-tiers.md` says
    // is correct once the proxy terminates TLS, silently stopped the policy filtering
    // with it.
    //
    // Decision #4's resolution half. A version the policy refuses is dropped from the
    // document, so the client's own resolver picks one that is allowed and the install
    // succeeds without anyone being told no. The pinned half, where there is no resolution
    // left to influence, refuses at the artifact request.
    let refused_by_policy = match normalized {
        Some(metadata) => policy_refused_versions(
            metadata,
            proxy.config.policy.as_deref(),
            intel.as_ref(),
            path,
            proxy.config.audit.as_deref(),
        ),
        None => Refused::default(),
    };
    let base = negotiation
        .rewriting
        .then_some(negotiation.rewrite_base.as_deref())
        .flatten();

    // The npm rewrite. Every client in the npm ecosystem has to fetch artifacts through the
    // proxy, and they do not agree about `dist.tarball`: npm rewrites it to the
    // configured registry, pnpm 10 and yarn 1 use it verbatim. Pointing it here makes
    // them behave alike.
    //
    // It needs the records, so a packument that did not normalise is not rewritten either.
    // That is the honest outcome: without records there is nothing to gate on anyway, and
    // it is already logged as UNINSPECTED. A simple index that parsed but did not
    // normalise still has its files repointed, because the file request is where PyPI's
    // digest is checked.
    let body = match &read {
        Read::Packument(packument) => npm::rewrite_packument(npm::Rewrite {
            decoded: &decoded,
            packument,
            base,
            origins: &proxy.config.origins,
            refused_by_policy: &refused_by_policy.versions,
            refuse_unservable: proxy.config.refuse_unservable,
            path,
        }),
        Read::SimpleIndex(index) => pypi::rewrite::rewrite_index(pypi::rewrite::Rewrite {
            decoded: &decoded,
            format: index.format,
            project: &index.project,
            reachable: proxy.config.origins.reachable(),
            base,
            refused_by_policy: &refused_by_policy.versions,
            path,
        }),
    };
    DocumentStep::Forward {
        body,
        refused: refused_by_policy,
    }
}

/// How a request's metadata document is asked for and read, decided from the request and
/// the proxy's configuration before anything goes upstream.
#[derive(Debug, PartialEq, Eq)]
struct Negotiation {
    /// The encoding asked of upstream on a document the proxy reads.
    encoding: RequestedEncoding,
    /// The body is read: a metadata GET, in an encoding this build can decode. Both
    /// ecosystems: a packument and a simple index are both read so their artifact URLs can
    /// be pointed at the proxy.
    read_metadata: bool,
    /// The address artifact URLs are pointed at. See [`public_base`].
    rewrite_base: Option<String>,
    /// Artifact URLs are pointed at the proxy.
    rewriting: bool,
    /// Under a cooldown, an ecosystem that publishes version times only in its full
    /// document is asked for that document, whatever the client asked for, so every record
    /// read from it carries its own publish time. The client is served the full document,
    /// filtered and rewritten; npm clients read it as they read the abbreviated one.
    full_document: bool,
}

fn negotiate(
    proxy: &Proxy,
    ecosystem: Ecosystem,
    target: &RequestTarget,
    method: &Method,
    headers: &HeaderMap,
) -> Negotiation {
    let encoding = encoding_to_request(
        headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok()),
    );
    let read_metadata = method == Method::GET
        && matches!(target, RequestTarget::Metadata(_))
        && encoding != RequestedEncoding::Unreadable;
    let rewrite_base = public_base(headers, proxy.config.public_base.as_deref());
    let rewriting = read_metadata && proxy.config.rewrite_artifacts && rewrite_base.is_some();
    let full_document = read_metadata
        && ecosystem::of(ecosystem).publish_times == ecosystem::PublishTimeSource::FullPackument
        && proxy
            .config
            .policy
            .as_deref()
            .is_some_and(Policy::uses_cooldown);
    Negotiation {
        encoding,
        read_metadata,
        rewrite_base,
        rewriting,
        full_document,
    }
}

/// Log a metadata document forwarded without rewriting.
///
/// Every such path leaves that package's artifacts to be fetched wherever the document
/// says, which for pnpm, yarn and pip means not through the proxy. They all carry the same
/// marker so one grep finds them.
fn report_uninspected(
    target: &RequestTarget,
    method: &Method,
    negotiation: &Negotiation,
    headers: &HeaderMap,
    path: &str,
) {
    match uninspected(
        target,
        method,
        negotiation.encoding,
        negotiation.rewrite_base.as_deref(),
        negotiation.rewriting,
    ) {
        Some(Uninspected::Unreadable) => warn!(
            path = %path,
            accept_encoding = headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-"),
            "UNINSPECTED: {}", Uninspected::Unreadable.reason()
        ),
        Some(reason) => warn!(path = %path, "UNINSPECTED: {}", reason.reason()),
        None => {}
    }
}

/// The headers sent upstream: the client's, less those that stop at the proxy, with the
/// encoding, `Accept` and `If-None-Match` the negotiation needs.
fn upstream_headers(client: &HeaderMap, negotiation: &Negotiation, path: &str) -> HeaderMap {
    let mut outbound = HeaderMap::new();
    for (name, value) in client {
        // `Authorization` is the client's credential for this proxy, and an account's token
        // under TODO Stage 8. Forwarded, it reached registry.npmjs.org and pypi.org: see
        // docs/engineering_decisions/account-identification.md.
        if is_hop_by_hop(name.as_str()) || name == header::HOST || name == header::AUTHORIZATION {
            continue;
        }
        if negotiation.read_metadata && name == header::ACCEPT_ENCODING {
            continue;
        }
        if negotiation.full_document && name == header::ACCEPT {
            continue;
        }
        if negotiation.rewriting && is_conditional(name.as_str()) {
            continue;
        }
        outbound.append(name, value.clone());
    }
    if negotiation.read_metadata
        && let Some(value) = negotiation.encoding.header_value()
    {
        outbound.append(header::ACCEPT_ENCODING, HeaderValue::from_static(value));
    }
    if negotiation.full_document {
        outbound.append(header::ACCEPT, HeaderValue::from_static(npm::FULL_ACCEPT));
    }
    // An `If-None-Match` the client got from us names our rewritten body, not the
    // upstream's. Turn it back, or drop it when it came from a proxy at another address.
    if negotiation.rewriting
        && let Some(inm) = client
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
        && let Some(base) = negotiation.rewrite_base.as_deref()
    {
        match unmark_if_none_match(inm, base).map(|v| HeaderValue::from_str(&v)) {
            Some(Ok(value)) => {
                outbound.append(header::IF_NONE_MATCH, value);
            }
            // A 304 would let the client serve a body this proxy did not produce here,
            // whose artifact URLs were never pointed at it. Dropping the header makes the
            // registry send a body to rewrite afresh.
            _ => info!(
                path = %path,
                "dropped a conditional request for a body this proxy did not rewrite"
            ),
        }
    }
    outbound
}

/// An artifact GET, as `handle` classified it.
struct ArtifactRequest<'a> {
    ecosystem: Ecosystem,
    method: &'a Method,
    key: &'a PackageKey,
    claimed_version: &'a str,
    filename: &'a str,
    path: &'a str,
    client: &'a str,
}

/// What the proxy does with an artifact GET, decided before a byte is fetched.
enum ArtifactStep {
    /// The proxy answers without asking upstream: refused by policy, published on an origin
    /// the proxy does not serve, or no intel to decide with.
    Answer(Response),
    /// Fetch it upstream.
    Fetch(ArtifactFetch),
}

/// How to fetch an artifact and check what arrives.
#[derive(Default)]
struct ArtifactFetch {
    /// The purl the request claims, for the verifier's log lines. Empty on a request that
    /// is not an artifact GET.
    purl: String,
    /// The digest the metadata published. `None` forwards the bytes unverified.
    digest: Option<Sri>,
    /// An origin the operator added, when the metadata published the artifact there.
    /// `None` sends the request to the ecosystem's upstream.
    origin: Option<String>,
}

/// Look up the record for an artifact, decide on it, and say how to fetch it.
///
/// Decision #4's pinned half. This is the first point where the exact version and its
/// record are both in hand, and it is still before a byte is fetched.
async fn decide_artifact(proxy: &Proxy, request: ArtifactRequest<'_>) -> ArtifactStep {
    let ArtifactRequest {
        ecosystem,
        method,
        key,
        claimed_version,
        filename,
        path,
        client,
    } = request;
    let purl = key
        .at_version(claimed_version)
        .map(|r| r.to_string())
        .unwrap_or_else(|_| format!("{key}@{claimed_version}"));
    let mut fetch = ArtifactFetch {
        purl: purl.clone(),
        ..ArtifactFetch::default()
    };
    let found = match lookup_or_fetch(proxy, key, claimed_version, path).await {
        Lookup::Found(found) => found,
        // The packument was read and does not name this version. A tarball filename
        // that spells the version differently lands here: `express@3.0.0-rc1` is
        // served at `express-3.0.0rc1.tgz`.
        Lookup::NoSuchVersion => {
            warn!(
                path = %path,
                claimed_purl = %purl,
                "artifact requested, but its metadata does not list this version"
            );
            return ArtifactStep::Fetch(fetch);
        }
        // Nothing was observed for this package, and fetching its packument did not
        // help either.
        Lookup::Unknown => {
            warn!(
                path = %path,
                claimed_purl = %purl,
                "artifact requested, no metadata seen for it"
            );
            return ArtifactStep::Fetch(fetch);
        }
    };

    // The lookup is by version; the request is for a file. On npm those are the same
    // thing. On PyPI one version offers a wheel and an sdist, with different digests and
    // different install behaviour, so everything below decides about the file that was
    // asked for rather than the version.
    let narrowed = found.narrowed_to(filename);
    if narrowed.is_none() {
        warn!(
            path = %path,
            claimed_purl = %purl,
            filename = %filename,
            "the record names no file by this name; deciding on the version's first file"
        );
    }
    let record: &PackageRecord = narrowed.as_ref().unwrap_or(&found);
    let artifact = record.artifact();
    info!(
        path = %path,
        claimed_purl = %purl,
        integrity = artifact
            .and_then(|a| a.integrity.as_deref())
            .unwrap_or("-"),
        has_install_scripts = record.has_install_scripts,
        // Reported, not refused: see docs/engineering_decisions/yanked-files.md.
        deprecated = record.deprecated.as_deref().unwrap_or("-"),
        "artifact requested, digest known"
    );
    // A record read from a full document carries its own publish time; only one without
    // it needs the time fetched.
    let times = match record.published_at {
        Some(_) => None,
        None => match publish_times_for(proxy, key).await {
            Some(times) => Some(times),
            // The index gave no date for this version, so the file host is asked for one.
            None => dated_by_host(proxy, record, path).await,
        },
    };
    let intel = match intel_for(proxy, key, path).await {
        Ok(intel) => intel,
        Err(unavailable) => return ArtifactStep::Answer(unavailable.response()),
    };
    audit_pinned(proxy, record, times.as_ref(), intel.as_ref());
    let policy_refusal = match enforce::artifact(
        proxy.config.policy.as_deref(),
        record,
        times.as_ref(),
        intel.as_ref(),
        crate::policy::today(),
    ) {
        enforce::Verdict::Refuse(refusal) => Some(refusal),
        _ => None,
    };
    // Where the packument said the artifact lives, when that is an origin the operator
    // added. Rewriting pointed the client at the proxy, so the proxy has to know where
    // "here" stood for. Everything else goes to the upstream, including artifacts
    // advertised on the default registry: a private mirror publishes those URLs and is
    // the reason the proxy was pointed at it.
    let artifact_url = artifact.map(|a| a.url.as_str()).unwrap_or("");
    fetch.origin = crate::origin::origin_of_url(artifact_url)
        .filter(|origin| proxy.config.origins.reachable().routes_directly(origin));
    let unservable_origin = match proxy.config.origins.disposition(artifact_url) {
        Disposition::Refused(origin) => Some(origin),
        _ => None,
    };
    match artifact
        .and_then(|a| a.integrity.as_deref())
        .map(Sri::parse)
    {
        Some(Ok(sri)) => {
            // Plan §5's branch, decided before a byte is fetched. In Stage 1 both arms do
            // the same thing, because nothing analyses and nothing defers; a hit is where
            // Stage 5 skips the analysis it already ran, and a miss is where the
            // novel-artifact branches go. The hit arm still hashes: see `crate::verified`.
            let seen = proxy
                .verified
                .lock()
                .expect("verified artifacts lock")
                .lookup(&sri);
            info!(
                path = %path,
                claimed_purl = %purl,
                digest = %sri,
                cache = seen.as_str(),
                "artifact cache consulted"
            );
            fetch.digest = Some(sri);
        }
        Some(Err(e)) => warn!(
            path = %path,
            claimed_purl = %purl,
            error = %e,
            "metadata integrity string is unusable; not verifying"
        ),
        // Two versions in 24,852 offer only SHA-1, which is collision-broken and not
        // verified here.
        None => warn!(
            path = %path,
            claimed_purl = %purl,
            "metadata publishes no strong digest; not verifying"
        ),
    }

    if let Some(refusal) = &policy_refusal {
        let status = refusal_status(proxy, ecosystem, Some(client));
        info!(
            %method,
            path = %path,
            status = status.as_u16(),
            claimed_purl = %purl,
            action = refusal.action.as_str(),
            reasons = ?refusal.reasons,
            client = %client,
            "refused by policy"
        );
        return ArtifactStep::Answer((status, refusal.message()).into_response());
    }

    // A pinned fetch of a version the packument filter removes. Decision #4: filter on
    // resolution, hard fail on a pinned fetch, because there is no resolution step left
    // to influence.
    if let Some(origin) = &unservable_origin
        && proxy.config.refuse_unservable
    {
        let status = refusal_status(proxy, ecosystem, Some(client));
        info!(
            %method,
            path = %path,
            status = status.as_u16(),
            claimed_purl = %purl,
            origin = %origin,
            client = %client,
            "refused: this artifact is published on an origin the proxy does not serve"
        );
        return ArtifactStep::Answer(
            (
                status,
                format!(
                    "waharoa: {purl} is published at {origin}, which this proxy does not \
                     serve, so it cannot be examined\n"
                ),
            )
                .into_response(),
        );
    }

    ArtifactStep::Fetch(fetch)
}

/// Write the pinned decision to the audit log, when there is a log and a policy.
///
/// Allowed decisions are written too. A log holding only refusals cannot answer "was this
/// ever evaluated", which is what `policy diff` needs a package set for.
fn audit_pinned(
    proxy: &Proxy,
    record: &PackageRecord,
    times: Option<&facts::PublishTimes>,
    intel: Option<&PackageIntel>,
) {
    let (Some(audit), Some(policy)) = (&proxy.config.audit, proxy.config.policy.as_deref()) else {
        return;
    };
    let mut facts = crate::policy::decide::Facts::from_record_and_times(record, times);
    if let Some(intel) = intel {
        facts = facts.with_intel(intel);
    }
    audit.write(
        &audit::Event::pinned(
            &facts.ecosystem,
            &facts.name,
            &facts.version,
            &crate::policy::decide::decide(policy, &facts, crate::policy::today()),
            &enforce::unenforceable(policy, record, times, facts.intel),
        )
        .with_intel_snapshot(intel.map(|i| i.snapshot.as_str())),
    );
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

    // Answered here rather than forwarded. `/-/` is the registry's own namespace and a
    // package name can never live there, so this collides with nothing a client asks for.
    match path_and_query.split('?').next() {
        Some(HEALTH_PATH) => return uncached_json(StatusCode::OK, proxy.health()),
        Some(READY_PATH) => {
            let readiness = proxy.readiness().await;
            let status = if readiness.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            return uncached_json(status, readiness);
        }
        _ => {}
    }

    let (ecosystem, target) = crate::route::classify(&path_and_query);

    #[cfg(debug_assertions)]
    if let Some((deferral, since)) = &proxy.config.defer_test
        && let Some((status, retry_after)) = deferral.applies_to(&target, since.elapsed())
    {
        return defer_response(
            status,
            retry_after,
            &method,
            &path_and_query,
            &client_ua,
            started,
        );
    }

    let negotiation = negotiate(&proxy, ecosystem, &target, &method, req.headers());
    report_uninspected(
        &target,
        &method,
        &negotiation,
        req.headers(),
        &path_and_query,
    );

    // The digest has to be known before the artifact is fetched, not after: that is what
    // decides whether this exact artifact has been analysed (plan §5).
    let artifact = match &target {
        RequestTarget::Artifact {
            key,
            claimed_version,
            filename,
        } if method == Method::GET => {
            let request = ArtifactRequest {
                ecosystem,
                method: &method,
                key,
                claimed_version,
                filename,
                path: &path_and_query,
                client: &client_ua,
            };
            match decide_artifact(&proxy, request).await {
                ArtifactStep::Answer(response) => return response,
                ArtifactStep::Fetch(fetch) => fetch,
            }
        }
        _ => ArtifactFetch::default(),
    };

    let url = upstream_url(
        &proxy,
        ecosystem,
        &path_and_query,
        artifact.origin.as_deref(),
    );
    let outbound = proxy
        .config
        .client
        .request(method.clone(), &url)
        .headers(upstream_headers(
            req.headers(),
            &negotiation,
            &path_and_query,
        ));

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

    let mut headers = upstream_response_headers(upstream_response.headers());
    let content_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let document = crate::ecosystem::of(ecosystem).document(content_type);

    if status == reqwest::StatusCode::NOT_MODIFIED {
        revalidated(&proxy, &target, &negotiation, &mut headers, &path_and_query).await;
    }

    let forward_status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let resolver_probe = resolver_probe(ecosystem, &target);
    let log_proxied = |bytes: u64| {
        if resolver_probe {
            debug!(
                %method,
                path = %path_and_query,
                status = status.as_u16(),
                bytes,
                elapsed_ms = started.elapsed().as_millis() as u64,
                client = %client_ua,
                "proxied"
            );
        } else {
            info!(
                %method,
                path = %path_and_query,
                status = status.as_u16(),
                bytes,
                elapsed_ms = started.elapsed().as_millis() as u64,
                client = %client_ua,
                "proxied"
            );
        }
    };

    let body_stream: ByteStream = Box::pin(upstream_response.bytes_stream());

    let Some(document) = document.filter(|_| negotiation.read_metadata && status.is_success())
    else {
        log_proxied(upstream_len.unwrap_or(0));
        let Some(sri) = artifact.digest else {
            return (forward_status, headers, Body::from_stream(body_stream)).into_response();
        };
        let verified = VerifyingStream::new(
            body_stream,
            &sri,
            path_and_query.clone(),
            artifact.purl,
            proxy.verified.clone(),
        );
        return (forward_status, headers, Body::from_stream(verified)).into_response();
    };

    let body = match buffer_to_limit(body_stream, proxy.config.max_metadata_bytes).await {
        Buffered::Complete(body) => body,
        Buffered::Oversized { prefix, rest } => {
            warn!(
                path = %path_and_query,
                limit = proxy.config.max_metadata_bytes,
                "UNINSPECTED: metadata document exceeds the size limit, forwarded without rewriting"
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

    let _slot = metadata_slot(&proxy, &path_and_query).await;

    let forwarded = match filtered_document(
        &proxy,
        document,
        &body,
        content_encoding.as_deref(),
        &negotiation,
        &path_and_query,
    )
    .await
    {
        DocumentStep::Answer(response) => return response,
        DocumentStep::Forward { body, refused } => {
            mark_filtered(&mut headers, &refused);
            body
        }
    };

    finish(
        forwarded,
        body,
        headers,
        forward_status,
        negotiation.encoding,
        negotiation.rewrite_base.as_deref(),
        &path_and_query,
        log_proxied,
    )
}

/// Say what the policy took out of this document, on the response that carries it.
///
/// Nothing is added when nothing was removed: an absent header is a document the policy
/// left alone, not one nobody looked at. Whether the proxy inspects at all is
/// [`HEALTH_PATH`].
fn mark_filtered(headers: &mut HeaderMap, refused: &Refused) {
    if refused.versions.is_empty() {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&refused.versions.len().to_string()) {
        headers.insert(FILTERED_VERSIONS, value);
    }
    if let Ok(value) = HeaderValue::from_str(&refused.checks.join(",")) {
        headers.insert(FILTERED_CHECKS, value);
    }
}

/// Send the document on, rewritten or not.
///
/// A rewritten body is this proxy's, so its length, its encoding and its entity tag all
/// have to describe it rather than the upstream's. `None` forwards the upstream's bytes
/// untouched, headers included.
#[allow(clippy::too_many_arguments)]
fn finish(
    forwarded: Option<Vec<u8>>,
    body: Bytes,
    mut headers: HeaderMap,
    forward_status: StatusCode,
    chosen_encoding: RequestedEncoding,
    rewrite_base: Option<&str>,
    path_and_query: &str,
    log_proxied: impl Fn(u64),
) -> Response {
    let body = match forwarded {
        Some(rewritten) => {
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
                .map(|etag| mark_etag(etag, rewrite_base.unwrap_or_default()))
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

/// Build the deferral response, and log the attempt so the harness can count retries.
///
/// The body says which request was turned away, so a client that logs it gives an
/// operator something to act on. Debug builds only; see [`crate::defer`].
#[cfg(debug_assertions)]
fn defer_response(
    status: u16,
    retry_after: Option<u32>,
    method: &Method,
    path_and_query: &str,
    client_ua: &str,
    started: Instant,
) -> Response {
    // Checked against 400..=599 when the spec was parsed.
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let mut headers = HeaderMap::new();
    if let Some(seconds) = retry_after
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        headers.insert(header::RETRY_AFTER, value);
    }
    info!(
        %method,
        path = %path_and_query,
        status,
        retry_after = retry_after.map(|s| s.to_string()).unwrap_or_else(|| "-".to_owned()),
        client = %client_ua,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "deferred ({})",
        crate::env::DEFER_TEST
    );
    (
        code,
        headers,
        format!("waharoa: {path_and_query} is deferred, not refused\n"),
    )
        .into_response()
}

/// Publish times for this package, fetched from the registry now.
///
/// Not kept between requests: a map filled once lacked every version published after it, and
/// a version with no time is one `cooldown_days` cannot hold back, so the newest version, the
/// one the check exists for, went through. Asked only for a record that carries no
/// `published_at`, which under a cooldown is an artifact whose document this proxy has not
/// read: a metadata request under a cooldown reads the full document, whose records carry it.
///
/// `None` when the policy uses no cooldown, and for an ecosystem whose records carry
/// `published_at`, which [`Clients::publish_times`] answers without a request. A fetch that
/// fails is not fatal: the check it feeds reports itself as unenforceable.
async fn publish_times_for(proxy: &Proxy, key: &PackageKey) -> Option<facts::PublishTimes> {
    if !proxy
        .config
        .policy
        .as_deref()
        .is_some_and(Policy::uses_cooldown)
    {
        return None;
    }
    let started = Instant::now();
    let times = match proxy.config.clients.publish_times(key).await {
        Ok(Some(times)) => times,
        Ok(None) => return None,
        Err(e) => {
            warn!(purl = %key, error = %e, "no publish times for this package");
            return None;
        }
    };
    info!(
        purl = %key,
        versions = times.len(),
        fetch_ms = started.elapsed().as_millis() as u64,
        "publish times read from the full packument"
    );
    Some(times)
}

/// Say when a cooldown cannot be answered while filtering this document.
///
/// A PEP 503 page carries no publish time and almost none adds one, so every version it
/// lists is undated and `cooldown_days` is dropped for each. The check still bites on the
/// artifact request, where [`dated_by_host`] asks the file host, so this says which of the
/// two an operator has rather than reporting the check as unenforceable and stopping.
fn report_undated(proxy: &Proxy, read: &Read, path: &str) {
    if !proxy
        .config
        .policy
        .as_deref()
        .is_some_and(Policy::uses_cooldown)
    {
        return;
    }
    let Some(metadata) = read.metadata() else {
        return;
    };
    let undated = metadata
        .records
        .iter()
        .filter(|record| record.published_at.is_none())
        .count();
    if undated == 0 {
        return;
    }
    warn!(
        path = %path,
        undated,
        versions = metadata.records.len(),
        "cooldown_days cannot be answered while filtering this document; a pinned fetch of \
         one of these versions is decided on the file's own date"
    );
}

/// The publish time read from the file itself, for a record whose index gave none.
///
/// A PEP 503 page has no field for a publish time and almost no index adds one, so
/// `cooldown_days` would be unenforceable for every version such an index lists. The file
/// host answers `Last-Modified`, and for an immutable artifact that is when it was
/// published: measured against PyPI's own upload times on 2026-09-21, files.pythonhosted.org
/// was within 4 seconds on six files, against a check measured in days.
///
/// One `HEAD` per artifact decision that needs it, on the pinned path only. The resolution
/// filter decides every version on the page at once, and one request per version is
/// thousands for `download.pytorch.org/whl/torch/`.
///
/// `None` leaves the check unenforceable, which is what it already was. A mirror that
/// rewrote the object makes the file look newer and holds it longer, which is the safe
/// direction.
async fn dated_by_host(
    proxy: &Proxy,
    record: &PackageRecord,
    path: &str,
) -> Option<facts::PublishTimes> {
    if !proxy
        .config
        .policy
        .as_deref()
        .is_some_and(Policy::uses_cooldown)
    {
        return None;
    }
    let url = record.artifact()?.url.as_str();
    let started = Instant::now();
    let response = match proxy.config.client.head(url).send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            warn!(path = %path, status = response.status().as_u16(), "no publish time: the file host refused a HEAD");
            return None;
        }
        Err(e) => {
            warn!(path = %path, error = %e, "no publish time: the file host could not be asked");
            return None;
        }
    };
    let last_modified = response
        .headers()
        .get(header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::http::http_date)?;
    info!(
        path = %path,
        published = %last_modified,
        fetch_ms = started.elapsed().as_millis() as u64,
        "publish time read from the file's Last-Modified"
    );
    Some(
        [(record.package.version().to_owned(), last_modified)]
            .into_iter()
            .collect(),
    )
}

/// JSON about the proxy itself, marked not to be cached: it reports the state at this moment.
fn uncached_json(status: StatusCode, body: impl Serialize) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body),
    )
        .into_response()
}

/// A metadata document as its ecosystem's reader returned it.
enum Read {
    Packument(Box<PackageMetadata>),
    SimpleIndex(pypi::Index),
}

impl Read {
    /// The records, when the document normalised.
    fn metadata(&self) -> Option<&PackageMetadata> {
        match self {
            Self::Packument(packument) => Some(packument),
            Self::SimpleIndex(index) => index.metadata.as_deref(),
        }
    }
}

/// How long a client is told to wait before asking again, on a request the proxy is not
/// ready to answer.
///
/// One second. Measured 2026-09-19, two clients of seven honour `Retry-After`: yarn 4 and
/// pip, whose total patience is 3.2s and 5.5s. npm, pnpm, yarn 1, uv and bun run their own
/// backoff and ignore the header, so the value only decides how promptly those two come
/// back. See `docs/engineering_decisions/deferral-status-codes.md`.
const RETRY_AFTER_SECONDS: &str = "1";

/// The header naming which not-ready case a 503 is, for a client or a log to read without
/// parsing prose. Neither status code distinguishes them.
pub const NOT_READY: header::HeaderName = header::HeaderName::from_static("x-waharoa-not-ready");

/// Why a package is not decided on. Already logged; [`IntelUnavailable::response`] is what
/// the client is sent.
enum IntelUnavailable {
    /// The store errored, or holds no snapshot.
    Unanswered,
    /// The snapshot has no stream that can report a finding or malware for this ecosystem,
    /// so an empty answer would read as "nothing known" about a package nothing was asked
    /// about.
    Uncovered(Ecosystem),
}

impl IntelUnavailable {
    /// What a log and the `x-waharoa-not-ready` header call this case.
    fn reason(&self) -> &'static str {
        match self {
            Self::Unanswered => "intel-store",
            Self::Uncovered(_) => "no-stream-for-ecosystem",
        }
    }

    /// 503 with a wait and a reason.
    ///
    /// 503 rather than 429: measured over seven clients, a 429 is terminal for yarn 1 and
    /// bun, which report it and stop, while every one of the seven retries a 503. 429 says
    /// "this one artifact is under analysis" and nothing here is, so the code that works
    /// is also the one that is true.
    fn response(self) -> Response {
        let body = match self {
            Self::Unanswered => {
                "waharoa: the intel store cannot answer, so nothing is served unchecked\n"
                    .to_owned()
            }
            Self::Uncovered(ecosystem) => format!(
                "waharoa: the intel snapshot has no advisory stream for {ecosystem}, so no \
                 {ecosystem} package is served unchecked\n"
            ),
        };
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, RETRY_AFTER_SECONDS),
                (NOT_READY, self.reason()),
            ],
            body,
        )
            .into_response()
    }
}

/// The snapshot whose digest is `digest`, from the cache or the store. `Ok(None)` when the
/// store's newest snapshot is a different one, which a refresh between the two reads
/// causes.
///
/// Keyed by the digest the records came from, so coverage is read from the same load as
/// the records, and the store is asked once per refresh rather than once per request.
async fn snapshot_named(
    proxy: &Proxy,
    store: &dyn Intel,
    digest: &str,
) -> Result<Option<LoadedSnapshot>, crate::intel::store::IntelError> {
    if let Some(held) = proxy
        .coverage
        .lock()
        .expect("coverage lock")
        .as_ref()
        .filter(|held| held.digest == digest)
    {
        return Ok(Some(held.clone()));
    }
    let Some(snapshot) = store.snapshot().await?.filter(|s| s.digest == digest) else {
        return Ok(None);
    };
    *proxy.coverage.lock().expect("coverage lock") = Some(snapshot.clone());
    Ok(Some(snapshot))
}

/// What the intel store knows about a package, when a policy and a store are both configured.
///
/// `Ok(None)` is no store, or no policy: the checks that read advisories are dropped as
/// unenforceable, as they were before a store existed. Each of these is `Err`, answered
/// with a 503:
///
/// - the store errors, or holds no snapshot yet;
/// - the snapshot has no stream providing `match` or `malware` for the package's ecosystem;
/// - a refresh replaced the snapshot between reading the records and reading its streams.
///
/// Never a serve: `known_malware` has no exception, and serving while it cannot be asked
/// would pass malware through unseen. An allowed decision is not written either, so the
/// audit log never records a snapshot as used for a package it could say nothing about.
async fn intel_for(
    proxy: &Proxy,
    key: &PackageKey,
    path: &str,
) -> Result<Option<PackageIntel>, IntelUnavailable> {
    let Some(store) = proxy.consulted_intel() else {
        return Ok(None);
    };
    let ecosystem = key.ecosystem();
    let why = match store
        .package(ecosystem.as_str(), &key.registry_name())
        .await
    {
        Ok(Some(found)) => match snapshot_named(proxy, store, &found.snapshot).await {
            Ok(Some(snapshot)) => {
                let gaps = snapshot.uncovered(ecosystem.as_str());
                if gaps.is_empty() {
                    return Ok(Some(found));
                }
                for gap in &gaps {
                    error!(path = %path, snapshot = %snapshot.digest, "{gap}; answering 503");
                }
                return Err(IntelUnavailable::Uncovered(ecosystem));
            }
            Ok(None) => "the intel snapshot changed while it was read".to_owned(),
            Err(e) => e.to_string(),
        },
        Ok(None) => "no intel has been loaded".to_owned(),
        Err(e) => e.to_string(),
    };
    // Logged, not sent: a database error can carry the database's address.
    error!(
        path = %path,
        why = %why,
        "intel store cannot answer; answering 503 rather than serving unchecked"
    );
    Err(IntelUnavailable::Unanswered)
}

/// The versions in this metadata document the policy refuses.
///
/// Every version is asked, not just the one a client might resolve to: which one it picks
/// is what the filtering decides. A check the record cannot answer is dropped, the same
/// way it is on the artifact path, so a configured `cooldown_days` does not empty the
/// document on a fact the registry never sent.
///
/// Publish times come from the records alone. Under a cooldown an npm request asks for the
/// full packument, whose records carry them, and a PyPI record always does. Fetching them
/// again would repeat the request this document came from.
fn policy_refused_versions(
    metadata: &PackageMetadata,
    policy: Option<&Policy>,
    intel: Option<&PackageIntel>,
    path: &str,
    audit: Option<&AuditLog>,
) -> Refused {
    let Some(policy) = policy else {
        return Refused::default();
    };
    let today = crate::policy::today();
    let mut refused = HashSet::new();
    let mut order = Vec::new();
    let mut checks: BTreeSet<String> = BTreeSet::new();
    let mut strongest = crate::policy::Action::Allow;
    for record in &metadata.records {
        let enforce::Verdict::Refuse(refusal) =
            enforce::artifact(Some(policy), record, None, intel, today)
        else {
            continue;
        };
        // `enforce::artifact` has already dropped unenforceable checks, so this needs no
        // `enforce::enforced` call.
        strongest = std::cmp::max_by_key(strongest, refusal.action, |a| a.strength());
        // The reason line leads with the check name, which is what the log records.
        checks.extend(
            refusal
                .reasons
                .iter()
                .filter_map(|r| r.split(':').next().map(str::to_owned)),
        );
        order.push(record.package.version().to_owned());
        refused.insert(record.package.version().to_owned());
    }

    if let Some(audit) = audit
        && !order.is_empty()
    {
        let unenforceable = metadata
            .records
            .first()
            .map(|record| {
                enforce::unenforceable(
                    policy,
                    record,
                    None,
                    crate::policy::decide::Intel::of(intel),
                )
            })
            .unwrap_or_default();
        audit.write(
            &audit::Event::resolution(
                metadata.key.ecosystem().as_str(),
                &metadata.key.registry_name(),
                strongest.as_str(),
                order,
                checks.iter().cloned().collect(),
                &unenforceable,
            )
            .with_intel_snapshot(intel.map(|i| i.snapshot.as_str())),
        );
    }

    if refused.len() == metadata.records.len() && !refused.is_empty() {
        // Every version gone leaves the resolver nothing to pick, so the install fails
        // with the registry's own "no matching version" rather than anything this proxy
        // said. Worth saying out loud, because it reads as a broken registry.
        warn!(
            path = %path,
            versions = refused.len(),
            "policy refuses every version of this package, so nothing is left to resolve to"
        );
    }
    Refused {
        checks: checks.into_iter().collect(),
        versions: refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defer::DeferTest;
    use crate::identity::Ecosystem;
    use crate::util::test_support::NO_UPSTREAM;
    use axum::routing::{any, get};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// Neither gzip nor identity, so nothing this build can decode.
    const UNREADABLE: &str = "br, identity;q=0";

    fn fixture(name: &str) -> Vec<u8> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
        std::fs::read(format!("{dir}{name}")).expect("fixture is missing")
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
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
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .router(),
        )
        .await;
        (base, seen)
    }

    /// The same, with the PyPI index pointed at the fake too, so a `/simple/` request
    /// reaches it rather than pypi.org.
    async fn pypi_proxy_serving(
        status: StatusCode,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> (String, Recorder) {
        let (upstream, seen) = upstream_serving(status, content_type, None, body).await;
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream.clone())
            .with_upstream(Ecosystem::PyPI, upstream);
        let base = serve(proxy.router()).await;
        (base, seen)
    }

    /// An error page carries a status, not a document. A registry that answers 404 with
    /// `application/json` is saying the package is gone, and reading that body as a
    /// packument would report it as one that did not normalise.
    #[tokio::test]
    async fn a_failed_response_is_forwarded_rather_than_read() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (base, _) = proxy_serving(
            StatusCode::NOT_FOUND,
            "application/json",
            None,
            body.clone(),
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_slice());
    }

    /// The same for a simple index. The body below would rewrite cleanly if it were read,
    /// so this measures the status gate rather than the parse failing anyway: a non-2xx
    /// response is forwarded byte for byte whatever it contains.
    #[tokio::test]
    async fn a_failed_index_response_is_forwarded_rather_than_read() {
        let body = br#"{"name":"x","files":[{"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0.tar.gz","hashes":{}}]}"#.to_vec();
        let (base, _) =
            pypi_proxy_serving(StatusCode::NOT_FOUND, pypi::SIMPLE_JSON, body.clone()).await;

        let response = reqwest::Client::new()
            .get(format!("{base}/simple/x/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_slice());
    }

    /// The whole path, through the router: pip asks for a project, the index comes back
    /// with its files pointed at the proxy, and the URL it now carries is one this proxy
    /// classifies as an artifact.
    #[tokio::test]
    async fn an_index_served_through_the_proxy_points_its_files_here() {
        let index = br#"{"name":"x","files":[
            {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl","hashes":{}}
        ]}"#.to_vec();
        let (base, seen) = pypi_proxy_serving(StatusCode::OK, pypi::SIMPLE_JSON, index).await;

        let response = reqwest::Client::new()
            .get(format!("{base}/simple/x/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.bytes().await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let url = document["files"][0]["url"].as_str().unwrap();
        assert_eq!(
            url,
            format!("{base}/packages/ab/cd/x-1.0-py3-none-any.whl"),
            "the file now points at this proxy"
        );

        // The proxy asked its PyPI upstream without sending its own `/simple` twice.
        assert_eq!(seen.lock().unwrap().paths, ["/x/"]);

        let path = url.strip_prefix(&base).unwrap();
        assert!(
            matches!(
                crate::route::classify(path),
                (Ecosystem::PyPI, RequestTarget::Artifact { .. })
            ),
            "{path}"
        );
    }

    /// The refusal table is keyed by (ecosystem, client), and the request says which
    /// ecosystem. Passing npm for every request made a `pypi/...` entry unreachable.
    #[test]
    fn a_refusal_takes_the_status_configured_for_its_own_ecosystem() {
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, "https://registry.npmjs.org")
            .with_refusal_status(
                crate::refusal::RefusalStatus::parse("default=403,pypi/pip=451,npm/pnpm=404")
                    .unwrap(),
            );
        let pip = "pip/26.1.1";
        let pnpm = "pnpm/10.33.0 npm/?";

        assert_eq!(refusal_status(&proxy, Ecosystem::PyPI, Some(pip)), 451);
        assert_eq!(
            refusal_status(&proxy, Ecosystem::Npm, Some(pip)),
            403,
            "pip is not an npm client"
        );
        assert_eq!(refusal_status(&proxy, Ecosystem::Npm, Some(pnpm)), 404);
        assert_eq!(
            refusal_status(&proxy, Ecosystem::PyPI, Some(pnpm)),
            403,
            "npm's entry does not answer for PyPI"
        );
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

    /// The deferral knob answers instead of fetching, which is what `make retry-matrix`
    /// measures the clients against. Debug builds only.
    #[tokio::test]
    async fn a_deferred_request_is_answered_without_fetching_upstream_npm() {
        let (upstream, seen) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_defer_test(Some(DeferTest::parse("429:1:metadata").unwrap()))
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert!(response.text().await.unwrap().contains("deferred"));

        // A path that is not a packument is out of scope, so it is forwarded as usual.
        let other = reqwest::get(format!("{base}/-/ping")).await.unwrap();
        assert_eq!(other.status(), StatusCode::OK);
        assert_eq!(
            seen.lock().unwrap().paths,
            vec!["/-/ping"],
            "the deferred request never reached upstream"
        );
    }

    /// Without a `Retry-After` the header is absent rather than empty, so a client that
    /// reads it is measured on the code alone.
    #[tokio::test]
    async fn a_deferral_without_retry_after_sends_no_such_header() {
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_defer_test(Some(DeferTest::parse("503:none:all").unwrap()))
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::RETRY_AFTER));
    }

    /// A bounded deferral lifts, which is what the warm-up case measures.
    #[tokio::test]
    async fn a_bounded_deferral_serves_once_it_has_lifted() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            body,
        )
        .await;
        // Zero seconds: already lifted when the request arrives.
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_defer_test(Some(DeferTest::parse("503:1:all:0").unwrap()))
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// An upstream that answers 304 to the tag it issued, and 200 to anything else.
    async fn upstream_revalidating(tag: &'static str, body: Vec<u8>) -> (String, Recorder) {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().fallback(any(move |req: Request| {
            let seen = recorder.clone();
            let body = body.clone();
            async move {
                let matched = req
                    .headers()
                    .get(header::IF_NONE_MATCH)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == tag);
                {
                    let mut s = seen.lock().unwrap();
                    s.paths.push(req.uri().to_string());
                    s.accept_encoding.push(None);
                    s.headers.push(req.headers().clone());
                }
                let response = Response::builder()
                    .header(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")
                    .header(header::ETAG, tag);
                if matched {
                    response
                        .status(StatusCode::NOT_MODIFIED)
                        .body(Body::empty())
                        .unwrap()
                } else {
                    response
                        .status(StatusCode::OK)
                        .body(Body::from(body))
                        .unwrap()
                }
            }
        }));
        (serve(router).await, seen)
    }

    /// A 304 carries the upstream's tag, and the client stores what comes back. Unless it
    /// is marked here, the next revalidation sends a tag this proxy will drop and the
    /// client gets a full body, alternating 200 and 304 forever.
    #[tokio::test]
    async fn a_revalidated_packument_keeps_the_tag_this_proxy_issued() {
        let (upstream, seen) =
            upstream_revalidating("\"abc\"", fixture("lodash-4.17.21.abbrev.json")).await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .router(),
        )
        .await;
        let client = reqwest::Client::new();

        let first = client.get(format!("{base}/lodash")).send().await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let issued = first.headers()[header::ETAG].to_str().unwrap().to_owned();
        assert!(issued.contains("waharoa."), "not marked: {issued}");

        let second = client
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, &issued)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            second.headers()[header::ETAG].to_str().unwrap(),
            issued,
            "a different tag makes the client treat this as a new representation"
        );
        assert_eq!(
            seen.lock().unwrap().headers[1][header::IF_NONE_MATCH],
            "\"abc\"",
            "upstream is asked with its own tag, not ours"
        );
    }

    const OFFSITE_PACKUMENT: &str = r#"{"name":"widget","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{
            "version":"1.0.0","dist":{
            "tarball":"https://elsewhere.example/widget-1.0.0.tgz","integrity":"sha512-AAAA"}}}}"#;

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
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_max_metadata_bytes(16)
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

    // -----------------------------------------------------------------------
    // Status handling
    // -----------------------------------------------------------------------

    fn policy(yaml: &str) -> std::sync::Arc<Policy> {
        std::sync::Arc::new(Policy::parse(yaml).expect("policy should load"))
    }

    /// Decision #4's pinned half, end to end. `npm ci` fetches an artifact by name
    /// without asking for a packument, which is the case this covers.
    #[tokio::test]
    async fn a_denied_version_is_refused_on_a_pinned_fetch_before_the_artifact_is_fetched() {
        let (upstream, seen) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_policy(Some(policy(
                    "version: 1\ncooldown_days: 0\n\
                     denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
                )))
                // Off, so the 403 can only be the policy's and not the origin check's.
                .with_refuse_unservable(false)
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/lodash/-/lodash-4.17.21.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let body = response.text().await.unwrap();
        assert!(body.contains("pkg:npm/lodash@4.17.21"), "{body}");
        assert!(body.contains("denials"), "{body}");

        // The packument was fetched, because the digest has to be known before the
        // artifact is. The artifact itself never was.
        let paths = &seen.lock().unwrap().paths;
        assert!(
            !paths.iter().any(|p| p.ends_with(".tgz")),
            "the artifact was fetched for a version policy denied: {paths:?}"
        );
    }

    /// A store with one advisory for every version, without the KEV catalogue.
    fn everywhere(advisory_id: &str, cvss: Option<f64>, malware: bool) -> Arc<dyn Intel> {
        store_with(
            crate::intel::store::Record {
                advisory_id: advisory_id.to_owned(),
                aliases: Vec::new(),
                source: "osv".to_owned(),
                cvss,
                band: None,
                cvss_source: None,
                exploited: false,
                malware,
            },
            false,
        )
    }

    fn store_with(
        record: crate::intel::store::Record,
        exploitation_loaded: bool,
    ) -> Arc<dyn Intel> {
        Arc::new(crate::intel::store::testing::FixedIntel(Ok(Some(
            PackageIntel {
                snapshot: "s1".to_owned(),
                records: vec![(None, record)],
                ranges: Vec::new(),
                exploitation_loaded,
            },
        ))))
    }

    fn malware_everywhere() -> Arc<dyn Intel> {
        everywhere("MAL-1", None, true)
    }

    async fn proxy_with_intel(
        intel: Arc<dyn Intel>,
        with_policy: bool,
    ) -> (String, Arc<Mutex<Seen>>) {
        let yaml = with_policy.then_some("version: 1\ncooldown_days: 0\n");
        proxy_for("lodash-4.17.21.abbrev.json", Some(intel), yaml).await
    }

    /// A proxy in front of an upstream serving `packument` for every path. The origin check
    /// is off, so a 403 can only be the policy's.
    async fn proxy_for(
        packument: &str,
        intel: Option<Arc<dyn Intel>>,
        yaml: Option<&str>,
    ) -> (String, Arc<Mutex<Seen>>) {
        let (upstream, seen) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture(packument),
        )
        .await;
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream)
            .with_intel(intel)
            .with_refuse_unservable(false)
            .with_policy(yaml.map(policy));
        (serve(proxy.router()).await, seen)
    }

    /// A pinned fetch of `tarball` answers 403 on `check`, and the artifact is never fetched.
    async fn assert_refused_pinned(base: &str, seen: &Mutex<Seen>, tarball: &str, check: &str) {
        let response = reqwest::get(format!("{base}{tarball}")).await.unwrap();
        assert_eq!(response.status(), 403, "{tarball}");
        let body = response.text().await.unwrap();
        assert!(body.contains(check), "{body}");
        let paths = &seen.lock().unwrap().paths;
        assert!(!paths.iter().any(|p| p.ends_with(".tgz")), "{paths:?}");
    }

    /// A HEAD for an artifact is forwarded as it came. It is not decided, so it costs no
    /// metadata fetch.
    #[tokio::test]
    async fn a_head_for_an_artifact_asks_upstream_for_nothing_else() {
        let (base, seen) = proxy_with_intel(malware_everywhere(), true).await;
        let tarball = "/lodash/-/lodash-4.17.21.tgz";
        reqwest::Client::new()
            .head(format!("{base}{tarball}"))
            .send()
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().paths, [tarball]);
    }

    /// A client that reached the proxy at `proxy.test` and accepts `accept_encoding`.
    fn client_headers(accept_encoding: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("proxy.test"));
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_str(accept_encoding).unwrap(),
        );
        headers
    }

    fn negotiated(
        yaml: Option<&str>,
        method: Method,
        path: &str,
        accept_encoding: &str,
    ) -> Negotiation {
        let proxy = Proxy::new(reqwest::Client::new()).with_policy(yaml.map(policy));
        let (ecosystem, target) = crate::route::classify(path);
        negotiate(
            &proxy,
            ecosystem,
            &target,
            &method,
            &client_headers(accept_encoding),
        )
    }

    /// The full packument is asked for only where it adds a fact: an npm metadata GET the
    /// proxy reads, under a cooldown.
    #[test]
    fn only_a_read_npm_document_under_a_cooldown_is_asked_for_in_full() {
        let cooldown = Some("version: 1\ncooldown_days: 7\n");
        let none = Some("version: 1\ncooldown_days: 0\n");
        let cases = [
            (cooldown, Method::GET, "/lodash", "gzip", true),
            (none, Method::GET, "/lodash", "gzip", false),
            (None, Method::GET, "/lodash", "gzip", false),
            (cooldown, Method::HEAD, "/lodash", "gzip", false),
            (cooldown, Method::GET, "/lodash", UNREADABLE, false),
            (cooldown, Method::GET, "/simple/requests/", "gzip", false),
            (
                cooldown,
                Method::GET,
                "/lodash/-/lodash-4.17.21.tgz",
                "gzip",
                false,
            ),
        ];
        for (yaml, method, path, encoding, full) in cases {
            let negotiation = negotiated(yaml, method.clone(), path, encoding);
            assert_eq!(
                negotiation.full_document, full,
                "{yaml:?} {method} {path} {encoding}"
            );
        }
    }

    #[test]
    fn a_read_document_is_rewritten_at_the_host_the_client_used() {
        let negotiation = negotiated(None, Method::GET, "/lodash", "gzip");
        assert_eq!(
            negotiation,
            Negotiation {
                encoding: RequestedEncoding::Gzip,
                read_metadata: true,
                rewrite_base: Some("http://proxy.test".to_owned()),
                rewriting: true,
                full_document: false,
            }
        );
        let unread = negotiated(None, Method::GET, "/lodash", UNREADABLE);
        assert!(!unread.read_metadata && !unread.rewriting, "{unread:?}");
    }

    /// The headers `handle` sends upstream for a client request carrying `client`, with
    /// `yaml` as the policy. The client reached the proxy at `proxy.test`.
    fn sent_upstream(
        yaml: Option<&str>,
        path: &str,
        client: &[(header::HeaderName, &'static str)],
    ) -> HeaderMap {
        let proxy = Proxy::new(reqwest::Client::new()).with_policy(yaml.map(policy));
        let (ecosystem, target) = crate::route::classify(path);
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("proxy.test"));
        for (name, value) in client {
            headers.append(name, HeaderValue::from_static(value));
        }
        let negotiation = negotiate(&proxy, ecosystem, &target, &Method::GET, &headers);
        upstream_headers(&headers, &negotiation, path)
    }

    /// What reaches upstream, header by header. `None` is a header that must not.
    #[test]
    fn what_each_request_sends_upstream() {
        const COOLDOWN: Option<&str> = Some("version: 1\ncooldown_days: 7\n");
        const PACKUMENT: &str = "/lodash";
        const TARBALL: &str = "/lodash/-/lodash-4.17.21.tgz";
        // Label, policy, path, the client's headers, the header asked about, and what
        // reaches upstream for it.
        type Case<'a> = (
            &'a str,
            Option<&'a str>,
            &'a str,
            &'a [(header::HeaderName, &'static str)],
            header::HeaderName,
            Option<&'a str>,
        );
        let cases: [Case; 13] = [
            // npm 9 offers `gzip,deflate` and registry.npmjs.org answers brotli whenever br
            // is offered. Narrowed, only gzip has to be decoded here.
            (
                "br narrowed away",
                None,
                PACKUMENT,
                &[(header::ACCEPT_ENCODING, "gzip, deflate, br")],
                header::ACCEPT_ENCODING,
                Some("gzip"),
            ),
            (
                "no gzip, so identity",
                None,
                PACKUMENT,
                &[(header::ACCEPT_ENCODING, "br")],
                header::ACCEPT_ENCODING,
                Some("identity"),
            ),
            // Rewriting the header to an encoding the client refused would break the
            // install for the sake of our inspection.
            (
                "neither gzip nor identity is kept",
                None,
                PACKUMENT,
                &[(header::ACCEPT_ENCODING, UNREADABLE)],
                header::ACCEPT_ENCODING,
                Some(UNREADABLE),
            ),
            (
                "an artifact is not read",
                None,
                TARBALL,
                &[(header::ACCEPT_ENCODING, "gzip, deflate, br")],
                header::ACCEPT_ENCODING,
                Some("gzip, deflate, br"),
            ),
            (
                "hop-by-hop",
                None,
                TARBALL,
                &[(header::TE, "trailers")],
                header::TE,
                None,
            ),
            (
                "a proxy credential",
                None,
                TARBALL,
                &[(header::PROXY_AUTHORIZATION, "Basic c2VjcmV0")],
                header::PROXY_AUTHORIZATION,
                None,
            ),
            // A credential for this proxy, an account's token under TODO Stage 8.
            (
                "a credential for this proxy",
                None,
                TARBALL,
                &[(header::AUTHORIZATION, "Bearer account-token")],
                header::AUTHORIZATION,
                None,
            ),
            // reqwest writes the upstream's own `Host`.
            ("the proxy's Host", None, TARBALL, &[], header::HOST, None),
            // Only `If-None-Match` carries the identity that says a cached body was
            // rewritten here. A date-based 304 would authorise the client to serve one that
            // was not.
            (
                "a date conditional",
                None,
                PACKUMENT,
                &[(header::IF_MODIFIED_SINCE, "Wed, 21 Oct 2015 07:28:00 GMT")],
                header::IF_MODIFIED_SINCE,
                None,
            ),
            (
                "a range conditional",
                None,
                PACKUMENT,
                &[(header::IF_RANGE, "\"abc\"")],
                header::IF_RANGE,
                None,
            ),
            // Measured: after rewriting was enabled at an address that had run without it,
            // npm sent the upstream's own tag, the registry answered 304, and the client
            // stayed on its unrewritten copy.
            (
                "a tag this proxy did not issue",
                None,
                PACKUMENT,
                &[(header::IF_NONE_MATCH, "W/\"abc123\"")],
                header::IF_NONE_MATCH,
                None,
            ),
            (
                "the client's Accept, without a cooldown",
                None,
                PACKUMENT,
                &[(header::ACCEPT, npm::ABBREVIATED_ACCEPT)],
                header::ACCEPT,
                Some(npm::ABBREVIATED_ACCEPT),
            ),
            // Replaced, not joined.
            (
                "the full packument, under a cooldown",
                COOLDOWN,
                PACKUMENT,
                &[(header::ACCEPT, npm::ABBREVIATED_ACCEPT)],
                header::ACCEPT,
                Some(npm::FULL_ACCEPT),
            ),
        ];
        for (label, yaml, path, client, name, expected) in cases {
            let sent = sent_upstream(yaml, path, client);
            let values: Vec<&str> = sent
                .get_all(&name)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(values, expected.into_iter().collect::<Vec<_>>(), "{label}");
        }
    }

    /// A tag this proxy issued reaches upstream as the upstream's own tag. One issued at
    /// another address does not reach upstream: a 304 would leave the client with artifact
    /// URLs pointing at an address nobody listens on, so the registry has to send a body
    /// to rewrite afresh.
    #[test]
    fn a_tag_is_turned_back_only_at_the_address_that_issued_it() {
        let proxy = Proxy::new(reqwest::Client::new());
        let (ecosystem, target) = crate::route::classify("/lodash");
        for (issued_at, expected) in [
            ("http://proxy.test", Some("W/\"abc123\"")),
            ("http://some-old-address:9999", None),
        ] {
            let mut headers = client_headers("gzip");
            let issued = mark_etag("W/\"abc123\"", issued_at);
            headers.insert(
                header::IF_NONE_MATCH,
                HeaderValue::from_str(&issued).unwrap(),
            );
            let negotiation = negotiate(&proxy, ecosystem, &target, &Method::GET, &headers);
            let sent = upstream_headers(&headers, &negotiation, "/lodash");
            assert_eq!(
                sent.get(header::IF_NONE_MATCH).map(|v| v.to_str().unwrap()),
                expected,
                "{issued_at}"
            );
        }
    }

    /// Artifact URLs point at the address the client used, so a proxy reachable by several
    /// names points each client back at its own. A configured base wins over `Host`, which
    /// a deployment behind a load balancer needs, and which pins a stable name into
    /// lockfiles.
    #[test]
    fn artifact_urls_point_at_the_host_the_client_used_unless_a_base_is_configured() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("npm.corp.example"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let (ecosystem, target) = crate::route::classify("/lodash");
        for (configured, expected) in [
            (None, "https://npm.corp.example"),
            (
                Some("https://registry.example/"),
                "https://registry.example",
            ),
        ] {
            let proxy =
                Proxy::new(reqwest::Client::new()).with_public_base(configured.map(str::to_owned));
            let negotiation = negotiate(&proxy, ecosystem, &target, &Method::GET, &headers);
            assert_eq!(negotiation.rewrite_base.as_deref(), Some(expected));
        }
    }

    /// A request the proxy does not read keeps every header the client sent it, other than
    /// the ones that stop at the proxy.
    #[test]
    fn an_artifact_request_keeps_the_clients_encoding_and_conditionals() {
        let client = [
            (header::ACCEPT_ENCODING, "gzip, br"),
            (header::IF_NONE_MATCH, "\"abc\""),
            (header::USER_AGENT, "npm/11"),
        ];
        let sent = sent_upstream(None, "/lodash/-/lodash-4.17.21.tgz", &client);
        let mut expected = HeaderMap::new();
        for (name, value) in client {
            expected.insert(name, HeaderValue::from_static(value));
        }
        assert_eq!(sent, expected);
    }

    /// A log sink a test can read back.
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Route this thread's logs at `level` and above into a buffer, until the guard drops.
    fn capture(level: tracing::Level) -> (tracing::subscriber::DefaultGuard, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(move || Captured(sink.clone()))
            .with_ansi(false)
            .finish();
        (tracing::subscriber::set_default(subscriber), buf)
    }

    fn text(buf: &Mutex<Vec<u8>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    /// What `f` logs at INFO and above.
    fn logged(f: impl FnOnce()) -> String {
        let (guard, buf) = capture(tracing::Level::INFO);
        f();
        drop(guard);
        text(&buf)
    }

    /// The installed version's own install-script answer is on the artifact request's line,
    /// which is what a range resolver was once wanted for: a file, not a document.
    #[tokio::test]
    async fn an_artifact_request_logs_the_answer_for_the_file_it_names() {
        let proxy = offline(None, Some(NO_POLICY));
        // 3.0 offers a wheel, which runs nothing, and an sdist, which runs `setup.py`.
        resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, PYPI_YANKED).await;
        for (file, expected) in [
            (
                "/packages/ef/01/25/x-3.0-py3-none-any.whl",
                "has_install_scripts=false",
            ),
            (YANKED_SDIST, "has_install_scripts=true"),
        ] {
            let (_guard, buf) = capture(tracing::Level::INFO);
            pinned(&proxy, file).await;
            drop(_guard);
            let log = text(&buf);
            assert!(log.contains(expected), "{file}: {log}");
        }
    }

    /// A document whose versions carry no date says so once, rather than leaving the
    /// operator to read `cooldown_days: enforced` and believe the index was filtered by it.
    #[tokio::test]
    async fn a_document_with_no_dates_says_the_cooldown_waits_for_the_artifact() {
        const INDEX: &[u8] = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ab/x-1.0.tar.gz","hashes":{}}
        ]}"#;
        async fn said(yaml: &str) -> String {
            let proxy = offline(None, Some(yaml));
            let (guard, buf) = capture(tracing::Level::WARN);
            resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, INDEX).await;
            drop(guard);
            text(&buf)
        }
        let warned = said("version: 1\ncooldown_days: 7\ninstall_scripts: allow\n").await;
        assert!(
            warned.contains("cooldown_days cannot be answered"),
            "{warned}"
        );
        assert!(warned.contains("undated=1"), "{warned}");
        assert!(
            !said(NO_POLICY)
                .await
                .contains("cooldown_days cannot be answered"),
            "no cooldown, nothing to say"
        );
    }

    /// An index with no publish time in it, and a file host that answers `Last-Modified`:
    /// the cooldown is decided on the file's own date. A PEP 503 page is this case, and
    /// almost none carries a date: see `docs/engineering_decisions/pep-503-html-index.md`.
    #[tokio::test]
    async fn a_cooldown_is_decided_on_the_file_hosts_last_modified() {
        for (label, status, last_modified, refused) in [
            (
                "published today",
                StatusCode::OK,
                Some(jiff::Timestamp::now()),
                true,
            ),
            (
                "published in 2020",
                StatusCode::OK,
                Some("2020-01-01T00:00:00Z".parse::<jiff::Timestamp>().unwrap()),
                false,
            ),
            // No date, so the check is dropped as unenforceable, which is what it was
            // before the file host was asked at all.
            ("no Last-Modified", StatusCode::OK, None, false),
            // A host that refuses the HEAD answers no question, whatever it puts in the
            // headers of its refusal.
            (
                "a 404 carrying a date",
                StatusCode::NOT_FOUND,
                Some(jiff::Timestamp::now()),
                false,
            ),
        ] {
            let router = Router::new().fallback(any(move |_req: Request| async move {
                let mut response = Response::builder().status(status);
                if let Some(at) = last_modified {
                    let zoned = at.to_zoned(jiff::tz::TimeZone::UTC);
                    let date = jiff::fmt::rfc2822::to_string(&zoned).unwrap();
                    response = response.header(header::LAST_MODIFIED, date);
                }
                response.body(Body::empty()).unwrap()
            }));
            let host = serve(router).await;
            // An sdist, so `install_scripts` is allowed here and the cooldown is the only
            // check that can refuse it.
            let yaml = "version: 1\ncooldown_days: 7\ninstall_scripts: allow\n";
            let proxy = offline(None, Some(yaml))
                .with_origin_policy([host.as_str()], [])
                .expect("the host is an origin");
            let index = format!(
                r#"{{"name":"x","files":[{{"filename":"x-1.0.tar.gz","url":"{host}/x-1.0.tar.gz","hashes":{{}}}}]}}"#
            );
            resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, index.as_bytes()).await;
            let step = pinned(&proxy, "/packages/x-1.0.tar.gz").await;
            assert_eq!(matches!(step, ArtifactStep::Answer(_)), refused, "{label}");
        }
    }

    /// A deprecated version is served, and the message its publisher left is logged. npm
    /// installs one after a warning and no client skips it, so the proxy does not refuse
    /// it: `docs/engineering_decisions/yanked-files.md`.
    #[tokio::test]
    async fn a_deprecated_version_is_served_and_its_message_logged() {
        let proxy = offline(None, Some(NO_POLICY));
        hold(&proxy, "rimraf-1.0.0.abbrev.json");
        let (_guard, buf) = capture(tracing::Level::INFO);
        let step = pinned(&proxy, "/rimraf/-/rimraf-1.0.0.tgz").await;
        drop(_guard);
        assert!(fetched(&step), "a deprecated version is served");
        let log = text(&buf);
        assert!(
            log.contains("Rimraf versions prior to v4 are no longer supported"),
            "{log}"
        );
    }

    /// A document the policy changed says so, and one it left alone says nothing.
    #[test]
    fn a_filtered_document_says_how_many_versions_went_and_which_checks_took_them() {
        let mut headers = HeaderMap::new();
        mark_filtered(&mut headers, &Refused::default());
        assert!(headers.is_empty(), "nothing removed, nothing said");

        let refused = Refused {
            versions: ["4.17.21", "4.17.20"]
                .map(str::to_owned)
                .into_iter()
                .collect(),
            checks: vec!["cooldown_days".to_owned(), "denials".to_owned()],
        };
        mark_filtered(&mut headers, &refused);
        assert_eq!(headers[FILTERED_VERSIONS], "2");
        assert_eq!(headers[FILTERED_CHECKS], "cooldown_days,denials");
    }

    /// A limit of zero would deadlock every metadata request, so it is raised to one.
    #[tokio::test]
    async fn a_limit_of_zero_is_treated_as_one() {
        let proxy = Proxy::new(reqwest::Client::new()).with_max_concurrent_documents(0);
        let slot = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            metadata_slot(&proxy, "/lodash"),
        );
        assert!(slot.await.is_ok(), "no slot was ever free");
    }

    /// A slot taken at once is not reported; one waited for is.
    #[tokio::test]
    async fn only_a_wait_for_a_metadata_slot_is_logged() {
        let proxy = Proxy::new(reqwest::Client::new()).with_max_concurrent_documents(1);
        let (_guard, buf) = capture(tracing::Level::DEBUG);
        let held = metadata_slot(&proxy, "/first").await;
        assert_eq!(text(&buf), "", "nothing was waited for");

        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            drop(held);
        });
        let _second = metadata_slot(&proxy, "/second").await;
        release.await.unwrap();
        let log = text(&buf);
        assert!(log.contains("waited for a metadata slot"), "{log}");
        assert!(log.contains("/second"), "{log}");
    }

    /// `make smoke-clients` greps for `UNINSPECTED`, so the line is part of the interface.
    #[test]
    fn a_document_the_proxy_cannot_read_is_logged_as_uninspected() {
        let report = |encoding: &str| {
            let negotiation = negotiated(None, Method::GET, "/lodash", encoding);
            let (_, target) = crate::route::classify("/lodash");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_str(encoding).unwrap(),
            );
            logged(|| report_uninspected(&target, &Method::GET, &negotiation, &headers, "/lodash"))
        };
        let unread = report(UNREADABLE);
        assert!(unread.contains("UNINSPECTED"), "{unread}");
        assert!(unread.contains(UNREADABLE), "{unread}");
        assert_eq!(report("gzip"), "", "a rewritten document is inspected");
    }

    /// Whether the packument the client receives offers `version`.
    async fn offered(base: &str, name: &str, version: &str) -> bool {
        let response = reqwest::get(format!("{base}/{name}")).await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "filtering is a 200 with fewer versions"
        );
        let doc: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        doc["versions"].get(version).is_some()
    }

    const NO_POLICY: &str = "version: 1\ncooldown_days: 0\n";
    const DENY_LODASH: &str = "version: 1\ncooldown_days: 0\n\
                               denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n";
    const LODASH_TARBALL: &str = "/lodash/-/lodash-4.17.21.tgz";

    /// A proxy with no upstream to reach. The origin check is off, so a 403 can only be the
    /// policy's.
    fn offline(intel: Option<Arc<dyn Intel>>, yaml: Option<&str>) -> Proxy {
        Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, NO_UPSTREAM)
            .with_upstream(Ecosystem::PyPI, NO_UPSTREAM)
            .with_intel(intel)
            .with_refuse_unservable(false)
            .with_policy(yaml.map(policy))
    }

    /// Whether `packument` is the full document, which is the one with publish times.
    fn is_full(packument: &str) -> bool {
        packument.contains(".full.")
    }

    /// Put an npm fixture's records in the store, as an earlier metadata request would.
    fn hold(proxy: &Proxy, packument: &str) {
        let detail = if is_full(packument) {
            crate::record::DocumentDetail::Full
        } else {
            crate::record::DocumentDetail::Abbreviated
        };
        hold_document(proxy, &fixture(packument), detail);
    }

    fn hold_document(proxy: &Proxy, packument: &[u8], detail: crate::record::DocumentDetail) {
        let metadata = npm::normalize_packument(packument, detail).unwrap();
        proxy.store.lock().unwrap().insert(metadata);
    }

    /// The proxy's decision on a GET of the artifact at `path`.
    async fn pinned(proxy: &Proxy, path: &str) -> ArtifactStep {
        pinned_by(proxy, path, "-").await
    }

    /// The same, for a client whose user agent is `client`.
    async fn pinned_by(proxy: &Proxy, path: &str, client: &str) -> ArtifactStep {
        let (
            ecosystem,
            RequestTarget::Artifact {
                key,
                claimed_version,
                filename,
            },
        ) = crate::route::classify(path)
        else {
            panic!("{path} is not an artifact");
        };
        let request = ArtifactRequest {
            ecosystem,
            method: &Method::GET,
            key: &key,
            claimed_version: &claimed_version,
            filename: &filename,
            path,
            client,
        };
        decide_artifact(proxy, request).await
    }

    /// The status and body of a response the proxy gives in place of asking upstream.
    async fn read(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn refused(step: ArtifactStep) -> (StatusCode, String) {
        match step {
            ArtifactStep::Answer(response) => read(response).await,
            ArtifactStep::Fetch(_) => panic!("the artifact would be fetched"),
        }
    }

    /// Fetched and verified against a digest from a record the store held. A store that
    /// missed would fetch too, unverified, after its metadata fetch to [`NO_UPSTREAM`]
    /// failed.
    fn fetched(step: &ArtifactStep) -> bool {
        matches!(step, ArtifactStep::Fetch(fetch) if fetch.digest.is_some())
    }

    /// The proxy's handling of a metadata GET of `path` that upstream answers with `body`.
    async fn resolve(proxy: &Proxy, path: &str, content_type: &str, body: &[u8]) -> DocumentStep {
        let (ecosystem, target) = crate::route::classify(path);
        let document = ecosystem::of(ecosystem)
            .document(Some(content_type))
            .expect("a metadata document");
        let headers = client_headers("gzip");
        let negotiation = negotiate(proxy, ecosystem, &target, &Method::GET, &headers);
        let body = Bytes::copy_from_slice(body);
        filtered_document(proxy, document, &body, None, &negotiation, path).await
    }

    async fn resolve_npm(proxy: &Proxy, name: &str, packument: &str) -> DocumentStep {
        let content_type = if is_full(packument) {
            npm::FULL_ACCEPT
        } else {
            npm::ABBREVIATED_ACCEPT
        };
        resolve(
            proxy,
            &format!("/{name}"),
            content_type,
            &fixture(packument),
        )
        .await
    }

    async fn answered(step: DocumentStep) -> (StatusCode, String) {
        match step {
            DocumentStep::Answer(response) => read(response).await,
            DocumentStep::Forward { .. } => panic!("the document would be forwarded"),
        }
    }

    /// The npm fixture `packument` as the client receives it.
    async fn resolved(proxy: &Proxy, name: &str, packument: &str) -> serde_json::Value {
        match resolve_npm(proxy, name, packument).await {
            DocumentStep::Forward {
                body: Some(body), ..
            } => serde_json::from_slice(&body).unwrap(),
            DocumentStep::Forward { body: None, .. } => {
                panic!("the document would be forwarded unread")
            }
            DocumentStep::Answer(response) => panic!("answered {}", response.status()),
        }
    }

    fn offers(document: &serde_json::Value, version: &str) -> bool {
        document["versions"].get(version).is_some()
    }

    const LODASH: &str = "lodash-4.17.21.abbrev.json";
    /// The only lodash fixture with publish times, which `cooldown_days` needs.
    const LODASH_FULL: &str = "lodash-4.17.21.full.json";
    /// rimraf 1.0.0 carries `deprecated`.
    const RIMRAF: &str = "rimraf-1.0.0.abbrev.json";
    /// esbuild 0.28.2 carries `hasInstallScript`.
    const ESBUILD: &str = "esbuild-0.28.2.abbrev.json";

    /// Every check refuses on a pinned fetch and filters the packument. The `match` has no
    /// wildcard, so a check added to `Check` without a case here does not compile.
    #[tokio::test]
    async fn every_check_refuses_on_a_pinned_fetch_and_filters_the_packument() {
        use crate::policy::decide::Check;
        const BASE: &str = NO_POLICY;
        for check in Check::ALL {
            // A yank is PyPI's, so that check has its own document and paths:
            // `a_yanked_version_is_refused_and_filtered`.
            if check == Check::Yanked {
                yanked_is_refused_and_filtered().await;
                continue;
            }
            let (packument, name, version, intel, yaml): (_, _, _, Option<Arc<dyn Intel>>, _) =
                match check {
                    Check::Denials => (LODASH, "lodash", "4.17.21", None, DENY_LODASH.to_owned()),
                    Check::KnownMalware => (
                        LODASH,
                        "lodash",
                        "4.17.21",
                        Some(malware_everywhere()),
                        BASE.to_owned(),
                    ),
                    Check::CooldownDays => (
                        LODASH_FULL,
                        "lodash",
                        "4.17.21",
                        None,
                        "version: 1\ncooldown_days: 36500\n".to_owned(),
                    ),
                    // Scored under the default `max_cvss`, so only `kev` refuses it.
                    Check::Kev => (
                        LODASH,
                        "lodash",
                        "4.17.21",
                        Some(store_with(
                            crate::intel::store::Record {
                                exploited: true,
                                aliases: vec!["CVE-2020-11023".to_owned()],
                                ..crate::intel::store::Record {
                                    advisory_id: "GHSA-0000-0000-0000".to_owned(),
                                    aliases: Vec::new(),
                                    source: "osv".to_owned(),
                                    cvss: Some(5.0),
                                    band: None,
                                    cvss_source: None,
                                    exploited: false,
                                    malware: false,
                                }
                            },
                            true,
                        )),
                        BASE.to_owned(),
                    ),
                    Check::MaxCvss => (
                        LODASH,
                        "lodash",
                        "4.17.21",
                        Some(everywhere("GHSA-0000-0000-0000", Some(8.1), false)),
                        format!("{BASE}max_cvss: 7.0\n"),
                    ),
                    Check::InstallScripts => (
                        ESBUILD,
                        "esbuild",
                        "0.28.2",
                        None,
                        format!("{BASE}install_scripts: block\n"),
                    ),
                    // rimraf 1.0.0 carries npm's `deprecated`.
                    Check::Deprecated => (
                        RIMRAF,
                        "rimraf",
                        "1.0.0",
                        None,
                        format!("{BASE}deprecated: block\n"),
                    ),
                    Check::Yanked => unreachable!("run above, against a PyPI index"),
                };
            let label = check.as_str();
            let proxy = offline(intel, Some(&yaml));
            hold(&proxy, packument);
            let tarball = format!("/{name}/-/{name}-{version}.tgz");
            let (status, body) = refused(pinned(&proxy, &tarball).await).await;
            assert_eq!(status, 403, "{label}");
            assert!(body.contains(label), "{label}: {body}");
            assert!(
                !offers(&resolved(&proxy, name, packument).await, version),
                "{label}"
            );
            // The same document under a policy that refuses nothing is offered, so the
            // filtering above is the check's.
            let allowing = offline(None, Some(&format!("{BASE}install_scripts: allow\n")));
            assert!(
                offers(&resolved(&allowing, name, packument).await, version),
                "{label}"
            );
        }
    }

    /// A record the store holds, no policy, and intel that would refuse it: the fetch gets
    /// its digest and the purl the verifier logs.
    #[tokio::test]
    async fn an_allowed_artifact_is_fetched_with_its_digest_and_purl() {
        let proxy = offline(Some(malware_everywhere()), None);
        hold(&proxy, LODASH);
        let ArtifactStep::Fetch(fetch) = pinned(&proxy, LODASH_TARBALL).await else {
            panic!("no policy refuses it");
        };
        assert_eq!(fetch.purl, "pkg:npm/lodash@4.17.21");
        assert!(fetch.digest.is_some(), "the packument publishes sha512");
        assert_eq!(
            fetch.origin, None,
            "the default registry is not an added origin"
        );
    }

    #[tokio::test]
    async fn a_version_no_denial_names_is_fetched() {
        let proxy = offline(
            None,
            Some(&DENY_LODASH.replace("lodash@4.17.21", "lodash@4.17.20")),
        );
        hold(&proxy, LODASH);
        assert!(fetched(&pinned(&proxy, LODASH_TARBALL).await));
    }

    /// No policy at all is not the same as a policy that allows everything, and neither
    /// refuses. With no policy the store is never asked, so one that is down changes
    /// nothing.
    #[tokio::test]
    async fn without_a_policy_nothing_is_refused_and_the_store_is_not_asked() {
        let down: Arc<dyn Intel> = Arc::new(crate::intel::store::testing::FixedIntel(Err(())));
        for intel in [None, Some(down)] {
            let proxy = offline(intel, None);
            hold(&proxy, LODASH);
            assert!(fetched(&pinned(&proxy, LODASH_TARBALL).await));
            assert!(offers(&resolved(&proxy, "lodash", LODASH).await, "4.17.21"));
        }
    }

    /// A store that cannot answer is not a store that found nothing.
    #[tokio::test]
    async fn a_store_that_cannot_answer_is_a_503_on_both_paths() {
        use crate::intel::store::testing::FixedIntel;
        for (label, store) in [
            ("down", FixedIntel(Err(()))),
            ("empty", FixedIntel(Ok(None))),
        ] {
            let proxy = offline(Some(Arc::new(store)), Some(NO_POLICY));
            hold(&proxy, LODASH);
            let (status, body) = refused(pinned(&proxy, LODASH_TARBALL).await).await;
            assert_eq!(status, 503, "{label}");
            assert!(body.contains("intel store"), "{label}: {body}");
            let (status, _) = answered(resolve_npm(&proxy, "lodash", LODASH).await).await;
            assert_eq!(status, 503, "{label}");
        }
    }

    /// The headers reach the client, on the response carrying the document they describe.
    #[tokio::test]
    async fn a_client_is_told_its_packument_was_filtered() {
        let (base, _) = proxy_for(LODASH, None, Some(DENY_LODASH)).await;
        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()[FILTERED_VERSIONS], "1");
        assert_eq!(response.headers()[FILTERED_CHECKS], "denials");

        let (base, _) = proxy_for(LODASH, None, Some(NO_POLICY)).await;
        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert!(
            !response.headers().contains_key(FILTERED_VERSIONS),
            "nothing was removed from this one"
        );
    }

    /// A 503 says how long to wait and which case it is. Measured over seven clients, a
    /// 429 is terminal for yarn 1 and bun and every one of the seven retries a 503:
    /// `docs/engineering_decisions/deferral-status-codes.md`.
    #[tokio::test]
    async fn a_request_the_proxy_cannot_decide_says_how_long_to_wait_and_why() {
        for (unavailable, reason) in [
            (IntelUnavailable::Unanswered, "intel-store"),
            (
                IntelUnavailable::Uncovered(Ecosystem::PyPI),
                "no-stream-for-ecosystem",
            ),
        ] {
            let response = unavailable.response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            assert_eq!(response.headers()[NOT_READY], reason);
        }
    }

    /// `handle` returns the metadata branch's answer in place of the document. The answer
    /// itself is `a_store_that_cannot_answer_is_a_503_on_both_paths`.
    #[tokio::test]
    async fn a_packument_the_proxy_cannot_decide_on_is_answered_with_a_503() {
        let down = Arc::new(crate::intel::store::testing::FixedIntel(Err(())));
        let (base, _) = proxy_with_intel(down, true).await;
        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 503);
    }

    /// Decision #4's resolution half. The refused version is not in the document, so the
    /// client's resolver picks another. Filtering is a policy question and repointing
    /// artifact URLs a transport one, so it happens with rewriting off too:
    /// `enforcement-tiers.md` says rewriting is correctly off once the proxy terminates TLS.
    #[tokio::test]
    async fn a_denied_version_is_absent_from_the_packument_the_client_receives() {
        for rewriting in [true, false] {
            let proxy = offline(None, Some(DENY_LODASH)).with_artifact_rewriting(rewriting);
            let document = resolved(&proxy, "lodash", LODASH).await;
            assert!(!offers(&document, "4.17.21"), "rewriting {rewriting}");
            // This fixture tags `latest` as 4.18.1, a version the document never carried,
            // so the tag never named the denied version and survives. Tag dropping is
            // covered against a document where it does, in `npm::tests::rewriting`.
            assert_eq!(document["dist-tags"]["latest"], "4.18.1");
        }
    }

    /// Both halves of decision #4 are recorded. A log holding only refusals cannot answer
    /// "was this ever evaluated".
    #[tokio::test]
    async fn every_decision_reaches_the_audit_log() {
        let path = crate::util::test_support::tempdir("proxy-audit").join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).expect("should open"));
        let proxy = offline(None, Some(DENY_LODASH)).with_audit_log(Some(log));

        resolved(&proxy, "lodash", LODASH).await;
        pinned(&proxy, LODASH_TARBALL).await;

        let written = std::fs::read_to_string(&path).expect("should read");
        let events: Vec<serde_json::Value> = written
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is one object"))
            .collect();
        let resolution = events
            .iter()
            .find(|e| e["path"] == "resolution")
            .expect("the packument request is recorded");
        assert_eq!(resolution["removed"], serde_json::json!(["4.17.21"]));
        assert_eq!(resolution["checks"], serde_json::json!(["denials"]));
        let pinned = events
            .iter()
            .find(|e| e["path"] == "pinned")
            .expect("the artifact request is recorded");
        assert_eq!(pinned["version"], "4.17.21");
        assert_eq!(pinned["action"], "block");
    }

    /// `pkg` with 1.0.0, published in 2020, and 2.0.0, published now.
    fn two_versions() -> PackageMetadata {
        let version = |v: &str| {
            serde_json::json!({"name": "pkg", "version": v, "dist": {
                "tarball": format!("https://registry.npmjs.org/pkg/-/pkg-{v}.tgz"),
                "integrity": "sha512-AAAA"}})
        };
        let doc = serde_json::json!({
            "name": "pkg",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {"1.0.0": version("1.0.0"), "2.0.0": version("2.0.0")},
            "time": {
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "2.0.0": jiff::Timestamp::now().to_string(),
            },
        });
        npm::normalize_packument(
            doc.to_string().as_bytes(),
            crate::record::DocumentDetail::Full,
        )
        .unwrap()
    }

    const COOLDOWN_AND_DENIAL: &str = "version: 1\ncooldown_days: 7\n\
                                       denials:\n  - purl: pkg:npm/pkg@1.0.0\n    reason: test\n";

    /// The resolution event carries the strongest action of the versions removed: 1.0.0 is
    /// blocked by a denial and 2.0.0 quarantined by the cooldown.
    #[test]
    fn a_resolution_is_recorded_with_its_strongest_action() {
        let path = crate::util::test_support::tempdir("proxy-strongest").join("audit.jsonl");
        let log = AuditLog::open(&path).expect("should open");
        let policy = policy(COOLDOWN_AND_DENIAL);
        let refused =
            policy_refused_versions(&two_versions(), Some(&policy), None, "/pkg", Some(&log));
        assert_eq!(refused.versions.len(), 2);
        assert_eq!(refused.checks, ["cooldown_days", "denials"]);
        let written = std::fs::read_to_string(&path).expect("should read");
        let event: serde_json::Value = serde_json::from_str(written.trim()).unwrap();
        assert_eq!(event["action"], "block");
        assert_eq!(
            event["checks"],
            serde_json::json!(["cooldown_days", "denials"])
        );
    }

    /// A document with every version removed reads as a broken registry to the client, so
    /// the proxy says so. One with a version left does not.
    #[test]
    fn a_document_with_every_version_refused_is_reported() {
        let refusing = |yaml: &str| {
            let policy = policy(yaml);
            logged(|| {
                policy_refused_versions(&two_versions(), Some(&policy), None, "/pkg", None);
            })
        };
        let every = refusing(COOLDOWN_AND_DENIAL);
        assert!(every.contains("policy refuses every version"), "{every}");
        assert_eq!(
            refusing("version: 1\ncooldown_days: 7\n"),
            "",
            "1.0.0 is left"
        );
        assert_eq!(refusing(NO_POLICY), "", "nothing refused");
    }

    /// The record budget is the one given, not the default.
    #[test]
    fn the_record_store_holds_the_budget_it_is_given() {
        let proxy = offline(None, None).with_max_records(1);
        hold(&proxy, LODASH);
        hold(&proxy, ESBUILD);
        assert_eq!(proxy.store.lock().unwrap().records(), 1);
    }

    /// An artifact the proxy cannot serve is removed from the packument, so a resolver
    /// picks a version that can be examined. It is the only control that works: the client
    /// would fetch that URL from `elsewhere.example` and never ask the proxy. With the
    /// refusal off, the document is forwarded as it came, and the URL stays as it was:
    /// rewriting it would mean the proxy fetching from an arbitrary host.
    #[tokio::test]
    async fn versions_the_proxy_cannot_serve_are_removed_from_the_packument() {
        let refusing = offline(None, None).with_refuse_unservable(true);
        let DocumentStep::Forward {
            body: Some(body), ..
        } = resolve(
            &refusing,
            "/widget",
            npm::ABBREVIATED_ACCEPT,
            OFFSITE_PACKUMENT.as_bytes(),
        )
        .await
        else {
            panic!("the packument is rewritten");
        };
        let served: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(served["versions"].as_object().unwrap().is_empty());
        assert!(
            served["dist-tags"].as_object().unwrap().is_empty(),
            "a tag naming a removed version resolves to nothing"
        );

        let forwarding = offline(None, None);
        let forwarded = resolve(
            &forwarding,
            "/widget",
            npm::ABBREVIATED_ACCEPT,
            OFFSITE_PACKUMENT.as_bytes(),
        )
        .await;
        assert!(matches!(
            forwarded,
            DocumentStep::Forward { body: None, .. }
        ));
    }

    /// A pinned fetch of a version the filter removes. Decision #4: filter on resolution,
    /// hard fail on a pinned fetch, because there is no resolution left to influence.
    /// Clients bucket status codes differently, so the status is configurable by
    /// (ecosystem, client). pnpm and yarn both carry `npm/` in their user-agent, so this
    /// also checks the client is read from the first token.
    #[tokio::test]
    async fn a_pinned_fetch_of_an_unservable_artifact_is_refused_with_the_clients_status() {
        let proxy = offline(None, None)
            .with_refuse_unservable(true)
            .with_refusal_status(
                crate::refusal::RefusalStatus::parse("default=403,npm/pnpm=451").unwrap(),
            );
        hold_document(
            &proxy,
            OFFSITE_PACKUMENT.as_bytes(),
            crate::record::DocumentDetail::Abbreviated,
        );
        for (agent, expected) in [
            ("pnpm/10.33.0 npm/? node/v20.11.1 linux x64", 451),
            ("npm/9.9.4 node/v16.20.1 linux x64", 403),
            ("yarn/1.22.22 npm/? node/v16.20.1 linux x64", 403),
        ] {
            let step = pinned_by(&proxy, "/widget/-/widget-1.0.0.tgz", agent).await;
            let (status, body) = refused(step).await;
            assert_eq!(status.as_u16(), expected, "{agent}");
            assert!(body.contains("elsewhere.example"), "{agent}: {body}");
        }
    }

    /// With rewriting off, a document no policy changes is forwarded as it came.
    #[tokio::test]
    async fn rewriting_can_be_turned_off() {
        let proxy = offline(None, None).with_artifact_rewriting(false);
        assert!(matches!(
            resolve_npm(&proxy, "lodash", LODASH).await,
            DocumentStep::Forward { body: None, .. }
        ));
    }

    /// A 200 carrying something unreadable, or in an encoding this cannot decode, is
    /// forwarded rather than turned into a 502: it is our gap, not an upstream outage.
    #[tokio::test]
    async fn a_document_the_proxy_cannot_read_is_forwarded_as_it_came() {
        let proxy = offline(None, None);
        let junk = resolve(
            &proxy,
            "/lodash",
            npm::ABBREVIATED_ACCEPT,
            b"<html>maintenance</html>",
        )
        .await;
        assert!(matches!(junk, DocumentStep::Forward { body: None, .. }));

        let (ecosystem, target) = crate::route::classify("/lodash");
        let negotiation = negotiate(
            &proxy,
            ecosystem,
            &target,
            &Method::GET,
            &client_headers("gzip"),
        );
        let brotli = filtered_document(
            &proxy,
            DocumentKind::Packument(crate::record::DocumentDetail::Abbreviated),
            &Bytes::from_static(b"\x1b[brotli bytes]"),
            Some("br"),
            &negotiation,
            "/lodash",
        )
        .await;
        assert!(matches!(brotli, DocumentStep::Forward { body: None, .. }));
    }

    /// A rewritten body is this proxy's, so its length, encoding and entity tag describe
    /// it. A body that was not rewritten goes as it came, headers included.
    #[tokio::test]
    async fn a_rewritten_body_carries_its_own_length_encoding_and_tag() {
        let mut upstream = HeaderMap::new();
        upstream.insert(header::CONTENT_LENGTH, HeaderValue::from_static("8"));
        upstream.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        upstream.insert(header::ETAG, HeaderValue::from_static("\"t\""));
        let base = "http://proxy.test";
        let finished = |rewritten: Option<&[u8]>, encoding| {
            finish(
                rewritten.map(<[u8]>::to_vec),
                Bytes::from_static(b"original"),
                upstream.clone(),
                StatusCode::OK,
                encoding,
                Some(base),
                "/lodash",
                |_| {},
            )
        };

        let (status, body) = read(finished(Some(b"rewritten"), RequestedEncoding::Identity)).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "rewritten"));
        let response = finished(Some(b"rewritten"), RequestedEncoding::Identity);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "9");
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(response.headers()[header::ETAG], mark_etag("\"t\"", base));

        let gzipped = finished(Some(b"rewritten"), RequestedEncoding::Gzip);
        assert_eq!(gzipped.headers()[header::CONTENT_ENCODING], "gzip");
        let bytes = axum::body::to_bytes(gzipped.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            decode_for_parsing(&bytes, Some("gzip"), 1 << 10).unwrap(),
            b"rewritten"
        );

        let unread = finished(None, RequestedEncoding::Identity);
        assert_eq!(unread.headers(), &upstream);
        assert_eq!(read(unread).await.1, "original");
    }

    /// The settings that decide what gets examined are visible without reading a running
    /// process's environment.
    #[test]
    fn health_reports_the_settings_that_decide_what_is_examined() {
        let health = offline(None, None)
            .with_refuse_unservable(true)
            .with_public_base(Some("https://npm.corp.example".into()))
            .with_origin_policy([], ["https://cdn.example"])
            .unwrap()
            .health();
        assert_eq!(health.service, "waharoa");
        assert_eq!(
            health.public_base.as_deref(),
            Some("https://npm.corp.example")
        );
        assert!(health.rewrite_artifacts);
        assert!(health.refuse_unservable);
        assert_eq!(health.allowed_direct_origins, ["https://cdn.example"]);
    }

    /// A refusal is on identity, not on the spelling of the path. `@babel%2ftraverse` and
    /// `@babel/traverse` are the same package, and a denial written either way reaches
    /// both.
    #[tokio::test]
    async fn a_denial_matches_both_spellings_of_a_scoped_name() {
        for spelling in [
            "pkg:npm/%40babel/traverse@8.0.5",
            "pkg:npm/@babel/traverse@8.0.5",
        ] {
            let yaml = DENY_LODASH.replace("pkg:npm/lodash@4.17.21", spelling);
            let proxy = offline(None, Some(&yaml));
            hold(&proxy, "@babel_traverse-8.0.5.abbrev.json");
            for path in [
                "/@babel%2ftraverse/-/traverse-8.0.5.tgz",
                "/@babel/traverse/-/traverse-8.0.5.tgz",
            ] {
                let (status, _) = refused(pinned(&proxy, path).await).await;
                assert_eq!(status, 403, "{spelling} did not reach {path}");
            }
        }
    }

    /// A client asks for the abbreviated packument, which has no `time` map, so a
    /// cooldown on npm is answered only by the full packument the proxy fetches itself.
    #[tokio::test]
    async fn a_cooldown_on_npm_reads_the_full_packument_the_client_did_not_ask_for() {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let router = Router::new().fallback(any(move |req: Request| {
            let seen = recorder.clone();
            async move {
                seen.lock().unwrap().paths.push(req.uri().to_string());
                let full = req
                    .headers()
                    .get(header::ACCEPT)
                    .is_some_and(|accept| accept == npm::FULL_ACCEPT);
                let (content_type, name) = if full {
                    (npm::FULL_ACCEPT, LODASH_FULL)
                } else {
                    (npm::ABBREVIATED_ACCEPT, LODASH)
                };
                Response::builder()
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(fixture(name)))
                    .unwrap()
            }
        }));
        let upstream = serve(router).await;
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream)
            .with_refuse_unservable(false)
            .with_policy(Some(policy("version: 1\ncooldown_days: 36500\n")));
        let base = serve(proxy.router()).await;

        let tarball = "/lodash/-/lodash-4.17.21.tgz";
        assert_refused_pinned(&base, &seen, tarball, "cooldown_days").await;
        assert!(!offered(&base, "lodash", "4.17.21").await);
    }

    /// A version published after an earlier request is held back on the next one. Publish
    /// times were kept per package once fetched, so a version newer than that fetch had no
    /// time, `cooldown_days` was unenforceable for it, and the newest version went through.
    /// Now each metadata request reads the full document, once, and its records carry the
    /// times.
    #[tokio::test]
    async fn a_version_published_after_an_earlier_request_is_held_back_by_the_cooldown() {
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let published = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (recorder, publisher) = (requests.clone(), published.clone());
        let router = Router::new().fallback(any(move |req: Request| {
            let (requests, published) = (recorder.clone(), publisher.clone());
            async move {
                let accept = req
                    .headers()
                    .get(header::ACCEPT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_owned();
                let mut seen = requests.lock().unwrap();
                seen.push(accept);
                let now = jiff::Timestamp::now().to_string();
                let version = |v: &str| {
                    serde_json::json!({"name": "pkg", "version": v, "dist": {
                        "tarball": format!("https://registry.npmjs.org/pkg/-/pkg-{v}.tgz"),
                        "integrity": "sha512-AAAA"}})
                };
                let mut doc = serde_json::json!({
                    "name": "pkg",
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {"1.0.0": version("1.0.0")},
                    "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
                });
                if published.load(std::sync::atomic::Ordering::SeqCst) {
                    doc["versions"]["2.0.0"] = version("2.0.0");
                    doc["time"]["2.0.0"] = serde_json::Value::String(now);
                    doc["dist-tags"]["latest"] = "2.0.0".into();
                }
                // As the registry does: the abbreviated document has no `time` map.
                let full = seen.last().is_some_and(|accept| accept == npm::FULL_ACCEPT);
                if !full {
                    doc.as_object_mut().unwrap().remove("time");
                }
                Response::builder()
                    .header(
                        header::CONTENT_TYPE,
                        if full {
                            npm::FULL_ACCEPT
                        } else {
                            npm::ABBREVIATED_ACCEPT
                        },
                    )
                    .body(Body::from(doc.to_string()))
                    .unwrap()
            }
        }));
        let upstream = serve(router).await;
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream)
            .with_refuse_unservable(false)
            .with_policy(Some(policy("version: 1\ncooldown_days: 7\n")));
        let base = serve(proxy.router()).await;

        assert!(offered(&base, "pkg", "1.0.0").await);
        published.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            !offered(&base, "pkg", "2.0.0").await,
            "published today, inside the cooldown"
        );
        let accepts = requests.lock().unwrap().clone();
        assert_eq!(
            accepts,
            [npm::FULL_ACCEPT; 2],
            "one full-document request per client request, and nothing else"
        );
    }

    const PYPI_INDEX: &[u8] = br#"{"name":"x","files":[
        {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/23/x-1.0.tar.gz","hashes":{}}
    ]}"#;

    /// No stream in the snapshot covers PyPI, so a file is not served: an empty answer
    /// would read as "nothing known" about a package nothing was asked about. The index is
    /// served, because pip reports an index 503 as `No matching distribution found`: see
    /// `UncoveredMetadata::FilterWithoutIntel`.
    #[tokio::test]
    async fn a_file_in_an_ecosystem_no_stream_covers_is_a_503() {
        let proxy = offline(Some(malware_everywhere()), Some(NO_POLICY));
        let index = resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, PYPI_INDEX).await;
        assert!(matches!(index, DocumentStep::Forward { body: Some(_), .. }));
        let (status, body) = refused(pinned(&proxy, "/packages/ef/01/23/x-1.0.tar.gz").await).await;
        assert_eq!(status, 503);
        assert!(
            body.contains("no advisory stream for pypi"),
            "the body says which ecosystem: {body}"
        );
        // npm is covered by the same snapshot and is served.
        let packument = resolve_npm(&proxy, "lodash", LODASH).await;
        assert!(matches!(
            packument,
            DocumentStep::Forward { body: Some(_), .. }
        ));
    }

    /// Four versions: 1.0 is yanked whole, 2.0 is not, 3.0 offers a wheel and a yanked
    /// sdist, and 4.0 is yanked with no reason. A sha256 on each, so a record carries a
    /// digest.
    const PYPI_YANKED: &[u8] = br#"{"name":"x","files":[
        {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/23/x-1.0.tar.gz","hashes":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"yanked":"broken sdist"},
        {"filename":"x-2.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/24/x-2.0.tar.gz","hashes":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
        {"filename":"x-3.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ef/01/25/x-3.0-py3-none-any.whl","hashes":{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},
        {"filename":"x-3.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/26/x-3.0.tar.gz","hashes":{"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"yanked":"wheel only"},
        {"filename":"x-4.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/27/x-4.0.tar.gz","hashes":{"sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"yanked":true}
    ]}"#;

    const YANKED_FILE: &str = "/packages/ef/01/23/x-1.0.tar.gz";
    /// 3.0's sdist, yanked, beside a wheel that is not.
    const YANKED_SDIST: &str = "/packages/ef/01/26/x-3.0.tar.gz";
    /// 4.0, yanked with `true` and no reason.
    const YANKED_NO_REASON: &str = "/packages/ef/01/27/x-4.0.tar.gz";

    /// A yanked version is removed from the index and refused on a pinned fetch, unless the
    /// policy allows yanked files.
    #[tokio::test]
    async fn a_yanked_version_is_refused_and_filtered() {
        yanked_is_refused_and_filtered().await;
    }

    /// The body of the test above, which
    /// `every_check_refuses_on_a_pinned_fetch_and_filters_the_packument` also runs, so that
    /// every check has a case there.
    async fn yanked_is_refused_and_filtered() {
        // Both versions are sdists, so `install_scripts` is allowed here and the only
        // check that can remove a file is the yank.
        const ALLOW_SDISTS: &str = "version: 1\ncooldown_days: 0\ninstall_scripts: allow\n";
        let refusing = offline(None, Some(ALLOW_SDISTS));
        assert_eq!(
            served_filenames(&refusing, PYPI_YANKED).await,
            ["x-2.0.tar.gz", "x-3.0-py3-none-any.whl", "x-3.0.tar.gz"],
            "1.0 and 4.0 are yanked whole and gone; 3.0 keeps a file, so the version stays"
        );
        for (file, told) in [
            (YANKED_FILE, "yanked: withdrawn, broken sdist"),
            (YANKED_SDIST, "yanked: withdrawn, wheel only"),
            // PEP 592 allows a bare `true`, and then there is no reason to repeat.
            (YANKED_NO_REASON, "yanked: withdrawn by the registry"),
        ] {
            let (status, body) = refused(pinned(&refusing, file).await).await;
            assert_eq!(status, 403, "{file}");
            assert!(
                body.contains(told),
                "the publisher's reason is what the client is told: {body}"
            );
        }
        assert!(
            fetched(&pinned(&refusing, "/packages/ef/01/25/x-3.0-py3-none-any.whl").await),
            "the wheel beside the yanked sdist is served"
        );

        let allowing = offline(None, Some(&format!("{ALLOW_SDISTS}yanked: allow\n")));
        assert_eq!(
            served_filenames(&allowing, PYPI_YANKED).await,
            [
                "x-1.0.tar.gz",
                "x-2.0.tar.gz",
                "x-3.0-py3-none-any.whl",
                "x-3.0.tar.gz",
                "x-4.0.tar.gz"
            ]
        );
        assert!(fetched(&pinned(&allowing, YANKED_FILE).await));
        assert!(fetched(&pinned(&allowing, YANKED_SDIST).await));
    }

    /// Two versions: 1.0 offers a wheel, 2.0 only an sdist.
    const PYPI_TWO_VERSIONS: &[u8] = br#"{"name":"x","files":[
        {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/ef/x-1.0-py3-none-any.whl","hashes":{}},
        {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/23/x-1.0.tar.gz","hashes":{}},
        {"filename":"x-2.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/24/x-2.0.tar.gz","hashes":{}}
    ]}"#;

    /// The filenames the client receives for `index`.
    async fn served_filenames(proxy: &Proxy, index: &[u8]) -> Vec<String> {
        let DocumentStep::Forward {
            body: Some(body), ..
        } = resolve(proxy, "/simple/x/", pypi::SIMPLE_JSON, index).await
        else {
            panic!("the index is read and rewritten");
        };
        let document: serde_json::Value = serde_json::from_slice(&body).expect("json");
        document["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| f["filename"].as_str().expect("a filename").to_owned())
            .collect()
    }

    /// The resolution half for PyPI. 2.0 runs `setup.py` whichever file pip takes, so it
    /// is removed and pip resolves to 1.0. 1.0's sdist stays: the version offers a wheel,
    /// and a request for the sdist is refused at the file.
    #[tokio::test]
    async fn a_pypi_version_the_policy_refuses_is_removed_from_the_index() {
        let blocking = offline(
            None,
            Some("version: 1\ncooldown_days: 0\ninstall_scripts: block\n"),
        );
        let names = served_filenames(&blocking, PYPI_TWO_VERSIONS).await;
        assert_eq!(names, ["x-1.0-py3-none-any.whl", "x-1.0.tar.gz"]);

        let allowing = offline(
            None,
            Some("version: 1\ncooldown_days: 0\ninstall_scripts: allow\n"),
        );
        let unfiltered = served_filenames(&allowing, PYPI_TWO_VERSIONS).await;
        assert_eq!(unfiltered.len(), 3, "nothing refused, nothing removed");
    }

    /// With no stream covering PyPI the index is still filtered by the checks that need no
    /// intel. The file request answers 503, held by
    /// `a_file_in_an_ecosystem_no_stream_covers_is_a_503`.
    #[tokio::test]
    async fn a_pypi_index_no_stream_covers_is_filtered_without_intel() {
        let proxy = offline(
            Some(malware_everywhere()),
            Some("version: 1\ncooldown_days: 0\ninstall_scripts: block\n"),
        );
        let names = served_filenames(&proxy, PYPI_TWO_VERSIONS).await;
        assert_eq!(names, ["x-1.0-py3-none-any.whl", "x-1.0.tar.gz"]);
    }

    /// A snapshot that loaded no stream, so it covers no ecosystem.
    struct NoStreams;

    impl Intel for NoStreams {
        fn lookup<'a>(
            &'a self,
            _ecosystem: &'a str,
            _name: &'a str,
            _version: &'a str,
        ) -> crate::intel::store::Lookup<'a, Vec<crate::intel::store::Record>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn snapshot(&self) -> crate::intel::store::Lookup<'_, Option<LoadedSnapshot>> {
            Box::pin(async move {
                Ok(Some(LoadedSnapshot {
                    digest: "s0".to_owned(),
                    taken_at: "2026-09-18T00:00:00Z".to_owned(),
                    sources: Vec::new(),
                    streams: Vec::new(),
                }))
            })
        }

        fn package<'a>(
            &'a self,
            _ecosystem: &'a str,
            _name: &'a str,
        ) -> crate::intel::store::Lookup<'a, Option<PackageIntel>> {
            Box::pin(async move {
                Ok(Some(PackageIntel {
                    snapshot: "s0".to_owned(),
                    records: Vec::new(),
                    ranges: Vec::new(),
                    exploitation_loaded: false,
                }))
            })
        }
    }

    /// npm clients report a packument 503 as one, so npm's row keeps it.
    #[tokio::test]
    async fn an_npm_packument_no_stream_covers_is_a_503() {
        let proxy = offline(Some(Arc::new(NoStreams)), Some(NO_POLICY));
        let (status, body) = answered(resolve_npm(&proxy, "lodash", LODASH).await).await;
        assert_eq!(status, 503);
        assert!(body.contains("no advisory stream for npm"), "{body}");
    }

    /// A store whose records name one snapshot and whose newest snapshot is another, as
    /// a refresh between the two reads leaves it. Counts how often it is asked for the
    /// snapshot.
    struct Refreshed {
        records_from: &'static str,
        newest: &'static str,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl Intel for Refreshed {
        fn lookup<'a>(
            &'a self,
            _ecosystem: &'a str,
            _name: &'a str,
            _version: &'a str,
        ) -> crate::intel::store::Lookup<'a, Vec<crate::intel::store::Record>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn snapshot(&self) -> crate::intel::store::Lookup<'_, Option<LoadedSnapshot>> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                Ok(Some(LoadedSnapshot {
                    digest: self.newest.to_owned(),
                    taken_at: "2026-09-17T00:00:00Z".to_owned(),
                    sources: Vec::new(),
                    streams: vec![crate::intel::refresh::StreamDigest {
                        stream: crate::intel::providers::osv::bundle::NPM_STREAM.to_owned(),
                        sha256: "aa".to_owned(),
                        etag: None,
                        last_modified: None,
                    }],
                }))
            })
        }

        fn package<'a>(
            &'a self,
            _ecosystem: &'a str,
            _name: &'a str,
        ) -> crate::intel::store::Lookup<'a, Option<PackageIntel>> {
            Box::pin(async move {
                Ok(Some(PackageIntel {
                    snapshot: self.records_from.to_owned(),
                    records: Vec::new(),
                    ranges: Vec::new(),
                    exploitation_loaded: false,
                }))
            })
        }
    }

    fn refreshed(records_from: &'static str, newest: &'static str) -> Arc<Refreshed> {
        Arc::new(Refreshed {
            records_from,
            newest,
            asked: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Coverage is read from the snapshot the records came from. When the newest is a
    /// different one, nothing is decided.
    #[tokio::test]
    async fn records_from_a_replaced_snapshot_are_not_decided_on() {
        let proxy = offline(Some(refreshed("s1", "s2")), Some(NO_POLICY));
        let (status, body) = answered(resolve_npm(&proxy, "lodash", LODASH).await).await;
        assert_eq!(status, 503);
        assert!(
            body.contains("intel store cannot answer"),
            "this is the store's answer changing, not a coverage gap: {body}"
        );
    }

    /// The store is asked for its snapshot once per snapshot, not once per request.
    #[tokio::test]
    async fn a_snapshot_is_read_once_for_its_digest() {
        let store = refreshed("s1", "s1");
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, NO_UPSTREAM)
            .with_intel(Some(store.clone()))
            .with_policy(Some(policy("version: 1\n")));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        for _ in 0..3 {
            assert!(matches!(
                intel_for(&proxy, &key, "/lodash").await,
                Ok(Some(_))
            ));
        }
        assert_eq!(store.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Ready exactly when a package request would not get the intel 503.
    #[tokio::test]
    async fn readiness_depends_on_the_store_only_when_a_policy_is_set() {
        use crate::intel::store::testing::FixedIntel;
        let proxy = |intel: Option<Arc<dyn Intel>>, with_policy: bool| {
            let proxy = Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, NO_UPSTREAM)
                .with_intel(intel);
            if with_policy {
                proxy.with_policy(Some(policy("version: 1\n")))
            } else {
                proxy
            }
        };
        let down = || Some(Arc::new(FixedIntel(Err(()))) as Arc<dyn Intel>);
        for (label, intel, with_policy, expected) in [
            ("no store", None, true, (true, IntelState::NotConsulted)),
            ("no policy", down(), false, (true, IntelState::NotConsulted)),
            (
                "loaded",
                Some(malware_everywhere()),
                true,
                (true, IntelState::Loaded),
            ),
            (
                "empty",
                Some(Arc::new(FixedIntel(Ok(None))) as Arc<dyn Intel>),
                true,
                (false, IntelState::Empty),
            ),
            ("down", down(), true, (false, IntelState::Unavailable)),
        ] {
            let readiness = proxy(intel, with_policy).readiness().await;
            assert_eq!((readiness.ready, readiness.intel), expected, "{label}");
            assert_eq!(
                readiness.snapshot.is_some(),
                expected.1 == IntelState::Loaded,
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn the_ready_path_answers_503_until_a_snapshot_can_be_read() {
        use crate::intel::store::testing::FixedIntel;
        let (base, _) = proxy_with_intel(Arc::new(FixedIntel(Err(()))), true).await;
        let response = reqwest::get(format!("{base}{READY_PATH}")).await.unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"ready":false,"intel":"unavailable","snapshot":null}"#,
            "the store's error is logged, not served"
        );

        let (base, seen) = proxy_with_intel(malware_everywhere(), true).await;
        let response = reqwest::get(format!("{base}{READY_PATH}?probe=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"ready":true,"intel":"loaded","snapshot":{"digest":"s1","taken_at":"2026-09-13T00:00:00Z","sources":[],"streams":[{"stream":"osv/npm","sha256":"aa","etag":null,"last_modified":null}]}}"#,
            "the body a probe and the README describe"
        );
        let paths = &seen.lock().unwrap().paths;
        assert!(paths.is_empty(), "answered here, not forwarded: {paths:?}");
    }

    /// An upstream that sends no response is 502. §5 forbids any 4xx for a not-ready state,
    /// because a 4xx from a registry proxy reads as "policy denied you".
    #[tokio::test]
    async fn an_upstream_that_sends_no_response_is_502() {
        let addr = crate::util::test_support::closing_server().await;

        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, format!("http://{addr}"))
                .router(),
        )
        .await;
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

    /// §5: a not-ready state never wears a code that reads as a block. A 4xx from a
    /// registry proxy means policy denied you, so every state that is not a denial has to
    /// be a 5xx.
    ///
    /// This enumerates the statuses the proxy produces of its own accord. Codes forwarded
    /// from upstream are not among them: those are the registry's answer, covered by
    /// `upstream_statuses_pass_through_unchanged`.
    #[tokio::test]
    async fn the_only_4xx_this_proxy_produces_is_a_policy_refusal() {
        let addr = crate::util::test_support::closing_server().await;
        let dead = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, format!("http://{addr}"))
                .router(),
        )
        .await;

        // Every request kind, because a tarball looks its packument up first and so has
        // a second way to meet an upstream that sends no response.
        for path in ["/lodash", "/lodash/-/lodash-4.17.21.tgz", "/-/ping"] {
            let status = reqwest::get(format!("{dead}{path}"))
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{path}");
        }

        // The one 4xx, and it is a denial rather than a state. It needs a live upstream:
        // a denial names an exact version, so the packument has to be read before the
        // policy has anything to answer about. An unreachable registry is a 502 for every
        // request, including one the policy would have refused had it known.
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let live = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_policy(Some(policy(
                    "version: 1\ncooldown_days: 0\n\
                     denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
                )))
                .with_refuse_unservable(false)
                .router(),
        )
        .await;
        let refused = reqwest::get(format!("{live}/lodash/-/lodash-4.17.21.tgz"))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            RefusalStatus::default().default_status(),
            403,
            "the default refusal is what makes the code above a denial and not an accident"
        );

        // Health is the proxy describing itself, and it is always ready to do that.
        let health = reqwest::get(format!("{dead}{HEALTH_PATH}")).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
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
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;

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
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;

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
        serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await
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

    async fn artifacts_verified(base: &str) -> usize {
        let body = reqwest::get(format!("{base}{HEALTH_PATH}"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str::<Health>(&body)
            .unwrap()
            .artifacts_verified
    }

    /// Plan §5 branches the fetch path on whether this artifact has been past before.
    /// The digest is the key, and it is known before the fetch.
    #[tokio::test]
    async fn a_verified_artifact_is_remembered_by_its_digest() {
        let tarball: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let base = registry_with(&sri_of(&tarball), tarball.clone()).await;
        assert_eq!(artifacts_verified(&base).await, 0);

        reqwest::get(format!("{base}/widget")).await.unwrap();
        reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(artifacts_verified(&base).await, 1);

        // A hit still hashes. Skipping it would mean a registry that served correct bytes
        // once could serve anything afterwards, which is what the verification exists to
        // catch. The body arriving whole is what proves the check ran.
        let again = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(again.bytes().await.unwrap().as_ref(), tarball.as_slice());
        assert_eq!(
            artifacts_verified(&base).await,
            1,
            "the same artifact is one entry, not two"
        );
    }

    /// A mismatch is the registry serving bytes its own packument does not describe.
    /// Recording that would be recording the attack, and a later request for the same
    /// digest would read as already seen.
    #[tokio::test]
    async fn a_tarball_that_fails_its_digest_is_not_remembered() {
        let honest: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut tampered = honest.clone();
        tampered[25_000] ^= 0xFF;

        let base = registry_with(&sri_of(&honest), tampered).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();
        assert_no_complete_body(&format!("{base}/widget/-/widget-1.0.0.tgz")).await;

        assert_eq!(artifacts_verified(&base).await, 0);
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
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;

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
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;

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
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .with_max_concurrent_documents(1)
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

    /// `/-/` is the registry's own namespace, and everything else under it still goes
    /// upstream. Only the one exact path is claimed.
    #[tokio::test]
    async fn other_registry_endpoints_are_still_forwarded() {
        let (base, seen) = proxy_serving(
            StatusCode::OK,
            "application/json",
            None,
            b"{\"objects\":[]}".to_vec(),
        )
        .await;

        for path in ["/-/v1/search?text=lodash", "/-/whoami", "/-/waharoa/other"] {
            let response = reqwest::get(format!("{base}{path}")).await.unwrap();
            assert_eq!(response.status(), 200, "{path}");
        }
        assert_eq!(seen.lock().unwrap().paths.len(), 3);
    }

    /// An upstream set after the origin policy keeps the origins the operator added, and
    /// the upstream replaced is no longer served.
    #[test]
    fn the_builders_give_the_same_origins_in_either_order() {
        let origins = |proxy: &Proxy| proxy.origin_policy().reachable().as_slice().to_vec();
        let policy_first = Proxy::new(reqwest::Client::new())
            .with_origin_policy(["https://cdn.example"], ["https://direct.example"])
            .expect("valid origins")
            .with_upstream(Ecosystem::Npm, "https://npm.mirror.example/")
            .with_upstream(Ecosystem::PyPI, "https://pypi.mirror.example/simple");
        let upstreams_first = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, "https://npm.mirror.example/")
            .with_upstream(Ecosystem::PyPI, "https://pypi.mirror.example/simple")
            .with_origin_policy(["https://cdn.example"], ["https://direct.example"])
            .expect("valid origins");
        assert_eq!(origins(&policy_first), origins(&upstreams_first));
        for origin in [
            "https://npm.mirror.example",
            "https://pypi.mirror.example",
            "https://cdn.example",
            "https://registry.npmjs.org",
        ] {
            assert!(
                origins(&policy_first).contains(&origin.to_owned()),
                "{origin}: {:?}",
                origins(&policy_first)
            );
        }
        assert_eq!(
            policy_first.origin_policy().allowed_direct(),
            upstreams_first.origin_policy().allowed_direct()
        );
        assert!(
            policy_first
                .origin_policy()
                .reachable()
                .routes_directly("https://cdn.example")
        );
    }

    #[test]
    #[should_panic(expected = "upstream is not a usable origin")]
    fn an_upstream_with_no_host_is_refused() {
        let _ = Proxy::new(reqwest::Client::new()).with_upstream(Ecosystem::Npm, "not a url");
    }

    #[test]
    fn the_upstream_base_drops_a_trailing_slash() {
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, "https://registry.npmjs.org/");
        assert_eq!(
            proxy.upstreams().get(Ecosystem::Npm),
            "https://registry.npmjs.org"
        );
        assert_eq!(proxy.upstreams().get(Ecosystem::PyPI), pypi::INDEX);
        let proxy = proxy.with_upstream(Ecosystem::PyPI, "https://mirror.example/simple/");
        assert_eq!(
            proxy.upstreams().get(Ecosystem::PyPI),
            "https://mirror.example/simple"
        );
        assert_eq!(
            proxy.upstreams().to_string(),
            "npm=https://registry.npmjs.org pypi=https://mirror.example/simple"
        );
        let both = Proxy::new(reqwest::Client::new()).with_upstreams(proxy.upstreams().clone());
        assert_eq!(both.upstreams(), proxy.upstreams());
    }

    mod routing {
        use super::*;
        use crate::route::IndexFormat;

        fn proxy() -> Proxy {
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, "https://registry.npmjs.org")
        }

        fn upstream_of(path: &str) -> String {
            let proxy = proxy();
            upstream_url(&proxy, crate::route::classify(path).0, path, None)
        }

        /// npm at the root, PyPI under the two prefixes it reserves.
        #[test]
        fn the_path_decides_which_registry_answers() {
            for (path, ecosystem) in [
                ("/lodash", Ecosystem::Npm),
                ("/@babel%2fcore", Ecosystem::Npm),
                ("/lodash/-/lodash-4.17.21.tgz", Ecosystem::Npm),
                ("/-/v1/search?text=lodash", Ecosystem::Npm),
                ("/simple", Ecosystem::Npm),
                ("/packages", Ecosystem::Npm),
                ("/simple/", Ecosystem::PyPI),
                ("/simple/requests/", Ecosystem::PyPI),
                ("/packages/a/b/c/requests-2.32.3.tar.gz", Ecosystem::PyPI),
                ("/packages/nonsense", Ecosystem::PyPI),
            ] {
                assert_eq!(crate::route::classify(path).0, ecosystem, "{path}");
            }
        }

        /// npm's own paths are untouched: the configured registry with the client's path
        /// appended, which is what every Stage 1 and Stage 2 test measures.
        #[test]
        fn an_npm_request_goes_where_it_always_did() {
            assert_eq!(upstream_of("/lodash"), "https://registry.npmjs.org/lodash");
            assert_eq!(
                upstream_of("/lodash/-/lodash-4.17.21.tgz"),
                "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            );
            assert_eq!(
                upstream_of("/-/v1/search?text=lodash"),
                "https://registry.npmjs.org/-/v1/search?text=lodash"
            );
        }

        /// The configured base already ends in `/simple`, so the proxy's own prefix comes
        /// off rather than being sent twice.
        #[test]
        fn the_index_prefix_is_not_sent_twice() {
            assert_eq!(
                upstream_of("/simple/requests/"),
                "https://pypi.org/simple/requests/"
            );
            assert_eq!(upstream_of("/simple/"), "https://pypi.org/simple/");
            let proxy =
                proxy().with_upstream(Ecosystem::PyPI, "https://mirror.example/pypi/simple");
            assert_eq!(
                upstream_url(&proxy, Ecosystem::PyPI, "/simple/requests/", None),
                "https://mirror.example/pypi/simple/requests/"
            );
        }

        /// A file goes to the host the index names, with the hash segments the client
        /// followed kept: they are what locate it.
        #[test]
        fn a_file_goes_to_the_files_host_with_its_hash_path_kept() {
            let path = "/packages/f9/9b/335f/requests-2.32.3-py3-none-any.whl";
            assert_eq!(
                upstream_of(path),
                format!("https://files.pythonhosted.org{path}")
            );
            assert_eq!(
                upstream_of("/packages/nonsense"),
                "https://files.pythonhosted.org/packages/nonsense",
                "a path under the prefix that names no file was still aimed here"
            );
        }

        /// An origin the operator added for artifacts wins for either ecosystem, which is
        /// what the additional-origins list is for.
        #[test]
        fn an_added_artifact_origin_wins() {
            let proxy = proxy();
            for path in [
                "/lodash/-/lodash-4.17.21.tgz",
                "/packages/a/b/c/requests-2.32.3.tar.gz",
            ] {
                let ecosystem = crate::route::classify(path).0;
                assert_eq!(
                    upstream_url(&proxy, ecosystem, path, Some("https://cdn.example")),
                    format!("https://cdn.example{path}"),
                    "{path}"
                );
            }
        }

        fn uninspected_for(
            path: &str,
            encoding: RequestedEncoding,
            base: Option<&str>,
            rewriting: bool,
        ) -> Option<Uninspected> {
            let target = crate::route::classify(path).1;
            uninspected(&target, &Method::GET, encoding, base, rewriting)
        }

        /// A packument the proxy is about to rewrite is inspected, and so is one an
        /// operator turned rewriting off for: that is a configured choice.
        #[test]
        fn a_rewritten_packument_is_not_reported() {
            assert_eq!(
                uninspected_for("/lodash", RequestedEncoding::Gzip, Some("http://p"), true),
                None
            );
            assert_eq!(
                uninspected_for("/lodash", RequestedEncoding::Gzip, Some("http://p"), false),
                None,
                "rewriting is off, which the operator asked for"
            );
        }

        /// The two npm cases, in the order the proxy reports them.
        #[test]
        fn a_packument_that_cannot_be_rewritten_says_which_reason() {
            assert_eq!(
                uninspected_for(
                    "/lodash",
                    RequestedEncoding::Unreadable,
                    Some("http://p"),
                    false
                ),
                Some(Uninspected::Unreadable)
            );
            assert_eq!(
                uninspected_for("/lodash", RequestedEncoding::Unreadable, None, false),
                Some(Uninspected::Unreadable),
                "an unreadable body is reported before a missing base"
            );
            assert_eq!(
                uninspected_for("/lodash", RequestedEncoding::Gzip, None, false),
                Some(Uninspected::NoBase)
            );
        }

        /// A simple index answers the same two reasons a packument does: both are
        /// rewritten, and a document that cannot be points its files somewhere the proxy
        /// will not see them.
        #[test]
        fn a_simple_index_answers_the_same_reasons() {
            assert_eq!(
                uninspected_for(
                    "/simple/requests/",
                    RequestedEncoding::Gzip,
                    Some("http://p"),
                    true
                ),
                None
            );
            assert_eq!(
                uninspected_for(
                    "/simple/requests/",
                    RequestedEncoding::Unreadable,
                    Some("http://p"),
                    false
                ),
                Some(Uninspected::Unreadable)
            );
            assert_eq!(
                uninspected_for("/simple/requests/", RequestedEncoding::Gzip, None, false),
                Some(Uninspected::NoBase)
            );
        }

        /// Only a metadata GET. An artifact request carries its own digest check, and a
        /// `HEAD` or `PUT` reads no document.
        #[test]
        fn nothing_else_is_reported() {
            for path in [
                "/lodash/-/lodash-4.17.21.tgz",
                "/packages/a/b/c/requests-2.32.3.tar.gz",
                "/-/v1/search",
                "/simple/",
            ] {
                assert_eq!(
                    uninspected_for(path, RequestedEncoding::Gzip, None, false),
                    None,
                    "{path}"
                );
            }
            let target = crate::route::classify("/lodash").1;
            assert_eq!(
                uninspected(&target, &Method::HEAD, RequestedEncoding::Gzip, None, false),
                None
            );
        }

        /// Each reason prints one line and they are different lines.
        #[test]
        fn every_reason_says_something_different() {
            let all = [Uninspected::Unreadable, Uninspected::NoBase];
            for (i, a) in all.iter().enumerate() {
                assert!(!a.reason().is_empty());
                for b in &all[i + 1..] {
                    assert_ne!(a.reason(), b.reason());
                }
            }
        }

        /// The response says which document arrived, and the request does not. An index
        /// that answers HTML where PEP 691 JSON was asked for reads as nothing.
        #[test]
        fn the_content_type_says_which_document_arrived() {
            use crate::record::DocumentDetail;
            for (ecosystem, content_type, expected) in [
                (
                    Ecosystem::Npm,
                    Some("application/vnd.npm.install-v1+json; charset=utf-8"),
                    Some(DocumentKind::Packument(DocumentDetail::Abbreviated)),
                ),
                (
                    Ecosystem::Npm,
                    Some("application/json"),
                    Some(DocumentKind::Packument(DocumentDetail::Full)),
                ),
                (
                    Ecosystem::PyPI,
                    Some("application/vnd.pypi.simple.v1+json"),
                    Some(DocumentKind::SimpleIndex(IndexFormat::Json)),
                ),
                (
                    Ecosystem::PyPI,
                    Some("APPLICATION/VND.PYPI.SIMPLE.V1+JSON; charset=utf-8"),
                    Some(DocumentKind::SimpleIndex(IndexFormat::Json)),
                ),
                (
                    Ecosystem::PyPI,
                    Some("text/html"),
                    Some(DocumentKind::SimpleIndex(IndexFormat::Html)),
                ),
                // An index may serve PEP 691 under the generic type, which
                // `pypi::Client::project` accepts too.
                (
                    Ecosystem::PyPI,
                    Some("application/json"),
                    Some(DocumentKind::SimpleIndex(IndexFormat::Json)),
                ),
                (
                    Ecosystem::Npm,
                    Some("application/vnd.pypi.simple.v1+json"),
                    None,
                ),
                (Ecosystem::PyPI, None, None),
            ] {
                assert_eq!(
                    crate::ecosystem::of(ecosystem).document(content_type),
                    expected,
                    "{ecosystem:?} {content_type:?}"
                );
            }
        }

        /// A PEP 658 probe is the resolver looking. An index page and a file are not, and
        /// npm has no equivalent, so its own unclassified traffic keeps its level.
        #[test]
        fn a_pep_658_probe_is_the_resolver_looking() {
            for (path, expected) in [
                ("/packages/ab/cd/x-1.0-py3-none-any.whl.metadata", true),
                ("/simple/", true),
                ("/packages/nonsense", true),
                ("/simple/requests/", false),
                ("/packages/ab/cd/x-1.0-py3-none-any.whl", false),
                ("/-/v1/search?text=lodash", false),
                ("/lodash", false),
                ("/lodash/-/lodash-4.17.21.tgz", false),
            ] {
                let (ecosystem, target) = crate::route::classify(path);
                assert_eq!(resolver_probe(ecosystem, &target), expected, "{path}");
            }
        }

        /// PyPI's index and file hosts are reachable, so a file request is served rather
        /// than refused as published on an origin the proxy does not front.
        #[test]
        fn both_pypi_hosts_are_fronted_by_default() {
            let reachable = proxy().origin_policy().reachable().as_slice().to_vec();
            for origin in ["https://pypi.org", "https://files.pythonhosted.org"] {
                assert!(reachable.contains(&origin.to_owned()), "{origin}");
            }
        }
    }
}
