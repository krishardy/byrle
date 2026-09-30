//! The reverse proxy: forward every request, and read, filter and rewrite the metadata
//! documents on the way back. Artifacts stream through, hashed on the way past.
//!
//! See docs/request-flow.md.

use crate::analysis::Claim;
use crate::analysis::attestation;
use crate::analysis::run::{Analyser, Attestation, Job, Known, SourceJob};
use crate::analysis::source::Sourced;
use crate::analysis::store::Scripts;
use crate::audit::{self, AuditLog};
#[cfg(debug_assertions)]
use crate::defer::DeferTest;
use crate::ecosystem::npm::transport::FullDocument;
use crate::ecosystem::{self, Clients, UncoveredMetadata, Upstreams};
use crate::ecosystem::{npm, pypi};
use crate::env::{
    DEFAULT_MAX_CONCURRENT_METADATA, DEFAULT_MAX_METADATA_BYTES, DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_TRAFFIC_CLIENTS, DEFAULT_MAX_VERIFIED,
};
use crate::heuristics::Signal;
use crate::http::{
    RequestedEncoding, decode_for_parsing, encoding_to_request, gzip, is_conditional,
    is_hop_by_hop, mark_etag, unmark_if_none_match,
};
use crate::identity::{Ecosystem, PackageKey};
use crate::integrity::{Sri, Verifier};
use crate::intel::store::{Intel, LoadedSnapshot, PackageIntel};
use crate::origin::{Disposition, OriginPolicy, ReachableOrigins};
use crate::policy::decide::Provenance;
use crate::policy::{Policy, enforce, facts};
use crate::record::{PackageMetadata, PackageRecord};
use crate::refusal::{Mode, RefusalStatus};
use crate::route::{DocumentKind, RequestTarget};
use crate::spool::Spool;
use crate::store::{Lookup, RecordStore};
use crate::util::lru::Lru;
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// The path the proxy answers for itself, under `/-/`, where no package name can be.
pub const HEALTH_PATH: &str = "/-/waharoa/health";

/// Where the proxy says whether it can decide on packages now, for a readiness probe.
pub const READY_PATH: &str = "/-/waharoa/ready";

/// How many versions the policy took out of a metadata document. Absent when it took none.
pub const FILTERED_VERSIONS: header::HeaderName =
    header::HeaderName::from_static("x-waharoa-filtered-versions");

/// Which checks took them out, comma separated, in name order.
pub const FILTERED_CHECKS: header::HeaderName =
    header::HeaderName::from_static("x-waharoa-filtered-checks");

/// Whether the proxy can decide on a package now. Served at [`READY_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Readiness {
    pub ready: bool,
    pub intel: IntelState,
    /// The snapshot decisions use, when the store holds one.
    pub snapshot: Option<LoadedSnapshot>,
    /// Why a loaded snapshot cannot answer for a served ecosystem, which is not ready.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
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

/// What the proxy is, and what it is configured to do, without secrets. Served at [`HEALTH_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    /// Always "waharoa", so a response from something else is recognisable as such.
    pub service: String,
    pub version: String,
    /// Each ecosystem's upstream, by purl type.
    pub upstreams: BTreeMap<String, String>,
    /// The address written into artifact URLs; `None` uses each request's own `Host`.
    pub public_base: Option<String>,
    /// Whether artifact URLs are pointed at this proxy.
    pub rewrite_artifacts: bool,
    /// Whether versions whose artifacts this proxy cannot serve are removed.
    pub refuse_unservable: bool,
    /// `enforce` or `observe`.
    #[serde(default)]
    pub mode: String,
    /// Origins whose artifacts this proxy serves.
    pub served_origins: Vec<String>,
    /// Origins it does not serve and permits a client to fetch directly.
    pub allowed_direct_origins: Vec<String>,
    /// Packages whose metadata is held, and the records in them.
    pub packages_held: usize,
    pub records_held: usize,
    /// Artifacts fetched and verified since the proxy started. See [`crate::verified`].
    pub artifacts_verified: usize,
    /// Where an artifact being analysed is written, when a spool is open.
    pub spool_dir: Option<String>,
    /// Artifact requests answered 304 since the proxy started, from the client's own cache.
    #[serde(default)]
    pub artifacts_revalidated: u64,
    /// Artifact requests for a version that depends on a package by URL, git or path.
    #[serde(default)]
    pub artifacts_with_direct_dependencies: u64,
    /// Metadata documents forwarded without being read or rewritten since the proxy started.
    #[serde(default)]
    pub documents_uninspected: u64,
    /// The clients the last window found reading documents and fetching no artifact.
    #[serde(default)]
    pub clients_without_artifacts: BTreeMap<String, u64>,
}

#[derive(Clone)]
pub struct Proxy {
    /// Set by the builders and read while serving, behind one `Arc` as axum clones the proxy.
    config: Arc<Config>,
    /// Records from metadata already seen, so an artifact request finds its digest.
    store: Arc<Mutex<RecordStore>>,
    /// Artifacts already fetched and verified, keyed by content digest.
    verified: Arc<Mutex<VerifiedArtifacts>>,
    /// Bounds how many metadata documents are decoded and rewritten at once.
    metadata_slots: Arc<Semaphore>,
    /// The configuration after a policy reload, `None` until the first.
    reloaded: Arc<RwLock<Option<Arc<Config>>>>,
    /// The intel snapshot [`intel_for`] last read coverage from. See [`snapshot_named`].
    coverage: Arc<Mutex<Option<LoadedSnapshot>>>,
    /// Artifacts answered 503 while their analysis ran. See [`Deferred`].
    deferred: Arc<Mutex<Deferred>>,
    /// Artifact requests answered 304, whose bytes the client took from its cache.
    revalidated: Arc<AtomicU64>,
    /// Artifact requests for a version with a dependency named by URL, git or path.
    direct: Arc<AtomicU64>,
    /// Metadata documents forwarded without being read or rewritten. See [`Uninspected`].
    uninspected: Arc<AtomicU64>,
    /// Documents and artifacts per client in the current window. See [`Traffic`].
    traffic: Arc<Mutex<Traffic>>,
    /// The clients the last closed window found reading documents and fetching no artifact.
    without_artifacts: Arc<Mutex<Vec<(String, u64)>>>,
}

/// What the builders set. Nothing here changes once the proxy is serving.
#[derive(Clone)]
struct Config {
    client: reqwest::Client,
    /// Fetches the metadata a client never asked for. See [`lookup_or_fetch`].
    clients: Clients,
    /// Which origins this proxy serves, and which it permits a client to fetch directly.
    origins: OriginPolicy,
    /// What a policy refusal answers with, per ecosystem and client.
    refusal: RefusalStatus,
    /// Whether to drop versions whose artifacts this proxy cannot serve.
    refuse_unservable: bool,
    mode: Mode,
    /// Origins the operator added, kept so a later upstream change can rebuild `origins`.
    served_origins: Vec<String>,
    /// Origins a client may fetch from directly, kept for the same reason.
    allowed_direct: Vec<String>,
    /// Where each ecosystem's requests are forwarded.
    upstreams: Upstreams,
    /// The policy, when one is configured. `None` asks nothing, unlike a policy allowing all.
    policy: Option<Arc<Policy>>,
    /// One line per policy decision, when a path is configured.
    audit: Option<Arc<AuditLog>>,
    /// The intel store, when one is configured. See [`intel_for`].
    intel: Option<Arc<dyn Intel>>,
    /// Where an artifact is written while it is analysed, locked while the proxy lives.
    spool: Option<Arc<Spool>>,
    /// Analyses an artifact nothing has analysed. Without one, the metadata's claim decides.
    analyser: Option<Arc<Analyser>>,
    max_metadata_bytes: usize,
    /// Point artifact URLs at the proxy so every client fetches through it.
    rewrite_artifacts: bool,
    /// The address to write into artifact URLs, when it must not be the request's `Host`.
    public_base: Option<String>,
    /// Debug builds only: answer with a deferral instead of fetching. See [`crate::defer`].
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
                spool: None,
                analyser: None,
                max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
                rewrite_artifacts: true,
                public_base: None,
                refusal: RefusalStatus::default(),
                refuse_unservable: true,
                mode: Mode::Enforce,
                #[cfg(debug_assertions)]
                defer_test: None,
            }),
            store: Arc::new(Mutex::new(RecordStore::new(DEFAULT_MAX_RECORDS))),
            verified: Arc::new(Mutex::new(VerifiedArtifacts::new(DEFAULT_MAX_VERIFIED))),
            coverage: Arc::new(Mutex::new(None)),
            deferred: Arc::new(Mutex::new(Deferred(Lru::new(DEFAULT_MAX_VERIFIED)))),
            revalidated: Arc::default(),
            direct: Arc::default(),
            uninspected: Arc::default(),
            traffic: Arc::default(),
            without_artifacts: Arc::default(),
            metadata_slots: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_METADATA)),
            reloaded: Arc::default(),
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

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.config_mut().mode = mode;
        self
    }

    pub fn with_max_concurrent_documents(mut self, limit: usize) -> Self {
        self.metadata_slots = Arc::new(Semaphore::new(limit.max(1)));
        self
    }

    /// Additional origins whose artifacts this proxy serves, beyond the upstream and the
    /// default registry, and origins it permits a client to fetch directly.
    pub fn with_origin_policy<'a>(
        self,
        served: impl IntoIterator<Item = &'a str>,
        allowed_direct: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, crate::origin::OriginError> {
        let served: Vec<String> = served.into_iter().map(str::to_owned).collect();
        let allowed_direct: Vec<String> = allowed_direct.into_iter().map(str::to_owned).collect();
        self.with_origin_lists(served, allowed_direct)
    }

    /// [`Proxy::with_origin_policy`] with its lists collected, so there is one body.
    fn with_origin_lists(
        mut self,
        served: Vec<String>,
        allowed_direct: Vec<String>,
    ) -> Result<Self, crate::origin::OriginError> {
        self.config_mut().origins = self.origin_policy_for(&served, &allowed_direct)?;
        self.config_mut().served_origins = served;
        self.config_mut().allowed_direct = allowed_direct;
        Ok(self)
    }

    /// The policy in force, when one is configured: the last one reloaded, or the one
    /// built with.
    pub fn policy(&self) -> Option<Arc<Policy>> {
        self.current().config.policy.clone()
    }

    /// Put `policy` in force for every request from now on. A request already being
    /// decided keeps the policy it started with.
    /// Returns the policy it replaced.
    pub fn replace_policy(&self, policy: Option<Arc<Policy>>) -> Option<Arc<Policy>> {
        let mut reloaded = self.reloaded.write().expect("reloaded lock");
        let base = reloaded.clone().unwrap_or_else(|| self.config.clone());
        let mut config = (*base).clone();
        let replaced = std::mem::replace(&mut config.policy, policy);
        *reloaded = Some(Arc::new(config));
        replaced
    }

    /// This proxy with the configuration in force now, for one request to read throughout.
    fn current(&self) -> Proxy {
        match self.reloaded.read().expect("reloaded lock").clone() {
            Some(config) => Proxy {
                config,
                ..self.clone()
            },
            None => self.clone(),
        }
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
            mode: self.config.mode.as_str().to_owned(),
            served_origins: self.config.origins.reachable().as_slice().to_vec(),
            allowed_direct_origins: self.config.origins.allowed_direct().to_vec(),
            packages_held,
            records_held,
            artifacts_verified: self.verified.lock().expect("verified artifacts lock").len(),
            spool_dir: self
                .config
                .spool
                .as_ref()
                .map(|spool| spool.dir().display().to_string()),
            artifacts_revalidated: self.revalidated.load(Ordering::Relaxed),
            artifacts_with_direct_dependencies: self.direct.load(Ordering::Relaxed),
            documents_uninspected: self.uninspected.load(Ordering::Relaxed),
            clients_without_artifacts: self
                .without_artifacts
                .lock()
                .expect("traffic lock")
                .iter()
                .cloned()
                .collect(),
        }
    }

    /// Close the traffic window: log each client that read metadata documents and fetched
    /// no artifact in it, keep them for [`HEALTH_PATH`], and open the next.
    pub fn report_traffic(&self) {
        let quiet = self.traffic.lock().expect("traffic lock").close();
        for (client, documents) in &quiet {
            info!(
                user_agent.original = %client,
                waharoa.traffic.documents = documents,
                waharoa.traffic.window_s = TRAFFIC_WINDOW.as_secs(),
                "client read metadata documents and fetched no artifact through this proxy: it \
                 installed nothing new, or takes artifacts from its own cache or another address"
            );
        }
        *self.without_artifacts.lock().expect("traffic lock") = quiet;
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
                gaps: Vec::new(),
            };
        };
        let (intel, snapshot) = match store.snapshot().await {
            Ok(Some(snapshot)) => (IntelState::Loaded, Some(snapshot)),
            Ok(None) => (IntelState::Empty, None),
            Err(e) => {
                error!(waharoa.reason = %e, "intel store cannot answer; not ready");
                (IntelState::Unavailable, None)
            }
        };
        let gaps: Vec<String> = snapshot
            .as_ref()
            .map(|s| s.gaps().iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        Readiness {
            ready: intel == IntelState::Loaded && gaps.is_empty(),
            intel,
            snapshot,
            gaps,
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

    /// How many client names a traffic window counts apart. See
    /// [`crate::env::MAX_TRAFFIC_CLIENTS`].
    pub fn with_max_traffic_clients(self, limit: usize) -> Self {
        self.traffic.lock().expect("traffic lock").max_clients = limit.max(1);
        self
    }

    pub fn with_spool(mut self, spool: Option<Arc<Spool>>) -> Self {
        self.config_mut().spool = spool;
        self
    }

    pub fn with_analyser(mut self, analyser: Option<Arc<Analyser>>) -> Self {
        self.config_mut().analyser = analyser;
        self
    }

    pub fn with_max_metadata_bytes(mut self, limit: usize) -> Self {
        self.config_mut().max_metadata_bytes = limit;
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
    /// The body passed the limit. Carries what was read and the rest, to forward unparsed.
    Oversized { prefix: Bytes, rest: ByteStream },
    /// The body could not be read to completion.
    Failed(reqwest::Error),
}

/// Any error a forwarded body can end with.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A body forwarded while its digest is checked, holding back one chunk until it matches.
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
        let verifier = self.verifier.take().expect("the body ends once");
        match verifier.finish(self.bytes) {
            Ok(()) => {
                self.verified
                    .lock()
                    .expect("verified artifacts lock")
                    .record(self.sri.clone());
                info!(
                    url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                    waharoa.package.purl = %self.purl,
                    waharoa.artifact.bytes = self.bytes,
                    "artifact digest verified"
                );
                Poll::Ready(self.held.take().map(Ok))
            }
            Err(mismatch) => {
                error!(
                    url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                    waharoa.package.purl = %self.purl,
                    waharoa.artifact.digest_expected = %mismatch.expected,
                    waharoa.artifact.digest_actual = %mismatch.actual,
                    waharoa.artifact.bytes = mismatch.bytes,
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
                    this.verifier
                        .as_mut()
                        .expect("the verifier is taken only when the body ends")
                        .update(&chunk);
                    this.bytes += chunk.len() as u64;
                    if chunk.is_empty() {
                        continue;
                    }
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
    StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN)
}

/// The address to write into artifact URLs: `configured` if set, else the request's
/// `Host` with `X-Forwarded-Proto` from `headers`.
/// Returns `None` when there is nothing usable, and the document is forwarded as it came.
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

/// Find the record for an artifact, fetching its metadata document if the client never
/// asked for one, as `npm ci` never does. The digest must be in hand before the artifact
/// is forwarded. See docs/engineering_decisions/artifact-digest-verification.md.
async fn lookup_or_fetch(
    proxy: &Proxy,
    key: &PackageKey,
    version: &str,
    filename: &str,
    path: &str,
) -> Lookup {
    let first = proxy
        .store
        .lock()
        .expect("record store lock")
        .lookup(key, version, filename);
    if first != Lookup::Unknown {
        return first;
    }

    fetch_and_store(proxy, key, path).await;

    proxy
        .store
        .lock()
        .expect("record store lock")
        .lookup(key, version, filename)
}

/// Fetch the metadata document the client did not ask for from `key`'s own registry, and
/// keep its records. A failure is logged, and the artifact request is answered 502.
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
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                waharoa.package.purl = %key,
                waharoa.package.versions = versions,
                waharoa.duration_ms = started.elapsed().as_millis() as u64,
                "fetched metadata on our own behalf, which the client never requested"
            );
        }
        Ok(Err(e)) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.package.purl = %key, error.message = %e, "metadata fetched but did not normalize")
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.package.purl = %key, error.message = %e, "could not fetch metadata")
        }
    }
}

/// Why a metadata document is forwarded without its artifact URLs pointed at the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Uninspected {
    /// The client accepts no encoding this build can decode, so the body cannot be read.
    Unreadable,
    /// No `Host` header and no configured public base to point artifact URLs at.
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

/// Whether this request leaves a package's artifacts unexamined, and why. `None` for
/// anything but a metadata GET, a document about to be rewritten, or `rewriting` off.
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

/// Whether this request is the resolver looking rather than the client installing, such
/// as a PEP 658 `.metadata` request. See docs/engineering_decisions/adapter-interface.md.
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
    if let RequestTarget::Metadata(key) = target {
        let held = proxy.store.lock().expect("record store lock").holds(key);
        info!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.package.purl = %key,
            "http.response.header.etag" = headers.get(header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("-"),
            waharoa.store.held = held,
            "metadata not modified, nothing to normalize"
        );
        if !held {
            fetch_and_store(proxy, key, path).await;
        }
    }

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

/// Wait for a slot to decode, read and rewrite a metadata document in, after its body is
/// read. See docs/engineering_decisions/default-ceilings.md.
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
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.metadata.slot_wait_ms = waited.as_millis() as u64,
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
    let parse_started = Instant::now();
    let decoded = match decode_for_parsing(body, content_encoding, proxy.config.max_metadata_bytes)
    {
        Ok(decoded) => decoded,
        Err(e) => {
            proxy.uninspected.fetch_add(1, Ordering::Relaxed);
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "UNINSPECTED: metadata body could not be decoded");
            return DocumentStep::Forward {
                body: None,
                refused: Refused::default(),
            };
        }
    };

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

    let intel = match normalized {
        Some(metadata) => match intel_for(proxy, &metadata.key, path).await {
            Ok(intel) => intel,
            Err(NotReady::Uncovered(uncovered))
                if ecosystem::of(uncovered).uncovered_metadata
                    == UncoveredMetadata::FilterWithoutIntel =>
            {
                warn!(
                    url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                    "filtering without intel; the artifact request answers 503"
                );
                None
            }
            Err(unavailable) => return DocumentStep::Answer(unavailable.response()),
        },
        None => None,
    };

    let refused_by_policy = match normalized {
        Some(metadata) => policy_refused_versions(
            metadata,
            proxy.config.policy.as_deref(),
            intel.as_ref(),
            path,
            proxy.config.audit.as_deref(),
            proxy.config.mode,
        ),
        None => Refused::default(),
    };
    let base = negotiation
        .rewriting
        .then_some(negotiation.rewrite_base.as_deref())
        .flatten();

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

/// How a request's metadata document is asked for and read, decided before going upstream.
#[derive(Debug, PartialEq, Eq)]
struct Negotiation {
    /// The encoding asked of upstream on a document the proxy reads.
    encoding: RequestedEncoding,
    /// The body is read: a metadata GET, in an encoding this build can decode.
    read_metadata: bool,
    /// The address artifact URLs are pointed at. See [`public_base`].
    rewrite_base: Option<String>,
    /// Artifact URLs are pointed at the proxy.
    rewriting: bool,
    /// The full packument is asked for and served, for its publish times and the heuristics.
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
        && ecosystem::of(ecosystem).publish_times == ecosystem::PublishTimeSource::FullPackument;
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
    proxy: &Proxy,
    target: &RequestTarget,
    method: &Method,
    negotiation: &Negotiation,
    headers: &HeaderMap,
    path: &str,
) {
    let Some(reason) = uninspected(
        target,
        method,
        negotiation.encoding,
        negotiation.rewrite_base.as_deref(),
        negotiation.rewriting,
    ) else {
        return;
    };
    proxy.uninspected.fetch_add(1, Ordering::Relaxed);
    match reason {
        Uninspected::Unreadable => warn!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            "http.request.header.accept-encoding" = headers
                .get(header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-"),
            waharoa.reason = Uninspected::Unreadable.reason(),
            "UNINSPECTED"
        ),
        reason => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.reason = reason.reason(), "UNINSPECTED")
        }
    }
}

/// The headers sent upstream: the client's, less those that stop at the proxy, with the
/// encoding, `Accept` and `If-None-Match` the negotiation needs.
fn upstream_headers(client: &HeaderMap, negotiation: &Negotiation, path: &str) -> HeaderMap {
    let mut outbound = HeaderMap::new();
    for (name, value) in client {
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
            _ => info!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
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
    /// The proxy answers without asking upstream.
    Answer(Response),
    /// Fetch it upstream.
    Fetch(ArtifactFetch),
}

/// How to fetch an artifact and check what arrives.
#[derive(Default)]
struct ArtifactFetch {
    /// The purl the request claims, for the verifier's log lines, if an artifact GET.
    purl: String,
    /// The digest the metadata published. `None` forwards the bytes unverified.
    digest: Option<Sri>,
    /// An origin the operator added, when the metadata published the artifact there.
    origin: Option<String>,
}

/// Look up the record for an artifact GET, decide on it before a byte is fetched, and
/// audit the answer.
/// `request`: the artifact the client asked for.
/// Returns the answer to send, or how to fetch and verify the artifact.
async fn decide_artifact(proxy: &Proxy, request: ArtifactRequest<'_>) -> ArtifactStep {
    let deciding = Deciding::new(proxy, request);
    let record = match deciding.locate().await {
        Ok(record) => record,
        Err(answer) => return *answer,
    };
    let (fetch, unservable) = deciding.fetch_plan(&record);
    let dated = deciding.dated(&record).await;
    let sourced = deciding.sourced(&fetch).await;
    let signals = deciding.signals(&record, dated.full.as_ref(), sourced.as_ref());
    let described = dated.describing(&record).clone();
    let times = dated.times;
    let Analysed {
        record,
        provenance,
        state,
    } = deciding.analysed(&record, &fetch, times.as_ref()).await;
    let today = crate::policy::today();
    let (intel, refusal) = match deciding
        .refusal(&record, times.as_ref(), &provenance, today)
        .await
    {
        Ok(decided) => decided,
        Err(unavailable) => return ArtifactStep::Answer(unavailable.response()),
    };
    if sourced.is_none() {
        deciding.compare_source(&described, &fetch, refusal.as_ref());
    }
    let (answered, step) = deciding.answer(refusal.as_ref(), unservable, fetch, state);
    audit_pinned(
        proxy,
        &Pinned {
            record: &record,
            times: times.as_ref(),
            intel: intel.as_ref(),
            provenance: &provenance,
            today,
        },
        answered,
        &signals,
    );
    step
}

/// What [`Deciding::dated`] found for a record whose document carried no publish time.
#[derive(Default)]
struct Dated {
    /// The publish times, which the policy reads when it needs them.
    times: Option<facts::PublishTimes>,
    /// The full document's records, for the heuristics.
    full: Option<PackageMetadata>,
}

impl Dated {
    /// `record` as the full document describes it, when it lists the version.
    fn describing<'a>(&'a self, record: &'a PackageRecord) -> &'a PackageRecord {
        self.full
            .as_ref()
            .and_then(|full| full.version(record.package.version()))
            .unwrap_or(record)
    }
}

/// One artifact GET while [`decide_artifact`] decides it.
struct Deciding<'a> {
    proxy: &'a Proxy,
    request: ArtifactRequest<'a>,
    /// The purl the request claims, as the log lines and answers name it.
    purl: String,
}

impl<'a> Deciding<'a> {
    fn new(proxy: &'a Proxy, request: ArtifactRequest<'a>) -> Self {
        let key = request.key;
        let version = request.claimed_version;
        let purl = key
            .at_version(version)
            .map(|r| r.to_string())
            .unwrap_or_else(|_| format!("{key}@{version}"));
        Self {
            proxy,
            request,
            purl,
        }
    }

    /// What the metadata heuristics report for `record`, logged when there is any.
    /// See docs/engineering_decisions/metadata-heuristics.md.
    /// `full` is the full document, when one was fetched for this request.
    fn signals(
        &self,
        record: &PackageRecord,
        full: Option<&PackageMetadata>,
        sourced: Option<&Sourced>,
    ) -> Vec<Signal> {
        let mut signals = self.proxy.store.lock().expect("record store lock").signals(
            record,
            full,
            jiff::Timestamp::now(),
        );
        signals.extend(
            sourced
                .map(crate::heuristics::of_source)
                .unwrap_or_default(),
        );
        if !signals.is_empty() {
            let found: Vec<String> = signals.iter().map(ToString::to_string).collect();
            let weights = self
                .proxy
                .config
                .policy
                .as_deref()
                .map(|policy| policy.signal_weights.clone())
                .unwrap_or_default();
            let score = crate::heuristics::score(&signals, &weights);
            warn!(url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path), waharoa.package.purl = %self.purl, waharoa.signals = ?found, waharoa.risk_score = score, "signals reported; they refuse nothing");
        }
        signals
    }

    /// What comparing the artifact with its source found, when it was compared before.
    /// See docs/engineering_decisions/source-diff.md.
    async fn sourced(&self, fetch: &ArtifactFetch) -> Option<Sourced> {
        let analyser = self.proxy.config.analyser.as_deref()?;
        analyser.sourced(fetch.digest.as_ref()?).await
    }

    /// Start comparing the artifact with its source, unless `refusal` blocks it: a block does
    /// not lapse, so nothing would be served. `record` is the version as the full document
    /// describes it, which names the repository and commit.
    fn compare_source(
        &self,
        record: &PackageRecord,
        fetch: &ArtifactFetch,
        refusal: Option<&enforce::Refusal>,
    ) {
        if refusal.is_some_and(|refusal| refusal.action == crate::policy::Action::Block) {
            return;
        }
        let (Some(analyser), Some(digest)) =
            (self.proxy.config.analyser.as_deref(), fetch.digest.as_ref())
        else {
            return;
        };
        let url = upstream_url(
            self.proxy,
            self.request.ecosystem,
            self.request.path,
            fetch.origin.as_deref(),
        );
        if let Some(job) = SourceJob::of(record, self.request.filename, digest, url) {
            analyser.start_source(job);
        }
    }

    /// The intel the policy reads for this package, and the policy's refusal of `record`
    /// with its publish `times` and `provenance`, as of `today`.
    /// Errors with why the intel store cannot answer.
    async fn refusal(
        &self,
        record: &PackageRecord,
        times: Option<&facts::PublishTimes>,
        provenance: &Provenance,
        today: jiff::civil::Date,
    ) -> Result<(Option<PackageIntel>, Option<enforce::Refusal>), NotReady> {
        let intel = intel_for(self.proxy, self.request.key, self.request.path).await?;
        let refusal = match enforce::artifact(
            self.proxy.config.policy.as_deref(),
            record,
            times,
            intel.as_ref(),
            provenance,
            today,
        ) {
            enforce::Verdict::Refuse(refusal) => Some(refusal),
            enforce::Verdict::Serve => None,
        };
        Ok((intel, refusal))
    }

    /// The record for the requested file, from the metadata held or fetched now.
    /// Errors with the answer when the registry gave no metadata or it names neither the
    /// version nor the file.
    async fn locate(&self) -> Result<PackageRecord, Box<ArtifactStep>> {
        let ArtifactRequest {
            key,
            claimed_version,
            filename,
            path,
            client,
            ..
        } = self.request;
        let found = match lookup_or_fetch(self.proxy, key, claimed_version, filename, path).await {
            Lookup::Found(found) => found,
            Lookup::NoSuchVersion => {
                self.audit_undecided(audit::Answered::NotListed);
                return Err(Box::new(self.unassessable(
                    self.refusal_status(),
                    "its metadata does not list this version",
                )));
            }
            Lookup::Unknown => {
                self.audit_undecided(audit::Answered::NoMetadata);
                return Err(Box::new(self.unassessable(
                    StatusCode::BAD_GATEWAY,
                    "the registry gave no metadata for it",
                )));
            }
        };
        let record = found.narrowed_to(filename).unwrap_or_else(|| {
            warn!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                waharoa.package.claimed_purl = %self.purl,
                waharoa.artifact.filename = %filename,
                "the record names no file by this name; deciding on the version's first file"
            );
            *found
        });
        info!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.artifact.integrity = record
                .artifact()
                .and_then(|a| a.integrity.as_deref())
                .unwrap_or("-"),
            waharoa.package.has_install_scripts = record.has_install_scripts,
            waharoa.package.deprecated = record.deprecated.as_deref().unwrap_or("-"),
            "artifact requested, digest known"
        );
        report_direct_dependencies(self.proxy, &record, path, client);
        Ok(record)
    }

    /// Write a pinned line for a request answered before anything was decided, when there
    /// is a log and a policy. `answered` is what the request got.
    fn audit_undecided(&self, answered: audit::Answered) {
        let (Some(log), Some(_)) = (&self.proxy.config.audit, &self.proxy.config.policy) else {
            return;
        };
        let key = self.request.key;
        log.write(&audit::Event::undecided(
            key.ecosystem().as_str(),
            &key.registry_name(),
            self.request.claimed_version,
            answered,
        ));
    }

    /// Where to fetch the artifact and the digest to verify it against.
    /// Returns the fetch, and the origin it is published on when the proxy does not serve
    /// that origin.
    fn fetch_plan(&self, record: &PackageRecord) -> (ArtifactFetch, Option<String>) {
        let artifact = record.artifact();
        let url = artifact.map(|a| a.url.as_str()).unwrap_or("");
        let origins = &self.proxy.config.origins;
        let unservable = match origins.disposition(url) {
            Disposition::Refused(origin) => Some(origin),
            _ => None,
        };
        let fetch = ArtifactFetch {
            purl: self.purl.clone(),
            digest: self.digest(artifact.and_then(|a| a.integrity.as_deref())),
            origin: crate::origin::origin_of_url(url)
                .filter(|origin| origins.reachable().routes_directly(origin)),
        };
        (fetch, unservable)
    }

    /// The strong digest `integrity` publishes, logged with whether it was verified before.
    /// Returns `None` for no integrity, SHA-1 only, or one that does not parse.
    fn digest(&self, integrity: Option<&str>) -> Option<Sri> {
        let path = self.request.path;
        match integrity.map(Sri::parse) {
            Some(Ok(sri)) => {
                let seen = self
                    .proxy
                    .verified
                    .lock()
                    .expect("verified artifacts lock")
                    .lookup(&sri);
                info!(
                    url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                    waharoa.package.claimed_purl = %self.purl,
                    waharoa.artifact.digest = %sri,
                    waharoa.artifact.cache = seen.as_str(),
                    "artifact cache consulted"
                );
                Some(sri)
            }
            Some(Err(e)) => {
                warn!(
                    url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                    waharoa.package.claimed_purl = %self.purl,
                    error.message = %e,
                    "metadata integrity string is unusable; not verifying"
                );
                None
            }
            None => {
                warn!(
                    url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                    waharoa.package.claimed_purl = %self.purl,
                    "metadata publishes no strong digest; not verifying"
                );
                None
            }
        }
    }

    /// For a record whose document carried no publish time: the full document, and the
    /// publish times from it or from the file host's `Last-Modified`.
    async fn dated(&self, record: &PackageRecord) -> Dated {
        if record.published_at.is_some() {
            return Dated::default();
        }
        let (times, full) = match full_document(self.proxy, self.request.key).await {
            Some(FullDocument { times, metadata }) => (Some(times), metadata.ok()),
            None => (None, None),
        };
        let times = match times {
            Some(times) => Some(times),
            None => dated_by_host(self.proxy, record, self.request.path).await,
        };
        Dated { times, full }
    }

    /// [`analysed`] for this request, logging a return after a deferral once the
    /// analysis is stored.
    async fn analysed(
        &self,
        record: &PackageRecord,
        fetch: &ArtifactFetch,
        times: Option<&facts::PublishTimes>,
    ) -> Analysed {
        let ArtifactRequest {
            ecosystem,
            filename,
            path,
            client,
            ..
        } = self.request;
        let upstream = upstream_url(self.proxy, ecosystem, path, fetch.origin.as_deref());
        let analysed = analysed(
            self.proxy,
            record,
            filename,
            fetch.digest.as_ref(),
            times,
            &upstream,
            path,
        )
        .await;
        if !matches!(analysed.state, AnalysisState::Pending(_))
            && let Some(digest) = &fetch.digest
        {
            returned(self.proxy, digest, path, client);
        }
        analysed
    }

    /// What to answer, in order: the policy's refusal, unless observing, an origin the
    /// proxy does not serve, no strong digest, then the analysis.
    /// Returns what the audit line records, and the answer.
    fn answer(
        &self,
        refusal: Option<&enforce::Refusal>,
        unservable: Option<String>,
        fetch: ArtifactFetch,
        state: AnalysisState,
    ) -> (audit::Answered, ArtifactStep) {
        if let Some(refusal) = refusal {
            if self.proxy.config.mode == Mode::Enforce {
                return (audit::Answered::Refused, self.refused_by_policy(refusal));
            }
            self.observed(refusal);
        }
        if let Some(origin) = unservable.filter(|_| self.proxy.config.refuse_unservable) {
            return (audit::Answered::Unservable, self.unservable(&origin));
        }
        if fetch.digest.is_none() {
            return (
                audit::Answered::NoStrongDigest,
                self.unassessable(
                    self.refusal_status(),
                    "its metadata publishes no strong digest, so its bytes can be neither \
                     verified nor analysed",
                ),
            );
        }
        match state {
            AnalysisState::Mismatched(mismatch) => (
                audit::Answered::UpstreamMismatch,
                self.mismatched(&mismatch),
            ),
            AnalysisState::Pending(job) => (audit::Answered::Deferred, self.defer(job)),
            AnalysisState::Decided => (audit::Answered::Served, ArtifactStep::Fetch(fetch)),
        }
    }

    fn refusal_status(&self) -> StatusCode {
        refusal_status(
            self.proxy,
            self.request.ecosystem,
            Some(self.request.client),
        )
    }

    /// The refusal status with the policy's reasons.
    fn refused_by_policy(&self, refusal: &enforce::Refusal) -> ArtifactStep {
        let status = self.refusal_status();
        info!(
            http.request.method = %self.request.method,
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            http.response.status_code = status.as_u16(),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.policy.action = refusal.action.as_str(),
            waharoa.policy.reasons = ?refusal.reasons,
            user_agent.original = %self.request.client,
            "refused by policy"
        );
        ArtifactStep::Answer((status, refusal.message()).into_response())
    }

    /// Log the refusal observe mode does not make.
    fn observed(&self, refusal: &enforce::Refusal) {
        warn!(
            http.request.method = %self.request.method,
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.policy.action = refusal.action.as_str(),
            waharoa.policy.reasons = ?refusal.reasons,
            user_agent.original = %self.request.client,
            "observe: the policy refuses this artifact; not refused"
        );
    }

    /// The refusal status for an artifact published on `origin`, which the proxy does not
    /// serve.
    fn unservable(&self, origin: &str) -> ArtifactStep {
        let status = self.refusal_status();
        info!(
            http.request.method = %self.request.method,
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            http.response.status_code = status.as_u16(),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.artifact.origin = %origin,
            user_agent.original = %self.request.client,
            "refused: this artifact is published on an origin the proxy does not serve"
        );
        let purl = &self.purl;
        ArtifactStep::Answer(
            (
                status,
                format!(
                    "waharoa: {purl} is published at {origin}, which this proxy does not \
                     serve, so it cannot be examined\n"
                ),
            )
                .into_response(),
        )
    }

    /// 502 for bytes that did not match their digest when the analysis fetched them.
    fn mismatched(&self, mismatch: &crate::integrity::Mismatch) -> ArtifactStep {
        warn!(
            http.request.method = %self.request.method,
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.artifact.digest_mismatch = %mismatch,
            "refused: the upstream serves bytes its metadata does not describe"
        );
        let purl = &self.purl;
        ArtifactStep::Answer(
            (
                StatusCode::BAD_GATEWAY,
                format!(
                    "waharoa: the upstream served {purl} as bytes its metadata does not \
                     describe: {mismatch}\n"
                ),
            )
                .into_response(),
        )
    }

    /// 503 until `job`, started here, has analysed the artifact.
    fn defer(&self, job: Job) -> ArtifactStep {
        let digest = job.digest.clone();
        self.proxy
            .config
            .analyser
            .as_ref()
            .expect("a pending job has an analyser")
            .start(job);
        let deferrals = self
            .proxy
            .deferred
            .lock()
            .expect("deferred lock")
            .defer(&digest);
        info!(
            http.request.method = %self.request.method,
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            waharoa.package.claimed_purl = %self.purl,
            waharoa.artifact.digest = %digest,
            waharoa.deferral.count = deferrals,
            user_agent.original = %self.request.client,
            "deferred: the artifact has not been analysed"
        );
        ArtifactStep::Answer(
            NotReady::Analysing {
                purl: self.purl.clone(),
                digest,
            }
            .response(),
        )
    }

    /// `status` for an artifact the proxy cannot assess, saying `why`.
    fn unassessable(&self, status: StatusCode, why: &str) -> ArtifactStep {
        let purl = &self.purl;
        warn!(
            url.path = %crate::http::url_path(self.request.path), url.query = crate::http::url_query(self.request.path),
            http.response.status_code = status.as_u16(),
            waharoa.package.claimed_purl = %purl,
            user_agent.original = %self.request.client,
            waharoa.reason = why,
            "not served"
        );
        ArtifactStep::Answer(
            (
                status,
                format!("waharoa: {purl} cannot be assessed: {why}\n"),
            )
                .into_response(),
        )
    }
}

/// The artifacts answered 503 while their analysis ran, by digest, for the deferral logs.
struct Deferred(Lru<Sri, Deferral>);

struct Deferral {
    first: Instant,
    count: u32,
}

impl Deferred {
    /// Count a deferral of `digest`, and return how many there have been.
    fn defer(&mut self, digest: &Sri) -> u32 {
        let (first, count) = match self.0.get(digest) {
            Some(held) => (held.first, held.count + 1),
            None => (Instant::now(), 1),
        };
        self.0.insert(digest.clone(), Deferral { first, count });
        count
    }
}

/// Documents and artifacts each client, by user-agent name, asked for in this window.
#[derive(Debug)]
struct Traffic {
    clients: BTreeMap<String, Counts>,
    /// [`crate::env::MAX_TRAFFIC_CLIENTS`]: past it, a new name is counted as `other`.
    max_clients: usize,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            clients: BTreeMap::new(),
            max_clients: DEFAULT_MAX_TRAFFIC_CLIENTS,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    documents: u64,
    artifacts: u64,
}

impl Traffic {
    fn count(&mut self, user_agent: &str, target: &RequestTarget) {
        let name = crate::refusal::client_name(Some(user_agent)).unwrap_or_else(|| "-".into());
        let name = if self.clients.len() >= self.max_clients && !self.clients.contains_key(&name) {
            "other".to_owned()
        } else {
            name
        };
        let counts = self.clients.entry(name).or_default();
        match target {
            RequestTarget::Metadata(_) => counts.documents += 1,
            RequestTarget::Artifact { .. } => counts.artifacts += 1,
            RequestTarget::Other => {}
        }
    }

    /// The clients that read documents and fetched no artifact, and a fresh window.
    fn close(&mut self) -> Vec<(String, u64)> {
        std::mem::take(&mut self.clients)
            .into_iter()
            .filter(|(_, c)| c.documents > 0 && c.artifacts == 0)
            .map(|(name, c)| (name, c.documents))
            .collect()
    }
}

/// Say that installing this version fetches dependencies around the proxy.
///
/// Once per artifact request rather than per version of a packument, which would repeat it
/// for every version a document lists. A warning, not a refusal: see
/// `docs/engineering_decisions/bypass-self-detection.md`.
fn report_direct_dependencies(proxy: &Proxy, record: &PackageRecord, path: &str, client: &str) {
    if record.direct_dependencies.is_empty() {
        return;
    }
    proxy.direct.fetch_add(1, Ordering::Relaxed);
    let named: Vec<String> = record
        .direct_dependencies
        .iter()
        .map(|d| format!("{} {}", d.name, d.spec))
        .collect();
    warn!(
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.package.purl = %record.package,
        waharoa.package.direct_dependencies = ?named,
        user_agent.original = %client,
        "BYPASS: this version depends on packages by URL, git or path, which the client \
         fetches directly and this proxy never examines"
    );
}

/// Log a request for `digest` that finds its analysis stored, when it was deferred before.
fn returned(proxy: &Proxy, digest: &Sri, path: &str, client: &str) {
    let Some(deferral) = proxy
        .deferred
        .lock()
        .expect("deferred lock")
        .0
        .remove(digest)
    else {
        return;
    };
    info!(
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.artifact.digest = %digest,
        waharoa.deferral.count = deferral.count,
        waharoa.deferral.after_ms = deferral.first.elapsed().as_millis() as u64,
        user_agent.original = %client,
        "returned after a deferral"
    );
}

/// The record to decide on, with the artifact's own install-script answer.
struct Analysed {
    record: PackageRecord,
    /// What its attestations say against the version published before it.
    provenance: Provenance,
    state: AnalysisState,
}

enum AnalysisState {
    /// Decide on the record and serve what the policy allows.
    Decided,
    /// The last fetch of these bytes did not match their digest. Answered 502.
    Mismatched(crate::integrity::Mismatch),
    /// Nothing has analysed these bytes, so the analysis starts and the request is answered 503.
    Pending(Job),
}

/// What the artifact's own bytes say about install scripts, where a reader reads it. A
/// stored analysis adds to the metadata's claim and never removes it; an unreadable
/// archive counts as running scripts; an artifact not analysed yet keeps the claim.
/// See docs/engineering_decisions/artifact-spool.md.
async fn analysed(
    proxy: &Proxy,
    record: &PackageRecord,
    filename: &str,
    digest: Option<&Sri>,
    times: Option<&facts::PublishTimes>,
    upstream: &str,
    path: &str,
) -> Analysed {
    let mut record = record.clone();
    let key = record.package.key();
    let analyser = proxy.config.analyser.as_deref();
    let (provenance, attestations) = attested(proxy, analyser, &record, digest, times).await;
    let reader = crate::analysis::Reader::for_file(key.ecosystem(), filename);
    let decided = |record, provenance| Analysed {
        record,
        provenance,
        state: AnalysisState::Decided,
    };
    let Some(analyser) = analyser else {
        return decided(record, provenance);
    };
    let Some(digest) = digest else {
        return decided(record, provenance);
    };
    let reads = match reader {
        None => None,
        Some(reader) => match analyser.known(digest).await {
            Known::Analysed(analysis) => {
                report_claim(&record, &analysis.scripts, path);
                record.has_install_scripts |= analysis
                    .scripts
                    .names()
                    .is_none_or(|names| !names.is_empty());
                None
            }
            Known::Mismatched(mismatch) => {
                return Analysed {
                    record,
                    provenance,
                    state: AnalysisState::Mismatched(mismatch),
                };
            }
            Known::Unknown => Some(reader),
        },
    };
    if reads.is_none() && attestations.is_empty() {
        return decided(record, provenance);
    }
    let job = Job {
        digest: digest.clone(),
        url: upstream.to_owned(),
        reader: reads,
        ecosystem: key.ecosystem().as_str().to_owned(),
        name: key.registry_name(),
        version: record.package.version().to_owned(),
        attestations,
    };
    Analysed {
        record,
        provenance,
        state: AnalysisState::Pending(job),
    }
}

/// Where the proxy fetches an attestations document the packument names, routed as an
/// artifact is: an origin the proxy serves through its upstream, an origin the operator
/// added directly, and any other not at all. `Err` names the origin, and counts as an
/// attestation that does not verify: a version must not escape the check by pointing its
/// attestations somewhere the proxy will not go.
fn attestation_url(
    proxy: &Proxy,
    ecosystem: Ecosystem,
    advertised: &str,
) -> Result<String, String> {
    match proxy.config.origins.disposition(advertised) {
        Disposition::Served => {}
        Disposition::AllowedDirect(origin) | Disposition::Refused(origin) => {
            return Err(format!(
                "its attestations are published at {origin}, which this proxy does not serve"
            ));
        }
    }
    let parsed = reqwest::Url::parse(advertised).expect("a served URL parses");
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    };
    let direct = crate::origin::origin_of_url(advertised)
        .filter(|origin| proxy.config.origins.reachable().routes_directly(origin));
    Ok(upstream_url(proxy, ecosystem, &path, direct.as_deref()))
}

/// What the version's attestations say against the version published before it, and the
/// attestations still to verify before that can be said. See
/// `docs/engineering_decisions/provenance-check.md`.
async fn attested(
    proxy: &Proxy,
    analyser: Option<&Analyser>,
    record: &PackageRecord,
    digest: Option<&Sri>,
    times: Option<&facts::PublishTimes>,
) -> (Provenance, Vec<Attestation>) {
    let key = record.package.key();
    let bundle: fn(&[u8]) -> Result<_, String> = match key.ecosystem() {
        Ecosystem::Npm => npm::attestation::provenance_bundle,
        Ecosystem::PyPI => pypi::attestation::provenance_bundle,
    };
    let window = proxy.config.policy.as_deref().map_or_else(
        || crate::policy::window_of(crate::policy::DEFAULT_PROVENANCE_WINDOW_DAYS),
        Policy::provenance_window,
    );
    let previous = proxy.store.lock().expect("record store lock").previous(
        key,
        record.package.version(),
        times,
        window,
    );
    let Some(analyser) = analyser else {
        return (attestation::from_metadata(record, &previous), Vec::new());
    };
    let ecosystem = key.ecosystem();
    let verifiable = |url: &String, digest: Option<Sri>, no_digest: &str| {
        let url = attestation_url(proxy, ecosystem, url)?;
        let digest = digest.ok_or_else(|| no_digest.to_owned())?;
        Ok::<_, String>((url, digest))
    };
    let this = record.provenance.attestation_url.as_ref().map(|url| {
        verifiable(
            url,
            digest.cloned(),
            "it publishes no strong digest to verify against",
        )
    });
    let this_result = match &this {
        None => None,
        Some(to_verify) => result_of(analyser, to_verify).await,
    };
    let priors: Vec<_> = match &previous {
        attestation::Previous::Known(priors) => priors
            .iter()
            .map(|prior| {
                verifiable(
                    &prior.attestation_url,
                    prior.integrity.as_deref().and_then(|i| Sri::parse(i).ok()),
                    "it publishes no strong digest",
                )
            })
            .collect(),
        attestation::Previous::Unknown => Vec::new(),
    };
    let mut prior_results = Vec::with_capacity(priors.len());
    for to_verify in &priors {
        prior_results.push(result_of(analyser, to_verify).await);
    }
    let prior_results: Vec<_> = prior_results.iter().map(Option::as_ref).collect();
    match attestation::provenance(record, &previous, this_result.as_ref(), &prior_results) {
        attestation::Answer::Known(provenance) => (provenance, Vec::new()),
        attestation::Answer::Needs {
            this: this_needed,
            priors: priors_needed,
        } => {
            let needed = |to_verify: &Result<(String, Sri), String>| {
                let (url, digest) = to_verify
                    .as_ref()
                    .expect("an attestation still needed can be verified");
                Attestation {
                    digest: digest.clone(),
                    url: url.clone(),
                    bundle,
                }
            };
            let mut work: Vec<Attestation> =
                this.iter().filter(|_| this_needed).map(needed).collect();
            work.extend(priors_needed.into_iter().map(|i| needed(&priors[i])));
            (Provenance::NOT_VERIFIED, work)
        }
    }
}

/// What verifying `to_verify` found: the analyser's stored result, or a failure when it
/// cannot be verified.
async fn result_of(
    analyser: &Analyser,
    to_verify: &Result<(String, Sri), String>,
) -> Option<attestation::Attested> {
    match to_verify {
        Ok((_, digest)) => analyser.attested(digest).await,
        Err(why) => Some(attestation::Attested::Failed { why: why.clone() }),
    }
}

/// Log what the artifact declares against what the metadata claimed. An `undeclared`
/// claim is a warning whatever the policy says: the metadata hid a script.
fn report_claim(record: &PackageRecord, scripts: &Scripts, path: &str) {
    let Scripts::Declared(found) = scripts else {
        warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.artifact.scripts = ?scripts, "the artifact could not be read; it counts as running install scripts");
        return;
    };
    let claim = Claim::of(found, record.has_install_scripts, record.detail);
    if claim == Claim::Undeclared {
        warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.artifact.scripts = ?found.names, waharoa.artifact.scripts_claimed = claim.as_str(), "the artifact runs install scripts its metadata does not declare");
    } else {
        info!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.artifact.scripts = ?found.names, waharoa.artifact.scripts_claimed = claim.as_str(), "install scripts read from the artifact");
    }
}

/// Write the pinned decision to the audit log, when there is a log and a policy.
///
/// Allowed decisions are written too. A log holding only refusals cannot answer "was this
/// ever evaluated", which is what `policy diff` needs a package set for.
/// `pinned` is what the verdict was reached on, and `signals` what the heuristics reported.
fn audit_pinned(proxy: &Proxy, pinned: &Pinned<'_>, answered: audit::Answered, signals: &[Signal]) {
    let Pinned {
        record,
        times,
        intel,
        provenance,
        today,
    } = *pinned;
    let (Some(audit), Some(policy)) = (&proxy.config.audit, proxy.config.policy.as_deref()) else {
        return;
    };
    let mut facts = crate::policy::decide::Facts::from_record_and_times(record, times)
        .with_provenance(provenance.clone());
    if let Some(intel) = intel {
        facts = facts.with_intel(intel);
    }
    audit.write(
        &audit::Event::pinned(
            &facts.ecosystem,
            &facts.name,
            &facts.version,
            &crate::policy::decide::decide(policy, &facts, today),
            &enforce::unenforceable(policy, record, times, facts.intel, &facts.provenance),
        )
        .with_intel_snapshot(intel.map(|i| i.snapshot.as_str()))
        .answered(answered)
        .with_inputs(audit::Inputs::of(policy, &facts, today))
        .with_signals(signals, &policy.signal_weights),
    );
}

/// What a pinned verdict was reached on, as [`audit_pinned`] writes it.
struct Pinned<'a> {
    record: &'a PackageRecord,
    times: Option<&'a facts::PublishTimes>,
    intel: Option<&'a PackageIntel>,
    provenance: &'a Provenance,
    today: jiff::civil::Date,
}

/// Answer one request: the proxy's own endpoints, or the upstream's answer once an
/// artifact is decided and a metadata document filtered.
async fn handle(State(proxy): State<Proxy>, req: Request) -> Response {
    let proxy = proxy.current();
    let started = Instant::now();
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let client = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    if let Some(response) = own_endpoint(&proxy, &path).await {
        return response;
    }
    let (ecosystem, target) = crate::route::classify(&path);
    #[cfg(debug_assertions)]
    if let Some((deferral, since)) = &proxy.config.defer_test
        && let Some((status, retry_after)) = deferral.applies_to(&target, since.elapsed())
    {
        return defer_response(status, retry_after, &method, &path, &client, started);
    }
    let negotiation = negotiate(&proxy, ecosystem, &target, &method, req.headers());
    let exchange = Exchange {
        proxy: &proxy,
        method,
        path,
        client,
        started,
        ecosystem,
        target,
        negotiation,
    };
    exchange.observe(req.headers());
    let artifact = match exchange.artifact_fetch().await {
        ArtifactStep::Answer(response) => return response,
        ArtifactStep::Fetch(fetch) => fetch,
    };
    let upstream = match exchange.send(req.headers(), &artifact).await {
        Ok(upstream) => upstream,
        Err(response) => return *response,
    };
    exchange.respond(upstream, artifact).await
}

/// `/-/waharoa/health` and `/-/waharoa/ready`, answered by the proxy. `None` for any other
/// `path`.
async fn own_endpoint(proxy: &Proxy, path: &str) -> Option<Response> {
    match path.split('?').next() {
        Some(HEALTH_PATH) => Some(uncached_json(StatusCode::OK, proxy.health())),
        Some(READY_PATH) => {
            let readiness = proxy.readiness().await;
            let status = if readiness.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            Some(uncached_json(status, readiness))
        }
        _ => None,
    }
}

/// One request forwarded upstream, and what [`handle`] knows about it.
struct Exchange<'a> {
    proxy: &'a Proxy,
    method: Method,
    /// The path and query the client asked for.
    path: String,
    /// The client's user agent, `-` when it sent none.
    client: String,
    started: Instant,
    ecosystem: Ecosystem,
    target: RequestTarget,
    negotiation: Negotiation,
}

/// The upstream's answer, before its body is read.
struct Upstream {
    status: reqwest::StatusCode,
    /// `status` as the client is sent it.
    forward_status: StatusCode,
    headers: HeaderMap,
    content_encoding: Option<String>,
    /// The metadata document the body is, when the proxy reads it.
    document: Option<DocumentKind>,
    length: Option<u64>,
    body: ByteStream,
}

impl Exchange<'_> {
    /// Report what the proxy will not inspect, and count the request for the traffic
    /// report.
    fn observe(&self, headers: &HeaderMap) {
        report_uninspected(
            self.proxy,
            &self.target,
            &self.method,
            &self.negotiation,
            headers,
            &self.path,
        );
        if self.method == Method::GET && !resolver_probe(self.ecosystem, &self.target) {
            self.proxy
                .traffic
                .lock()
                .expect("traffic lock")
                .count(&self.client, &self.target);
        }
    }

    /// [`decide_artifact`] for an artifact GET. Any other request is fetched with no
    /// digest.
    async fn artifact_fetch(&self) -> ArtifactStep {
        let RequestTarget::Artifact {
            key,
            claimed_version,
            filename,
        } = &self.target
        else {
            return ArtifactStep::Fetch(ArtifactFetch::default());
        };
        if self.method != Method::GET {
            return ArtifactStep::Fetch(ArtifactFetch::default());
        }
        let request = ArtifactRequest {
            ecosystem: self.ecosystem,
            method: &self.method,
            key,
            claimed_version,
            filename,
            path: &self.path,
            client: &self.client,
        };
        decide_artifact(self.proxy, request).await
    }

    /// Send the request upstream with the client's headers, less those that stop here.
    /// Errors with a 502 when no answer arrives.
    async fn send(
        &self,
        headers: &HeaderMap,
        artifact: &ArtifactFetch,
    ) -> Result<Upstream, Box<Response>> {
        let url = upstream_url(
            self.proxy,
            self.ecosystem,
            &self.path,
            artifact.origin.as_deref(),
        );
        let response = self
            .proxy
            .config
            .client
            .request(self.method.clone(), &url)
            .headers(upstream_headers(headers, &self.negotiation, &self.path))
            .send()
            .await
            .map_err(|e| {
                error!(http.request.method = %self.method, url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path), error.message = %e, "upstream request failed");
                Box::new(
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("waharoa: upstream request failed: {e}\n"),
                    )
                        .into_response(),
                )
            })?;
        let status = response.status();
        let headers = upstream_response_headers(response.headers());
        let content_encoding = headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let document = crate::ecosystem::of(self.ecosystem).document(content_type);
        Ok(Upstream {
            status,
            forward_status: StatusCode::from_u16(status.as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY),
            headers,
            content_encoding,
            document,
            length: response.content_length(),
            body: Box::pin(response.bytes_stream()),
        })
    }

    /// The upstream's answer as the client is sent it: a metadata document filtered, an
    /// artifact verified, anything else as it came.
    async fn respond(&self, mut upstream: Upstream, artifact: ArtifactFetch) -> Response {
        if upstream.status == reqwest::StatusCode::NOT_MODIFIED {
            revalidated(
                self.proxy,
                &self.target,
                &self.negotiation,
                &mut upstream.headers,
                &self.path,
            )
            .await;
        }
        let read = self.negotiation.read_metadata && upstream.status.is_success();
        match upstream.document.filter(|_| read) {
            Some(document) => self.forward_document(document, upstream).await,
            None => self.forward_artifact(upstream, artifact),
        }
    }

    /// Forward a body the proxy does not read, verifying a 200 against `artifact`'s digest
    /// when it has one.
    fn forward_artifact(&self, upstream: Upstream, artifact: ArtifactFetch) -> Response {
        let Upstream {
            status,
            forward_status,
            headers,
            length,
            body,
            ..
        } = upstream;
        self.log_proxied(status, length.unwrap_or(0));
        let Some(sri) = artifact.digest else {
            return (forward_status, headers, Body::from_stream(body)).into_response();
        };
        if status != reqwest::StatusCode::OK {
            if status == reqwest::StatusCode::NOT_MODIFIED {
                self.proxy.revalidated.fetch_add(1, Ordering::Relaxed);
                info!(
                    url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                    waharoa.package.purl = %artifact.purl,
                    user_agent.original = %self.client,
                    "artifact revalidated with a 304: the client installs its cached bytes, \
                     which this proxy did not hash on this request"
                );
            }
            return (forward_status, headers, Body::from_stream(body)).into_response();
        }
        let verified = VerifyingStream::new(
            body,
            &sri,
            self.path.clone(),
            artifact.purl,
            self.proxy.verified.clone(),
        );
        (forward_status, headers, Body::from_stream(verified)).into_response()
    }

    /// Read a metadata document, filter it by policy and rewrite it. One over
    /// `max_metadata_bytes` is forwarded as it came.
    async fn forward_document(&self, document: DocumentKind, upstream: Upstream) -> Response {
        let Upstream {
            status,
            forward_status,
            mut headers,
            content_encoding,
            length,
            body,
            ..
        } = upstream;
        let limit = self.proxy.config.max_metadata_bytes;
        let body = match buffer_to_limit(body, limit).await {
            Buffered::Complete(body) => body,
            Buffered::Oversized { prefix, rest } => {
                self.proxy.uninspected.fetch_add(1, Ordering::Relaxed);
                warn!(
                    url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                    waharoa.metadata.limit = limit,
                    "UNINSPECTED: metadata document exceeds the size limit, forwarded without rewriting"
                );
                self.log_proxied(status, length.unwrap_or(0));
                let spliced = stream::iter(std::iter::once(Ok(prefix))).chain(rest);
                return (forward_status, headers, Body::from_stream(spliced)).into_response();
            }
            Buffered::Failed(e) => {
                error!(http.request.method = %self.method, url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path), error.message = %e, "upstream body failed mid-stream");
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("waharoa: upstream body failed: {e}\n"),
                )
                    .into_response();
            }
        };
        let _slot = metadata_slot(self.proxy, &self.path).await;
        let forwarded = match filtered_document(
            self.proxy,
            document,
            &body,
            content_encoding.as_deref(),
            &self.negotiation,
            &self.path,
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
            self.negotiation.encoding,
            self.negotiation.rewrite_base.as_deref(),
            &|bytes| self.log_proxied(status, bytes),
        )
    }

    /// Log the answer sent, at debug for a resolver's probe and at info otherwise.
    fn log_proxied(&self, status: reqwest::StatusCode, bytes: u64) {
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        if resolver_probe(self.ecosystem, &self.target) {
            debug!(
                http.request.method = %self.method,
                url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                http.response.status_code = status.as_u16(),
                http.response.body.size = bytes,
                waharoa.duration_ms = elapsed_ms,
                user_agent.original = %self.client,
                "proxied"
            );
        } else {
            info!(
                http.request.method = %self.method,
                url.path = %crate::http::url_path(&self.path), url.query = crate::http::url_query(&self.path),
                http.response.status_code = status.as_u16(),
                http.response.body.size = bytes,
                waharoa.duration_ms = elapsed_ms,
                user_agent.original = %self.client,
                "proxied"
            );
        }
    }
}

/// Say what the policy took out of this document, on the response that carries it.
/// Nothing is added when nothing was removed.
fn mark_filtered(headers: &mut HeaderMap, refused: &Refused) {
    if refused.versions.is_empty() {
        return;
    }
    headers.insert(FILTERED_VERSIONS, HeaderValue::from(refused.versions.len()));
    headers.insert(
        FILTERED_CHECKS,
        HeaderValue::from_str(&refused.checks.join(",")).expect("check names are ASCII"),
    );
}

/// Send the document on, rewritten or not.
///
/// A rewritten body is this proxy's, so its length, its encoding and its entity tag all
/// have to describe it rather than the upstream's. `None` forwards the upstream's bytes
/// untouched, headers included.
fn finish(
    forwarded: Option<Vec<u8>>,
    body: Bytes,
    mut headers: HeaderMap,
    forward_status: StatusCode,
    chosen_encoding: RequestedEncoding,
    rewrite_base: Option<&str>,
    log_proxied: &dyn Fn(u64),
) -> Response {
    let body = match forwarded {
        Some(rewritten) => {
            let encoded = match chosen_encoding {
                RequestedEncoding::Gzip => {
                    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                    gzip(&rewritten)
                }
                _ => {
                    headers.remove(header::CONTENT_ENCODING);
                    rewritten
                }
            };
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(encoded.len()));
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
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let mut headers = HeaderMap::new();
    if let Some(seconds) = retry_after
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        headers.insert(header::RETRY_AFTER, value);
    }
    info!(
        http.request.method = %method,
        url.path = %crate::http::url_path(path_and_query), url.query = crate::http::url_query(path_and_query),
        http.response.status_code = status,
        "http.response.header.retry-after" = retry_after.map(|s| s.to_string()).unwrap_or_else(|| "-".to_owned()),
        user_agent.original = %client_ua,
        waharoa.duration_ms = started.elapsed().as_millis() as u64,
        waharoa.config.variable = %crate::env::DEFER_TEST,
        "deferred by the defer test"
    );
    (
        code,
        headers,
        format!("waharoa: {path_and_query} is deferred, not refused\n"),
    )
        .into_response()
}

/// The full packument for a package whose client asked for less, logged either way.
/// Fetched now and never kept: see docs/engineering_decisions/no-metadata-cache.md.
/// `None` for an ecosystem whose records carry publish times, or when it cannot be read.
async fn full_document(proxy: &Proxy, key: &PackageKey) -> Option<FullDocument> {
    let started = Instant::now();
    let full = match proxy.config.clients.full_document(key).await {
        Ok(Some(full)) => full,
        Ok(None) => return None,
        Err(e) => {
            warn!(waharoa.package.purl = %key, error.message = %e, "no full packument for this package");
            return None;
        }
    };
    if let Err(e) = &full.metadata {
        warn!(waharoa.package.purl = %key, error.message = %e, "the full packument's records did not normalize; the heuristics read the held document");
    }
    info!(
        waharoa.package.purl = %key,
        waharoa.package.versions = full.times.len(),
        waharoa.metadata.fetch_ms = started.elapsed().as_millis() as u64,
        "full packument read"
    );
    Some(full)
}

/// Say when a cooldown cannot be answered while filtering this document, because a PEP 503
/// page carries no publish time, and that [`dated_by_host`] answers it on the artifact.
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
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.package.undated_versions = undated,
        waharoa.package.versions = metadata.records.len(),
        "cooldown_days cannot be answered while filtering this document; a pinned fetch of \
         one of these versions is decided on the file's own date"
    );
}

/// The publish time from the file host's `Last-Modified`, for a record whose index gave
/// none. One `HEAD`, on the pinned path only.
/// See docs/engineering_decisions/pep-503-html-index.md.
/// Returns `None` when the host gives no date.
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
    let started = Instant::now();
    let artifact = record.artifact().expect("a pinned record names its file");
    let last_modified = head_last_modified(proxy, &artifact.url, path).await?;
    info!(
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.package.published = %last_modified,
        waharoa.metadata.fetch_ms = started.elapsed().as_millis() as u64,
        "publish time read from the file's Last-Modified"
    );
    Some(
        [(record.package.version().to_owned(), last_modified)]
            .into_iter()
            .collect(),
    )
}

/// The `Last-Modified` a HEAD of `url` answers, for the request at `path`.
/// Returns `None` when the host refuses the HEAD, cannot be asked, or sends no date.
async fn head_last_modified(proxy: &Proxy, url: &str, path: &str) -> Option<jiff::Timestamp> {
    let response = match proxy.config.client.head(url).send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), http.response.status_code = response.status().as_u16(), "no publish time: the file host refused a HEAD");
            return None;
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "no publish time: the file host could not be asked");
            return None;
        }
    };
    response
        .headers()
        .get(header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::http::http_date)
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

/// `Retry-After` on a 503. See docs/engineering_decisions/deferral-status-codes.md.
const RETRY_AFTER_SECONDS: &str = "1";

/// The client name the watcher's requests are logged under.
const WATCHER: &str = "waharoa-watch";

/// What one pass of the watcher did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Watched {
    /// Packages whose metadata was read.
    pub packages: usize,
    /// Versions their metadata listed that the proxy did not hold.
    pub new_versions: usize,
    /// Analyses started for those versions' preferred files.
    pub started: usize,
}

impl Proxy {
    /// One pass of the watcher: read each held package's metadata, and start analysing the
    /// preferred file of every version the proxy did not hold, before a client asks for it.
    /// See docs/engineering_decisions/watcher.md. Returns what it did.
    pub async fn watch(&self) -> Watched {
        let mut watched = Watched::default();
        if self.config.analyser.is_none() {
            return watched;
        }
        let keys = self.store.lock().expect("record store lock").packages();
        for key in keys {
            let path = format!("/{}", key.registry_name());
            let slot = metadata_slot(self, &path).await;
            let fetched = crate::ecosystem::fetched(self.config.clients.metadata(&key).await);
            drop(slot);
            let metadata = match fetched {
                Ok(metadata) => metadata,
                Err(e) => {
                    warn!(waharoa.package.purl = %key, error.message = %e, "watcher: could not read metadata");
                    continue;
                }
            };
            watched.packages += 1;
            let new = self
                .store
                .lock()
                .expect("record store lock")
                .refresh(metadata);
            watched.new_versions += new.len();
            let files = new
                .iter()
                .filter_map(|r| r.artifact().map(|file| (r, file)));
            for (record, file) in files {
                if self.watch_version(record, file).await {
                    watched.started += 1;
                }
            }
        }
        info!(
            waharoa.watch.packages = watched.packages,
            waharoa.watch.new_versions = watched.new_versions,
            waharoa.watch.started = watched.started,
            "watcher pass"
        );
        watched
    }

    /// Start analysing `record`'s preferred file, `artifact`, as a client's request would.
    /// Returns whether an analysis started: not for a file on an origin the proxy does not
    /// serve, with no strong digest, or already analysed.
    async fn watch_version(
        &self,
        record: &PackageRecord,
        artifact: &crate::record::Artifact,
    ) -> bool {
        let Some(path) =
            crate::origin::reachable_path(&artifact.url, self.config.origins.reachable())
        else {
            return false;
        };
        let path = path.split('#').next().unwrap_or_default().to_owned();
        let narrowed = record.narrowed_to(&artifact.filename);
        let record = narrowed.as_ref().unwrap_or(record);
        let key = record.package.key();
        let deciding = Deciding::new(
            self,
            ArtifactRequest {
                ecosystem: key.ecosystem(),
                method: &Method::GET,
                key,
                claimed_version: record.package.version(),
                filename: &artifact.filename,
                path: &path,
                client: WATCHER,
            },
        );
        let (fetch, _) = deciding.fetch_plan(record);
        let dated = deciding.dated(record).await;
        let analysed = deciding
            .analysed(record, &fetch, dated.times.as_ref())
            .await;
        if deciding.sourced(&fetch).await.is_none() {
            let refusal = deciding
                .refusal(
                    &analysed.record,
                    dated.times.as_ref(),
                    &analysed.provenance,
                    crate::policy::today(),
                )
                .await
                .ok()
                .and_then(|(_, refusal)| refusal);
            deciding.compare_source(dated.describing(record), &fetch, refusal.as_ref());
        }
        let (AnalysisState::Pending(job), Some(analyser)) = (analysed.state, &self.config.analyser)
        else {
            return false;
        };
        analyser.start(job).is_some()
    }
}

/// How often [`Proxy::report_traffic`] closes the window.
pub const TRAFFIC_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

/// The header naming which not-ready case a 503 is, since the status does not.
pub const NOT_READY: header::HeaderName = header::HeaderName::from_static("x-waharoa-not-ready");

/// The digest of the artifact a 503 is waiting on, as its log lines carry it.
pub const DEFERRED_DIGEST: header::HeaderName = header::HeaderName::from_static("x-waharoa-digest");

/// Why a request is not decided on yet. [`NotReady::response`] is what the client is sent.
enum NotReady {
    /// The store errored, or holds no snapshot.
    Unanswered,
    /// The snapshot has no stream that can report a finding or malware for this ecosystem.
    Uncovered(Ecosystem),
    /// The artifact's analysis has started, and the client's retry is decided on it.
    Analysing { purl: String, digest: Sri },
}

impl NotReady {
    /// What a log and the `x-waharoa-not-ready` header call this case.
    fn reason(&self) -> &'static str {
        match self {
            Self::Unanswered => "intel-store",
            Self::Uncovered(_) => "no-stream-for-ecosystem",
            Self::Analysing { .. } => "artifact-analysis",
        }
    }

    /// 503 with a wait and a reason, since a 429 is terminal for yarn 1 and bun.
    /// See docs/engineering_decisions/deferral-status-codes.md.
    fn response(self) -> Response {
        let body = match &self {
            Self::Unanswered => {
                "waharoa: the intel store cannot answer, so nothing is served unchecked\n"
                    .to_owned()
            }
            Self::Uncovered(ecosystem) => format!(
                "waharoa: the intel snapshot has no advisory stream for {ecosystem}, so no \
                 {ecosystem} package is served unchecked\n"
            ),
            Self::Analysing { purl, digest } => format!(
                "waharoa: {purl}, {digest}, has not been analysed yet; the analysis has \
                 started, ask again shortly\n"
            ),
        };
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (header::RETRY_AFTER, RETRY_AFTER_SECONDS),
                (NOT_READY, self.reason()),
            ],
            body,
        )
            .into_response();
        if let Self::Analysing { digest, .. } = &self
            && let Ok(value) = HeaderValue::from_str(&digest.to_string())
        {
            response.headers_mut().insert(DEFERRED_DIGEST, value);
        }
        response
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

/// What the intel store knows about a package, when a policy and a store are both
/// configured. `Ok(None)` without either. See docs/engineering_decisions/intel-in-decisions.md.
/// Returns [`NotReady`] when the store errors, has no snapshot, does not cover the
/// ecosystem, or was replaced mid-read, so the request is answered 503, never served.
async fn intel_for(
    proxy: &Proxy,
    key: &PackageKey,
    path: &str,
) -> Result<Option<PackageIntel>, NotReady> {
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
                    error!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), waharoa.intel.snapshot = %snapshot.digest, waharoa.intel.gap = %gap, "the intel snapshot has a gap for this ecosystem; answering 503");
                }
                return Err(NotReady::Uncovered(ecosystem));
            }
            Ok(None) => "the intel snapshot changed while it was read".to_owned(),
            Err(e) => e.to_string(),
        },
        Ok(None) => "no intel has been loaded".to_owned(),
        Err(e) => e.to_string(),
    };
    error!(
        url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
        waharoa.reason = %why,
        "intel store cannot answer; answering 503 rather than serving unchecked"
    );
    Err(NotReady::Unanswered)
}

/// The versions in this metadata document the policy refuses, every one asked, with
/// checks the record cannot answer dropped. Publish times come from the records alone.
fn policy_refused_versions(
    metadata: &PackageMetadata,
    policy: Option<&Policy>,
    intel: Option<&PackageIntel>,
    path: &str,
    audit: Option<&AuditLog>,
    mode: Mode,
) -> Refused {
    let Some(policy) = policy else {
        return Refused::default();
    };
    let today = crate::policy::today();
    let mut refused = HashSet::new();
    let mut order = Vec::new();
    let mut checks: BTreeSet<String> = BTreeSet::new();
    let mut strongest = crate::policy::Action::Allow;
    let predecessors =
        attestation::predecessors(&metadata.records, None, policy.provenance_window());
    for (record, previous) in metadata.records.iter().zip(&predecessors) {
        let provenance = attestation::from_metadata(record, previous);
        let enforce::Verdict::Refuse(refusal) =
            enforce::artifact(Some(policy), record, None, intel, &provenance, today)
        else {
            continue;
        };
        strongest = std::cmp::max_by_key(strongest, refusal.action, |a| a.strength());
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
                    &crate::policy::decide::Provenance::default(),
                )
            })
            .unwrap_or_default();
        let event = audit::Event::resolution(
            metadata.key.ecosystem().as_str(),
            &metadata.key.registry_name(),
            strongest.as_str(),
            order,
            checks.iter().cloned().collect(),
            &unenforceable,
        )
        .with_intel_snapshot(intel.map(|i| i.snapshot.as_str()));
        audit.write(&match mode {
            Mode::Enforce => event,
            Mode::Observe => event.answered(audit::Answered::Served),
        });
    }

    if mode == Mode::Observe {
        if !refused.is_empty() {
            warn!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                waharoa.package.versions = refused.len(),
                waharoa.policy.checks = ?checks,
                "observe: the policy refuses these versions; left in the document"
            );
        }
        return Refused::default();
    }
    if refused.len() == metadata.records.len() && !refused.is_empty() {
        warn!(
            url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
            waharoa.package.versions = refused.len(),
            "policy refuses every version of this package, so nothing is left to resolve to"
        );
    }
    Refused {
        checks: checks.into_iter().collect(),
        versions: refused,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::defer::DeferTest;
    use crate::identity::Ecosystem;
    use crate::util::test_support::NO_UPSTREAM;
    use crate::util::test_support::{capture, text};
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

    /// Everything a fake upstream saw, so a test can assert on the request the proxy made.
    #[derive(Default)]
    struct Seen {
        paths: Vec<String>,
        accept_encoding: Vec<Option<String>>,
        headers: Vec<HeaderMap>,
    }

    type Recorder = Arc<Mutex<Seen>>;

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

    /// An error page carries a status, not a document.
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

    /// A failed simple-index response is forwarded byte for byte, however readable its body.
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

    /// Through the router, an index comes back with its files pointed at the proxy, at URLs
    /// the proxy classifies as artifacts.
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

    /// A packument is rewritten, and everything except the artifact URLs has to survive it intact.
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

    /// A 304 carries this proxy's marked tag, not the upstream's, so the next one is a 304 too.
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
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream)
            .with_max_metadata_bytes(16);
        let base = serve(proxy.clone().router()).await;

        let response = reqwest::get(format!("{base}/lodash")).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            body.as_slice(),
            "the whole body has to arrive, including the prefix already buffered"
        );
        assert_eq!(proxy.health().documents_uninspected, 1);
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
    fn only_a_read_npm_document_is_asked_for_in_full() {
        let cooldown = Some("version: 1\ncooldown_days: 7\nprovenance: allow\n");
        let none = Some("version: 1\ncooldown_days: 0\nprovenance: allow\n");
        let cases = [
            (cooldown, Method::GET, "/lodash", "gzip", true),
            (none, Method::GET, "/lodash", "gzip", true),
            (None, Method::GET, "/lodash", "gzip", true),
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
                full_document: true,
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
        type Case<'a> = (
            &'a str,
            Option<&'a str>,
            &'a str,
            &'a [(header::HeaderName, &'static str)],
            header::HeaderName,
            Option<&'a str>,
        );
        let cases: [Case; 13] = [
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
            (
                "a credential for this proxy",
                None,
                TARBALL,
                &[(header::AUTHORIZATION, "Bearer account-token")],
                header::AUTHORIZATION,
                None,
            ),
            ("the proxy's Host", None, TARBALL, &[], header::HOST, None),
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
            (
                "a tag this proxy did not issue",
                None,
                PACKUMENT,
                &[(header::IF_NONE_MATCH, "W/\"abc123\"")],
                header::IF_NONE_MATCH,
                None,
            ),
            (
                "the full packument, without a policy",
                None,
                PACKUMENT,
                &[(header::ACCEPT, npm::ABBREVIATED_ACCEPT)],
                header::ACCEPT,
                Some(npm::FULL_ACCEPT),
            ),
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

    /// A tag this proxy issued reaches upstream as the upstream's own tag.
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

    /// Artifact URLs point at the address the client used, so a proxy reachable by several names
    /// points each client back at its own.
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
        assert!(
            warned.contains("waharoa.package.undated_versions=1"),
            "{warned}"
        );
        assert!(
            !said(NO_POLICY)
                .await
                .contains("cooldown_days cannot be answered"),
            "no cooldown, nothing to say"
        );
    }

    /// An index with no publish time in it, and a file host that answers `Last-Modified`: the
    /// cooldown is decided on the file's own date.
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
            ("no Last-Modified", StatusCode::OK, None, false),
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
            let yaml = "version: 1\ncooldown_days: 7\ninstall_scripts: allow\n";
            let proxy = offline(None, Some(yaml))
                .with_origin_policy([host.as_str()], [])
                .expect("the host is an origin");
            let index = format!(
                r#"{{"name":"x","files":[{{"filename":"x-1.0.tar.gz","url":"{host}/x-1.0.tar.gz","hashes":{{"sha256":"{}"}}}}]}}"#,
                "a".repeat(64)
            );
            resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, index.as_bytes()).await;
            let step = pinned(&proxy, "/packages/x-1.0.tar.gz").await;
            assert_eq!(matches!(step, ArtifactStep::Answer(_)), refused, "{label}");
        }
    }

    /// A deprecated version is served, and the message its publisher left is logged.
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
        let proxy = offline(None, None);
        let report = |encoding: &str| {
            let negotiation = negotiated(None, Method::GET, "/lodash", encoding);
            let (_, target) = crate::route::classify("/lodash");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_str(encoding).unwrap(),
            );
            logged(|| {
                report_uninspected(
                    &proxy,
                    &target,
                    &Method::GET,
                    &negotiation,
                    &headers,
                    "/lodash",
                )
            })
        };
        let unread = report(UNREADABLE);
        assert!(unread.contains("UNINSPECTED"), "{unread}");
        assert!(unread.contains(UNREADABLE), "{unread}");
        assert_eq!(report("gzip"), "", "a rewritten document is inspected");
        assert_eq!(proxy.health().documents_uninspected, 1);
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
    /// missed would answer 502, after its metadata fetch to [`NO_UPSTREAM`] failed.
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
            if check == Check::Yanked {
                yanked_is_refused_and_filtered().await;
                continue;
            }
            if check == Check::Provenance {
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
                    Check::Deprecated => (
                        RIMRAF,
                        "rimraf",
                        "1.0.0",
                        None,
                        format!("{BASE}deprecated: block\n"),
                    ),
                    Check::Yanked => unreachable!("run above, against a PyPI index"),
                    Check::Provenance => unreachable!("skipped above"),
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

    /// No policy at all is not the same as a policy that allows everything, and neither refuses.
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

    /// A 503 says how long to wait and which case it is.
    #[tokio::test]
    async fn a_request_the_proxy_cannot_decide_says_how_long_to_wait_and_why() {
        for (unavailable, reason) in [
            (NotReady::Unanswered, "intel-store"),
            (
                NotReady::Uncovered(Ecosystem::PyPI),
                "no-stream-for-ecosystem",
            ),
            (
                NotReady::Analysing {
                    purl: "pkg:npm/widget@1.0.0".to_owned(),
                    digest: Sri::parse(&sri_of(b"widget")).expect("parses"),
                },
                "artifact-analysis",
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

    /// A denied version is absent from the packument the client receives, with rewriting off too.
    #[tokio::test]
    async fn a_denied_version_is_absent_from_the_packument_the_client_receives() {
        for rewriting in [true, false] {
            let proxy = offline(None, Some(DENY_LODASH)).with_artifact_rewriting(rewriting);
            let document = resolved(&proxy, "lodash", LODASH).await;
            assert!(!offers(&document, "4.17.21"), "rewriting {rewriting}");
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

    /// A policy put in force after the router is built decides the next request.
    #[tokio::test]
    async fn a_replaced_policy_decides_the_next_request() {
        let proxy = offline(None, Some(DENY_LODASH));
        hold(&proxy, LODASH);
        let base = serve(proxy.clone().router()).await;
        let status = || async {
            reqwest::get(format!("{base}{LODASH_TARBALL}"))
                .await
                .unwrap()
                .status()
        };
        assert_eq!(status().await, StatusCode::FORBIDDEN);

        let replaced = proxy.replace_policy(Some(policy(ALLOW_ALL)));

        assert_eq!(
            replaced.map(|p| p.digest.clone()),
            Some(crate::policy::digest_of(DENY_LODASH))
        );
        assert_eq!(
            status().await,
            StatusCode::BAD_GATEWAY,
            "fetched, not refused"
        );
        assert_eq!(
            proxy.policy().map(|p| p.digest.clone()),
            Some(crate::policy::digest_of(ALLOW_ALL))
        );
    }

    /// Observe mode serves what the policy refuses. The version stays in the document, the
    /// artifact is fetched, and both are logged at WARN and audited as served.
    #[tokio::test]
    async fn observe_mode_serves_what_the_policy_refuses_and_records_it() {
        let path = crate::util::test_support::tempdir("proxy-observe").join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).expect("should open"));
        let proxy = offline(None, Some(DENY_LODASH))
            .with_mode(Mode::Observe)
            .with_audit_log(Some(log));
        let (guard, captured) = capture(tracing::Level::WARN);

        let DocumentStep::Forward {
            body: Some(body),
            refused,
        } = resolve_npm(&proxy, "lodash", LODASH).await
        else {
            panic!("the packument is rewritten");
        };
        let step = pinned(&proxy, LODASH_TARBALL).await;
        drop(guard);

        let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(offers(&document, "4.17.21"));
        assert!(refused.versions.is_empty(), "nothing to name in a header");
        assert!(fetched(&step));
        let captured = text(&captured);
        assert!(
            captured.contains("observe: the policy refuses these versions; left in the document"),
            "{captured}"
        );
        assert!(
            captured.contains("observe: the policy refuses this artifact; not refused"),
            "{captured}"
        );
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let answered: Vec<_> = events
            .iter()
            .map(|e| {
                (
                    e["path"].clone(),
                    e["action"].clone(),
                    e["answered"].clone(),
                )
            })
            .collect();
        assert_eq!(
            answered,
            [
                ("resolution".into(), "block".into(), "served".into()),
                ("pinned".into(), "block".into(), "served".into()),
            ]
        );
        assert_eq!(events[0]["removed"], serde_json::json!(["4.17.21"]));
    }

    /// Observe mode never serves what the proxy cannot assess: an artifact on an origin it
    /// does not serve, one with no strong digest, or one whose analysis has not finished.
    #[tokio::test]
    async fn observe_mode_still_refuses_what_cannot_be_assessed() {
        let unservable = offline(None, Some(ALLOW_ALL))
            .with_refuse_unservable(true)
            .with_mode(Mode::Observe);
        let DocumentStep::Forward {
            body: Some(body), ..
        } = resolve(
            &unservable,
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
        let (status, _) = refused(pinned(&unservable, "/widget/-/widget-1.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let undigested = offline(None, Some(ALLOW_ALL)).with_mode(Mode::Observe);
        hold_document(
            &undigested,
            br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
                "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );
        let (status, _) = refused(pinned(&undigested, "/widget/-/widget-1.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let tarball =
            crate::util::test_support::tarball(&[("package/package.json", RUNS_POSTINSTALL)]);
        let (base, analyser) = analysing_with(
            "observe-pending",
            "",
            &integrity(&tarball),
            tarball.clone(),
            Some(BLOCK),
            Arc::new(crate::analysis::store::InProcess::new(8)),
            Extras {
                mode: Mode::Observe,
                ..Extras::default()
            },
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 503);
        analyser.ended(1).await;
        let retry = tarball_request(&base).await;
        assert_eq!(retry.status(), 200, "install_scripts refuses it; observed");
        assert_eq!(retry.bytes().await.unwrap().as_ref(), tarball.as_slice());
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
        let refused = policy_refused_versions(
            &two_versions(),
            Some(&policy),
            None,
            "/pkg",
            Some(&log),
            Mode::Enforce,
        );
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
                policy_refused_versions(
                    &two_versions(),
                    Some(&policy),
                    None,
                    "/pkg",
                    None,
                    Mode::Enforce,
                );
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

    /// An artifact the proxy cannot serve is removed from the packument, so a resolver picks a
    /// version that can be examined.
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

    /// A pinned fetch of an unservable artifact is refused with the client's configured status.
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
                &|_| {},
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

    /// A refusal is on identity, not on the spelling of the path.
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

    /// A version published after an earlier request is held back on the next one.
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

    /// No stream in the snapshot covers PyPI, so a file is not served: an empty answer would read
    /// as "nothing known" about a package nothing was asked about.
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
        let packument = resolve_npm(&proxy, "lodash", LODASH).await;
        assert!(matches!(
            packument,
            DocumentStep::Forward { body: Some(_), .. }
        ));
    }

    /// 1.0 yanked whole, 2.0 not, 3.0 a wheel and a yanked sdist, 4.0 yanked with no reason.
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

    /// The yanked case, which `every_check_refuses_on_a_pinned_fetch_and_filters_the_packument`
    /// also runs.
    async fn yanked_is_refused_and_filtered() {
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

    /// A PyPI version the policy refuses is removed from the index, and pip resolves to another.
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

    /// With no stream covering PyPI the index is still filtered by the checks that need no intel.
    #[tokio::test]
    async fn a_pypi_index_no_stream_covers_is_filtered_without_intel() {
        let proxy = offline(
            Some(malware_everywhere()),
            Some("version: 1\ncooldown_days: 0\ninstall_scripts: block\n"),
        );
        let names = served_filenames(&proxy, PYPI_TWO_VERSIONS).await;
        assert_eq!(names, ["x-1.0-py3-none-any.whl", "x-1.0.tar.gz"]);
    }

    /// Every stream a served ecosystem lists, as a snapshot records them.
    fn every_listed_stream() -> Vec<crate::intel::refresh::StreamDigest> {
        crate::ecosystem::TABLE
            .iter()
            .flat_map(|registry| registry.streams.iter())
            .map(|listed| crate::intel::refresh::StreamDigest {
                stream: listed.stream.to_owned(),
                sha256: "aa".to_owned(),
                etag: None,
                last_modified: None,
            })
            .collect()
    }

    /// A snapshot holding every listed stream but the one named, knowing nothing of any package.
    struct EveryStream(Option<&'static str>);

    impl Intel for EveryStream {
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
                    digest: "s1".to_owned(),
                    taken_at: "2026-09-13T00:00:00Z".to_owned(),
                    sources: Vec::new(),
                    streams: every_listed_stream()
                        .into_iter()
                        .filter(|s| Some(s.stream.as_str()) != self.0)
                        .collect(),
                    unconfigured: Vec::new(),
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
                    snapshot: "s1".to_owned(),
                    records: Vec::new(),
                    ranges: Vec::new(),
                    exploitation_loaded: false,
                }))
            })
        }
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
                    unconfigured: Vec::new(),
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

    /// A snapshot missing one stream npm lists answers npm's packages 503, though the other
    /// streams still cover npm.
    #[tokio::test]
    async fn a_listed_stream_the_snapshot_does_not_hold_is_a_503() {
        let without_osv = Arc::new(EveryStream(Some("osv/npm")));
        let proxy = offline(Some(without_osv.clone()), Some(NO_POLICY));
        let (status, _) = answered(resolve_npm(&proxy, "lodash", LODASH).await).await;
        assert_eq!(status, 503);
        let readiness = offline(Some(without_osv), Some(NO_POLICY))
            .readiness()
            .await;
        assert!(!readiness.ready);
        assert!(
            readiness.gaps.iter().any(|g| g.contains("lists `osv/npm`")),
            "{:?}",
            readiness.gaps
        );

        let proxy = offline(Some(Arc::new(EveryStream(None))), Some(NO_POLICY));
        assert!(
            matches!(
                resolve_npm(&proxy, "lodash", LODASH).await,
                DocumentStep::Forward { .. }
            ),
            "with every stream held, the same document is forwarded"
        );
    }

    /// npm clients report a packument 503 as one, so npm's row keeps it.
    #[tokio::test]
    async fn an_npm_packument_no_stream_covers_is_a_503() {
        let proxy = offline(Some(Arc::new(NoStreams)), Some(NO_POLICY));
        let (status, body) = answered(resolve_npm(&proxy, "lodash", LODASH).await).await;
        assert_eq!(status, 503);
        assert!(body.contains("no advisory stream for npm"), "{body}");
    }

    /// A store whose records and newest snapshot differ, as a refresh between two reads leaves it.
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
                    streams: every_listed_stream(),
                    unconfigured: Vec::new(),
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
                Some(Arc::new(EveryStream(None)) as Arc<dyn Intel>),
                true,
                (true, IntelState::Loaded),
            ),
            (
                "loaded, with PyPI uncovered",
                Some(malware_everywhere()),
                true,
                (false, IntelState::Loaded),
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

        let (base, seen) = proxy_with_intel(Arc::new(EveryStream(None)), true).await;
        let response = reqwest::get(format!("{base}{READY_PATH}?probe=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.unwrap()).expect("a JSON body");
        assert_eq!(body["ready"], true);
        assert_eq!(body["intel"], "loaded");
        assert_eq!(body["snapshot"]["digest"], "s1");
        assert!(
            body.get("gaps").is_none(),
            "no gaps, so none listed: {body}"
        );
        let paths = seen.lock().unwrap().paths.clone();
        assert!(paths.is_empty(), "answered here, not forwarded: {paths:?}");

        let (base, _) = proxy_with_intel(malware_everywhere(), true).await;
        let response = reqwest::get(format!("{base}{READY_PATH}")).await.unwrap();
        assert_eq!(response.status(), 503, "a gap is not ready");
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.unwrap()).expect("a JSON body");
        assert_eq!(body["intel"], "loaded");
        let gaps = body["gaps"].as_array().expect("the gaps are listed");
        assert!(
            gaps.iter()
                .any(|g| g.as_str().is_some_and(|g| g.contains("`pypi` lists"))),
            "{body}"
        );
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

    /// §5: a not-ready state never wears a code that reads as a block.
    #[tokio::test]
    async fn the_only_4xx_this_proxy_produces_is_a_policy_refusal() {
        let addr = crate::util::test_support::closing_server().await;
        let dead = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, format!("http://{addr}"))
                .router(),
        )
        .await;

        for path in ["/lodash", "/lodash/-/lodash-4.17.21.tgz", "/-/ping"] {
            let status = reqwest::get(format!("{dead}{path}"))
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{path}");
        }

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

    /// A 304 leaves the proxy nothing to normalise, so when it holds no records for that package it
    /// fetches the packument itself.
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

        let ours = crate::http::mark_etag("W/\"abc123\"", &base);
        let response = reqwest::Client::new()
            .get(format!("{base}/lodash"))
            .header(header::IF_NONE_MATCH, ours)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 304);

        let response = reqwest::get(format!("{base}/lodash/-/lodash-4.17.21.tgz"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            404,
            "the fake registry serves no tarball"
        );

        let mut asked: Vec<(bool, bool)> = seen
            .lock()
            .unwrap()
            .headers
            .iter()
            .map(|h| {
                (
                    h.contains_key(header::IF_NONE_MATCH),
                    h.get(header::ACCEPT)
                        .is_some_and(|accept| accept == crate::ecosystem::npm::FULL_ACCEPT),
                )
            })
            .collect();
        asked.sort_unstable();
        assert_eq!(
            asked,
            [(false, false), (false, true), (true, true)],
            "the client's revalidation, one abbreviated fetch for the record and not a second \
             for the artifact, and the full packument, for its times and the heuristics"
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

    /// The whole point: the digest comes from a packument seen earlier, and the tarball
    /// is checked against it without being buffered.
    #[tokio::test]
    async fn a_tarball_matching_its_packument_digest_is_forwarded_whole() {
        let tarball: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let base = registry_with(&sri_of(&tarball), tarball.clone()).await;

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

    async fn revalidations(base: &str) -> u64 {
        let body = reqwest::get(format!("{base}{HEALTH_PATH}"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        serde_json::from_str::<Health>(&body)
            .unwrap()
            .artifacts_revalidated
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

    /// A tarball that fails its digest is not recorded as verified.
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

    /// A tarball that fails its digest never reaches the client complete.
    #[tokio::test]
    async fn a_tampered_tarball_never_arrives_complete() {
        let honest: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut tampered = honest.clone();
        tampered[25_000] ^= 0xFF;

        let base = registry_with(&sri_of(&honest), tampered).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();

        assert_no_complete_body(&format!("{base}/widget/-/widget-1.0.0.tgz")).await;
    }

    /// A tarball request with no packument behind it still gets verified, because the proxy fetches
    /// the packument itself.
    #[tokio::test]
    async fn a_tarball_with_no_packument_seen_is_verified_anyway() {
        let honest: Vec<u8> = vec![9u8; 1_000];
        let mut tampered = honest.clone();
        tampered[500] ^= 0xFF;
        let base = registry_with(&sri_of(&honest), tampered).await;

        assert_no_complete_body(&format!("{base}/widget/-/widget-1.0.0.tgz")).await;
    }

    /// A failed digest must not deliver a whole artifact.
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

    /// Every answer forwarded from upstream is logged once as `proxied`, with its status
    /// and the client.
    #[tokio::test]
    async fn a_forwarded_answer_is_logged_as_proxied() {
        let (upstream, _) = upstream_serving(
            StatusCode::NOT_FOUND,
            "application/json",
            None,
            b"{}".to_vec(),
        )
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, upstream)
                .router(),
        )
        .await;
        let (guard, log) = capture(tracing::Level::INFO);

        let response = reqwest::Client::new()
            .get(format!("{base}/-/v1/search?text=x"))
            .header(header::USER_AGENT, "npm/10.0.0")
            .send()
            .await
            .unwrap();
        drop(guard);

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let log = text(&log);
        let proxied: Vec<&str> = log.lines().filter(|l| l.contains("proxied")).collect();
        assert_eq!(proxied.len(), 1, "{log}");
        assert!(
            proxied[0].contains("http.response.status_code=404"),
            "{}",
            proxied[0]
        );
        assert!(
            proxied[0].contains("user_agent.original=npm/10.0.0"),
            "{}",
            proxied[0]
        );
        assert!(
            proxied[0].contains("url.path=/-/v1/search url.query=\"text=x\""),
            "{}",
            proxied[0]
        );
    }

    /// A resolver's probe, PyPI's root index here, is logged as `proxied` at debug, not
    /// info.
    #[tokio::test]
    async fn a_resolver_probe_is_logged_at_debug() {
        let (upstream, _) =
            upstream_serving(StatusCode::OK, "text/html", None, b"<html></html>".to_vec()).await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::PyPI, upstream)
                .router(),
        )
        .await;
        let proxied = |level| {
            let base = base.clone();
            async move {
                let (guard, log) = capture(level);
                reqwest::get(format!("{base}/simple/")).await.unwrap();
                drop(guard);
                text(&log).lines().filter(|l| l.contains("proxied")).count()
            }
        };

        assert_eq!(proxied(tracing::Level::INFO).await, 0);
        assert_eq!(proxied(tracing::Level::DEBUG).await, 1);
    }

    /// A metadata body that ends before its declared length is a 502, not a document
    /// forwarded short.
    #[tokio::test]
    async fn a_metadata_body_that_fails_mid_stream_is_a_502() {
        use crate::util::test_support::{Answer, scripted};
        let addr = scripted(vec![Answer::Body {
            bytes: b"{\"name\":".to_vec(),
            declared: Some(100),
        }])
        .await;
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, format!("http://{addr}"))
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/widget")).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.text().await.unwrap();
        assert!(body.contains("upstream body failed"), "{body}");
    }

    /// A file the record does not name, for a version it does, is decided on the version's
    /// first file, and says so.
    #[tokio::test]
    async fn a_file_the_record_does_not_name_is_decided_on_the_first_file() {
        let proxy = offline(None, None);
        let index = format!(
            r#"{{"name":"x","files":[{{"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/x-1.0.tar.gz","hashes":{{"sha256":"{}"}}}}]}}"#,
            "a".repeat(64)
        );
        resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, index.as_bytes()).await;
        let (guard, log) = capture(tracing::Level::WARN);

        let step = pinned(&proxy, "/packages/x-1.0.zip").await;
        drop(guard);

        assert!(fetched(&step));
        assert!(
            text(&log).contains("the record names no file by this name"),
            "{}",
            text(&log)
        );
    }

    /// An upstream that sends headers and then stops ends the request after the read
    /// timeout, rather than holding it for as long as the connection stays open.
    #[tokio::test]
    async fn a_stalled_upstream_ends_the_request_it_holds() {
        let stalled = crate::util::test_support::stalling_server().await;
        let client = crate::http::client_builder(std::time::Duration::from_millis(100))
            .build()
            .expect("a client");
        let base = serve(
            Proxy::new(client)
                .with_upstream(Ecosystem::Npm, format!("http://{stalled}"))
                .router(),
        )
        .await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz")),
        )
        .await
        .expect("the read timeout ends it well inside 5 s")
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    /// When the packument cannot be fetched either, nothing about the artifact can be
    /// assessed. The registry did not answer as it should, so it is a 502, not a refusal.
    #[tokio::test]
    async fn an_artifact_whose_packument_cannot_be_fetched_is_not_served() {
        let tarball = vec![4u8; 300];
        let body = tarball.clone();
        let router = Router::new().route(
            "/widget/-/widget-1.0.0.tgz",
            get(move || {
                let body = body.clone();
                async move { ([(header::CONTENT_TYPE, "application/octet-stream")], body) }
            }),
        );
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = response.text().await.unwrap();
        assert!(body.contains("the registry gave no metadata"), "{body}");
        assert!(!body.as_bytes().windows(tarball.len()).any(|w| w == tarball));
    }

    /// An empty body still has to terminate and still has to be checked.
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

    /// Two versions in 24,852 publish only SHA-1, which is collision-broken.
    #[tokio::test]
    async fn a_version_with_only_a_sha1_digest_is_refused() {
        let tarball = vec![3u8; 500];
        let base = registry_with("sha1-2KoFEwbCVDvbCxC5dXgvFkSlpwc=", tarball.clone()).await;
        reqwest::get(format!("{base}/widget")).await.unwrap();

        let response = reqwest::get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.text().await.unwrap();
        assert!(body.contains("no strong digest"), "{body}");
        assert!(!body.as_bytes().windows(tarball.len()).any(|w| w == tarball));
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

    /// A client that caches a rewritten packument revalidates against a tag we issued, not the
    /// upstream's.
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

        /// A simple index answers the same two reasons a packument does: both are rewritten, and a
        /// document that cannot be points its files somewhere the proxy will not see them.
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

    /// A listed version whose tarball the upstream answers 404 stores no analysis, and nothing
    /// remembers the 404, so every request for it is answered 503.
    #[tokio::test]
    async fn an_artifact_the_upstream_does_not_have_stays_deferred() {
        let packument = format!(
            r#"{{"name":"widget","versions":{{"1.0.0":{{"version":"1.0.0","dist":{{{}
                "tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}}}}}"#,
            integrity(b"gone")
        );
        let router = Router::new().route(
            "/widget",
            get(move || {
                let packument = packument.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], packument) }
            }),
        );
        let (spool, _) = Spool::open(&crate::util::test_support::tempdir("analyse-404"), 1 << 20)
            .expect("opens");
        let analyser = Arc::new(Analyser::new(
            reqwest::Client::new(),
            Arc::new(spool),
            Arc::new(crate::analysis::store::InProcess::new(8)),
            2,
            8,
        ));
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .with_analyser(Some(analyser.clone()))
                .router(),
        )
        .await;

        for attempt in 1..=3 {
            assert_eq!(
                tarball_request(&base).await.status(),
                503,
                "attempt {attempt}"
            );
            analyser.ended(attempt).await;
        }
    }

    /// Bounded, so a proxy that forwards to an upstream a test holds shut fails the test
    /// rather than hanging it.
    async fn tarball_request(base: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .expect("answered within 10 s")
    }

    /// A version whose claim passes waits for the analysis, and each deferral names the
    /// digest. The retry is served whole.
    #[tokio::test]
    async fn a_deferred_artifact_is_served_on_its_retry_after_the_analysis() {
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let gate = Arc::new(Semaphore::new(0));
        let (base, analyser) = analysing_with(
            "analyse-defer",
            "",
            &integrity(&tarball),
            tarball.clone(),
            Some(BLOCK),
            Arc::new(crate::analysis::store::InProcess::new(8)),
            Extras {
                gate: Some(gate.clone()),
                ..Extras::default()
            },
        )
        .await;

        let digest = sri_of(&tarball);
        let (guard, log) = capture(tracing::Level::INFO);
        for _ in 0..2 {
            let deferred = tarball_request(&base).await;
            assert_eq!(deferred.status(), 503);
            assert_eq!(deferred.headers()[NOT_READY.as_str()], "artifact-analysis");
            assert_eq!(
                deferred.headers()[DEFERRED_DIGEST.as_str()],
                digest.as_str()
            );
            assert_eq!(deferred.headers()[header::RETRY_AFTER.as_str()], "1");
            let body = deferred.text().await.unwrap();
            assert!(body.contains("pkg:npm/widget@1.0.0"), "{body}");
            assert!(body.contains(&digest), "{body}");
        }

        gate.add_permits(Semaphore::MAX_PERMITS);
        analyser.ended(1).await;
        let retry = tarball_request(&base).await;
        assert_eq!(retry.status(), 200);
        assert_eq!(retry.bytes().await.unwrap().as_ref(), tarball.as_slice());
        assert_eq!(tarball_request(&base).await.status(), 200);
        drop(guard);

        let log = text(&log);
        let returns: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("returned after a deferral"))
            .collect();
        assert_eq!(returns.len(), 1, "{log}");
        assert!(
            returns[0].contains("waharoa.deferral.count=2"),
            "{}",
            returns[0]
        );
        assert!(returns[0].contains(&digest), "{}", returns[0]);
        assert!(
            returns[0].contains("waharoa.deferral.after_ms="),
            "{}",
            returns[0]
        );
    }

    /// Each deferral of a digest is counted from the first, and a return takes the record away.
    #[test]
    fn deferrals_of_one_digest_are_counted_until_it_returns() {
        let digest = Sri::parse(&sri_of(b"widget")).expect("parses");
        let other = Sri::parse(&sri_of(b"other")).expect("parses");
        let mut deferred = Deferred(Lru::new(8));
        assert_eq!(deferred.defer(&digest), 1);
        assert_eq!(deferred.defer(&digest), 2);
        assert_eq!(deferred.defer(&other), 1);
        let first = deferred.0.remove(&digest).expect("held").first;
        assert!(first.elapsed() < std::time::Duration::from_secs(60));
        assert_eq!(deferred.defer(&digest), 1);
    }

    /// Under any policy, or none, an artifact is answered 503 until its analysis has
    /// finished, and served after.
    #[tokio::test]
    async fn an_artifact_is_deferred_until_its_analysis_has_finished_under_any_policy() {
        let tarball =
            crate::util::test_support::tarball(&[("package/package.json", RUNS_POSTINSTALL)]);
        let allow = "version: 1\ncooldown_days: 0\ninstall_scripts: allow\n";
        let excepted = "version: 1\ncooldown_days: 0\ninstall_scripts: block\n\
                        packages:\n  - match: { ecosystem: npm, name: widget }\n    \
                        set: { install_scripts: allow }\n    reason: reviewed\n    \
                        permanent: true\n";
        for (label, yaml) in [
            ("analyse-none", None),
            ("analyse-allow", Some(allow)),
            ("analyse-excepted", Some(excepted)),
        ] {
            let (base, analyser) =
                analysing(label, "", &integrity(&tarball), tarball.clone(), yaml).await;
            assert_eq!(tarball_request(&base).await.status(), 503, "{label}");
            analyser.ended(1).await;
            let digest = Sri::parse(&sri_of(&tarball)).expect("parses");
            assert!(
                matches!(analyser.known(&digest).await, Known::Analysed(_)),
                "{label}"
            );
            let retry = tarball_request(&base).await;
            assert_eq!(retry.status(), 200, "{label}");
            assert_eq!(retry.bytes().await.unwrap().as_ref(), tarball.as_slice());
        }
    }

    /// The packument claims no script and the tarball runs `postinstall`. The artifact
    /// decides.
    #[tokio::test]
    async fn a_script_the_metadata_did_not_declare_is_refused_under_block() {
        let tarball =
            crate::util::test_support::tarball(&[("package/package.json", RUNS_POSTINSTALL)]);
        let yaml = BLOCK;
        let (base, analyser) = analysing(
            "analyse-undeclared",
            "",
            &integrity(&tarball),
            tarball,
            Some(yaml),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 503);
        analyser.ended(1).await;
        let retry = tarball_request(&base).await;
        assert_eq!(retry.status(), 403);
        assert!(retry.text().await.unwrap().contains("install_scripts"));
    }

    /// A claimed script `package.json` does not name still refuses under `block`, unanalysed.
    #[tokio::test]
    async fn a_claimed_script_the_artifact_does_not_name_is_still_refused_under_block() {
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let yaml = BLOCK;
        let (base, analyser) = analysing(
            "analyse-overstated",
            r#""hasInstallScript":true,"#,
            &integrity(&tarball),
            tarball,
            Some(yaml),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 403);
        assert_eq!(analyser.in_flight(), 0, "no job was started");
    }

    /// A stored analysis finding no script never removes a script the packument claims.
    #[tokio::test]
    async fn a_stored_analysis_never_removes_a_claimed_script() {
        use crate::analysis::store::{Analyses, Analysis, InProcess};
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let store = Arc::new(InProcess::new(8));
        let digest = Sri::parse(&sri_of(&tarball)).expect("parses");
        let none = Analysis {
            ecosystem: "npm".to_owned(),
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
            scripts: Scripts::Declared(crate::analysis::InstallScripts::default()),
        };
        store.put(&digest, &none).await.expect("stores");
        let yaml = BLOCK;

        let (base, _) = analysing_with(
            "analyse-stored-claim",
            r#""hasInstallScript":true,"#,
            &integrity(&tarball),
            tarball.clone(),
            Some(yaml),
            store.clone(),
            Extras::default(),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 403);

        let (base, _) = analysing_with(
            "analyse-stored-none",
            "",
            &integrity(&tarball),
            tarball,
            Some(yaml),
            store,
            Extras::default(),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 200);
    }

    /// Not knowing is not knowing there is no script.
    #[tokio::test]
    async fn an_archive_that_cannot_be_read_is_refused_under_block() {
        let tarball = b"not a gzip stream".to_vec();
        let yaml = BLOCK;
        let (base, analyser) = analysing(
            "analyse-unreadable",
            "",
            &integrity(&tarball),
            tarball,
            Some(yaml),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 503);
        analyser.ended(1).await;
        assert_eq!(tarball_request(&base).await.status(), 403);
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_their_digest_are_a_502_on_the_retry() {
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let (base, analyser) = analysing(
            "analyse-mismatch",
            "",
            &integrity(b"other bytes"),
            tarball,
            Some(BLOCK),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 503);
        analyser.ended(1).await;
        let retry = tarball_request(&base).await;
        assert_eq!(retry.status(), 502);
        assert!(retry.text().await.unwrap().contains("does not describe"));
    }

    /// No strong digest, so nothing can be stored or checked against: refused under any
    /// policy, and with none.
    #[tokio::test]
    async fn an_artifact_with_no_strong_digest_is_refused_under_any_policy() {
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let yaml = BLOCK;
        let (base, _) = analysing(
            "analyse-nodigest-block",
            "",
            "",
            tarball.clone(),
            Some(yaml),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 403);

        let (base, _) = analysing("analyse-nodigest", "", "", tarball, None).await;
        assert_eq!(tarball_request(&base).await.status(), 403);
    }

    /// A script the artifact runs and the metadata did not declare is a warning whatever the policy
    /// says.
    #[test]
    fn a_script_the_metadata_hid_is_a_warning() {
        let record = &two_versions().records[0];
        assert!(!record.has_install_scripts);
        let runs = |names: &[&str]| {
            Scripts::Declared(crate::analysis::InstallScripts {
                names: names.iter().map(|n| (*n).to_owned()).collect(),
                bodies: Vec::new(),
            })
        };
        let said = |scripts: Scripts| {
            let (guard, buf) = capture(tracing::Level::INFO);
            report_claim(record, &scripts, "/pkg/-/pkg-1.0.0.tgz");
            drop(guard);
            text(&buf)
        };

        let hidden = said(runs(&["postinstall"]));
        assert!(hidden.contains("WARN"), "{hidden}");
        assert!(hidden.contains("does not declare"), "{hidden}");
        assert!(hidden.contains("undeclared"), "{hidden}");

        let kept = said(runs(&[]));
        assert!(kept.contains("INFO") && !kept.contains("WARN"), "{kept}");
        assert!(kept.contains("\"kept\""), "{kept}");

        let unreadable = said(Scripts::Unreadable("not an archive".to_owned()));
        assert!(unreadable.contains("could not be read"), "{unreadable}");
    }

    /// A check that needs no analysis refuses at once, without deferring.
    #[tokio::test]
    async fn a_denied_version_is_refused_before_it_is_analysed() {
        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let yaml = "version: 1\ncooldown_days: 0\n\
                    denials:\n  - purl: pkg:npm/widget@1.0.0\n    reason: test\n";
        let (base, analyser) = analysing(
            "analyse-denied",
            "",
            &integrity(&tarball),
            tarball,
            Some(yaml),
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 403);
        assert_eq!(analyser.in_flight(), 0, "no job was started");
    }

    const PROVENANCE: &str = "version: 1\ncooldown_days: 0\ninstall_scripts: allow\n";

    fn widget_digest(version: &str) -> Sri {
        Sri::parse(&sri_of(version.as_bytes())).expect("parses")
    }

    /// `widget` 1.0.0 then 2.0.0, as a full packument with publish times. A version in
    /// `attested` publishes attestations on npm's registry, which an offline proxy routes
    /// to its upstream, an address that refuses connections.
    fn widget_versions(attested: &[&str]) -> String {
        let mut doc = serde_json::json!({"name": "widget", "dist-tags": {"latest": "2.0.0"},
            "versions": {}, "time": {}});
        for (month, version) in [(1, "1.0.0"), (2, "2.0.0")] {
            let mut dist = serde_json::json!({
                "tarball": format!("https://registry.npmjs.org/widget/-/widget-{version}.tgz"),
                "integrity": sri_of(version.as_bytes()),
            });
            if attested.contains(&version) {
                dist["attestations"] = serde_json::json!({
                    "url": format!("https://registry.npmjs.org/-/npm/v1/attestations/widget@{version}"),
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
                });
            }
            doc["versions"][version] =
                serde_json::json!({"name": "widget", "version": version, "dist": dist});
            doc["time"][version] = serde_json::json!(format!("2026-0{month}-01T00:00:00.000Z"));
        }
        doc.to_string()
    }

    /// An offline proxy under `yaml` whose analyser holds `results`, each an attestation
    /// result by digest, and `scripts`, an analysis naming no script for each digest.
    async fn attesting_proxy(
        label: &str,
        yaml: &str,
        results: &[(Sri, crate::analysis::attestation::Attested)],
        scripts: &[Sri],
    ) -> (Proxy, Arc<Analyser>) {
        use crate::analysis::store::{Analyses, Analysis, InProcess};
        let store = Arc::new(InProcess::new(16));
        for (digest, result) in results {
            store.put_attested(digest, result).await.expect("stores");
        }
        for digest in scripts {
            let none = Analysis {
                ecosystem: "npm".to_owned(),
                name: "widget".to_owned(),
                version: "2.0.0".to_owned(),
                scripts: Scripts::Declared(crate::analysis::InstallScripts::default()),
            };
            store.put(digest, &none).await.expect("stores");
        }
        let (spool, _) =
            Spool::open(&crate::util::test_support::tempdir(label), 1 << 20).expect("opens");
        let analyser = Arc::new(Analyser::new(
            reqwest::Client::new(),
            Arc::new(spool),
            store,
            2,
            8,
        ));
        let proxy = offline(None, Some(yaml)).with_analyser(Some(analyser.clone()));
        (proxy, analyser)
    }

    /// An offline proxy holding `widget_versions(attested)`, whose analyser holds `results`
    /// and an analysis of 2.0.0's scripts, so only attestations can be pending.
    async fn provenance_proxy(
        label: &str,
        yaml: &str,
        attested: &[&str],
        results: &[(&str, crate::analysis::attestation::Attested)],
    ) -> (Proxy, Arc<Analyser>) {
        let results: Vec<_> = results
            .iter()
            .map(|(version, result)| (widget_digest(version), result.clone()))
            .collect();
        let (proxy, analyser) =
            attesting_proxy(label, yaml, &results, &[widget_digest("2.0.0")]).await;
        hold_document(
            &proxy,
            widget_versions(attested).as_bytes(),
            crate::record::DocumentDetail::Full,
        );
        (proxy, analyser)
    }

    fn verified(identity: &str) -> crate::analysis::attestation::Attested {
        crate::analysis::attestation::Attested::Verified {
            identity: identity.to_owned(),
        }
    }

    const WIDGET_2: &str = "/widget/-/widget-2.0.0.tgz";

    /// Each case `docs/engineering_decisions/provenance-check.md` refuses, on a pinned
    /// fetch, with the case named in the body.
    #[tokio::test]
    async fn the_provenance_check_refuses_on_a_pinned_fetch() {
        let both = &["1.0.0", "2.0.0"];
        let failed = crate::analysis::attestation::Attested::Failed {
            why: "artifact hash does not match any subject in attestation".to_owned(),
        };
        let cases = [
            (
                "provenance-changed",
                &both[..],
                vec![("1.0.0", verified("a")), ("2.0.0", verified("b"))],
                "provenance: built by b, and 1.0.0 was built by a",
            ),
            (
                "provenance-unverified",
                &both[..],
                vec![("1.0.0", verified("a")), ("2.0.0", failed.clone())],
                "provenance: an attestation failed verification",
            ),
            (
                "provenance-dropped",
                &["1.0.0"][..],
                vec![],
                "provenance: publishes no attestation, and 1.0.0, published before it, did",
            ),
        ];
        for (label, attested, results, reason) in cases {
            let (proxy, _) = provenance_proxy(label, PROVENANCE, attested, &results).await;
            let (status, body) = refused(pinned(&proxy, WIDGET_2).await).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {body}");
            assert!(body.contains(reason), "{label}: {body}");
        }
    }

    /// The same identity as the version before it, and a version whose predecessor
    /// published nothing, are served.
    #[tokio::test]
    async fn a_version_its_attestations_agree_with_is_served() {
        let (proxy, _) = provenance_proxy(
            "provenance-same",
            PROVENANCE,
            &["1.0.0", "2.0.0"],
            &[("1.0.0", verified("a")), ("2.0.0", verified("a"))],
        )
        .await;
        assert!(fetched(&pinned(&proxy, WIDGET_2).await));

        let (proxy, _) = provenance_proxy(
            "provenance-first",
            PROVENANCE,
            &["2.0.0"],
            &[("2.0.0", verified("a"))],
        )
        .await;
        assert!(fetched(&pinned(&proxy, WIDGET_2).await));
    }

    /// `set: { provenance: allow }` releases a changed identity.
    #[tokio::test]
    async fn an_exception_releases_a_changed_identity() {
        let yaml = format!(
            "{PROVENANCE}packages:\n  - match: {{ ecosystem: npm, name: widget }}\n    \
             set: {{ provenance: allow }}\n    reason: moved to release.yml\n    \
             permanent: true\n"
        );
        let (proxy, _) = provenance_proxy(
            "provenance-excepted",
            &yaml,
            &["1.0.0", "2.0.0"],
            &[("1.0.0", verified("a")), ("2.0.0", verified("b"))],
        )
        .await;
        assert!(fetched(&pinned(&proxy, WIDGET_2).await));
    }

    /// Attestations nothing has verified are waited for under `provenance: block` and under
    /// `allow`: nothing is served until its analysis has finished.
    #[tokio::test]
    async fn unverified_attestations_are_waited_for_under_any_policy() {
        let (proxy, analyser) =
            provenance_proxy("provenance-pending", PROVENANCE, &["1.0.0", "2.0.0"], &[]).await;
        let (status, _) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        analyser.ended(1).await;
        let (status, _) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        analyser.ended(2).await;

        let allow = format!("{PROVENANCE}provenance: allow\n");
        let (proxy, analyser) =
            provenance_proxy("provenance-allowed", &allow, &["1.0.0", "2.0.0"], &[]).await;
        let (status, _) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        analyser.ended(1).await;
    }

    /// Dropped provenance needs nothing verified, so it is decided from the document: the
    /// version is filtered on resolution, and refused on a pinned fetch with no analyser.
    #[tokio::test]
    async fn dropped_provenance_is_decided_from_metadata_alone() {
        let packument = widget_versions(&["1.0.0"]);
        let proxy = offline(None, Some(PROVENANCE));
        let document =
            match resolve(&proxy, "/widget", npm::FULL_ACCEPT, packument.as_bytes()).await {
                DocumentStep::Forward {
                    body: Some(body), ..
                } => serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                _ => panic!("the document is read and filtered"),
            };
        assert!(offers(&document, "1.0.0"));
        assert!(!offers(&document, "2.0.0"));

        hold_document(
            &proxy,
            packument.as_bytes(),
            crate::record::DocumentDetail::Full,
        );
        let (status, body) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// Holding only the abbreviated packument, which carries no publish times, the proxy
    /// fetches the full one for them, and dropped provenance is found.
    #[tokio::test]
    async fn publish_times_are_fetched_to_find_the_version_before() {
        let full = widget_versions(&["1.0.0"]);
        let router = Router::new().route(
            "/widget",
            get(move || {
                let full = full.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], full) }
            }),
        );
        let upstream = serve(router).await;
        let proxy = offline(None, Some(PROVENANCE)).with_upstream(Ecosystem::Npm, upstream);
        let mut abbreviated: serde_json::Value =
            serde_json::from_str(&widget_versions(&["1.0.0"])).unwrap();
        abbreviated.as_object_mut().unwrap().remove("time");
        hold_document(
            &proxy,
            abbreviated.to_string().as_bytes(),
            crate::record::DocumentDetail::Abbreviated,
        );
        let (status, body) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("publishes no attestation"), "{body}");
    }

    /// An attestations document is fetched where the artifact would be: npm's registry
    /// through the upstream, an added origin directly, and any other origin not at all.
    #[test]
    fn attestations_are_fetched_where_the_artifact_would_be() {
        let proxy = offline(None, None)
            .with_origin_policy(["https://cdn.example"], ["https://direct.example"])
            .unwrap();
        let routed = |url: &str| attestation_url(&proxy, Ecosystem::Npm, url);
        assert_eq!(
            routed("https://registry.npmjs.org/-/npm/v1/attestations/widget@1.0.0?x=1"),
            Ok(format!(
                "{NO_UPSTREAM}/-/npm/v1/attestations/widget@1.0.0?x=1"
            ))
        );
        assert_eq!(
            routed("https://cdn.example/attestations/widget@1.0.0"),
            Ok("https://cdn.example/attestations/widget@1.0.0".to_owned())
        );
        for origin in ["https://direct.example", "https://elsewhere.example"] {
            let error = routed(&format!("{origin}/a")).expect_err(origin);
            assert!(error.contains(origin), "{error}");
        }
    }

    /// Attestations published somewhere the proxy will not go count as not verifying, so
    /// a version cannot slip the check by pointing them at a dead host.
    #[tokio::test]
    async fn attestations_the_proxy_will_not_fetch_are_refused() {
        let packument = widget_versions(&["2.0.0"]).replace(
            "https://registry.npmjs.org/-/npm/v1/attestations",
            "https://elsewhere.example/attestations",
        );
        let (proxy, _) = provenance_proxy("provenance-elsewhere", PROVENANCE, &[], &[]).await;
        hold_document(
            &proxy,
            packument.as_bytes(),
            crate::record::DocumentDetail::Full,
        );
        let (status, body) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("https://elsewhere.example"), "{body}");
    }

    /// PyPI project `x`: 1.0 then 2.0, each an sdist and a wheel, as a PEP 691 index. A
    /// version in `attested` publishes provenance for both its files, on pypi.org.
    fn x_index(attested: &[&str]) -> String {
        let mut files = Vec::new();
        for (day, version) in [(1, "1.0"), (2, "2.0")] {
            for file in [
                format!("x-{version}.tar.gz"),
                format!("x-{version}-py3-none-any.whl"),
            ] {
                let mut entry = serde_json::json!({
                    "filename": file,
                    "url": format!("https://files.pythonhosted.org/packages/aa/bb/{file}"),
                    "hashes": {"sha256": x_hex(&file)},
                    "upload-time": format!("2026-01-0{day}T00:00:00Z"),
                });
                if attested.contains(&version) {
                    entry["provenance"] = serde_json::json!(format!(
                        "https://pypi.org/integrity/x/{version}/{file}/provenance"
                    ));
                }
                files.push(entry);
            }
        }
        serde_json::json!({"meta": {"api-version": "1.1"}, "name": "x", "files": files}).to_string()
    }

    fn x_hex(file: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(file.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn x_digest(file: &str) -> Sri {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        Sri::parse(&format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(file.as_bytes()))
        ))
        .expect("parses")
    }

    const X_WHEEL_2: &str = "/packages/aa/bb/x-2.0-py3-none-any.whl";

    /// A wheel is checked against its own attestation, and against the previous version as
    /// a whole, whose identity is read from its sdist.
    #[tokio::test]
    async fn a_pypi_file_is_checked_against_the_version_before_it() {
        let cases = [
            ("pypi-changed", verified("b"), false),
            ("pypi-same", verified("a"), true),
        ];
        for (label, wheel, served) in cases {
            let results = [
                (x_digest("x-1.0.tar.gz"), verified("a")),
                (x_digest("x-2.0-py3-none-any.whl"), wheel),
            ];
            let (proxy, _) = attesting_proxy(label, PROVENANCE, &results, &[]).await;
            served_filenames(&proxy, x_index(&["1.0", "2.0"]).as_bytes()).await;
            let step = pinned(&proxy, X_WHEEL_2).await;
            if served {
                assert!(fetched(&step), "{label}");
            } else {
                let (status, body) = refused(step).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
                assert!(
                    body.contains("built by b, and 1.0 was built by a"),
                    "{body}"
                );
            }
        }
    }

    /// A release with no provenance after one with some is taken out of the index, and a
    /// pinned fetch of either of its files is refused.
    #[tokio::test]
    async fn a_pypi_release_that_drops_provenance_is_filtered_and_refused() {
        let (proxy, _) = attesting_proxy("pypi-dropped", PROVENANCE, &[], &[]).await;
        assert_eq!(
            served_filenames(&proxy, x_index(&["1.0"]).as_bytes()).await,
            ["x-1.0.tar.gz", "x-1.0-py3-none-any.whl"]
        );
        let (status, body) = refused(pinned(&proxy, X_WHEEL_2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("publishes no attestation"), "{body}");
    }

    /// A wheel no reader reads still has its attestations verified, and waits for them.
    #[tokio::test]
    async fn a_wheel_waits_for_its_attestations() {
        let (proxy, analyser) = attesting_proxy("pypi-pending", PROVENANCE, &[], &[]).await;
        served_filenames(&proxy, x_index(&["1.0", "2.0"]).as_bytes()).await;
        let (status, _) = refused(pinned(&proxy, X_WHEEL_2).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        analyser.ended(1).await;
    }

    /// PEP 740's attestations are served beside the index, not by the file host.
    #[test]
    fn pypi_attestations_are_fetched_from_the_index_host() {
        let proxy = offline(None, None);
        assert_eq!(
            attestation_url(
                &proxy,
                Ecosystem::PyPI,
                "https://pypi.org/integrity/x/1.0/x-1.0.tar.gz/provenance"
            ),
            Ok(format!(
                "{NO_UPSTREAM}/integrity/x/1.0/x-1.0.tar.gz/provenance"
            ))
        );
    }

    /// A registry whose `widget` 1.0.0 tarball answers 304 to a conditional request and 200
    /// otherwise, and whose 2.0.0 tarball is gone, 404. Both digests are published.
    async fn conditional_registry() -> (String, Vec<u8>) {
        let tarball: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let digest = sri_of(&tarball);
        let packument = format!(
            r#"{{"name":"widget","dist-tags":{{"latest":"2.0.0"}},"versions":{{
                "1.0.0":{{"version":"1.0.0","dist":{{"integrity":"{digest}",
                    "tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}},
                "2.0.0":{{"version":"2.0.0","dist":{{"integrity":"{digest}",
                    "tarball":"https://registry.npmjs.org/widget/-/widget-2.0.0.tgz"}}}}}}}}"#
        );
        let body = tarball.clone();
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
                get(move |headers: HeaderMap| {
                    let body = body.clone();
                    async move {
                        if headers.contains_key(header::IF_NONE_MATCH) {
                            StatusCode::NOT_MODIFIED.into_response()
                        } else {
                            ([(header::ETAG, "\"t1\"")], body).into_response()
                        }
                    }
                }),
            )
            .route(
                "/widget/-/widget-2.0.0.tgz",
                get(|| async { (StatusCode::NOT_FOUND, "gone") }),
            );
        let base = serve(
            Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .router(),
        )
        .await;
        reqwest::get(format!("{base}/widget")).await.unwrap();
        (base, tarball)
    }

    /// A 304 and a 404 on an artifact pass through as they came.
    #[tokio::test]
    async fn an_artifact_answered_without_its_bytes_is_passed_through_unhashed() {
        let (base, tarball) = conditional_registry().await;
        let client = reqwest::Client::new();
        let (guard, log) = capture(tracing::Level::INFO);

        let fresh = client
            .get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .send()
            .await
            .unwrap();
        assert_eq!(fresh.status(), 200);
        assert_eq!(fresh.bytes().await.unwrap().as_ref(), tarball.as_slice());
        assert_eq!(artifacts_verified(&base).await, 1);

        let revalidated = client
            .get(format!("{base}/widget/-/widget-1.0.0.tgz"))
            .header(header::IF_NONE_MATCH, "\"t1\"")
            .send()
            .await
            .unwrap();
        assert_eq!(revalidated.status(), 304);
        assert!(revalidated.bytes().await.is_ok(), "the 304 ends cleanly");
        assert_eq!(revalidations(&base).await, 1);

        let gone = client
            .get(format!("{base}/widget/-/widget-2.0.0.tgz"))
            .send()
            .await
            .unwrap();
        assert_eq!(gone.status(), 404);
        assert_eq!(gone.text().await.unwrap(), "gone");
        drop(guard);

        let log = text(&log);
        assert!(!log.contains("MISMATCH"), "{log}");
        let revalidated: Vec<&str> = log
            .lines()
            .filter(|line| line.contains("artifact revalidated with a 304"))
            .collect();
        assert_eq!(revalidated.len(), 1, "{log}");
        assert!(
            revalidated[0].contains("widget-1.0.0.tgz"),
            "{}",
            revalidated[0]
        );
        assert_eq!(artifacts_verified(&base).await, 1);
        assert_eq!(revalidations(&base).await, 1);
    }

    /// A packument that does not list the version asked for says nothing about its
    /// artifact, so the artifact is refused.
    #[tokio::test]
    async fn an_artifact_for_a_version_its_metadata_does_not_list_is_refused() {
        let proxy = offline(None, None);
        hold_document(
            &proxy,
            br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
                "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );

        let (status, body) = refused(pinned(&proxy, "/widget/-/widget-2.0.0.tgz").await).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            "waharoa: pkg:npm/widget@2.0.0 cannot be assessed: its metadata does not list this \
             version\n"
        );
    }

    /// A pinned fetch of a version with a dependency named by URL says so, once, and
    /// counts it.
    #[tokio::test]
    async fn a_version_depending_on_a_url_is_reported_when_fetched() {
        let proxy = offline(None, None);
        let packument = br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
            "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
            "integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},
            "dependencies":{"left":"github:someone/left-pad#main","ok":"^1.0.0"}}}}"#;
        hold_document(
            &proxy,
            packument,
            crate::record::DocumentDetail::Abbreviated,
        );
        let (guard, log) = capture(tracing::Level::WARN);
        let step = pinned(&proxy, "/widget/-/widget-1.0.0.tgz").await;
        assert!(matches!(step, ArtifactStep::Fetch(_)));
        drop(guard);
        let log = text(&log);
        let lines: Vec<&str> = log.lines().filter(|l| l.contains("BYPASS")).collect();
        assert_eq!(lines.len(), 1, "{log}");
        assert!(
            lines[0].contains("left github:someone/left-pad#main"),
            "{}",
            lines[0]
        );
        assert!(!lines[0].contains("^1.0.0"), "{}", lines[0]);
        assert_eq!(proxy.health().artifacts_with_direct_dependencies, 1);
    }

    /// A client that reads documents and fetches no artifact in a window is reported when the
    /// window closes, and kept in health until the next one.
    #[tokio::test]
    async fn a_client_reading_documents_and_no_artifacts_is_reported() {
        let proxy = offline(None, None);
        let (_, packument) = crate::route::classify("/lodash");
        let (_, tarball) = crate::route::classify("/lodash/-/lodash-4.17.21.tgz");
        {
            let mut traffic = proxy.traffic.lock().unwrap();
            for _ in 0..3 {
                traffic.count("pnpm/10.0.0 npm/? node/v24", &packument);
            }
            traffic.count("npm/11.0.0 node/v24", &packument);
            traffic.count("npm/11.0.0 node/v24", &tarball);
            traffic.count("curl/8", &crate::route::RequestTarget::Other);
        }
        let log = logged(|| proxy.report_traffic());
        assert!(
            log.contains("user_agent.original=pnpm") && log.contains("waharoa.traffic.documents=3"),
            "{log}"
        );
        assert!(!log.contains("user_agent.original=npm"), "{log}");
        assert!(!log.contains("user_agent.original=curl"), "{log}");
        assert_eq!(
            proxy.health().clients_without_artifacts,
            [("pnpm".to_owned(), 3)].into()
        );
        proxy.report_traffic();
        assert!(proxy.health().clients_without_artifacts.is_empty());
    }

    /// Past the cap, a new client name is counted as `other`.
    #[test]
    fn traffic_keeps_a_bounded_number_of_client_names() {
        let proxy = offline(None, None).with_max_traffic_clients(4);
        let mut traffic = proxy.traffic.lock().unwrap();
        let (_, packument) = crate::route::classify("/lodash");
        for i in 0..4 + 5 {
            traffic.count(&format!("client{i}/1"), &packument);
        }
        traffic.count("client0/1", &packument);
        assert_eq!(traffic.clients.len(), 4 + 1);
        assert_eq!(traffic.clients["other"].documents, 5);
        assert_eq!(traffic.clients["client0"].documents, 2);
        traffic.count("", &packument);
        assert_eq!(traffic.clients["other"].documents, 6);
    }

    /// Requests through the proxy are counted by client, and a HEAD is not.
    #[tokio::test]
    async fn requests_through_the_proxy_are_counted_by_client() {
        let (upstream, _) = upstream_serving(
            StatusCode::OK,
            "application/vnd.npm.install-v1+json",
            None,
            fixture("lodash-4.17.21.abbrev.json"),
        )
        .await;
        let proxy = Proxy::new(reqwest::Client::new()).with_upstream(Ecosystem::Npm, upstream);
        let base = serve(proxy.clone().router()).await;
        let client = reqwest::Client::new();
        client
            .get(format!("{base}/lodash"))
            .header(header::USER_AGENT, "pnpm/10.0.0")
            .send()
            .await
            .unwrap();
        client
            .head(format!("{base}/lodash"))
            .header(header::USER_AGENT, "yarn/1.22.22")
            .send()
            .await
            .unwrap();
        proxy.report_traffic();
        assert_eq!(
            proxy.health().clients_without_artifacts,
            [("pnpm".to_owned(), 1)].into()
        );
    }

    /// How a version in [`watching`]'s registry publishes its tarball.
    #[derive(Clone)]
    enum Published {
        /// On the registry, with its digest.
        Served(Vec<u8>),
        /// On an origin the proxy does not serve, with its digest.
        Elsewhere(Vec<u8>),
        /// On the registry, with no digest.
        Undigested(Vec<u8>),
    }

    impl Published {
        /// The `integrity` member, the tarball URL and the bytes, for `version`.
        fn written(&self, version: &str) -> (String, String, &[u8]) {
            let (bytes, digested, host) = match self {
                Self::Served(bytes) => (bytes, true, "registry.npmjs.org/widget/-"),
                Self::Elsewhere(bytes) => (bytes, true, "elsewhere.example"),
                Self::Undigested(bytes) => (bytes, false, "registry.npmjs.org/widget/-"),
            };
            let integrity = if digested {
                format!(r#""integrity":"{}","#, sri_of(bytes))
            } else {
                String::new()
            };
            (
                integrity,
                format!("https://{host}/widget-{version}.tgz"),
                bytes,
            )
        }
    }

    /// A registry serving `widget` at the versions in `published`. A proxy with an analyser
    /// holds `widget` 1.0.0 and `gone`, which the registry no longer answers for.
    async fn watching(
        label: &str,
        published: Arc<Mutex<Vec<(&'static str, Published)>>>,
    ) -> (Proxy, Arc<Analyser>) {
        let serving = published.clone();
        let packument = move || {
            let versions: Vec<String> = serving
                .lock()
                .unwrap()
                .iter()
                .map(|(v, published)| {
                    let (integrity, url, _) = published.written(v);
                    format!(r#""{v}":{{"version":"{v}","dist":{{{integrity}"tarball":"{url}"}}}}"#)
                })
                .collect();
            format!(
                r#"{{"name":"widget","versions":{{{}}}}}"#,
                versions.join(",")
            )
        };
        let tarballs = published.clone();
        let tarball = move |file: String| {
            tarballs
                .lock()
                .unwrap()
                .iter()
                .find(|(v, _)| file == format!("widget-{v}.tgz"))
                .map(|(v, published)| published.written(v).2.to_vec())
                .unwrap_or_default()
        };
        let router = Router::new()
            .route(
                "/widget",
                get(move || {
                    let body = packument();
                    async move {
                        (
                            [(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")],
                            body,
                        )
                    }
                }),
            )
            .route(
                "/widget/-/{file}",
                get(
                    move |axum::extract::Path(file): axum::extract::Path<String>| {
                        let bytes = tarball(file);
                        async move { bytes }
                    },
                ),
            );
        let (spool, _) =
            crate::spool::Spool::open(&crate::util::test_support::tempdir(label), 1 << 20)
                .expect("opens");
        let analyser = Arc::new(Analyser::new(
            reqwest::Client::new(),
            Arc::new(spool),
            Arc::new(crate::analysis::store::InProcess::new(8)),
            2,
            8,
        ));
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, serve(router).await)
            .with_analyser(Some(analyser.clone()));
        let first = Published::Served(crate::util::test_support::tarball(&[(
            "package/package.json",
            RUNS_NOTHING,
        )]));
        let (integrity, url, _) = first.written("1.0.0");
        hold_document(
            &proxy,
            format!(r#"{{"name":"widget","versions":{{"1.0.0":{{"version":"1.0.0","dist":{{{integrity}"tarball":"{url}"}}}}}}}}"#)
                .as_bytes(),
            crate::record::DocumentDetail::Abbreviated,
        );
        published.lock().unwrap().push(("1.0.0", first));
        hold_document(
            &proxy,
            br#"{"name":"gone","versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/gone/-/gone-1.0.0.tgz"}}}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );
        (proxy, analyser)
    }

    /// A version published after the proxy read the package is analysed by the next pass.
    /// A held version, analysed bytes, an origin not served and no digest start nothing.
    #[tokio::test]
    async fn the_watcher_analyses_a_new_version_before_a_client_asks() {
        let published = Arc::new(Mutex::new(Vec::new()));
        let (proxy, analyser) = watching("watch", published.clone()).await;
        let second =
            crate::util::test_support::tarball(&[("package/package.json", RUNS_POSTINSTALL)]);
        published
            .lock()
            .unwrap()
            .push(("2.0.0", Published::Served(second.clone())));

        assert_eq!(
            proxy.watch().await,
            Watched {
                packages: 1,
                new_versions: 1,
                started: 1
            },
            "1.0.0 was held, so only 2.0.0 is new, and `gone` is not read"
        );
        analyser.ended(1).await;
        let digest = Sri::parse(&sri_of(&second)).expect("an SRI");
        assert!(
            matches!(analyser.known(&digest).await, Known::Analysed(_)),
            "2.0.0 was analysed before any client asked for it"
        );
        assert_eq!(
            proxy.watch().await.new_versions,
            0,
            "the refreshed document holds 2.0.0"
        );

        let other = |name: &str| {
            crate::util::test_support::tarball(&[(
                "package/package.json",
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#).as_bytes(),
            )])
        };
        {
            let mut published = published.lock().unwrap();
            published.push(("3.0.0", Published::Served(second)));
            published.push(("4.0.0", Published::Elsewhere(other("elsewhere"))));
            published.push(("5.0.0", Published::Undigested(other("undigested"))));
        }
        assert_eq!(
            proxy.watch().await,
            Watched {
                packages: 1,
                new_versions: 3,
                started: 0
            },
            "3.0.0's bytes are 2.0.0's, already analysed; 4.0.0 is on an origin the proxy does \
             not serve; 5.0.0 publishes no digest"
        );

        let unanalysed =
            Proxy::new(reqwest::Client::new()).with_upstream(Ecosystem::Npm, NO_UPSTREAM);
        assert_eq!(
            unanalysed.watch().await,
            Watched::default(),
            "no analyser, no pass"
        );
    }

    /// Each answer `decide_artifact` reaches writes one audit line saying what it was.
    #[tokio::test]
    async fn every_pinned_answer_after_the_lookup_is_audited_once() {
        let dir = crate::util::test_support::tempdir("audit-every-answer");
        let path = dir.join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).expect("opens"));

        let unservable = offline(None, Some(ALLOW_ALL))
            .with_refuse_unservable(true)
            .with_audit_log(Some(log.clone()));
        hold_document(
            &unservable,
            OFFSITE_PACKUMENT.as_bytes(),
            crate::record::DocumentDetail::Abbreviated,
        );
        let (status, _) = refused(pinned(&unservable, "/widget/-/widget-1.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let undigested = offline(None, Some(ALLOW_ALL)).with_audit_log(Some(log.clone()));
        hold_document(
            &undigested,
            br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
                "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );
        let (status, _) = refused(pinned(&undigested, "/widget/-/widget-1.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = refused(pinned(&undigested, "/widget/-/widget-2.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "not listed");
        let unfetchable = offline(None, Some(ALLOW_ALL)).with_audit_log(Some(log.clone()));
        let (status, _) = refused(pinned(&unfetchable, "/gadget/-/gadget-1.0.0.tgz").await).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "no metadata");

        let tarball = crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)]);
        let (base, analyser) = analysing_with(
            "audit-mismatch",
            "",
            &integrity(b"other bytes"),
            tarball,
            Some(ALLOW_ALL),
            Arc::new(crate::analysis::store::InProcess::new(8)),
            Extras {
                audit: Some(log),
                ..Extras::default()
            },
        )
        .await;
        assert_eq!(tarball_request(&base).await.status(), 503);
        analyser.ended(1).await;
        assert_eq!(tarball_request(&base).await.status(), 502);

        let answered: Vec<_> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<audit::Event>(l).unwrap().answered)
            .collect();
        assert_eq!(
            answered,
            [
                Some(audit::Answered::Unservable),
                Some(audit::Answered::NoStrongDigest),
                Some(audit::Answered::NotListed),
                Some(audit::Answered::NoMetadata),
                Some(audit::Answered::Deferred),
                Some(audit::Answered::UpstreamMismatch),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const SOURCE_HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A policy that serves the widget [`sourcing`] publishes.
    const SOURCE_POLICY: &str =
        "version: 1\ncooldown_days: 0\ninstall_scripts: allow\nprovenance: allow\n";

    /// A version the policy blocks is not compared with its source, by a request or the
    /// watcher. One it quarantines is: the quarantine lapses, and then it is served.
    #[tokio::test]
    async fn a_blocked_version_is_not_compared_with_its_source() {
        let blocked =
            format!("{SOURCE_POLICY}denials:\n  - purl: pkg:npm/widget@1.0.0\n    reason: r\n");
        let quarantined = SOURCE_POLICY.replace("cooldown_days: 0", "cooldown_days: 36500");
        for (label, yaml, compared) in [("blocked", &blocked, 0), ("quarantined", &quarantined, 1)]
        {
            let (proxy, analyser, _, packument) = sourcing(&format!("source-{label}"), yaml).await;
            hold_document(
                &proxy,
                packument.to_string().as_bytes(),
                crate::record::DocumentDetail::Full,
            );
            let _ = pinned(&proxy, "/widget/-/widget-1.0.0.tgz").await;
            assert_eq!(
                analyser.sources_started(),
                compared,
                "{label}, by a request"
            );

            let (proxy, analyser, _, _) = sourcing(&format!("source-{label}-watched"), yaml).await;
            hold_document(
                &proxy,
                br#"{"name":"widget","versions":{}}"#,
                crate::record::DocumentDetail::Abbreviated,
            );
            proxy.watch().await;
            assert_eq!(
                analyser.sources_started(),
                compared,
                "{label}, by the watcher"
            );
        }
    }

    /// A registry serving `widget` 1.0.0, whose `postinstall` and `x.js` its source at
    /// [`SOURCE_HEAD`] lacks, and GitHub's archive of that source. Returns the proxy with an
    /// audit log at the returned path, its analyser, and the full packument.
    async fn sourcing(
        label: &str,
        yaml: &str,
    ) -> (Proxy, Arc<Analyser>, std::path::PathBuf, serde_json::Value) {
        let artifact = crate::util::test_support::tarball(&[
            (
                "package/package.json",
                br#"{"name":"widget","version":"1.0.0","scripts":{"postinstall":"node x.js"}}"#,
            ),
            ("package/x.js", b"published"),
        ]);
        let source = crate::util::test_support::tarball(&[
            (
                "r-head/package.json",
                br#"{"name":"widget","version":"1.0.0"}"#,
            ),
            ("r-head/x.js", b"source"),
        ]);
        let packument = serde_json::json!({
            "name": "widget",
            "time": {"1.0.0": "2020-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {
                "name": "widget", "version": "1.0.0", "gitHead": SOURCE_HEAD,
                "repository": {"type": "git", "url": "git+https://github.com/o/r.git"},
                "scripts": {"postinstall": "node x.js"},
                "dist": {
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
                    "integrity": sri_of(&artifact).to_string(),
                },
            }},
        });
        let document = packument.to_string();
        let router = Router::new()
            .route(
                "/widget",
                get(move || {
                    let body = document.clone();
                    async move { body }
                }),
            )
            .route(
                "/widget/-/widget-1.0.0.tgz",
                get(move || {
                    let bytes = artifact.clone();
                    async move { bytes }
                }),
            )
            .route(
                &format!("/o/r/tar.gz/{SOURCE_HEAD}"),
                get(move || {
                    let bytes = source.clone();
                    async move { bytes }
                }),
            );
        let upstream = serve(router).await;
        let (spool, _) =
            crate::spool::Spool::open(&crate::util::test_support::tempdir(label), 1 << 20)
                .expect("opens");
        let analyser = Arc::new(
            Analyser::new(
                reqwest::Client::new(),
                Arc::new(spool),
                Arc::new(crate::analysis::store::InProcess::new(8)),
                2,
                8,
            )
            .with_sources(Some(upstream.clone())),
        );
        let path =
            crate::util::test_support::tempdir(&format!("{label}-audit")).join("audit.jsonl");
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, upstream)
            .with_analyser(Some(analyser.clone()))
            .with_policy(Some(policy(yaml)))
            .with_audit_log(Some(Arc::new(AuditLog::open(&path).expect("opens"))));
        (proxy, analyser, path, packument)
    }

    /// A decision starts the comparison without waiting for it, and a later one reports it,
    /// with the full document held or the abbreviated one, which names no repository.
    #[tokio::test]
    async fn the_source_comparison_is_reported_on_a_later_request() {
        for detail in [
            crate::record::DocumentDetail::Full,
            crate::record::DocumentDetail::Abbreviated,
        ] {
            let (proxy, analyser, path, packument) =
                sourcing(&format!("source-{detail:?}"), SOURCE_POLICY).await;
            let mut held = packument.clone();
            if detail == crate::record::DocumentDetail::Abbreviated {
                held.as_object_mut().unwrap().remove("time");
                let version = &mut held["versions"]["1.0.0"];
                for field in ["gitHead", "repository", "scripts"] {
                    version.as_object_mut().unwrap().remove(field);
                }
            }
            hold_document(&proxy, held.to_string().as_bytes(), detail);

            let _ = pinned(&proxy, "/widget/-/widget-1.0.0.tgz").await;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                analyser.sources_ended(1),
            )
            .await
            .expect("the comparison ends");
            let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
            let _ = pinned(&proxy, "/widget/-/widget-1.0.0.tgz").await;
            drop(guard);
            let log = crate::util::test_support::text(&buf);
            assert!(log.contains("waharoa.risk_score=3"), "{detail:?}: {log}");

            assert_eq!(
                analyser.sources_started(),
                1,
                "{detail:?}: the second decision reads the stored comparison"
            );
            let lines: Vec<audit::Event> = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            let at = format!("source o/r@{SOURCE_HEAD}");
            let sourced: Vec<&String> = lines[1]
                .signals
                .iter()
                .filter(|s| s.starts_with("source "))
                .collect();
            assert!(
                !lines[0].signals.iter().any(|s| s.starts_with("source ")),
                "{detail:?}: not compared yet"
            );
            assert_eq!(
                lines[1].risk_score,
                Some(lines[0].risk_score.unwrap_or(0) + 3),
                "{detail:?}: three source kinds, weight 1 each"
            );
            assert_eq!(
                sourced,
                [
                    &format!("{at}: install scripts it lacks or has otherwise: postinstall"),
                    &format!("{at}: install files it lacks or has otherwise: x.js"),
                    &format!("{at}: 1 file differs from it: `x.js`"),
                ],
                "{detail:?}"
            );
        }
    }

    /// The watcher starts the comparison for a version no client has asked for.
    #[tokio::test]
    async fn the_watcher_starts_the_source_comparison() {
        let (proxy, analyser, _, packument) = sourcing("source-watched", SOURCE_POLICY).await;
        hold_document(
            &proxy,
            br#"{"name":"widget","versions":{}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );
        proxy.watch().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            analyser.sources_ended(1),
        )
        .await
        .expect("the comparison ends");
        let integrity = packument["versions"]["1.0.0"]["dist"]["integrity"]
            .as_str()
            .unwrap();
        assert!(matches!(
            analyser.sourced(&Sri::parse(integrity).unwrap()).await,
            Some(crate::analysis::source::Sourced::Compared { .. })
        ));

        hold_document(
            &proxy,
            br#"{"name":"widget","versions":{}}"#,
            crate::record::DocumentDetail::Abbreviated,
        );
        proxy.watch().await;
        assert_eq!(
            analyser.sources_started(),
            1,
            "compared once, then read back"
        );
    }

    /// One full packument request serves the heuristics and a cooldown, a held full one
    /// asks nothing, and records that do not normalise leave the heuristics the held one.
    #[tokio::test]
    async fn the_signals_read_the_full_packument() {
        use crate::record::DocumentDetail::{Abbreviated, Full};
        let published =
            (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24 * 2)).to_string();
        let full = serde_json::json!({
            "name": "pkg",
            "time": {"1.0.0": published},
            "versions": {"1.0.0": {"name": "pkg", "version": "1.0.0", "dist": {
                "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                "integrity": "sha512-AAAA"}}},
        });
        let mut abbreviated = full.clone();
        abbreviated.as_object_mut().unwrap().remove("time");
        let mut unnamed = full.clone();
        unnamed["name"] = "".into();
        let signals = vec![
            "new package: first published 2 days ago".to_owned(),
            "no repository: the metadata names none".to_owned(),
        ];
        let one = || vec![Some(HeaderValue::from_static(npm::FULL_ACCEPT))];
        let (off, cooldown) = (
            "version: 1\ncooldown_days: 0\n",
            "version: 1\ncooldown_days: 7\n",
        );
        let cases = [
            (
                &abbreviated,
                Abbreviated,
                &full,
                off,
                "allow",
                &signals,
                one(),
            ),
            (
                &abbreviated,
                Abbreviated,
                &full,
                cooldown,
                "quarantine",
                &signals,
                one(),
            ),
            (&full, Full, &full, cooldown, "quarantine", &signals, vec![]),
            (
                &abbreviated,
                Abbreviated,
                &unnamed,
                cooldown,
                "quarantine",
                &vec![],
                one(),
            ),
        ];
        for (held, detail, served, yaml, action, expected, asked) in cases {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorder = requests.clone();
            let body = served.to_string();
            let router = Router::new().fallback(any(move |req: Request| {
                recorder
                    .lock()
                    .unwrap()
                    .push(req.headers().get(header::ACCEPT).cloned());
                let body = body.clone();
                async move { body }
            }));
            let dir = crate::util::test_support::tempdir("signals-full");
            let path = dir.join("audit.jsonl");
            let proxy = Proxy::new(reqwest::Client::new())
                .with_upstream(Ecosystem::Npm, serve(router).await)
                .with_policy(Some(policy(yaml)))
                .with_audit_log(Some(Arc::new(AuditLog::open(&path).expect("opens"))));
            hold_document(&proxy, held.to_string().as_bytes(), detail);
            let _ = pinned(&proxy, "/pkg/-/pkg-1.0.0.tgz").await;

            let line: audit::Event =
                serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
            assert_eq!(line.action, action, "{yaml}");
            assert_eq!(&line.signals, expected, "{yaml}");
            let accepts = requests.lock().unwrap().clone();
            assert_eq!(accepts, asked, "one full packument serves both: {yaml}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A pinned line says what the request was answered, written once that is known: a
    /// request deferred for its analysis is not recorded as served.
    #[tokio::test]
    async fn the_audit_line_records_what_the_request_was_answered() {
        let dir = crate::util::test_support::tempdir("audit-answered");
        let path = dir.join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).expect("opens"));
        let lines = |path: &std::path::Path| -> Vec<audit::Event> {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };

        let (proxy, _) =
            provenance_proxy("audit-deferred", PROVENANCE, &["1.0.0", "2.0.0"], &[]).await;
        let proxy = proxy.with_audit_log(Some(log.clone()));
        let (status, _) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (proxy, _) = provenance_proxy(
            "audit-refused",
            PROVENANCE,
            &["1.0.0", "2.0.0"],
            &[("1.0.0", verified("a")), ("2.0.0", verified("b"))],
        )
        .await;
        let proxy = proxy.with_audit_log(Some(log.clone()));
        let (status, _) = refused(pinned(&proxy, WIDGET_2).await).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (proxy, _) = provenance_proxy(
            "audit-served",
            PROVENANCE,
            &["1.0.0", "2.0.0"],
            &[("1.0.0", verified("a")), ("2.0.0", verified("a"))],
        )
        .await;
        let proxy = proxy.with_audit_log(Some(log));
        assert!(fetched(&pinned(&proxy, WIDGET_2).await));

        let answered: Vec<_> = lines(&path)
            .iter()
            .map(|e| (e.action.clone(), e.answered))
            .collect();
        assert_eq!(
            answered,
            [
                ("allow".to_owned(), Some(audit::Answered::Deferred)),
                ("block".to_owned(), Some(audit::Answered::Refused)),
                ("allow".to_owned(), Some(audit::Answered::Served)),
            ]
        );
        for event in lines(&path) {
            assert_eq!(
                event.signals,
                [crate::heuristics::Signal::NoRepository.to_string()],
                "widget's document names no repository"
            );
        }
        let replayed = audit::replay(
            &std::fs::read_to_string(&path).unwrap(),
            &[Policy::parse(PROVENANCE).unwrap()],
        );
        assert_eq!(
            replayed,
            audit::Replay {
                reproduced: 3,
                ..audit::Replay::default()
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty chunk is skipped, an error from the upstream ends the body with that error,
    /// and a finished body stays finished.
    #[tokio::test]
    async fn a_verifying_stream_skips_empty_chunks_and_ends_on_an_error() {
        use futures_util::StreamExt as _;
        let closed = crate::util::test_support::closing_server().await;
        let failed = reqwest::get(format!("http://{closed}"))
            .await
            .expect_err("nothing answers");
        let body: ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok(Bytes::from_static(b"a")),
            Ok(Bytes::new()),
            Err(failed),
        ]));
        let sri = Sri::parse(&sri_of(b"a")).expect("an SRI");
        let mut stream = VerifyingStream::new(
            body,
            &sri,
            "/a".to_owned(),
            "pkg:npm/a@1.0.0".to_owned(),
            Arc::new(Mutex::new(VerifiedArtifacts::new(8))),
        );
        assert!(matches!(stream.next().await, Some(Err(_))));
        assert!(stream.next().await.is_none());
    }

    /// The base a rewritten URL points at comes from a `Host` that can be read, and is
    /// nothing without one.
    #[test]
    fn a_host_that_cannot_be_read_gives_no_base() {
        let mut headers = HeaderMap::new();
        assert_eq!(public_base(&headers, None), None, "no Host");
        headers.insert(header::HOST, HeaderValue::from_static(" "));
        assert_eq!(public_base(&headers, None), None, "an empty Host");
        headers.insert(
            header::HOST,
            HeaderValue::from_bytes(b"h\xffst").expect("obs-text"),
        );
        assert_eq!(public_base(&headers, None), None, "not visible ASCII");
    }

    /// A prior whose attestations are published where the proxy will not go, or which has no strong
    /// digest, cannot be compared with, so the version is served.
    #[tokio::test]
    async fn an_attestation_that_cannot_be_verified_counts_as_not_verifying() {
        let edit = |label: &str, change: &dyn Fn(&mut serde_json::Value)| {
            let mut doc: serde_json::Value =
                serde_json::from_str(&widget_versions(&["1.0.0", "2.0.0"])).expect("json");
            change(&mut doc);
            (label.to_owned(), doc.to_string())
        };
        let served = "fetch digest=true";
        let refused = "403 Forbidden waharoa: pkg:npm/widget@2.0.0 is blocked by policy\n  - \
                       provenance: an attestation failed verification: it publishes no strong \
                       digest to verify against\n";
        let cases = [
            edit("provenance-prior-elsewhere", &|doc| {
                doc["versions"]["1.0.0"]["dist"]["attestations"]["url"] =
                    serde_json::json!("https://elsewhere.example/attestations/widget@1.0.0");
            }),
            edit("provenance-prior-no-digest", &|doc| {
                doc["versions"]["1.0.0"]["dist"]
                    .as_object_mut()
                    .expect("an object")
                    .remove("integrity");
            }),
            edit("provenance-this-no-digest", &|doc| {
                doc["versions"]["2.0.0"]["dist"]
                    .as_object_mut()
                    .expect("an object")
                    .remove("integrity");
            }),
        ];
        for ((label, packument), expected) in cases.into_iter().zip([served, served, refused]) {
            let (proxy, analyser) = provenance_proxy(
                &label,
                PROVENANCE,
                &[],
                &[("1.0.0", verified("a")), ("2.0.0", verified("a"))],
            )
            .await;
            hold_document(
                &proxy,
                packument.as_bytes(),
                crate::record::DocumentDetail::Full,
            );
            let step = pinned(&proxy, WIDGET_2).await;
            let outcome = match step {
                ArtifactStep::Answer(response) => {
                    let (status, body) = read(response).await;
                    format!("{status} {body}")
                }
                ArtifactStep::Fetch(fetch) => format!("fetch digest={}", fetch.digest.is_some()),
            };
            assert_eq!(outcome, expected, "{label}");
            assert_eq!(analyser.in_flight(), 0, "{label}: nothing to fetch");
        }
    }

    /// With a store, each audit line names the snapshot it was decided with.
    #[tokio::test]
    async fn an_audit_line_names_the_snapshot() {
        let path = crate::util::test_support::tempdir("proxy-audit-snapshot").join("audit.jsonl");
        let log = Arc::new(AuditLog::open(&path).expect("should open"));
        let proxy = offline(
            Some(Arc::new(crate::intel::store::testing::knowing_nothing())),
            Some(DENY_LODASH),
        )
        .with_audit_log(Some(log));
        resolved(&proxy, "lodash", LODASH).await;
        pinned(&proxy, LODASH_TARBALL).await;
        let written = std::fs::read_to_string(&path).expect("should read");
        let events: Vec<serde_json::Value> = written
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is one object"))
            .collect();
        assert_eq!(events.len(), 2, "{written}");
        for event in &events {
            assert_eq!(event["intel_snapshot"], "s1", "{event}");
        }
    }

    /// A store that answers for a package and then cannot say its snapshot is not ready.
    #[tokio::test]
    async fn a_snapshot_that_cannot_be_read_is_not_ready() {
        use crate::intel::store::testing::Unsnapshotted;
        let proxy = offline(Some(Arc::new(Unsnapshotted)), Some(ALLOW_ALL));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        assert!(intel_for(&proxy, &key, "/lodash").await.is_err());
    }

    /// With no `Host` and no public base, a document the proxy would read is uninspected
    /// for that reason.
    #[test]
    fn a_document_with_no_address_to_point_at_is_uninspected() {
        let proxy = offline(None, None);
        let mut negotiation = negotiated(None, Method::GET, "/lodash", "gzip");
        negotiation.rewrite_base = None;
        negotiation.rewriting = false;
        let (_, target) = crate::route::classify("/lodash");
        let log = logged(|| {
            report_uninspected(
                &proxy,
                &target,
                &Method::GET,
                &negotiation,
                &HeaderMap::new(),
                "/lodash",
            )
        });
        assert!(
            log.contains("no Host header and no configured public base"),
            "{log}"
        );
    }

    /// A PyPI index that reads but does not normalise is forwarded with nothing filtered,
    /// under a cooldown too.
    #[tokio::test]
    async fn an_index_that_does_not_normalise_is_forwarded() {
        let nameless =
            br#"{"meta":{"api-version":"1.1"},"name":"","files":[{"filename":"x-1.0.tar.gz",
            "url":"https://files.pythonhosted.org/packages/aa/bb/x-1.0.tar.gz","hashes":{}}]}"#;
        for yaml in [None, Some("version: 1\ncooldown_days: 3\n")] {
            let proxy = offline(None, yaml);
            let step = resolve(&proxy, "/simple/x/", pypi::SIMPLE_JSON, nameless).await;
            assert!(
                matches!(&step, DocumentStep::Forward { refused, .. } if refused.versions.is_empty()),
                "{yaml:?}"
            );
        }
    }

    /// A claimed version that makes no purl is named as written.
    #[tokio::test]
    async fn a_claimed_version_that_makes_no_purl_is_named_as_written() {
        let proxy = offline(None, None);
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let deciding = Deciding::new(
            &proxy,
            ArtifactRequest {
                ecosystem: Ecosystem::Npm,
                method: &Method::GET,
                key: &key,
                claimed_version: " ",
                filename: "lodash-.tgz",
                path: "/lodash/-/lodash-.tgz",
                client: "-",
            },
        );
        assert_eq!(deciding.purl, "pkg:npm/lodash@ ");
    }

    /// A file host that cannot be asked gives no publish time.
    #[tokio::test]
    async fn a_file_host_that_cannot_be_asked_gives_no_date() {
        let proxy = offline(None, None);
        let closed = crate::util::test_support::closing_server().await;
        assert_eq!(
            head_last_modified(&proxy, &format!("http://{closed}/x.tar.gz"), "/x").await,
            None
        );
    }

    /// Metadata fetched on the proxy's own behalf that does not read leaves nothing to find.
    #[tokio::test]
    async fn metadata_fetched_that_does_not_read_is_logged() {
        use crate::util::test_support::{Answer, scripted};
        let upstream = scripted(vec![Answer::body("not json")]).await;
        let proxy = Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, format!("http://{upstream}"))
            .with_policy(Some(policy(ALLOW_ALL)));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let (guard, buf) = capture(tracing::Level::WARN);
        fetch_and_store(&proxy, &key, "/lodash/-/lodash-4.17.21.tgz").await;
        drop(guard);
        let log = text(&buf);
        assert!(
            log.contains("metadata fetched but did not normalize"),
            "{log}"
        );
    }
}
