//! Analysing an artifact in the background, so no request waits for it: fetch it, spool
//! it, check its digest, read it, and store what was read under the digest.
//!
//! See `docs/engineering_decisions/artifact-spool.md`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sigstore_verify::types::Bundle;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::analysis::Reader;
use crate::analysis::attestation::{Attested, verify};
use crate::analysis::store::{Analyses, Analysis, Scripts};
use crate::integrity::{Mismatch, Sri};
use crate::spool::{Spool, Spooled, WriteError};
use crate::util::lru::Lru;

/// How long one job may take, from its fetch starting to its analysis being stored.
pub const DEADLINE: Duration = Duration::from_secs(600);

/// What is known about the artifact with a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known {
    /// An analysis is stored.
    Analysed(Analysis),
    /// The upstream served bytes that do not match the digest, on this process's last fetch.
    Mismatched(Mismatch),
    /// Neither, including when the analysis store cannot answer.
    Unknown,
}

/// One artifact to analyse.
#[derive(Debug, Clone)]
pub struct Job {
    /// The digest the metadata published. The analysis is stored under it.
    pub digest: Sri,
    /// Where the proxy fetches the artifact from, as it would for the client.
    pub url: String,
    /// What reads the artifact for install scripts. `None` when only attestations are missing.
    pub reader: Option<Reader>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Attestations to verify: this artifact's and the previous version's.
    pub attestations: Vec<Attestation>,
}

/// One artifact's attestations to verify.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The digest the metadata published for the artifact. The result is stored under it.
    pub digest: Sri,
    /// Where the registry serves the attestations document.
    pub url: String,
    /// The adapter's reader for that document, such as npm's `attestation::provenance_bundle`.
    pub bundle: fn(&[u8]) -> Result<Bundle, String>,
}

/// Runs analyses in the background, one per digest at a time.
#[derive(Clone)]
pub struct Analyser {
    client: reqwest::Client,
    spool: Arc<Spool>,
    store: Arc<dyn Analyses>,
    /// Bounds how many analyses run at once. A job waits for a slot; a request never does.
    slots: Arc<Semaphore>,
    /// The digests being analysed now, so each has one job at a time.
    in_flight: Arc<Mutex<HashSet<Sri>>>,
    /// The digests whose last fetch did not match, bounded by count, in this process only.
    mismatched: Arc<Mutex<Lru<Sri, Mismatch>>>,
    /// How many jobs have ended, however they ended. What a test waits on.
    ended: Arc<watch::Sender<u64>>,
    /// [`DEADLINE`], unless a test shortens it.
    deadline: Duration,
}

impl Analyser {
    pub fn new(
        client: reqwest::Client,
        spool: Arc<Spool>,
        store: Arc<dyn Analyses>,
        max_concurrent: usize,
        max_mismatches: usize,
    ) -> Self {
        Self {
            client,
            spool,
            store,
            slots: Arc::new(Semaphore::new(max_concurrent.max(1))),
            in_flight: Arc::default(),
            mismatched: Arc::new(Mutex::new(Lru::new(max_mismatches))),
            ended: Arc::new(watch::Sender::new(0)),
            deadline: DEADLINE,
        }
    }

    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// What is known about `digest`.
    pub async fn known(&self, digest: &Sri) -> Known {
        let mismatch = self
            .mismatched
            .lock()
            .expect("mismatch lock")
            .get(digest)
            .cloned();
        if let Some(mismatch) = mismatch {
            return Known::Mismatched(mismatch);
        }
        match self.store.get(digest).await {
            Ok(Some(analysis)) => Known::Analysed(analysis),
            Ok(None) => Known::Unknown,
            Err(e) => {
                warn!(waharoa.artifact.digest = %digest, error.message = %e, "analysis store cannot answer; analysing again");
                Known::Unknown
            }
        }
    }

    /// How many digests are being analysed now.
    pub fn in_flight(&self) -> usize {
        self.in_flight.lock().expect("in-flight lock").len()
    }

    /// What verifying the attestations of the artifact with `digest` found. A store that
    /// cannot answer is `None`, and they are verified again.
    pub async fn attested(&self, digest: &Sri) -> Option<Attested> {
        match self.store.attested(digest).await {
            Ok(attested) => attested,
            Err(e) => {
                warn!(waharoa.artifact.digest = %digest, error.message = %e, "analysis store cannot answer; verifying again");
                None
            }
        }
    }

    /// Wait until `count` jobs have ended since this analyser was made.
    pub async fn ended(&self, count: u64) {
        let _ = self
            .ended
            .subscribe()
            .wait_for(|ended| *ended >= count)
            .await;
    }

    /// Start analysing `job` unless its digest is already being analysed. The handle is
    /// for a test to wait on. The proxy drops it.
    pub fn start(&self, job: Job) -> Option<JoinHandle<Timings>> {
        if !self
            .in_flight
            .lock()
            .expect("in-flight lock")
            .insert(job.digest.clone())
        {
            return None;
        }
        let guard = InFlight {
            set: self.in_flight.clone(),
            digest: job.digest.clone(),
            ended: self.ended.clone(),
        };
        let analyser = self.clone();
        let started = Instant::now();
        Some(tokio::spawn(async move {
            let _guard = guard;
            analyser.run(job, started).await
        }))
    }

    /// Analyse `job` once a slot is free, within the deadline, and log how long each
    /// phase took. `started` is when the job was asked for.
    /// Returns the times it logged.
    async fn run(&self, job: Job, started: Instant) -> Timings {
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let mut timings = Timings {
            queued_ms: ms(started),
            ..Timings::default()
        };
        let running = Instant::now();
        let work = async {
            if let Some(reader) = job.reader {
                self.analyse(&job, reader, &mut timings).await;
            }
            for attestation in &job.attestations {
                timings.attest_ms += self.attest(attestation).await;
            }
        };
        timings.completed = tokio::time::timeout(self.deadline, work).await.is_ok();
        timings.attestations = job.attestations.len();
        timings.total_ms = ms(running);
        if !timings.completed {
            warn!(url.full = %job.url, waharoa.analysis.deadline_s = self.deadline.as_secs(), "artifact analysis: past its deadline, nothing stored");
        }
        info!(
            url.full = %job.url,
            waharoa.artifact.digest = %job.digest,
            waharoa.analysis.completed = timings.completed,
            waharoa.analysis.queued_ms = timings.queued_ms,
            waharoa.analysis.fetch_ms = timings.fetch_ms,
            waharoa.analysis.download_ms = timings.download_ms,
            waharoa.analysis.bytes = timings.bytes,
            waharoa.analysis.read_ms = timings.read_ms,
            waharoa.analysis.store_ms = timings.store_ms,
            waharoa.analysis.attestations = timings.attestations,
            waharoa.analysis.attest_ms = timings.attest_ms,
            waharoa.analysis.total_ms = timings.total_ms,
            "analysis job timed"
        );
        timings
    }

    /// Fetch the attestations document and verify it. A registry that cannot be reached,
    /// or answers 5xx or 429, stores nothing, so the next request tries again: a flaky
    /// registry must not refuse a package. Any other answer is stored, a failure included.
    /// Returns the milliseconds it took.
    async fn attest(&self, attestation: &Attestation) -> u64 {
        let started = Instant::now();
        let Some(answer) = self.attestation_document(attestation).await else {
            return ms(started);
        };
        let fetch_ms = ms(started);
        let verifying = Instant::now();
        let attested = match answer {
            Ok(document) => match (attestation.bundle)(&document) {
                Ok(bundle) => verify(&bundle, &attestation.digest),
                Err(why) => Attested::Failed { why },
            },
            Err(failed) => failed,
        };
        log_attested(attestation, &attested, fetch_ms, ms(verifying));
        if let Err(e) = self
            .store
            .put_attested(&attestation.digest, &attested)
            .await
        {
            warn!(url.full = %attestation.url, error.message = %e, "attestations: not stored");
        }
        ms(started)
    }

    /// The attestations document, or the failure a registry's 4xx answer is.
    /// Returns `None` when nothing should be stored: no answer, a 5xx or a 429, or a body
    /// that failed.
    async fn attestation_document(
        &self,
        attestation: &Attestation,
    ) -> Option<Result<bytes::Bytes, Attested>> {
        let url = &attestation.url;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(
                |e| warn!(url.full = %url, error.message = %e, "attestations: fetch failed, nothing stored"),
            )
            .ok()?;
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!(url.full = %url, http.response.status_code = status.as_u16(), "attestations: not answered, nothing stored");
            return None;
        }
        if !status.is_success() {
            return Some(Err(Attested::Failed {
                why: format!("the registry answered {status} for {url}"),
            }));
        }
        let document = response
            .bytes()
            .await
            .map_err(|e| warn!(url.full = %url, error.message = %e, "attestations: body failed, nothing stored"))
            .ok()?;
        Some(Ok(document))
    }

    /// Fetch, spool, read and store `job`'s artifact, adding each phase to `timings`.
    async fn analyse(&self, job: &Job, reader: Reader, timings: &mut Timings) {
        let phase = Instant::now();
        let Some(response) = self.fetch(job).await else {
            return;
        };
        timings.fetch_ms = ms(phase);
        let Some(scripts) = self.scripts(job, response, reader, timings).await else {
            return;
        };
        let phase = Instant::now();
        self.put(job, scripts).await;
        timings.store_ms = ms(phase);
    }

    /// What `reader` finds in `response`'s body, spooled and checked against the digest, or
    /// `Unreadable` for one over the spool's ceiling. `None` when nothing should be stored:
    /// a mismatch, a spool that failed, or a spooled file that could not be read.
    async fn scripts(
        &self,
        job: &Job,
        response: reqwest::Response,
        reader: Reader,
        timings: &mut Timings,
    ) -> Option<Scripts> {
        let phase = Instant::now();
        let spooled = self.spool_verified(job, response).await;
        timings.download_ms = ms(phase);
        match spooled? {
            Err(unreadable) => Some(unreadable),
            Ok(spooled) => {
                timings.bytes = spooled.len();
                let phase = Instant::now();
                let read = read(job, spooled, reader).await;
                timings.read_ms = ms(phase);
                read
            }
        }
    }

    /// The upstream's 2xx answer for `job`'s artifact. `None` when there is none.
    async fn fetch(&self, job: &Job) -> Option<reqwest::Response> {
        match self
            .client
            .get(&job.url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(response) => Some(response),
            Err(e) => {
                warn!(url.full = %job.url, error.message = %e, "artifact analysis: fetch failed, nothing stored");
                None
            }
        }
    }

    /// The artifact written to the spool and checked against the digest, or `Unreadable`
    /// for one over the spool's ceiling.
    /// Returns `None` when nothing should be stored: a mismatch, remembered, or a spool
    /// that failed.
    async fn spool_verified(
        &self,
        job: &Job,
        response: reqwest::Response,
    ) -> Option<Result<Spooled, Scripts>> {
        let claimed = response.content_length();
        let mut verifier = job.digest.verifier();
        let written = self
            .spool
            .write(response.bytes_stream(), claimed, |chunk| {
                verifier.update(chunk)
            })
            .await;
        match written {
            Ok(spooled) => match verifier.finish(spooled.len()) {
                Ok(()) => Some(Ok(spooled)),
                Err(mismatch) => {
                    warn!(url.full = %job.url, waharoa.artifact.digest_mismatch = %mismatch, "artifact analysis: digest mismatch");
                    self.mismatched
                        .lock()
                        .expect("mismatch lock")
                        .insert(job.digest.clone(), mismatch);
                    None
                }
            },
            Err(too_large @ WriteError::TooLarge { .. }) => {
                warn!(url.full = %job.url, error.message = %too_large, "artifact analysis: over the ceiling");
                Some(Err(Scripts::Unreadable(too_large.to_string())))
            }
            Err(e) => {
                warn!(url.full = %job.url, error.message = %e, "artifact analysis: not spooled, nothing stored");
                None
            }
        }
    }

    /// Store what was read of `job`'s artifact under its digest.
    async fn put(&self, job: &Job, scripts: Scripts) {
        let analysis = Analysis {
            ecosystem: job.ecosystem.clone(),
            name: job.name.clone(),
            version: job.version.clone(),
            scripts,
        };
        if let Err(e) = self.store.put(&job.digest, &analysis).await {
            warn!(url.full = %job.url, error.message = %e, "artifact analysis: not stored");
            return;
        }
        info!(
            url.full = %job.url,
            waharoa.artifact.digest = %job.digest,
            waharoa.artifact.scripts = ?analysis.scripts.names(),
            "artifact analysed"
        );
    }
}

/// Log an attestation's result with how long fetching and verifying it took.
fn log_attested(attestation: &Attestation, attested: &Attested, fetch_ms: u64, verify_ms: u64) {
    let (url, digest) = (&attestation.url, &attestation.digest);
    match attested {
        Attested::Verified { identity } => {
            info!(url.full = %url, waharoa.artifact.digest = %digest, waharoa.attestation.identity = %identity, waharoa.attestation.fetch_ms = fetch_ms, waharoa.attestation.verify_ms = verify_ms, "attestation verified");
        }
        Attested::Failed { why } => {
            warn!(url.full = %url, waharoa.artifact.digest = %digest, waharoa.reason = %why, waharoa.attestation.fetch_ms = fetch_ms, waharoa.attestation.verify_ms = verify_ms, "attestation did not verify");
        }
    }
}

/// What `reader` reads from the spooled artifact. `None` when the file cannot be read.
async fn read(job: &Job, spooled: Spooled, reader: Reader) -> Option<Scripts> {
    let read = tokio::task::spawn_blocking(move || {
        let file = spooled.reader()?;
        Ok(Scripts::of(reader.read(&mut std::io::BufReader::new(file))))
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|read: std::io::Result<Scripts>| read);
    match read {
        Ok(scripts) => Some(scripts),
        Err(e) => {
            warn!(url.full = %job.url, error.message = %e, "artifact analysis: the spool file could not be read, nothing stored");
            None
        }
    }
}

/// How long each phase of one job took, as its `analysis job timed` line logs it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Timings {
    /// Whether the job ended before its deadline.
    pub completed: bool,
    /// From the job being asked for to a slot being free.
    pub queued_ms: u64,
    /// To the upstream's response headers.
    pub fetch_ms: u64,
    /// Writing the body to the spool, hashing it as it arrives.
    pub download_ms: u64,
    pub bytes: u64,
    pub read_ms: u64,
    pub store_ms: u64,
    /// Every attestation: fetching, verifying and storing it.
    pub attest_ms: u64,
    pub attestations: usize,
    /// From the slot being free to the job ending.
    pub total_ms: u64,
}

/// Milliseconds since `since`.
fn ms(since: Instant) -> u64 {
    since.elapsed().as_millis() as u64
}

/// Takes a digest out of the in-flight set when its job ends, however it ends.
struct InFlight {
    set: Arc<Mutex<HashSet<Sri>>>,
    digest: Sri,
    ended: Arc<watch::Sender<u64>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let _ = self.set.lock().map(|mut set| set.remove(&self.digest));
        self.ended.send_modify(|ended| *ended += 1);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::attestation::Attested;
    use crate::analysis::store::{AnalysisError, InProcess, Stored};
    use crate::util::test_support::tarball;
    use crate::util::test_support::tempdir;
    use axum::Router;
    use axum::routing::get;

    const POSTINSTALL: &[u8] =
        br#"{"name":"widget","version":"1.0.0","scripts":{"postinstall":"node x.js"}}"#;

    fn sri_of(data: &[u8]) -> Sri {
        use base64::Engine as _;
        use sha2::{Digest, Sha512};
        let encoded = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data));
        Sri::parse(&format!("sha512-{encoded}")).expect("parses")
    }

    /// An upstream answering every path with `status` and `body`.
    async fn upstream(status: u16, body: Vec<u8>) -> String {
        let router = Router::new().fallback(get(move || {
            let body = body.clone();
            async move {
                (
                    axum::http::StatusCode::from_u16(status).expect("a status"),
                    body,
                )
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, router).into_future());
        format!("http://{addr}/widget/-/widget-1.0.0.tgz")
    }

    fn analyser(label: &str, ceiling: u64, store: Arc<dyn Analyses>) -> Analyser {
        let (spool, _) = Spool::open(&tempdir(label), ceiling).expect("opens");
        Analyser::new(reqwest::Client::new(), Arc::new(spool), store, 2, 16)
    }

    fn job(digest: &Sri, url: &str) -> Job {
        Job {
            digest: digest.clone(),
            url: url.to_owned(),
            reader: Some(Reader::NpmTarball),
            ecosystem: "npm".to_owned(),
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
            attestations: Vec::new(),
        }
    }

    fn spool_files(analyser: &Analyser) -> usize {
        std::fs::read_dir(analyser.spool.dir())
            .expect("reads")
            .filter(|e| e.as_ref().expect("entry").file_name() != ".lock")
            .count()
    }

    #[tokio::test]
    async fn an_artifact_is_fetched_read_and_its_analysis_stored() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let url = upstream(200, tarball).await;
        let analyser = analyser("run-stored", 1 << 20, Arc::new(InProcess::new(8)));
        assert_eq!(analyser.known(&digest).await, Known::Unknown);

        analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");
        let Known::Analysed(analysis) = analyser.known(&digest).await else {
            panic!("the analysis is stored");
        };
        assert_eq!(
            analysis.scripts.names(),
            Some(&["postinstall".to_owned()][..])
        );
        assert_eq!(
            (analysis.name.as_str(), analysis.version.as_str()),
            ("widget", "1.0.0")
        );
        assert_eq!(spool_files(&analyser), 0, "the spool file is deleted");
    }

    /// A job returns how long each phase took, as it logs them.
    #[tokio::test]
    async fn a_job_logs_how_long_each_phase_took() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let size = tarball.len();
        let url = upstream(200, tarball).await;
        let analyser = analyser("run-timed", 1 << 20, Arc::new(InProcess::new(8)));
        let timings = analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");

        assert!(timings.completed);
        assert_eq!(timings.bytes, size as u64);
        assert_eq!((timings.attestations, timings.attest_ms), (0, 0));
        let phases = timings.fetch_ms + timings.download_ms + timings.read_ms + timings.store_ms;
        assert!(phases <= timings.total_ms + 4, "{timings:?}");
    }

    /// A retry arriving while the first job runs starts nothing. Once the job ends, the
    /// digest can be analysed again.
    #[tokio::test]
    async fn one_digest_is_analysed_once_at_a_time() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let url = upstream(200, tarball).await;
        let analyser = analyser("run-once", 1 << 20, Arc::new(InProcess::new(8)));
        assert!(analyser.start(job(&digest, &url)).is_some());
        assert!(analyser.start(job(&digest, &url)).is_none());
        assert_eq!(analyser.in_flight(), 1);
        analyser.ended(1).await;
        assert_eq!(analyser.in_flight(), 0);
        assert!(analyser.start(job(&digest, &url)).is_some());
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_the_digest_are_remembered_and_not_stored() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(b"other bytes");
        let url = upstream(200, tarball).await;
        let store = Arc::new(InProcess::new(8));
        let analyser = analyser("run-mismatch", 1 << 20, store.clone());
        analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");
        assert!(matches!(
            analyser.known(&digest).await,
            Known::Mismatched(_)
        ));
        assert!(store.is_empty());
        assert_eq!(spool_files(&analyser), 0);
    }

    /// Stored as unreadable, so the retry is decided rather than deferred forever.
    #[tokio::test]
    async fn an_artifact_over_the_ceiling_is_stored_as_unreadable() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let url = upstream(200, tarball).await;
        let analyser = analyser("run-ceiling", 16, Arc::new(InProcess::new(8)));
        analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");
        let Known::Analysed(analysis) = analyser.known(&digest).await else {
            panic!("the analysis is stored");
        };
        assert!(
            matches!(&analysis.scripts, Scripts::Unreadable(why) if why.contains("16-byte ceiling")),
            "{:?}",
            analysis.scripts
        );
    }

    /// A failed fetch and a spool that cannot be written store nothing, so the next
    /// request starts another job.
    #[tokio::test]
    async fn a_failed_fetch_or_spool_stores_nothing() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let store = Arc::new(InProcess::new(8));

        let missing = upstream(404, Vec::new()).await;
        let analyser = analyser("run-404", 1 << 20, store.clone());
        analyser
            .start(job(&digest, &missing))
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.known(&digest).await, Known::Unknown);

        let url = upstream(200, tarball).await;
        std::fs::remove_dir_all(analyser.spool.dir()).expect("removes");
        analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");
        assert!(store.is_empty());
    }

    /// An upstream that accepts the connection and never answers. The job ends at its
    /// deadline, stores nothing, and releases the digest for the next request.
    #[tokio::test]
    async fn a_job_past_its_deadline_ends_and_stores_nothing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let digest = sri_of(b"never sent");
        let analyser = analyser("run-deadline", 1 << 20, Arc::new(InProcess::new(8)))
            .with_deadline(Duration::from_millis(100));
        analyser
            .start(job(&digest, &format!("http://{addr}/widget.tgz")))
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.known(&digest).await, Known::Unknown);
        assert_eq!(analyser.in_flight(), 0);
    }

    /// The attestations document at each path, with its status.
    async fn registry(routes: Vec<(&'static str, u16, Vec<u8>)>) -> String {
        let mut router = Router::new();
        for (path, status, body) in routes {
            router = router.route(
                path,
                get(move || {
                    let body = body.clone();
                    async move {
                        (
                            axum::http::StatusCode::from_u16(status).expect("a status"),
                            body,
                        )
                    }
                }),
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, router).into_future());
        format!("http://{addr}")
    }

    /// Each phase that takes time is timed: an upstream that answers 150 ms late, an
    /// attestations document 100 ms late, and a second job waiting for the only slot.
    #[tokio::test]
    async fn each_phase_is_timed() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let late = |millis: u64, status: u16, body: Vec<u8>| {
            get(move || {
                let body = body.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(millis)).await;
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            })
        };
        let router = Router::new()
            .route("/artifact", late(150, 200, tarball.clone()))
            .route("/attestations", late(100, 404, Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, router).into_future());
        let (spool, _) = Spool::open(&tempdir("run-phases"), 1 << 20).expect("opens");
        let one_slot = Analyser::new(
            reqwest::Client::new(),
            Arc::new(spool),
            Arc::new(InProcess::new(8)),
            1,
            16,
        );
        let digest = sri_of(&tarball);
        let first = Job {
            attestations: vec![Attestation {
                digest: digest.clone(),
                url: format!("{base}/attestations"),
                bundle: crate::ecosystem::npm::attestation::provenance_bundle,
            }],
            ..job(&digest, &format!("{base}/artifact"))
        };
        let second = job(
            &crate::analysis::store::tests::sri(9),
            &format!("{base}/artifact"),
        );

        let first = one_slot.start(first).expect("starts");
        let second = one_slot.start(second).expect("starts");
        let (first, second) = (first.await.unwrap(), second.await.unwrap());

        assert!(first.fetch_ms >= 140, "{first:?}");
        assert_eq!(first.attestations, 1);
        assert!(first.attest_ms >= 90, "{first:?}");
        assert!(second.queued_ms >= 230, "{second:?}");
    }

    /// A real document verifies and is stored, a 404 or a non-document is stored as a
    /// failure, and a 503 stores nothing, so the next request verifies again.
    #[tokio::test]
    async fn attestations_are_verified_and_only_a_real_answer_is_stored() {
        let sigstore = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/attestations/sigstore-5.0.0.json"
        ))
        .expect("fixture");
        let base = registry(vec![
            ("/sigstore", 200, sigstore),
            ("/missing", 404, Vec::new()),
            ("/html", 200, b"<html>".to_vec()),
            ("/busy", 503, Vec::new()),
        ])
        .await;
        let store = Arc::new(InProcess::new(8));
        let analyser = analyser("run-attest", 1 << 20, store.clone());
        let digests: Vec<Sri> = (1..=4).map(crate::analysis::store::tests::sri).collect();
        let real = Sri::parse(
            "sha512-hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==",
        )
        .expect("parses");
        let checks = [
            (real.clone(), "/sigstore"),
            (digests[1].clone(), "/missing"),
            (digests[2].clone(), "/html"),
            (digests[3].clone(), "/busy"),
        ];
        let job = Job {
            reader: None,
            attestations: checks
                .iter()
                .map(|(digest, path)| Attestation {
                    digest: digest.clone(),
                    url: format!("{base}{path}"),
                    bundle: crate::ecosystem::npm::attestation::provenance_bundle,
                })
                .collect(),
            ..job(&digests[0], &format!("{base}/never-fetched"))
        };
        let timings = analyser
            .start(job)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(timings.attestations, 4);
        assert_eq!(
            timings.fetch_ms, 0,
            "no reader, so the artifact is not fetched"
        );

        assert_eq!(
            analyser.attested(&real).await,
            Some(Attested::Verified {
                identity: "github.com/sigstore/sigstore-js/.github/workflows/release.yml"
                    .to_owned()
            })
        );
        let Some(Attested::Failed { why }) = analyser.attested(&digests[1]).await else {
            panic!("a 404 is an answer");
        };
        assert!(why.contains("404"), "{why}");
        assert!(matches!(
            analyser.attested(&digests[2]).await,
            Some(Attested::Failed { .. })
        ));
        assert_eq!(analyser.attested(&digests[3]).await, None);
        assert_eq!(
            analyser.known(&digests[0]).await,
            Known::Unknown,
            "the artifact itself was not fetched: its analysis was not asked for"
        );
    }

    /// A registry that refuses the connection stores nothing either.
    #[tokio::test]
    async fn an_attestation_registry_that_cannot_be_reached_stores_nothing() {
        let store = Arc::new(InProcess::new(8));
        let analyser = analyser("run-attest-down", 1 << 20, store);
        let digest = crate::analysis::store::tests::sri(9);
        let job = Job {
            reader: None,
            attestations: vec![Attestation {
                digest: digest.clone(),
                url: format!("{}/attestations", crate::util::test_support::NO_UPSTREAM),
                bundle: crate::ecosystem::npm::attestation::provenance_bundle,
            }],
            ..job(&digest, crate::util::test_support::NO_UPSTREAM)
        };
        analyser
            .start(job)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.attested(&digest).await, None);
    }

    /// A store that answers every read and write with an error.
    struct Broken;

    impl Analyses for Broken {
        fn get<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Analysis>> {
            Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
        }

        fn put<'a>(&'a self, _: &'a Sri, _: &'a Analysis) -> Stored<'a, ()> {
            Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
        }

        fn attested<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Attested>> {
            Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
        }

        fn put_attested<'a>(&'a self, _: &'a Sri, _: &'a Attested) -> Stored<'a, ()> {
            Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
        }
    }

    #[tokio::test]
    async fn a_store_that_cannot_answer_is_unknown_and_its_failed_write_is_logged() {
        let tarball = tarball(&[("package/package.json", POSTINSTALL)]);
        let digest = sri_of(&tarball);
        let url = upstream(200, tarball).await;
        let analyser = analyser("run-broken", 1 << 20, Arc::new(Broken));
        assert_eq!(analyser.known(&digest).await, Known::Unknown);
        analyser
            .start(job(&digest, &url))
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.known(&digest).await, Known::Unknown);
    }

    /// A store that cannot say or keep what attestations found is logged, and the answer
    /// is verified again.
    #[tokio::test]
    async fn a_store_that_cannot_keep_attestations_is_logged() {
        use crate::util::test_support::{capture, text};
        let analyser = analyser("run-broken-attest", 1 << 20, Arc::new(Broken));
        let digest = crate::analysis::store::tests::sri(7);
        let (guard, buf) = capture(tracing::Level::WARN);
        assert_eq!(analyser.attested(&digest).await, None);
        let registry = upstream(200, b"{}".to_vec()).await;
        let job = Job {
            reader: None,
            attestations: vec![Attestation {
                digest: digest.clone(),
                url: registry,
                bundle: crate::ecosystem::npm::attestation::provenance_bundle,
            }],
            ..job(&digest, crate::util::test_support::NO_UPSTREAM)
        };
        analyser
            .start(job)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.attested(&digest).await, None);
        drop(guard);
        let log = text(&buf);
        assert!(
            log.contains("analysis store cannot answer; verifying again"),
            "{log}"
        );
        assert!(log.contains("attestations: not stored"), "{log}");
    }

    /// An attestations body cut short stores nothing, an artifact that cannot be fetched
    /// stores nothing, and a spooled file removed before it is read stores nothing.
    #[tokio::test]
    async fn what_cannot_be_read_stores_nothing() {
        use crate::util::test_support::{Answer, scripted};
        let store = Arc::new(InProcess::new(8));
        let analyser = analyser("run-unread", 1 << 20, store);
        let digest = crate::analysis::store::tests::sri(8);
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
        let cut = scripted(vec![Answer::cut_short()]).await;
        let cut_short = Job {
            attestations: vec![Attestation {
                digest: digest.clone(),
                url: format!("http://{cut}/attestations"),
                bundle: crate::ecosystem::npm::attestation::provenance_bundle,
            }],
            ..job(&digest, crate::util::test_support::NO_UPSTREAM)
        };
        analyser
            .start(cut_short)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.attested(&digest).await, None);
        assert_eq!(analyser.known(&digest).await, Known::Unknown);

        analyser
            .start(job(&digest, crate::util::test_support::NO_UPSTREAM))
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.known(&digest).await, Known::Unknown);

        let spooled = analyser
            .spool
            .write(
                futures_util::stream::iter(vec![Ok::<_, String>(bytes::Bytes::from_static(b"x"))]),
                None,
                |_| {},
            )
            .await
            .expect("spools");
        for entry in std::fs::read_dir(analyser.spool.dir()).expect("lists") {
            let path = entry.expect("an entry").path();
            if path.file_name().is_some_and(|name| name != ".lock") {
                std::fs::remove_file(path).expect("removes");
            }
        }
        let unread = read(
            &job(&digest, crate::util::test_support::NO_UPSTREAM),
            spooled,
            Reader::NpmTarball,
        )
        .await;
        assert!(unread.is_none());
        drop(guard);
        let log = crate::util::test_support::text(&buf);
        for said in [
            "attestations: body failed, nothing stored",
            "artifact analysis: fetch failed, nothing stored",
            "artifact analysis: the spool file could not be read, nothing stored",
        ] {
            assert!(log.contains(said), "{said}: {log}");
        }
    }
}
