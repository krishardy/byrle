//! Analysing an artifact in the background, so no request waits for it.
//!
//! The first fetch of an artifact starts a job here: fetch the artifact from upstream,
//! write it to the [`crate::spool`], check its digest, read it, and store what was read
//! under the digest. The request is answered 503 until the job has finished, and the
//! client's retry is decided on what was stored. See
//! `docs/engineering_decisions/artifact-spool.md`.
//!
//! The retry fetches the artifact from upstream again, and that fetch is checked against
//! the same digest. That check is what makes the stored analysis apply to the bytes
//! served.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sigstore_verify::types::Bundle;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::analysis::Reader;
use crate::analysis::attestation::{Attested, verify};
use crate::analysis::store::{Analyses, Analysis, Scripts};
use crate::integrity::{Mismatch, Sri};
use crate::spool::{Spool, WriteError};
use crate::util::lru::Lru;

/// How long one job may take, from its fetch starting to its analysis being stored.
///
/// The upstream client ends a stall after [`crate::http::READ_TIMEOUT`] with no bytes, and
/// sets no total timeout, so without this an upstream that trickles holds a slot, and its
/// digest is answered 503 for as long as it trickles. Ten minutes is a
/// [`crate::env::DEFAULT_MAX_ARTIFACT_BYTES`] artifact at under 2 MB/s.
pub const DEADLINE: Duration = Duration::from_secs(600);

/// What is known about the artifact with a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Known {
    /// An analysis is stored.
    Analysed(Analysis),
    /// The upstream served bytes that do not match the digest, on the last fetch this
    /// process made.
    Mismatched(Mismatch),
    /// Neither. An analysis store that cannot answer is this too, and the artifact is
    /// analysed again, which is the safe direction.
    Unknown,
}

/// One artifact to analyse.
#[derive(Debug, Clone)]
pub struct Job {
    /// The digest the metadata published. The analysis is stored under it.
    pub digest: Sri,
    /// Where the proxy fetches the artifact from, as it would for the client.
    pub url: String,
    /// What reads the artifact for install scripts. `None` when that analysis is already
    /// stored and only attestations are missing, so the artifact is not fetched.
    pub reader: Option<Reader>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// Attestations to verify: this artifact's, and the version published before it,
    /// each against the digest the metadata published for its own artifact.
    pub attestations: Vec<Attestation>,
}

/// One artifact's attestations to verify.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// The digest the metadata published for the artifact. The result is stored under it.
    pub digest: Sri,
    /// Where the registry serves the attestations document.
    pub url: String,
    /// The adapter's reader for that document, which is laid out per registry:
    /// `crate::ecosystem::npm::attestation::provenance_bundle` for npm.
    pub bundle: fn(&[u8]) -> Result<Bundle, String>,
}

/// Runs analyses in the background, one per digest at a time.
#[derive(Clone)]
pub struct Analyser {
    client: reqwest::Client,
    spool: Arc<Spool>,
    store: Arc<dyn Analyses>,
    /// Bounds how many analyses run at once, and so how much of the spool is in use. A
    /// job waits for a slot. A request never does.
    slots: Arc<Semaphore>,
    /// The digests being analysed now. A client retrying, and an install asking for one
    /// artifact from several places, start one job between them.
    in_flight: Arc<Mutex<HashSet<Sri>>>,
    /// The digests whose last fetch did not match, bounded by count. In this process only:
    /// a mismatch is about one upstream at one time, not about the bytes.
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
                warn!(digest = %digest, error = %e, "analysis store cannot answer; analysing again");
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
                warn!(digest = %digest, error = %e, "analysis store cannot answer; verifying again");
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
    pub fn start(&self, job: Job) -> Option<JoinHandle<()>> {
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
        Some(tokio::spawn(async move {
            let _guard = guard;
            analyser.run(job).await;
        }))
    }

    async fn run(&self, job: Job) {
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        // Dropping the analysis on expiry drops its spool file too.
        let work = async {
            if let Some(reader) = job.reader {
                self.analyse(&job, reader).await;
            }
            for attestation in &job.attestations {
                self.attest(attestation).await;
            }
        };
        if tokio::time::timeout(self.deadline, work).await.is_err() {
            warn!(url = %job.url, deadline_s = self.deadline.as_secs(), "artifact analysis: past its deadline, nothing stored");
        }
    }

    /// Fetch the attestations document and verify it. A registry that cannot be reached,
    /// or answers 5xx or 429, stores nothing, so the next request tries again: a flaky
    /// registry must not refuse a package. Any other answer is stored, a failure included.
    async fn attest(&self, attestation: &Attestation) {
        let url = &attestation.url;
        let response = match self.client.get(url).send().await {
            Ok(response) => response,
            Err(e) => {
                warn!(url = %url, error = %e, "attestations: fetch failed, nothing stored");
                return;
            }
        };
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!(url = %url, status = status.as_u16(), "attestations: not answered, nothing stored");
            return;
        }
        let attested = if !status.is_success() {
            Attested::Failed {
                why: format!("the registry answered {status} for {url}"),
            }
        } else {
            let document = match response.bytes().await {
                Ok(document) => document,
                Err(e) => {
                    warn!(url = %url, error = %e, "attestations: body failed, nothing stored");
                    return;
                }
            };
            match (attestation.bundle)(&document) {
                Ok(bundle) => verify(&bundle, &attestation.digest),
                Err(why) => Attested::Failed { why },
            }
        };
        match &attested {
            Attested::Verified { identity } => {
                info!(url = %url, digest = %attestation.digest, identity = %identity, "attestation verified");
            }
            Attested::Failed { why } => {
                warn!(url = %url, digest = %attestation.digest, why = %why, "attestation did not verify");
            }
        }
        if let Err(e) = self
            .store
            .put_attested(&attestation.digest, &attested)
            .await
        {
            warn!(url = %url, error = %e, "attestations: not stored");
        }
    }

    async fn analyse(&self, job: &Job, reader: Reader) {
        let response = match self
            .client
            .get(&job.url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(response) => response,
            Err(e) => {
                warn!(url = %job.url, error = %e, "artifact analysis: fetch failed, nothing stored");
                return;
            }
        };
        let claimed = response.content_length();
        let mut verifier = job.digest.verifier();
        let written = self
            .spool
            .write(response.bytes_stream(), claimed, |chunk| {
                verifier.update(chunk)
            })
            .await;
        let scripts = match written {
            Ok(spooled) => {
                if let Err(mismatch) = verifier.finish(spooled.len()) {
                    warn!(url = %job.url, %mismatch, "artifact analysis: digest mismatch");
                    self.mismatched
                        .lock()
                        .expect("mismatch lock")
                        .insert(job.digest.clone(), mismatch);
                    return;
                }
                let read = tokio::task::spawn_blocking(move || {
                    let file = spooled.reader()?;
                    Ok(Scripts::of(reader.read(std::io::BufReader::new(file))))
                })
                .await
                .map_err(std::io::Error::other)
                .and_then(|read: std::io::Result<Scripts>| read);
                match read {
                    Ok(scripts) => scripts,
                    Err(e) => {
                        warn!(url = %job.url, error = %e, "artifact analysis: the spool file could not be read, nothing stored");
                        return;
                    }
                }
            }
            // Stored, so the retry is decided rather than deferred again. An artifact
            // nothing read is `Unreadable`, which `install_scripts: block` refuses.
            Err(too_large @ WriteError::TooLarge { .. }) => {
                warn!(url = %job.url, error = %too_large, "artifact analysis: over the ceiling");
                Scripts::Unreadable(too_large.to_string())
            }
            Err(e) => {
                warn!(url = %job.url, error = %e, "artifact analysis: not spooled, nothing stored");
                return;
            }
        };
        let analysis = Analysis {
            ecosystem: job.ecosystem.clone(),
            name: job.name.clone(),
            version: job.version.clone(),
            scripts,
        };
        if let Err(e) = self.store.put(&job.digest, &analysis).await {
            warn!(url = %job.url, error = %e, "artifact analysis: not stored");
            return;
        }
        info!(
            url = %job.url,
            digest = %job.digest,
            scripts = ?analysis.scripts.names(),
            "artifact analysed"
        );
    }
}

/// Takes a digest out of the in-flight set when its job ends, however it ends, and counts
/// the job as ended.
struct InFlight {
    set: Arc<Mutex<HashSet<Sri>>>,
    digest: Sri,
    ended: Arc<watch::Sender<u64>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut set) = self.set.lock() {
            set.remove(&self.digest);
        }
        self.ended.send_modify(|ended| *ended += 1);
    }
}

#[cfg(test)]
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
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
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
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    /// A real document verifies and its identity is stored. A 404 and a body that is not
    /// an attestations document are stored as failures. A 503 stores nothing, so the next
    /// request verifies again: a registry having a bad minute refuses nothing.
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
        analyser
            .start(job)
            .expect("starts")
            .await
            .expect("finishes");

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
        // The artifact itself was not fetched: its analysis was not asked for.
        assert_eq!(analyser.known(&digests[0]).await, Known::Unknown);
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
}
