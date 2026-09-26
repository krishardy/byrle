//! Analysing an artifact in the background, so no request waits for it.
//!
//! A request for an artifact nothing has analysed is answered 503 at once, and the
//! analysis runs here: fetch the artifact from upstream, write it to the
//! [`crate::spool`], check its digest, read it, and store what was read under the digest.
//! The client's retry finds the analysis and is served. See
//! `docs/engineering_decisions/artifact-spool.md`.
//!
//! The retry fetches the artifact from upstream again, and that fetch is checked against
//! the same digest. That check is what makes the stored analysis apply to the bytes
//! served.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::analysis::Reader;
use crate::analysis::store::{Analyses, Analysis, Scripts};
use crate::integrity::{Mismatch, Sri};
use crate::spool::{Spool, WriteError};
use crate::util::lru::Lru;

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
    pub reader: Reader,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
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
        }
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
                let reader = job.reader;
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
            ecosystem: job.ecosystem,
            name: job.name,
            version: job.version,
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
            reader: Reader::NpmTarball,
            ecosystem: "npm".to_owned(),
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
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

    /// A store that answers every read and write with an error.
    struct Broken;

    impl Analyses for Broken {
        fn get<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Analysis>> {
            Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
        }

        fn put<'a>(&'a self, _: &'a Sri, _: &'a Analysis) -> Stored<'a, ()> {
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
