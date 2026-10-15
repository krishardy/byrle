//! Checking a claim a database beside the registry makes of an artifact, such as a Go zip's
//! `h1:`, against the artifact's bytes, and keeping the sha256 of the bytes that matched. The
//! artifact is then served checked against that sha256 as it streams. See docs/go-plan.md.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::{Analyser, InFlight, ms};
use crate::integrity::Sri;
use crate::spool::{Spooled, WriteError};
use crate::util::lru::Lru;

/// One artifact whose claim is checked against its bytes.
#[derive(Debug, Clone)]
pub struct ClaimJob {
    /// The claim, such as Go's `h1:`. The digest of the bytes found to match is kept under it.
    pub claim: String,
    /// Where the proxy fetches the artifact from, as it would for the client.
    pub url: String,
    /// The claim's form of the spooled artifact.
    pub digest: fn(std::fs::File) -> Result<String, String>,
}

/// What is known about a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimKnown {
    /// The sha256 of bytes found to be what the claim names.
    Checked(Sri),
    /// The upstream's bytes are not what it names, on this process's last fetch.
    Failed(String),
    /// Neither, including when the analysis store cannot answer.
    Unknown,
}

/// The claims being checked now, and those whose last check failed.
#[derive(Clone)]
pub(super) struct Claims {
    in_flight: Arc<Mutex<HashSet<String>>>,
    failed: Arc<Mutex<Lru<String, String>>>,
}

impl Claims {
    /// Remembering at most `max_failed` failures, in this process only.
    pub(super) fn new(max_failed: usize) -> Self {
        Self {
            in_flight: Arc::default(),
            failed: Arc::new(Mutex::new(Lru::new(max_failed))),
        }
    }
}

impl Analyser {
    /// What is known about `claim`.
    pub async fn claim_known(&self, claim: &str) -> ClaimKnown {
        let failed = self
            .claims
            .failed
            .lock()
            .expect("failed claims lock")
            .get(&claim.to_owned())
            .cloned();
        if let Some(why) = failed {
            return ClaimKnown::Failed(why);
        }
        match self.store.claimed(claim).await {
            Ok(Some(digest)) => ClaimKnown::Checked(digest),
            Ok(None) => ClaimKnown::Unknown,
            Err(e) => {
                warn!(byrle.artifact.claim = %claim, error.message = %e, "analysis store cannot answer; checking the claim again");
                ClaimKnown::Unknown
            }
        }
    }

    /// Start checking `job` unless its claim is already being checked. The handle is for a
    /// test to wait on. The proxy drops it.
    pub fn start_claim(&self, job: ClaimJob) -> Option<JoinHandle<()>> {
        let set = self.claims.in_flight.clone();
        if !set
            .lock()
            .expect("in-flight lock")
            .insert(job.claim.clone())
        {
            return None;
        }
        let guard = InFlight {
            set,
            key: job.claim.clone(),
            ended: self.ended.clone(),
        };
        let analyser = self.clone();
        Some(tokio::spawn(async move {
            let _guard = guard;
            let _slot = analyser
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            if tokio::time::timeout(analyser.deadline, analyser.check_claim(&job))
                .await
                .is_err()
            {
                warn!(url.full = %job.url, byrle.analysis.deadline_s = analyser.deadline.as_secs(), "claim check: past its deadline, nothing stored");
            }
        }))
    }

    /// Check `job`'s artifact against its claim. A match is stored; a mismatch, an artifact
    /// over the spool's ceiling or one that does not read is remembered as failed. A fetch
    /// or spool that failed stores nothing, so the next request tries again.
    async fn check_claim(&self, job: &ClaimJob) {
        let started = Instant::now();
        let (spooled, digest) = match self.spool_hashed(job).await {
            Some(Ok(spooled)) => spooled,
            Some(Err(why)) => return self.claim_failed(job, why),
            None => return,
        };
        match digest_of(spooled, job.digest).await {
            Ok(found) if found == job.claim => {
                if let Err(e) = self.store.put_claimed(&job.claim, &digest).await {
                    warn!(url.full = %job.url, error.message = %e, "claim check: not stored");
                    return;
                }
                info!(url.full = %job.url, byrle.artifact.claim = %job.claim, byrle.artifact.digest = %digest, byrle.analysis.total_ms = ms(started), "claim checked against the artifact's bytes");
            }
            Ok(found) => self.claim_failed(job, format!("its files' digest is {found}")),
            Err(why) => self.claim_failed(job, why),
        }
    }

    /// `job`'s artifact spooled, with the sha256 of its bytes, or why it is over the ceiling.
    /// `None` when the fetch or the spool failed, which is logged.
    async fn spool_hashed(&self, job: &ClaimJob) -> Option<Result<(Spooled, Sri), String>> {
        let response = self.fetch(&job.url).await?;
        let claimed = response.content_length();
        let mut hasher = Sha256::new();
        let written = self
            .spool
            .write(response.bytes_stream(), claimed, |chunk| {
                hasher.update(chunk)
            })
            .await;
        match written {
            Ok(spooled) => Some(Ok((spooled, Sri::from_sha256(&hasher.finalize())))),
            Err(too_large @ WriteError::TooLarge { .. }) => Some(Err(too_large.to_string())),
            Err(e) => {
                warn!(url.full = %job.url, error.message = %e, "claim check: not spooled, nothing stored");
                None
            }
        }
    }

    /// Remember that `job`'s claim failed, and why: in this process only, so a restart
    /// checks it again.
    fn claim_failed(&self, job: &ClaimJob, why: String) {
        warn!(url.full = %job.url, byrle.artifact.claim = %job.claim, byrle.reason = %why, "claim check: the upstream's artifact is not what the claim names");
        self.claims
            .failed
            .lock()
            .expect("failed claims lock")
            .insert(job.claim.clone(), why);
    }
}

/// `check` over the spooled file, off the async threads. Errors with why it could not be
/// computed, the file not being readable among them.
async fn digest_of(
    spooled: Spooled,
    check: fn(std::fs::File) -> Result<String, String>,
) -> Result<String, String> {
    tokio::task::spawn_blocking(move || spooled.reader().map(check))
        .await
        .map_err(std::io::Error::other)
        .and_then(|read| read)
        .map_err(|e| format!("the spooled file could not be read: {e}"))
        .and_then(|found| found)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::tests::analyser;
    use super::*;
    use crate::analysis::store::InProcess;
    use crate::util::test_support::{Answer, scripted};

    /// sum.golang.org's `h1:` for rsc.io/quote v1.5.2's zip.
    const QUOTE: &str = "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=";

    fn zip() -> Vec<u8> {
        crate::ecosystem::go::fixture("rsc.io-quote-v1.5.2.zip")
    }

    fn job(claim: &str, url: String) -> ClaimJob {
        ClaimJob {
            claim: claim.to_owned(),
            url,
            digest: crate::ecosystem::go::dirhash::zip_h1::<std::fs::File>,
        }
    }

    /// What is known of `claim` once a job has checked it against `answer`.
    async fn checked(analyser: &Analyser, claim: &str, answer: Answer) -> ClaimKnown {
        let addr = scripted(vec![answer]).await;
        analyser
            .start_claim(job(claim, format!("http://{addr}/v1.5.2.zip")))
            .expect("starts")
            .await
            .expect("finishes");
        analyser.claim_known(claim).await
    }

    /// The zip's files hash to the claim, so the sha256 of its bytes is kept under it.
    #[tokio::test]
    async fn a_zip_matching_its_claim_keeps_its_sha256() {
        let analyser = analyser("claim-match", 1 << 20, Arc::new(InProcess::new(8)));
        assert_eq!(analyser.claim_known(QUOTE).await, ClaimKnown::Unknown);
        let known = checked(&analyser, QUOTE, Answer::body(zip())).await;
        assert_eq!(
            known,
            ClaimKnown::Checked(Sri::from_sha256(&Sha256::digest(zip())))
        );
    }

    /// Another zip, bytes that are no zip, and a zip over the spool's ceiling each fail, and
    /// are remembered.
    #[tokio::test]
    async fn a_zip_that_is_not_what_its_claim_names_fails() {
        let analyser = analyser("claim-fail", 1 << 20, Arc::new(InProcess::new(8)));
        for (claim, body, why) in [
            ("h1:other=", zip(), format!("its files' digest is {QUOTE}")),
            (QUOTE, b"not a zip".to_vec(), "not a zip".to_owned()),
        ] {
            let ClaimKnown::Failed(found) = checked(&analyser, claim, Answer::body(body)).await
            else {
                panic!("{claim} fails");
            };
            assert!(found.contains(&why), "{found}");
        }
        let small = super::super::tests::analyser("claim-small", 16, Arc::new(InProcess::new(8)));
        let ClaimKnown::Failed(found) = checked(&small, QUOTE, Answer::body(zip())).await else {
            panic!("over the ceiling");
        };
        assert!(found.contains("16-byte ceiling"), "{found}");
    }

    /// A fetch that fails, a body cut short, a store that does not answer and a job past its
    /// deadline store nothing, so the claim is checked again.
    #[tokio::test]
    async fn what_cannot_be_checked_stores_nothing() {
        let analyser = analyser("claim-nothing", 1 << 20, Arc::new(InProcess::new(8)));
        for answer in [Answer::Status(404), Answer::cut_short()] {
            assert_eq!(checked(&analyser, QUOTE, answer).await, ClaimKnown::Unknown);
        }
        let broken = super::super::tests::analyser(
            "claim-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        );
        assert_eq!(
            checked(&broken, QUOTE, Answer::body(zip())).await,
            ClaimKnown::Unknown
        );

        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                held.push(socket);
            }
        });
        let hurried = analyser.with_deadline(std::time::Duration::from_millis(50));
        hurried
            .start_claim(job(QUOTE, format!("http://{addr}/v1.5.2.zip")))
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(hurried.claim_known(QUOTE).await, ClaimKnown::Unknown);
    }

    /// One claim is checked by one job at a time.
    #[tokio::test]
    async fn one_claim_is_checked_once_at_a_time() {
        let analyser = analyser("claim-once", 1 << 20, Arc::new(InProcess::new(8)));
        let addr = scripted(vec![Answer::body(zip())]).await;
        let url = format!("http://{addr}/v1.5.2.zip");
        let first = analyser
            .start_claim(job(QUOTE, url.clone()))
            .expect("starts");
        assert!(analyser.start_claim(job(QUOTE, url)).is_none());
        first.await.expect("finishes");
        assert!(matches!(
            analyser.claim_known(QUOTE).await,
            ClaimKnown::Checked(_)
        ));
    }

    /// A spooled file gone before it is read cannot be checked.
    #[tokio::test]
    async fn a_spooled_file_that_cannot_be_read_is_not_checked() {
        let analyser = analyser("claim-gone", 1 << 20, Arc::new(InProcess::new(8)));
        let spooled = analyser
            .spool
            .write(
                futures_util::stream::iter(vec![Ok::<_, String>(bytes::Bytes::from(zip()))]),
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
        let error = digest_of(
            spooled,
            crate::ecosystem::go::dirhash::zip_h1::<std::fs::File>,
        )
        .await
        .unwrap_err();
        assert!(error.contains("could not be read"), "{error}");
    }
}
