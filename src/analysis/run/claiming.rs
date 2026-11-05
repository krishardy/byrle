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
use crate::analysis::Reader;
use crate::analysis::store::Analysis;
use crate::ecosystem::{Material, Signature, Signer};
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
    /// What checks the artifact's signature, where its registry signs files.
    pub signer: Option<Arc<dyn Signer>>,
    /// The repository it is fetched from, which its signature's result is kept by.
    pub repository: crate::ecosystem::Repository,
    /// What reads it for install scripts, stored under the sha256 found, where one reads it.
    pub reads: Option<Reads>,
}

/// A reader for a claimed artifact, and the version it is read as.
#[derive(Debug, Clone)]
pub struct Reads {
    pub reader: Reader,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
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

    /// Check `job`'s artifact against its claim, and its signature as [`Self::store_signature`]
    /// does. A match is stored; a mismatch or an artifact that does not read is remembered
    /// as failed. One that could not be fetched or spooled stores nothing.
    async fn check_claim(&self, job: &ClaimJob) {
        let started = Instant::now();
        let material = async {
            match &job.signer {
                Some(signer) => Some(signer.material().await),
                None => None,
            }
        };
        let (spooled, material) = tokio::join!(self.spool_hashed(job), material);
        let (spooled, digest) = match spooled {
            Some(Ok(spooled)) => spooled,
            Some(Err(why)) => return self.claim_failed(job, why),
            None => return,
        };
        let (file, read_file) = (spooled.reader(), spooled.reader());
        match digest_of(spooled, job.digest).await {
            Ok(found) if found == job.claim => {
                if !self.store_signature(job, &digest, material, file).await {
                    return;
                }
                if !self.store_read(job, &digest, read_file).await {
                    return;
                }
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

    /// Store what `job`'s signer makes of `material` against `file`, the bytes with `digest`.
    /// Whether the claim may be stored after it: not when it could not be checked or kept.
    async fn store_signature(
        &self,
        job: &ClaimJob,
        digest: &Sri,
        material: Option<Result<Option<Material>, String>>,
        file: std::io::Result<std::fs::File>,
    ) -> bool {
        let (Some(signer), Some(material)) = (&job.signer, material) else {
            return true;
        };
        let Some(signature) = signed(signer, material, file).await else {
            warn!(url.full = %job.url, "claim check: the signature could not be checked, nothing stored");
            return false;
        };
        if let Err(e) = self
            .store
            .put_signature(digest, job.repository.name(), signer.verifier(), &signature)
            .await
        {
            warn!(url.full = %job.url, error.message = %e, "claim check: the signature's result not stored");
            return false;
        }
        info!(url.full = %job.url, byrle.artifact.signature = ?signature, "signature checked against the artifact's bytes");
        true
    }

    /// Store what `job`'s reader finds in `file`, the bytes with `digest`, so the request after
    /// the claim reads nothing. Whether the claim may be stored after it.
    async fn store_read(
        &self,
        job: &ClaimJob,
        digest: &Sri,
        file: std::io::Result<std::fs::File>,
    ) -> bool {
        let Some(reads) = &job.reads else {
            return true;
        };
        let Some(scripts) = super::read(&job.url, file, reads.reader).await else {
            return false;
        };
        let analysis = Analysis {
            ecosystem: reads.ecosystem.clone(),
            name: reads.name.clone(),
            version: reads.version.clone(),
            scripts,
        };
        if let Err(e) = self.store.put(digest, &analysis).await {
            warn!(url.full = %job.url, error.message = %e, "claim check: the artifact's analysis not stored");
            return false;
        }
        info!(url.full = %job.url, byrle.artifact.digest = %digest, byrle.artifact.scripts = ?analysis.scripts.names(), "artifact analysed");
        true
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

/// What `signer` makes of `material`, a fetched signature, against `file`, the artifact's
/// bytes, off the async threads; for a file with none, whether an earlier version had one.
/// `None` when the signature or the versions could not be asked, or the file read.
async fn signed(
    signer: &Arc<dyn Signer>,
    material: Result<Option<Material>, String>,
    file: std::io::Result<std::fs::File>,
) -> Option<Signature> {
    let material = match material {
        Ok(material) => material,
        Err(why) => {
            warn!(error.message = %why, "the signature or its key could not be fetched");
            return None;
        }
    };
    let Some(material) = material else {
        return match signer.signed_before().await {
            Ok(Some((previous, history))) => Some(Signature::Dropped { previous, history }),
            Ok(None) => Some(Signature::Unsigned),
            Err(why) => {
                warn!(error.message = %why, "the earlier versions' signatures could not be asked");
                None
            }
        };
    };
    let signer = Arc::clone(signer);
    let checked = crate::util::blocking::run(move |stop| {
        let mut file = stop.reading(file?);
        signer.verify(&material, &mut file)
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|checked| checked);
    checked.ok()
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
    use crate::policy::decide::History;
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
            signer: None,
            repository: crate::ecosystem::Repository::of(crate::identity::Ecosystem::Go),
            reads: None,
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

    /// A signer answering as it is set: material, the version signed before, and a verdict.
    #[derive(Debug)]
    struct Fake {
        material: Result<Option<Material>, String>,
        before: Result<Option<(String, History)>, String>,
        verdict: Option<Signature>,
    }

    impl Signer for Fake {
        fn verifier(&self) -> &'static str {
            "fake 1"
        }
        fn material(
            &self,
        ) -> futures_util::future::BoxFuture<'_, Result<Option<Material>, String>> {
            let material = self.material.clone();
            Box::pin(async move { material })
        }
        fn signed_before(
            &self,
        ) -> futures_util::future::BoxFuture<'_, Result<Option<(String, History)>, String>>
        {
            let before = self.before.clone();
            Box::pin(async move { before })
        }
        fn verify(
            &self,
            _: &Material,
            _: &mut dyn crate::ecosystem::Source,
        ) -> std::io::Result<Signature> {
            self.verdict
                .clone()
                .ok_or_else(|| std::io::Error::other("unreadable"))
        }
    }

    /// A signer whose check reads the file without end, saying in [`SAID`] why it stopped.
    #[derive(Debug)]
    struct Endless;

    static SAID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    impl Signer for Endless {
        fn verifier(&self) -> &'static str {
            "endless 1"
        }
        fn material(
            &self,
        ) -> futures_util::future::BoxFuture<'_, Result<Option<Material>, String>> {
            Box::pin(async { Ok(Some(material())) })
        }
        fn signed_before(
            &self,
        ) -> futures_util::future::BoxFuture<'_, Result<Option<(String, History)>, String>>
        {
            Box::pin(async { Ok(None) })
        }
        fn verify(
            &self,
            _: &Material,
            file: &mut dyn crate::ecosystem::Source,
        ) -> std::io::Result<Signature> {
            crate::util::blocking::testing::read_endlessly(file, &SAID);
            Err(std::io::Error::other("stopped"))
        }
    }

    /// A signature check stops reading once the claim is past its deadline.
    #[tokio::test]
    async fn a_signature_check_past_its_deadline_stops_reading() {
        let analyser = analyser("claim-endless", 1 << 20, Arc::new(InProcess::new(8)))
            .with_deadline(std::time::Duration::from_millis(200));
        let addr = scripted(vec![Answer::body(zip())]).await;
        let job = ClaimJob {
            signer: Some(Arc::new(Endless)),
            reads: None,
            ..job(QUOTE, format!("http://{addr}/v1.5.2.zip"))
        };
        analyser
            .start_claim(job)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(
            crate::util::blocking::testing::stopped(&SAID).await,
            crate::util::blocking::STOPPED
        );
        assert_eq!(analyser.claim_known(QUOTE).await, ClaimKnown::Unknown);
    }

    fn material() -> Material {
        Material {
            signature: b"sig".to_vec(),
            keys: vec!["key".to_owned()],
        }
    }

    /// The signature's result is stored before the claim, and with it whatever it says: a
    /// signature that fails is a provenance fact, and the claim still matches.
    #[tokio::test]
    async fn a_signed_artifact_s_signature_is_stored_before_its_claim() {
        let verified = Signature::Verified {
            key: "K".to_owned(),
        };
        let failed = Signature::Failed {
            why: "bad".to_owned(),
        };
        for (fake, stored) in [
            (
                Fake {
                    material: Ok(Some(material())),
                    before: Ok(None),
                    verdict: Some(verified.clone()),
                },
                Some(verified),
            ),
            (
                Fake {
                    material: Ok(Some(material())),
                    before: Ok(None),
                    verdict: Some(failed.clone()),
                },
                Some(failed),
            ),
            (
                Fake {
                    material: Ok(None),
                    before: Ok(Some(("1.0".to_owned(), History(vec![true, false])))),
                    verdict: None,
                },
                Some(Signature::Dropped {
                    previous: "1.0".to_owned(),
                    history: History(vec![true, false]),
                }),
            ),
            (
                Fake {
                    material: Ok(None),
                    before: Ok(None),
                    verdict: None,
                },
                Some(Signature::Unsigned),
            ),
            (
                Fake {
                    material: Err("down".to_owned()),
                    before: Ok(None),
                    verdict: None,
                },
                None,
            ),
            (
                Fake {
                    material: Ok(None),
                    before: Err("down".to_owned()),
                    verdict: None,
                },
                None,
            ),
            (
                Fake {
                    material: Ok(Some(material())),
                    before: Ok(None),
                    verdict: None,
                },
                None,
            ),
        ] {
            let store = Arc::new(InProcess::new(8));
            let analyser = analyser("claim-signed", 1 << 20, store.clone());
            let addr = scripted(vec![Answer::body(zip())]).await;
            let job = ClaimJob {
                signer: Some(Arc::new(fake)),
                reads: None,
                ..job(QUOTE, format!("http://{addr}/v1.5.2.zip"))
            };
            analyser
                .start_claim(job)
                .expect("starts")
                .await
                .expect("finishes");
            let digest = Sri::from_sha256(&Sha256::digest(zip()));
            let found = crate::analysis::store::Analyses::signature(
                store.as_ref(),
                &digest,
                "golang",
                "fake 1",
            )
            .await
            .unwrap();
            assert_eq!(found, stored);
            let known = analyser.claim_known(QUOTE).await;
            assert_eq!(
                known == ClaimKnown::Checked(digest),
                stored.is_some(),
                "{known:?}"
            );
        }
    }

    /// What the claim job reads is stored under the bytes' sha256 before the claim; a store
    /// that cannot keep it keeps no claim, and a file that cannot be opened stores nothing.
    #[tokio::test]
    async fn a_claimed_artifact_is_read_before_its_claim_is_stored() {
        let reads = || {
            Some(Reads {
                reader: crate::analysis::jar_annotation_processors,
                ecosystem: "golang".to_owned(),
                name: "rsc.io/quote".to_owned(),
                version: "v1.5.2".to_owned(),
            })
        };
        let store = Arc::new(InProcess::new(8));
        let analyser = analyser("claim-read", 1 << 20, store.clone());
        let addr = scripted(vec![Answer::body(zip())]).await;
        let read = ClaimJob {
            reads: reads(),
            ..job(QUOTE, format!("http://{addr}/v1.5.2.zip"))
        };
        analyser
            .start_claim(read.clone())
            .expect("starts")
            .await
            .expect("finishes");
        let digest = Sri::from_sha256(&Sha256::digest(zip()));
        let super::super::Known::Analysed(analysis) = analyser.known(&digest).await else {
            panic!("analysed");
        };
        assert_eq!(analysis.scripts.names(), Some(&[][..]));
        assert_eq!(analysis.version, "v1.5.2");
        assert_eq!(
            analyser.claim_known(QUOTE).await,
            ClaimKnown::Checked(digest.clone())
        );
        let gone = Err(std::io::Error::other("gone"));
        assert!(!analyser.store_read(&read, &digest, gone).await);

        let broken = super::super::tests::analyser(
            "claim-read-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        );
        let addr = scripted(vec![Answer::body(zip())]).await;
        let unkept = ClaimJob {
            reads: reads(),
            ..job(QUOTE, format!("http://{addr}/v1.5.2.zip"))
        };
        broken
            .start_claim(unkept)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(broken.claim_known(QUOTE).await, ClaimKnown::Unknown);
    }

    /// A store that cannot answer has no signature to give.
    #[tokio::test]
    async fn a_store_that_cannot_answer_gives_no_signature() {
        let broken = analyser(
            "signature-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        );
        let digest = Sri::from_sha256(&Sha256::digest(zip()));
        let at = crate::ecosystem::Repository::of(crate::identity::Ecosystem::Go);
        assert_eq!(broken.signature(&digest, at, "fake 1").await, None);
    }

    /// A spooled file that cannot be opened has no signature to check.
    #[tokio::test]
    async fn an_unreadable_file_has_no_signature_checked() {
        let fake: Arc<dyn Signer> = Arc::new(Fake {
            material: Ok(Some(material())),
            before: Ok(None),
            verdict: Some(Signature::Unsigned),
        });
        let gone = Err(std::io::Error::other("gone"));
        assert_eq!(signed(&fake, Ok(Some(material())), gone).await, None);
    }

    /// A store that keeps the claim but not the signature's result keeps neither.
    #[tokio::test]
    async fn a_signature_not_stored_stores_no_claim() {
        let analyser = analyser(
            "claim-signed-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        );
        let addr = scripted(vec![Answer::body(zip())]).await;
        let fake = Fake {
            material: Ok(None),
            before: Ok(None),
            verdict: None,
        };
        let job = ClaimJob {
            signer: Some(Arc::new(fake)),
            reads: None,
            ..job(QUOTE, format!("http://{addr}/v1.5.2.zip"))
        };
        analyser
            .start_claim(job)
            .expect("starts")
            .await
            .expect("finishes");
        assert_eq!(analyser.claim_known(QUOTE).await, ClaimKnown::Unknown);
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
