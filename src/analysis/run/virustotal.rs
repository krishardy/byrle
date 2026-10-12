//! Asking VirusTotal about an artifact, beside the analysis and never in front of it: no
//! request is deferred for it. See docs/engineering_decisions/virustotal.md.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::{OnceCell, Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::{Analyser, InFlight};
use crate::analysis::virustotal::{
    self, Client, Counts, DIRECT_UPLOAD_BYTES, Failure, Limiter, MAX_UPLOAD_BYTES, Mode, Scanned,
    Settings, Verdict,
};
use crate::integrity::Sri;

/// One artifact to ask VirusTotal about.
#[derive(Debug, Clone)]
pub struct ScanJob {
    /// The digest the metadata published. The answer is stored under it.
    pub digest: Sri,
    /// Where the proxy fetches the artifact from.
    pub url: String,
}

/// VirusTotal's client, limiter and in-flight set, apart from the analyses a client waits on.
#[derive(Clone)]
pub(super) struct Scans {
    client: Arc<Client>,
    mode: Mode,
    uploads_from: Vec<String>,
    per_minute: u32,
    per_day: u32,
    /// [`DIRECT_UPLOAD_BYTES`] and [`MAX_UPLOAD_BYTES`], unless a test lowers them.
    upload_limits: (u64, u64),
    /// Made on the first request, from the requests the store says were made in the last day.
    limiter: Arc<OnceCell<Limiter>>,
    /// One job at a time: the quota is a few requests a minute.
    slot: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<Sri>>>,
    started: Arc<std::sync::atomic::AtomicU64>,
    ended: Arc<watch::Sender<u64>>,
}

impl Analyser {
    /// Ask VirusTotal as `settings` say. `None` leaves it off.
    pub fn with_virustotal(mut self, settings: Option<&Settings>) -> Self {
        self.scans = settings.map(|settings| Scans {
            client: Arc::new(Client::new(self.client.clone(), settings)),
            mode: settings.mode,
            uploads_from: settings.uploads_from.clone(),
            per_minute: settings.per_minute,
            per_day: settings.per_day,
            upload_limits: (DIRECT_UPLOAD_BYTES, MAX_UPLOAD_BYTES),
            limiter: Arc::default(),
            slot: Arc::new(Semaphore::new(1)),
            in_flight: Arc::default(),
            started: Arc::default(),
            ended: Arc::new(watch::Sender::new(0)),
        });
        self
    }

    /// What VirusTotal said about the artifact with `digest`. A store that cannot answer is
    /// `None`, and it is asked again.
    pub async fn scanned(&self, digest: &Sri) -> Option<Scanned> {
        match self.store.scanned(digest).await {
            Ok(scanned) => scanned,
            Err(e) => {
                warn!(byrle.artifact.digest = %digest, error.message = %e, "analysis store cannot answer; asking VirusTotal again");
                None
            }
        }
    }

    /// Ask VirusTotal about `job` unless it is off, `prior` is not due, or its digest is
    /// being asked about. `now` is Unix seconds. The handle is for a test to wait on.
    pub fn start_scan(
        &self,
        job: ScanJob,
        prior: Option<Scanned>,
        now: i64,
    ) -> Option<JoinHandle<()>> {
        let scans = self.scans.clone()?;
        if prior.as_ref().is_some_and(|prior| !prior.due(now))
            || !scans
                .in_flight
                .lock()
                .expect("virustotal in-flight lock")
                .insert(job.digest.clone())
        {
            return None;
        }
        scans
            .started
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let guard = InFlight {
            set: scans.in_flight.clone(),
            key: job.digest.clone(),
            ended: scans.ended.clone(),
        };
        let analyser = self.clone();
        Some(tokio::spawn(async move {
            let _guard = guard;
            let _slot = scans
                .slot
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            let scanned = match prior {
                Some(Scanned {
                    sha256,
                    verdict: Verdict::Queued(id),
                    ..
                }) => analyser.polled(&scans, sha256, &id).await,
                _ => analyser.looked_up(&scans, &job).await,
            };
            match scanned {
                Ok(scanned) => analyser.put_scanned(&job, &scanned).await,
                Err(why) => {
                    warn!(url.full = %job.url, error.message = %why, "virustotal: not answered, nothing stored")
                }
            }
        }))
    }

    /// Whether VirusTotal is asked.
    pub fn scanning(&self) -> bool {
        self.scans.is_some()
    }

    /// How many VirusTotal jobs have started since this analyser was made. 0 when it is off.
    pub fn scans_started(&self) -> u64 {
        self.scans.as_ref().map_or(0, |scans| {
            scans.started.load(std::sync::atomic::Ordering::Relaxed)
        })
    }

    /// Wait until `count` VirusTotal jobs have ended since this analyser was made.
    pub async fn scans_ended(&self, count: u64) {
        if let Some(scans) = &self.scans {
            let _ = scans
                .ended
                .subscribe()
                .wait_for(|ended| *ended >= count)
                .await;
        }
    }

    /// The finished analysis `id` of the upload of the file with `sha256`, or it queued again.
    /// Errors with why VirusTotal did not answer.
    async fn polled(&self, scans: &Scans, sha256: String, id: &str) -> Result<Scanned, String> {
        self.ask(scans).await;
        let verdict = match scans.client.analysis(id).await.map_err(said)? {
            Some(counts) => Verdict::Known(counts),
            None => Verdict::Queued(id.to_owned()),
        };
        Ok(scanned(sha256, verdict))
    }

    /// Fetch `job`'s artifact, verify it, hash it, and look it up; upload it when the mode
    /// and its origin allow and VirusTotal does not know it. Errors with why not.
    async fn looked_up(&self, scans: &Scans, job: &ScanJob) -> Result<Scanned, String> {
        let response = self
            .fetch(&job.url)
            .await
            .ok_or("the artifact was not fetched")?;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        let spooled = match self
            .spool_verified(&job.url, &job.digest, response, |chunk| {
                sha2::Digest::update(&mut hasher, chunk)
            })
            .await
        {
            Some(Ok(spooled)) => spooled,
            Some(Err(too_large)) => return Err(format!("the artifact: {too_large}")),
            None => return Err("the artifact was not verified".to_owned()),
        };
        let sha256 = crate::util::hex(&sha2::Digest::finalize(hasher));
        self.ask(scans).await;
        if let Some(counts) = scans.client.lookup(&sha256).await.map_err(said)? {
            return Ok(scanned(sha256, Verdict::Known(counts)));
        }
        let (direct, max) = scans.upload_limits;
        let uploadable = scans.mode == Mode::Upload
            && virustotal::uploadable_from(&job.url, &scans.uploads_from)
            && spooled.len() <= max;
        if !uploadable {
            return Ok(scanned(sha256, Verdict::Unknown));
        }
        let to = match spooled.len() > direct {
            true => {
                self.ask(scans).await;
                Some(scans.client.upload_url().await.map_err(said)?)
            }
            false => None,
        };
        self.ask(scans).await;
        let file = spooled
            .reader()
            .expect("a spool file is there while its guard lives");
        let id = scans
            .client
            .upload(
                to.as_deref(),
                file,
                spooled.len(),
                virustotal::file_name(&job.url),
            )
            .await
            .map_err(said)?;
        Ok(scanned(sha256, Verdict::Queued(id)))
    }

    /// Wait for the limiter, made from the store's count of the last day's requests on the
    /// first call, and record the request.
    async fn ask(&self, scans: &Scans) {
        let now = jiff::Timestamp::now().as_second();
        let limiter = scans
            .limiter
            .get_or_init(|| async {
                let asked = self
                    .store
                    .virustotal_asked(now - 86_400)
                    .await
                    .unwrap_or_else(|e| {
                        warn!(error.message = %e, "analysis store cannot answer; VirusTotal's daily count starts at 0");
                        Vec::new()
                    });
                let ago: Vec<u64> = asked.iter().map(|at| (now - at).max(0) as u64).collect();
                Limiter::new(scans.per_minute, scans.per_day, &ago)
            })
            .await;
        limiter.ask().await;
        if let Err(e) = self
            .store
            .put_virustotal_asked(jiff::Timestamp::now().as_second())
            .await
        {
            warn!(error.message = %e, "analysis store cannot record a VirusTotal request");
        }
    }

    /// Store what VirusTotal said about `job`'s artifact under its digest.
    async fn put_scanned(&self, job: &ScanJob, scanned: &Scanned) {
        if let Err(e) = self.store.put_scanned(&job.digest, scanned).await {
            warn!(url.full = %job.url, error.message = %e, "virustotal: not stored");
            return;
        }
        report(job, scanned);
    }
}

/// Log what VirusTotal said about `job`'s artifact.
fn report(job: &ScanJob, scanned: &Scanned) {
    match &scanned.verdict {
        Verdict::Known(Counts {
            malicious,
            suspicious,
            engines,
        }) => info!(
            url.full = %job.url,
            byrle.virustotal.malicious = malicious,
            byrle.virustotal.suspicious = suspicious,
            byrle.virustotal.engines = engines,
            "virustotal answered"
        ),
        Verdict::Unknown => info!(url.full = %job.url, "virustotal: not known to it"),
        Verdict::Queued(_) => {
            info!(url.full = %job.url, "virustotal: uploaded, analysis queued")
        }
    }
}

/// `verdict` about the file with `sha256`, asked now.
fn scanned(sha256: String, verdict: Verdict) -> Scanned {
    Scanned {
        sha256,
        verdict,
        asked: jiff::Timestamp::now().as_second(),
    }
}

/// A failure as the warning that reports it.
fn said(failure: Failure) -> String {
    failure.to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::run::tests::{analyser, server, sri_of};
    use crate::analysis::store::Analyses;
    use crate::analysis::store::InProcess;
    use crate::analysis::store::tests::Broken;
    use crate::analysis::virustotal::Counts;
    use crate::analysis::virustotal::tests::{UPLOADED, analysis, file, settings};
    use std::sync::Mutex as StdMutex;

    const BYTES: &[u8] = b"the artifact";
    const PATH: &str = "/pkg/-/pkg-1.0.0.tgz";

    fn sha256() -> String {
        use sha2::Digest as _;
        crate::util::hex(&sha2::Sha256::digest(BYTES))
    }

    /// An analyser asking the VirusTotal at `base` in `mode`, which may upload from `base`.
    fn scanning(label: &str, base: &str, mode: Mode, store: Arc<dyn Analyses>) -> Analyser {
        let mut settings = settings(base.to_owned());
        settings.mode = mode;
        settings.uploads_from = vec![format!("{base}/")];
        analyser(label, 1 << 20, store).with_virustotal(Some(&settings))
    }

    fn job(base: &str, bytes: &[u8]) -> ScanJob {
        ScanJob {
            digest: sri_of(bytes),
            url: format!("{base}{PATH}"),
        }
    }

    /// Start `job` with `prior` and wait for it. Returns what is then stored.
    async fn run(analyser: &Analyser, job: ScanJob, prior: Option<Scanned>) -> Option<Scanned> {
        let digest = job.digest.clone();
        analyser
            .start_scan(job, prior, jiff::Timestamp::now().as_second())
            .expect("starts")
            .await
            .expect("finishes");
        analyser.scanned(&digest).await
    }

    fn routes(extra: Vec<(String, u16, Vec<u8>)>) -> Vec<(String, u16, Vec<u8>)> {
        let mut routes = vec![(PATH.to_owned(), 200, BYTES.to_vec())];
        routes.extend(extra);
        routes
    }

    /// The verified bytes' SHA-256 is looked up, and the counts stored with the request.
    #[tokio::test]
    async fn an_artifact_is_hashed_and_its_counts_stored() {
        let (base, asked) = server(routes(vec![(
            format!("/files/{}", sha256()),
            200,
            file(2, 0, 60),
        )]))
        .await;
        let store = Arc::new(InProcess::new(8));
        let analyser = scanning("vt-known", &base, Mode::Hash, store.clone());
        assert!(analyser.scanning());
        let scanned = run(&analyser, job(&base, BYTES), None)
            .await
            .expect("stored");
        assert_eq!(scanned.sha256, sha256());
        assert_eq!(
            scanned.verdict,
            Verdict::Known(Counts {
                malicious: 2,
                suspicious: 0,
                engines: 62
            })
        );
        assert_eq!(
            asked.lock().unwrap().len(),
            2,
            "the artifact, then the lookup"
        );
        assert_eq!(store.virustotal_asked(0).await.unwrap().len(), 1);
        assert_eq!(analyser.scans_started(), 1);
        analyser.scans_ended(1).await;
    }

    /// A file VirusTotal does not know is uploaded only in upload mode, only from a listed
    /// origin, and only within the size limit; above the direct limit through an upload URL.
    #[tokio::test]
    async fn an_unknown_artifact_is_uploaded_only_when_allowed() {
        let (uploads, uploaded) = server(vec![("/up".to_owned(), 200, UPLOADED.to_vec())]).await;
        let up = format!(r#"{{"data":"{uploads}/up"}}"#);
        let (base, asked) = server(routes(vec![
            ("/files".to_owned(), 200, UPLOADED.to_vec()),
            ("/files/upload_url".to_owned(), 200, up.into_bytes()),
        ]))
        .await;
        let fresh = || Arc::new(InProcess::new(8)) as Arc<dyn Analyses>;
        let paths =
            |asked: &Arc<StdMutex<Vec<String>>>| std::mem::take(&mut *asked.lock().unwrap());

        let hash = scanning("vt-hash", &base, Mode::Hash, fresh());
        let scanned = run(&hash, job(&base, BYTES), None).await.expect("stored");
        assert_eq!(scanned.verdict, Verdict::Unknown);
        assert_eq!(
            paths(&asked),
            [PATH.to_owned(), format!("/files/{}", sha256())]
        );

        let upload = scanning("vt-upload", &base, Mode::Upload, fresh());
        let scanned = run(&upload, job(&base, BYTES), None).await.expect("stored");
        assert_eq!(scanned.verdict, Verdict::Queued("an-1".to_owned()));
        assert_eq!(paths(&asked)[2..], ["/files".to_owned()]);

        let mut large = scanning("vt-large", &base, Mode::Upload, fresh());
        large.scans.as_mut().unwrap().upload_limits = (4, 1 << 20);
        let scanned = run(&large, job(&base, BYTES), None).await.expect("stored");
        assert_eq!(scanned.verdict, Verdict::Queued("an-1".to_owned()));
        assert_eq!(paths(&asked)[2..], ["/files/upload_url".to_owned()]);
        assert_eq!(paths(&uploaded), ["/up".to_owned()]);

        let mut too_large = scanning("vt-too-large", &base, Mode::Upload, fresh());
        too_large.scans.as_mut().unwrap().upload_limits = (4, 8);
        let scanned = run(&too_large, job(&base, BYTES), None)
            .await
            .expect("stored");
        assert_eq!(scanned.verdict, Verdict::Unknown);
        assert_eq!(paths(&asked).len(), 2);

        let mut elsewhere = scanning("vt-elsewhere", &base, Mode::Upload, fresh());
        elsewhere.scans.as_mut().unwrap().uploads_from =
            vec!["https://registry.npmjs.org/".to_owned()];
        let scanned = run(&elsewhere, job(&base, BYTES), None)
            .await
            .expect("stored");
        assert_eq!(
            scanned.verdict,
            Verdict::Unknown,
            "a private origin is never uploaded from"
        );
        assert_eq!(paths(&asked).len(), 2);
    }

    /// A queued analysis is polled when due; one not due, or a digest in flight, starts nothing.
    #[tokio::test]
    async fn a_queued_analysis_is_polled_and_a_fresh_answer_is_kept() {
        let (base, _) = server(vec![(
            "/analyses/an-1".to_owned(),
            200,
            analysis("completed", 4),
        )])
        .await;
        let analyser = scanning("vt-poll", &base, Mode::Upload, Arc::new(InProcess::new(8)));
        let queued = Scanned {
            sha256: sha256(),
            verdict: Verdict::Queued("an-1".to_owned()),
            asked: 0,
        };
        let scanned = run(&analyser, job(&base, BYTES), Some(queued.clone()))
            .await
            .expect("stored");
        assert_eq!(scanned.sha256, sha256());
        assert!(matches!(
            scanned.verdict,
            Verdict::Known(Counts { malicious: 4, .. })
        ));

        let (base, _) = server(vec![(
            "/analyses/an-1".to_owned(),
            200,
            analysis("queued", 0),
        )])
        .await;
        let analyser = scanning(
            "vt-poll-queued",
            &base,
            Mode::Upload,
            Arc::new(InProcess::new(8)),
        );
        let scanned = run(&analyser, job(&base, BYTES), Some(queued))
            .await
            .expect("stored");
        assert_eq!(scanned.verdict, Verdict::Queued("an-1".to_owned()));
        assert!(scanned.asked > 0, "asked again now");

        let now = jiff::Timestamp::now().as_second();
        assert!(
            analyser
                .start_scan(job(&base, BYTES), Some(scanned), now)
                .is_none(),
            "not due"
        );
        analyser
            .scans
            .as_ref()
            .unwrap()
            .in_flight
            .lock()
            .unwrap()
            .insert(sri_of(BYTES));
        assert!(
            analyser.start_scan(job(&base, BYTES), None, now).is_none(),
            "in flight"
        );

        let off =
            crate::analysis::run::tests::analyser("vt-off", 1 << 20, Arc::new(InProcess::new(8)));
        assert!(!off.scanning());
        assert!(off.start_scan(job(&base, BYTES), None, now).is_none());
        assert_eq!(off.scans_started(), 0);
        off.scans_ended(1).await;
    }

    /// Nothing is stored when the artifact cannot be fetched, verified or spooled, or when
    /// VirusTotal does not answer; a store that fails is warned about, not panicked on.
    #[tokio::test]
    async fn nothing_is_stored_without_an_answer() {
        let (base, _) = server(routes(vec![(
            format!("/files/{}", sha256()),
            429,
            Vec::new(),
        )]))
        .await;
        let none = |label: &'static str, base: String, bytes: &'static [u8], url: &'static str| async move {
            let analyser = scanning(label, &base, Mode::Hash, Arc::new(InProcess::new(8)));
            let mut job = job(&base, bytes);
            job.url = format!("{base}{url}");
            run(&analyser, job, None).await
        };
        assert_eq!(none("vt-quota", base.clone(), BYTES, PATH).await, None);
        assert_eq!(
            none("vt-missing", base.clone(), BYTES, "/absent.tgz").await,
            None
        );
        assert_eq!(
            none("vt-mismatch", base.clone(), b"other bytes", PATH).await,
            None
        );
        let small = analyser("vt-small", 4, Arc::new(InProcess::new(8)))
            .with_virustotal(Some(&settings(base.clone())));
        assert_eq!(
            run(&small, job(&base, BYTES), None).await,
            None,
            "over the spool's ceiling"
        );

        let (base, _) = server(routes(vec![(
            format!("/files/{}", sha256()),
            200,
            file(0, 0, 9),
        )]))
        .await;
        let broken = scanning("vt-broken", &base, Mode::Hash, Arc::new(Broken));
        assert_eq!(run(&broken, job(&base, BYTES), None).await, None);
    }

    /// A poll, an upload URL or an upload VirusTotal refuses stores nothing.
    #[tokio::test]
    async fn a_refused_poll_or_upload_stores_nothing() {
        let (base, _) = server(routes(vec![
            ("/analyses/an-1".to_owned(), 429, Vec::new()),
            ("/files".to_owned(), 429, Vec::new()),
            ("/files/upload_url".to_owned(), 429, Vec::new()),
        ]))
        .await;
        let fresh = || Arc::new(InProcess::new(8)) as Arc<dyn Analyses>;
        let queued = Scanned {
            sha256: sha256(),
            verdict: Verdict::Queued("an-1".to_owned()),
            asked: 0,
        };
        let polled = scanning("vt-poll-refused", &base, Mode::Upload, fresh());
        assert_eq!(run(&polled, job(&base, BYTES), Some(queued)).await, None);
        let upload = scanning("vt-upload-refused", &base, Mode::Upload, fresh());
        assert_eq!(run(&upload, job(&base, BYTES), None).await, None);
        let mut large = scanning("vt-url-refused", &base, Mode::Upload, fresh());
        large.scans.as_mut().unwrap().upload_limits = (4, 1 << 20);
        assert_eq!(run(&large, job(&base, BYTES), None).await, None);
    }

    /// The day's requests the store recorded count against the limit after a restart.
    #[tokio::test]
    async fn the_limiter_starts_from_the_requests_the_store_recorded() {
        let store = Arc::new(InProcess::new(8));
        let now = jiff::Timestamp::now().as_second();
        store.put_virustotal_asked(now - 30).await.unwrap();
        store.put_virustotal_asked(now - 5 * 86_400).await.unwrap();
        let (base, _) = server(routes(vec![(
            format!("/files/{}", sha256()),
            200,
            file(0, 0, 9),
        )]))
        .await;
        let analyser = scanning("vt-seeded", &base, Mode::Hash, store.clone());
        run(&analyser, job(&base, BYTES), None)
            .await
            .expect("stored");
        let limiter = analyser
            .scans
            .as_ref()
            .unwrap()
            .limiter
            .get()
            .expect("made");
        assert_eq!(
            limiter.asked.lock().await.len(),
            2,
            "the recent one and this one"
        );
        assert_eq!(store.virustotal_asked(now - 86_400).await.unwrap().len(), 2);
    }
}
