//! What analysing an artifact found, kept under the digest of the bytes that were read.
//!
//! See `docs/engineering_decisions/artifact-analysis-store.md`.

use crate::analysis::attestation::Attested;
use crate::analysis::detector::Detection;
use crate::analysis::source::Sourced;
use crate::analysis::virustotal::Scanned;
use crate::analysis::{InstallScripts, ReadError};
use crate::integrity::Sri;
use crate::util::lru::Lru;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

/// What the install-script reader answered about one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scripts {
    /// The archive was read. Carries what it declares, which may be nothing.
    Declared(InstallScripts),
    /// The archive could not be read. Carries what [`ReadError`] said.
    Unreadable(String),
}

impl Scripts {
    /// What a reader in `crate::analysis` returned, as the store holds it.
    pub fn of(read: Result<InstallScripts, ReadError>) -> Self {
        match read {
            Ok(found) => Self::Declared(found),
            Err(e) => Self::Unreadable(e.to_string()),
        }
    }

    /// The scripts that run on install, empty when the archive declares none. `None` when
    /// it could not be read, which no caller may read as "runs nothing".
    pub fn names(&self) -> Option<&[String]> {
        match self {
            Self::Declared(found) => Some(&found.names),
            Self::Unreadable(_) => None,
        }
    }
}

/// What the detectors found in one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// The ecosystem of the package the artifact was fetched as.
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub scripts: Scripts,
}

/// Which run of which detector on which version a [`Detection`] is kept under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectionKey {
    pub detector: String,
    /// The detector's version. A result another version wrote is not read back.
    pub detector_version: String,
    pub ecosystem: String,
    /// The registry name, as `PackageKey::registry_name` gives it.
    pub name: String,
    pub version: String,
}

/// Why an analysis could not be read or written.
#[derive(Debug)]
pub enum AnalysisError {
    /// The database returned an error.
    Backend(sqlx::Error),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "analysis store: {e}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

/// A read or write in flight, boxed so the proxy can hold a `dyn Analyses`.
pub type Stored<'a, T> = Pin<Box<dyn Future<Output = Result<T, AnalysisError>> + Send + 'a>>;

/// Where analyses are kept.
pub trait Analyses: Send + Sync {
    /// What was found in these bytes before. `Ok(None)` is an artifact nothing has
    /// analysed, which the fetch path defers and analyses.
    fn get<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Analysis>>;

    /// Record what was found in these bytes, replacing what was held under the same
    /// digest. Two clients can ask for one artifact at once, and each analysed the same
    /// bytes, so a second write is not an error.
    fn put<'a>(&'a self, digest: &'a Sri, analysis: &'a Analysis) -> Stored<'a, ()>;

    /// What verifying the attestations of the artifact with this digest found. `Ok(None)`
    /// is an artifact whose attestations nothing has verified.
    fn attested<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Attested>>;

    /// Record what verifying them found, replacing what was held under the same digest.
    fn put_attested<'a>(&'a self, digest: &'a Sri, attested: &'a Attested) -> Stored<'a, ()>;

    /// What comparing the artifact with this digest with its source found, by the current
    /// [`crate::analysis::source::COMPARER`]. `Ok(None)` is an artifact not compared yet.
    fn sourced<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Sourced>>;

    /// Record what comparing it found, replacing what was held under the same digest.
    fn put_sourced<'a>(&'a self, digest: &'a Sri, sourced: &'a Sourced) -> Stored<'a, ()>;

    /// What the detector run `key` names found. `Ok(None)` is a run not made yet.
    fn detected<'a>(&'a self, key: &'a DetectionKey) -> Stored<'a, Option<Detection>>;

    /// Record what it found, replacing what an earlier run of any version wrote.
    fn put_detected<'a>(
        &'a self,
        key: &'a DetectionKey,
        detection: &'a Detection,
    ) -> Stored<'a, ()>;

    /// What VirusTotal said about the artifact with this digest. `Ok(None)` is not asked yet.
    fn scanned<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Scanned>>;

    /// Record what it said, replacing what was held under the same digest.
    fn put_scanned<'a>(&'a self, digest: &'a Sri, scanned: &'a Scanned) -> Stored<'a, ()>;

    /// When each request to VirusTotal after `since` was made, in Unix seconds.
    fn virustotal_asked(&self, since: i64) -> Stored<'_, Vec<i64>>;

    /// Record a request made at `at`, Unix seconds.
    fn put_virustotal_asked(&self, at: i64) -> Stored<'_, ()>;
}

/// The analyses this process has made, least recently used evicted first.
pub struct InProcess(
    Mutex<Lru<Sri, Analysis>>,
    Mutex<Lru<Sri, Attested>>,
    Mutex<Lru<Sri, Sourced>>,
    Mutex<Lru<DetectionKey, Detection>>,
    Mutex<Lru<Sri, Scanned>>,
    Mutex<Vec<i64>>,
);

impl InProcess {
    /// `max_entries` analyses, and as many attestation, source, detector and VirusTotal
    /// results.
    pub fn new(max_entries: usize) -> Self {
        Self(
            Mutex::new(Lru::new(max_entries)),
            Mutex::new(Lru::new(max_entries)),
            Mutex::new(Lru::new(max_entries)),
            Mutex::new(Lru::new(max_entries)),
            Mutex::new(Lru::new(max_entries)),
            Mutex::default(),
        )
    }

    pub fn len(&self) -> usize {
        self.held().len()
    }

    pub fn is_empty(&self) -> bool {
        self.held().is_empty()
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Lru<Sri, Analysis>> {
        self.0.lock().expect("analysis store lock")
    }
}

impl Analyses for InProcess {
    fn get<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Analysis>> {
        Box::pin(async move { Ok(self.held().get(digest).cloned()) })
    }

    fn put<'a>(&'a self, digest: &'a Sri, analysis: &'a Analysis) -> Stored<'a, ()> {
        Box::pin(async move {
            self.held().insert(digest.clone(), analysis.clone());
            Ok(())
        })
    }

    fn attested<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Attested>> {
        Box::pin(async move {
            Ok(self
                .1
                .lock()
                .expect("attestation store lock")
                .get(digest)
                .cloned())
        })
    }

    fn put_attested<'a>(&'a self, digest: &'a Sri, attested: &'a Attested) -> Stored<'a, ()> {
        Box::pin(async move {
            self.1
                .lock()
                .expect("attestation store lock")
                .insert(digest.clone(), attested.clone());
            Ok(())
        })
    }

    fn sourced<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Sourced>> {
        Box::pin(async move {
            Ok(self
                .2
                .lock()
                .expect("source store lock")
                .get(digest)
                .cloned())
        })
    }

    fn put_sourced<'a>(&'a self, digest: &'a Sri, sourced: &'a Sourced) -> Stored<'a, ()> {
        Box::pin(async move {
            self.2
                .lock()
                .expect("source store lock")
                .insert(digest.clone(), sourced.clone());
            Ok(())
        })
    }

    fn detected<'a>(&'a self, key: &'a DetectionKey) -> Stored<'a, Option<Detection>> {
        Box::pin(async move {
            Ok(self
                .3
                .lock()
                .expect("detection store lock")
                .get(key)
                .cloned())
        })
    }

    fn put_detected<'a>(
        &'a self,
        key: &'a DetectionKey,
        detection: &'a Detection,
    ) -> Stored<'a, ()> {
        Box::pin(async move {
            self.3
                .lock()
                .expect("detection store lock")
                .insert(key.clone(), detection.clone());
            Ok(())
        })
    }

    fn scanned<'a>(&'a self, digest: &'a Sri) -> Stored<'a, Option<Scanned>> {
        Box::pin(async move {
            Ok(self
                .4
                .lock()
                .expect("virustotal store lock")
                .get(digest)
                .cloned())
        })
    }

    fn put_scanned<'a>(&'a self, digest: &'a Sri, scanned: &'a Scanned) -> Stored<'a, ()> {
        Box::pin(async move {
            self.4
                .lock()
                .expect("virustotal store lock")
                .insert(digest.clone(), scanned.clone());
            Ok(())
        })
    }

    fn virustotal_asked(&self, since: i64) -> Stored<'_, Vec<i64>> {
        Box::pin(async move {
            let asked = self.5.lock().expect("virustotal request lock");
            Ok(asked.iter().copied().filter(|at| *at > since).collect())
        })
    }

    fn put_virustotal_asked(&self, at: i64) -> Stored<'_, ()> {
        Box::pin(async move {
            let mut asked = self.5.lock().expect("virustotal request lock");
            asked.retain(|held| at - held < 2 * 86_400);
            asked.push(at);
            Ok(())
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    /// A store that answers every read and write with an error.
    pub struct Broken;

    fn broken<'a, T: Send + 'a>() -> Stored<'a, T> {
        Box::pin(async { Err(AnalysisError::Backend(sqlx::Error::PoolClosed)) })
    }

    impl Analyses for Broken {
        fn get<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Analysis>> {
            broken()
        }
        fn put<'a>(&'a self, _: &'a Sri, _: &'a Analysis) -> Stored<'a, ()> {
            broken()
        }
        fn attested<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Attested>> {
            broken()
        }
        fn put_attested<'a>(&'a self, _: &'a Sri, _: &'a Attested) -> Stored<'a, ()> {
            broken()
        }
        fn sourced<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Sourced>> {
            broken()
        }
        fn scanned<'a>(&'a self, _: &'a Sri) -> Stored<'a, Option<Scanned>> {
            broken()
        }
        fn put_scanned<'a>(&'a self, _: &'a Sri, _: &'a Scanned) -> Stored<'a, ()> {
            broken()
        }
        fn virustotal_asked(&self, _: i64) -> Stored<'_, Vec<i64>> {
            broken()
        }
        fn put_virustotal_asked(&self, _: i64) -> Stored<'_, ()> {
            broken()
        }
        fn put_sourced<'a>(&'a self, _: &'a Sri, _: &'a Sourced) -> Stored<'a, ()> {
            broken()
        }
        fn detected<'a>(&'a self, _: &'a DetectionKey) -> Stored<'a, Option<Detection>> {
            broken()
        }
        fn put_detected<'a>(&'a self, _: &'a DetectionKey, _: &'a Detection) -> Stored<'a, ()> {
            broken()
        }
    }

    pub fn sri(seed: u8) -> Sri {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![seed; 64]);
        Sri::parse(&format!("sha512-{encoded}")).expect("the digest parses")
    }

    fn analysis(scripts: Scripts) -> Analysis {
        Analysis {
            ecosystem: "npm".to_owned(),
            name: "bufferutil".to_owned(),
            version: "4.1.0".to_owned(),
            scripts,
        }
    }

    fn runs(name: &str, body: &str) -> Scripts {
        Scripts::Declared(InstallScripts {
            names: vec![name.to_owned()],
            bodies: vec![(name.to_owned(), body.to_owned())],
        })
    }

    #[tokio::test]
    async fn an_artifact_is_unanalysed_until_one_is_recorded() {
        let store = InProcess::new(4);
        assert!(store.is_empty());
        assert_eq!(store.get(&sri(1)).await.expect("the store answers"), None);

        let found = analysis(runs("install", "node-gyp-build"));
        store.put(&sri(1), &found).await.expect("the store writes");

        assert_eq!(
            store.get(&sri(1)).await.expect("the store answers"),
            Some(found)
        );
        assert!(!store.is_empty());
        assert_eq!(
            store.get(&sri(2)).await.expect("the store answers"),
            None,
            "a different artifact"
        );
        assert_eq!(store.len(), 1);
    }

    /// A detector's result is kept under its run: another detector version reads nothing.
    #[tokio::test]
    async fn a_detection_is_kept_under_its_run() {
        let store = InProcess::new(4);
        let key = DetectionKey {
            detector: "guarddog".to_owned(),
            detector_version: "3.2.0".to_owned(),
            ecosystem: "npm".to_owned(),
            name: "widget".to_owned(),
            version: "1.0.0".to_owned(),
        };
        assert_eq!(store.detected(&key).await.expect("answers"), None);
        let found = Detection::default();
        store.put_detected(&key, &found).await.expect("writes");
        assert_eq!(store.detected(&key).await.expect("answers"), Some(found));
        let newer = DetectionKey {
            detector_version: "3.3.0".to_owned(),
            ..key
        };
        assert_eq!(store.detected(&newer).await.expect("answers"), None);
    }

    #[tokio::test]
    async fn a_source_comparison_is_kept_until_replaced() {
        let store = InProcess::new(4);
        assert_eq!(store.sourced(&sri(1)).await.expect("answers"), None);
        let not = Sourced::NotCompared("why".to_owned());
        store.put_sourced(&sri(1), &not).await.expect("writes");
        assert_eq!(store.sourced(&sri(1)).await.expect("answers"), Some(not));
    }

    /// Two clients asking for one artifact at once both analysed the same bytes.
    #[tokio::test]
    async fn recording_the_same_digest_twice_holds_one_analysis() {
        let store = InProcess::new(4);
        let found = analysis(runs("postinstall", "node install.js"));
        store.put(&sri(1), &found).await.expect("the store writes");
        store.put(&sri(1), &found).await.expect("the store writes");
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn the_budget_evicts_least_recently_used_analyses() {
        let store = InProcess::new(2);
        let found = analysis(Scripts::Declared(InstallScripts::default()));
        for seed in [1, 2] {
            store.put(&sri(seed), &found).await.expect("it writes");
        }
        assert!(
            store.get(&sri(1)).await.expect("it answers").is_some(),
            "reading 1 makes 2 the oldest"
        );
        store.put(&sri(3), &found).await.expect("it writes");

        assert_eq!(store.len(), 2);
        assert!(store.get(&sri(1)).await.expect("it answers").is_some());
        assert!(store.get(&sri(3)).await.expect("it answers").is_some());
        assert!(
            store.get(&sri(2)).await.expect("it answers").is_none(),
            "evicted"
        );
    }

    /// An archive that could not be read is stored as that, so the next request for the
    /// same bytes reads "not known" rather than "runs nothing".
    #[test]
    fn an_unreadable_archive_is_not_an_archive_that_declares_nothing() {
        let unreadable = Scripts::of(Err(ReadError::NothingToRead));
        assert_eq!(
            unreadable,
            Scripts::Unreadable("the archive holds no manifest to read".to_owned())
        );
        assert_eq!(unreadable.names(), None);

        let none = Scripts::of(Ok(InstallScripts::default()));
        assert_eq!(none, Scripts::Declared(InstallScripts::default()));
        assert_eq!(none.names(), Some(&[][..]));
    }

    #[test]
    fn a_read_archive_carries_the_scripts_it_declares() {
        let scripts = Scripts::of(Ok(InstallScripts {
            names: vec!["postinstall".to_owned()],
            bodies: vec![("postinstall".to_owned(), "node install.js".to_owned())],
        }));
        assert_eq!(scripts.names(), Some(&["postinstall".to_owned()][..]));
    }

    #[test]
    fn a_backend_failure_names_the_store_it_came_from() {
        let error = AnalysisError::Backend(sqlx::Error::PoolTimedOut);
        assert_eq!(
            error.to_string(),
            "analysis store: pool timed out while waiting for an open connection"
        );
    }
}
