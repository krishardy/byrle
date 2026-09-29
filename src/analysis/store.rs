//! What analysing an artifact found, kept under the digest of the bytes that were read.
//!
//! [`crate::verified`] answers whether these bytes have been past before. This answers
//! what was found in them, which is what a cache hit saves:
//! `docs/engineering_decisions/fetch-path-branching.md` defers and analyses a novel
//! artifact, and streams one that was analysed before straight through.
//!
//! The key is the artifact's content digest, not the package. A registry that repoints a
//! version at different bytes produces a different key, so those bytes are analysed.
//!
//! # Why a trait
//!
//! The same reason as [`crate::intel::store`]: everything above this seam is unit-tested
//! with no database. [`crate::env::DATABASE_URL`] is optional, and a proxy started without one
//! uses [`InProcess`], which dies with the process.

use crate::analysis::attestation::Attested;
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
    /// The archive could not be read, so it was never asked. Carries what [`ReadError`]
    /// said. Not the same as declaring none: `crate::analysis` keeps the two apart
    /// because not knowing is not the same as knowing there is no script.
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
    /// The package the artifact was fetched as. The digest is the key; this is what an
    /// operator reading a row needs to know which package it was.
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub scripts: Scripts,
}

/// Why an analysis could not be read or written.
#[derive(Debug)]
pub enum AnalysisError {
    /// The database said no. A caller that reads this as "not analysed before" analyses
    /// the artifact again, which is the safe direction and costs a deferral per request.
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

/// A read or write in flight. Boxed so the proxy can hold a store as `dyn Analyses`,
/// which an `async fn` in a trait does not allow.
pub type Stored<'a, T> = Pin<Box<dyn Future<Output = Result<T, AnalysisError>> + Send + 'a>>;

/// Where analyses are kept, and the seam that lets the fetch path be tested without a
/// database.
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
}

/// The analyses this process has made, bounded by count, least recently used evicted
/// first.
///
/// What a proxy started without [`crate::env::DATABASE_URL`] uses. It dies with the process, so
/// a restarted proxy analyses each artifact once more, and a second proxy shares nothing
/// with it.
pub struct InProcess(Mutex<Lru<Sri, Analysis>>, Mutex<Lru<Sri, Attested>>);

impl InProcess {
    /// `max_entries` analyses, and as many attestation results.
    pub fn new(max_entries: usize) -> Self {
        Self(
            Mutex::new(Lru::new(max_entries)),
            Mutex::new(Lru::new(max_entries)),
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

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
        // Reading 1 makes 2 the oldest.
        assert!(store.get(&sri(1)).await.expect("it answers").is_some());
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
