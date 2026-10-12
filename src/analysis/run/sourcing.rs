//! Comparing an artifact with the source its metadata names, beside the analysis and never
//! in front of it: no request is deferred for it. See docs/engineering_decisions/source-diff.md.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::{Analyser, InFlight};
use crate::analysis::ReadError;
use crate::analysis::source::{self, Layout, MAX_SOURCE_BYTES, Repo, Sourced, Tree};
use crate::identity::Ecosystem;
use crate::integrity::Sri;
use crate::record::PackageRecord;
use crate::spool::{Spooled, WriteError};
use crate::util::lru::Lru;

/// How many comparisons run at once, apart from the analyses a client waits on.
pub const SOURCE_SLOTS: usize = 2;

/// Source archives kept read, so one repository's packages, such as binaries, fetch it once.
pub const SOURCE_TREES: usize = 8;

/// One artifact to compare with its source.
#[derive(Debug, Clone)]
pub struct SourceJob {
    /// The digest the metadata published. The result is stored under it.
    pub digest: Sri,
    /// Where the proxy fetches the artifact from.
    pub url: String,
    /// The package's name, as the source's manifest spells it.
    pub name: String,
    pub ecosystem: Ecosystem,
    pub layout: Layout,
    /// The repository the npm metadata names. `None` for PyPI, whose artifact names it.
    pub repo: Option<Repo>,
    /// The metadata's `repository.directory`, for a package in a monorepo.
    pub directory: Option<String>,
    /// The commit or tags to try, in order, from [`source::references`].
    pub references: Vec<String>,
}

impl SourceJob {
    /// The job for `record`'s artifact `filename` with `digest`, fetched from `url`.
    /// Returns `None` for an npm record naming no repository on GitHub, or a file this does
    /// not read.
    pub fn of(record: &PackageRecord, filename: &str, digest: &Sri, url: String) -> Option<Self> {
        let ecosystem = record.package.key().ecosystem();
        let (repo, directory) = match ecosystem {
            Ecosystem::Npm => {
                let repository = record.repository.as_ref()?;
                (
                    Some(Repo::from_url(&repository.url)?),
                    repository.directory.clone(),
                )
            }
            Ecosystem::PyPI => (None, None),
        };
        Some(Self {
            digest: digest.clone(),
            url,
            name: record.package.key().registry_name(),
            ecosystem,
            layout: Layout::of(ecosystem, filename)?,
            repo,
            directory,
            references: source::references(record),
        })
    }
}

/// The comparisons' own host, slots and cache, apart from the analyses a client waits on.
#[derive(Clone)]
pub(super) struct Sources {
    /// GitHub's archive host, or a mirror of it.
    base: String,
    slots: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<Sri>>>,
    /// The archives read, by URL.
    archives: Arc<Mutex<Lru<String, Archive>>>,
    /// How many comparisons have started.
    started: Arc<std::sync::atomic::AtomicU64>,
    ended: Arc<watch::Sender<u64>>,
}

impl Sources {
    /// Comparisons that fetch source archives from `base`.
    pub(super) fn new(base: String) -> Self {
        Self {
            base,
            slots: Arc::new(Semaphore::new(SOURCE_SLOTS)),
            in_flight: Arc::default(),
            archives: Arc::new(Mutex::new(Lru::new(SOURCE_TREES))),
            started: Arc::default(),
            ended: Arc::new(watch::Sender::new(0)),
        }
    }
}

/// What one source archive URL answered.
#[derive(Clone)]
enum Archive {
    Tree(Arc<Tree>),
    /// A 404: no such commit or tag.
    Absent,
    /// Too large, or not an archive, and why.
    Unreadable(String),
}

impl Analyser {
    /// Compare artifacts with their sources from `base`, GitHub's archive host or a mirror.
    /// `None` leaves the comparison off.
    pub fn with_sources(mut self, base: Option<String>) -> Self {
        self.sources = base.map(Sources::new);
        self
    }

    /// What comparing the artifact with `digest` with its source found. A store that
    /// cannot answer is `None`, and it is compared again.
    pub async fn sourced(&self, digest: &Sri) -> Option<Sourced> {
        match self.store.sourced(digest).await {
            Ok(sourced) => sourced,
            Err(e) => {
                warn!(byrle.artifact.digest = %digest, error.message = %e, "analysis store cannot answer; comparing with the source again");
                None
            }
        }
    }

    /// Start comparing `job` unless the comparison is off or its digest is being compared.
    /// The handle is for a test to wait on. The proxy drops it.
    pub fn start_source(&self, job: SourceJob) -> Option<JoinHandle<()>> {
        let sources = self.sources.clone()?;
        if !sources
            .in_flight
            .lock()
            .expect("source in-flight lock")
            .insert(job.digest.clone())
        {
            return None;
        }
        sources
            .started
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let guard = InFlight {
            set: sources.in_flight.clone(),
            key: job.digest.clone(),
            ended: sources.ended.clone(),
        };
        let analyser = self.clone();
        Some(tokio::spawn(async move {
            let _guard = guard;
            let _slot = sources
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            match tokio::time::timeout(analyser.deadline, analyser.compared(&job, &sources)).await {
                Ok(Some(sourced)) => analyser.put_sourced(&job, &sourced).await,
                Ok(None) => {}
                Err(_) => {
                    warn!(url.full = %job.url, "source comparison: past its deadline, nothing stored");
                }
            }
        }))
    }

    /// How many comparisons have started since this analyser was made. 0 when it is off.
    pub fn sources_started(&self) -> u64 {
        self.sources.as_ref().map_or(0, |sources| {
            sources.started.load(std::sync::atomic::Ordering::Relaxed)
        })
    }

    /// Wait until `count` comparisons have ended since this analyser was made.
    pub async fn sources_ended(&self, count: u64) {
        if let Some(sources) = &self.sources {
            let _ = sources
                .ended
                .subscribe()
                .wait_for(|ended| *ended >= count)
                .await;
        }
    }

    /// What comparing `job`'s artifact with its source found.
    /// Returns `None` when nothing should be stored: an artifact or archive that could not be
    /// fetched, bytes that do not match the digest, or no reference found yet.
    async fn compared(&self, job: &SourceJob, sources: &Sources) -> Option<Sourced> {
        let response = self.fetch(&job.url).await?;
        let package = match self
            .spool_verified(&job.url, &job.digest, response, |_| {})
            .await
        {
            Some(Ok(spooled)) => tree_of(spooled, job.layout).await,
            Some(Err(too_large)) => Some(Err(format!("the artifact: {too_large}"))),
            None => None,
        };
        let package = match package? {
            Ok(package) => package,
            Err(why) => return Some(Sourced::NotCompared(why)),
        };
        let Some(repo) = job.repo.clone().or_else(|| {
            package
                .metadata
                .as_deref()
                .and_then(source::pypi_repository)
        }) else {
            return Some(Sourced::NotCompared(
                "the artifact's metadata names no repository on GitHub".to_owned(),
            ));
        };
        for reference in &job.references {
            let Some(url) = repo.archive_url(&sources.base, reference) else {
                continue;
            };
            let built = match self.archive(sources, &url).await? {
                Archive::Absent => continue,
                Archive::Unreadable(why) => return Some(Sourced::NotCompared(why)),
                Archive::Tree(tree) => tree,
            };
            let (comparison, unfound) = match job.ecosystem {
                Ecosystem::Npm => (
                    built
                        .package(&job.name, job.directory.as_deref())
                        .map(|built| source::compare(&package, &built)),
                    "no package.json in the source names the package",
                ),
                Ecosystem::PyPI => (
                    source::compare_pypi(&package, &built, job.layout),
                    "none of the package's Python files is in the source",
                ),
            };
            return Some(match comparison {
                Some(comparison) => Sourced::Compared {
                    repository: format!("{}/{}", repo.owner, repo.name),
                    reference: reference.clone(),
                    comparison: Box::new(comparison),
                },
                None => Sourced::NotCompared(unfound.to_owned()),
            });
        }
        info!(url.full = %job.url, "source comparison: no commit or tag found yet, nothing stored");
        None
    }

    /// The archive at `url`, from the cache or fetched and read now.
    /// Returns `None` when it could not be fetched, which is tried again later.
    async fn archive(&self, sources: &Sources, url: &str) -> Option<Archive> {
        let cached = sources
            .archives
            .lock()
            .expect("source archive lock")
            .get(&url.to_owned())
            .cloned();
        if let Some(cached) = cached {
            return Some(cached);
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| warn!(url.full = %url, error.message = %e, "source comparison: fetch failed, nothing stored"))
            .ok()?;
        let archive = if response.status() == reqwest::StatusCode::NOT_FOUND {
            Archive::Absent
        } else if !response.status().is_success() {
            warn!(url.full = %url, http.response.status_code = response.status().as_u16(), "source comparison: not answered, nothing stored");
            return None;
        } else {
            let claimed = response.content_length();
            let read = match self
                .spool
                .write(response.bytes_stream(), claimed, |_| {})
                .await
            {
                Ok(spooled) => tree_of(spooled, Layout::Tar).await.map(|read| match read {
                    Ok(tree) => Archive::Tree(Arc::new(tree)),
                    Err(why) => Archive::Unreadable(format!("the source archive: {why}")),
                }),
                Err(too_large @ WriteError::TooLarge { .. }) => Some(Archive::Unreadable(format!(
                    "the source archive: {too_large}"
                ))),
                Err(e) => {
                    warn!(url.full = %url, error.message = %e, "source comparison: not spooled, nothing stored");
                    None
                }
            };
            read?
        };
        sources
            .archives
            .lock()
            .expect("source archive lock")
            .insert(url.to_owned(), archive.clone());
        Some(archive)
    }

    /// Store what comparing `job` found under its digest.
    async fn put_sourced(&self, job: &SourceJob, sourced: &Sourced) {
        if let Err(e) = self.store.put_sourced(&job.digest, sourced).await {
            warn!(url.full = %job.url, error.message = %e, "source comparison: not stored");
            return;
        }
        match sourced {
            Sourced::Compared {
                repository,
                reference,
                comparison,
            } => info!(
                url.full = %job.url,
                byrle.source.repository = %repository,
                byrle.source.reference = %reference,
                byrle.source.differing = comparison.differing.len(),
                byrle.source.only_in_package = comparison.only_in_package.len(),
                "source compared"
            ),
            Sourced::NotCompared(why) => {
                info!(url.full = %job.url, byrle.source.not_compared = %why, "source not compared");
            }
        }
    }
}

/// The spooled archive read as a [`Tree`], or why it could not be.
/// Returns `None` when the spool file could not be opened.
async fn tree_of(spooled: Spooled, layout: Layout) -> Option<Result<Tree, String>> {
    let read = tokio::task::spawn_blocking(move || {
        let file = std::io::BufReader::new(spooled.reader()?);
        Ok(match layout {
            Layout::Tar => source::tree(&mut { file }, MAX_SOURCE_BYTES),
            Layout::Wheel => source::wheel_tree(file, MAX_SOURCE_BYTES),
        })
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|read: std::io::Result<Result<Tree, ReadError>>| read);
    match read {
        Ok(tree) => Some(tree.map_err(|e| e.to_string())),
        Err(e) => {
            warn!(error.message = %e, "source comparison: the spool file could not be read, nothing stored");
            None
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::run::tests::{analyser, server, sri_of};
    use crate::analysis::store::InProcess;
    use crate::util::test_support::tarball;
    use std::time::Duration;

    const HEAD: &str = "0123456789abcdef0123456789abcdef01234567";

    fn package() -> Vec<u8> {
        tarball(&[
            (
                "package/package.json",
                br#"{"name":"pkg","version":"1.0.0","scripts":{"postinstall":"node x.js"}}"#,
            ),
            ("package/x.js", b"published"),
        ])
    }

    fn source() -> Vec<u8> {
        tarball(&[
            ("r-v1/package.json", br#"{"name":"pkg","version":"1.0.0"}"#),
            ("r-v1/x.js", b"source"),
        ])
    }

    fn job(base: &str, bytes: &[u8], references: &[&str]) -> SourceJob {
        SourceJob {
            digest: sri_of(bytes),
            url: format!("{base}/pkg/-/pkg-1.0.0.tgz"),
            name: "pkg".to_owned(),
            ecosystem: Ecosystem::Npm,
            layout: Layout::Tar,
            repo: Some(Repo {
                owner: "o".to_owned(),
                name: "r".to_owned(),
            }),
            directory: None,
            references: references.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    fn comparing(label: &str, base: &str, ceiling: u64) -> Analyser {
        analyser(label, ceiling, Arc::new(InProcess::new(8))).with_sources(Some(base.to_owned()))
    }

    async fn run(analyser: &Analyser, job: SourceJob) -> Option<Sourced> {
        let digest = job.digest.clone();
        analyser
            .start_source(job)
            .expect("starts")
            .await
            .expect("finishes");
        analyser.sourced(&digest).await
    }

    /// The commit is tried before the tag, the source lacks the install script and file, and
    /// a second package from the same archive reads it from the cache.
    #[tokio::test]
    async fn an_artifact_is_compared_with_the_first_reference_found() {
        let (base, asked) = server(vec![
            ("/pkg/-/pkg-1.0.0.tgz".to_owned(), 200, package()),
            ("/o/r/tar.gz/v1.0.0".to_owned(), 200, source()),
            (
                "/binding.tgz".to_owned(),
                200,
                tarball(&[
                    (
                        "package/package.json",
                        br#"{"name":"pkg","version":"1.0.0"}"#,
                    ),
                    ("package/x.js", b"source"),
                ]),
            ),
        ])
        .await;
        let analyser = comparing("source-compared", &base, 1 << 20);
        let sourced = run(&analyser, job(&base, &package(), &[HEAD, "a b", "v1.0.0"])).await;
        let Some(Sourced::Compared {
            repository,
            reference,
            comparison,
        }) = sourced
        else {
            panic!("compared: {sourced:?}");
        };
        assert_eq!((repository.as_str(), reference.as_str()), ("o/r", "v1.0.0"));
        assert_eq!(comparison.lifecycle_scripts, ["postinstall"]);
        assert_eq!(comparison.differing, ["x.js"]);

        let binding = tarball(&[
            (
                "package/package.json",
                br#"{"name":"pkg","version":"1.0.0"}"#,
            ),
            ("package/x.js", b"source"),
        ]);
        let again = SourceJob {
            url: format!("{base}/binding.tgz"),
            ..job(&base, &binding, &[HEAD, "v1.0.0"])
        };
        assert!(matches!(
            run(&analyser, again).await,
            Some(Sourced::Compared { comparison, .. }) if comparison.differing.is_empty()
        ));
        let mismatched = job(&base, b"another digest", &["v1.0.0"]);
        assert_eq!(
            run(&analyser, mismatched).await,
            None,
            "bytes that do not match"
        );
        assert_eq!(analyser.sources_started(), 3);
        let asked = asked.lock().unwrap().clone();
        assert_eq!(
            asked.iter().filter(|p| p.contains("tar.gz")).count(),
            2,
            "the commit and the tag once each, for both packages: {asked:?}"
        );
        assert_eq!(
            analyser
                .sources
                .as_ref()
                .unwrap()
                .in_flight
                .lock()
                .unwrap()
                .len(),
            0
        );
    }

    /// What is stored as not compared, and why.
    #[tokio::test]
    async fn what_cannot_be_compared_is_stored_with_the_reason() {
        let unnamed = tarball(&[("r-v1/package.json", br#"{"name":"other","version":"1"}"#)]);
        let (base, _) = server(vec![
            ("/pkg/-/pkg-1.0.0.tgz".to_owned(), 200, package()),
            ("/o/r/tar.gz/unnamed".to_owned(), 200, unnamed),
            ("/o/r/tar.gz/garbage".to_owned(), 200, b"not gzip".to_vec()),
            ("/o/r/tar.gz/huge".to_owned(), 200, vec![7; 4096]),
            ("/garbage.tgz".to_owned(), 200, b"not gzip".to_vec()),
        ])
        .await;
        for (reference, why) in [
            ("unnamed", "no package.json in the source names the package"),
            ("garbage", "the source archive: not readable as an archive"),
            ("huge", "the source archive:"),
        ] {
            let analyser = comparing(&format!("source-{reference}"), &base, 2048);
            let sourced = run(&analyser, job(&base, &package(), &[reference])).await;
            let Some(Sourced::NotCompared(said)) = sourced else {
                panic!("{reference}: {sourced:?}");
            };
            assert!(said.starts_with(why), "{reference}: {said}");
        }

        let analyser = comparing("source-garbage-artifact", &base, 1 << 20);
        let garbage = SourceJob {
            url: format!("{base}/garbage.tgz"),
            ..job(&base, b"not gzip", &["v1.0.0"])
        };
        assert!(matches!(
            run(&analyser, garbage).await,
            Some(Sourced::NotCompared(why)) if why.starts_with("not readable as an archive")
        ));
        let small = comparing("source-small", &base, 16);
        assert!(matches!(
            run(&small, job(&base, &package(), &["v1.0.0"])).await,
            Some(Sourced::NotCompared(why)) if why.starts_with("the artifact:")
        ));
    }

    /// No reference found, a source host that fails, and an artifact that cannot be fetched
    /// store nothing, so a later request compares again.
    #[tokio::test]
    async fn what_may_answer_later_stores_nothing() {
        let (base, _) = server(vec![
            ("/pkg/-/pkg-1.0.0.tgz".to_owned(), 200, package()),
            ("/o/r/tar.gz/failing".to_owned(), 503, Vec::new()),
        ])
        .await;
        let analyser = comparing("source-later", &base, 1 << 20);
        assert_eq!(run(&analyser, job(&base, &package(), &["v9"])).await, None);
        assert_eq!(
            run(&analyser, job(&base, &package(), &["failing"])).await,
            None
        );
        let missing = SourceJob {
            url: format!("{base}/absent.tgz"),
            ..job(&base, &package(), &["v1.0.0"])
        };
        assert_eq!(run(&analyser, missing).await, None);

        let cut = crate::util::test_support::scripted(vec![
            crate::util::test_support::Answer::cut_short(),
        ])
        .await;
        let cut_short = comparing("source-cut", &format!("http://{cut}"), 1 << 20);
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
        assert_eq!(
            run(&cut_short, job(&base, &package(), &["v1.0.0"])).await,
            None
        );
        drop(guard);
        let log = crate::util::test_support::text(&buf);
        assert!(
            log.contains("source comparison: not spooled, nothing stored"),
            "{log}"
        );

        let closed = comparing(
            "source-closed",
            &format!(
                "http://{}",
                crate::util::test_support::closing_server().await
            ),
            1 << 20,
        );
        assert_eq!(
            run(&closed, job(&base, &package(), &["v1.0.0"])).await,
            None
        );
    }

    /// Off, nothing starts and waiting returns. On, a digest is compared once at a time, a
    /// job past its deadline stores nothing, and a store that fails is logged.
    #[tokio::test]
    async fn a_comparison_runs_once_at_a_time_within_its_deadline() {
        let off = analyser("source-off", 1 << 20, Arc::new(InProcess::new(8)));
        assert!(off.start_source(job("http://x", b"x", &[])).is_none());
        assert_eq!(off.sources_started(), 0);
        off.sources_ended(1).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let base = format!("http://{addr}");
        let slow =
            comparing("source-slow", &base, 1 << 20).with_deadline(Duration::from_millis(100));
        let first = slow
            .start_source(job(&base, b"x", &["v1"]))
            .expect("starts");
        assert!(
            slow.start_source(job(&base, b"x", &["v1"])).is_none(),
            "in flight"
        );
        first.await.expect("finishes");
        tokio::time::timeout(std::time::Duration::from_secs(10), slow.sources_ended(1))
            .await
            .expect("the comparison ends");
        assert_eq!(slow.sourced(&sri_of(b"x")).await, None);

        let (base, _) = server(vec![
            ("/pkg/-/pkg-1.0.0.tgz".to_owned(), 200, package()),
            ("/o/r/tar.gz/v1.0.0".to_owned(), 200, source()),
        ])
        .await;
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
        let broken = analyser(
            "source-broken",
            1 << 20,
            Arc::new(crate::analysis::store::tests::Broken),
        )
        .with_sources(Some(base.clone()));
        assert_eq!(
            run(&broken, job(&base, &package(), &["v1.0.0"])).await,
            None
        );
        drop(guard);
        let log = crate::util::test_support::text(&buf);
        for said in [
            "source comparison: not stored",
            "analysis store cannot answer; comparing with the source again",
        ] {
            assert!(log.contains(said), "{said}: {log}");
        }
    }

    /// A spool file removed before it is read stores nothing.
    #[tokio::test]
    async fn a_spool_file_that_cannot_be_read_is_no_tree() {
        let analyser = comparing("source-unread", "http://x", 1 << 20);
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
        assert!(tree_of(spooled, Layout::Tar).await.is_none());
    }

    /// A wheel is compared with the repository its own metadata names, and one naming none,
    /// or whose files the source does not have, is stored as not compared.
    #[tokio::test]
    async fn a_wheel_is_compared_with_the_repository_its_metadata_names() {
        use crate::util::test_support::zip_of;
        let named = zip_of(&[
            ("pkg/__init__.py", b"published"),
            (
                "pkg-1.0.dist-info/METADATA",
                b"Name: pkg\nProject-URL: Source, https://github.com/o/r\n",
            ),
        ]);
        let unnamed = zip_of(&[
            ("pkg/__init__.py", b"x"),
            ("pkg-1.0.dist-info/METADATA", b"Name: pkg\n"),
        ]);
        let elsewhere = zip_of(&[
            ("other/__init__.py", b"x"),
            (
                "other-1.0.dist-info/METADATA",
                b"Project-URL: Source, https://github.com/o/r\n",
            ),
        ]);
        let source = tarball(&[("r-v1/src/pkg/__init__.py", b"source")]);
        let (base, _) = server(vec![
            ("/named.whl".to_owned(), 200, named.clone()),
            ("/unnamed.whl".to_owned(), 200, unnamed.clone()),
            ("/elsewhere.whl".to_owned(), 200, elsewhere.clone()),
            ("/o/r/tar.gz/v1.0".to_owned(), 200, source),
        ])
        .await;
        let analyser = comparing("source-wheel", &base, 1 << 20);
        let wheel = |file: &str, bytes: &[u8]| SourceJob {
            url: format!("{base}/{file}"),
            ecosystem: Ecosystem::PyPI,
            layout: Layout::Wheel,
            repo: None,
            ..job(&base, bytes, &["v1.0"])
        };
        let Some(Sourced::Compared {
            repository,
            comparison,
            ..
        }) = run(&analyser, wheel("named.whl", &named)).await
        else {
            panic!("compared");
        };
        assert_eq!(repository, "o/r");
        assert_eq!(comparison.differing, ["pkg/__init__.py"]);
        for (file, bytes, why) in [
            (
                "unnamed.whl",
                &unnamed,
                "the artifact's metadata names no repository on GitHub",
            ),
            (
                "elsewhere.whl",
                &elsewhere,
                "none of the package's Python files is in the source",
            ),
        ] {
            assert_eq!(
                run(&analyser, wheel(file, bytes)).await,
                Some(Sourced::NotCompared(why.to_owned())),
                "{file}"
            );
        }
    }

    /// A job is made from a record naming a GitHub repository, and not from one that does not.
    #[test]
    fn a_job_needs_a_repository_on_github() {
        let record = crate::ecosystem::npm::normalized(
            "@babel_traverse-8.0.5.full.json",
            crate::record::DocumentDetail::Full,
        )
        .version("8.0.5")
        .unwrap()
        .clone();
        let made = SourceJob::of(&record, "x.tgz", &sri_of(b"x"), "u".to_owned()).expect("a job");
        assert_eq!(
            made.repo,
            Some(Repo {
                owner: "babel".to_owned(),
                name: "babel".to_owned()
            })
        );
        assert_eq!(made.layout, Layout::Tar);
        assert_eq!(made.directory.as_deref(), Some("packages/babel-traverse"));
        assert_eq!(made.name, "@babel/traverse");
        let mut elsewhere = record.clone();
        elsewhere.repository.as_mut().unwrap().url = "https://gitlab.com/o/r".to_owned();
        assert!(SourceJob::of(&elsewhere, "x.tgz", &sri_of(b"x"), "u".to_owned()).is_none());
        elsewhere.repository = None;
        assert!(SourceJob::of(&elsewhere, "x.tgz", &sri_of(b"x"), "u".to_owned()).is_none());

        let mut pypi = record.clone();
        pypi.repository = None;
        pypi.package = crate::identity::PackageKey::from_registry_name(Ecosystem::PyPI, "idna")
            .and_then(|key| key.at_version("3.10"))
            .unwrap();
        let wheel = SourceJob::of(
            &pypi,
            "idna-3.10-py3-none-any.whl",
            &sri_of(b"x"),
            "u".to_owned(),
        )
        .expect("a PyPI job needs no repository from its record");
        assert_eq!((wheel.repo, wheel.layout), (None, Layout::Wheel));
        let sdist = SourceJob::of(&pypi, "idna-3.10.tar.gz", &sri_of(b"x"), "u".to_owned());
        assert_eq!(sdist.map(|job| job.layout), Some(Layout::Tar));
        assert!(SourceJob::of(&pypi, "idna-3.10.zip", &sri_of(b"x"), "u".to_owned()).is_none());
    }
}
