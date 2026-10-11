//! Where advisories are kept, and the seam that lets everything above be tested without
//! them. One lookup per package answers every check that reads advisories.
//!
//! See docs/engineering_decisions/intel-in-decisions.md.

use crate::intel::range::{Interval, Ordered, VersionOrder};
use crate::intel::refresh::StreamDigest;
use crate::intel::{Enrichment, Finding, Score};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

/// What a stream recorded against one package version.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub advisory_id: String,
    /// The other ids the advisory is known by, sorted, such as a GHSA record's CVE id.
    pub aliases: Vec<String>,
    pub source: String,
    pub cvss: Option<f64>,
    pub cvss_source: Option<String>,
    /// The severity band `cvss` was read from, when the advisory carries no CVSS vector.
    pub band: Option<String>,
    pub exploited: bool,
    pub malware: bool,
}

impl Record {
    /// Turn a stored row, which names a package and so is a `match`-stream result, into a
    /// finding. Returns the finding.
    pub fn finding(&self) -> Finding {
        let mut finding = Finding::new(&self.source, &self.advisory_id).with_aliases(&self.aliases);
        if let Some(cvss) = self.cvss {
            finding = finding.with_score(cvss);
        }
        if self.exploited {
            finding = finding.enriched_by(&[Enrichment::new(&self.advisory_id).exploited()]);
        }
        finding
    }

    /// The score as stored, with whoever supplied it.
    pub fn score(&self) -> Option<Score> {
        Score::new(
            self.cvss_source.as_deref().unwrap_or(&self.source),
            self.cvss?,
        )
    }
}

/// Why a lookup could not be answered.
#[derive(Debug)]
pub enum IntelError {
    /// The database said no. Never treated as "nothing known": see `Intel::NotConsulted`.
    Backend(sqlx::Error),
    /// A stored range does not parse.
    Range { advisory_id: String },
    /// A row refers to an advisory the load did not key.
    Unkeyed { advisory_id: String },
    /// A package a kept snapshot was not read for.
    Unread { ecosystem: String, name: String },
}

impl std::fmt::Display for IntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "intel store: {}", super::postgres::described(e)),
            Self::Unkeyed { advisory_id } => {
                write!(
                    f,
                    "intel store: {advisory_id} was not keyed before its rows"
                )
            }
            Self::Range { advisory_id } => {
                write!(
                    f,
                    "intel store: a stored range of {advisory_id} does not parse"
                )
            }
            Self::Unread { ecosystem, name } => {
                write!(
                    f,
                    "intel store: the kept snapshot was not read for {ecosystem} {name}"
                )
            }
        }
    }
}

impl std::error::Error for IntelError {}

/// A lookup in flight, boxed so the proxy can hold a `dyn Intel`.
pub type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, IntelError>> + Send + 'a>>;

/// Everything recorded against one package, read from one load.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageIntel {
    /// The snapshot the records came from.
    pub snapshot: String,
    /// Each record with the version it names. `None` is every version.
    pub records: Vec<(Option<String>, Record)>,
    /// Each record with an interval of versions it is against.
    pub ranges: Vec<(Interval<Ordered>, Record)>,
    /// Whether the snapshot includes the KEV catalogue, without which `kev` cannot be answered.
    pub exploitation_loaded: bool,
}

impl PackageIntel {
    /// The records that apply to one version, each advisory once per stream.
    /// `ecosystem` is the purl type, whose [`VersionOrder`] reads the versions.
    /// `version` matches a listed version equal to it in that order, or as written.
    pub fn for_version(&self, ecosystem: &str, version: &str) -> Vec<&Record> {
        let order = VersionOrder::of(ecosystem);
        let parsed = order.and_then(|order| order.parse(version));
        let same = |listed: &str| {
            listed == version
                || parsed.is_some() && order.and_then(|order| order.parse(listed)) == parsed
        };
        let listed = self
            .records
            .iter()
            .filter(|(v, _)| v.as_deref().is_none_or(same));
        let ranged = self
            .ranges
            .iter()
            .filter(|(interval, _)| parsed.as_ref().is_some_and(|v| interval.contains(v)));
        let mut seen = BTreeSet::new();
        listed
            .map(|(_, record)| record)
            .chain(ranged.map(|(_, record)| record))
            .filter(|record| seen.insert((record.source.as_str(), record.advisory_id.as_str())))
            .collect()
    }
}

/// The load the answers come from, as `byrle refresh` recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedSnapshot {
    /// The snapshot id, over every source's rows. See `load::snapshot_id`.
    pub digest: String,
    /// When the refresh that wrote it ran. RFC 3339, UTC, to the second.
    pub taken_at: String,
    /// Each source the snapshot id is the digest of, sorted.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Each stream the sources' rows were read from, sorted by name.
    pub streams: Vec<StreamDigest>,
    /// Each stream whose latest refresh did not read it because it is not configured.
    #[serde(default)]
    pub unconfigured: Vec<String>,
}

impl LoadedSnapshot {
    /// Whether the snapshot includes the KEV catalogue, read from its sources. A stream is not
    /// read: a kept snapshot records none. `PgIntel::package` asks `intel_source` the same
    /// question in its statement.
    pub fn exploitation_loaded(&self) -> bool {
        self.sources
            .iter()
            .any(|source| source == crate::intel::providers::kev::STREAM)
    }

    /// Each served ecosystem no stream in this snapshot can originate a finding for, then
    /// each no stream can report malware for. Returns them, for startup and `doctor`.
    pub fn gaps(&self) -> Vec<crate::intel::Gap> {
        self.gaps_in(&crate::intel::served())
    }

    /// [`Self::gaps`] for one ecosystem. Empty means a stream in this snapshot can both
    /// originate a finding and report malware for it.
    pub fn uncovered(&self, ecosystem: &str) -> Vec<crate::intel::Gap> {
        self.gaps_in(&[ecosystem])
    }

    fn gaps_in(&self, ecosystems: &[&str]) -> Vec<crate::intel::Gap> {
        let capabilities = crate::intel::capabilities_of(&self.streams);
        let mut gaps = capabilities.gaps(ecosystems);
        gaps.extend(capabilities.uncovered_by(ecosystems, crate::intel::Capability::Malware));
        gaps.extend(self.unloaded(ecosystems));
        gaps
    }

    /// Each stream an ecosystem in `ecosystems` lists that this snapshot neither holds nor
    /// records as unconfigured. Returns one gap per stream.
    fn unloaded(&self, ecosystems: &[&str]) -> Vec<crate::intel::Gap> {
        let held = |stream: &str| {
            self.streams.iter().any(|s| s.stream == stream)
                || self.unconfigured.iter().any(|s| s == stream)
        };
        crate::ecosystem::TABLE
            .iter()
            .filter(|registry| ecosystems.contains(&registry.ecosystem.as_str()))
            .flat_map(|registry| {
                registry
                    .streams
                    .iter()
                    .filter(|listed| !held(listed.stream))
                    .map(|listed| crate::intel::Gap {
                        ecosystem: registry.ecosystem.as_str().to_owned(),
                        missing: crate::intel::Missing::Stream(listed.stream.to_owned()),
                    })
            })
            .collect()
    }
}

/// What the decision engine asks of the mirror. A failure is an error, never an empty answer.
pub trait Intel: Send + Sync {
    /// Everything recorded against this exact version, a range holding it, or the package as
    /// a whole. [`PackageIntel::for_version`] over [`Intel::package`].
    fn lookup<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
        version: &'a str,
    ) -> Lookup<'a, Vec<Record>>;

    /// Which snapshot the answers above came from, so a verdict can record it and readiness
    /// can report it. `None` when nothing has been loaded.
    fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>>;

    /// Every record against a package, for all its versions at once, so a packument with
    /// 3,823 versions is one query. `None` when nothing has been loaded, which is not the
    /// same as a package nothing is known against.
    fn package<'a>(&'a self, ecosystem: &'a str, name: &'a str)
    -> Lookup<'a, Option<PackageIntel>>;
}

/// Why a command has no intel to judge a package with.
#[derive(Debug, PartialEq, Eq)]
pub enum NoIntel {
    /// The snapshot has no `match` or `malware` stream for the package's ecosystem.
    Uncovered(String),
    /// The store errored, holds no snapshot, or was replaced while it was read.
    Failed(String),
}

impl std::fmt::Display for NoIntel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uncovered(why) | Self::Failed(why) => f.write_str(why),
        }
    }
}

/// What `store` knows about one package, for `byrle explain` and `byrle policy diff`.
///
/// `Ok(None)` is no store configured. A store that errors or holds no snapshot is an error,
/// so a command cannot print a verdict reached without intel it was told to use.
///
/// With `streams_recorded`, the snapshot's streams have to cover the package's ecosystem, as
/// the proxy requires. A kept snapshot records no streams, so its coverage is not checked.
pub async fn for_command(
    store: Option<&dyn Intel>,
    ecosystem: &str,
    name: &str,
    streams_recorded: bool,
) -> Result<Option<PackageIntel>, NoIntel> {
    let Some(store) = store else {
        return Ok(None);
    };
    let found = match store.package(ecosystem, name).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return Err(NoIntel::Failed(
                "the intel store holds no snapshot; run `byrle refresh`".to_owned(),
            ));
        }
        Err(e) => return Err(NoIntel::Failed(e.to_string())),
    };
    if !streams_recorded {
        return Ok(Some(found));
    }
    match store.snapshot().await {
        Ok(Some(snapshot)) if snapshot.digest == found.snapshot => {
            let gaps: Vec<String> = snapshot
                .uncovered(ecosystem)
                .iter()
                .map(ToString::to_string)
                .collect();
            if gaps.is_empty() {
                Ok(Some(found))
            } else {
                Err(NoIntel::Uncovered(gaps.join("; ")))
            }
        }
        Ok(_) => Err(NoIntel::Failed(
            "the intel snapshot changed while it was read".to_owned(),
        )),
        Err(e) => Err(NoIntel::Failed(e.to_string())),
    }
}

/// A store for tests above the storage seam.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod testing {
    use super::*;

    /// A store holding snapshot `s1`, which covers npm, with nothing against any package.
    pub fn knowing_nothing() -> FixedIntel {
        FixedIntel(Ok(Some(PackageIntel {
            snapshot: "s1".to_owned(),
            records: Vec::new(),
            ranges: Vec::new(),
            exploitation_loaded: false,
        })))
    }

    /// A store that answers for any package and then cannot say its snapshot.
    pub struct Unsnapshotted;

    impl Intel for Unsnapshotted {
        fn lookup<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> Lookup<'a, Vec<Record>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
            Box::pin(async move { Err(IntelError::Backend(sqlx::Error::PoolTimedOut)) })
        }

        fn package<'a>(&'a self, _: &'a str, _: &'a str) -> Lookup<'a, Option<PackageIntel>> {
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

    /// One fixed reply: `Ok(None)` is nothing loaded, `Err(())` unreachable; covers npm only.
    pub struct FixedIntel(pub Result<Option<PackageIntel>, ()>);

    impl FixedIntel {
        fn answer(&self) -> Result<Option<PackageIntel>, IntelError> {
            self.0
                .clone()
                .map_err(|()| IntelError::Backend(sqlx::Error::PoolTimedOut))
        }
    }

    impl Intel for FixedIntel {
        fn lookup<'a>(
            &'a self,
            ecosystem: &'a str,
            _name: &'a str,
            version: &'a str,
        ) -> Lookup<'a, Vec<Record>> {
            Box::pin(async move {
                Ok(self
                    .answer()?
                    .map(|p| {
                        p.for_version(ecosystem, version)
                            .into_iter()
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default())
            })
        }

        fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
            Box::pin(async move {
                Ok(self.answer()?.map(|p| LoadedSnapshot {
                    digest: p.snapshot,
                    taken_at: "2026-09-13T00:00:00Z".to_owned(),
                    sources: Vec::new(),
                    streams: crate::ecosystem::of(crate::identity::Ecosystem::Npm)
                        .streams
                        .iter()
                        .map(|listed| StreamDigest {
                            stream: listed.stream.to_owned(),
                            sha256: "aa".to_owned(),
                            etag: None,
                            last_modified: None,
                        })
                        .collect(),
                    unconfigured: Vec::new(),
                }))
            })
        }

        fn package<'a>(
            &'a self,
            _ecosystem: &'a str,
            _name: &'a str,
        ) -> Lookup<'a, Option<PackageIntel>> {
            Box::pin(async move { self.answer() })
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            advisory_id: "GHSA-x".to_owned(),
            aliases: Vec::new(),
            source: "osv".to_owned(),
            cvss: None,
            band: None,
            cvss_source: None,
            exploited: false,
            malware: false,
        }
    }

    #[test]
    fn an_unscored_unexploited_row_is_a_bare_finding() {
        let finding = record().finding();
        assert_eq!(finding, Finding::new("osv", "GHSA-x"));
        assert!(!finding.exploited());
    }

    #[test]
    fn a_scored_exploited_row_carries_both_into_the_finding() {
        let finding = Record {
            cvss: Some(7.5),
            exploited: true,
            ..record()
        }
        .finding();
        assert_eq!(finding.score.as_ref().map(Score::cvss), Some(7.5));
        assert!(finding.exploited());
    }

    #[test]
    fn a_row_gives_its_aliases_to_the_finding_so_an_enrichment_keyed_on_one_applies() {
        let finding = Record {
            aliases: vec!["CVE-1".to_owned()],
            ..record()
        }
        .finding();
        assert_eq!(finding.aliases, ["CVE-1"]);
        assert!(
            finding
                .enriched_by(&[Enrichment::new("CVE-1").exploited()])
                .exploited()
        );
    }

    #[test]
    fn the_score_names_the_stream_that_supplied_it() {
        let score = Record {
            cvss: Some(9.8),
            cvss_source: Some("nvd".to_owned()),
            ..record()
        }
        .score()
        .expect("a score");
        assert_eq!((score.source.as_str(), score.cvss()), ("nvd", 9.8));
    }

    #[test]
    fn a_score_with_no_named_supplier_is_credited_to_the_advisory_source() {
        let score = Record {
            cvss: Some(4.0),
            ..record()
        }
        .score()
        .expect("a score");
        assert_eq!(score.source, "osv");
    }

    #[test]
    fn no_stored_score_or_an_out_of_range_one_is_no_score() {
        assert_eq!(record().score(), None);
        assert_eq!(
            Record {
                cvss: Some(11.0),
                ..record()
            }
            .score(),
            None
        );
    }

    fn at(version: Option<&str>, id: &str) -> (Option<String>, Record) {
        (
            version.map(str::to_owned),
            Record {
                advisory_id: id.to_owned(),
                ..record()
            },
        )
    }

    #[test]
    fn a_version_sees_its_own_rows_and_every_version_rows_once_each() {
        let intel = PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![
                at(None, "MAL-1"),
                at(Some("1.0.0"), "MAL-1"),
                at(Some("1.0.0"), "GHSA-2"),
                at(Some("2.0.0"), "GHSA-3"),
            ],
            ranges: Vec::new(),
            exploitation_loaded: false,
        };
        let ids = |version: &str| -> Vec<String> {
            intel
                .for_version("npm", version)
                .iter()
                .map(|r| r.advisory_id.clone())
                .collect()
        };
        assert_eq!(ids("1.0.0"), ["MAL-1", "GHSA-2"]);
        assert_eq!(ids("2.0.0"), ["MAL-1", "GHSA-3"]);
        assert_eq!(ids("3.0.0"), ["MAL-1"]);
    }

    fn within(
        introduced: Option<&str>,
        fixed: Option<&str>,
        id: &str,
    ) -> (Interval<Ordered>, Record) {
        (
            Interval::from_columns(VersionOrder::SemVer, introduced, false, fixed, None)
                .expect("a test interval parses"),
            Record {
                advisory_id: id.to_owned(),
                ..record()
            },
        )
    }

    #[test]
    fn a_version_sees_the_ranges_holding_it_once_each() {
        let intel = PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![at(Some("1.5.0"), "GHSA-1")],
            ranges: vec![
                within(Some("1.0.0"), Some("2.0.0"), "GHSA-1"),
                within(Some("1.0.0"), Some("2.0.0"), "GHSA-2"),
                within(None, Some("1.2.0"), "GHSA-3"),
            ],
            exploitation_loaded: false,
        };
        let ids = |version: &str| -> Vec<String> {
            intel
                .for_version("npm", version)
                .iter()
                .map(|r| r.advisory_id.clone())
                .collect()
        };
        assert_eq!(ids("1.5.0"), ["GHSA-1", "GHSA-2"]);
        assert_eq!(ids("1.1.0"), ["GHSA-1", "GHSA-2", "GHSA-3"]);
        assert_eq!(ids("1.5.0+build"), ["GHSA-1", "GHSA-2"]);
        assert_eq!(ids("2.0.0-rc.1"), ["GHSA-1", "GHSA-2"]);
        assert!(ids("2.0.0").is_empty());
        assert!(ids("1.5.0rc1").is_empty());
    }

    /// A PyPI version is read as PEP 440, in a range and in the listed versions, and an
    /// ecosystem with no order matches only as written.
    #[test]
    fn a_pypi_version_is_matched_by_pep_440() {
        let range = |introduced, fixed, id: &str| {
            (
                Interval::from_columns(VersionOrder::Pep440, introduced, false, fixed, None)
                    .expect("a test interval parses"),
                Record {
                    advisory_id: id.to_owned(),
                    ..record()
                },
            )
        };
        let intel = PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![at(Some("1.0"), "PYSEC-1")],
            ranges: vec![range(None, Some("2.6.11.post1"), "GHSA-1")],
            exploitation_loaded: false,
        };
        let ids = |ecosystem: &str, version: &str| -> Vec<String> {
            intel
                .for_version(ecosystem, version)
                .iter()
                .map(|r| r.advisory_id.clone())
                .collect()
        };
        assert_eq!(ids("pypi", "1.0.0"), ["PYSEC-1", "GHSA-1"]);
        assert_eq!(ids("pypi", "2.6.11"), ["GHSA-1"]);
        assert!(ids("pypi", "2.6.11-1").is_empty());
        assert_eq!(ids("cargo", "1.0"), ["PYSEC-1"]);
        assert!(ids("cargo", "1.0.0").is_empty());
    }

    #[tokio::test]
    async fn the_fixed_store_answers_all_three_questions_from_one_reply() {
        use testing::FixedIntel;
        let loaded = FixedIntel(Ok(Some(PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![at(None, "MAL-1")],
            ranges: Vec::new(),
            exploitation_loaded: false,
        })));
        assert_eq!(
            loaded.snapshot().await.expect("answers").map(|s| s.digest),
            Some("s1".to_owned())
        );
        assert_eq!(
            loaded
                .lookup("npm", "p", "1.0.0")
                .await
                .expect("answers")
                .len(),
            1
        );
        assert!(loaded.package("npm", "p").await.expect("answers").is_some());

        let down = FixedIntel(Err(()));
        assert!(down.package("npm", "p").await.is_err());
        assert!(
            FixedIntel(Ok(None))
                .lookup("npm", "p", "1.0.0")
                .await
                .expect("answers")
                .is_empty()
        );
    }

    /// The gaps a snapshot has for want of a capability, leaving out missing streams.
    fn capability_gaps(snapshot: &LoadedSnapshot) -> Vec<crate::intel::Gap> {
        snapshot
            .gaps()
            .into_iter()
            .filter(|gap| capability_of(&gap.missing).is_some())
            .collect()
    }

    fn capability_of(missing: &crate::intel::Missing) -> Option<crate::intel::Capability> {
        match missing {
            crate::intel::Missing::Capability(capability) => Some(*capability),
            crate::intel::Missing::Stream(_) => None,
        }
    }

    /// A listed stream the snapshot does not hold is a gap, unless its latest refresh
    /// recorded it as unconfigured. An older load of it counts as held.
    #[test]
    fn a_listed_stream_the_snapshot_does_not_hold_is_a_gap_unless_unconfigured() {
        let stream_gaps = |snapshot: &LoadedSnapshot| -> Vec<(String, String)> {
            snapshot
                .gaps()
                .into_iter()
                .filter_map(|gap| match gap.missing {
                    crate::intel::Missing::Stream(stream) => Some((gap.ecosystem, stream)),
                    crate::intel::Missing::Capability(_) => None,
                })
                .collect()
        };
        let without_osv = recording(&["datadog/npm", "datadog/pypi", "osv/pypi"]);
        assert_eq!(
            stream_gaps(&without_osv),
            [
                ("npm".to_owned(), "osv/npm".to_owned()),
                ("npm".to_owned(), "github/npm".to_owned()),
                ("pypi".to_owned(), "github/pypi".to_owned()),
            ]
        );
        let unconfigured = LoadedSnapshot {
            unconfigured: vec!["github/npm".to_owned(), "github/pypi".to_owned()],
            ..without_osv
        };
        assert_eq!(
            stream_gaps(&unconfigured),
            [("npm".to_owned(), "osv/npm".to_owned())],
            "only the stream that was configured and did not load is missing"
        );
        assert!(
            unconfigured.uncovered("npm")[0]
                .to_string()
                .contains("lists `osv/npm`"),
            "the gap names the stream"
        );
    }

    fn recording(streams: &[&str]) -> LoadedSnapshot {
        LoadedSnapshot {
            digest: "s1".to_owned(),
            taken_at: "2026-09-15T00:00:00Z".to_owned(),
            sources: Vec::new(),
            streams: streams
                .iter()
                .map(|stream| StreamDigest {
                    stream: (*stream).to_owned(),
                    sha256: "aa".to_owned(),
                    etag: None,
                    last_modified: None,
                })
                .collect(),
            unconfigured: Vec::new(),
        }
    }

    #[test]
    fn a_snapshot_covers_an_ecosystem_only_when_it_records_that_ecosystems_osv_stream() {
        let without = |ecosystem: &str, capability| crate::intel::Gap {
            ecosystem: ecosystem.to_owned(),
            missing: crate::intel::Missing::Capability(capability),
        };
        let (matching, malware) = (
            crate::intel::Capability::Match,
            crate::intel::Capability::Malware,
        );
        assert_eq!(
            capability_gaps(&recording(&["cisa/kev", "osv/npm"])),
            [without("pypi", matching), without("pypi", malware)]
        );
        assert_eq!(
            capability_gaps(&recording(&["osv/pypi"])),
            [without("npm", matching), without("npm", malware)]
        );
        assert!(capability_gaps(&recording(&["osv/npm", "osv/pypi"])).is_empty());
        for streams in [&[][..], &["cisa/kev"]] {
            assert_eq!(
                capability_gaps(&recording(streams)),
                [
                    without("npm", matching),
                    without("pypi", matching),
                    without("npm", malware),
                    without("pypi", malware),
                ],
                "{streams:?}"
            );
        }
    }

    fn nothing_known(snapshot: &str) -> PackageIntel {
        PackageIntel {
            snapshot: snapshot.to_owned(),
            records: Vec::new(),
            ranges: Vec::new(),
            exploitation_loaded: false,
        }
    }

    fn fixed(answer: Result<Option<PackageIntel>, ()>) -> testing::FixedIntel {
        testing::FixedIntel(answer)
    }

    #[tokio::test]
    async fn a_command_gets_intel_only_for_a_covered_ecosystem() {
        let store = fixed(Ok(Some(nothing_known("s1"))));
        assert_eq!(
            for_command(None, "npm", "x", true).await,
            Ok(None),
            "no store"
        );
        assert_eq!(
            for_command(Some(&store), "npm", "x", true).await,
            Ok(Some(nothing_known("s1")))
        );
        let Err(NoIntel::Uncovered(why)) = for_command(Some(&store), "pypi", "x", true).await
        else {
            panic!("pypi has no stream in the test store");
        };
        assert!(
            why.contains("`pypi` is served with no stream providing match"),
            "{why}"
        );
        assert!(
            why.contains("; `pypi` is served with no stream providing malware"),
            "{why}"
        );
        assert_eq!(NoIntel::Uncovered(why.clone()).to_string(), why);
    }

    /// A kept snapshot records no streams, so its coverage is not asked.
    #[tokio::test]
    async fn a_kept_snapshot_is_not_checked_for_coverage() {
        let store = fixed(Ok(Some(nothing_known("s1"))));
        assert_eq!(
            for_command(Some(&store), "pypi", "x", false).await,
            Ok(Some(nothing_known("s1")))
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_answer_fails_the_command() {
        let empty = fixed(Ok(None));
        assert_eq!(
            for_command(Some(&empty), "npm", "x", true).await,
            Err(NoIntel::Failed(
                "the intel store holds no snapshot; run `byrle refresh`".to_owned()
            ))
        );
        let down = fixed(Err(()));
        let Err(NoIntel::Failed(why)) = for_command(Some(&down), "npm", "x", true).await else {
            panic!("a store that errors fails");
        };
        assert_eq!(NoIntel::Failed(why.clone()).to_string(), why);
        assert!(why.starts_with("intel store:"), "{why}");
    }

    /// Records from one snapshot are not judged against another's streams.
    #[tokio::test]
    async fn records_from_a_replaced_snapshot_fail_the_command() {
        struct Replaced;
        impl Intel for Replaced {
            fn lookup<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> Lookup<'a, Vec<Record>> {
                Box::pin(async move { Ok(Vec::new()) })
            }
            fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
                Box::pin(async move { Ok(Some(recording(&["osv/npm"]))) })
            }
            fn package<'a>(&'a self, _: &'a str, _: &'a str) -> Lookup<'a, Option<PackageIntel>> {
                Box::pin(async move { Ok(Some(nothing_known("s0"))) })
            }
        }
        assert_eq!(
            for_command(Some(&Replaced), "npm", "x", true).await,
            Err(NoIntel::Failed(
                "the intel snapshot changed while it was read".to_owned()
            ))
        );
    }

    /// One ecosystem's gaps are the served gaps for that ecosystem and no other.
    #[test]
    fn an_ecosystem_is_uncovered_by_what_it_lacks_and_not_by_another_ecosystem() {
        let covered = recording(&["cisa/kev", "osv/npm", "datadog/npm", "github/npm"]);
        assert_eq!(covered.uncovered("npm"), []);
        let pypi = covered.uncovered("pypi");
        assert_eq!(
            pypi.iter()
                .filter_map(|gap| capability_of(&gap.missing))
                .collect::<Vec<_>>(),
            [
                crate::intel::Capability::Match,
                crate::intel::Capability::Malware
            ]
        );
        assert!(pypi.iter().all(|gap| gap.ecosystem == "pypi"));
        let github_only = recording(&["github/npm"]);
        assert_eq!(
            github_only
                .uncovered("npm")
                .iter()
                .filter_map(|gap| capability_of(&gap.missing))
                .collect::<Vec<_>>(),
            [crate::intel::Capability::Malware],
            "a match stream without malware still leaves known_malware unable to fire"
        );
    }

    #[test]
    fn exploitation_is_loaded_when_a_source_is_the_catalogue_whatever_the_streams() {
        let with_sources = |sources: &[&str]| LoadedSnapshot {
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            ..recording(&["cisa/kev", "osv/npm"])
        };
        assert!(with_sources(&["cisa/kev", "osv"]).exploitation_loaded());
        assert!(!with_sources(&["datadog", "osv"]).exploitation_loaded());
        assert!(
            !with_sources(&[]).exploitation_loaded(),
            "a stream named cisa/kev is not the source"
        );
    }

    #[test]
    fn a_backend_error_names_the_intel_store() {
        let e = IntelError::Backend(sqlx::Error::RowNotFound);
        assert!(e.to_string().starts_with("intel store: "), "{e}");
        let e = IntelError::Range {
            advisory_id: "GHSA-x".to_owned(),
        };
        assert_eq!(
            e.to_string(),
            "intel store: a stored range of GHSA-x does not parse"
        );
        let e = IntelError::Unkeyed {
            advisory_id: "GHSA-x".to_owned(),
        };
        assert_eq!(
            e.to_string(),
            "intel store: GHSA-x was not keyed before its rows"
        );
    }

    /// A store that answers for the package and then cannot say its snapshot fails the
    /// command.
    #[tokio::test]
    async fn a_snapshot_that_cannot_be_read_fails_the_command() {
        use testing::Unsnapshotted;
        let Err(NoIntel::Failed(why)) = for_command(Some(&Unsnapshotted), "npm", "x", true).await
        else {
            panic!("a snapshot that cannot be read fails");
        };
        assert!(why.starts_with("intel store: "), "{why}");
    }
}
