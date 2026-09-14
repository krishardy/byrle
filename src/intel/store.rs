//! Where advisories are kept, and the seam that lets everything above be tested without
//! them.
//!
//! # Why a trait, now that there is one backend
//!
//! Not portability. SQLite was dropped and Postgres is the only target. The trait is here
//! because CLAUDE.md puts the unit coverage floor at 95% excluding corpus and live tests,
//! so the policy engine and everything above this seam has to be testable with no database
//! at all. Reading "one backend" and deleting the trait would put the decision engine
//! behind a container.
//!
//! # What a lookup answers
//!
//! One question, asked per package version: what is known against it. The three checks
//! that read advisories all answer from that one result, so the proxy makes one query per
//! package rather than one per check.

use crate::intel::range::{self, Interval};
use crate::intel::refresh::StreamDigest;
use crate::intel::{Enrichment, Finding, Score};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

/// What a stream recorded against one package version.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub advisory_id: String,
    /// The other ids the advisory is known by, sorted. A GHSA record's CVE id is here, and it
    /// is what a `vuln_advisory_ids` exception names.
    pub aliases: Vec<String>,
    pub source: String,
    pub cvss: Option<f64>,
    pub cvss_source: Option<String>,
    pub exploited: bool,
    pub malware: bool,
}

impl Record {
    /// Turn a stored row into a finding.
    ///
    /// A row is a `match`-stream result by construction: it names a package. See
    /// `src/intel.rs` for why that matters and why an `Enrichment` cannot be built here.
    pub fn finding(&self) -> Finding {
        let mut finding = Finding::new(&self.source, &self.advisory_id);
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
    /// A stored range does not parse. The loader writes none, so something else wrote the
    /// row. Matching it against nothing would drop the advisory unannounced.
    Range { advisory_id: String },
    /// A row refers to an advisory the load did not key. `advisory` is written first and
    /// every other table joins on its key, so this is a loader defect, not bad input.
    Unkeyed { advisory_id: String },
    /// A package a kept snapshot was not read for. Answering it as nothing known would be
    /// wrong for any package with an advisory.
    Unread { ecosystem: String, name: String },
}

impl std::fmt::Display for IntelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => {
                write!(f, "intel store: {e}")?;
                // Postgres names the table, line and column a failed `COPY` stopped at here,
                // such as a value longer than its column.
                match e
                    .as_database_error()
                    .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
                    .and_then(|d| d.r#where())
                {
                    Some(context) => write!(f, " ({context})"),
                    None => Ok(()),
                }
            }
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

/// A lookup in flight. Boxed so the proxy can hold a store as `dyn Intel`, which an
/// `async fn` in a trait does not allow.
pub type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, IntelError>> + Send + 'a>>;

/// Everything recorded against one package, read from one load.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageIntel {
    /// The snapshot the records came from.
    pub snapshot: String,
    /// Each record with the version it names. `None` is every version.
    pub records: Vec<(Option<String>, Record)>,
    /// Each record with an interval of versions it is against.
    pub ranges: Vec<(Interval<Version>, Record)>,
}

impl PackageIntel {
    /// The records that apply to one version, each advisory once.
    ///
    /// An advisory recorded against every version, this one, and a range holding it appears
    /// three times. Which copy is kept does not matter: every field of [`Record`] comes from
    /// the `advisory` row, keyed by id, and only the version or interval differs.
    ///
    /// A version that is not SemVer, such as `3.0.0rc1`, is in no range. It still matches a
    /// listed version and every version. No packument version seen is one: 0 in 103 packages
    /// on 2026-09-15, and `express` lists `3.0.0-rc1`, which only its tarball name spells
    /// `3.0.0rc1`.
    pub fn for_version(&self, version: &str) -> Vec<&Record> {
        let parsed = range::version(version);
        let listed = self
            .records
            .iter()
            .filter(|(v, _)| v.as_deref().is_none_or(|v| v == version));
        let ranged = self
            .ranges
            .iter()
            .filter(|(interval, _)| parsed.as_ref().is_some_and(|v| interval.contains(v)));
        let mut seen = BTreeSet::new();
        listed
            .map(|(_, record)| record)
            .chain(ranged.map(|(_, record)| record))
            .filter(|record| seen.insert(record.advisory_id.as_str()))
            .collect()
    }
}

/// The load the answers come from, as `waharoa refresh` recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedSnapshot {
    /// The snapshot id, over every source's rows. See `load::snapshot_id`.
    pub digest: String,
    /// When the refresh that wrote it ran. RFC 3339, UTC, to the second.
    pub taken_at: String,
    /// Each stream the sources' rows were read from, sorted by name.
    pub streams: Vec<StreamDigest>,
}

/// What the decision engine asks of the mirror.
///
/// A failure is an error rather than an empty answer. An empty answer means a stream was
/// asked and knew nothing; an error means nothing was asked, and the two have to stay
/// distinguishable all the way up to `Facts::intel`.
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

/// A store for tests above the storage seam.
#[cfg(test)]
pub mod testing {
    use super::*;

    /// Answers every question from one fixed reply. `Ok(None)` is a store with nothing
    /// loaded, and `Err(())` is a store that cannot be reached.
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
            _ecosystem: &'a str,
            _name: &'a str,
            version: &'a str,
        ) -> Lookup<'a, Vec<Record>> {
            Box::pin(async move {
                Ok(self
                    .answer()?
                    .map(|p| p.for_version(version).into_iter().cloned().collect())
                    .unwrap_or_default())
            })
        }

        fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
            Box::pin(async move {
                Ok(self.answer()?.map(|p| LoadedSnapshot {
                    digest: p.snapshot,
                    taken_at: "2026-09-13T00:00:00Z".to_owned(),
                    streams: Vec::new(),
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
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            advisory_id: "GHSA-x".to_owned(),
            aliases: Vec::new(),
            source: "osv".to_owned(),
            cvss: None,
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
        };
        let ids = |version: &str| -> Vec<String> {
            intel
                .for_version(version)
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
    ) -> (Interval<Version>, Record) {
        (
            Interval::from_columns(introduced, fixed, None).expect("a test interval parses"),
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
        };
        let ids = |version: &str| -> Vec<String> {
            intel
                .for_version(version)
                .iter()
                .map(|r| r.advisory_id.clone())
                .collect()
        };
        assert_eq!(ids("1.5.0"), ["GHSA-1", "GHSA-2"]);
        assert_eq!(ids("1.1.0"), ["GHSA-1", "GHSA-2", "GHSA-3"]);
        assert_eq!(ids("1.5.0+build"), ["GHSA-1", "GHSA-2"]);
        assert_eq!(ids("2.0.0-rc.1"), ["GHSA-1", "GHSA-2"]);
        assert!(ids("2.0.0").is_empty());
        // Not SemVer, so in no range.
        assert!(ids("1.5.0rc1").is_empty());
    }

    #[tokio::test]
    async fn the_fixed_store_answers_all_three_questions_from_one_reply() {
        use testing::FixedIntel;
        let loaded = FixedIntel(Ok(Some(PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![at(None, "MAL-1")],
            ranges: Vec::new(),
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
}
