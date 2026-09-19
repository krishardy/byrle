//! An advisory as the intel store holds it, whichever provider it came from.

use super::range::Interval;
use std::collections::{BTreeMap, BTreeSet};

/// One advisory, as the store holds it. Every provider produces these.
#[derive(Debug, Clone, PartialEq)]
pub struct Rows {
    pub id: String,
    pub summary: Option<String>,
    /// RFC 3339, as OSV wrote it.
    pub modified: Option<String>,
    pub malware: bool,
    /// The CVSS base score. From a vector when one parses; otherwise, when the record carries
    /// no CVSS vector at all, the top of its severity band. `None` when neither gives one.
    pub cvss: Option<f64>,
    /// The `database_specific.severity` band `cvss` was read from: `LOW`, `MODERATE`, `HIGH`
    /// or `CRITICAL`. `None` when a vector gave the score, or nothing did.
    pub band: Option<String>,
    /// CVSS vectors in the record that did not parse.
    pub unread_vectors: usize,
    pub aliases: BTreeSet<String>,
    pub affected: BTreeSet<Affected>,
    pub ranges: BTreeSet<Ranged>,
    /// npm entries in the record with a range or a whole entry that could not be stored, so
    /// a record can be partly stored without that reading as fully stored.
    pub unexpressed: usize,
}

/// A package version an advisory is against. `version` `None` is every version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Affected {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

impl Affected {
    /// A row for `name` as its source wrote it, stored as the ecosystem compares names, so
    /// a lookup by a package key finds it: Datadog writes `SentinelOne` and GitHub
    /// `jupyter_server`, and their PyPI keys are `sentinelone` and `jupyter-server`.
    pub fn new(ecosystem: &str, name: &str, version: Option<String>) -> Self {
        Self {
            ecosystem: ecosystem.to_owned(),
            name: crate::ecosystem::canonical_name(ecosystem, name),
            version,
        }
    }
}

/// An interval of package versions an advisory is against. Never every version, which is
/// an [`Affected`] with no version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ranged {
    pub ecosystem: String,
    pub name: String,
    pub interval: Interval<String>,
}

impl Ranged {
    /// A row for `name` as its source wrote it, stored as [`Affected::new`] stores one.
    pub fn new(ecosystem: &str, name: &str, interval: Interval<String>) -> Self {
        Self {
            ecosystem: ecosystem.to_owned(),
            name: crate::ecosystem::canonical_name(ecosystem, name),
            interval,
        }
    }
}

/// Give each unscored vulnerability the highest score among the records in `rows` it is a
/// direct alias of: records it lists by id, or records that list its id. Returns how many
/// took a score.
///
/// One load's records only, so a score is borrowed from the same stream. In OSV's PyPI
/// bundle of 2026-09-19, 2,583 of 2,731 unscored `PYSEC-` records had a scored `GHSA-` alias:
/// `PYSEC-2018-28` and `GHSA-x84v-xcm2-53pg` are both CVE-2018-18074, and only the second
/// carries 7.5. Unscored, the first would refuse every version `max_cvss` lets the second
/// through. A malware record has no score to take or give. The alias's band comes with its
/// score, so a score read from a band still says so.
pub fn score_from_aliases(rows: &mut [Rows]) -> u64 {
    let mut scored: BTreeMap<String, (f64, Option<String>)> = BTreeMap::new();
    let mut named_by: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in rows.iter().filter(|r| !r.malware) {
        let Some(cvss) = r.cvss else { continue };
        scored.insert(r.id.clone(), (cvss, r.band.clone()));
        for alias in &r.aliases {
            named_by
                .entry(alias.clone())
                .or_default()
                .push(r.id.clone());
        }
    }
    let mut taken = 0;
    for r in rows.iter_mut().filter(|r| !r.malware && r.cvss.is_none()) {
        let best = r
            .aliases
            .iter()
            .chain(named_by.get(&r.id).into_iter().flatten())
            .filter_map(|id| scored.get(id))
            .max_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((cvss, band)) = best {
            r.cvss = Some(*cvss);
            r.band.clone_from(band);
            taken += 1;
        }
    }
    taken
}

/// The highest CVSS score a GitHub severity band covers, the qualitative ranges of CVSS v3.1:
/// `LOW` 0.1 to 3.9, `MODERATE` 4.0 to 6.9, `HIGH` 7.0 to 8.9, `CRITICAL` 9.0 to 10.0. The top,
/// decided 2026-09-15, so a threshold inside a band refuses what the band could be. `None` for
/// any other text.
pub fn band_ceiling(band: &str) -> Option<f64> {
    match band {
        "LOW" => Some(3.9),
        "MODERATE" => Some(6.9),
        "HIGH" => Some(8.9),
        "CRITICAL" => Some(10.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};
    use crate::intel::range::{End, Start};

    /// A row is found by the key a request builds, however its source spelled the name.
    /// The PyPI names are ones Datadog's and GitHub's PyPI data held on 2026-09-19.
    #[test]
    fn a_row_is_stored_under_the_name_its_package_key_looks_up() {
        for (ecosystem, written) in [
            (Ecosystem::PyPI, "SentinelOne"),
            (Ecosystem::PyPI, "Roblox.-com"),
            (Ecosystem::PyPI, "jupyter_server"),
            (Ecosystem::PyPI, "GitPython"),
            (Ecosystem::Npm, "JSONStream"),
            (Ecosystem::Npm, "@babel/core"),
        ] {
            let key = PackageKey::from_registry_name(ecosystem, written).expect("a name");
            let affected = Affected::new(ecosystem.as_str(), written, None);
            let ranged = Ranged::new(
                ecosystem.as_str(),
                written,
                Interval {
                    start: Start::First,
                    end: End::Fixed("2.0.0".to_owned()),
                },
            );
            assert_eq!(affected.name, key.registry_name(), "{written}");
            assert_eq!(ranged.name, key.registry_name(), "{written}");
        }
        assert_eq!(Affected::new("pypi", "GitPython", None).name, "gitpython");
        assert_eq!(Affected::new("npm", "JSONStream", None).name, "JSONStream");
        assert_eq!(Affected::new("cargo", "Serde", None).name, "Serde");
    }

    fn advisory(id: &str, cvss: Option<f64>, band: Option<&str>, aliases: &[&str]) -> Rows {
        Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware: false,
            cvss,
            band: band.map(str::to_owned),
            unread_vectors: 0,
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            affected: BTreeSet::new(),
            ranges: BTreeSet::new(),
            unexpressed: 0,
        }
    }

    /// `PYSEC-2018-28` and `GHSA-x84v-xcm2-53pg` as OSV's PyPI bundle had them on
    /// 2026-09-19, each listing the other, and the ways a score is not taken.
    #[test]
    fn an_unscored_vulnerability_takes_the_highest_score_of_a_direct_alias() {
        let mut rows = [
            advisory(
                "PYSEC-2018-28",
                None,
                None,
                &["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
            ),
            advisory(
                "GHSA-x84v-xcm2-53pg",
                Some(7.5),
                None,
                &["CVE-2018-18074", "PYSEC-2018-28"],
            ),
            // Named only by the scored record, which lists it.
            advisory("PYSEC-2020-1", None, None, &[]),
            advisory("GHSA-aaaa", Some(5.0), Some("MODERATE"), &["PYSEC-2020-1"]),
            advisory("GHSA-bbbb", Some(8.1), None, &["PYSEC-2020-1"]),
            // Sharing only a CVE is not a direct alias.
            advisory("PYSEC-2021-1", None, None, &["CVE-1"]),
            advisory("GHSA-cccc", Some(9.8), None, &["CVE-1"]),
            // A malware record neither takes nor gives a score.
            Rows {
                malware: true,
                ..advisory("MAL-1", None, None, &["GHSA-cccc"])
            },
            // A scored record keeps its own.
            advisory("PYSEC-2022-1", Some(2.0), None, &["GHSA-cccc"]),
        ];
        assert_eq!(score_from_aliases(&mut rows), 2);
        let score = |id: &str| {
            let r = rows.iter().find(|r| r.id == id).expect("a row");
            (r.cvss, r.band.as_deref())
        };
        assert_eq!(score("PYSEC-2018-28"), (Some(7.5), None));
        assert_eq!(score("PYSEC-2020-1"), (Some(8.1), None));
        assert_eq!(score("PYSEC-2021-1"), (None, None));
        assert_eq!(score("MAL-1"), (None, None));
        assert_eq!(score("PYSEC-2022-1"), (Some(2.0), None));

        let mut banded = [
            advisory("PYSEC-2023-1", None, None, &["GHSA-dddd"]),
            advisory("GHSA-dddd", Some(6.9), Some("MODERATE"), &[]),
        ];
        assert_eq!(score_from_aliases(&mut banded), 1);
        assert_eq!(
            (banded[0].cvss, banded[0].band.as_deref()),
            (Some(6.9), Some("MODERATE")),
            "a score read from a band still says so"
        );
    }
}
