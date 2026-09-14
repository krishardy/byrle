//! OSV records, as rows for the intel store.
//!
//! Two publishers' records are read for npm. Non-withdrawn counts from `npm/all.zip` fetched
//! 2026-09-13:
//!
//! | Prefix | Publisher | Records | `malware` |
//! |---|---|---|---|
//! | `MAL-` | OpenSSF Malicious Packages | 221,217 | true |
//! | `GHSA-` | GitHub Advisory Database | 7,052 | false |
//!
//! The other two, `EEF-CVE-2026-56812` and `GSD-2022-1000008`, are skipped as
//! [`Skipped::OtherPublisher`].
//!
//! Each npm `affected` entry becomes rows:
//!
//! | Entry shape | Stored as |
//! |---|---|
//! | a range that is every version, such as `introduced: "0"` alone | one `advisory_affected` row, `version` NULL, and nothing else from the entry |
//! | otherwise, a `versions` list | one `advisory_affected` row per version |
//! | otherwise, and beside a list, other ranges | one `advisory_range` row per interval; see [`super::range`] |
//!
//! A list and a range are both stored because the list is what OSV enumerated when the
//! record was last modified. `MAL-2025-3661` lists 2 versions beside `introduced: "99.9.1"`,
//! and a version published into that range afterwards is only in the range.
//!
//! GHSA text is CC-BY-4.0, which owes attribution wherever it is shown. `summary` is stored
//! and nothing displays it. See `docs/engineering_decisions/advisory-stream-licences.md`.

use super::range::{self, Interval};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The `source` every row from this module is stored under.
pub const SOURCE: &str = "osv";

const NPM: &str = "npm";

/// One OSV record, as the store holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Rows {
    pub id: String,
    pub summary: Option<String>,
    /// RFC 3339, as OSV wrote it.
    pub modified: Option<String>,
    pub malware: bool,
    /// The CVSS base score. `None` when the record carries no CVSS vector that parses.
    pub cvss: Option<f64>,
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

/// An interval of package versions an advisory is against. Never every version, which is
/// an [`Affected`] with no version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ranged {
    pub ecosystem: String,
    pub name: String,
    pub interval: Interval<String>,
}

/// Why a record produced no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    Withdrawn,
    /// Neither a `MAL-` nor a `GHSA-` record.
    OtherPublisher,
    NoNpmPackage,
    /// No npm entry held a version, or a range that could be evaluated.
    NothingStorable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Rows(Rows),
    Skipped(Skipped),
}

#[derive(Deserialize)]
struct Record {
    id: String,
    summary: Option<String>,
    modified: Option<String>,
    withdrawn: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<Severity>,
    #[serde(default)]
    affected: Vec<Entry>,
}

#[derive(Deserialize)]
struct Severity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct Entry {
    package: Option<Package>,
    #[serde(default)]
    ranges: Vec<Range>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct Range {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

/// The base score of the newest CVSS version the record carries, and how many of its
/// vectors did not parse.
///
/// Newest rather than highest. v3 and v4 are different scoring systems, and taking the
/// larger of the two would compare them as one. On 2026-09-13, 809 GHSA records carried
/// both. Only `CVSS_V3` and `CVSS_V4` entries are read; no npm record carried another type.
fn score(severity: &[Severity]) -> (Option<f64>, usize) {
    let vectors = severity
        .iter()
        .filter(|s| matches!(s.kind.as_str(), "CVSS_V3" | "CVSS_V4"));
    let (mut best, mut unread) = (None::<cvss::Cvss>, 0);
    for vector in vectors {
        match base_vector(&vector.score).and_then(|v| v.parse::<cvss::Cvss>().ok()) {
            Some(parsed) if !complete(&parsed) => unread += 1,
            Some(parsed) if best.as_ref().is_none_or(|b| newness(&parsed) > newness(b)) => {
                best = Some(parsed);
            }
            Some(_) => {}
            None => unread += 1,
        }
    }
    (best.as_ref().map(cvss::Cvss::score), unread)
}

const V3_BASE: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const V4_BASE: [&str; 11] = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

/// The vector with only its base metrics, or `None` when one appears twice.
///
/// The score compared is the base score. GHSA vectors also carry threat and temporal
/// metrics, such as `E:U` for an exploit nobody has reported, which lower a score. `cvss`
/// 2.2.0 counts them in a v4 score and refuses a v3 vector that carries them. A vector with
/// an unknown prefix is returned whole, for `cvss` to refuse.
fn base_vector(vector: &str) -> Option<String> {
    let mut parts = vector.split('/');
    let prefix = parts.next()?;
    let base: &[&str] = match prefix {
        "CVSS:3.0" | "CVSS:3.1" => &V3_BASE,
        "CVSS:4.0" => &V4_BASE,
        _ => return Some(vector.to_owned()),
    };
    let (mut seen, mut out) = (BTreeSet::new(), prefix.to_owned());
    for part in parts {
        let metric = part.split(':').next().unwrap_or_default();
        if base.contains(&metric) {
            if !seen.insert(metric) {
                return None;
            }
            out.push('/');
            out.push_str(part);
        }
    }
    Some(out)
}

/// Whether every base metric is present.
///
/// `cvss` 2.2.0 refuses a v4 vector missing one, and parses a v3 vector missing any of them,
/// scoring `CVSS:3.1/AV:N` as 0.0. That would pass every `max_cvss`.
fn complete(vector: &cvss::Cvss) -> bool {
    match vector {
        cvss::Cvss::CvssV30(base) | cvss::Cvss::CvssV31(base) => {
            base.av.is_some()
                && base.ac.is_some()
                && base.pr.is_some()
                && base.ui.is_some()
                && base.s.is_some()
                && base.c.is_some()
                && base.i.is_some()
                && base.a.is_some()
        }
        _ => true,
    }
}

fn newness(vector: &cvss::Cvss) -> u8 {
    match vector {
        cvss::Cvss::CvssV30(_) => 0,
        cvss::Cvss::CvssV31(_) => 1,
        _ => 2,
    }
}

/// Read one OSV record.
///
/// Unknown fields are accepted. This is a feed that adds fields, not a file an operator
/// writes, so refusing one would stop every refresh on a schema bump.
pub fn parse(bytes: &[u8]) -> Result<Parsed, serde_json::Error> {
    let record: Record = serde_json::from_slice(bytes)?;
    if record.withdrawn.is_some() {
        return Ok(Parsed::Skipped(Skipped::Withdrawn));
    }
    let malware = if record.id.starts_with("MAL-") {
        true
    } else if record.id.starts_with("GHSA-") {
        false
    } else {
        return Ok(Parsed::Skipped(Skipped::OtherPublisher));
    };

    let (mut affected, mut ranges) = (BTreeSet::new(), BTreeSet::new());
    let (mut npm_entries, mut unexpressed) = (0, 0);
    for entry in &record.affected {
        let Some(package) = entry.package.as_ref().filter(|p| p.ecosystem == NPM) else {
            continue;
        };
        npm_entries += 1;

        let (mut intervals, mut every, mut refused) = (BTreeSet::new(), false, 0);
        for r in &entry.ranges {
            match range::intervals(r.kind.as_deref(), &r.events) {
                Ok(found) => {
                    for interval in found {
                        every |= interval.is_every_version();
                        intervals.insert(interval);
                    }
                }
                Err(_) => refused += 1,
            }
        }

        let row = |version: Option<&String>| Affected {
            ecosystem: NPM.to_owned(),
            name: package.name.clone(),
            version: version.cloned(),
        };
        // Every version subsumes everything else the entry says, a refused range included.
        if every {
            affected.insert(row(None));
            continue;
        }
        if refused > 0 || (entry.versions.is_empty() && intervals.is_empty()) {
            unexpressed += 1;
        }
        // Padded as a range's versions are, so a listed `12.0` matches the published `12.0.0`.
        // One that does not pad is kept as written.
        let listed = entry
            .versions
            .iter()
            .map(|v| range::padded(v).unwrap_or_else(|| v.clone()));
        affected.extend(listed.map(|v| row(Some(&v))));
        ranges.extend(intervals.into_iter().map(|interval| Ranged {
            ecosystem: NPM.to_owned(),
            name: package.name.clone(),
            interval,
        }));
    }

    if npm_entries == 0 {
        return Ok(Parsed::Skipped(Skipped::NoNpmPackage));
    }
    if affected.is_empty() && ranges.is_empty() {
        return Ok(Parsed::Skipped(Skipped::NothingStorable));
    }
    let (cvss, unread_vectors) = score(&record.severity);
    Ok(Parsed::Rows(Rows {
        id: record.id,
        summary: record.summary,
        modified: record.modified,
        malware,
        cvss,
        unread_vectors,
        aliases: record.aliases.into_iter().collect(),
        affected,
        ranges,
        unexpressed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::range::End;

    fn fixture(id: &str) -> Parsed {
        let path = format!(
            "{}/tests/fixtures/osv/{id}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        parse(&std::fs::read(path).expect("fixture is missing")).expect("fixture should parse")
    }

    fn rows(id: &str) -> Rows {
        match fixture(id) {
            Parsed::Rows(rows) => rows,
            other => panic!("{id}: {other:?}"),
        }
    }

    fn versions(rows: &Rows) -> Vec<Option<&str>> {
        rows.affected.iter().map(|a| a.version.as_deref()).collect()
    }

    fn intervals(rows: &Rows) -> Vec<&Interval<String>> {
        rows.ranges.iter().map(|r| &r.interval).collect()
    }

    fn record(id: &str, affected: &str) -> Parsed {
        parse(format!(r#"{{"id": "{id}", "affected": [{affected}]}}"#).as_bytes())
            .expect("should parse")
    }

    fn inline(affected: &str) -> Parsed {
        record("MAL-0", affected)
    }

    fn stored(parsed: Parsed) -> Rows {
        match parsed {
            Parsed::Rows(rows) => rows,
            other => panic!("{other:?}"),
        }
    }

    /// A GHSA-shaped record with these `severity` entries, written with an id that is not a
    /// real advisory: GHSA text is CC-BY-4.0 and none is committed.
    fn scored(severity: &str) -> Rows {
        stored(
            parse(
                format!(
                    r#"{{"id": "GHSA-0000-0000-0000", "severity": [{severity}],
                         "affected": [{{"package": {{"ecosystem": "npm", "name": "p"}},
                                        "versions": ["1.0.0"]}}]}}"#
                )
                .as_bytes(),
            )
            .expect("should parse"),
        )
    }

    const V31_CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const V30_CRITICAL: &str = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    const V40_CONFIDENTIALITY_LOW: &str =
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";

    fn severity(kind: &str, vector: &str) -> String {
        format!(r#"{{"type": "{kind}", "score": "{vector}"}}"#)
    }

    #[test]
    fn an_introduced_zero_range_is_every_version() {
        let rows = rows("MAL-2021-1");
        assert_eq!(versions(&rows), vec![None]);
        assert!(rows.ranges.is_empty());
        assert!(rows.malware);
        assert_eq!(rows.cvss, None);
        assert_eq!(rows.unexpressed, 0);
        assert!(rows.summary.is_some());
        assert!(rows.modified.is_some());
    }

    #[test]
    fn a_versions_list_is_one_row_per_version() {
        let rows = rows("MAL-2022-174");
        assert_eq!(rows.affected.len(), 4);
        assert!(versions(&rows).iter().all(Option::is_some));
        assert_eq!(
            rows.aliases.iter().collect::<Vec<_>>(),
            vec!["GHSA-gjfj-qv3p-9q4w"]
        );
    }

    #[test]
    fn every_version_subsumes_a_list_beside_it() {
        assert_eq!(versions(&rows("MAL-2022-1122")), vec![None]);
        // Here the zero range is the second of two.
        let rows = rows("MAL-2025-3605");
        assert_eq!(versions(&rows), vec![None]);
        assert!(rows.ranges.is_empty());
    }

    #[test]
    fn a_bounded_range_with_a_list_stores_both() {
        let rows = rows("MAL-2025-3661");
        assert_eq!(versions(&rows), vec![Some("99.9.0"), Some("99.9.1")]);
        assert_eq!(
            intervals(&rows),
            vec![&Interval {
                introduced: Some("99.9.1".to_owned()),
                end: End::Open,
            }]
        );
        assert_eq!(rows.unexpressed, 0);
    }

    #[test]
    fn a_bounded_range_alone_is_stored_as_that_range() {
        let rows = rows("MAL-2022-219");
        assert!(rows.affected.is_empty());
        assert_eq!(
            intervals(&rows),
            vec![&Interval {
                introduced: Some("1.2.2".to_owned()),
                end: End::Open,
            }]
        );
    }

    #[test]
    fn a_withdrawn_record_is_skipped() {
        assert_eq!(
            fixture("MAL-2024-1398"),
            Parsed::Skipped(Skipped::Withdrawn)
        );
    }

    /// Records shaped alike, so only the id decides.
    #[test]
    fn the_id_prefix_decides_malware_and_whether_the_record_is_read() {
        let listed = r#"{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}"#;
        assert!(stored(record("MAL-0000-0", listed)).malware);
        assert!(!stored(record("GHSA-0000-0000-0000", listed)).malware);
        for other in [
            "EEF-CVE-0000-0",
            "GSD-0000-0",
            "CVE-0000-0",
            "MAL0",
            "GHSA0",
        ] {
            assert_eq!(
                record(other, listed),
                Parsed::Skipped(Skipped::OtherPublisher),
                "{other}"
            );
        }
    }

    #[test]
    fn a_zero_range_with_an_end_is_a_range_not_every_version() {
        let fixed = r#"{"package": {"ecosystem": "npm", "name": "p"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}"#;
        let rows = stored(inline(fixed));
        assert!(rows.affected.is_empty());
        assert_eq!(
            intervals(&rows),
            vec![&Interval {
                introduced: None,
                end: End::Fixed("2.0.0".to_owned()),
            }]
        );
    }

    #[test]
    fn an_entry_whose_only_range_is_refused_stores_nothing() {
        let two_keys = r#"{"package": {"ecosystem": "npm", "name": "p"},
                           "ranges": [{"type": "SEMVER", "events": [{"introduced": "0", "last_affected": "1.0.0"}]}]}"#;
        assert_eq!(inline(two_keys), Parsed::Skipped(Skipped::NothingStorable));
        let not_semver = r#"{"package": {"ecosystem": "npm", "name": "p"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0rc1"}]}]}"#;
        assert_eq!(
            inline(not_semver),
            Parsed::Skipped(Skipped::NothingStorable)
        );
    }

    #[test]
    fn every_version_subsumes_a_refused_range_beside_it() {
        let rows = stored(inline(
            r#"{"package": {"ecosystem": "npm", "name": "p"},
                "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]},
                           {"type": "SEMVER", "events": [{"introduced": "0"}]}]}"#,
        ));
        assert_eq!(versions(&rows), vec![None]);
        assert_eq!(rows.unexpressed, 0);
    }

    #[test]
    fn a_record_for_another_ecosystem_is_skipped() {
        let pypi = r#"{"package": {"ecosystem": "PyPI", "name": "p"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}"#;
        assert_eq!(inline(pypi), Parsed::Skipped(Skipped::NoNpmPackage));
        assert_eq!(
            inline(r#"{"versions": ["1.0.0"]}"#),
            Parsed::Skipped(Skipped::NoNpmPackage)
        );
    }

    #[test]
    fn an_unstorable_entry_beside_a_stored_one_is_counted() {
        let rows = stored(inline(
            r#"{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0", "1.0.0"]},
               {"package": {"ecosystem": "npm", "name": "b"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "v2026.4.1"}]}]}"#,
        ));
        // The repeated version is one row, or the unique index refuses the load.
        assert_eq!(rows.affected.len(), 1);
        assert_eq!(rows.unexpressed, 1);
    }

    #[test]
    fn a_refused_range_beside_a_list_stores_the_list_and_is_counted() {
        let rows = stored(inline(
            r#"{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0"],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]},
                           {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0rc1"}]}]}"#,
        ));
        assert_eq!(rows.affected.len(), 1);
        assert_eq!(rows.ranges.len(), 1);
        assert_eq!(rows.unexpressed, 1);
    }

    /// Shaped as `GHSA-3h52-269p-cp9r` for `next` and `GHSA-pwvp-h579-hfxg` for `total4`,
    /// which stored nothing before.
    #[test]
    fn a_short_version_in_a_range_or_a_list_is_stored_padded() {
        let rows = stored(inline(
            r#"{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["12.0", "12.0.0", "1.0.0rc1"],
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "13.0"}, {"fixed": "14.2.30"}]}]}"#,
        ));
        assert_eq!(versions(&rows), vec![Some("1.0.0rc1"), Some("12.0.0")]);
        assert_eq!(
            intervals(&rows),
            vec![&Interval {
                introduced: Some("13.0.0".to_owned()),
                end: End::Fixed("14.2.30".to_owned()),
            }]
        );
        assert_eq!(rows.unexpressed, 0);
    }

    #[test]
    fn a_v4_score_is_taken_over_a_v3_one_in_either_order() {
        let v3 = severity("CVSS_V3", V31_CRITICAL);
        let v4 = severity("CVSS_V4", V40_CONFIDENTIALITY_LOW);
        for order in [format!("{v3}, {v4}"), format!("{v4}, {v3}")] {
            let rows = scored(&order);
            // Lower than the v3 score, so this is not the larger of the two.
            assert_eq!(rows.cvss, Some(6.9), "{order}");
            assert!(!rows.malware);
        }
    }

    #[test]
    fn a_v3_score_is_read_alone_and_3_1_is_taken_over_3_0() {
        assert_eq!(scored(&severity("CVSS_V3", V31_CRITICAL)).cvss, Some(9.8));
        assert_eq!(scored(&severity("CVSS_V3", V30_CRITICAL)).cvss, Some(9.8));
        let low_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
        let both = format!(
            "{}, {}",
            severity("CVSS_V3", V30_CRITICAL),
            severity("CVSS_V3", low_31)
        );
        assert_eq!(scored(&both).cvss, Some(5.3));
    }

    #[test]
    fn a_vector_that_does_not_parse_is_counted_and_scores_nothing() {
        // Each missing one base metric. `cvss` scores the v3 ones 0.0 if asked.
        for incomplete in [
            "CVSS:3.1/AV:N",
            "CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/A:H",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "CVSS:4.0/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        ] {
            let rows = scored(&severity("CVSS_V3", incomplete));
            assert_eq!((rows.cvss, rows.unread_vectors), (None, 1), "{incomplete}");
        }

        let beside = format!(
            "{}, {}",
            severity("CVSS_V4", "CVSS:4.0/AV:X"),
            severity("CVSS_V3", V31_CRITICAL)
        );
        let rows = scored(&beside);
        assert_eq!((rows.cvss, rows.unread_vectors), (Some(9.8), 1));
    }

    #[test]
    fn threat_and_temporal_metrics_do_not_change_the_base_score() {
        let v3 = format!("{V31_CRITICAL}/E:U/RL:O/RC:R");
        let rows = scored(&severity("CVSS_V3", &v3));
        assert_eq!((rows.cvss, rows.unread_vectors), (Some(9.8), 0), "{v3}");
        let v4_critical = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        for v4 in [
            v4_critical.to_owned(),
            format!("{v4_critical}/E:U"),
            format!("{v4_critical}/E:U/U:Clear/"),
        ] {
            let rows = scored(&severity("CVSS_V4", &v4));
            assert_eq!((rows.cvss, rows.unread_vectors), (Some(9.3), 0), "{v4}");
        }
    }

    #[test]
    fn a_base_metric_given_twice_is_unread() {
        let twice = format!("{V31_CRITICAL}/C:N");
        let rows = scored(&severity("CVSS_V3", &twice));
        assert_eq!((rows.cvss, rows.unread_vectors), (None, 1));
        let rows = scored(&severity("CVSS_V4", "CVSS:2.0/AV:N"));
        assert_eq!((rows.cvss, rows.unread_vectors), (None, 1), "unknown prefix");
    }

    #[test]
    fn no_cvss_vector_is_no_score_and_nothing_unread() {
        let rows = scored("");
        assert_eq!((rows.cvss, rows.unread_vectors), (None, 0));
        let other = scored(&severity("Ubuntu", "high"));
        assert_eq!((other.cvss, other.unread_vectors), (None, 0));
    }

    #[test]
    fn a_record_that_is_not_json_is_an_error() {
        assert!(parse(b"{\"id\": ").is_err());
    }
}
