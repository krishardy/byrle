//! OSV records, as rows for the intel store, one ecosystem's bundle at a time.
//!
//! See docs/engineering_decisions/osv-ranges-and-scores.md and
//! docs/engineering_decisions/advisory-stream-licences.md.

pub mod bundle;

use crate::intel::range;
use crate::intel::rows::{Affected, Ranged, Rows, band_ceiling};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::identity::Ecosystem;

/// The publishers whose records are read, by id prefix, and whether each publishes malware.
const PUBLISHERS: [(&str, bool); 4] = [
    ("MAL-", true),
    ("GHSA-", false),
    ("PYSEC-", false),
    ("OSV-", false),
];

/// The name OSV gives `ecosystem`, in `affected[].package.ecosystem` and in its bundle's
/// path.
pub const fn osv_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "PyPI",
    }
}

/// Why a record produced no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    Withdrawn,
    /// An id whose prefix is not `MAL-`, `GHSA-`, `PYSEC-` or `OSV-`.
    OtherPublisher,
    /// No `affected` entry is for the ecosystem being read.
    NoPackage,
    /// No entry for the ecosystem held a version, or a range that could be evaluated.
    NothingStorable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    /// Boxed: a record's rows are far larger than a reason to skip it.
    Rows(Box<Rows>),
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
    /// Read only for `severity`, a GitHub band. Any shape is accepted.
    database_specific: Option<serde_json::Value>,
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

/// The base score of the newest CVSS version in `severity`, or with no vector at all, the
/// top of `band`. See docs/engineering_decisions/osv-ranges-and-scores.md.
/// Returns the score, the band it was read from, and how many vectors did not parse.
fn score(severity: &[Severity], band: Option<&str>) -> (Option<f64>, Option<String>, usize) {
    let (cvss, unread) = vector_score(severity);
    match (cvss, band.and_then(|b| Some((b, band_ceiling(b)?)))) {
        (None, Some((band, ceiling))) if unread == 0 => (Some(ceiling), Some(band.to_owned()), 0),
        _ => (cvss, None, unread),
    }
}

/// The base score of the newest CVSS version the record carries, and how many of its
/// vectors did not parse.
fn vector_score(severity: &[Severity]) -> (Option<f64>, usize) {
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
/// `vector` is returned whole when its prefix is unknown, for `cvss` to refuse.
fn base_vector(vector: &str) -> Option<String> {
    let mut parts = vector.split('/');
    let prefix = parts.next().unwrap_or_default();
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
/// `cvss` 3.0.0 refuses a v4 vector missing one, and parses a v3 vector missing any of them,
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
pub fn parse(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, serde_json::Error> {
    let record: Record = serde_json::from_slice(bytes)?;
    if record.withdrawn.is_some() {
        return Ok(Parsed::Skipped(Skipped::Withdrawn));
    }
    let Some(&(_, malware)) = PUBLISHERS
        .iter()
        .find(|(prefix, _)| record.id.starts_with(prefix))
    else {
        return Ok(Parsed::Skipped(Skipped::OtherPublisher));
    };
    let (osv, purl_type) = (osv_name(ecosystem), ecosystem.as_str());
    let order = crate::ecosystem::of(ecosystem).versions;

    let entries: Vec<_> = record
        .affected
        .iter()
        .filter_map(|entry| {
            let package = entry.package.as_ref().filter(|p| p.ecosystem == osv)?;
            Some((entry, package))
        })
        .collect();
    if entries.is_empty() {
        return Ok(Parsed::Skipped(Skipped::NoPackage));
    }

    let (mut affected, mut ranges) = (BTreeSet::new(), BTreeSet::new());
    let mut unexpressed = 0;
    for (entry, package) in entries {
        let (mut intervals, mut every, mut refused) = (BTreeSet::new(), false, 0);
        for r in &entry.ranges {
            match range::intervals(order, r.kind.as_deref(), &r.events) {
                Ok(found) => {
                    for interval in found {
                        every |= interval.is_every_version();
                        intervals.insert(interval);
                    }
                }
                Err(_) => refused += 1,
            }
        }

        let row =
            |version: Option<&String>| Affected::new(purl_type, &package.name, version.cloned());
        if every {
            affected.insert(row(None));
            continue;
        }
        if refused > 0 || (entry.versions.is_empty() && intervals.is_empty()) {
            unexpressed += 1;
        }
        let listed = entry.versions.iter().map(|v| range::stored(order, v));
        affected.extend(listed.map(|v| row(Some(&v))));
        ranges.extend(
            intervals
                .into_iter()
                .map(|interval| Ranged::new(purl_type, &package.name, interval)),
        );
    }

    if affected.is_empty() && ranges.is_empty() {
        return Ok(Parsed::Skipped(Skipped::NothingStorable));
    }
    let band = record
        .database_specific
        .as_ref()
        .and_then(|d| d.get("severity"))
        .and_then(serde_json::Value::as_str);
    let (cvss, band, unread_vectors) = score(&record.severity, band);
    Ok(Parsed::Rows(Box::new(Rows {
        id: record.id,
        summary: record.summary,
        modified: record.modified,
        malware,
        cvss,
        band,
        unread_vectors,
        aliases: record.aliases.into_iter().collect(),
        affected,
        ranges,
        unexpressed,
    })))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::intel::range::{End, Interval, Start};

    fn fixture(id: &str) -> Parsed {
        let path = format!(
            "{}/tests/fixtures/osv/{id}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        parse(
            Ecosystem::Npm,
            &std::fs::read(path).expect("fixture is missing"),
        )
        .expect("fixture should parse")
    }

    fn rows(id: &str) -> Rows {
        match fixture(id) {
            Parsed::Rows(rows) => *rows,
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
        parse(
            Ecosystem::Npm,
            format!(r#"{{"id": "{id}", "affected": [{affected}]}}"#).as_bytes(),
        )
        .expect("should parse")
    }

    fn inline(affected: &str) -> Parsed {
        record("MAL-0", affected)
    }

    fn stored(parsed: Parsed) -> Rows {
        match parsed {
            Parsed::Rows(rows) => *rows,
            other => panic!("{other:?}"),
        }
    }

    /// A GHSA-shaped record with these `severity` entries, written with an id that is not a
    /// real advisory: GHSA text is CC-BY-4.0 and none is committed.
    fn scored(severity: &str) -> Rows {
        stored(
            parse(
                Ecosystem::Npm,
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
                start: Start::Introduced("99.9.1".to_owned()),
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
                start: Start::Introduced("1.2.2".to_owned()),
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
                start: Start::First,
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
        assert_eq!(inline(pypi), Parsed::Skipped(Skipped::NoPackage));
        assert_eq!(
            inline(r#"{"versions": ["1.0.0"]}"#),
            Parsed::Skipped(Skipped::NoPackage)
        );
    }

    #[test]
    fn an_unstorable_entry_beside_a_stored_one_is_counted() {
        let rows = stored(inline(
            r#"{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0", "1.0.0"]},
               {"package": {"ecosystem": "npm", "name": "b"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "v2026.4.1"}]}]}"#,
        ));
        assert_eq!(
            rows.affected.len(),
            1,
            "a repeated version is one row, or the unique index refuses the load"
        );
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
                start: Start::Introduced("13.0.0".to_owned()),
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
            assert_eq!(rows.cvss, Some(6.9), "the lower v4 score, in {order}");
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
        assert_eq!(
            (rows.cvss, rows.unread_vectors),
            (None, 1),
            "unknown prefix"
        );
    }

    #[test]
    fn no_cvss_vector_is_no_score_and_nothing_unread() {
        let rows = scored("");
        assert_eq!((rows.cvss, rows.unread_vectors), (None, 0));
        let other = scored(&severity("Ubuntu", "high"));
        assert_eq!((other.cvss, other.unread_vectors), (None, 0));
    }

    /// [`scored`], with `database_specific` given as JSON text.
    fn banded(database_specific: &str, severity: &str) -> Rows {
        stored(
            parse(
                Ecosystem::Npm,
                format!(
                    r#"{{"id": "GHSA-0000-0000-0000", "severity": [{severity}],
                         "database_specific": {database_specific},
                         "affected": [{{"package": {{"ecosystem": "npm", "name": "p"}},
                                        "versions": ["1.0.0"]}}]}}"#
                )
                .as_bytes(),
            )
            .expect("should parse"),
        )
    }

    #[test]
    fn a_record_with_only_a_band_is_scored_at_the_top_of_the_band() {
        for (band, cvss) in [
            ("LOW", 3.9),
            ("MODERATE", 6.9),
            ("HIGH", 8.9),
            ("CRITICAL", 10.0),
        ] {
            let rows = banded(&format!(r#"{{"severity": "{band}", "cwe_ids": []}}"#), "");
            assert_eq!(
                (rows.cvss, rows.band.as_deref(), rows.unread_vectors),
                (Some(cvss), Some(band), 0),
                "{band}"
            );
        }
    }

    #[test]
    fn a_vector_is_read_over_a_band_and_an_unread_one_is_not_replaced_by_it() {
        let high = r#"{"severity": "HIGH"}"#;
        let rows = banded(high, &severity("CVSS_V3", V31_CRITICAL));
        assert_eq!((rows.cvss, rows.band), (Some(9.8), None));
        let rows = banded(high, &severity("CVSS_V3", "CVSS:3.1/AV:N"));
        assert_eq!((rows.cvss, rows.band, rows.unread_vectors), (None, None, 1));
        let rows = banded(high, &severity("Ubuntu", "high"));
        assert_eq!((rows.cvss, rows.band.as_deref()), (Some(8.9), Some("HIGH")));
    }

    #[test]
    fn a_band_this_build_does_not_know_scores_nothing_and_refuses_nothing() {
        for database_specific in [
            r#"{"severity": "moderate"}"#,
            r#"{"severity": "MEDIUM"}"#,
            r#"{"severity": ""}"#,
            r#"{"severity": 7}"#,
            r#"{"severity": null}"#,
            r#"{}"#,
            r#""HIGH""#,
            "null",
        ] {
            let rows = banded(database_specific, "");
            assert_eq!(
                (rows.cvss, rows.band, rows.unread_vectors),
                (None, None, 0),
                "{database_specific}"
            );
        }
    }

    #[test]
    fn a_record_that_is_not_json_is_an_error() {
        assert!(parse(Ecosystem::Npm, b"{\"id\": ").is_err());
    }

    /// A PyPI record is read by PyPI's rules: its ecosystem name, purl type, PEP 503 name
    /// and PEP 440 versions. The same record read for npm has no package.
    #[test]
    fn a_pypi_record_is_read_by_pypis_rules() {
        let record = |id: &str| {
            format!(
                r#"{{"id": "{id}", "affected": [{{"package": {{"ecosystem": "PyPI", "name": "Jupyter_Server"}},
                    "versions": ["1.0"],
                    "ranges": [{{"type": "ECOSYSTEM", "events": [{{"introduced": "0"}}, {{"fixed": "2.6.11-1"}}]}}]}}]}}"#
            )
        };
        for id in ["PYSEC-2023-1", "OSV-2021-1", "GHSA-aaaa-bbbb-cccc"] {
            let Parsed::Rows(rows) = parse(Ecosystem::PyPI, record(id).as_bytes()).expect("parses")
            else {
                panic!("{id} is stored");
            };
            assert!(!rows.malware, "{id}");
            let affected: Vec<_> = rows.affected.iter().collect();
            assert_eq!(affected.len(), 1);
            assert_eq!(
                (affected[0].ecosystem.as_str(), affected[0].name.as_str()),
                ("pypi", "jupyter-server")
            );
            assert_eq!(affected[0].version.as_deref(), Some("1.0"));
            assert_eq!(
                intervals(&rows),
                [&Interval {
                    start: Start::First,
                    end: End::Fixed("2.6.11.post1".to_owned()),
                }]
            );
            assert_eq!(
                parse(Ecosystem::Npm, record(id).as_bytes()).expect("parses"),
                Parsed::Skipped(Skipped::NoPackage)
            );
        }
        assert_eq!(osv_name(Ecosystem::PyPI), "PyPI");
        assert_eq!(osv_name(Ecosystem::Npm), "npm");
    }
}
