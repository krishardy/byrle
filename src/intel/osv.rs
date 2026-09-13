//! OSV records, as rows for the intel store.
//!
//! This reads OSV's `MAL-` records for npm and nothing else. They feed `known_malware`, the
//! check with no exception, and they need no version-range evaluation. Measured over
//! `npm/all.zip` fetched 2026-09-13, the 221,217 non-withdrawn `MAL-` records each carry one
//! npm entry:
//!
//! | Entry shape | Entries | Stored as |
//! |---|---|---|
//! | a range of `introduced: "0"` and no end | 206,687 | one row, `version` NULL |
//! | a `versions` list, and no such range | 13,997 | one row per listed version |
//! | neither | 533 | nothing: [`Skipped::NeedsRangeEvaluation`] |
//!
//! Of the 13,997, 472 also carry a range such as `introduced: "99.9.1"` with no end. Their
//! `versions` list is what OSV enumerated when the record was last modified, so a version
//! published inside that range afterwards is not stored.
//!
//! `GHSA-` records are skipped. 9,320 of their npm entries are bounded ranges with no
//! `versions` list, and GHSA text is CC-BY-4.0, which owes attribution wherever it is shown.
//! See `docs/engineering_decisions/advisory-stream-licences.md`.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The `source` every row from this module is stored under.
pub const SOURCE: &str = "osv";

const NPM: &str = "npm";

/// One OSV record, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rows {
    pub id: String,
    pub summary: Option<String>,
    /// RFC 3339, as OSV wrote it.
    pub modified: Option<String>,
    pub malware: bool,
    pub aliases: BTreeSet<String>,
    pub affected: BTreeSet<Affected>,
    /// npm entries in the record that could not be stored, so a record can be partly
    /// stored without that reading as fully stored.
    pub unexpressed: usize,
}

/// A package version an advisory is against. `version` `None` is every version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Affected {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

/// Why a record produced no rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    Withdrawn,
    /// Not a `MAL-` record.
    NotMalware,
    NoNpmPackage,
    /// Every npm entry is a range with a lower bound other than `0` and no `versions` list.
    NeedsRangeEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    affected: Vec<Entry>,
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
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

impl Range {
    /// One event, `introduced: "0"`: from the first version, with no end.
    fn is_every_version(&self) -> bool {
        matches!(
            self.events.as_slice(),
            [only] if only.len() == 1 && only.get("introduced").is_some_and(|v| v == "0")
        )
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
    if !record.id.starts_with("MAL-") {
        return Ok(Parsed::Skipped(Skipped::NotMalware));
    }

    let mut affected = BTreeSet::new();
    let (mut npm_entries, mut unexpressed) = (0, 0);
    for entry in &record.affected {
        let Some(package) = entry.package.as_ref().filter(|p| p.ecosystem == NPM) else {
            continue;
        };
        npm_entries += 1;
        let row = |version: Option<&String>| Affected {
            ecosystem: NPM.to_owned(),
            name: package.name.clone(),
            version: version.cloned(),
        };
        // Every version subsumes any list, so a list beside it adds nothing.
        if entry.ranges.iter().any(Range::is_every_version) {
            affected.insert(row(None));
        } else if !entry.versions.is_empty() {
            affected.extend(entry.versions.iter().map(Some).map(row));
        } else {
            unexpressed += 1;
        }
    }

    if npm_entries == 0 {
        return Ok(Parsed::Skipped(Skipped::NoNpmPackage));
    }
    if affected.is_empty() {
        return Ok(Parsed::Skipped(Skipped::NeedsRangeEvaluation));
    }
    Ok(Parsed::Rows(Rows {
        id: record.id,
        summary: record.summary,
        modified: record.modified,
        malware: true,
        aliases: record.aliases.into_iter().collect(),
        affected,
        unexpressed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn record(id: &str, affected: &str) -> Parsed {
        parse(format!(r#"{{"id": "{id}", "affected": [{affected}]}}"#).as_bytes())
            .expect("should parse")
    }

    fn inline(affected: &str) -> Parsed {
        record("MAL-0", affected)
    }

    #[test]
    fn an_introduced_zero_range_is_every_version() {
        let rows = rows("MAL-2021-1");
        assert_eq!(versions(&rows), vec![None]);
        assert!(rows.malware);
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
        assert_eq!(versions(&rows("MAL-2025-3605")), vec![None]);
    }

    #[test]
    fn a_bounded_range_with_a_list_stores_the_list() {
        let rows = rows("MAL-2025-3661");
        assert_eq!(rows.affected.len(), 2);
        assert!(versions(&rows).iter().all(Option::is_some));
    }

    #[test]
    fn a_bounded_range_alone_is_not_stored_as_every_version() {
        assert_eq!(
            fixture("MAL-2022-219"),
            Parsed::Skipped(Skipped::NeedsRangeEvaluation)
        );
    }

    #[test]
    fn a_withdrawn_record_is_skipped() {
        assert_eq!(
            fixture("MAL-2024-1398"),
            Parsed::Skipped(Skipped::Withdrawn)
        );
    }

    /// A GHSA record shaped like a storable malware one, so only the id decides.
    #[test]
    fn a_vulnerability_record_is_skipped() {
        let listed = r#"{"package": {"ecosystem": "npm", "name": "p"}, "versions": ["1.0.0"]}"#;
        assert_eq!(
            record("GHSA-0000-0000-0000", listed),
            Parsed::Skipped(Skipped::NotMalware)
        );
        assert!(matches!(record("MAL-0000-0", listed), Parsed::Rows(_)));
    }

    #[test]
    fn a_zero_range_with_an_end_is_not_every_version() {
        let fixed = r#"{"package": {"ecosystem": "npm", "name": "p"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}"#;
        assert_eq!(
            inline(fixed),
            Parsed::Skipped(Skipped::NeedsRangeEvaluation)
        );

        let last = r#"{"package": {"ecosystem": "npm", "name": "p"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0", "last_affected": "1.0.0"}]}]}"#;
        assert_eq!(inline(last), Parsed::Skipped(Skipped::NeedsRangeEvaluation));
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
        let parsed = inline(
            r#"{"package": {"ecosystem": "npm", "name": "a"}, "versions": ["1.0.0", "1.0.0"]},
               {"package": {"ecosystem": "npm", "name": "b"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}]}]}"#,
        );
        let Parsed::Rows(rows) = parsed else {
            panic!("{parsed:?}");
        };
        // The repeated version is one row, or the unique index refuses the load.
        assert_eq!(rows.affected.len(), 1);
        assert_eq!(rows.unexpressed, 1);
    }

    #[test]
    fn a_record_that_is_not_json_is_an_error() {
        assert!(parse(b"{\"id\": ").is_err());
    }
}
