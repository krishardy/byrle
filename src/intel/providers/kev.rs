//! Reading CISA's Known Exploited Vulnerabilities catalogue.
//!
//! One JSON document, CC0 1.0. On 2026-09-14 it was 1.7 MB and listed 1,710 CVE ids. An entry
//! gives a `cveID` and no package, so only `cveID` is read: an advisory is exploited when its id
//! or one of its aliases is listed. See docs/engineering_decisions/kev-stream.md.

use serde::Deserialize;
use std::collections::BTreeSet;

pub const CATALOGUE: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// The source the catalogue's ids are stored under, and the stream a snapshot records.
pub const STREAM: &str = "cisa/kev";

/// 9.7 times the catalogue on 2026-09-14.
pub const MAX_CATALOGUE_BYTES: usize = 16 << 20;

/// The width of `exploited_cve.cve_id`. A longer id is refused here, because a load that
/// Postgres refuses would also fail the OSV load in the same transaction.
const MAX_ID_BYTES: usize = 128;

#[derive(Deserialize)]
struct Catalogue {
    vulnerabilities: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// Why a catalogue was refused. Any of these refuses the whole catalogue.
#[derive(Debug)]
pub enum KevError {
    NotACatalogue(serde_json::Error),
    NotACveId(String),
    /// An empty list would delete every stored id.
    Empty,
}

impl std::fmt::Display for KevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotACatalogue(e) => write!(f, "not a KEV catalogue: {e}"),
            Self::NotACveId(id) => write!(f, "`{id}` is not a CVE id"),
            Self::Empty => f.write_str("the KEV catalogue lists no vulnerabilities"),
        }
    }
}

impl std::error::Error for KevError {}

/// The CVE ids the catalogue lists, each once.
pub fn parse(bytes: &[u8]) -> Result<BTreeSet<String>, KevError> {
    let catalogue: Catalogue = serde_json::from_slice(bytes).map_err(KevError::NotACatalogue)?;
    let ids = catalogue
        .vulnerabilities
        .into_iter()
        .map(|entry| {
            if is_cve_id(&entry.cve_id) {
                Ok(entry.cve_id)
            } else {
                Err(KevError::NotACveId(entry.cve_id))
            }
        })
        .collect::<Result<BTreeSet<String>, KevError>>()?;
    if ids.is_empty() {
        return Err(KevError::Empty);
    }
    Ok(ids)
}

/// `CVE-`, a four-digit year, `-`, and at least four digits, in at most [`MAX_ID_BYTES`].
fn is_cve_id(id: &str) -> bool {
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    id.len() <= MAX_ID_BYTES
        && id
            .strip_prefix("CVE-")
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(year, number)| {
                year.len() == 4 && number.len() >= 4 && digits(year) && digits(number)
            })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn catalogue(ids: &[&str]) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| serde_json::json!({"cveID": id, "vendorProject": "v", "notes": ""}))
            .collect();
        serde_json::json!({
            "title": "CISA Catalog of Known Exploited Vulnerabilities",
            "catalogVersion": "2026.09.14",
            "count": ids.len(),
            "vulnerabilities": entries,
        })
        .to_string()
        .into_bytes()
    }

    /// 16 MiB. The catalogue of 2026-09-14 was 1,722,859 bytes.
    #[test]
    fn the_ceiling_is_sixteen_mebibytes() {
        assert_eq!(MAX_CATALOGUE_BYTES, 16_777_216);
    }

    #[test]
    fn a_catalogue_gives_its_cve_ids_sorted_and_once_each() {
        let ids = parse(&catalogue(&[
            "CVE-2026-76461",
            "CVE-2020-11023",
            "CVE-2020-11023",
        ]))
        .expect("parses");
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            ["CVE-2020-11023", "CVE-2026-76461"]
        );
    }

    #[test]
    fn one_id_that_is_not_a_cve_id_refuses_the_catalogue() {
        let long = format!("CVE-2026-{}", "1".repeat(MAX_ID_BYTES - 8));
        for bad in [
            "GHSA-jpcq-cgw6-v4j6",
            "CVE-2020-110",
            "CVE-20-11023",
            "CVE-2020",
            "CVE-2020-1102x",
            "CVE-202x-11023",
            "cve-2020-11023",
            "",
            &long,
        ] {
            let err = parse(&catalogue(&["CVE-2020-11023", bad])).expect_err(bad);
            assert_eq!(err.to_string(), format!("`{bad}` is not a CVE id"));
        }
        let longest = format!("CVE-2026-{}", "1".repeat(MAX_ID_BYTES - 9));
        assert!(parse(&catalogue(&[&longest])).is_ok());
    }

    #[test]
    fn a_document_that_is_not_a_catalogue_or_lists_nothing_is_refused() {
        for bytes in [
            &b"not json"[..],
            br#"{"vulnerabilities": [{"cve": "CVE-2020-11023"}]}"#,
            br#"{"count": 0}"#,
        ] {
            let err = parse(bytes).expect_err("not a catalogue");
            assert!(
                err.to_string().starts_with("not a KEV catalogue: "),
                "{err}"
            );
        }
        assert_eq!(
            parse(&catalogue(&[])).expect_err("empty").to_string(),
            "the KEV catalogue lists no vulnerabilities"
        );
    }
}
