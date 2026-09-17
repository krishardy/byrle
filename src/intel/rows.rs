//! An advisory as the intel store holds it, whichever provider it came from.

use super::range::Interval;
use std::collections::BTreeSet;

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

/// An interval of package versions an advisory is against. Never every version, which is
/// an [`Affected`] with no version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ranged {
    pub ecosystem: String,
    pub name: String,
    pub interval: Interval<String>,
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
