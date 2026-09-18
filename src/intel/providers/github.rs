//! GitHub's Advisory Database, read through the GraphQL API.
//!
//! A signal stream beside OSV rather than a replacement for it: both are checked
//! independently and the decision vector reviews what each holds. OSV imports GHSA, so most
//! ids appear twice, under source `osv` and under source `github`. That is corroboration,
//! and `advisory` is keyed `(source, publisher_id)` so both rows exist. See
//! `docs/engineering_decisions/github-advisory-signal-stream.md`.
//!
//! The API is a POST with `Authorization: bearer` and cursor pagination, where every other
//! stream is one unauthenticated GET. `waharoa refresh` pages it and concatenates the
//! response bodies into one JSON array, which is what [`parse`] reads.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::intel::range::{End, Interval, Start, VersionOrder, stored};
use crate::intel::rows::{Affected, Ranged, Rows, band_ceiling};

pub const SOURCE: &str = "github";
pub const STREAM: &str = "github/npm";
pub const ENDPOINT: &str = "https://api.github.com/graphql";

/// Bytes past which the concatenated pages are refused. 9,980 rows came to 5.6 MB on
/// 2026-09-16; 64 MiB is an order of magnitude of headroom.
pub const MAX_BYTES: usize = 64 << 20;

/// Advisories per page. 100 is GitHub's maximum for a connection.
pub const PAGE: usize = 100;

const NPM: &str = crate::identity::Ecosystem::Npm.as_str();

/// How npm's versions order, which every bound here is read by.
const ORDER: VersionOrder = crate::ecosystem::NPM.versions;

/// The query `waharoa refresh` sends, once per page.
///
/// `securityVulnerabilities` returns one node per advisory-and-range, so an advisory with
/// several affected ranges appears several times and [`parse`] groups them.
pub const QUERY: &str = r"
query($after: String) {
  rateLimit { cost remaining }
  securityVulnerabilities(ecosystem: NPM, first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      package { name }
      vulnerableVersionRange
      advisory {
        ghsaId summary updatedAt withdrawnAt severity
        cvss { score }
        identifiers { type value }
      }
    }
  }
}
";

#[derive(Debug)]
pub enum GithubError {
    /// The concatenated pages are not the JSON array a refresh writes.
    NotJson(serde_json::Error),
    /// GitHub answered with an `errors` array.
    Api(String),
    /// Every page read and no advisory in any of them.
    Empty,
}

impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(e) => write!(f, "the GitHub pages are not readable: {e}"),
            Self::Api(e) => write!(f, "GitHub answered with an error: {e}"),
            Self::Empty => f.write_str("GitHub returned no advisories"),
        }
    }
}

impl std::error::Error for GithubError {}

#[derive(Deserialize)]
struct Page {
    data: Option<Data>,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    message: String,
}

#[derive(Deserialize)]
struct Data {
    #[serde(rename = "securityVulnerabilities")]
    vulnerabilities: Connection,
}

#[derive(Deserialize)]
struct Connection {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    package: Package,
    #[serde(rename = "vulnerableVersionRange")]
    range: Option<String>,
    advisory: Advisory,
}

#[derive(Deserialize)]
struct Package {
    name: String,
}

#[derive(Deserialize)]
struct Advisory {
    #[serde(rename = "ghsaId")]
    id: String,
    summary: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "withdrawnAt")]
    withdrawn_at: Option<String>,
    severity: Option<String>,
    cvss: Option<Cvss>,
    #[serde(default)]
    identifiers: Vec<Identifier>,
}

#[derive(Deserialize)]
struct Cvss {
    score: Option<f64>,
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// One `vulnerableVersionRange`, as the store holds it.
///
/// GitHub writes a comma-separated pair of bounds, or one bound: `>= 0.0.1, < 2.1.27`,
/// `< 2.1.30`, `= 1.2.3`. An exact version is a listed version rather than an interval.
#[derive(Debug, PartialEq, Eq)]
enum Bounds {
    /// `= X`.
    Exact(String),
    Interval(Interval<String>),
    /// A bound this build does not express, such as an exclusive `>`.
    Unexpressed,
}

fn bounds(range: &str) -> Bounds {
    let (mut start, mut end) = (Start::First, End::Open);
    for part in range.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(">=") {
            start = Start::Introduced(stored(ORDER, v.trim()));
        } else if let Some(v) = part.strip_prefix('>') {
            // `> 4.0.2` says 4.0.2 is the last version not affected.
            start = Start::After(stored(ORDER, v.trim()));
        } else if let Some(v) = part.strip_prefix("<=") {
            end = End::LastAffected(stored(ORDER, v.trim()));
        } else if let Some(v) = part.strip_prefix('<') {
            end = End::Fixed(stored(ORDER, v.trim()));
        } else if let Some(v) = part.strip_prefix('=') {
            return Bounds::Exact(stored(ORDER, v.trim()));
        } else {
            return Bounds::Unexpressed;
        }
    }
    if start == Start::First && end == End::Open {
        return Bounds::Unexpressed;
    }
    Bounds::Interval(Interval { start, end })
}

/// The score for an advisory: its CVSS base score, or the top of its severity band when
/// GitHub gives no vector score. The same reading as OSV's, so the two streams score one
/// advisory alike.
fn score(advisory: &Advisory) -> (Option<f64>, Option<String>) {
    match advisory.cvss.as_ref().and_then(|c| c.score) {
        // GitHub writes 0.0 for an advisory it has not scored, which is not a CVSS 0.0.
        Some(score) if score > 0.0 => (Some(score), None),
        _ => match advisory.severity.as_deref().filter(|b| *b != "UNKNOWN") {
            Some(band) => (band_ceiling(band), Some(band.to_owned())),
            None => (None, None),
        },
    }
}

/// Every advisory in the concatenated pages, one [`Rows`] each.
///
/// A withdrawn advisory is skipped, as `osv::parse` skips one. An advisory whose every range
/// is unexpressed keeps its record and counts the ranges in `unexpressed`.
pub fn parse(bytes: &[u8]) -> Result<Vec<Rows>, GithubError> {
    let pages: Vec<Page> = serde_json::from_slice(bytes).map_err(GithubError::NotJson)?;
    let mut by_id: BTreeMap<String, Rows> = BTreeMap::new();
    for page in pages {
        if !page.errors.is_empty() {
            let joined: Vec<&str> = page.errors.iter().map(|e| e.message.as_str()).collect();
            return Err(GithubError::Api(joined.join("; ")));
        }
        let Some(data) = page.data else { continue };
        for node in data.vulnerabilities.nodes {
            let a = node.advisory;
            if a.withdrawn_at.is_some() {
                continue;
            }
            let (cvss, band) = score(&a);
            let rows = by_id.entry(a.id.clone()).or_insert_with(|| Rows {
                id: a.id.clone(),
                summary: a.summary.clone(),
                modified: a.updated_at.clone(),
                malware: false,
                cvss,
                band,
                unread_vectors: 0,
                aliases: BTreeSet::new(),
                affected: BTreeSet::new(),
                ranges: BTreeSet::new(),
                unexpressed: 0,
            });
            for id in &a.identifiers {
                if id.kind == "CVE" {
                    rows.aliases.insert(id.value.clone());
                }
            }
            let name = node.package.name;
            match node.range.as_deref().map(bounds) {
                Some(Bounds::Exact(version)) => {
                    rows.affected.insert(Affected {
                        ecosystem: NPM.to_owned(),
                        name,
                        version: Some(version),
                    });
                }
                Some(Bounds::Interval(interval)) => {
                    rows.ranges.insert(Ranged {
                        ecosystem: NPM.to_owned(),
                        name,
                        interval,
                    });
                }
                // No range given is every version, as OSV's `introduced: "0"` is.
                None => {
                    rows.affected.insert(Affected {
                        ecosystem: NPM.to_owned(),
                        name,
                        version: None,
                    });
                }
                Some(Bounds::Unexpressed) => rows.unexpressed += 1,
            }
        }
    }
    // An advisory with no version row at all says nothing about any package.
    by_id.retain(|_, r| !r.affected.is_empty() || !r.ranges.is_empty());
    if by_id.is_empty() {
        return Err(GithubError::Empty);
    }
    Ok(by_id.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One page holding the nodes given, as `waharoa refresh` concatenates them.
    fn pages(nodes: &[serde_json::Value]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "data": {"securityVulnerabilities": {
                "pageInfo": {"hasNextPage": false, "endCursor": null},
                "nodes": nodes,
            }}
        }]))
        .expect("the fixture serialises")
    }

    fn node(
        id: &str,
        name: &str,
        range: serde_json::Value,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        let mut advisory = serde_json::json!({
            "ghsaId": id, "summary": "s", "updatedAt": "2026-01-01T00:00:00Z",
            "withdrawnAt": null, "severity": "HIGH", "cvss": {"score": 9.1},
            "identifiers": [{"type": "GHSA", "value": id}],
        });
        let (Some(a), Some(e)) = (advisory.as_object_mut(), extra.as_object()) else {
            unreachable!("both are objects")
        };
        for (k, v) in e {
            a.insert(k.clone(), v.clone());
        }
        serde_json::json!({"package": {"name": name}, "vulnerableVersionRange": range, "advisory": advisory})
    }

    #[test]
    fn the_ceiling_is_sixty_four_mebibytes() {
        assert_eq!(MAX_BYTES, 67_108_864);
    }

    #[test]
    fn a_two_bound_range_is_one_interval_and_an_exact_version_is_a_listed_version() {
        assert_eq!(
            bounds(">= 0.0.1, < 2.1.27"),
            Bounds::Interval(Interval {
                start: Start::Introduced("0.0.1".to_owned()),
                end: End::Fixed("2.1.27".to_owned()),
            })
        );
        assert_eq!(
            bounds("< 2.1.30"),
            Bounds::Interval(Interval {
                start: Start::First,
                end: End::Fixed("2.1.30".to_owned()),
            })
        );
        assert_eq!(
            bounds("<= 1.5"),
            Bounds::Interval(Interval {
                start: Start::First,
                // Padded as OSV's listed versions are, so 1.5 matches the published 1.5.0.
                end: End::LastAffected("1.5.0".to_owned()),
            })
        );
        assert_eq!(bounds("= 1.2.3"), Bounds::Exact("1.2.3".to_owned()));
        // `> X` says X is the last version not affected, so it excludes its own bound.
        assert_eq!(
            bounds("> 4.0.2"),
            Bounds::Interval(Interval {
                start: Start::After("4.0.2".to_owned()),
                end: End::Open,
            })
        );
        assert_eq!(
            bounds("> 6.8.0, < 6.9.0"),
            Bounds::Interval(Interval {
                start: Start::After("6.8.0".to_owned()),
                end: End::Fixed("6.9.0".to_owned()),
            })
        );
        assert_eq!(bounds("whatever"), Bounds::Unexpressed);
    }

    #[test]
    fn an_advisory_with_several_ranges_is_one_record_carrying_all_of_them() {
        let rows = parse(&pages(&[
            node(
                "GHSA-aaaa-bbbb-cccc",
                "left",
                serde_json::json!("< 1.0.0"),
                serde_json::json!({}),
            ),
            node(
                "GHSA-aaaa-bbbb-cccc",
                "right",
                serde_json::json!(">= 2.0.0"),
                serde_json::json!({}),
            ),
        ]))
        .expect("the pages read");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(rows[0].ranges.len(), 2);
        assert!(!rows[0].malware, "a GHSA advisory is a vulnerability");
    }

    #[test]
    fn a_cve_identifier_is_an_alias_and_the_ghsa_id_is_not() {
        let rows = parse(&pages(&[node(
            "GHSA-aaaa-bbbb-cccc",
            "p",
            serde_json::json!("< 1.0.0"),
            serde_json::json!({"identifiers": [
                {"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"},
                {"type": "CVE", "value": "CVE-2026-1"}
            ]}),
        )]))
        .expect("the pages read");
        assert_eq!(
            rows[0].aliases.iter().collect::<Vec<_>>(),
            ["CVE-2026-1"],
            "the record's own id is not one of its aliases"
        );
    }

    #[test]
    fn a_withdrawn_advisory_is_skipped_as_osv_skips_one() {
        let err = parse(&pages(&[node(
            "GHSA-aaaa-bbbb-cccc",
            "p",
            serde_json::json!("< 1.0.0"),
            serde_json::json!({"withdrawnAt": "2025-08-11T21:15:20Z"}),
        )]))
        .expect_err("nothing is left to load");
        assert!(matches!(err, GithubError::Empty), "{err}");
    }

    /// `e9b4376` scores an OSV record with no vector at the top of its band. GitHub writes
    /// 0.0 for an advisory it has not scored, which is not a CVSS 0.0.
    #[test]
    fn an_advisory_with_no_score_is_scored_at_the_top_of_its_band() {
        for (cvss, severity, expected, band) in [
            (
                serde_json::json!({"score": 9.1}),
                "CRITICAL",
                Some(9.1),
                None,
            ),
            (
                serde_json::json!({"score": 0.0}),
                "MODERATE",
                Some(6.9),
                Some("MODERATE"),
            ),
            (serde_json::json!(null), "LOW", Some(3.9), Some("LOW")),
            (serde_json::json!(null), "UNKNOWN", None, None),
        ] {
            let rows = parse(&pages(&[node(
                "GHSA-aaaa-bbbb-cccc",
                "p",
                serde_json::json!("< 1.0.0"),
                serde_json::json!({"cvss": cvss, "severity": severity}),
            )]))
            .expect("the pages read");
            assert_eq!(rows[0].cvss, expected, "{severity}");
            assert_eq!(rows[0].band.as_deref(), band, "{severity}");
        }
    }

    #[test]
    fn a_node_with_no_range_is_every_version() {
        let rows = parse(&pages(&[node(
            "GHSA-aaaa-bbbb-cccc",
            "p",
            serde_json::json!(null),
            serde_json::json!({}),
        )]))
        .expect("the pages read");
        assert_eq!(rows[0].affected.len(), 1);
        assert_eq!(rows[0].affected.iter().next().expect("one").version, None);
    }

    #[test]
    fn an_api_error_is_reported_rather_than_read_as_no_advisories() {
        let bytes = serde_json::to_vec(&serde_json::json!([
            {"errors": [{"message": "Bad credentials"}]}
        ]))
        .expect("serialises");
        let err = parse(&bytes).expect_err("the page carries an error");
        assert!(
            matches!(err, GithubError::Api(ref m) if m.contains("Bad credentials")),
            "{err}"
        );
    }

    #[test]
    fn pages_that_are_not_json_are_refused_with_the_reason() {
        let err = parse(b"not json").expect_err("not an array of pages");
        assert!(matches!(err, GithubError::NotJson(_)), "{err}");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn an_advisory_whose_every_range_is_unexpressed_says_nothing_about_a_package() {
        let err = parse(&pages(&[node(
            "GHSA-aaaa-bbbb-cccc",
            "p",
            serde_json::json!("nonsense"),
            serde_json::json!({}),
        )]))
        .expect_err("no version row");
        assert!(matches!(err, GithubError::Empty), "{err}");
    }

    /// The three advisories GitHub holds that OSV's bundle lacks all write `>`, so this is
    /// the whole of what the stream uniquely adds. See
    /// docs/engineering_decisions/github-advisory-signal-stream.md.
    #[test]
    fn an_exclusive_lower_bound_is_stored_and_does_not_cover_its_own_version() {
        let rows = parse(&pages(&[node(
            "GHSA-m2hm-hrr2-6p2q",
            "bootstrap-3-typeahead",
            serde_json::json!("> 4.0.2"),
            serde_json::json!({}),
        )]))
        .expect("the pages read");
        let ranged = rows[0].ranges.iter().next().expect("one range");
        assert_eq!(ranged.interval.start, Start::After("4.0.2".to_owned()));
        assert_eq!(rows[0].unexpressed, 0);
    }
}
