//! Reading Datadog's malicious software packages dataset, one ecosystem's manifest at a time.
//!
//! A manifest maps each package name to `null`, every version, or a list of versions.
//! Apache-2.0. npm's, at commit `8fff54014596` (2026-09-14), was 1,698,934 bytes and listed
//! 48,313 packages: 46,242 at every version and 2,071 by version. PyPI's, read 2026-09-18, was
//! 49,739 bytes and listed 1,834: 1,817 at every version and 17 by version. An entry gives no
//! id, so each package is one record, `DATADOG-<purl type>-<name>`, stored as a malware report
//! the way an OSV `MAL-` record is. See docs/engineering_decisions/datadog-stream.md.

use crate::identity::Ecosystem;
use crate::intel::range;
use crate::intel::rows::{Affected, Rows};
use std::collections::{BTreeMap, BTreeSet};

pub const NPM_MANIFEST: &str = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json";

/// The stream a snapshot records npm's manifest under.
pub const NPM_STREAM: &str = "datadog/npm";

pub const PYPI_MANIFEST: &str = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json";

/// The stream a snapshot records PyPI's manifest under.
pub const PYPI_STREAM: &str = "datadog/pypi";

/// 9.9 times the manifest of 2026-09-14.
pub const MAX_MANIFEST_BYTES: usize = 16 << 20;

/// What every record id for `ecosystem` starts with.
fn id_prefix(ecosystem: Ecosystem) -> String {
    format!("DATADOG-{}-", ecosystem.as_str())
}

/// The widths of `advisory.publisher_id` and `advisory_affected.version`. A longer value is
/// refused here, because a load Postgres refuses would also fail the OSV load in the same
/// transaction.
const MAX_ID_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 255;

/// Why a manifest was refused. Any of these refuses the whole manifest.
#[derive(Debug)]
pub enum DatadogError {
    NotAManifest(serde_json::Error),
    Entry {
        name: String,
        reason: &'static str,
    },
    /// An empty manifest would delete every stored record.
    Empty,
}

impl std::fmt::Display for DatadogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAManifest(e) => write!(f, "not a Datadog manifest: {e}"),
            Self::Entry { name, reason } => write!(f, "`{name}`: {reason}"),
            Self::Empty => f.write_str("the Datadog manifest lists no packages"),
        }
    }
}

impl std::error::Error for DatadogError {}

/// One record per package in `ecosystem`'s manifest, in name order.
pub fn parse(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Vec<Rows>, DatadogError> {
    let manifest: BTreeMap<String, Option<Vec<String>>> =
        serde_json::from_slice(bytes).map_err(DatadogError::NotAManifest)?;
    if manifest.is_empty() {
        return Err(DatadogError::Empty);
    }
    manifest
        .into_iter()
        .map(|(name, versions)| record(ecosystem, name, versions))
        .collect()
}

fn record(
    ecosystem: Ecosystem,
    name: String,
    versions: Option<Vec<String>>,
) -> Result<Rows, DatadogError> {
    let id = format!("{}{name}", id_prefix(ecosystem));
    let refused = |reason| DatadogError::Entry {
        name: name.clone(),
        reason,
    };
    if name.is_empty() {
        return Err(refused("the name is empty"));
    }
    if id.len() > MAX_ID_BYTES {
        return Err(refused("the record id is longer than 128 bytes"));
    }
    let versions: Vec<Option<String>> = match versions {
        None => vec![None],
        Some(listed) if listed.is_empty() => return Err(refused("lists no versions")),
        Some(listed) if listed.iter().any(|v| v.len() > MAX_VERSION_BYTES) => {
            return Err(refused("a version is longer than 255 bytes"));
        }
        Some(listed) => listed
            .iter()
            .map(|v| Some(range::stored(crate::ecosystem::of(ecosystem).versions, v)))
            .collect(),
    };
    let affected: BTreeSet<Affected> = versions
        .into_iter()
        .map(|version| Affected::new(ecosystem.as_str(), &name, version))
        .collect();
    Ok(Rows {
        id,
        summary: None,
        modified: None,
        malware: true,
        cvss: None,
        band: None,
        unread_vectors: 0,
        aliases: BTreeSet::new(),
        affected,
        ranges: BTreeSet::new(),
        unexpressed: 0,
    })
}

/// A package Datadog flags at every version and OSV's malware records flag only at some.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    /// The Datadog stream that flags every version.
    pub datadog_stream: &'static str,
    /// The OSV stream that flags some.
    pub osv_stream: &'static str,
    pub name: String,
    /// The OSV malware records that affect some of its versions, sorted.
    pub osv: Vec<String>,
}

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} every version, {} some: {}",
            self.name,
            self.datadog_stream,
            self.osv_stream,
            self.osv.join(", ")
        )
    }
}

/// Each package a `datadog` record flags at every version that OSV has malware records for and
/// none at every version, in the order `datadog` gives them. A record that is not malware, such
/// as a `GHSA-` vulnerability, says nothing about which versions are malicious.
pub fn disagreements(
    (osv_stream, osv): (&'static str, &[Rows]),
    (datadog_stream, datadog): (&'static str, &[Rows]),
) -> Vec<Disagreement> {
    let mut every: BTreeSet<&str> = BTreeSet::new();
    let mut some: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in osv.iter().filter(|r| r.malware) {
        for a in &r.affected {
            match a.version {
                None => {
                    every.insert(&a.name);
                }
                Some(_) => {
                    some.entry(&a.name).or_default().insert(&r.id);
                }
            }
        }
        for ranged in &r.ranges {
            some.entry(&ranged.name).or_default().insert(&r.id);
        }
    }
    datadog
        .iter()
        .flat_map(|r| &r.affected)
        .filter(|a| a.version.is_none() && !every.contains(a.name.as_str()))
        .filter_map(|a| {
            some.get(a.name.as_str()).map(|ids| Disagreement {
                datadog_stream,
                osv_stream,
                name: a.name.clone(),
                osv: ids.iter().map(|id| (*id).to_owned()).collect(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::range::{End, Interval, Start};
    use crate::intel::rows::Ranged;

    fn names_and_versions(rows: &Rows) -> Vec<(String, Option<String>)> {
        rows.affected
            .iter()
            .map(|a| (a.name.clone(), a.version.clone()))
            .collect()
    }

    #[test]
    fn the_ceiling_is_sixteen_mebibytes() {
        assert_eq!(MAX_MANIFEST_BYTES, 16_777_216);
    }

    #[test]
    fn each_package_is_one_malware_record_at_every_version_or_its_listed_ones() {
        let rows = parse(
            Ecosystem::Npm,
            br#"{"vant": ["2.13.3", "3.6.13"], "0h": null, "@s/p": ["13.0"]}"#,
        )
        .expect("parses");
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["DATADOG-npm-0h", "DATADOG-npm-@s/p", "DATADOG-npm-vant"]
        );
        assert!(rows.iter().all(|r| r.malware && r.cvss.is_none()));
        assert!(
            rows.iter()
                .all(|r| r.aliases.is_empty() && r.ranges.is_empty())
        );
        assert_eq!(names_and_versions(&rows[0]), [("0h".to_owned(), None)]);
        // Listed versions are stored as OSV's are, padded.
        assert_eq!(
            names_and_versions(&rows[1]),
            [("@s/p".to_owned(), Some("13.0.0".to_owned()))]
        );
        assert_eq!(
            names_and_versions(&rows[2]),
            [
                ("vant".to_owned(), Some("2.13.3".to_owned())),
                ("vant".to_owned(), Some("3.6.13".to_owned()))
            ]
        );
        assert_eq!(
            rows[2].affected.first().map(|a| a.ecosystem.as_str()),
            Some("npm")
        );
    }

    #[test]
    fn an_entry_that_would_not_load_refuses_the_manifest() {
        let longest_name = "n".repeat(MAX_ID_BYTES - id_prefix(Ecosystem::Npm).len());
        let long_name = format!("{longest_name}n");
        let long_version = "1".repeat(MAX_VERSION_BYTES + 1);
        for (json, reason) in [
            (r#"{"": null}"#.to_owned(), "``: the name is empty"),
            (
                format!(r#"{{"{long_name}": null}}"#),
                "the record id is longer than 128 bytes",
            ),
            (r#"{"p": []}"#.to_owned(), "`p`: lists no versions"),
            (
                format!(r#"{{"p": ["{long_version}"]}}"#),
                "`p`: a version is longer than 255 bytes",
            ),
        ] {
            let err = parse(Ecosystem::Npm, json.as_bytes())
                .expect_err(reason)
                .to_string();
            assert!(err.ends_with(reason), "{err:?} lacks {reason:?}");
        }
        let at_the_limit = format!(
            r#"{{"{longest_name}": ["{}"]}}"#,
            "1".repeat(MAX_VERSION_BYTES)
        );
        assert!(parse(Ecosystem::Npm, at_the_limit.as_bytes()).is_ok());
    }

    #[test]
    fn a_document_that_is_not_a_manifest_or_lists_nothing_is_refused() {
        for bytes in [
            &b"not json"[..],
            br#"["vant"]"#,
            br#"{"p": "1.0.0"}"#,
            br#"{"p": [1]}"#,
        ] {
            let err = parse(Ecosystem::Npm, bytes)
                .expect_err("not a manifest")
                .to_string();
            assert!(err.starts_with("not a Datadog manifest: "), "{err}");
        }
        assert_eq!(
            parse(Ecosystem::Npm, b"{}").expect_err("empty").to_string(),
            "the Datadog manifest lists no packages"
        );
    }

    fn osv(id: &str, name: &str, version: Option<&str>) -> Rows {
        Rows {
            id: id.to_owned(),
            affected: [Affected {
                ecosystem: "npm".to_owned(),
                name: name.to_owned(),
                version: version.map(str::to_owned),
            }]
            .into(),
            malware: true,
            ..record(Ecosystem::Npm, "x".to_owned(), None).expect("a record")
        }
    }

    #[test]
    fn a_package_datadog_flags_at_every_version_and_osv_only_at_some_is_a_disagreement() {
        let osv_rows = [
            osv(
                "MAL-2024-10301",
                "@lottiefiles/lottie-player",
                Some("2.0.5"),
            ),
            osv(
                "MAL-2024-10302",
                "@lottiefiles/lottie-player",
                Some("2.0.6"),
            ),
            osv("MAL-1", "agreed", None),
            osv("MAL-2", "agreed", Some("1.0.0")),
            osv("MAL-3", "listed-by-both", Some("1.0.0")),
            Rows {
                ranges: [Ranged {
                    ecosystem: "npm".to_owned(),
                    name: "ranged".to_owned(),
                    interval: Interval {
                        start: Start::Introduced("1.0.0".to_owned()),
                        end: End::Open,
                    },
                }]
                .into(),
                affected: BTreeSet::new(),
                ..osv("MAL-4", "unused", None)
            },
            Rows {
                malware: false,
                ..osv("GHSA-1", "vulnerable", Some("1.0.0"))
            },
        ];
        let datadog = parse(
            Ecosystem::Npm,
            br#"{"@lottiefiles/lottie-player": null, "agreed": null, "listed-by-both": ["1.0.0"],
                 "ranged": null, "osv-has-nothing": null, "vulnerable": null}"#,
        )
        .expect("parses");
        let npm = |osv_rows: &[Rows], datadog: &[Rows]| {
            disagreements(("osv/npm", osv_rows), ("datadog/npm", datadog))
        };
        assert_eq!(
            npm(&osv_rows, &datadog),
            [
                Disagreement {
                    datadog_stream: "datadog/npm",
                    osv_stream: "osv/npm",
                    name: "@lottiefiles/lottie-player".to_owned(),
                    osv: vec!["MAL-2024-10301".to_owned(), "MAL-2024-10302".to_owned()],
                },
                Disagreement {
                    datadog_stream: "datadog/npm",
                    osv_stream: "osv/npm",
                    name: "ranged".to_owned(),
                    osv: vec!["MAL-4".to_owned()],
                },
            ]
        );
        assert_eq!(
            npm(&osv_rows, &datadog)[0].to_string(),
            "@lottiefiles/lottie-player: datadog/npm every version, osv/npm some: \
             MAL-2024-10301, MAL-2024-10302"
        );
    }

    /// PyPI's manifest has npm's shape; its ids and names are PyPI's.
    #[test]
    fn a_pypi_manifest_is_read_by_pypis_rules() {
        let rows = parse(
            Ecosystem::PyPI,
            br#"{"SentinelOne": null, "Roblox.-com": ["1.0-1"]}"#,
        )
        .expect("parses");
        let read: Vec<_> = rows
            .iter()
            .map(|r| (r.id.as_str(), names_and_versions(r)))
            .collect();
        assert_eq!(
            read,
            [
                (
                    "DATADOG-pypi-Roblox.-com",
                    vec![("roblox-com".to_owned(), Some("1.0.post1".to_owned()))]
                ),
                (
                    "DATADOG-pypi-SentinelOne",
                    vec![("sentinelone".to_owned(), None)]
                ),
            ]
        );
        assert!(
            rows.iter()
                .all(|r| r.affected.iter().all(|a| a.ecosystem == "pypi"))
        );
    }
}
