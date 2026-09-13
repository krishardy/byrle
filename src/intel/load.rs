//! The bytes a bulk load sends, built without a database, and the encoding a snapshot id is
//! the digest of.
//!
//! `COPY ... FROM STDIN (FORMAT csv)`. Every value is quoted, so an unquoted empty field is
//! NULL and a quoted one is an empty string, and a summary holding `\.` on a line of its own
//! cannot end the data early. Kept apart from `postgres.rs` so the encoding is unit-tested
//! inside the coverage floor, and only the sending needs a container.
//!
//! `advisory` is written first. Every other table refers to the key Postgres assigns an
//! advisory, so their rows are built from the keys read back after that `COPY`.
//!
//! See docs/engineering_decisions/snapshot-identity.md.

use super::osv::Rows;
use super::refresh::{StreamDigest, sha256_hex};
use std::collections::HashMap;

pub const ADVISORY: &str = "COPY advisory (publisher_id, source, summary, cvss, modified, \
                            malware) FROM STDIN (FORMAT csv)";
pub const ALIAS: &str = "COPY advisory_alias (advisory_id, alias) FROM STDIN (FORMAT csv)";
pub const AFFECTED: &str =
    "COPY advisory_affected (advisory_id, ecosystem, name, version) FROM STDIN (FORMAT csv)";
pub const RANGE: &str = "COPY advisory_range (advisory_id, ecosystem, name, introduced, fixed, \
                         last_affected) FROM STDIN (FORMAT csv)";

/// The first line of an [`encode`]d source. A change to the encoding changes this line.
pub const FORMAT: &str = "waharoa intel rows 1";

/// What a refresh fetched, as `intel_source` and `intel_snapshot` record it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    /// RFC 3339 UTC.
    pub taken_at: String,
    /// The bundles the rows were read from. Recorded, and part of no digest.
    pub streams: Vec<StreamDigest>,
}

impl Fetch {
    /// The streams as a JSON object keyed by stream.
    pub fn streams_json(&self) -> String {
        let recorded: serde_json::Map<String, serde_json::Value> = self
            .streams
            .iter()
            .map(|s| {
                (
                    s.stream.clone(),
                    serde_json::json!({
                        "sha256": s.sha256,
                        "etag": s.etag,
                        "last_modified": s.last_modified,
                    }),
                )
            })
            .collect();
        serde_json::Value::Object(recorded).to_string()
    }
}

/// CSV for the tables that refer to an advisory.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Children {
    pub alias: Vec<u8>,
    pub affected: Vec<u8>,
    pub range: Vec<u8>,
}

impl Children {
    /// One record's rows, each carrying `key`.
    fn push(&mut self, key: &str, r: &Rows) {
        for ranged in &r.ranges {
            let (fixed, last_affected) = ranged.interval.end.columns();
            line(
                &mut self.range,
                &[
                    Some(key),
                    Some(&ranged.ecosystem),
                    Some(&ranged.name),
                    ranged.interval.introduced.as_deref(),
                    fixed,
                    last_affected,
                ],
            );
        }
        for alias in &r.aliases {
            line(&mut self.alias, &[Some(key), Some(alias)]);
        }
        for a in &r.affected {
            line(
                &mut self.affected,
                &[
                    Some(key),
                    Some(&a.ecosystem),
                    Some(&a.name),
                    a.version.as_deref(),
                ],
            );
        }
    }
}

/// A record whose publisher id has no key.
#[derive(Debug, PartialEq, Eq)]
pub struct Unkeyed(pub String);

/// One source's rows, as [`encode`] writes them.
#[derive(Debug, PartialEq, Eq)]
pub struct Encoded {
    /// CSV for `advisory`, which a load sends to `COPY` as it is.
    pub advisory: Vec<u8>,
    /// The whole encoding.
    pub bytes: Vec<u8>,
    /// `sha256:` and the hex digest of `bytes`.
    pub digest: String,
}

/// Encode one source's rows so the same rows give the same bytes in every database.
///
/// ```text
/// waharoa intel rows 1
/// source osv
/// advisory 23771415
/// (23,771,415 bytes of CSV)
/// advisory_alias 1149815
/// (1,149,815 bytes of CSV)
/// advisory_affected 9360804
/// (9,360,804 bytes of CSV)
/// advisory_range 437575
/// (437,575 bytes of CSV)
/// ```
///
/// Each table's CSV is the `COPY` encoding. Records are sorted by publisher id. A child row
/// carries its advisory's position in that order, from 1, where `COPY` carries the key
/// Postgres assigned, which differs between databases. Lengths are in bytes, so a summary
/// cannot be read as a table line.
pub fn encode(source: &str, rows: &[Rows]) -> Encoded {
    let mut sorted: Vec<&Rows> = rows.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let advisory = advisories(source, sorted.iter().copied());
    let mut children = Children::default();
    for (position, r) in (1_u64..).zip(&sorted) {
        children.push(&position.to_string(), r);
    }

    let mut bytes = format!("{FORMAT}\nsource {source}\n").into_bytes();
    for (table, csv) in [
        ("advisory", &advisory),
        ("advisory_alias", &children.alias),
        ("advisory_affected", &children.affected),
        ("advisory_range", &children.range),
    ] {
        bytes.extend_from_slice(format!("{table} {}\n", csv.len()).as_bytes());
        bytes.extend_from_slice(csv);
    }
    Encoded {
        digest: prefixed_sha256(&bytes),
        advisory,
        bytes,
    }
}

/// `sha256:` and the hex digest, the form both `intel_source.digest` and
/// `intel_snapshot.digest` take.
fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The snapshot id: `sha256:` and the hex digest of one `source digest` line per source,
/// sorted.
///
/// Given every source in the store, not only the one a refresh loaded, two stores with the
/// same id contain the same rows.
pub fn snapshot_id<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<String> = sources
        .into_iter()
        .map(|(source, digest)| format!("{source} {digest}\n"))
        .collect();
    lines.sort();
    prefixed_sha256(lines.concat().as_bytes())
}

/// CSV for `advisory`.
pub fn advisories<'a>(source: &str, rows: impl IntoIterator<Item = &'a Rows>) -> Vec<u8> {
    let mut out = Vec::new();
    for r in rows {
        // `f64`'s `Display` is the shortest text that reads back as the same number.
        let cvss = r.cvss.map(|c| c.to_string());
        let modified = r.modified.as_deref().map(timestamp);
        line(
            &mut out,
            &[
                Some(&r.id),
                Some(source),
                r.summary.as_deref(),
                cvss.as_deref(),
                modified.as_deref(),
                Some(if r.malware { "true" } else { "false" }),
            ],
        );
    }
    out
}

/// `value` in UTC, rounded to the microsecond.
///
/// Postgres keeps microseconds, so the value sent is the value stored, and [`encode`] hashes
/// what the row contains. OSV writes nanoseconds. A value that does not parse as an RFC 3339
/// timestamp is sent as it is.
fn timestamp(value: &str) -> String {
    value
        .parse::<jiff::Timestamp>()
        .and_then(|t| t.round(jiff::Unit::Microsecond))
        .map_or_else(|_| value.to_owned(), |t| t.to_string())
}

/// CSV for the other three tables, each row carrying the key `keys` gives its advisory's
/// publisher id.
pub fn children(rows: &[Rows], keys: &HashMap<String, i64>) -> Result<Children, Unkeyed> {
    let mut out = Children::default();
    for r in rows {
        let key = keys
            .get(&r.id)
            .ok_or_else(|| Unkeyed(r.id.clone()))?
            .to_string();
        out.push(&key, r);
    }
    Ok(out)
}

fn line(out: &mut Vec<u8>, fields: &[Option<&str>]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        if let Some(value) = field {
            out.push(b'"');
            for byte in value.bytes() {
                if byte == b'"' {
                    out.push(b'"');
                }
                out.push(byte);
            }
            out.push(b'"');
        }
    }
    out.push(b'\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::osv::{Affected, Ranged};
    use crate::intel::range::{End, Interval};

    fn rows() -> Rows {
        Rows {
            id: "MAL-1".to_owned(),
            summary: Some("say \"hi\"\n\\.\nafter".to_owned()),
            modified: None,
            malware: true,
            cvss: None,
            unread_vectors: 0,
            aliases: ["GHSA-a".to_owned()].into(),
            affected: [
                Affected {
                    ecosystem: "npm".to_owned(),
                    name: "@s/p".to_owned(),
                    version: None,
                },
                Affected {
                    ecosystem: "npm".to_owned(),
                    name: "@s/p".to_owned(),
                    version: Some(String::new()),
                },
            ]
            .into(),
            ranges: [
                Ranged {
                    ecosystem: "npm".to_owned(),
                    name: "@s/p".to_owned(),
                    interval: Interval {
                        introduced: None,
                        end: End::Fixed("2.0.0".to_owned()),
                    },
                },
                Ranged {
                    ecosystem: "npm".to_owned(),
                    name: "@s/p".to_owned(),
                    interval: Interval {
                        introduced: Some("3.0.0".to_owned()),
                        end: End::LastAffected("3.1.0".to_owned()),
                    },
                },
                Ranged {
                    ecosystem: "npm".to_owned(),
                    name: "@s/p".to_owned(),
                    interval: Interval {
                        introduced: Some("4.0.0".to_owned()),
                        end: End::Open,
                    },
                },
            ]
            .into(),
            unexpressed: 0,
        }
    }

    /// A record with one alias and one package, every version.
    fn plain(id: &str, alias: &str, name: &str) -> Rows {
        Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware: true,
            cvss: None,
            unread_vectors: 0,
            aliases: [alias.to_owned()].into(),
            affected: [Affected {
                ecosystem: "npm".to_owned(),
                name: name.to_owned(),
                version: None,
            }]
            .into(),
            ranges: Default::default(),
            unexpressed: 0,
        }
    }

    fn keys() -> HashMap<String, i64> {
        [("MAL-1".to_owned(), 7)].into()
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("utf-8")
    }

    #[test]
    fn a_quote_is_doubled_and_every_value_is_quoted() {
        assert_eq!(
            text(&advisories("osv", &[rows()])),
            "\"MAL-1\",\"osv\",\"say \"\"hi\"\"\n\\.\nafter\",,,\"true\"\n"
        );
    }

    #[test]
    fn a_child_row_carries_its_advisory_key_rather_than_the_publisher_id() {
        let c = children(&[rows()], &keys()).expect("keyed");
        assert_eq!(text(&c.alias), "\"7\",\"GHSA-a\"\n");
    }

    #[test]
    fn a_record_with_no_key_is_an_error_naming_it() {
        assert_eq!(
            children(&[rows()], &HashMap::new()),
            Err(Unkeyed("MAL-1".to_owned()))
        );
    }

    #[test]
    fn a_score_is_written_as_the_number_it_is() {
        let csv = advisories(
            "osv",
            &[Rows {
                cvss: Some(6.9),
                ..rows()
            }],
        );
        assert!(
            text(&csv).ends_with(",\"6.9\",,\"true\"\n"),
            "{}",
            text(&csv)
        );
    }

    #[test]
    fn modified_is_written_in_utc_to_the_microsecond() {
        let written = |modified: &str| {
            let csv = advisories(
                "osv",
                &[Rows {
                    modified: Some(modified.to_owned()),
                    ..plain("MAL-1", "a", "p")
                }],
            );
            text(&csv).to_owned()
        };
        assert_eq!(
            written("2026-09-08T05:45:02.886710534+02:00"),
            "\"MAL-1\",\"osv\",,,\"2026-09-08T03:45:02.886711Z\",\"true\"\n"
        );
        assert!(written("2026-09-08T03:45:02Z").contains(",\"2026-09-08T03:45:02Z\","));
        assert!(written("yesterday").contains(",\"yesterday\","));
    }

    #[test]
    fn each_interval_is_one_row_with_its_end_in_the_column_that_names_it() {
        let c = children(&[rows()], &keys()).expect("keyed");
        assert_eq!(
            text(&c.range),
            "\"7\",\"npm\",\"@s/p\",,\"2.0.0\",\n\
             \"7\",\"npm\",\"@s/p\",\"3.0.0\",,\"3.1.0\"\n\
             \"7\",\"npm\",\"@s/p\",\"4.0.0\",,\n"
        );
    }

    #[test]
    fn none_is_an_empty_field_and_an_empty_string_is_quoted() {
        let c = children(&[rows()], &keys()).expect("keyed");
        assert_eq!(
            text(&c.affected),
            "\"7\",\"npm\",\"@s/p\",\n\"7\",\"npm\",\"@s/p\",\"\"\n"
        );
    }

    #[test]
    fn a_vulnerability_row_is_not_marked_malware() {
        let csv = advisories(
            "osv",
            &[Rows {
                malware: false,
                ..rows()
            }],
        );
        assert!(text(&csv).ends_with(",\"false\"\n"));
    }

    #[test]
    fn nothing_to_load_is_empty_tables() {
        assert!(advisories("osv", &[]).is_empty());
        assert_eq!(children(&[], &HashMap::new()), Ok(Children::default()));
    }

    /// Given out of order, so the numbering has to come from sorting.
    #[test]
    fn an_encoding_numbers_advisories_by_publisher_id_and_gives_each_table_its_length() {
        let encoded = encode(
            "osv",
            &[plain("MAL-2", "CVE-b", "b"), plain("GHSA-1", "CVE-a", "a")],
        );
        let advisory = "\"GHSA-1\",\"osv\",,,,\"true\"\n\"MAL-2\",\"osv\",,,,\"true\"\n";
        let alias = "\"1\",\"CVE-a\"\n\"2\",\"CVE-b\"\n";
        let affected = "\"1\",\"npm\",\"a\",\n\"2\",\"npm\",\"b\",\n";
        assert_eq!(
            text(&encoded.bytes),
            format!(
                "waharoa intel rows 1\nsource osv\n\
                 advisory {}\n{advisory}\
                 advisory_alias {}\n{alias}\
                 advisory_affected {}\n{affected}\
                 advisory_range 0\n",
                advisory.len(),
                alias.len(),
                affected.len(),
            )
        );
        assert_eq!(text(&encoded.advisory), advisory);
        assert_eq!(
            encoded.digest,
            format!("sha256:{}", sha256_hex(&encoded.bytes))
        );
    }

    #[test]
    fn an_encoding_is_the_same_for_rows_in_any_order_and_changes_with_any_row() {
        let (a, b) = (plain("GHSA-1", "CVE-a", "a"), rows());
        let encoded = encode("osv", &[a.clone(), b.clone()]);
        assert_eq!(encoded, encode("osv", &[b.clone(), a.clone()]));
        // `intel_source.digest` is VARCHAR(71).
        assert_eq!(encoded.digest.len(), 71);

        let rescored = Rows {
            cvss: Some(0.1),
            ..b.clone()
        };
        for other in [
            encode("ghsa", &[a.clone(), b.clone()]),
            encode("osv", &[a.clone(), rescored]),
            encode("osv", std::slice::from_ref(&a)),
        ] {
            assert_ne!(encoded.digest, other.digest);
        }
    }

    #[test]
    fn a_snapshot_id_is_the_same_for_sources_in_any_order_and_changes_with_any_digest() {
        let id = snapshot_id([("osv", "sha256:aa"), ("ghsa", "sha256:bb")]);
        assert_eq!(
            id,
            snapshot_id([("ghsa", "sha256:bb"), ("osv", "sha256:aa")])
        );
        assert_eq!(
            id,
            format!("sha256:{}", sha256_hex(b"ghsa sha256:bb\nosv sha256:aa\n"))
        );
        assert_eq!(id.len(), 71);
        assert_ne!(
            id,
            snapshot_id([("osv", "sha256:ab"), ("ghsa", "sha256:bb")])
        );
        assert_ne!(id, snapshot_id([("osv", "sha256:aa")]));
    }

    #[test]
    fn a_fetch_records_each_stream_by_name() {
        let fetch = Fetch {
            taken_at: "t1".to_owned(),
            streams: vec![StreamDigest {
                stream: "osv/npm".to_owned(),
                sha256: "aa".to_owned(),
                etag: Some("\"e\"".to_owned()),
                last_modified: None,
            }],
        };
        let recorded: serde_json::Value =
            serde_json::from_str(&fetch.streams_json()).expect("json");
        assert_eq!(
            recorded,
            serde_json::json!({"osv/npm": {"sha256": "aa", "etag": "\"e\"", "last_modified": null}})
        );
    }
}
