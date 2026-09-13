//! The bytes a bulk load sends, built without a database.
//!
//! `COPY ... FROM STDIN (FORMAT csv)`. Every value is quoted, so an unquoted empty field is
//! NULL and a quoted one is an empty string, and a summary holding `\.` on a line of its own
//! cannot end the data early. Kept apart from `postgres.rs` so the encoding is unit-tested
//! inside the coverage floor, and only the sending needs a container.
//!
//! `advisory` is written first. Every other table refers to the key Postgres assigns an
//! advisory, so their rows are built from the keys read back after that `COPY`.

use super::osv::Rows;
use std::collections::HashMap;

pub const ADVISORY: &str = "COPY advisory (publisher_id, source, summary, cvss, modified, \
                            malware) FROM STDIN (FORMAT csv)";
pub const ALIAS: &str = "COPY advisory_alias (advisory_id, alias) FROM STDIN (FORMAT csv)";
pub const AFFECTED: &str =
    "COPY advisory_affected (advisory_id, ecosystem, name, version) FROM STDIN (FORMAT csv)";
pub const RANGE: &str = "COPY advisory_range (advisory_id, ecosystem, name, introduced, fixed, \
                         last_affected) FROM STDIN (FORMAT csv)";

/// What a refresh records about itself in `intel_snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// `sha256:` and the hex digest of the per-stream digests.
    pub digest: String,
    /// RFC 3339 UTC.
    pub taken_at: String,
    /// Per-stream digests, as a JSON object.
    pub streams: String,
}

/// CSV for the tables that refer to an advisory.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Children {
    pub alias: Vec<u8>,
    pub affected: Vec<u8>,
    pub range: Vec<u8>,
}

/// A record whose publisher id has no key.
#[derive(Debug, PartialEq, Eq)]
pub struct Unkeyed(pub String);

/// CSV for `advisory`.
pub fn advisories(source: &str, rows: &[Rows]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in rows {
        // `f64`'s `Display` is the shortest text that reads back as the same number.
        let cvss = r.cvss.map(|c| c.to_string());
        line(
            &mut out,
            &[
                Some(&r.id),
                Some(source),
                r.summary.as_deref(),
                cvss.as_deref(),
                r.modified.as_deref(),
                Some(if r.malware { "true" } else { "false" }),
            ],
        );
    }
    out
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
        for ranged in &r.ranges {
            let (fixed, last_affected) = ranged.interval.end.columns();
            line(
                &mut out.range,
                &[
                    Some(&key),
                    Some(&ranged.ecosystem),
                    Some(&ranged.name),
                    ranged.interval.introduced.as_deref(),
                    fixed,
                    last_affected,
                ],
            );
        }
        for alias in &r.aliases {
            line(&mut out.alias, &[Some(&key), Some(alias)]);
        }
        for a in &r.affected {
            line(
                &mut out.affected,
                &[
                    Some(&key),
                    Some(&a.ecosystem),
                    Some(&a.name),
                    a.version.as_deref(),
                ],
            );
        }
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
}
