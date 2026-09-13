//! The bytes a bulk load sends, built without a database.
//!
//! `COPY ... FROM STDIN (FORMAT csv)`. Every value is quoted, so an unquoted empty field is
//! NULL and a quoted one is an empty string, and a summary holding `\.` on a line of its own
//! cannot end the data early. Kept apart from `postgres.rs` so the encoding is unit-tested
//! inside the coverage floor, and only the sending needs a container.

use super::osv::Rows;

pub const ADVISORY: &str =
    "COPY advisory (id, source, summary, modified, malware) FROM STDIN (FORMAT csv)";
pub const ALIAS: &str = "COPY advisory_alias (advisory_id, alias) FROM STDIN (FORMAT csv)";
pub const AFFECTED: &str =
    "COPY advisory_affected (advisory_id, ecosystem, name, version) FROM STDIN (FORMAT csv)";

/// What a refresh records about itself in `intel_snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    /// RFC 3339 UTC.
    pub taken_at: String,
    /// Per-stream digests, as a JSON object.
    pub streams: String,
}

/// CSV for each of the three tables, in the order they have to be loaded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tables {
    pub advisory: Vec<u8>,
    pub alias: Vec<u8>,
    pub affected: Vec<u8>,
}

pub fn tables(source: &str, rows: &[Rows]) -> Tables {
    let mut out = Tables::default();
    for r in rows {
        line(
            &mut out.advisory,
            &[
                Some(&r.id),
                Some(source),
                r.summary.as_deref(),
                r.modified.as_deref(),
                Some(if r.malware { "true" } else { "false" }),
            ],
        );
        for alias in &r.aliases {
            line(&mut out.alias, &[Some(&r.id), Some(alias)]);
        }
        for a in &r.affected {
            line(
                &mut out.affected,
                &[
                    Some(&r.id),
                    Some(&a.ecosystem),
                    Some(&a.name),
                    a.version.as_deref(),
                ],
            );
        }
    }
    out
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
    use crate::intel::osv::Affected;

    fn rows() -> Rows {
        Rows {
            id: "MAL-1".to_owned(),
            summary: Some("say \"hi\"\n\\.\nafter".to_owned()),
            modified: None,
            malware: true,
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
            unexpressed: 0,
        }
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("utf-8")
    }

    #[test]
    fn a_quote_is_doubled_and_every_value_is_quoted() {
        let t = tables("osv", &[rows()]);
        assert_eq!(
            text(&t.advisory),
            "\"MAL-1\",\"osv\",\"say \"\"hi\"\"\n\\.\nafter\",,\"true\"\n"
        );
        assert_eq!(text(&t.alias), "\"MAL-1\",\"GHSA-a\"\n");
    }

    #[test]
    fn none_is_an_empty_field_and_an_empty_string_is_quoted() {
        let t = tables("osv", &[rows()]);
        assert_eq!(
            text(&t.affected),
            "\"MAL-1\",\"npm\",\"@s/p\",\n\"MAL-1\",\"npm\",\"@s/p\",\"\"\n"
        );
    }

    #[test]
    fn a_vulnerability_row_is_not_marked_malware() {
        let t = tables(
            "osv",
            &[Rows {
                malware: false,
                ..rows()
            }],
        );
        assert!(text(&t.advisory).ends_with(",\"false\"\n"));
    }

    #[test]
    fn nothing_to_load_is_three_empty_tables() {
        assert_eq!(tables("osv", &[]), Tables::default());
    }
}
