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

use super::osv::{Affected, Ranged, Rows};
use super::range::{End, Interval};
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

/// The tables an encoding holds, in the order it holds them.
const TABLES: [&str; 4] = [
    "advisory",
    "advisory_alias",
    "advisory_affected",
    "advisory_range",
];

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
            range_line(&mut self.range, key, ranged);
        }
        for alias in &r.aliases {
            alias_line(&mut self.alias, key, alias);
        }
        for a in &r.affected {
            affected_line(&mut self.affected, key, a);
        }
    }
}

/// A record whose publisher id has no key.
#[derive(Debug, PartialEq, Eq)]
pub struct Unkeyed(pub String);

/// One source's rows, as [`encode`] writes them.
#[derive(Debug, PartialEq, Eq)]
pub struct Encoded {
    /// The source the rows are stored under.
    pub source: String,
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
    for (table, csv) in TABLES.into_iter().zip([
        &advisory,
        &children.alias,
        &children.affected,
        &children.range,
    ]) {
        bytes.extend_from_slice(format!("{table} {}\n", csv.len()).as_bytes());
        bytes.extend_from_slice(csv);
    }
    Encoded {
        source: source.to_owned(),
        digest: digest(&bytes),
        advisory,
        bytes,
    }
}

/// `sha256:` and the hex digest, the form both `intel_source.digest` and
/// `intel_snapshot.digest` take.
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// What a snapshot id is the digest of: one `source digest` line per source, sorted.
///
/// Given every source in the store, not only the one a refresh loaded, two stores with the
/// same id contain the same rows.
pub fn manifest<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<String> = sources
        .into_iter()
        .map(|(source, digest)| format!("{source} {digest}\n"))
        .collect();
    lines.sort();
    lines.concat()
}

/// The snapshot id of a [`manifest`].
pub fn snapshot_id(manifest: &str) -> String {
    digest(manifest.as_bytes())
}

/// Why bytes are not an [`encode`]d source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undecodable(pub String);

impl std::fmt::Display for Undecodable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Undecodable {}

/// One row of an [`encode`]d source, in the order the encoding contains them. A child row
/// carries its advisory's index in the advisory table, from 0.
#[derive(Debug, Clone, PartialEq)]
pub enum Row {
    /// A record with no aliases, affected entries or ranges. Those follow as rows of their own.
    /// `unread_vectors` and `unexpressed` are not in the encoding and are 0.
    Advisory(Rows),
    Alias(usize, String),
    Affected(usize, Affected),
    Ranged(usize, Ranged),
}

/// Whether `next` can follow `previous`: advisories in publisher id order, then each table's
/// rows in position and row order, none repeated. [`Decoder`] reads the tables in order, so
/// rows of different tables always can.
fn follows(previous: &Row, next: &Row) -> bool {
    match (previous, next) {
        (Row::Advisory(a), Row::Advisory(b)) => a.id < b.id,
        (Row::Alias(i, a), Row::Alias(j, b)) => (i, a) < (j, b),
        (Row::Affected(i, a), Row::Affected(j, b)) => (i, a) < (j, b),
        (Row::Ranged(i, a), Row::Ranged(j, b)) => (i, a) < (j, b),
        _ => true,
    }
}

/// The rows of an [`encode`]d source, read one at a time.
///
/// Each row is encoded again and compared with the bytes it was read from, and must follow the
/// row before it, so a reading that differs from what was written is refused rather than used.
/// Only one row is decoded at a time, so reading a source costs its bytes and not its rows.
#[derive(Debug)]
pub struct Decoder<'a> {
    source: String,
    /// The bytes after the table being read.
    rest: &'a [u8],
    /// The table being read, as an index into [`TABLES`].
    table: usize,
    records: Records<'a>,
    advisories: usize,
    previous: Option<Row>,
    /// Every row is read, or one was refused.
    done: bool,
}

impl<'a> Decoder<'a> {
    /// Read the lines before the first table.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Undecodable> {
        let mut rest = bytes;
        let first = take_line(&mut rest)?;
        if first != FORMAT {
            return Err(Undecodable(format!(
                "the first line is `{first}`, not `{FORMAT}`"
            )));
        }
        let header = take_line(&mut rest)?;
        let source = header
            .strip_prefix("source ")
            .ok_or_else(|| Undecodable(format!("`{header}` is not `source <name>`")))?
            .to_owned();
        let records = take_table(&mut rest, TABLES[0])?;
        Ok(Self {
            source,
            rest,
            table: 0,
            records,
            advisories: 0,
            previous: None,
            done: false,
        })
    }

    /// The source the rows are stored under.
    pub fn source(&self) -> &str {
        &self.source
    }

    fn next_row(&mut self) -> Result<Option<Row>, Undecodable> {
        loop {
            let table = TABLES[self.table];
            if let Some(record) = self.records.next() {
                let (bytes, fields) = record?;
                let row = self.row(table, fields)?;
                let mut written = Vec::new();
                self.write(&row, &mut written);
                if written != bytes {
                    return Err(Undecodable(format!(
                        "{table}: a row does not encode back to the same bytes"
                    )));
                }
                if self.previous.as_ref().is_some_and(|p| !follows(p, &row)) {
                    return Err(Undecodable(format!(
                        "{table}: a row is out of order or repeated"
                    )));
                }
                self.previous = Some(row.clone());
                return Ok(Some(row));
            }
            self.table += 1;
            match TABLES.get(self.table) {
                Some(next) => self.records = take_table(&mut self.rest, next)?,
                None if self.rest.is_empty() => return Ok(None),
                None => {
                    return Err(Undecodable(format!(
                        "{} bytes follow {table}",
                        self.rest.len()
                    )));
                }
            }
        }
    }

    /// A record of `table`, the table at `self.table`.
    fn row(&mut self, table: &str, fields: Vec<Option<String>>) -> Result<Row, Undecodable> {
        Ok(match self.table {
            0 => {
                let [id, _source, summary, cvss, modified, malware] = width(table, fields)?;
                let cvss = match cvss {
                    Some(text) => Some(text.parse::<f64>().map_err(|_| {
                        Undecodable(format!("{table}: cvss `{text}` is not a number"))
                    })?),
                    None => None,
                };
                let malware = match malware.as_deref() {
                    Some("true") => true,
                    Some("false") => false,
                    other => {
                        return Err(Undecodable(format!(
                            "{table}: malware is `{}`, not true or false",
                            other.unwrap_or_default()
                        )));
                    }
                };
                self.advisories += 1;
                Row::Advisory(Rows {
                    id: given(table, id)?,
                    summary,
                    modified,
                    malware,
                    cvss,
                    unread_vectors: 0,
                    aliases: Default::default(),
                    affected: Default::default(),
                    ranges: Default::default(),
                    unexpressed: 0,
                })
            }
            1 => {
                let [position, name] = width(table, fields)?;
                Row::Alias(self.index(table, position)?, given(table, name)?)
            }
            2 => {
                let [position, ecosystem, name, version] = width(table, fields)?;
                Row::Affected(
                    self.index(table, position)?,
                    Affected {
                        ecosystem: given(table, ecosystem)?,
                        name: given(table, name)?,
                        version,
                    },
                )
            }
            // `advisory_range`, the last table.
            _ => {
                let [position, ecosystem, name, introduced, fixed, last_affected] =
                    width(table, fields)?;
                let end = match (fixed, last_affected) {
                    (None, None) => End::Open,
                    (Some(version), None) => End::Fixed(version),
                    (None, Some(version)) => End::LastAffected(version),
                    (Some(_), Some(_)) => {
                        return Err(Undecodable(format!(
                            "{table}: a row has both fixed and last_affected"
                        )));
                    }
                };
                Row::Ranged(
                    self.index(table, position)?,
                    Ranged {
                        ecosystem: given(table, ecosystem)?,
                        name: given(table, name)?,
                        interval: Interval { introduced, end },
                    },
                )
            }
        })
    }

    /// The index of the advisory a child row's position, counted from 1, refers to.
    fn index(&self, table: &str, position: Option<String>) -> Result<usize, Undecodable> {
        let position = given(table, position)?;
        position
            .parse::<usize>()
            .ok()
            .and_then(|p| p.checked_sub(1))
            .filter(|i| *i < self.advisories)
            .ok_or_else(|| Undecodable(format!("{table}: no advisory at position {position}")))
    }

    /// `row` as [`encode`] writes it.
    fn write(&self, row: &Row, out: &mut Vec<u8>) {
        let key = |index: usize| (index + 1).to_string();
        match row {
            Row::Advisory(r) => advisory_line(out, &self.source, r),
            Row::Alias(i, alias) => alias_line(out, &key(*i), alias),
            Row::Affected(i, a) => affected_line(out, &key(*i), a),
            Row::Ranged(i, r) => range_line(out, &key(*i), r),
        }
    }
}

impl Iterator for Decoder<'_> {
    type Item = Result<Row, Undecodable>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let next = self.next_row().transpose();
        self.done = !matches!(next, Some(Ok(_)));
        next
    }
}

/// A source and its rows, collected from a [`Decoder`].
#[cfg(test)]
pub fn decode(bytes: &[u8]) -> Result<(String, Vec<Rows>), Undecodable> {
    let decoder = Decoder::new(bytes)?;
    let source = decoder.source().to_owned();
    let mut rows: Vec<Rows> = Vec::new();
    for row in decoder {
        match row? {
            Row::Advisory(r) => rows.push(r),
            Row::Alias(i, alias) => {
                rows[i].aliases.insert(alias);
            }
            Row::Affected(i, a) => {
                rows[i].affected.insert(a);
            }
            Row::Ranged(i, r) => {
                rows[i].ranges.insert(r);
            }
        }
    }
    Ok((source, rows))
}

fn take_line<'a>(rest: &mut &'a [u8]) -> Result<&'a str, Undecodable> {
    let end = rest
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Undecodable("a line has no end".to_owned()))?;
    let (line, after) = rest.split_at(end);
    *rest = &after[1..];
    std::str::from_utf8(line).map_err(|_| Undecodable("a line is not UTF-8".to_owned()))
}

/// A `table <bytes>` line and the records in the bytes after it.
fn take_table<'a>(rest: &mut &'a [u8], table: &'static str) -> Result<Records<'a>, Undecodable> {
    let header = take_line(rest)?;
    let length = header
        .strip_prefix(table)
        .and_then(|n| n.strip_prefix(' '))
        .and_then(|n| n.parse::<usize>().ok().filter(|l| l.to_string() == n))
        .ok_or_else(|| Undecodable(format!("`{header}` is not `{table} <bytes>`")))?;
    if length > rest.len() {
        return Err(Undecodable(format!(
            "{table} is {length} bytes and {} remain",
            rest.len()
        )));
    }
    let (csv, after) = rest.split_at(length);
    *rest = after;
    Ok(Records { table, csv, i: 0 })
}

/// Each record's bytes and fields, as [`line`] writes them: an empty field is `None`, and a
/// quoted one is its text with doubled quotes undone. Anything else is refused.
#[derive(Debug)]
struct Records<'a> {
    table: &'static str,
    csv: &'a [u8],
    /// Where the next record starts.
    i: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<(&'a [u8], Vec<Option<String>>), Undecodable>;

    fn next(&mut self) -> Option<Self::Item> {
        (self.i < self.csv.len()).then(|| self.record())
    }
}

impl<'a> Records<'a> {
    fn record(&mut self) -> Result<(&'a [u8], Vec<Option<String>>), Undecodable> {
        let (table, csv, start) = (self.table, self.csv, self.i);
        let refuse = |at: usize, what: &str| Undecodable(format!("{table}: {what} at byte {at}"));
        let i = &mut self.i;
        let mut fields = Vec::new();
        loop {
            let field = if csv.get(*i) == Some(&b'"') {
                let mut value = Vec::new();
                *i += 1;
                loop {
                    match (csv.get(*i).copied(), csv.get(*i + 1).copied()) {
                        (Some(b'"'), Some(b'"')) => {
                            value.push(b'"');
                            *i += 2;
                        }
                        (Some(b'"'), _) => {
                            *i += 1;
                            break;
                        }
                        (Some(byte), _) => {
                            value.push(byte);
                            *i += 1;
                        }
                        (None, _) => return Err(refuse(*i, "a quoted value does not end")),
                    }
                }
                Some(String::from_utf8(value).map_err(|_| refuse(*i, "a value is not UTF-8"))?)
            } else {
                None
            };
            fields.push(field);
            match csv.get(*i) {
                Some(b',') => *i += 1,
                Some(b'\n') => {
                    *i += 1;
                    return Ok((&csv[start..*i], fields));
                }
                _ => return Err(refuse(*i, "a field is neither empty nor quoted")),
            }
        }
    }
}

fn width<const N: usize>(
    table: &str,
    record: Vec<Option<String>>,
) -> Result<[Option<String>; N], Undecodable> {
    <[Option<String>; N]>::try_from(record).map_err(|record| {
        Undecodable(format!(
            "{table}: a row has {} fields, not {N}",
            record.len()
        ))
    })
}

fn given(table: &str, field: Option<String>) -> Result<String, Undecodable> {
    field.ok_or_else(|| Undecodable(format!("{table}: a required value is empty")))
}

/// CSV for `advisory`.
pub fn advisories<'a>(source: &str, rows: impl IntoIterator<Item = &'a Rows>) -> Vec<u8> {
    let mut out = Vec::new();
    for r in rows {
        advisory_line(&mut out, source, r);
    }
    out
}

fn advisory_line(out: &mut Vec<u8>, source: &str, r: &Rows) {
    // `f64`'s `Display` is the shortest text that reads back as the same number.
    let cvss = r.cvss.map(|c| c.to_string());
    let modified = r.modified.as_deref().map(timestamp);
    line(
        out,
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

fn alias_line(out: &mut Vec<u8>, key: &str, alias: &str) {
    line(out, &[Some(key), Some(alias)]);
}

fn affected_line(out: &mut Vec<u8>, key: &str, a: &Affected) {
    line(
        out,
        &[
            Some(key),
            Some(&a.ecosystem),
            Some(&a.name),
            a.version.as_deref(),
        ],
    );
}

fn range_line(out: &mut Vec<u8>, key: &str, ranged: &Ranged) {
    let (fixed, last_affected) = ranged.interval.end.columns();
    line(
        out,
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

    #[test]
    fn decoding_an_encoding_gives_back_the_rows() {
        let given = vec![
            rows(),
            plain("GHSA-1", "CVE-a", "a"),
            Rows {
                cvss: Some(0.1 + 0.2),
                modified: Some("2026-09-08T03:45:02.886711Z".to_owned()),
                ..plain("GHSA-2", "CVE-\"q\"", "b")
            },
        ];
        let (source, decoded) = decode(&encode("osv", &given).bytes).expect("decodes");
        let mut expected = given.clone();
        expected.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!((source.as_str(), decoded), ("osv", expected));

        assert_eq!(
            decode(&encode("ghsa", &[]).bytes),
            Ok(("ghsa".to_owned(), Vec::new()))
        );
    }

    /// The four tables with their lengths, around whatever CSV a case gives.
    fn framed(tables: [&str; 4]) -> Vec<u8> {
        let mut out = format!("{FORMAT}\nsource osv\n");
        for (table, csv) in TABLES.into_iter().zip(tables) {
            out.push_str(&format!("{table} {}\n{csv}", csv.len()));
        }
        out.into_bytes()
    }

    #[test]
    fn bytes_that_are_not_an_encoding_are_refused_with_the_reason() {
        let good = String::from_utf8(encode("osv", &[plain("GHSA-1", "CVE-a", "a")]).bytes)
            .expect("utf-8");
        let row = "\"GHSA-1\",\"osv\",,,,\"true\"\n";
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "a line has no end"),
            (b"\xff\n".to_vec(), "a line is not UTF-8"),
            (
                good.replacen("rows 1", "rows 2", 1).into_bytes(),
                "the first line is `waharoa intel rows 2`, not `waharoa intel rows 1`",
            ),
            (
                good.replacen("source osv", "origin osv", 1).into_bytes(),
                "`origin osv` is not `source <name>`",
            ),
            (
                good.replacen("advisory_alias ", "advisory_aliases ", 1)
                    .into_bytes(),
                "is not `advisory_alias <bytes>`",
            ),
            (
                good.replacen("advisory_range 0", "advisory_range 9", 1)
                    .into_bytes(),
                "advisory_range is 9 bytes and 0 remain",
            ),
            (
                format!("{good}x").into_bytes(),
                "1 bytes follow advisory_range",
            ),
            (
                framed(["\"GHSA-1\",osv,,,,\"true\"\n", "", "", ""]),
                "advisory: a field is neither empty nor quoted at byte 9",
            ),
            (
                framed(["\"GHSA-1", "", "", ""]),
                "advisory: a quoted value does not end at byte 7",
            ),
            (
                framed(["\"X\",\"osv\",,,,\"true\"\n", "", "", ""])
                    .into_iter()
                    .map(|b| if b == b'X' { 0xff } else { b })
                    .collect(),
                "advisory: a value is not UTF-8",
            ),
            (
                framed(["\"GHSA-1\",\"osv\",,,\"true\"\n", "", "", ""]),
                "advisory: a row has 5 fields, not 6",
            ),
            (
                framed(["\"GHSA-1\",\"osv\",,\"high\",,\"true\"\n", "", "", ""]),
                "advisory: cvss `high` is not a number",
            ),
            (
                framed(["\"GHSA-1\",\"osv\",,,,\"yes\"\n", "", "", ""]),
                "advisory: malware is `yes`, not true or false",
            ),
            (
                framed([",\"osv\",,,,\"true\"\n", "", "", ""]),
                "advisory: a required value is empty",
            ),
            (
                framed([row, "\"2\",\"CVE-a\"\n", "", ""]),
                "advisory_alias: no advisory at position 2",
            ),
            (
                framed([row, "\"0\",\"CVE-a\"\n", "", ""]),
                "advisory_alias: no advisory at position 0",
            ),
            (
                framed([row, "", "\"1\",\"npm\",,\n", ""]),
                "advisory_affected: a required value is empty",
            ),
            (
                framed([row, "", "", "\"1\",\"npm\",\"a\",,\"2.0.0\",\"1.0.0\"\n"]),
                "advisory_range: a row has both fixed and last_affected",
            ),
            (
                framed([
                    "\"MAL-1\",\"osv\",,,,\"true\"\n\"GHSA-1\",\"osv\",,,,\"true\"\n",
                    "",
                    "",
                    "",
                ]),
                "advisory: a row is out of order or repeated",
            ),
            (
                framed([&format!("{row}{row}"), "", "", ""]),
                "advisory: a row is out of order or repeated",
            ),
            (
                framed([row, "\"1\",\"CVE-b\"\n\"1\",\"CVE-a\"\n", "", ""]),
                "advisory_alias: a row is out of order or repeated",
            ),
            (
                framed([row, "\"1\",\"CVE-a\"\n\"1\",\"CVE-a\"\n", "", ""]),
                "advisory_alias: a row is out of order or repeated",
            ),
            (
                framed([row, "", "\"1\",\"npm\",\"a\",\n\"1\",\"npm\",\"a\",\n", ""]),
                "advisory_affected: a row is out of order or repeated",
            ),
            (
                framed([row, "", "\"1\",\"npm\",\"b\",\n\"1\",\"npm\",\"a\",\n", ""]),
                "advisory_affected: a row is out of order or repeated",
            ),
            (
                framed([
                    row,
                    "",
                    "",
                    "\"1\",\"npm\",\"a\",,\"1.0.0\",\n\"1\",\"npm\",\"a\",,\"1.0.0\",\n",
                ]),
                "advisory_range: a row is out of order or repeated",
            ),
            (
                framed([
                    row,
                    "",
                    "",
                    "\"1\",\"npm\",\"a\",,\"2.0.0\",\n\"1\",\"npm\",\"a\",,\"1.0.0\",\n",
                ]),
                "advisory_range: a row is out of order or repeated",
            ),
            (
                framed(["\"GHSA-1\",\"osv\",,\"7.50\",,\"true\"\n", "", "", ""]),
                "advisory: a row does not encode back to the same bytes",
            ),
            (
                framed(["\"GHSA-1\",\"ghsa\",,,,\"true\"\n", "", "", ""]),
                "advisory: a row does not encode back to the same bytes",
            ),
            (
                framed([row, "\"01\",\"CVE-a\"\n", "", ""]),
                "advisory_alias: a row does not encode back to the same bytes",
            ),
            (
                good.replacen("advisory_range 0", "advisory_range +0", 1)
                    .into_bytes(),
                "is not `advisory_range <bytes>`",
            ),
        ];
        for (bytes, reason) in cases {
            let err = decode(&bytes).expect_err(reason).to_string();
            assert!(err.contains(reason), "{err:?} lacks {reason:?}");
        }
        assert!(decode(good.as_bytes()).is_ok());
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
    fn a_manifest_is_the_same_for_sources_in_any_order_and_its_id_changes_with_any_digest() {
        let lines = manifest([("osv", "sha256:aa"), ("ghsa", "sha256:bb")]);
        assert_eq!(lines, "ghsa sha256:bb\nosv sha256:aa\n");
        assert_eq!(
            lines,
            manifest([("ghsa", "sha256:bb"), ("osv", "sha256:aa")])
        );

        let id = snapshot_id(&lines);
        assert_eq!(id, format!("sha256:{}", sha256_hex(lines.as_bytes())));
        assert_eq!(id.len(), 71);
        assert_ne!(
            id,
            snapshot_id(&manifest([("osv", "sha256:ab"), ("ghsa", "sha256:bb")]))
        );
        assert_ne!(id, snapshot_id(&manifest([("osv", "sha256:aa")])));
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
