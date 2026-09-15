//! The ingestion history: every stream a refresh loaded or did not, as `intel_ingestion`
//! records it and `waharoa intel history` prints it.
//!
//! See docs/engineering_decisions/ingestion-history.md.

use super::refresh::StreamDigest;
use std::fmt::Write;

/// A stream a refresh fetched, or tried to, that did not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotLoaded {
    /// The source its rows are stored under.
    pub source: String,
    pub stream: String,
    /// The bundle, when it was fetched.
    pub bundle: Option<StreamDigest>,
    pub error: String,
}

/// One row of `intel_ingestion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingestion {
    /// RFC 3339 UTC.
    pub taken_at: String,
    pub source: String,
    pub stream: String,
    /// The bundle's hex SHA-256, when it was fetched.
    pub sha256: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// The digest of the rows loaded. `None` when the stream did not load.
    pub rows: Option<String>,
    /// The snapshot the store contained after the refresh. `None` when it loaded nothing.
    pub snapshot: Option<String>,
    /// Why the stream did not load. `None` when it loaded.
    pub error: Option<String>,
}

impl Ingestion {
    /// A stream whose rows, digest `rows`, loaded into `snapshot`.
    pub fn loaded(
        taken_at: &str,
        source: &str,
        bundle: &StreamDigest,
        rows: &str,
        snapshot: &str,
    ) -> Self {
        Self {
            taken_at: taken_at.to_owned(),
            source: source.to_owned(),
            stream: bundle.stream.clone(),
            sha256: Some(bundle.sha256.clone()),
            etag: bundle.etag.clone(),
            last_modified: bundle.last_modified.clone(),
            rows: Some(rows.to_owned()),
            snapshot: Some(snapshot.to_owned()),
            error: None,
        }
    }

    /// A stream that did not load. `snapshot` is `None` when the refresh loaded nothing.
    pub fn not_loaded(taken_at: &str, stream: &NotLoaded, snapshot: Option<&str>) -> Self {
        let bundle = stream.bundle.as_ref();
        Self {
            taken_at: taken_at.to_owned(),
            source: stream.source.clone(),
            stream: stream.stream.clone(),
            sha256: bundle.map(|b| b.sha256.clone()),
            etag: bundle.and_then(|b| b.etag.clone()),
            last_modified: bundle.and_then(|b| b.last_modified.clone()),
            rows: None,
            snapshot: snapshot.map(str::to_owned),
            error: Some(stream.error.clone()),
        }
    }
}

/// `entries` as `waharoa intel history` prints them, in the order given.
pub fn render(entries: &[Ingestion]) -> String {
    if entries.is_empty() {
        return "no ingestion recorded; run `waharoa refresh`\n".to_owned();
    }
    let blocks: Vec<String> = entries.iter().map(block).collect();
    blocks.join("\n")
}

fn block(entry: &Ingestion) -> String {
    let outcome = match entry.error {
        None => "loaded",
        Some(_) => "not loaded",
    };
    let snapshot = entry
        .snapshot
        .as_deref()
        .unwrap_or("none: the refresh loaded nothing");
    let mut out = format!("{} {} {outcome}\n", entry.taken_at, entry.stream);
    for (label, value) in [
        ("source", Some(entry.source.as_str())),
        ("bundle sha256", entry.sha256.as_deref()),
        ("etag", entry.etag.as_deref()),
        ("last-modified", entry.last_modified.as_deref()),
        ("rows", entry.rows.as_deref()),
        ("snapshot", Some(snapshot)),
        ("error", entry.error.as_deref()),
    ] {
        if let Some(value) = value {
            let _ = writeln!(out, "  {label:13} {value}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_entry_prints_what_it_records_and_whether_it_loaded() {
        let bundle = StreamDigest {
            stream: "osv/npm".to_owned(),
            sha256: "ca0e".to_owned(),
            etag: Some("\"219a\"".to_owned()),
            last_modified: Some("Mon, 14 Sep 2026 22:35:59 GMT".to_owned()),
        };
        let fetch_failed = NotLoaded {
            source: "datadog".to_owned(),
            stream: "datadog/npm".to_owned(),
            bundle: None,
            error: "fetching: refused".to_owned(),
        };
        let unread = NotLoaded {
            source: "osv".to_owned(),
            stream: "osv/npm".to_owned(),
            bundle: Some(StreamDigest {
                last_modified: None,
                ..bundle.clone()
            }),
            error: "a record did not read".to_owned(),
        };
        let entries = [
            Ingestion::not_loaded("2026-09-15T15:14:02Z", &fetch_failed, Some("sha256:7796")),
            Ingestion::loaded(
                "2026-09-15T15:14:02Z",
                "osv",
                &bundle,
                "sha256:4c0f",
                "sha256:7796",
            ),
            Ingestion::not_loaded("2026-09-14T09:00:00Z", &unread, None),
        ];
        assert_eq!(
            render(&entries),
            "\
2026-09-15T15:14:02Z datadog/npm not loaded
  source        datadog
  snapshot      sha256:7796
  error         fetching: refused

2026-09-15T15:14:02Z osv/npm loaded
  source        osv
  bundle sha256 ca0e
  etag          \"219a\"
  last-modified Mon, 14 Sep 2026 22:35:59 GMT
  rows          sha256:4c0f
  snapshot      sha256:7796

2026-09-14T09:00:00Z osv/npm not loaded
  source        osv
  bundle sha256 ca0e
  etag          \"219a\"
  snapshot      none: the refresh loaded nothing
  error         a record did not read
"
        );
    }

    #[test]
    fn no_entry_says_so() {
        assert_eq!(
            render(&[]),
            "no ingestion recorded; run `waharoa refresh`\n"
        );
    }
}
