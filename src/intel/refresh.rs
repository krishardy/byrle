//! Naming what a refresh read: each stream's bundle by its digest, and what it does with a
//! fetch that did not finish.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// Past this, a stream's host is not answering at all.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// No bytes for this long is a stalled connection rather than a slow one.
///
/// Per read, reset by each one, so a download that keeps arriving is never cut off: OSV's
/// 215,141,389-byte npm bundle took 9 s on 2026-09-17 and would take 36 minutes at 100 kB/s,
/// both without a 30 s gap. A total timeout would have to be longer than that whole 36
/// minutes to allow it, and would then let a stall run that long.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches of one stream's bundle before a refresh gives up on it.
pub const ATTEMPTS: u32 = 3;

/// The wait between them.
pub const RETRY_WAIT: Duration = Duration::from_secs(2);

/// Why a fetch did not finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchFailure {
    pub why: String,
    /// Whether another attempt could go better: a refused connection, a stalled read, a
    /// body that stopped mid-stream. A status the host chose and a bundle over its ceiling
    /// are the same on every attempt.
    pub again: bool,
}

impl FetchFailure {
    /// A failure another attempt could get past.
    pub fn transient(why: impl Into<String>) -> Self {
        Self {
            why: why.into(),
            again: true,
        }
    }

    /// A failure every attempt would reach.
    pub fn settled(why: impl Into<String>) -> Self {
        Self {
            why: why.into(),
            again: false,
        }
    }
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

/// The snapshot file a refresh wrote, and what pruning removed.
#[derive(Debug)]
pub struct Kept {
    pub path: std::path::PathBuf,
    pub pruned: super::snapshot_dir::Pruned,
}

/// What a refresh loaded, as it prints it.
///
/// Each stream's own tally first, then the rows written, then what Datadog lists that OSV
/// lists by version, then the snapshot. Built rather than printed so the shape is tested.
pub fn report(
    loaded: &[super::fetch::Loaded],
    written: &super::postgres::Loaded,
    kept: Option<&Kept>,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    for tally in loaded.iter().filter_map(|l| l.tally.as_ref()) {
        let _ = write!(out, "{tally}");
    }
    let mut count = |label: &str, value: u64| {
        let _ = writeln!(out, "{label:32} {value:>8}");
    };
    count("advisories written", written.advisories);
    count("aliases written", written.aliases);
    count("affected rows written", written.affected);
    count("ranges written", written.ranges);
    count("exploited CVE ids written", written.exploited);

    let rows_of = |source: &str| {
        loaded
            .iter()
            .find(|l| l.source == source)
            .map(|l| l.payload.rows())
    };
    if let (Some(osv_rows), Some(datadog_rows)) = (
        rows_of(super::providers::osv::SOURCE),
        rows_of(super::providers::datadog::SOURCE),
    ) {
        let disagreements = super::providers::datadog::disagreements(osv_rows, datadog_rows);
        for disagreement in &disagreements {
            let _ = writeln!(out, "{disagreement}");
        }
        let _ = writeln!(
            out,
            "{:32} {:>8}",
            "datadog every version, osv some",
            disagreements.len()
        );
    }
    let _ = writeln!(out, "snapshot {}", written.snapshot);
    if let Some(kept) = kept {
        let _ = writeln!(out, "{:32} {}", "snapshot file", kept.path.display());
        let _ = writeln!(
            out,
            "{:32} {:>8}",
            "snapshot files removed", kept.pruned.snapshots
        );
        let _ = writeln!(out, "{:32} {:>8}", "rows files removed", kept.pruned.rows);
    }
    out
}

/// The client a refresh fetches every stream with.
///
/// `read_timeout` is [`READ_TIMEOUT`] in the binary; a test passes a short one. There is no
/// total timeout: see [`READ_TIMEOUT`].
pub fn http_client(read_timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(read_timeout)
        .build()
}

/// Whether `failure` on attempt `attempt`, counted from 1, is followed by another.
pub fn retried(failure: &FetchFailure, attempt: u32) -> bool {
    failure.again && attempt < ATTEMPTS
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One stream's bundle, as a snapshot records it. Recorded, and part of no digest: the
/// snapshot id is the digest of the rows. See `load::encode`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamDigest {
    pub stream: String,
    pub sha256: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transient failure is retried until the attempts run out. A settled one is not
    /// retried at all: `osv/npm` is `Required`, so a refresh that gives up on it loads
    /// nothing, and one that retries a 404 forever would never say so.
    #[test]
    fn only_a_transient_failure_is_retried_and_only_while_attempts_are_left() {
        let transient = FetchFailure::transient("reading: error decoding response body");
        let settled = FetchFailure::settled("fetching: HTTP status 404");
        assert_eq!(
            (1..=ATTEMPTS)
                .map(|attempt| retried(&transient, attempt))
                .collect::<Vec<_>>(),
            [true, true, false]
        );
        assert!(!retried(&settled, 1));
        assert_eq!(transient.to_string(), transient.why);
        assert!(transient.again && !settled.again);
    }

    /// Every count a refresh prints, in order, and the snapshot last.
    #[test]
    fn the_report_counts_what_was_written_and_names_the_snapshot() {
        let written = crate::intel::postgres::Loaded {
            advisories: 3,
            aliases: 2,
            affected: 7,
            ranges: 1,
            exploited: 4,
            snapshot: "sha256:ab".to_owned(),
            manifest: "osv sha256:cd\n".to_owned(),
        };
        let kept = Kept {
            path: std::path::PathBuf::from("/snapshots/ab.snapshot"),
            pruned: crate::intel::snapshot_dir::Pruned {
                snapshots: 2,
                rows: 5,
            },
        };
        let printed = report(&[], &written, Some(&kept));
        assert_eq!(
            printed.lines().collect::<Vec<_>>(),
            [
                "advisories written                      3",
                "aliases written                         2",
                "affected rows written                   7",
                "ranges written                          1",
                "exploited CVE ids written               4",
                "snapshot sha256:ab",
                "snapshot file                    /snapshots/ab.snapshot",
                "snapshot files removed                  2",
                "rows files removed                      5",
            ]
        );
    }

    /// A package Datadog lists at every version and OSV lists by version is printed and
    /// counted. Which stream is which is read from `source`.
    #[test]
    fn the_report_names_what_datadog_lists_and_osv_lists_by_version() {
        use crate::intel::providers::{datadog, osv};
        use crate::intel::rows::{Affected, Rows};
        use crate::intel::stream::{Parsed as _Parsed, Payload};

        let _ = std::mem::size_of::<_Parsed>();
        let rows = |id: &str, version: Option<&str>, malware: bool| Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware,
            cvss: None,
            band: None,
            unread_vectors: 0,
            aliases: Default::default(),
            affected: [Affected {
                ecosystem: "npm".to_owned(),
                name: "left-pad".to_owned(),
                version: version.map(str::to_owned),
            }]
            .into(),
            ranges: Default::default(),
            unexpressed: 0,
        };
        let loaded = |source: &'static str, row: Rows| super::super::fetch::Loaded {
            source,
            payload: Payload::Advisories(vec![row]),
            tally: None,
            streams: [StreamDigest {
                stream: source.to_owned(),
                sha256: "aa".to_owned(),
                etag: None,
                last_modified: None,
            }],
        };
        let written = crate::intel::postgres::Loaded {
            advisories: 1,
            aliases: 0,
            affected: 1,
            ranges: 0,
            exploited: 0,
            snapshot: "sha256:ab".to_owned(),
            manifest: String::new(),
        };
        let printed = report(
            &[
                loaded(osv::SOURCE, rows("MAL-1", Some("1.0.0"), true)),
                loaded(datadog::SOURCE, rows("DATADOG-npm-left-pad", None, true)),
            ],
            &written,
            None,
        );
        assert!(
            printed.contains("left-pad: datadog/npm every version, osv/npm some: MAL-1"),
            "{printed}"
        );
        let counted = printed
            .lines()
            .find_map(|line| line.strip_prefix("datadog every version, osv some"))
            .expect("the count is printed");
        assert_eq!(counted.trim(), "1", "{printed}");
    }

    /// Without a snapshot directory the last line is the snapshot id.
    #[test]
    fn a_refresh_that_keeps_no_snapshot_prints_no_file() {
        let written = crate::intel::postgres::Loaded {
            advisories: 0,
            aliases: 0,
            affected: 0,
            ranges: 0,
            exploited: 0,
            snapshot: "sha256:ab".to_owned(),
            manifest: String::new(),
        };
        let printed = report(&[], &written, None);
        assert!(printed.ends_with("snapshot sha256:ab\n"), "{printed}");
        assert!(!printed.contains("snapshot file"), "{printed}");
    }

    /// A body that is declared and never sent ends the read, rather than holding the
    /// refresh for as long as the host keeps the connection open.
    #[tokio::test]
    async fn a_stalled_body_times_out() {
        let addr = crate::test_support::stalling_server().await;
        let client = http_client(Duration::from_millis(100)).expect("a client");
        let response = client
            .get(format!("http://{addr}/all.zip"))
            .send()
            .await
            .expect("the headers arrive");
        // A deadline of its own, so this test fails rather than hanging when the client
        // carries no read timeout.
        let error = tokio::time::timeout(Duration::from_secs(5), response.bytes())
            .await
            .expect("the read timeout ends it well inside 5 s")
            .expect_err("the body never arrives");
        assert!(error.is_timeout(), "{error}");
        assert!(!error.is_status(), "a stall is not a status the host chose");
    }

    /// One read at a time, so a download that keeps arriving is never cut off.
    #[test]
    fn the_read_timeout_is_a_gap_rather_than_a_deadline() {
        assert_eq!(READ_TIMEOUT, Duration::from_secs(30));
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(RETRY_WAIT, Duration::from_secs(2));
    }

    #[test]
    fn a_digest_is_lowercase_hex_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
