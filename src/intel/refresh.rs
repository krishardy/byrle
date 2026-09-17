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
