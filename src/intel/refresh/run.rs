//! Running a refresh: fetch every stream, write its rows, replace the store's load.
//!
//! The one part of a refresh that needs a database, so
//! `scripts/make/coverage.sh` excludes this file as it excludes
//! `crate::intel::postgres`. What is decidable without one is in the rest of
//! `crate::intel`: the requests in `fetch`, the ceilings and retries in the module above,
//! the parses in `providers`, and the report `super::report` renders.

use std::ffi::OsString;
use std::fmt::Write as _;

use super::{Kept, READ_TIMEOUT, http_client};
use crate::env::{self, Env};
use crate::intel::fetch::Notice;
use crate::intel::history::{self, NotLoaded};
use crate::intel::postgres::{self, PgIntel, Replacement};
use crate::intel::snapshot_dir::SnapshotDir;
use crate::intel::{fetch, stream};

/// What a refresh printed and exits with.
#[derive(Debug)]
pub struct Run {
    pub report: String,
    pub code: u8,
}

impl Run {
    /// Nothing was loaded: the reason went to `notice`.
    fn stopped() -> Self {
        Self {
            report: String::new(),
            code: 1,
        }
    }
}

/// Load every stream in [`stream::ALL`] into the intel store, and append what each stream
/// did to the ingestion history.
///
/// Connect, migrate, fetch, load. A `Required` stream that cannot be fetched or read loads
/// nothing, and the streams after it are not fetched. An `Optional` stream that cannot be
/// fetched or read leaves its previous load in place: the others still load, and the code
/// is 1.
pub async fn run<L: Fn(&str) -> Option<OsString>>(environment: &Env<L>, notice: Notice<'_>) -> Run {
    /// Append `not_loaded` for a refresh that loaded nothing, and answer 1.
    async fn nothing_loaded(intel: &PgIntel, not_loaded: &[NotLoaded], notice: Notice<'_>) -> Run {
        let taken_at = jiff::Timestamp::now().to_string();
        if let Err(e) = intel.record_not_loaded(not_loaded, &taken_at).await {
            notice(&format!("the ingestion history is not written: {e}"));
        }
        Run::stopped()
    }

    // Connected before the fetch, so a refresh that could record nothing stops before
    // downloading.
    let intel = match postgres::required(environment).await {
        Ok(intel) => intel,
        Err(refused) => {
            notice(&refused.why);
            return Run {
                report: String::new(),
                code: refused.code,
            };
        }
    };
    let started = std::time::Instant::now();

    // Opened before the fetch, so a second refresh into the same directory waits here rather
    // than after downloading.
    let limit = match environment.snapshot_limit() {
        Ok(value) => value,
        Err(e) => {
            notice(&e.to_string());
            return Run {
                report: String::new(),
                code: 2,
            };
        }
    };
    let kept = match match environment.snapshot_dir() {
        Ok(value) => value,
        Err(e) => {
            notice(&e.to_string());
            return Run {
                report: String::new(),
                code: 2,
            };
        }
    }
    .as_deref()
    .map(SnapshotDir::open)
    .transpose()
    {
        Ok(kept) => kept,
        Err(e) => {
            notice(&format!("{}: {e}", env::SNAPSHOT_DIR));
            return Run::stopped();
        }
    };

    // Without its timeouts a stalled connection blocks the refresh for as long as the host
    // keeps it open: measured 2026-09-17, one sat for 12 minutes with nothing arriving.
    let http = match http_client(READ_TIMEOUT) {
        Ok(http) => http,
        Err(e) => {
            notice(&format!("{e}"));
            return Run::stopped();
        }
    };

    let github_token = match environment.github_token() {
        Ok(value) => value,
        Err(e) => {
            notice(&e.to_string());
            return Run {
                report: String::new(),
                code: 2,
            };
        }
    };

    let read = fetch::read_streams(&http, stream::ALL, github_token.as_deref(), notice).await;
    let (loaded, not_loaded) = (read.loaded, read.not_loaded);
    if loaded.is_empty() {
        notice("nothing loaded: no stream loaded");
        return nothing_loaded(&intel, &not_loaded, notice).await;
    }

    let taken_at = jiff::Timestamp::now().to_string();
    let encoded: Vec<_> = loaded.iter().map(|l| l.payload.encode(l.source)).collect();
    let sources: Vec<Replacement> = loaded
        .iter()
        .zip(&encoded)
        .map(|(l, encoded)| Replacement {
            encoded,
            rows: l.payload.rows(),
            streams: &l.streams,
        })
        .collect();

    let none_loaded = |error: String| history::none_loaded(&sources, &not_loaded, &error);

    // Written before the load, so a snapshot Postgres records never lacks its rows here. Rows
    // left by a load that then fails are removed by the next prune.
    if let Some(kept) = &kept {
        for source in &sources {
            if let Err(e) = kept.write_rows(source.encoded) {
                notice(&format!("nothing loaded: {e}"));
                return nothing_loaded(&intel, &none_loaded(e.to_string()), notice).await;
            }
        }
    }

    let written = match intel.replace(&sources, &not_loaded, &taken_at).await {
        Ok(written) => written,
        Err(e) => {
            notice(&format!("nothing loaded: {e}"));
            return nothing_loaded(&intel, &none_loaded(e.to_string()), notice).await;
        }
    };

    let kept_report = match &kept {
        Some(kept) => match kept
            .write_snapshot(&written.manifest)
            .and_then(|path| Ok((path, kept.prune(limit)?)))
        {
            Ok((path, pruned)) => Some(Kept { path, pruned }),
            Err(e) => {
                notice(&format!(
                    "loaded, but the snapshot file is not written: {e}"
                ));
                return Run::stopped();
            }
        },
        None => None,
    };
    let mut report = super::report(&loaded, &written, kept_report.as_ref());
    let _ = writeln!(report, "took {:.1}s", started.elapsed().as_secs_f64());
    Run {
        report,
        code: u8::from(!not_loaded.is_empty()),
    }
}
