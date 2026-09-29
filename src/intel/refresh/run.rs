//! Running a refresh: fetch every stream, write its rows, replace the store's load.
//!
//! The part of a refresh that needs a database, so `scripts/make/coverage.sh` excludes it.

use std::ffi::OsString;
use std::fmt::Write as _;

use super::{Kept, http_client};
use crate::env::{self, Env};
use crate::http::READ_TIMEOUT;
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
    fn stopped(code: u8) -> Self {
        Self {
            report: String::new(),
            code,
        }
    }
}

/// Load every stream in [`stream::ALL`] into the intel store, and append what each stream
/// did to the ingestion history.
pub async fn run<L: Fn(&str) -> Option<OsString>>(environment: &Env<L>, notice: Notice<'_>) -> Run {
    let intel = match postgres::required(environment).await {
        Ok(intel) => intel,
        Err(refused) => {
            notice(&refused.why);
            return Run::stopped(refused.code);
        }
    };
    let started = std::time::Instant::now();
    let setup = match Setup::read(environment, notice) {
        Ok(setup) => setup,
        Err(code) => return Run::stopped(code),
    };

    let read = fetch::read_streams(
        &setup.http,
        stream::ALL,
        setup.github_token.as_deref(),
        notice,
    )
    .await;
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
    let written = match load(
        &intel,
        setup.kept.as_ref(),
        &sources,
        &not_loaded,
        &taken_at,
        notice,
    )
    .await
    {
        Ok(written) => written,
        Err(run) => return run,
    };

    let kept_report = match &setup.kept {
        Some(kept) => match kept
            .write_snapshot(&written.manifest)
            .and_then(|path| Ok((path, kept.prune(setup.limit)?)))
        {
            Ok((path, pruned)) => Some(Kept { path, pruned }),
            Err(e) => {
                notice(&format!(
                    "loaded, but the snapshot file is not written: {e}"
                ));
                return Run::stopped(1);
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

/// What a refresh reads from the environment besides the store.
struct Setup {
    limit: usize,
    kept: Option<SnapshotDir>,
    http: reqwest::Client,
    github_token: Option<String>,
}

impl Setup {
    /// `Err` is the exit code, after the reason went to `notice`.
    ///
    /// The snapshot directory is opened before the fetch, so a second refresh into the same
    /// directory waits here rather than after downloading.
    fn read<L: Fn(&str) -> Option<OsString>>(
        environment: &Env<L>,
        notice: Notice<'_>,
    ) -> Result<Self, u8> {
        let stop = |code: u8, why: String| {
            notice(&why);
            code
        };
        let limit = environment
            .snapshot_limit()
            .map_err(|e| stop(2, e.to_string()))?;
        let kept = environment
            .snapshot_dir()
            .map_err(|e| stop(2, e.to_string()))?
            .as_deref()
            .map(SnapshotDir::open)
            .transpose()
            .map_err(|e| stop(1, format!("{}: {e}", env::SNAPSHOT_DIR)))?;
        let http = http_client(READ_TIMEOUT).map_err(|e| stop(1, format!("{e}")))?;
        let github_token = environment
            .github_token()
            .map_err(|e| stop(2, e.to_string()))?;
        Ok(Self {
            limit,
            kept,
            http,
            github_token,
        })
    }
}

/// Write each source's rows to `kept`, then replace the store's load with `sources`. `Err`
/// is the answer for a refresh that loaded nothing.
///
/// The rows are written before the load, so a snapshot Postgres records never lacks its
/// rows here. Rows left by a load that then fails are removed by the next prune.
async fn load(
    intel: &PgIntel,
    kept: Option<&SnapshotDir>,
    sources: &[Replacement<'_>],
    not_loaded: &[NotLoaded],
    taken_at: &str,
    notice: Notice<'_>,
) -> Result<postgres::Loaded, Run> {
    let failed = |error: String| async move {
        notice(&format!("nothing loaded: {error}"));
        let not_loaded = history::none_loaded(sources, not_loaded, &error);
        nothing_loaded(intel, &not_loaded, notice).await
    };
    if let Some(kept) = kept {
        for source in sources {
            if let Err(e) = kept.write_rows(source.encoded) {
                return Err(failed(e.to_string()).await);
            }
        }
    }
    match intel.replace(sources, not_loaded, taken_at).await {
        Ok(written) => Ok(written),
        Err(e) => Err(failed(e.to_string()).await),
    }
}

/// Append `not_loaded` for a refresh that loaded nothing, and answer 1.
async fn nothing_loaded(intel: &PgIntel, not_loaded: &[NotLoaded], notice: Notice<'_>) -> Run {
    let taken_at = jiff::Timestamp::now().to_string();
    if let Err(e) = intel.record_not_loaded(not_loaded, &taken_at).await {
        notice(&format!("the ingestion history is not written: {e}"));
    }
    Run::stopped(1)
}
