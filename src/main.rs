//! Stage 1: reverse proxy in front of an npm registry, normalising what passes through.
//!
//! Startup only. The proxy itself is [`waharoa::proxy`], which lives in the library so
//! it can be tested against a fake registry; `make smoke-npm` covers this file by
//! running a real npm client through it.
//!
//! No policy engine and no adapter trait (decision #12: Stage 1 calls reqwest
//! concretely). What this stage has to show is that installs work through the proxy and
//! that every package in the resolved graph is observed and normalised, so the logging
//! is load-bearing rather than decoration.

use clap::Parser as _;
use tracing::info;
use waharoa::cli;
use waharoa::doctor;
use waharoa::env;
use waharoa::explain;

use waharoa::intel::fetch;
use waharoa::intel::postgres;
use waharoa::intel::refresh;
use waharoa::policy::{check, diff, today};
use waharoa::startup;

/// A variable that does not parse ends the process with exit 2, as a malformed command line
/// does: the operator asked for something, and continuing without it would hide that.
fn or_exit<T>(result: Result<T, env::EnvError>) -> T {
    or_exit_with(result, 2)
}

/// [`or_exit`] with `code`, for a command whose exit 2 means something else.
fn or_exit_with<T>(result: Result<T, env::EnvError>, code: u8) -> T {
    result.unwrap_or_else(|e| {
        eprintln!("waharoa: {e}");
        std::process::exit(i32::from(code))
    })
}

/// `waharoa policy check <path> [--as-of YYYY-MM-DD] [--strict]`.
///
/// The same load as the proxy at startup, with the same expiry ceiling, so a policy this
/// accepts is one the proxy starts with.
fn run_policy_check(args: cli::Check) -> std::process::ExitCode {
    let as_of = args.as_of.unwrap_or_else(today);
    let ceiling = or_exit(env::process().expiry_ceiling_days());
    let report = match check::load(&args.path, as_of, ceiling) {
        Ok((_, report)) => report,
        Err(e) => {
            eprintln!("waharoa policy check: {}: {e}", args.path.display());
            return std::process::ExitCode::from(e.exit_code());
        }
    };
    print!("{}", report.render());
    if args.strict
        && let Some(failure) = report.strict_failure()
    {
        eprintln!("\nwaharoa policy check: --strict: {failure}");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// `waharoa policy diff <from> <to> [--from-date DATE] [--to-date DATE] [--snapshot ID]
/// [--lockfile PATH]...`.
///
/// The package set is the audit log's versions, which record what this proxy has actually
/// been asked about, and each lockfile's. The exit code is the OR of `diff::LOOSENED` and
/// `diff::TIGHTENED`, or `diff::ERROR` alone.
async fn run_policy_diff(args: cli::Diff) -> std::process::ExitCode {
    let outcome = diff::run(&args, &env::process()).await;
    for note in &outcome.notes {
        eprintln!("waharoa policy diff: {note}");
    }
    print!("{}", outcome.report);
    for note in &outcome.summary {
        eprintln!("waharoa policy diff: {note}");
    }
    std::process::ExitCode::from(outcome.code)
}

/// `waharoa explain`: what the policy says, or what it says about one package.
async fn run_explain(target: cli::Explain) -> std::process::ExitCode {
    let answered = explain::run(&target, &env::process()).await;
    for note in &answered.notes {
        eprintln!("waharoa explain: {note}");
    }
    print!("{}", answered.answer);
    std::process::ExitCode::from(answered.code)
}

async fn run_doctor() -> std::process::ExitCode {
    let checked = match doctor::run(&env::process()).await {
        Ok(checked) => checked,
        Err(e) => {
            eprintln!("waharoa: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    print!("{}", checked.report);
    std::process::ExitCode::from(checked.code)
}

/// The intel store a command cannot run without. Exit 2 when [`env::DATABASE_URL`] is unset,
/// and 1 when the store cannot be reached or migrated.
async fn required_intel_store(
    command: &str,
) -> Result<waharoa::intel::postgres::PgIntel, std::process::ExitCode> {
    match postgres::from_env(&env::process()).await {
        Ok(Some(intel)) => Ok(intel),
        Ok(None) => {
            eprintln!(
                "waharoa {command}: set {} to the intel store's Postgres",
                env::DATABASE_URL
            );
            Err(std::process::ExitCode::from(2))
        }
        Err(e) => {
            eprintln!("waharoa {command}: {}: {e}", env::DATABASE_URL);
            Err(std::process::ExitCode::from(1))
        }
    }
}

/// `waharoa intel history`: the newest entries of the ingestion history.
async fn run_intel_history(args: cli::History) -> std::process::ExitCode {
    let intel = match required_intel_store("intel history").await {
        Ok(intel) => intel,
        Err(code) => return code,
    };
    match intel.history(args.limit).await {
        Ok(entries) => {
            print!("{}", waharoa::intel::history::render(&entries));
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("waharoa intel history: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// The snapshot `--snapshot` names, read from the snapshot directory without its lock.
/// `waharoa refresh`: load every stream in `intel::stream::ALL` into the intel store, and
/// append what each stream did to the ingestion history.
///
/// Connect, migrate, fetch, load, exit. A `Required` stream that cannot be fetched or read
/// loads nothing, and the streams after it are not fetched. An `Optional` stream that cannot
/// be fetched or read leaves its previous load in place: the others still load, and the exit
/// is 1.
async fn run_refresh() -> std::process::ExitCode {
    use waharoa::intel::history::{self, NotLoaded};
    use waharoa::intel::postgres::{PgIntel, Replacement};
    use waharoa::intel::{snapshot_dir::SnapshotDir, stream};

    /// Append `not_loaded` for a refresh that loaded nothing, and exit 1.
    async fn nothing_loaded(intel: &PgIntel, not_loaded: &[NotLoaded]) -> std::process::ExitCode {
        let taken_at = jiff::Timestamp::now().to_string();
        if let Err(e) = intel.record_not_loaded(not_loaded, &taken_at).await {
            eprintln!("waharoa refresh: the ingestion history is not written: {e}");
        }
        std::process::ExitCode::from(1)
    }

    // Connected before the fetch, so a refresh that could record nothing stops before
    // downloading.
    let intel = match required_intel_store("refresh").await {
        Ok(intel) => intel,
        Err(code) => return code,
    };
    let started = std::time::Instant::now();

    // Opened before the fetch, so a second refresh into the same directory waits here rather
    // than after downloading.
    let limit = or_exit(env::process().snapshot_limit());
    let kept = match or_exit(env::process().snapshot_dir())
        .as_deref()
        .map(SnapshotDir::open)
        .transpose()
    {
        Ok(kept) => kept,
        Err(e) => {
            eprintln!("waharoa refresh: {}: {e}", env::SNAPSHOT_DIR);
            return std::process::ExitCode::from(1);
        }
    };

    // Without its timeouts a stalled connection blocks the refresh for as long as the host
    // keeps it open: measured 2026-09-17, one sat for 12 minutes with nothing arriving.
    // Every progress line a fetch produces, prefixed like the rest of this command's.
    let notice = |line: &str| eprintln!("waharoa refresh: {line}");
    let http = match waharoa::intel::refresh::http_client(waharoa::intel::refresh::READ_TIMEOUT) {
        Ok(http) => http,
        Err(e) => {
            eprintln!("waharoa refresh: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let github_token = or_exit(env::process().github_token());

    let read = fetch::read_streams(&http, stream::ALL, github_token.as_deref(), &notice).await;
    let (loaded, not_loaded) = (read.loaded, read.not_loaded);
    if let Some(error) = read.stopped {
        eprintln!("waharoa refresh: nothing loaded: {error}");
        return nothing_loaded(&intel, &not_loaded).await;
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
                eprintln!("waharoa refresh: nothing loaded: {e}");
                return nothing_loaded(&intel, &none_loaded(e.to_string())).await;
            }
        }
    }

    let written = match intel.replace(&sources, &not_loaded, &taken_at).await {
        Ok(written) => written,
        Err(e) => {
            eprintln!("waharoa refresh: nothing loaded: {e}");
            return nothing_loaded(&intel, &none_loaded(e.to_string())).await;
        }
    };

    let kept_report = match &kept {
        Some(kept) => match kept
            .write_snapshot(&written.manifest)
            .and_then(|path| Ok((path, kept.prune(limit)?)))
        {
            Ok((path, pruned)) => Some(refresh::Kept { path, pruned }),
            Err(e) => {
                eprintln!("waharoa refresh: loaded, but the snapshot file is not written: {e}");
                return std::process::ExitCode::from(1);
            }
        },
        None => None,
    };
    print!(
        "{}",
        refresh::report(&loaded, &written, kept_report.as_ref())
    );
    println!("took {:.1}s", started.elapsed().as_secs_f64());
    if not_loaded.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // An unknown command or argument exits 2, or 4 for `policy diff`, rather than falling
    // through to the proxy: `waharoa doctr` silently serving traffic is the wrong thing to do
    // with a typo.
    // `--help` and `--version` exit 0. Every trust decision the proxy makes comes from the
    // environment and the packuments it reads, not from argv.
    // The rule below warns about trusting argv for security decisions. These arguments only
    // choose the exit code for a command line clap refused, and the program path is skipped.
    // nosemgrep: rust.lang.security.args-os.args-os
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let parsed = match cli::Cli::try_parse_from(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            let _ = e.print();
            return std::process::ExitCode::from(cli::exit_code(&e, &args));
        }
    };
    match parsed.command {
        None => {}
        Some(cli::Command::Doctor) => return run_doctor().await,
        Some(cli::Command::Explain(target)) => return run_explain(target).await,
        Some(cli::Command::Policy(cli::PolicyCommand::Check(args))) => {
            return run_policy_check(args);
        }
        Some(cli::Command::Policy(cli::PolicyCommand::Diff(args))) => {
            return run_policy_diff(args).await;
        }
        Some(cli::Command::Intel(cli::IntelCommand::History(args))) => {
            return run_intel_history(args).await;
        }
        Some(cli::Command::Refresh) => return run_refresh().await,
    }

    let environment = env::process();
    let filter = or_exit(environment.log_filter());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|e| {
                eprintln!("waharoa: {}: `{filter}` {e}", env::LOG_FILTER);
                std::process::exit(2)
            }),
        )
        .with_target(false)
        .init();

    let started = match startup::proxy(&environment).await {
        Ok(started) => started,
        // A value that does not parse exits 2, as a malformed command line does.
        Err(startup::StartupError::Env(e)) => {
            eprintln!("waharoa: {e}");
            return std::process::ExitCode::from(2);
        }
        // Something the operator asked for and that is not there or not usable. Refusing
        // to start is right: a running proxy would read as that thing being in force.
        Err(startup::StartupError::Unusable(why)) => panic!("{why}"),
    };
    let (proxy, listen) = (started.proxy, started.listen);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));

    info!(
        listen = %listen,
        upstream_npm = %proxy.upstream_npm(),
        upstream_pypi = %proxy.upstream_pypi(),
        artifact_origins = ?proxy.origin_policy().reachable().as_slice(),
        allowed_direct = ?proxy.origin_policy().allowed_direct(),
        "waharoa listening"
    );
    info!("point npm at it with:  npm config set registry http://{listen}/");
    info!("point pip at it with:  pip config set global.index-url http://{listen}/simple/");

    axum::serve(listener, proxy.router())
        .await
        .expect("server failed");
    std::process::ExitCode::SUCCESS
}
