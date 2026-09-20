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

/// `waharoa policy check <path> [--as-of YYYY-MM-DD] [--strict] [--fetch]`.
///
/// The same load as the proxy at startup, with the same expiry ceiling, so a policy this
/// accepts is one the proxy starts with.
async fn run_policy_check(args: cli::Check) -> std::process::ExitCode {
    let as_of = args.as_of.unwrap_or_else(today);
    let ceiling = or_exit(env::process().expiry_ceiling_days());
    let (policy, mut report) = match check::load(&args.path, as_of, ceiling) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("waharoa policy check: {}: {e}", args.path.display());
            return std::process::ExitCode::from(e.exit_code());
        }
    };
    // The only part that leaves the machine, and only when asked: a waiver's version has
    // to be dated by the registry that published it.
    if args.fetch {
        let clients = or_exit(waharoa::ecosystem::Clients::from_env(&env::process()));
        let (outlived, notes) = check::outlived_waivers(&policy, &clients, as_of).await;
        for note in notes {
            eprintln!("waharoa policy check: {note}");
        }
        report.outlived = outlived;
    }
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

/// `waharoa intel history`: the newest entries of the ingestion history.
async fn run_intel_history(args: cli::History) -> std::process::ExitCode {
    let intel = match postgres::required(&env::process()).await {
        Ok(intel) => intel,
        Err(refused) => {
            eprintln!("waharoa intel history: {refused}");
            return std::process::ExitCode::from(refused.code);
        }
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
/// `waharoa refresh`: load every stream into the intel store, and append what each stream
/// did to the ingestion history.
async fn run_refresh() -> std::process::ExitCode {
    let notice = |line: &str| eprintln!("waharoa refresh: {line}");
    let run = refresh::run(&env::process(), &notice).await;
    print!("{}", run.report);
    std::process::ExitCode::from(run.code)
}

/// `waharoa daemon`: serve the proxy until the process is stopped.
async fn run_daemon() -> std::process::ExitCode {
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
        upstreams = %proxy.upstreams(),
        artifact_origins = ?proxy.origin_policy().reachable().as_slice(),
        allowed_direct = ?proxy.origin_policy().allowed_direct(),
        "waharoa listening"
    );
    for registry in waharoa::ecosystem::TABLE {
        let setup = &registry.setup;
        info!(
            "point {} at it with:  {}",
            setup.client,
            setup.command_line(&listen)
        );
    }

    axum::serve(listener, proxy.router())
        .await
        .expect("server failed");
    std::process::ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // No command, or an unknown command or argument, exits 2, or 4 for `policy diff`.
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
        cli::Command::Daemon => run_daemon().await,
        cli::Command::Doctor => run_doctor().await,
        cli::Command::Explain(target) => run_explain(target).await,
        cli::Command::Policy(cli::PolicyCommand::Check(args)) => run_policy_check(args).await,
        cli::Command::Policy(cli::PolicyCommand::Diff(args)) => run_policy_diff(args).await,
        cli::Command::Intel(cli::IntelCommand::History(args)) => run_intel_history(args).await,
        cli::Command::Refresh => run_refresh().await,
    }
}
