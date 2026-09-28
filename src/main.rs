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
/// `waharoa audit verify`: decide each pinned line of an audit log again.
fn run_audit_verify(args: cli::Verify) -> std::process::ExitCode {
    let verified = waharoa::audit::verify(&args.log, &args.policy);
    for note in &verified.notes {
        eprintln!("waharoa audit verify: {note}");
    }
    print!("{}", verified.report);
    std::process::ExitCode::from(verified.code)
}

/// `waharoa warm`: ask the proxy for every artifact the lockfiles lock.
async fn run_warm(args: cli::Warm) -> std::process::ExitCode {
    let targets = match (args.all_platforms, args.platform.is_empty()) {
        (true, _) => None,
        (false, true) => Some(vec![waharoa::lockfile::Target::this_machine()]),
        (false, false) => Some(args.platform),
    };
    let warmed = waharoa::warm::run(
        &args.lockfile,
        args.proxy.as_deref(),
        targets.as_deref(),
        std::time::Duration::from_secs(args.deadline),
        &env::process(),
    )
    .await;
    for note in &warmed.notes {
        eprintln!("waharoa warm: {note}");
    }
    print!("{}", warmed.report);
    std::process::ExitCode::from(warmed.code)
}

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

/// `waharoa status`: what this build does for each ecosystem, and what covers it.
///
/// Two axes that fail separately: an adapter can be complete while no stream covers its
/// ecosystem. `doctor` answers whether this machine is wired up; this answers what waharoa
/// does at all.
async fn run_status() -> std::process::ExitCode {
    let environment = env::process();
    let upstreams = or_exit(environment.upstreams());
    // The snapshot is what the store last loaded. No store, or one that cannot answer, is
    // reported as no snapshot rather than as an error: the adapter axis is still worth
    // printing.
    use waharoa::intel::store::Intel as _;
    let snapshot = match postgres::from_env(&environment).await {
        Ok(Some(store)) => match store.snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                eprintln!("waharoa status: the intel store could not be read: {e}");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            eprintln!("waharoa status: {}: {e}", env::DATABASE_URL);
            None
        }
    };
    print!("{}", waharoa::status::report(&upstreams, snapshot.as_ref()));
    std::process::ExitCode::SUCCESS
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
    let filter = tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|e| {
        eprintln!("waharoa: {}: `{filter}` {e}", env::LOG_FILTER);
        std::process::exit(2)
    });
    let format = or_exit(environment.log_format());
    tracing::subscriber::set_global_default(waharoa::logging::subscriber(
        filter,
        format,
        std::io::stdout,
    ))
    .expect("the daemon sets its subscriber once");

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
            client = setup.client,
            command = %setup.command_line(&listen),
            "point a client at the proxy"
        );
    }

    #[cfg(unix)]
    tokio::spawn(startup::reload_on_hangup(proxy.clone(), env::process()));
    let reporting = proxy.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(waharoa::proxy::TRAFFIC_WINDOW);
        every.tick().await;
        loop {
            every.tick().await;
            reporting.report_traffic();
        }
    });
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
        cli::Command::Status => run_status().await,
        cli::Command::Explain(target) => run_explain(target).await,
        cli::Command::Audit(cli::AuditCommand::Verify(args)) => run_audit_verify(args),
        cli::Command::Policy(cli::PolicyCommand::Check(args)) => run_policy_check(args).await,
        cli::Command::Policy(cli::PolicyCommand::Diff(args)) => run_policy_diff(args).await,
        cli::Command::Intel(cli::IntelCommand::History(args)) => run_intel_history(args).await,
        cli::Command::Refresh => run_refresh().await,
        cli::Command::Warm(args) => run_warm(args).await,
    }
}
