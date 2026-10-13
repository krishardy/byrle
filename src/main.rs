//! The `byrle` binary: parse the command line, run the command, print what it returns.
//!
//! Each command is in the library. `make smoke-npm`, `make smoke-python` and
//! `make smoke-clients` cover this file by running real clients through the proxy.

use byrle::cli;
use byrle::doctor;
use byrle::env;
use byrle::explain;
use clap::Parser as _;
use tracing::info;

use byrle::intel::postgres;
use byrle::intel::refresh;
use byrle::policy::{check, diff, today};
use byrle::startup;

/// A variable that does not parse ends the process with exit 2, as a malformed command line
/// does: the operator asked for something, and continuing without it would hide that.
fn or_exit<T>(result: Result<T, env::EnvError>) -> T {
    or_exit_with(result, 2)
}

/// [`or_exit`] with `code`, for a command whose exit 2 means something else.
fn or_exit_with<T>(result: Result<T, env::EnvError>, code: u8) -> T {
    result.unwrap_or_else(|e| {
        eprintln!("byrle: {e}");
        std::process::exit(i32::from(code))
    })
}

/// `byrle policy check <path> [--as-of YYYY-MM-DD] [--strict] [--fetch]`.
///
/// The same load as the proxy at startup, with the same expiry ceiling, so a policy this
/// accepts is one the proxy starts with.
async fn run_policy_check(args: cli::Check) -> std::process::ExitCode {
    let as_of = args.as_of.unwrap_or_else(today);
    let ceiling = or_exit(env::process().expiry_ceiling_days());
    let (policy, mut report) = match check::load(&args.path, as_of, ceiling) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("byrle policy check: {}: {e}", args.path.display());
            return std::process::ExitCode::from(e.exit_code());
        }
    };
    if args.fetch {
        let clients = or_exit(byrle::ecosystem::Clients::from_env(&env::process()));
        let (outlived, notes) = check::outlived_waivers(&policy, &clients, as_of).await;
        for note in notes {
            eprintln!("byrle policy check: {note}");
        }
        report.outlived = outlived;
    }
    print!("{}", report.render());
    if args.strict
        && let Some(failure) = report.strict_failure()
    {
        eprintln!("\nbyrle policy check: --strict: {failure}");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// `byrle audit verify`: decide each pinned line of an audit log again.
fn run_audit_verify(args: cli::Verify) -> std::process::ExitCode {
    let verified = byrle::audit::verify(&args.log, &args.policy);
    for note in &verified.notes {
        eprintln!("byrle audit verify: {note}");
    }
    print!("{}", verified.report);
    std::process::ExitCode::from(verified.code)
}

/// `byrle warm`: ask the proxy for every artifact the lockfiles lock.
fn run_lockfile_verify(args: cli::VerifyLockfile) -> std::process::ExitCode {
    let verified =
        byrle::lockfile::verify::run(&args.lockfile, args.proxy.as_deref(), &env::process());
    for note in &verified.notes {
        eprintln!("byrle lockfile verify: {note}");
    }
    print!("{}", verified.report);
    std::process::ExitCode::from(verified.code)
}

async fn run_warm(args: cli::Warm) -> std::process::ExitCode {
    let targets = match (args.all_platforms, args.platform.is_empty()) {
        (true, _) => None,
        (false, true) => Some(vec![byrle::lockfile::Target::this_machine()]),
        (false, false) => Some(args.platform),
    };
    let warmed = byrle::warm::run(
        &args.lockfile,
        args.proxy.as_deref(),
        targets.as_deref(),
        std::time::Duration::from_secs(args.deadline),
        &env::process(),
    )
    .await;
    for note in &warmed.notes {
        eprintln!("byrle warm: {note}");
    }
    print!("{}", warmed.report);
    std::process::ExitCode::from(warmed.code)
}

async fn run_policy_diff(args: cli::Diff) -> std::process::ExitCode {
    let outcome = diff::run(&args, &env::process()).await;
    for note in &outcome.notes {
        eprintln!("byrle policy diff: {note}");
    }
    print!("{}", outcome.report);
    for note in &outcome.summary {
        eprintln!("byrle policy diff: {note}");
    }
    std::process::ExitCode::from(outcome.code)
}

/// `byrle explain`: what the policy says, or what it says about one package.
async fn run_explain(target: cli::Explain) -> std::process::ExitCode {
    let answered = explain::run(&target, &env::process()).await;
    for note in &answered.notes {
        eprintln!("byrle explain: {note}");
    }
    print!("{}", answered.answer);
    std::process::ExitCode::from(answered.code)
}

async fn run_doctor() -> std::process::ExitCode {
    let environment = env::process();
    let dir = std::env::current_dir().unwrap_or_default();
    let checked = match doctor::run(&doctor::Machine::this(&environment, &dir)).await {
        Ok(checked) => checked,
        Err(e) => {
            eprintln!("byrle: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    print!("{}", checked.report);
    std::process::ExitCode::from(checked.code)
}

/// `byrle status`: what this build does for each ecosystem, and which streams cover it.
async fn run_status() -> std::process::ExitCode {
    let environment = env::process();
    let upstreams = or_exit(environment.upstreams());
    use byrle::intel::store::Intel as _;
    let snapshot = match postgres::from_env(&environment).await {
        Ok(Some(store)) => match store.snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                eprintln!("byrle status: the intel store could not be read: {e}");
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            eprintln!("byrle status: {}: {e}", env::DATABASE_URL);
            None
        }
    };
    print!("{}", byrle::status::report(&upstreams, snapshot.as_ref()));
    std::process::ExitCode::SUCCESS
}

/// The account store at [`env::DATABASE_URL`], or the exit `byrle <command>` takes without it.
async fn accounts(
    command: &str,
) -> Result<byrle::account::postgres::PgAccounts, std::process::ExitCode> {
    match postgres::required(&env::process()).await {
        Ok(intel) => Ok(byrle::account::postgres::PgAccounts::new(
            intel.pool().clone(),
        )),
        Err(refused) => {
            eprintln!("byrle {command}: {refused}");
            Err(std::process::ExitCode::from(refused.code))
        }
    }
}

/// [`env::ACCOUNT_EVENT_LOG`], checked to be writable before anything is changed.
fn event_log(command: &str) -> Result<Option<std::path::PathBuf>, std::process::ExitCode> {
    let refused = |e: &dyn std::fmt::Display| {
        eprintln!("byrle {command}: {}: {e}", env::ACCOUNT_EVENT_LOG);
        std::process::ExitCode::from(1)
    };
    let path = env::process()
        .account_event_log()
        .map_err(|e| refused(&e))?;
    if let Some(path) = &path {
        byrle::account::events::writable(path).map_err(|e| refused(&e))?;
    }
    Ok(path)
}

/// Append what an account or token command changed to the account event log, print what
/// it printed, and exit with its code.
fn finish(
    outcome: byrle::account::command::Outcome,
    log: Option<&std::path::Path>,
) -> std::process::ExitCode {
    let outcome = byrle::account::command::logged(outcome, log);
    print!("{}", outcome.stdout);
    eprint!("{}", outcome.stderr);
    std::process::ExitCode::from(outcome.code)
}

/// `byrle artifact show|export`, against the analysis store at [`env::DATABASE_URL`].
async fn run_artifact(command: cli::ArtifactCommand) -> std::process::ExitCode {
    use byrle::analysis::decision::command;
    let store = match postgres::required(&env::process()).await {
        Ok(intel) => byrle::analysis::postgres::PgAnalyses::new(intel.pool().clone()),
        Err(refused) => {
            eprintln!("byrle artifact: {refused}");
            return std::process::ExitCode::from(refused.code);
        }
    };
    let (mut out, mut err) = (std::io::stdout().lock(), std::io::stderr());
    std::process::ExitCode::from(match command {
        cli::ArtifactCommand::Show(args) => {
            command::show(&store, &args.artifact, &mut out, &mut err).await
        }
        cli::ArtifactCommand::Export(args) => {
            command::export(&store, args.since, args.until, &mut out, &mut err).await
        }
    })
}

/// `byrle account create|disable|list`.
async fn run_account(command: cli::AccountCommand) -> std::process::ExitCode {
    use byrle::account::command;
    let (store, log) = match (accounts("account").await, event_log("account")) {
        (Ok(store), Ok(log)) => (store, log),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let outcome = match command {
        cli::AccountCommand::Create(args) => {
            command::create_account(&store, &args.name, &args.roles).await
        }
        cli::AccountCommand::Disable(args) => command::disable_account(&store, &args.name).await,
        cli::AccountCommand::Password(args) => {
            match byrle::account::password::read(&mut std::io::stdin().lock()) {
                Ok(password) => {
                    let hasher = byrle::account::password::Hasher::standard();
                    command::set_password(&store, &args.name, &password, &hasher).await
                }
                Err(why) => {
                    eprintln!("byrle account password: {why}");
                    return std::process::ExitCode::from(1);
                }
            }
        }
        cli::AccountCommand::List => command::list_accounts(&store).await,
    };
    finish(outcome, log.as_deref())
}

/// `byrle token create|revoke|list`.
async fn run_token(command: cli::TokenCommand) -> std::process::ExitCode {
    use byrle::account::command;
    let (store, log) = match (accounts("token").await, event_log("token")) {
        (Ok(store), Ok(log)) => (store, log),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let outcome = match command {
        cli::TokenCommand::Create(args) => {
            command::create_token(&store, &args.account, &args.name).await
        }
        cli::TokenCommand::Revoke(args) => {
            command::revoke_token(&store, &args.account, &args.name).await
        }
        cli::TokenCommand::List(args) => command::list_tokens(&store, args.account.as_ref()).await,
    };
    finish(outcome, log.as_deref())
}

/// `byrle intel history`: the newest entries of the ingestion history.
async fn run_intel_history(args: cli::History) -> std::process::ExitCode {
    let intel = match postgres::required(&env::process()).await {
        Ok(intel) => intel,
        Err(refused) => {
            eprintln!("byrle intel history: {refused}");
            return std::process::ExitCode::from(refused.code);
        }
    };
    match intel.history(args.limit).await {
        Ok(entries) => {
            print!("{}", byrle::intel::history::render(&entries));
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("byrle intel history: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// The snapshot `--snapshot` names, read from the snapshot directory without its lock.
/// `byrle refresh`: load every stream into the intel store, and append what each stream
/// did to the ingestion history.
async fn run_refresh() -> std::process::ExitCode {
    let notice = |line: &str| eprintln!("byrle refresh: {line}");
    let run = refresh::run(&env::process(), &notice).await;
    print!("{}", run.report);
    std::process::ExitCode::from(run.code)
}

/// `byrle daemon`: serve the proxy until the process is stopped.
async fn run_daemon() -> std::process::ExitCode {
    let environment = env::process();
    let filter = or_exit(environment.log_filter());
    let filter = tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|e| {
        eprintln!("byrle: {}: `{filter}` {e}", env::LOG_FILTER);
        std::process::exit(2)
    });
    let format = or_exit(environment.log_format());
    tracing::subscriber::set_global_default(byrle::logging::subscriber(
        filter,
        format,
        std::io::stdout,
    ))
    .expect("the daemon sets its subscriber once");

    let started = match startup::proxy(&environment).await {
        Ok(started) => started,
        Err(startup::StartupError::Env(e)) => {
            eprintln!("byrle: {e}");
            return std::process::ExitCode::from(2);
        }
        Err(startup::StartupError::Unusable(why)) => panic!("{why}"),
    };
    let (proxy, listen, console, watch) = (
        started.proxy,
        started.listen,
        started.console,
        started.watch,
    );

    report_listening(
        &proxy,
        &listen,
        console.as_ref(),
        &or_exit(environment.proxy_base()),
    );

    #[cfg(unix)]
    tokio::spawn(startup::reload_on_hangup(proxy.clone(), env::process()));
    let reporting = proxy.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(byrle::proxy::TRAFFIC_WINDOW);
        every.tick().await;
        loop {
            every.tick().await;
            reporting.report_traffic();
        }
    });
    if let Some(every) = watch {
        let watching = proxy.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(every);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            every.tick().await;
            loop {
                every.tick().await;
                watching.watch().await;
            }
        });
    }
    serve_each(byrle::console::listeners(
        proxy.router(),
        &listen,
        console.as_ref(),
    ))
    .await;
    std::process::ExitCode::SUCCESS
}

/// Where the proxy and the console listen, and the line that points each client at the
/// proxy reached at `base`.
fn report_listening(
    proxy: &byrle::proxy::Proxy,
    listen: &str,
    console: Option<&byrle::console::Console>,
    base: &str,
) {
    let (address, port) = listen.rsplit_once(':').unwrap_or((listen, ""));
    info!(
        server.address = address,
        server.port = port.parse::<u16>().unwrap_or_default(),
        byrle.upstreams = %proxy.upstreams(),
        byrle.artifact_origins = ?proxy.origin_policy().reachable().as_slice(),
        byrle.allowed_direct_origins = ?proxy.origin_policy().allowed_direct(),
        "byrle listening"
    );
    if let Some(console) = console {
        info!(
            byrle.console.url = %console.url,
            byrle.console.path = %console.mount,
            byrle.console.listen = console.listen.as_deref().unwrap_or(listen),
            "console listening"
        );
    }
    for registry in byrle::ecosystem::TABLE {
        let setup = &registry.setup;
        info!(
            byrle.client.name = setup.client,
            byrle.client.command = %setup.command_line(base),
            "point a client at the proxy"
        );
    }
}

/// Bind each address and serve its router until one of them stops.
async fn serve_each(servers: Vec<(String, axum::Router)>) {
    let mut serving = Vec::new();
    for (at, router) in servers {
        let listener = tokio::net::TcpListener::bind(&at)
            .await
            .unwrap_or_else(|e| panic!("cannot bind {at}: {e}"));
        let router = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
        serving.push(axum::serve(listener, router).into_future());
    }
    futures_util::future::try_join_all(serving)
        .await
        .expect("server failed");
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
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
        cli::Command::Account(command) => run_account(command).await,
        cli::Command::Token(command) => run_token(command).await,
        cli::Command::Artifact(command) => run_artifact(command).await,
        cli::Command::Refresh => run_refresh().await,
        cli::Command::Warm(args) => run_warm(args).await,
        cli::Command::Lockfile(cli::LockfileCommand::Verify(args)) => run_lockfile_verify(args),
    }
}
