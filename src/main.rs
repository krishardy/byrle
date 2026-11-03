//! The `byrle` binary: parse the command line, run the command, print what it returns.
//!
//! Each command is in the library. `make smoke-npm`, `make smoke-python` and
//! `make smoke-npm-clients` cover this file by running real clients through the proxy.

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

/// mimalloc rather than the C library's allocator, on glibc as on the static musl release.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Unwrap the variable or exit 2 if it can't be unwrapped
fn unwrap_or_exit_2<T>(result: Result<T, env::EnvError>) -> T {
    unwrap_or_exit(result, 2)
}

/// Unwrap the variable or exit with a given code if it can't be unwrapped
fn unwrap_or_exit<T>(result: Result<T, env::EnvError>, code: u8) -> T {
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
    match remote("policy check") {
        Err(code) => return code,
        Ok(Some(remote)) => {
            let policy = match std::fs::read_to_string(&args.path) {
                Ok(policy) => policy,
                Err(e) => {
                    eprintln!("byrle policy check: {}: {e}", args.path.display());
                    return std::process::ExitCode::from(2);
                }
            };
            let asked = byrle::remote::CheckAsked {
                policy,
                as_of: args.as_of.map(|day| day.to_string()),
                strict: args.strict,
                fetch: args.fetch,
            };
            let printed = remote
                .post(
                    "policy check",
                    byrle::console::routes::POLICY_CHECK_PATH,
                    &asked,
                )
                .await;
            return std::process::ExitCode::from(printed.print());
        }
        Ok(None) => {}
    }
    let as_of = args.as_of.unwrap_or_else(today);
    let ceiling = unwrap_or_exit_2(env::process().expiry_ceiling_days());
    let loaded = check::load(&args.path, as_of, ceiling);
    let clients = args
        .fetch
        .then(|| unwrap_or_exit_2(byrle::ecosystem::Clients::from_env(&env::process())));
    let label = args.path.display().to_string();
    let answer = check::answer(loaded, &label, as_of, (args.strict, clients.as_ref())).await;
    for note in &answer.notes {
        eprintln!("byrle policy check: {note}");
    }
    print!("{}", answer.report);
    std::process::ExitCode::from(answer.code)
}

/// `byrle policy diff <candidate>` asked of the deployment `remote`, whose policy in force
/// is `<FROM>`.
async fn remote_policy_diff(
    remote: &byrle::remote::Remote,
    args: &cli::Diff,
) -> std::process::ExitCode {
    let refused = |why: String| {
        eprintln!("byrle policy diff: {why}");
        std::process::ExitCode::from(byrle::policy::diff::ERROR)
    };
    if args.to.is_some() {
        return refused(format!(
            "with {} set, the policy in force is the deployment's: pass the candidate alone",
            env::REMOTE_URL
        ));
    }
    if args.snapshot.is_some() {
        return refused("--snapshot is not asked of a deployment".to_owned());
    }
    let policy = match std::fs::read_to_string(&args.from) {
        Ok(policy) => policy,
        Err(e) => return refused(format!("{}: {e}", args.from.display())),
    };
    let mut versions = Vec::new();
    for path in &args.lockfile {
        match byrle::lockfile::listed(path) {
            Ok(listed) => versions.extend(listed.iter().map(byrle::remote::Sent::of)),
            Err(e) => return refused(e.to_string()),
        }
    }
    let asked = byrle::remote::DiffAsked {
        policy,
        from_date: args.from_date.map(|when| when.to_string()),
        to_date: args.to_date.map(|when| when.to_string()),
        versions,
    };
    let printed = remote
        .post(
            "policy diff",
            byrle::console::routes::POLICY_DIFF_PATH,
            &asked,
        )
        .await;
    std::process::ExitCode::from(printed.print())
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
    match remote("policy diff") {
        Err(code) => return code,
        Ok(Some(remote)) => return remote_policy_diff(&remote, &args).await,
        Ok(None) => {}
    }
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
/// The deployment [`env::REMOTE_URL`] names, or the code to exit with when it is set and
/// cannot be asked.
fn remote(command: &str) -> Result<Option<byrle::remote::Remote>, std::process::ExitCode> {
    byrle::remote::Remote::from_env(&env::process()).map_err(|e| {
        eprintln!("byrle {command}: {e}");
        std::process::ExitCode::from(2)
    })
}

async fn run_explain(target: cli::Explain) -> std::process::ExitCode {
    match remote("explain") {
        Err(code) => return code,
        Ok(Some(remote)) => {
            let query: Vec<(&str, String)> = target
                .purl
                .iter()
                .map(|purl| ("purl", purl.clone()))
                .collect();
            let printed = remote
                .get("explain", byrle::console::routes::EXPLAIN_PATH, &query)
                .await;
            return std::process::ExitCode::from(printed.print());
        }
        Ok(None) => {}
    }
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

/// `byrle status`: prints [`byrle::status::report`] for this machine's upstreams and intel
/// snapshot, with no snapshot when the intel store cannot be read. When
/// [`env::REMOTE_URL`] is set, it asks that deployment instead.
async fn run_status() -> std::process::ExitCode {
    match remote("status") {
        Err(code) => return code,
        Ok(Some(remote)) => {
            let printed = remote
                .get("status", byrle::console::routes::ECOSYSTEMS_PATH, &[])
                .await;
            return std::process::ExitCode::from(printed.print());
        }
        Ok(None) => {}
    }
    let environment = env::process();
    let upstreams = unwrap_or_exit_2(environment.upstreams());
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

/// `byrle artifact show|export`: prints the latest decision on each artifact named, or every
/// decision in a date range, as JSON Lines. It reads the analysis store at
/// [`env::DATABASE_URL`], or asks the deployment at [`env::REMOTE_URL`] when it is set.
async fn run_artifact(command: cli::ArtifactCommand) -> std::process::ExitCode {
    use byrle::analysis::decision::command;
    match remote("artifact") {
        Err(code) => return code,
        Ok(Some(remote)) => {
            let printed = match &command {
                cli::ArtifactCommand::Show(args) => {
                    let query = [("artifact", args.artifact.to_string())];
                    remote
                        .get("artifact", byrle::console::routes::ARTIFACT_PATH, &query)
                        .await
                }
                cli::ArtifactCommand::Export(args) => {
                    let query: Vec<(&str, String)> =
                        [("since", &args.since), ("until", &args.until)]
                            .into_iter()
                            .filter_map(|(name, day)| Some((name, day.clone()?)))
                            .collect();
                    remote
                        .get("artifact", byrle::console::routes::ARTIFACTS_PATH, &query)
                        .await
                }
            };
            return std::process::ExitCode::from(printed.print());
        }
        Ok(None) => {}
    }
    let store = match postgres::required(&env::process()).await {
        Ok(intel) => byrle::analysis::postgres::PgAnalyses::new(intel.pool().clone()),
        Err(refused) => {
            eprintln!("byrle artifact: {refused}");
            return std::process::ExitCode::from(refused.code);
        }
    };
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    std::process::ExitCode::from(match command {
        cli::ArtifactCommand::Show(args) => {
            command::show(&store, &args.artifact, &mut out, &mut err).await
        }
        cli::ArtifactCommand::Export(args) => {
            command::export(&store, args.since, args.until, &mut out, &mut err).await
        }
    })
}

/// `byrle account create|disable|password|link|list`: changes or lists the accounts in the
/// store at [`env::DATABASE_URL`]. `password` reads the password from the first line of
/// stdin. Each change is appended to [`env::ACCOUNT_EVENT_LOG`] when it is set.
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
        cli::AccountCommand::Link(args) => {
            command::link_oidc(&store, &args.name, &args.issuer, &args.subject).await
        }
        cli::AccountCommand::Password(args) => {
            match byrle::account::password::read(&mut std::io::stdin().lock()) {
                Ok(password) => {
                    let environment = env::process();
                    let settings = environment
                        .password_min_chars()
                        .and_then(|min| environment.password_hasher().map(|h| (min, h)));
                    match settings {
                        Ok((min_chars, hasher)) => {
                            let policy = (min_chars, &hasher);
                            command::set_password(&store, &args.name, &password, policy).await
                        }
                        Err(e) => {
                            eprintln!("byrle account password: {e}");
                            return std::process::ExitCode::from(2);
                        }
                    }
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

/// `byrle token create|revoke|list`: changes or lists the API tokens in the store at
/// [`env::DATABASE_URL`]. `create` prints the new token on stdout, the only time it is
/// shown. Each change is appended to [`env::ACCOUNT_EVENT_LOG`] when it is set.
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

/// `byrle intel history`: prints the newest `--limit` entries of the ingestion history, one
/// per stream each `byrle refresh` loaded or failed to load, newest first. It reads the intel
/// store at [`env::DATABASE_URL`], or asks the deployment at [`env::REMOTE_URL`] when set.
async fn run_intel_history(args: cli::History) -> std::process::ExitCode {
    match remote("intel history") {
        Err(code) => return code,
        Ok(Some(remote)) => {
            let query = [("limit", args.limit.to_string())];
            let printed = remote
                .get(
                    "intel history",
                    byrle::console::routes::INTEL_HISTORY_PATH,
                    &query,
                )
                .await;
            return std::process::ExitCode::from(printed.print());
        }
        Ok(None) => {}
    }
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

/// `byrle refresh`: load every stream into the intel store, and append what each stream
/// did to the ingestion history.
async fn run_refresh() -> std::process::ExitCode {
    let notice = |line: &str| eprintln!("byrle refresh: {line}");
    let run = refresh::run(&env::process(), &notice).await;
    print!("{}", run.report);
    std::process::ExitCode::from(run.code)
}

/// `byrle daemon`: serves the proxy, and the console when [`env::CONSOLE_URL`] is set. It
/// reloads the policy on `SIGHUP` and runs the watcher every [`env::WATCH_INTERVAL`] unless 0.
/// A variable that does not parse exits 2. A failed startup or bind panics.
async fn run_daemon() -> std::process::ExitCode {
    let environment = env::process();
    byrle::allocator::set_purge_delay(unwrap_or_exit_2(environment.allocator_purge_delay_ms()));
    let filter = unwrap_or_exit_2(environment.log_filter());
    let filter = tracing_subscriber::EnvFilter::try_new(&filter).unwrap_or_else(|e| {
        eprintln!("byrle: {}: `{filter}` {e}", env::LOG_FILTER);
        std::process::exit(2)
    });
    let format = unwrap_or_exit_2(environment.log_format());
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
        console.as_ref().map(|site| &site.console),
        &unwrap_or_exit_2(environment.proxy_base()),
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
