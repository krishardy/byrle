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
use tracing::{info, warn};
use waharoa::cli;
use waharoa::doctor;
use waharoa::env;
use waharoa::explain;
use waharoa::identity::PackageRef;

use waharoa::audit;
use waharoa::intel::store::Intel;
use waharoa::npm;
use waharoa::policy::{Policy, check, decide, diff, enforce, packages, today};
use waharoa::proxy::Proxy;
use waharoa::record;
use waharoa::tls::{self, TrustMode};

/// Load a policy, refuse to start if it is unusable, and report what it says.
///
/// Every failure here stops the process. An operator who pointed at a policy and got a
/// running proxy would reasonably believe it was in force.
fn report_policy(path: &std::path::Path, ceiling: i64) -> std::sync::Arc<Policy> {
    let (policy, report) =
        check::load(path, today(), ceiling).unwrap_or_else(|e| panic!("{}: {e}", env::POLICY));

    info!(
        path = %path.display(),
        cooldown_days = policy.cooldown_days,
        max_cvss = policy.max_cvss,
        install_scripts = %policy.install_scripts,
        kev = %policy.kev,
        denials = policy.denials.len(),
        exceptions = policy.packages.len(),
        "policy loaded and validated"
    );

    // What is configured and what can actually fire are different things, and the gap
    // has to be said out loud rather than discovered by a package getting through.
    warn!(
        "ENFORCED: denials, install_scripts, cooldown_days. A refused version is removed \
         from the packument so the resolver picks another, and a pinned fetch of one is \
         refused"
    );
    if policy.uses_cooldown() {
        warn!(
            cooldown_days = policy.cooldown_days,
            "cooldown_days is enforced, and costs a full-packument fetch per package that \
             the client never asked for. npm publishes version timestamps only in the full \
             document, measured at 1.7x to 3.6x the abbreviated one"
        );
    }
    // An entry that does nothing is valid and worth saying out loud. `waharoa policy check`
    // and `doctor` report the same entries.
    for &index in &report.unchanged {
        warn!(
            at = packages::label(index),
            reason = %policy.packages[index].reason,
            "policy exception changes nothing, so nothing it matches is affected by it"
        );
    }
    for shadowed in report.never_wins() {
        warn!(
            at = packages::label(shadowed.index),
            "policy exception never wins: {}",
            shadowed.cover()
        );
    }

    std::sync::Arc::new(policy)
}

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

/// Ask a package manager what registry it is actually configured to use.
///
/// Its own resolved configuration, not a file this could read: the effective value comes
/// from a project `.npmrc`, then the user's, then the global one, and only the client
/// knows which won.
fn configured_registry(client: &str) -> Option<String> {
    let args: &[&str] = match client {
        "yarn" => &["config", "get", "registry"],
        _ => &["config", "get", "registry"],
    };
    let output = std::process::Command::new(client)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty() && value != "undefined").then_some(value)
}

/// Where a client keeps its cache, asked of the client itself where it will say.
///
/// bun is the exception: `bun pm cache` needs a package.json in the working directory,
/// which doctor cannot assume, so its documented default is used.
fn cache_dir(client: &str) -> Option<std::path::PathBuf> {
    let ask = |program: &str, args: &[&str]| -> Option<std::path::PathBuf> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let path = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        (!path.is_empty()).then(|| std::path::PathBuf::from(path))
    };

    match client {
        // npm's cache directory holds _cacache, and every cached response is one file
        // under its index.
        "npm" => Some(ask("npm", &["config", "get", "cache"])?.join("_cacache/index-v5")),
        "pnpm" => ask("pnpm", &["store", "path"]),
        "yarn" => ask("yarn", &["cache", "dir"]),
        "bun" => {
            let environment = env::process();
            match or_exit(environment.bun_install_cache_dir()) {
                Some(dir) => Some(dir),
                None => Some(or_exit(environment.home())?.join(".bun/install/cache")),
            }
        }
        _ => None,
    }
}

/// The client's cache when it holds something, `None` when it is empty, absent, or the
/// client is not installed.
fn warm_cache(client: &str) -> Option<std::path::PathBuf> {
    std::process::Command::new(client)
        .arg("--version")
        .output()
        .ok()?;
    let dir = cache_dir(client)?;
    (dir.is_dir() && doctor::count_files(&dir) > 0).then_some(dir)
}

/// Ask the proxy about itself at `path`. `None` when nothing answers there with the JSON
/// expected, which is itself the finding.
///
/// The status is not checked: readiness answers with its JSON on a 503 too, and anything
/// that is not a waharoa does not answer with this JSON.
///
/// Async, not `reqwest::blocking`: doctor runs inside the same tokio runtime as
/// everything else, and a blocking client builds a second runtime, which panics when it
/// is dropped in an async context.
///
/// The timeout is short because doctor is a command someone is waiting on, and a proxy
/// that takes seconds to say hello is not one that is working.
async fn fetch_own<T: serde::de::DeserializeOwned>(proxy: &str, path: &str) -> Option<T> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let response = client.get(format!("{proxy}{path}")).send().await.ok()?;
    serde_json::from_str(&response.text().await.ok()?).ok()
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
    let now = today();
    let from_date = args.from_date.map_or(now, |when| when.date(now));
    let to_date = args.to_date.map_or(now, |when| when.date(now));
    if from_date != to_date {
        eprintln!("waharoa policy diff: <FROM> as of {from_date}, <TO> as of {to_date}");
    }

    let mut loaded = Vec::new();
    for path in [&args.from, &args.to] {
        match Policy::load(path) {
            Ok(policy) => loaded.push(policy),
            Err(e) => {
                eprintln!("waharoa policy diff: {}: {e}", path.display());
                return std::process::ExitCode::from(diff::ERROR);
            }
        }
    }

    let log_path = or_exit_with(env::process().audit_log(), diff::ERROR);
    if log_path.is_none() && args.lockfile.is_empty() {
        eprintln!(
            "waharoa policy diff: set {} or pass --lockfile, for the packages to compare over",
            env::AUDIT_LOG
        );
        return std::process::ExitCode::from(diff::ERROR);
    }
    let mut listed = Vec::new();
    if let Some(log_path) = log_path {
        match std::fs::read_to_string(&log_path) {
            Ok(log) => listed.extend(audit::packages(&log)),
            Err(e) => {
                eprintln!("waharoa policy diff: {}: {e}", log_path.display());
                return std::process::ExitCode::from(diff::ERROR);
            }
        }
    }
    for path in &args.lockfile {
        match waharoa::lockfile::read(path) {
            Ok(locked) => listed.extend(locked),
            Err(e) => {
                eprintln!("waharoa policy diff: {e}");
                return std::process::ExitCode::from(diff::ERROR);
            }
        }
    }

    // The npm package versions the log and the lockfiles list, each once, with its purl.
    let mut seen = std::collections::HashSet::new();
    let versions: Vec<(String, PackageRef, String)> = listed
        .into_iter()
        .filter(|(ecosystem, _, _)| ecosystem == "npm")
        .filter(|package| seen.insert(package.clone()))
        .filter_map(|(ecosystem, name, version)| {
            let purl = format!("pkg:{ecosystem}/{name}@{version}");
            let reference = purl.parse::<PackageRef>().ok()?;
            Some((purl, reference, version))
        })
        .collect();

    // A kept snapshot when one is named, so a changed result is the policy's and not an
    // advisory published since. It is read for the packages above only.
    let store: Option<Box<dyn Intel>> = match &args.snapshot {
        Some(id) => {
            let packages = versions
                .iter()
                .map(|(_, reference, _)| intel_key(reference.key()))
                .collect();
            match kept_snapshot(id, packages) {
                Ok(kept) => Some(Box::new(kept)),
                Err(e) => {
                    eprintln!("waharoa policy diff: --snapshot {id}: {e}");
                    return std::process::ExitCode::from(diff::ERROR);
                }
            }
        }
        None => match intel_store().await {
            Ok(store) => store.map(|store| Box::new(store) as Box<dyn Intel>),
            Err(e) => {
                eprintln!("waharoa policy diff: {}: {e}", env::DATABASE_URL);
                return std::process::ExitCode::from(diff::ERROR);
            }
        },
    };
    if let Some(store) = &store
        && let Ok(Some(snapshot)) = store.snapshot().await
    {
        eprintln!("waharoa policy diff: intel snapshot {}", snapshot.digest);
    }

    let upstream = or_exit_with(env::process().upstream(), diff::ERROR);
    let client = npm::Client::new(reqwest::Client::new(), upstream);
    let needs_times = loaded.iter().any(Policy::uses_cooldown);

    let mut report = diff::Report {
        listed: versions.len(),
        ..diff::Report::default()
    };
    for (purl, reference, version) in &versions {
        // A packument that cannot be read is reported and counted, and the run goes on, so
        // one bad package does not hide the rest. The count sets the exit's error bit.
        let fetched = client
            .packument(reference.key(), record::PackumentDetail::Abbreviated)
            .await;
        let packument = match npm::fetched(fetched, "packument") {
            Ok(packument) => packument,
            Err(e) => {
                eprintln!("waharoa policy diff: {purl}: {e}");
                report.unread += 1;
                continue;
            }
        };
        let Some(package) = packument.version(version) else {
            // The registry no longer publishes it. That is a real answer for a lockfile
            // and is not a diff between two policies, so it is reported and skipped.
            eprintln!("waharoa policy diff: {purl}: no longer published");
            continue;
        };

        let times = if needs_times {
            match npm::fetched(client.publish_times(reference.key()).await, "publish times") {
                Ok(times) => Some(times),
                Err(e) => {
                    eprintln!("waharoa policy diff: {purl}: {e}");
                    report.unread += 1;
                    continue;
                }
            }
        } else {
            None
        };
        let intel = match package_intel(store.as_deref(), reference.key()).await {
            Ok(intel) => intel,
            Err(e) => {
                eprintln!("waharoa policy diff: {purl}: {e}");
                return std::process::ExitCode::from(diff::ERROR);
            }
        };
        let decided: Vec<(decide::Decision, Vec<enforce::Unenforceable>)> = loaded
            .iter()
            .zip([from_date, to_date])
            .map(|(policy, as_of)| {
                let mut facts = decide::Facts::from_record_and_times(package, times.as_ref());
                if let Some(intel) = &intel {
                    facts = facts.with_intel(intel);
                }
                (
                    decide::decide(policy, &facts, as_of),
                    enforce::unenforceable(policy, package, times.as_ref(), facts.intel),
                )
            })
            .collect();
        report.push(diff::package(
            purl,
            (&decided[0].0, &decided[0].1),
            (&decided[1].0, &decided[1].1),
        ));
    }

    print!("{}", report.render());
    let bits = report.exit_bits();
    if bits != 0 {
        eprintln!(
            "\nwaharoa policy diff: {} loosened, {} incomparable, {} tightened, {} could not be read",
            report.loosened().len(),
            report.incomparable().len(),
            report.tightened().len(),
            report.unread
        );
    }
    if report.judged_none() {
        eprintln!(
            "waharoa policy diff: none of the {} package versions listed was judged",
            report.listed
        );
    }
    std::process::ExitCode::from(bits)
}

/// `waharoa explain`.
///
/// Reads the same policy the proxy does and asks the same engine, so an answer here and a
/// refusal in the proxy cannot disagree. The packument is fetched directly from the
/// upstream registry rather than through a running proxy: explain is a question about the
/// policy, and requiring the proxy to be up to ask it would be the wrong dependency.
async fn run_explain(target: cli::Explain) -> std::process::ExitCode {
    let Some(path) = or_exit(env::process().policy()) else {
        eprintln!(
            "waharoa explain: set {} to the policy file to explain",
            env::POLICY
        );
        return std::process::ExitCode::from(2);
    };
    let policy = match Policy::load(&path) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("waharoa explain: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let store = match intel_store().await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("waharoa explain: {}: {e}", env::DATABASE_URL);
            return std::process::ExitCode::from(1);
        }
    };

    // `cli::Explain` holds `--policy` or a purl, never both and never neither.
    let Some(argument) = target.purl else {
        // A store with no snapshot answers nothing, so the checks that need one are
        // reported as unenforced rather than as settings that will fire. A snapshot records
        // the stream of every source it includes.
        let intel = match &store {
            Some(store) => match store.snapshot().await {
                Ok(Some(snapshot)) => decide::Intel::Consulted {
                    exploitation_loaded: snapshot
                        .streams
                        .iter()
                        .any(|s| s.stream == waharoa::intel::kev::SOURCE),
                },
                Ok(None) => decide::Intel::NotConsulted,
                Err(e) => {
                    eprintln!("waharoa explain: {e}");
                    return std::process::ExitCode::from(1);
                }
            },
            None => decide::Intel::NotConsulted,
        };
        print!("{}", explain::policy(&policy, intel));
        return std::process::ExitCode::SUCCESS;
    };

    let reference = match argument.parse::<PackageRef>() {
        Ok(reference) => reference,
        Err(e) => {
            eprintln!("waharoa explain: `{argument}` is not a package reference: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let upstream = or_exit(env::process().upstream());
    let client = npm::Client::new(reqwest::Client::new(), upstream);
    let fetched = client
        .packument(reference.key(), record::PackumentDetail::Abbreviated)
        .await;
    let packument = match npm::fetched(fetched, "packument") {
        Ok(packument) => packument,
        Err(e) => {
            eprintln!("waharoa explain: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let Some(package) = packument.version(reference.version()) else {
        eprintln!("waharoa explain: the registry does not publish {argument}");
        return std::process::ExitCode::from(1);
    };

    // Only when the policy asks for it, the same gate the proxy uses.
    // A cooldown that cannot be judged is an answer `explain` cannot give.
    let times = if policy.uses_cooldown() {
        match npm::fetched(client.publish_times(reference.key()).await, "publish times") {
            Ok(times) => Some(times),
            Err(e) => {
                eprintln!("waharoa explain: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        None
    };

    let store = store.as_ref().map(|store| store as &dyn Intel);
    let intel = match package_intel(store, reference.key()).await {
        Ok(intel) => intel,
        Err(e) => {
            eprintln!("waharoa explain: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let mut facts = decide::Facts::from_record_and_times(package, times.as_ref());
    if let Some(intel) = &intel {
        facts = facts.with_intel(intel);
    }
    print!(
        "{}",
        explain::decision(
            &policy,
            &facts,
            &decide::decide(&policy, &facts, today()),
            &enforce::unenforceable(&policy, package, times.as_ref(), facts.intel),
        )
    );
    std::process::ExitCode::SUCCESS
}

async fn run_doctor() -> std::process::ExitCode {
    let environment = env::process();
    let listen = or_exit(environment.listen());
    let public = or_exit(environment.public_url());
    let proxy = doctor::expected_proxy_url(public.as_deref(), &listen);

    println!("waharoa doctor");
    println!("  proxy expected at {proxy}");
    println!(
        "  checking from {}",
        std::env::current_dir().unwrap_or_default().display()
    );
    println!();

    let mut findings = Vec::new();

    // Whether the thing at the other end is there at all, and what it says it does.
    // Everything after this reads client configuration, which can be perfect while
    // nothing is listening.
    let health: Option<waharoa::proxy::Health> =
        fetch_own(&proxy, waharoa::proxy::HEALTH_PATH).await;
    findings.extend(doctor::check_proxy(health.as_ref(), &proxy));
    // A proxy that responds to the health request can still answer every package request
    // with 503 while its intel store is empty or down.
    if health.is_some() {
        let readiness: Option<waharoa::proxy::Readiness> =
            fetch_own(&proxy, waharoa::proxy::READY_PATH).await;
        findings.push(doctor::check_readiness(readiness.as_ref(), &proxy));
    }

    // The policy the proxy is configured with, judged as `waharoa policy check` judges it.
    if let Some(path) = or_exit(environment.policy()) {
        let loaded = check::load(&path, today(), or_exit(environment.expiry_ceiling_days()))
            .map(|(_, report)| report)
            .map_err(|e| e.to_string());
        findings.extend(doctor::check_policy(
            &path.display().to_string(),
            loaded.as_ref().map_err(String::as_str),
        ));
    }

    for client in ["npm", "pnpm", "yarn"] {
        findings.push(doctor::check_registry(
            client,
            configured_registry(client).as_deref(),
            &proxy,
        ));
    }

    // Lockfiles in this directory are the record of what actually happened, as opposed to
    // what is configured now.
    let mut recorded = std::collections::BTreeSet::new();
    for kind in doctor::Lockfile::ALL {
        let Ok(contents) = std::fs::read_to_string(kind.filename()) else {
            continue;
        };
        recorded.extend(doctor::recorded_origins(kind, &contents));
        findings.push(doctor::check_lockfile(kind, &contents, &proxy));
    }
    findings.push(doctor::check_public_url(public.as_deref(), &recorded));
    // Every client caches, and what a warm cache supplies never reaches the proxy. How
    // much it supplies differs, so each is reported with what was measured for it.
    for (client, bypass) in [
        ("npm", doctor::CacheBypass::Complete),
        ("pnpm", doctor::CacheBypass::Complete),
        ("bun", doctor::CacheBypass::Complete),
        ("yarn", doctor::CacheBypass::ArtifactsOnly),
    ] {
        if std::process::Command::new(client)
            .arg("--version")
            .output()
            .is_ok()
        {
            findings.push(doctor::check_cache(
                client,
                warm_cache(client).as_deref(),
                bypass,
            ));
        }
    }

    for finding in &findings {
        println!("{finding}");
    }
    println!();

    match doctor::worst(&findings) {
        doctor::Severity::Ok => {
            println!("Everything checked is pointing at the proxy.");
            std::process::ExitCode::SUCCESS
        }
        doctor::Severity::Warn => {
            println!("Installs reach the proxy, with the caveats above.");
            std::process::ExitCode::SUCCESS
        }
        doctor::Severity::Problem => {
            println!("Some installs are not going through the proxy. See above.");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The intel store at [`env::DATABASE_URL`], migrated. `None` when the variable is unset.
async fn intel_store() -> Result<Option<waharoa::intel::postgres::PgIntel>, String> {
    let Some(url) = or_exit(env::process().database_url()) else {
        return Ok(None);
    };
    let pool = sqlx::PgPool::connect(&url)
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    let intel = waharoa::intel::postgres::PgIntel::new(pool);
    intel.migrate().await.map_err(|e| e.to_string())?;
    Ok(Some(intel))
}

/// The snapshot `--snapshot` names, read from the snapshot directory without its lock.
fn kept_snapshot(
    id: &str,
    packages: std::collections::HashSet<waharoa::intel::snapshot_intel::Package>,
) -> Result<waharoa::intel::snapshot_intel::SnapshotIntel, String> {
    let Some(path) = or_exit(env::process().snapshot_dir()) else {
        return Err(format!(
            "{} is not set, so there is no kept snapshot to read",
            env::SNAPSHOT_DIR
        ));
    };
    let dir = waharoa::intel::snapshot_dir::SnapshotDir::open_to_read(&path);
    waharoa::intel::snapshot_intel::SnapshotIntel::read(&dir, id, packages)
        .map_err(|e| e.to_string())
}

/// The ecosystem and name an intel store keys a package by.
fn intel_key(key: &waharoa::identity::PackageKey) -> waharoa::intel::snapshot_intel::Package {
    (key.ecosystem().as_str().to_owned(), key.registry_name())
}

/// What the store knows about one package, for a command that has to answer with it.
///
/// `Ok(None)` is no store configured. A store that errors or holds no snapshot is an error,
/// so a command cannot print a verdict reached without intel it was told to use.
async fn package_intel(
    store: Option<&dyn Intel>,
    key: &waharoa::identity::PackageKey,
) -> Result<Option<waharoa::intel::store::PackageIntel>, String> {
    let Some(store) = store else {
        return Ok(None);
    };
    let (ecosystem, name) = intel_key(key);
    match store.package(&ecosystem, &name).await {
        Ok(Some(found)) => Ok(Some(found)),
        Ok(None) => Err("the intel store holds no snapshot; run `waharoa refresh`".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

/// `waharoa refresh`: load OSV's npm records and CISA's KEV catalogue into the intel store.
///
/// Connect, migrate, fetch, load, exit. Nothing is written unless every record in the OSV
/// bundle reads, so a broken bundle leaves the previous load in place. A catalogue that cannot
/// be fetched or read leaves the previous KEV load in place: OSV still loads, and the exit is 1.
async fn run_refresh() -> std::process::ExitCode {
    use waharoa::intel::postgres::{PgIntel, Replacement};
    use waharoa::intel::{kev, load, osv, refresh, snapshot_dir::SnapshotDir};

    let Some(url) = or_exit(env::process().database_url()) else {
        eprintln!(
            "waharoa refresh: set {} to the Postgres that holds intel",
            env::DATABASE_URL
        );
        return std::process::ExitCode::from(2);
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

    let http = match reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(http) => http,
        Err(e) => {
            eprintln!("waharoa refresh: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let bundle = match fetch(&http, refresh::NPM_BUNDLE, refresh::MAX_BUNDLE_BYTES).await {
        Ok(fetched) => fetched,
        Err(e) => {
            eprintln!("waharoa refresh: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let osv_rows = match refresh::read_bundle(&bundle.bytes) {
        Ok(read) => read,
        Err(e) => {
            eprintln!("waharoa refresh: nothing loaded: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let osv_streams = [bundle.stream(refresh::NPM_STREAM)];
    drop(bundle);

    let catalogue = match fetch(&http, kev::CATALOGUE, kev::MAX_CATALOGUE_BYTES)
        .await
        .and_then(|fetched| {
            let ids = kev::parse(&fetched.bytes).map_err(|e| e.to_string())?;
            Ok((ids, [fetched.stream(kev::SOURCE)]))
        }) {
        Ok(catalogue) => Some(catalogue),
        Err(e) => {
            eprintln!(
                "waharoa refresh: {} is not loaded, and its last load stays: {e}",
                kev::SOURCE
            );
            None
        }
    };
    let taken_at = jiff::Timestamp::now().to_string();

    // Written before the load, so a snapshot Postgres records never lacks its rows here. Rows
    // left by a load that then fails are removed by the next prune.
    let encoded = load::encode(osv::SOURCE, &osv_rows.rows);
    let exploited = catalogue
        .as_ref()
        .map(|(ids, _)| load::encode_exploited(kev::SOURCE, ids));
    if let Some(kept) = &kept {
        for rows in std::iter::once(&encoded).chain(&exploited) {
            if let Err(e) = kept.write_rows(rows) {
                eprintln!("waharoa refresh: nothing loaded: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    }

    let intel = match sqlx::PgPool::connect(&url).await {
        Ok(pool) => PgIntel::new(pool),
        Err(e) => {
            eprintln!("waharoa refresh: connecting to {}: {e}", env::DATABASE_URL);
            return std::process::ExitCode::from(1);
        }
    };
    if let Err(e) = intel.migrate().await {
        eprintln!("waharoa refresh: {e}");
        return std::process::ExitCode::from(1);
    }
    let mut sources = vec![Replacement {
        encoded: &encoded,
        rows: &osv_rows.rows,
        streams: &osv_streams,
    }];
    if let (Some(encoded), Some((_, streams))) = (&exploited, &catalogue) {
        sources.push(Replacement {
            encoded,
            rows: &[],
            streams,
        });
    }
    let loaded = match intel.replace(&sources, &taken_at).await {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("waharoa refresh: nothing loaded: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    print!("{}", osv_rows.tally);
    println!("{:32} {:>8}", "advisories written", loaded.advisories);
    println!("{:32} {:>8}", "aliases written", loaded.aliases);
    println!("{:32} {:>8}", "affected rows written", loaded.affected);
    println!("{:32} {:>8}", "ranges written", loaded.ranges);
    println!("{:32} {:>8}", "exploited CVE ids written", loaded.exploited);
    println!("snapshot {}", loaded.snapshot);
    if let Some(kept) = kept {
        match kept
            .write_snapshot(&loaded.manifest)
            .and_then(|path| Ok((path, kept.prune(limit)?)))
        {
            Ok((path, pruned)) => {
                println!("{:32} {}", "snapshot file", path.display());
                println!("{:32} {:>8}", "snapshot files removed", pruned.snapshots);
                println!("{:32} {:>8}", "rows files removed", pruned.rows);
            }
            Err(e) => {
                eprintln!("waharoa refresh: loaded, but the snapshot file is not written: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    }
    println!("took {:.1}s", started.elapsed().as_secs_f64());
    match catalogue {
        Some(_) => std::process::ExitCode::SUCCESS,
        None => std::process::ExitCode::from(1),
    }
}

/// A body `waharoa refresh` fetched, with the headers a snapshot records.
struct Fetched {
    bytes: Vec<u8>,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl Fetched {
    /// The body as a snapshot records it under `stream`.
    fn stream(&self, stream: &str) -> waharoa::intel::refresh::StreamDigest {
        waharoa::intel::refresh::StreamDigest {
            stream: stream.to_owned(),
            sha256: waharoa::intel::refresh::sha256_hex(&self.bytes),
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
        }
    }
}

/// The body at `url`, refused past `ceiling` bytes.
async fn fetch(http: &reqwest::Client, url: &str, ceiling: usize) -> Result<Fetched, String> {
    use futures_util::StreamExt;

    eprintln!("waharoa refresh: fetching {url}");
    let response = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("fetching {url}: {e}"))?;
    let header = |name: reqwest::header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let (etag, last_modified) = (
        header(reqwest::header::ETAG),
        header(reqwest::header::LAST_MODIFIED),
    );
    if let Some(declared) = response.content_length().filter(|&n| n > ceiling as u64) {
        return Err(format!(
            "{url} declares {declared} bytes, over the {ceiling} byte ceiling"
        ));
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("reading {url}: {e}"))?;
        if bytes.len() + chunk.len() > ceiling {
            return Err(format!("{url} is over the {ceiling} byte ceiling"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        bytes,
        etag,
        last_modified,
    })
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

    let listen = or_exit(environment.listen());
    let upstream = or_exit(environment.upstream());

    // reqwest 0.13 defaults to rustls with rustls-platform-verifier, so the upstream leg
    // validates against the OS trust store. The inbound leg stays plain HTTP on
    // loopback: decision #3 is reverse proxy first, CA-terminating forward proxy later.
    //
    // The `gzip` feature is off, so reqwest never decompresses behind our back and
    // bodies can be forwarded with their `Content-Encoding` intact.
    let mut builder =
        reqwest::Client::builder().user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")));
    let mut bundle_path: Option<std::path::PathBuf> = None;

    // A private registry with an internal CA, or a corporate TLS-inspecting middlebox,
    // needs roots the OS store may not carry. `env::CA_BUNDLE_EXCLUSIVE` set to 1 drops the
    // public roots entirely, which pins the upstream to whoever issued the bundle.
    if let Some(path) = or_exit(environment.ca_bundle()) {
        let exclusive = or_exit(environment.ca_bundle_exclusive());
        let mode = if exclusive {
            TrustMode::Exclusive
        } else {
            TrustMode::Merge
        };
        // Refusing to start is right: the operator asked for a trust anchor and it is not
        // there, and continuing would fall back to the platform roots without saying so.
        let certificates = tls::load_bundle(&path).unwrap_or_else(|e| panic!("{e}"));
        info!(
            bundle = %path.display(),
            certificates = certificates.len(),
            mode = ?mode,
            "upstream CA bundle loaded"
        );
        if exclusive {
            info!("public roots are NOT trusted for the upstream connection");
        }
        builder = tls::apply(builder, certificates, mode);
        bundle_path = Some(path);
    }

    let client = match bundle_path.as_deref() {
        Some(path) => tls::build(builder, path).unwrap_or_else(|e| panic!("{e}")),
        None => builder
            .build()
            .expect("failed to build upstream HTTP client"),
    };

    let max_packument_bytes = or_exit(environment.max_packument_bytes());
    let max_records = or_exit(environment.max_records());
    let max_verified = or_exit(environment.max_verified());

    // Artifact URLs are pointed at the proxy so every client in the ecosystem fetches
    // through it. Setting `env::PUBLIC_URL` pins the address written into them, which is
    // what lockfiles record; without it the request's own Host is used.
    let public_base = or_exit(environment.public_url());
    let rewrite_artifacts = or_exit(environment.rewrite_artifacts());
    if !rewrite_artifacts {
        warn!(
            "artifact URL rewriting is OFF; every client except npm will fetch artifacts \
             directly and nothing about them is observed"
        );
    } else if public_base.is_none() {
        // Measured: with a lockfile whose `resolved` names a proxy address that is no
        // longer reachable, `npm ci` fails outright. It does not fall back to the
        // registry it was given on the command line.
        warn!(
            "{} is not set, so {}. `npm ci` fails if that address later becomes unreachable. \
             Set it to a stable name.",
            env::PUBLIC_URL,
            doctor::WITHOUT_PUBLIC_URL
        );
    }

    let max_concurrent = or_exit(environment.max_concurrent_packuments());

    // Additional origins whose artifacts this proxy serves, for a registry that publishes
    // them somewhere else. The upstream and the default registry are always included.
    let served_origins = or_exit(environment.artifact_origins());

    // Origins the proxy does not serve and permits anyway, so the client fetches those
    // artifacts directly and unexamined. Without this the only escape from a refusal is
    // setting `env::REFUSE_UNSERVABLE` to 0, which trades one origin's exemption for every
    // origin's.
    let allowed_direct = or_exit(environment.allow_direct_origins());

    // What a policy refusal answers with: `env::DEFAULT_REFUSAL_STATUS` unless an operator
    // finds a client that mishandles it.
    let refusal = or_exit(environment.refusal_status());
    for status in refusal.misleading() {
        warn!(
            status,
            "a refusal configured to answer {status} will read as the proxy being broken \
             rather than as policy denying the request (plan §5 reserves 5xx for not-ready)"
        );
    }

    // Versions whose artifacts are published where this proxy cannot see them are removed
    // from the packument, so a resolver picks one that can be examined. Setting this to 0
    // forwards them instead, and the client then fetches those artifacts directly.
    let refuse_unservable = or_exit(environment.refuse_unservable());
    if !refuse_unservable {
        warn!(
            "{}=0: artifacts published off this registry are forwarded, and the client \
             fetches them without the proxy seeing them",
            env::REFUSE_UNSERVABLE
        );
    }

    // Debug builds only, and the module is not compiled into a release binary at all: an
    // env var that makes a proxy turn traffic away is a denial-of-service switch. The
    // warning is loud because a proxy answering 429 to everything looks like a bug.
    #[cfg(debug_assertions)]
    let defer_test = or_exit(environment.defer_test()).inspect(|deferral| {
        warn!(
            %deferral,
            "{} is set: matching requests are answered with a deferral and never fetched. \
             This is a measurement harness, not a feature.",
            env::DEFER_TEST
        );
    });

    // Loaded, validated and reported. Not consulted for any decision: the engine is
    // Stage 2 work in progress, and a policy that silently did nothing would be worse
    // than no policy at all, so the log says so every time.
    let policy = or_exit(environment.policy())
        .map(|path| report_policy(&path, or_exit(environment.expiry_ceiling_days())));

    let audit = or_exit(environment.audit_log()).map(|path| {
        let log = waharoa::audit::AuditLog::open(&path)
            // Refusing to start is right. An operator who asked for an audit log and
            // silently did not get one would believe decisions were being recorded.
            .unwrap_or_else(|e| panic!("{} {}: {e}", env::AUDIT_LOG, path.display()));
        info!(path = %path.display(), "audit log open");
        std::sync::Arc::new(log)
    });
    if audit.is_none() && policy.is_some() {
        warn!(
            "no audit log configured; set {} to record policy decisions",
            env::AUDIT_LOG
        );
    }

    // Refusing to start is right, as for the audit log: an operator who configured a store
    // and silently did not get one would believe known_malware was being enforced.
    let intel = intel_store()
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", env::DATABASE_URL));
    match (&intel, &policy) {
        (Some(_), Some(_)) => warn!(
            "ENFORCED: known_malware and max_cvss, from the intel store at {}, and kev once \
             the store has loaded the KEV catalogue. A store that cannot answer, or holds no \
             snapshot, is a 503 for every package",
            env::DATABASE_URL
        ),
        (None, Some(_)) => warn!(
            "NOT ENFORCED: known_malware, max_cvss and kev. {} is not set, so there is no \
             intel store to ask",
            env::DATABASE_URL
        ),
        _ => {}
    }
    let intel = intel.map(|store| {
        std::sync::Arc::new(store) as std::sync::Arc<dyn waharoa::intel::store::Intel>
    });

    let proxy = Proxy::new(client, upstream)
        .with_intel(intel)
        .with_refusal_status(refusal)
        .with_refuse_unservable(refuse_unservable)
        .with_origin_policy(
            served_origins.iter().map(String::as_str),
            allowed_direct.iter().map(String::as_str),
        )
        // Refusing to start is right: an origin the operator named and that was quietly
        // dropped would leave them believing those artifacts are covered.
        .unwrap_or_else(|e| panic!("origin configuration: {e}"))
        .with_max_concurrent_packuments(max_concurrent)
        .with_policy(policy)
        .with_audit_log(audit)
        .with_max_packument_bytes(max_packument_bytes)
        .with_max_records(max_records)
        .with_max_verified(max_verified)
        .with_artifact_rewriting(rewrite_artifacts)
        .with_public_base(public_base);
    #[cfg(debug_assertions)]
    let proxy = proxy.with_defer_test(defer_test);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));

    info!(
        listen = %listen,
        upstream = %proxy.upstream(),
        artifact_origins = ?proxy.origin_policy().reachable().as_slice(),
        allowed_direct = ?proxy.origin_policy().allowed_direct(),
        "waharoa listening"
    );
    info!("point npm at it with:  npm config set registry http://{listen}/");

    axum::serve(listener, proxy.router())
        .await
        .expect("server failed");
    std::process::ExitCode::SUCCESS
}
