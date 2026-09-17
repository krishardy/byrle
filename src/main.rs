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
use waharoa::identity::PackageRef;

use waharoa::audit;
use waharoa::ecosystem::{self, Clients};
use waharoa::intel::fetch;
use waharoa::intel::postgres;
use waharoa::intel::store::{Intel, NoIntel};
use waharoa::policy::{Policy, check, decide, diff, enforce, today};
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

    // The package versions the log and the lockfiles list, each once, with its purl.
    let mut seen = std::collections::HashSet::new();
    let versions: Vec<(String, PackageRef, String)> = listed
        .into_iter()
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
        None => match postgres::from_env(&env::process()).await {
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

    // Each package is asked of its own ecosystem's registry.
    let clients = or_exit_with(Clients::from_env(&env::process()), diff::ERROR);
    let needs_times = loaded.iter().any(Policy::uses_cooldown);

    let mut report = diff::Report {
        listed: versions.len(),
        ..diff::Report::default()
    };
    for (purl, reference, version) in &versions {
        // Metadata that cannot be read is reported and counted, and the run goes on, so
        // one bad package does not hide the rest. The count sets the exit's error bit.
        let metadata = match ecosystem::fetched(clients.metadata(reference.key()).await) {
            Ok(metadata) => metadata,
            Err(e) => {
                eprintln!("waharoa policy diff: {purl}: {e}");
                report.unread += 1;
                continue;
            }
        };
        let Some(package) = metadata.version(version) else {
            // The registry no longer publishes it. That is a real answer for a lockfile
            // and is not a diff between two policies, so it is reported and skipped.
            eprintln!("waharoa policy diff: {purl}: no longer published");
            continue;
        };

        let times = if needs_times {
            match clients.publish_times(reference.key()).await {
                Ok(times) => times,
                Err(e) => {
                    eprintln!("waharoa policy diff: {purl}: {e}");
                    report.unread += 1;
                    continue;
                }
            }
        } else {
            None
        };
        let intel =
            match package_intel(store.as_deref(), reference.key(), args.snapshot.is_none()).await {
                Ok(intel) => intel,
                // Counted with the packages that could not be read, so the others are still
                // compared and the exit's error bit is set.
                Err(NoIntel::Uncovered(e)) => {
                    eprintln!("waharoa policy diff: {purl}: {e}");
                    report.unread += 1;
                    continue;
                }
                Err(NoIntel::Failed(e)) => {
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

    let store = match postgres::from_env(&env::process()).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("waharoa explain: {}: {e}", env::DATABASE_URL);
            return std::process::ExitCode::from(1);
        }
    };

    // `cli::Explain` holds `--policy` or a purl, never both and never neither.
    let Some(argument) = target.purl else {
        // A store with no snapshot answers nothing, so the checks that need one are
        // reported as unenforced rather than as settings that will fire.
        let intel = match &store {
            Some(store) => match store.snapshot().await {
                Ok(Some(snapshot)) => decide::Intel::Consulted {
                    exploitation_loaded: snapshot.exploitation_loaded(),
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

    // The package is asked of its own ecosystem's registry.
    let clients = or_exit(Clients::from_env(&env::process()));
    let metadata = match ecosystem::fetched(clients.metadata(reference.key()).await) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("waharoa explain: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let Some(package) = metadata.version(reference.version()) else {
        eprintln!("waharoa explain: the registry does not publish {argument}");
        return std::process::ExitCode::from(1);
    };

    // Only when the policy asks for it, the same gate the proxy uses.
    // A cooldown that cannot be judged is an answer `explain` cannot give.
    let times = if policy.uses_cooldown() {
        match clients.publish_times(reference.key()).await {
            Ok(times) => times,
            Err(e) => {
                eprintln!("waharoa explain: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        None
    };

    let store = store.as_ref().map(|store| store as &dyn Intel);
    let intel = match package_intel(store, reference.key(), true).await {
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
    let as_of = today();
    print!(
        "{}",
        explain::decision(
            &policy,
            &facts,
            &decide::decide(&policy, &facts, as_of),
            &enforce::unenforceable(&policy, package, times.as_ref(), facts.intel),
            as_of,
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

    for client in doctor::clients() {
        if let Some(args) = client.registry {
            findings.push(doctor::check_registry(
                client,
                doctor::probe::configured_registry(client, args).as_deref(),
                &proxy,
            ));
        }
    }

    // Lockfiles in this directory are the record of what actually happened, as opposed to
    // what is configured now.
    let mut recorded = std::collections::BTreeSet::new();
    for (lockfile, pins) in waharoa::lockfile::pinning() {
        let Ok(contents) = std::fs::read_to_string(lockfile.name) else {
            continue;
        };
        recorded.extend(doctor::recorded_origins(pins.key, &contents));
        findings.push(doctor::check_lockfile(
            lockfile.name,
            pins,
            &contents,
            &proxy,
        ));
    }
    findings.push(doctor::check_public_url(public.as_deref(), &recorded));
    // Every client caches, and what a warm cache supplies never reaches the proxy. How
    // much it supplies differs, so each is reported with what was measured for it.
    for client in doctor::clients() {
        if std::process::Command::new(client.name)
            .arg("--version")
            .output()
            .is_ok()
        {
            let warm = or_exit(doctor::probe::warm_cache(client, &environment));
            findings.push(doctor::check_cache(client, warm.as_deref()));
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
/// See [`waharoa::intel::store::for_command`].
async fn package_intel(
    store: Option<&dyn Intel>,
    key: &waharoa::identity::PackageKey,
    streams_recorded: bool,
) -> Result<Option<waharoa::intel::store::PackageIntel>, NoIntel> {
    let (ecosystem, name) = intel_key(key);
    waharoa::intel::store::for_command(store, &ecosystem, &name, streams_recorded).await
}

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
    use waharoa::intel::providers::{datadog, osv};
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

    for tally in loaded.iter().filter_map(|l| l.tally.as_ref()) {
        print!("{tally}");
    }
    println!("{:32} {:>8}", "advisories written", written.advisories);
    println!("{:32} {:>8}", "aliases written", written.aliases);
    println!("{:32} {:>8}", "affected rows written", written.affected);
    println!("{:32} {:>8}", "ranges written", written.ranges);
    println!(
        "{:32} {:>8}",
        "exploited CVE ids written", written.exploited
    );
    let rows_of = |source: &str| {
        loaded
            .iter()
            .find(|l| l.source == source)
            .map(|l| l.payload.rows())
    };
    if let (Some(osv_rows), Some(datadog_rows)) = (rows_of(osv::SOURCE), rows_of(datadog::SOURCE)) {
        let disagreements = datadog::disagreements(osv_rows, datadog_rows);
        for disagreement in &disagreements {
            println!("{disagreement}");
        }
        println!(
            "{:32} {:>8}",
            "datadog every version, osv some",
            disagreements.len()
        );
    }
    println!("snapshot {}", written.snapshot);
    if let Some(kept) = kept {
        match kept
            .write_snapshot(&written.manifest)
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
