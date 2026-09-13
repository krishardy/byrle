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

use tracing::{info, warn};
#[cfg(debug_assertions)]
use waharoa::defer::DeferTest;
use waharoa::doctor;
use waharoa::explain;
use waharoa::identity::PackageRef;
use waharoa::http::DEFAULT_MAX_PACKUMENT_BYTES;

use waharoa::npm;
use waharoa::audit;
use waharoa::intel::store::Intel as _;
use waharoa::policy::{Policy, decide, diff, enforce, packages};
use waharoa::record;
use waharoa::proxy::{DEFAULT_MAX_CONCURRENT_PACKUMENTS, Proxy};
use waharoa::refusal::RefusalStatus;
use waharoa::store::DEFAULT_MAX_RECORDS;
use waharoa::tls::{self, TrustMode};
use waharoa::verified::DEFAULT_MAX_VERIFIED;

const USAGE: &str = "\
usage: waharoa [command]

  (no command)  run the proxy
  doctor        check whether this machine installs through the proxy
  explain       why a package is allowed or refused. `explain --policy` for the
                policy itself, `explain <purl>` for one version
  policy diff   what changes if one policy replaces another, over the packages
                the audit log has seen. Exits 1 on any loosening
  refresh       load OSV's npm malware and vulnerability records into the Postgres at
                WAHAROA_DATABASE_URL, which the proxy reads when it is set
  help          show this

Proxy configuration, all through the environment:

  WAHAROA_LISTEN                    address to listen on (127.0.0.1:8080)
  WAHAROA_UPSTREAM                  registry to forward to (https://registry.npmjs.org)
  WAHAROA_PUBLIC_URL                address written into artifact URLs, and therefore
                                    into lockfiles. Defaults to each request's own Host,
                                    which is rarely what you want.
  WAHAROA_ARTIFACT_ORIGINS          comma-separated origins this proxy also serves
  WAHAROA_ALLOW_DIRECT_ORIGINS      comma-separated origins the proxy does not serve and
                                    permits anyway, fetched directly and unexamined
  WAHAROA_REWRITE_ARTIFACTS=0       do not point artifact URLs at the proxy. pnpm and
                                    yarn then fetch artifacts without the proxy seeing
                                    them.
  WAHAROA_CA_BUNDLE                 PEM bundle for the upstream connection
  WAHAROA_CA_BUNDLE_EXCLUSIVE=1     trust only that bundle, not the public roots
  WAHAROA_MAX_PACKUMENT_BYTES       ceiling on a packument body (32 MiB)
  WAHAROA_MAX_RECORDS               packument records held in memory (50,000)
  WAHAROA_MAX_VERIFIED              verified artifact digests remembered (50,000)
  WAHAROA_DATABASE_URL              Postgres holding intel from `waharoa refresh`. With a
                                    policy, known_malware is enforced from it, and a
                                    store that cannot answer is a 503
  WAHAROA_POLICY                    path to a policy file. Loaded, validated and
                                    enforced. Startup reports which checks can fire
  WAHAROA_AUDIT_LOG                 path for one JSON line per policy decision,
                                    appended. Refuses to start if it cannot be opened
  WAHAROA_EXPIRY_CEILING_DAYS       how far ahead a `packages` entry may be dated (90)
  WAHAROA_MAX_CONCURRENT_PACKUMENTS packuments decoded at once (8)
  WAHAROA_REFUSAL_STATUS            status a refusal answers with, per client, e.g.
                                    \"default=403,npm/pnpm=451\" (default 403)
  WAHAROA_REFUSE_UNSERVABLE=0       forward versions whose artifacts this proxy cannot
                                    see, instead of removing them from the packument
";

/// The deferral knob is not compiled into a release binary, so a release binary does not
/// advertise it either.
#[cfg(debug_assertions)]
const DEBUG_USAGE: &str = "\
  WAHAROA_DEFER_TEST                DEBUG BUILDS ONLY: answer every matching request with
                                    a deferral instead of fetching, so client retry
                                    behaviour can be measured. `<status>:<seconds|none>:
                                    <packument|tarball|all>[:<seconds>]`, e.g.
                                    \"429:1:tarball\" or \"503:1:all:8\"
";
#[cfg(not(debug_assertions))]
const DEBUG_USAGE: &str = "";

/// Load a policy, refuse to start if it is unusable, and report what it says.
///
/// Every failure here stops the process. An operator who pointed at a policy and got a
/// running proxy would reasonably believe it was in force.
fn report_policy(path: &std::path::Path) -> std::sync::Arc<Policy> {
    let policy = Policy::load(path).unwrap_or_else(|e| panic!("WAHAROA_POLICY: {e}"));

    let today = jiff::Zoned::now().date();
    let ceiling = std::env::var("WAHAROA_EXPIRY_CEILING_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(packages::DEFAULT_EXPIRY_CEILING_DAYS);
    packages::check(&policy, today, ceiling).unwrap_or_else(|e| panic!("WAHAROA_POLICY: {e}"));

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
    if policy.kev == waharoa::policy::Action::Block {
        warn!(
            "NOT ENFORCED: kev. No stream the intel store loads marks an advisory exploited: \
             OSV carries no exploitation data and the CISA KEV stream is not built"
        );
    }

    // An entry that changes nothing is valid and worth saying out loud, because it is
    // almost always a selector that no longer matches what it was written for.
    let findings = packages::findings(&policy);
    for (index, entry) in policy.packages.iter().enumerate() {
        if packages::changes_nothing(&findings, index) {
            warn!(
                at = format!("packages[{index}]"),
                reason = %entry.reason,
                "policy exception changes nothing, so nothing it matches is affected by it"
            );
        }
    }

    std::sync::Arc::new(policy)
}

/// A comma-separated environment variable, blanks dropped./// A comma-separated environment variable, blanks dropped.
fn comma_separated(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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
        "bun" => match std::env::var("BUN_INSTALL_CACHE_DIR") {
            Ok(dir) if !dir.is_empty() => Some(std::path::PathBuf::from(dir)),
            _ => Some(
                std::path::PathBuf::from(std::env::var("HOME").ok()?).join(".bun/install/cache"),
            ),
        },
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

/// Ask the proxy what it is. `None` when nothing answers, which is itself the finding.
///
/// Async, not `reqwest::blocking`: doctor runs inside the same tokio runtime as
/// everything else, and a blocking client builds a second runtime, which panics when it
/// is dropped in an async context.
///
/// The timeout is short because doctor is a command someone is waiting on, and a proxy
/// that takes seconds to say hello is not one that is working.
async fn fetch_health(proxy: &str) -> Option<waharoa::proxy::Health> {
    let url = format!("{proxy}{}", waharoa::proxy::HEALTH_PATH);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    serde_json::from_str(&response.text().await.ok()?).ok()
}

/// `waharoa policy diff <from> <to> [--as-of YYYY-MM-DD]`.
///
/// The package set is the audit log, which is the only record of what this proxy has
/// actually been asked about. Lockfiles are the other source named in the plan and are not
/// read yet.
async fn run_policy(args: Vec<String>) -> std::process::ExitCode {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if positional.first().map(|s| s.as_str()) != Some("diff") || positional.len() != 3 {
        eprintln!("waharoa policy diff <from.yaml> <to.yaml> [--as-of YYYY-MM-DD]");
        return std::process::ExitCode::from(2);
    }

    let as_of = match args.iter().find_map(|a| a.strip_prefix("--as-of=")) {
        None => jiff::Timestamp::now()
            .to_zoned(jiff::tz::TimeZone::UTC)
            .date(),
        Some(raw) => match raw.parse::<jiff::civil::Date>() {
            Ok(date) => date,
            Err(e) => {
                eprintln!("waharoa policy diff: --as-of `{raw}` is not a date: {e}");
                return std::process::ExitCode::from(2);
            }
        },
    };
    if args.iter().any(|a| a.starts_with("--snapshot")) {
        // Accepting it silently would imply intel is pinned when nothing pins it.
        eprintln!(
            "waharoa policy diff: --snapshot pins nothing yet; the store holds only its latest load"
        );
        return std::process::ExitCode::from(2);
    }

    let store = match intel_store().await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("waharoa policy diff: WAHAROA_DATABASE_URL: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let mut loaded = Vec::new();
    for path in [positional[1], positional[2]] {
        match Policy::load(std::path::Path::new(path)) {
            Ok(policy) => loaded.push(policy),
            Err(e) => {
                eprintln!("waharoa policy diff: {path}: {e}");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let Some(log_path) = std::env::var("WAHAROA_AUDIT_LOG")
        .ok()
        .filter(|p| !p.is_empty())
    else {
        eprintln!("waharoa policy diff: set WAHAROA_AUDIT_LOG to the package set to compare over");
        return std::process::ExitCode::from(2);
    };
    let log = match std::fs::read_to_string(&log_path) {
        Ok(log) => log,
        Err(e) => {
            eprintln!("waharoa policy diff: {log_path}: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let upstream = env_or("WAHAROA_UPSTREAM", npm::DEFAULT_REGISTRY);
    let client = npm::Client::new(reqwest::Client::new(), upstream);
    let needs_times = loaded.iter().any(Policy::uses_cooldown);

    let mut report = diff::Report::default();
    for (ecosystem, name, version) in audit::packages(&log) {
        if ecosystem != "npm" {
            continue;
        }
        let purl = format!("pkg:{ecosystem}/{name}@{version}");
        let Ok(reference) = purl.parse::<PackageRef>() else {
            continue;
        };
        let Ok(Ok(packument)) = client
            .packument(reference.key(), record::PackumentDetail::Abbreviated)
            .await
        else {
            eprintln!("waharoa policy diff: {purl}: packument could not be read");
            continue;
        };
        let Some(package) = packument.version(&version) else {
            // The registry no longer publishes it. That is a real answer for a lockfile
            // and is not a diff between two policies, so it is reported and skipped.
            eprintln!("waharoa policy diff: {purl}: no longer published");
            continue;
        };

        let times = if needs_times {
            client.publish_times(reference.key()).await.ok().and_then(Result::ok)
        } else {
            None
        };
        let intel = match package_intel(store.as_ref(), reference.key()).await {
            Ok(intel) => intel,
            Err(e) => {
                eprintln!("waharoa policy diff: {purl}: {e}");
                return std::process::ExitCode::from(2);
            }
        };
        let decided: Vec<(decide::Decision, Vec<enforce::Unenforceable>)> = loaded
            .iter()
            .map(|policy| {
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
            &purl,
            (&decided[0].0, &decided[0].1),
            (&decided[1].0, &decided[1].1),
        ));
    }

    print!("{}", report.render());
    if report.fails_the_gate() {
        eprintln!(
            "\nwaharoa policy diff: {} loosened, {} incomparable",
            report.loosened().len(),
            report.incomparable().len()
        );
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// `waharoa explain`.
///
/// Reads the same policy the proxy does and asks the same engine, so an answer here and a
/// refusal in the proxy cannot disagree. The packument is fetched directly from the
/// upstream registry rather than through a running proxy: explain is a question about the
/// policy, and requiring the proxy to be up to ask it would be the wrong dependency.
async fn run_explain(argument: Option<String>) -> std::process::ExitCode {
    let Some(argument) = argument else {
        eprintln!("waharoa explain: needs `--policy` or a purl, for example");
        eprintln!("  waharoa explain pkg:npm/lodash@4.17.21");
        return std::process::ExitCode::from(2);
    };

    let Some(path) = std::env::var("WAHAROA_POLICY")
        .ok()
        .filter(|p| !p.is_empty())
    else {
        eprintln!("waharoa explain: set WAHAROA_POLICY to the policy file to explain");
        return std::process::ExitCode::from(2);
    };
    let policy = match Policy::load(std::path::Path::new(&path)) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("waharoa explain: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let store = match intel_store().await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("waharoa explain: WAHAROA_DATABASE_URL: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    if argument == "--policy" {
        // A store with no snapshot answers nothing, so the checks that need one are
        // reported as unenforced rather than as settings that will fire.
        let has_intel = match &store {
            Some(store) => match store.snapshot().await {
                Ok(snapshot) => snapshot.is_some(),
                Err(e) => {
                    eprintln!("waharoa explain: {e}");
                    return std::process::ExitCode::from(1);
                }
            },
            None => false,
        };
        print!("{}", explain::policy(&policy, has_intel));
        return std::process::ExitCode::SUCCESS;
    }

    let reference = match argument.parse::<PackageRef>() {
        Ok(reference) => reference,
        Err(e) => {
            eprintln!("waharoa explain: `{argument}` is not a package reference: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let upstream = env_or("WAHAROA_UPSTREAM", npm::DEFAULT_REGISTRY);
    let client = npm::Client::new(reqwest::Client::new(), upstream);
    let packument = match client
        .packument(reference.key(), record::PackumentDetail::Abbreviated)
        .await
    {
        Ok(Ok(packument)) => packument,
        Ok(Err(e)) => {
            eprintln!("waharoa explain: packument could not be read: {e}");
            return std::process::ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("waharoa explain: packument could not be fetched: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let Some(package) = packument.version(reference.version()) else {
        eprintln!(
            "waharoa explain: the registry does not publish {argument}"
        );
        return std::process::ExitCode::from(1);
    };

    // Only when the policy asks for it, the same gate the proxy uses.
    let times = if policy.uses_cooldown() {
        client.publish_times(reference.key()).await.ok().and_then(Result::ok)
    } else {
        None
    };

    let intel = match package_intel(store.as_ref(), reference.key()).await {
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
    let today = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date();
    print!(
        "{}",
        explain::decision(
            &facts,
            &decide::decide(&policy, &facts, today),
            &enforce::unenforceable(&policy, package, times.as_ref(), facts.intel),
        )
    );
    std::process::ExitCode::SUCCESS
}

async fn run_doctor() -> std::process::ExitCode {
    let listen = env_or("WAHAROA_LISTEN", "127.0.0.1:8080");
    let public = std::env::var("WAHAROA_PUBLIC_URL")
        .ok()
        .filter(|s| !s.is_empty());
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
    findings.extend(doctor::check_proxy(
        fetch_health(&proxy).await.as_ref(),
        &proxy,
    ));

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

/// The intel store at `WAHAROA_DATABASE_URL`, migrated. `None` when the variable is unset.
async fn intel_store() -> Result<Option<waharoa::intel::postgres::PgIntel>, String> {
    let Some(url) = std::env::var("WAHAROA_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        return Ok(None);
    };
    let pool = sqlx::PgPool::connect(&url)
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    let intel = waharoa::intel::postgres::PgIntel::new(pool);
    intel.migrate().await.map_err(|e| e.to_string())?;
    Ok(Some(intel))
}

/// What the store knows about one package, for a command that has to answer with it.
///
/// `Ok(None)` is no store configured. A store that errors or holds no snapshot is an error,
/// so a command cannot print a verdict reached without intel it was told to use.
async fn package_intel(
    store: Option<&waharoa::intel::postgres::PgIntel>,
    key: &waharoa::identity::PackageKey,
) -> Result<Option<waharoa::intel::store::PackageIntel>, String> {
    let Some(store) = store else {
        return Ok(None);
    };
    match store
        .package(key.ecosystem().as_str(), &key.registry_name())
        .await
    {
        Ok(Some(found)) => Ok(Some(found)),
        Ok(None) => Err("the intel store holds no snapshot; run `waharoa refresh`".to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

/// `waharoa refresh`: load OSV's npm malware records into the intel store.
///
/// Connect, migrate, fetch, load, exit. Nothing is written unless every record in the bundle
/// reads, so a broken bundle leaves the previous load in place.
async fn run_refresh() -> std::process::ExitCode {
    use waharoa::intel::{osv, postgres::PgIntel, refresh};

    let Some(url) = std::env::var("WAHAROA_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        eprintln!("waharoa refresh: set WAHAROA_DATABASE_URL to the Postgres that holds intel");
        return std::process::ExitCode::from(2);
    };
    let started = std::time::Instant::now();

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
    eprintln!("waharoa refresh: fetching {}", refresh::NPM_BUNDLE);
    let (bytes, etag, last_modified) = match fetch_bundle(&http).await {
        Ok(fetched) => fetched,
        Err(e) => {
            eprintln!("waharoa refresh: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let bundle = match refresh::read_bundle(&bytes) {
        Ok(bundle) => bundle,
        Err(e) => {
            eprintln!("waharoa refresh: nothing loaded: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    let snapshot = refresh::snapshot(
        &[refresh::StreamDigest {
            stream: refresh::NPM_STREAM.to_owned(),
            sha256: refresh::sha256_hex(&bytes),
            etag,
            last_modified,
        }],
        &jiff::Timestamp::now().to_string(),
    );
    drop(bytes);

    let intel = match sqlx::PgPool::connect(&url).await {
        Ok(pool) => PgIntel::new(pool),
        Err(e) => {
            eprintln!("waharoa refresh: connecting to WAHAROA_DATABASE_URL: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    if let Err(e) = intel.migrate().await {
        eprintln!("waharoa refresh: {e}");
        return std::process::ExitCode::from(1);
    }
    let loaded = match intel
        .replace_source(osv::SOURCE, &bundle.rows, &snapshot)
        .await
    {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("waharoa refresh: nothing loaded: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    print!("{}", bundle.tally);
    println!("{:32} {:>8}", "advisories written", loaded.advisories);
    println!("{:32} {:>8}", "aliases written", loaded.aliases);
    println!("{:32} {:>8}", "affected rows written", loaded.affected);
    println!("{:32} {:>8}", "ranges written", loaded.ranges);
    println!("snapshot {}", snapshot.id);
    println!("took {:.1}s", started.elapsed().as_secs_f64());
    std::process::ExitCode::SUCCESS
}

/// The npm bundle, with its etag and `last-modified`, refused past `MAX_BUNDLE_BYTES`.
async fn fetch_bundle(
    http: &reqwest::Client,
) -> Result<(Vec<u8>, Option<String>, Option<String>), String> {
    use futures_util::StreamExt;
    use waharoa::intel::refresh::{MAX_BUNDLE_BYTES, NPM_BUNDLE};

    let response = http
        .get(NPM_BUNDLE)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("fetching the bundle: {e}"))?;
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
    if let Some(declared) = response
        .content_length()
        .filter(|&n| n > MAX_BUNDLE_BYTES as u64)
    {
        return Err(format!(
            "the bundle declares {declared} bytes, over the {MAX_BUNDLE_BYTES} byte ceiling"
        ));
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("reading the bundle: {e}"))?;
        if body.len() + chunk.len() > MAX_BUNDLE_BYTES {
            return Err(format!(
                "the bundle is over the {MAX_BUNDLE_BYTES} byte ceiling"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, etag, last_modified))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Anything other than `doctor` is refused rather than falling through to the proxy:
    // `waharoa doctr` silently serving traffic is the wrong thing to do with a typo.
    //
    // The rule below guards against trusting argv for security decisions, argv[0] in
    // particular. This reads argv[1] to pick a subcommand, and every trust decision the
    // proxy makes comes from the environment and the packuments it reads.
    // nosemgrep: rust.lang.security.args.args
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("doctor") => return run_doctor().await,
        Some("explain") => return run_explain(std::env::args().nth(2)).await,
        // nosemgrep: rust.lang.security.args.args
        Some("policy") => return run_policy(std::env::args().skip(2).collect()).await,
        Some("refresh") => return run_refresh().await,
        Some("help" | "-h" | "--help") => {
            print!("{USAGE}{DEBUG_USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        Some(other) => {
            eprintln!("waharoa: unknown command `{other}`\n");
            eprint!("{USAGE}{DEBUG_USAGE}");
            return std::process::ExitCode::from(2);
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "waharoa=info".into()),
        )
        .with_target(false)
        .init();

    let listen = env_or("WAHAROA_LISTEN", "127.0.0.1:8080");
    let upstream = env_or("WAHAROA_UPSTREAM", npm::DEFAULT_REGISTRY);

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
    // needs roots the OS store may not carry. WAHAROA_CA_BUNDLE_EXCLUSIVE=1 drops the
    // public roots entirely, which pins the upstream to whoever issued the bundle.
    if let Some(path) = std::env::var("WAHAROA_CA_BUNDLE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        let path = std::path::PathBuf::from(path);
        let exclusive = std::env::var("WAHAROA_CA_BUNDLE_EXCLUSIVE")
            .map(|v| v == "1")
            .unwrap_or(false);
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

    let max_packument_bytes = std::env::var("WAHAROA_MAX_PACKUMENT_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_PACKUMENT_BYTES);

    let max_records = std::env::var("WAHAROA_MAX_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_RECORDS);

    let max_verified = std::env::var("WAHAROA_MAX_VERIFIED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_VERIFIED);

    // Artifact URLs are pointed at the proxy so every client in the ecosystem fetches
    // through it. Setting WAHAROA_PUBLIC_URL pins the address written into them, which
    // is what lockfiles record; without it the request's own Host is used.
    let public_base = std::env::var("WAHAROA_PUBLIC_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let rewrite_artifacts = std::env::var("WAHAROA_REWRITE_ARTIFACTS")
        .map(|v| v != "0")
        .unwrap_or(true);
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
            "WAHAROA_PUBLIC_URL is not set, so artifact URLs use whatever Host each \
             client used. That address is written into lockfiles, and `npm ci` fails if \
             it later becomes unreachable. Set it to a stable name."
        );
    }

    let max_concurrent = std::env::var("WAHAROA_MAX_CONCURRENT_PACKUMENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONCURRENT_PACKUMENTS);

    // Additional origins whose artifacts this proxy serves, for a registry that publishes
    // them somewhere else. The upstream and the default registry are always included.
    let served_origins = comma_separated("WAHAROA_ARTIFACT_ORIGINS");

    // Origins the proxy does not serve and permits anyway, so the client fetches those
    // artifacts directly and unexamined. Without this the only escape from a refusal is
    // WAHAROA_REFUSE_UNSERVABLE=0, which trades one origin's exemption for every
    // origin's.
    let allowed_direct = comma_separated("WAHAROA_ALLOW_DIRECT_ORIGINS");

    // What a policy refusal answers with. 403 unless an operator finds a client that
    // mishandles it: `WAHAROA_REFUSAL_STATUS=default=403,npm/pnpm=451`.
    let refusal =
        RefusalStatus::parse(&std::env::var("WAHAROA_REFUSAL_STATUS").unwrap_or_default())
            .unwrap_or_else(|e| panic!("WAHAROA_REFUSAL_STATUS: {e}"));
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
    let refuse_unservable = std::env::var("WAHAROA_REFUSE_UNSERVABLE")
        .map(|v| v != "0")
        .unwrap_or(true);
    if !refuse_unservable {
        warn!(
            "WAHAROA_REFUSE_UNSERVABLE=0: artifacts published off this registry are \
             forwarded, and the client fetches them without the proxy seeing them"
        );
    }

    // Debug builds only, and the module is not compiled into a release binary at all: an
    // env var that makes a proxy turn traffic away is a denial-of-service switch. The
    // warning is loud because a proxy answering 429 to everything looks like a bug.
    #[cfg(debug_assertions)]
    let defer_test = std::env::var("WAHAROA_DEFER_TEST").ok().map(|spec| {
        let deferral = DeferTest::parse(&spec).unwrap_or_else(|e| {
            panic!("WAHAROA_DEFER_TEST: {e}");
        });
        warn!(
            %deferral,
            "WAHAROA_DEFER_TEST is set: matching requests are answered with a deferral \
             and never fetched. This is a measurement harness, not a feature."
        );
        deferral
    });

    // Loaded, validated and reported. Not consulted for any decision: the engine is
    // Stage 2 work in progress, and a policy that silently did nothing would be worse
    // than no policy at all, so the log says so every time.
    let policy = std::env::var("WAHAROA_POLICY")
        .ok()
        .filter(|p| !p.is_empty())
        .map(|path| report_policy(std::path::Path::new(&path)));

    let audit = std::env::var("WAHAROA_AUDIT_LOG")
        .ok()
        .filter(|p| !p.is_empty())
        .map(|path| {
            let log = waharoa::audit::AuditLog::open(std::path::Path::new(&path))
                // Refusing to start is right. An operator who asked for an audit log and
                // silently did not get one would believe decisions were being recorded.
                .unwrap_or_else(|e| panic!("WAHAROA_AUDIT_LOG {path}: {e}"));
            info!(path = %path, "audit log open");
            std::sync::Arc::new(log)
        });
    if audit.is_none() && policy.is_some() {
        warn!("no audit log configured; set WAHAROA_AUDIT_LOG to record policy decisions");
    }

    // Refusing to start is right, as for the audit log: an operator who configured a store
    // and silently did not get one would believe known_malware was being enforced.
    let intel = intel_store()
        .await
        .unwrap_or_else(|e| panic!("WAHAROA_DATABASE_URL: {e}"));
    match (&intel, &policy) {
        (Some(_), Some(_)) => warn!(
            "ENFORCED: known_malware and max_cvss, from the intel store at \
             WAHAROA_DATABASE_URL. A store that cannot answer, or holds no snapshot, is a 503 \
             for every package"
        ),
        (None, Some(_)) => warn!(
            "NOT ENFORCED: known_malware and max_cvss. WAHAROA_DATABASE_URL is not set, so \
             there is no intel store to ask"
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
