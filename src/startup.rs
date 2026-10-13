//! Building the proxy from the environment, the way `byrle` runs it.
//!
//! Logs what each `crate::env` value means as the proxy starts. `main` keeps the logging
//! setup, the listener and the exit codes.

use crate::analysis::detector::{Command, Detector};
use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use tracing::{error, info, warn};

use crate::analysis::run::Analyser;
use crate::audit::AuditLog;
use crate::doctor;
use crate::env::{self, Env};
use crate::intel::postgres;
use crate::intel::store::Intel;
use crate::policy::{Policy, check, packages, today};
use crate::proxy::Proxy;
use crate::spool::Spool;
use crate::tls::{self, TrustMode};

/// A proxy built from the environment, and the address it is to listen on.
pub struct Started {
    pub proxy: Proxy,
    pub listen: String,
    /// The admin console, when [`env::CONSOLE_URL`] asks for one.
    pub console: Option<Arc<crate::console::Site>>,
    /// How long the watcher waits between passes. `None` when it is off.
    pub watch: Option<std::time::Duration>,
}

/// Why the proxy is not started.
#[derive(Debug)]
pub enum StartupError {
    /// A variable that does not parse.
    Env(env::EnvError),
    /// Something the operator asked for that is not there, or not usable.
    Unusable(String),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Env(e) => write!(f, "{e}"),
            Self::Unusable(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for StartupError {}

impl From<env::EnvError> for StartupError {
    fn from(e: env::EnvError) -> Self {
        Self::Env(e)
    }
}

/// The proxy the environment describes, with every warning it earns.
pub async fn proxy<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<Started, StartupError> {
    let listen = environment.listen()?;
    let console = crate::console::Console::from_env(environment, &listen)?;
    let upstreams = environment.upstreams()?;
    let client = upstream_client(environment)?;
    let max_metadata_bytes = environment.max_metadata_bytes()?;
    let max_records = environment.max_records()?;
    let max_verified = environment.max_verified()?;
    let (public_base, rewrite_artifacts) = artifact_urls(environment)?;
    let max_concurrent = environment.max_concurrent_metadata()?;
    let served_origins = environment.artifact_origins()?;
    let allowed_direct = environment.allow_direct_origins()?;
    let refusal = refusal_status(environment)?;
    report_forward_proxy(environment)?;
    let (mode, refuse_unservable) = serving(environment)?;
    #[cfg(debug_assertions)]
    let defer_test = defer_test(environment)?;
    let (policy, audit) = policy_and_audit(environment)?;
    let store = postgres::from_env(environment)
        .await
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::DATABASE_URL)))?;
    let accounts = crate::account::postgres::store(store.as_ref());
    let gate = gate(environment, accounts.clone())?;
    let console = site(environment, console, accounts)?;
    let usage = crate::usage::postgres::queue(store.as_ref());
    let (intel, analyses) = crate::analysis::postgres::stores(store, max_verified);
    if policy.is_some() {
        warn_enforcement(intel.as_deref()).await;
    }
    let spool = open_spool(environment)?;

    let analyser = Analyser::new(
        client.clone(),
        spool.clone(),
        analyses,
        environment.max_concurrent_analyses()?,
        max_verified,
    )
    .with_sources(environment.source_archives()?)
    .with_detectors(detectors(environment).await?)
    .with_virustotal(virustotal(environment)?.as_ref());
    analyser.forget_decisions_daily(environment.decision_retention_days()?);

    let proxy = Proxy::new(client)
        .with_upstreams(upstreams)
        .with_intel(intel)
        .with_spool(Some(spool))
        .with_analyser(Some(Arc::new(analyser)))
        .with_refusal_status(refusal)
        .with_refuse_unservable(refuse_unservable)
        .with_mode(mode)
        .with_origin_policy(
            served_origins.iter().map(String::as_str),
            allowed_direct.iter().map(String::as_str),
        )
        .map_err(|e| StartupError::Unusable(format!("origin configuration: {e}")))?
        .with_max_concurrent_documents(max_concurrent)
        .with_max_traffic_clients(environment.max_traffic_clients()?)
        .with_policy(policy)
        .with_audit_log(audit)
        .with_usage(usage)
        .with_max_metadata_bytes(max_metadata_bytes)
        .with_max_records(max_records)
        .with_max_verified(max_verified)
        .with_artifact_rewriting(rewrite_artifacts)
        .with_public_base(public_base)
        .with_gate(gate);
    #[cfg(debug_assertions)]
    let proxy = proxy.with_defer_test(defer_test);

    let watch = environment.watch_interval()?;
    match watch {
        Some(every) => info!(
            byrle.config.variable = %env::WATCH_INTERVAL,
            byrle.watch.interval_s = every.as_secs(),
            "watcher on: served packages are read for new versions, which are analysed before a client asks"
        ),
        None => info!(byrle.config.variable = %env::WATCH_INTERVAL, "watcher off"),
    }
    Ok(Started {
        proxy,
        listen,
        console,
        watch,
    })
}

/// How VirusTotal is asked, reported at startup. `None` when no key is set.
/// Errors when a setting does not parse.
fn virustotal<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<Option<crate::analysis::virustotal::Settings>, StartupError> {
    let settings = environment.virustotal()?;
    match &settings {
        Some(settings) => info!(
            byrle.config.variable = %env::VIRUSTOTAL_MODE,
            byrle.virustotal.mode = settings.mode.as_str(),
            byrle.virustotal.per_minute = settings.per_minute,
            byrle.virustotal.per_day = settings.per_day,
            "virustotal on: each artifact's SHA-256 is looked up, a signal that refuses nothing"
        ),
        None => info!(byrle.config.variable = %env::VIRUSTOTAL_API_KEY, "virustotal off"),
    }
    Ok(settings)
}

/// The console as it runs, logging in against `accounts` and writing logins to
/// [`env::ACCOUNT_EVENT_LOG`]. Errors when there is a console and no store, or the log
/// cannot be opened.
fn site<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
    console: Option<crate::console::Console>,
    accounts: Option<Arc<dyn crate::account::Accounts>>,
) -> Result<Option<Arc<crate::console::Site>>, StartupError> {
    let Some(console) = console else {
        return Ok(None);
    };
    let Some(accounts) = accounts else {
        return Err(StartupError::Unusable(format!(
            "{} is set, and {} is not: the console logs in against the accounts kept there",
            env::CONSOLE_URL,
            env::DATABASE_URL
        )));
    };
    let events = match environment.account_event_log()? {
        Some(path) => Some(Arc::new(
            crate::account::events::EventLog::open(&path, environment.log_retention_days()?)
                .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::ACCOUNT_EVENT_LOG)))?,
        )),
        None => None,
    };
    let login = (environment.password_hasher()?, environment.login_limits()?);
    Ok(Some(Arc::new(crate::console::Site::new(
        console, accounts, login, events,
    ))))
}

/// What checks each request's token: `accounts`, unless [`env::REQUIRE_TOKEN`] is `0`.
/// Errors when a token is required and there is no store to check it in.
fn gate<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
    accounts: Option<Arc<dyn crate::account::Accounts>>,
) -> Result<Option<crate::account::gate::Gate>, StartupError> {
    if !environment.require_token()? {
        warn!(
            byrle.config.variable = %env::REQUIRE_TOKEN,
            "proxy tokens NOT required: every request is answered, and none is tied to an account"
        );
        return Ok(None);
    }
    let Some(accounts) = accounts else {
        return Err(StartupError::Unusable(format!(
            "{} is not set, and the accounts and tokens a request is checked in are kept there. \
             Set it, or set {}=0 to answer requests without a token",
            env::DATABASE_URL,
            env::REQUIRE_TOKEN
        )));
    };
    info!(
        byrle.config.variable = %env::REQUIRE_TOKEN,
        byrle.config.guide = doctor::TOKEN_GUIDE,
        "proxy tokens required: a request without one is answered 401. The guide lists \
         where each client puts its token"
    );
    Ok(Some(crate::account::gate::Gate::new(accounts)))
}

/// The client every upstream request goes through, trusting [`env::CA_BUNDLE`]'s roots
/// too when it is set, or only them with [`env::CA_BUNDLE_EXCLUSIVE`].
/// Errors when a bundle is named and does not load.
fn upstream_client<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<reqwest::Client, StartupError> {
    let builder = crate::http::client_builder(crate::http::READ_TIMEOUT);
    let Some(path) = environment.ca_bundle()? else {
        return Ok(builder.build().expect("the TLS backend initialises"));
    };
    let exclusive = environment.ca_bundle_exclusive()?;
    let mode = if exclusive {
        TrustMode::Exclusive
    } else {
        TrustMode::Merge
    };
    let certificates =
        tls::load_bundle(&path).map_err(|e| StartupError::Unusable(e.to_string()))?;
    info!(
        byrle.tls.bundle = %path.display(),
        byrle.tls.certificates = certificates.len(),
        byrle.tls.mode = ?mode,
        "upstream CA bundle loaded"
    );
    if exclusive {
        info!("public roots are NOT trusted for the upstream connection");
    }
    tls::build(tls::apply(builder, certificates, mode), &path)
        .map_err(|e| StartupError::Unusable(e.to_string()))
}

/// [`env::PROXY_URL`] and whether artifact URLs are rewritten, warning when rewriting is
/// off or the address lockfiles record is left to each request's `Host`.
fn artifact_urls<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<(Option<String>, bool), StartupError> {
    let public_base = environment.proxy_url()?;
    let rewrite_artifacts = environment.rewrite_artifacts()?;
    if !rewrite_artifacts {
        warn!(
            "artifact URL rewriting is OFF; every client except npm will fetch artifacts \
             directly and nothing about them is observed"
        );
    } else if public_base.is_none() {
        warn!(
            byrle.config.variable = %env::PROXY_URL,
            byrle.config.consequence = doctor::WITHOUT_PROXY_URL,
            "not set: `npm ci` fails if the address lockfiles record later becomes \
             unreachable. Set it to a stable name"
        );
    }
    Ok((public_base, rewrite_artifacts))
}

/// What a refusal answers with, warning about each 5xx, which reads as not-ready.
fn refusal_status<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<crate::refusal::RefusalStatus, StartupError> {
    let refusal = environment.refusal_status()?;
    for status in refusal.misleading() {
        warn!(
            byrle.refusal.status = status,
            "a refusal configured with this status will read as the proxy being broken rather \
             than as policy denying the request (plan §5 reserves 5xx for not-ready)"
        );
    }
    Ok(refusal)
}

/// Log the forward proxy upstream traffic goes through, when one is set.
fn report_forward_proxy<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<(), StartupError> {
    if let Some([https, http, direct]) = environment.upstream_proxy()?.fields() {
        info!(
            byrle.forward_proxy.https = https,
            byrle.forward_proxy.http = http,
            byrle.forward_proxy.direct = direct,
            "upstream traffic goes through a forward proxy"
        );
    }
    Ok(())
}

/// [`env::MODE`] and [`env::REFUSE_UNSERVABLE`], warning when either serves what enforce
/// mode would refuse.
fn serving<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<(crate::refusal::Mode, bool), StartupError> {
    let mode = environment.mode()?;
    if mode == crate::refusal::Mode::Observe {
        warn!(
            byrle.config.variable = %env::MODE,
            "observe mode: what the policy refuses is served and logged, not refused"
        );
    }
    let refuse_unservable = environment.refuse_unservable()?;
    if !refuse_unservable {
        warn!(
            byrle.config.variable = %env::REFUSE_UNSERVABLE,
            "set to 0: artifacts published off this registry are forwarded, and the client \
             fetches them without the proxy seeing them"
        );
    }
    Ok((mode, refuse_unservable))
}

/// [`env::DEFER_TEST`], warned about when set: it turns traffic away.
#[cfg(debug_assertions)]
fn defer_test<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<Option<crate::defer::DeferTest>, StartupError> {
    Ok(environment.defer_test()?.inspect(|deferral| {
        warn!(
            byrle.defer_test = %deferral,
            byrle.config.variable = %env::DEFER_TEST,
            "set: matching requests are answered with a deferral and never fetched. This is \
             a measurement harness, not a feature"
        );
    }))
}

/// A policy and an audit log, each when configured.
type PolicyAndAudit = (Option<Arc<Policy>>, Option<Arc<AuditLog>>);

/// The policy and the audit log, each when configured, warning when a policy has no log
/// to record its decisions in.
/// Errors when either is named and cannot be loaded or opened.
fn policy_and_audit<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<PolicyAndAudit, StartupError> {
    let policy = match environment.policy()? {
        Some(path) => Some(report_policy(&path, environment.expiry_ceiling_days()?)?),
        None => None,
    };
    let audit = match environment.audit_log()? {
        Some(path) => {
            let log = AuditLog::open(&path, environment.log_retention_days()?).map_err(|e| {
                StartupError::Unusable(format!("{} {}: {e}", env::AUDIT_LOG, path.display()))
            })?;
            info!(byrle.audit.path = %path.display(), "audit log open");
            Some(Arc::new(log))
        }
        None => None,
    };
    if audit.is_none() && policy.is_some() {
        warn!(
            byrle.config.variable = %env::AUDIT_LOG,
            "no audit log configured, so policy decisions are not recorded"
        );
    }
    Ok((policy, audit))
}

/// Warn which checks a policy enforces from `store`, and each gap in its snapshot; or,
/// with no store, which it cannot enforce.
async fn warn_enforcement(store: Option<&dyn Intel>) {
    let Some(store) = store else {
        warn!(
            byrle.config.variable = %env::DATABASE_URL,
            "NOT ENFORCED: known_malware, max_cvss and kev. The variable is not set, so there \
             is no intel store to ask"
        );
        return;
    };
    warn!(
        byrle.config.variable = %env::DATABASE_URL,
        "ENFORCED: known_malware and max_cvss, from the intel store, and kev once the store \
         has loaded the KEV catalogue. A store that cannot answer, or holds no snapshot, is a \
         503 for every package"
    );
    let Ok(Some(snapshot)) = store.snapshot().await else {
        return;
    };
    for gap in snapshot.gaps() {
        warn!(byrle.intel.gap = %gap, "the intel snapshot has a gap");
    }
}

/// The detectors [`env::DETECTORS`] names, each asked its version.
/// Errors when one does not parse or does not print a version.
async fn detectors<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<Vec<Arc<dyn Detector>>, StartupError> {
    let mut configured: Vec<Arc<dyn Detector>> = Vec::new();
    for spec in environment.detectors()? {
        let detector = Command::configured(&spec, environment.detector_environment())
            .await
            .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::DETECTORS)))?;
        info!(
            byrle.detector = detector.name(),
            byrle.detector.version = detector.version(),
            "detector on: each version served is run through it, and each rule it fires is a signal"
        );
        configured.push(Arc::new(detector));
    }
    Ok(configured)
}

/// The spool at [`env::SPOOL_DIR`], with the files an earlier process left removed.
/// Errors when it cannot be opened, or another proxy holds it.
fn open_spool<L: Fn(&str) -> Option<OsString>>(
    environment: &Env<L>,
) -> Result<Arc<Spool>, StartupError> {
    let spool_dir = environment.spool_dir()?;
    let (spool, swept) = Spool::open(&spool_dir, environment.max_artifact_bytes()?)
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::SPOOL_DIR)))?;
    info!(
        byrle.spool.path = %spool_dir.display(),
        byrle.spool.ceiling = spool.ceiling(),
        byrle.spool.swept = swept,
        "spool open; files left by an earlier process removed"
    );
    Ok(Arc::new(spool))
}

/// Load a policy and report what it says.
///
/// An unusable policy is [`StartupError::Unusable`]: an operator who pointed at a policy
/// and got a running proxy would reasonably believe it was in force.
fn report_policy(path: &Path, ceiling: i64) -> Result<Arc<Policy>, StartupError> {
    let (policy, report) = check::load(path, today(), ceiling)
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::POLICY)))?;

    info!(
        byrle.policy.path = %path.display(),
        byrle.policy.cooldown_days = policy.cooldown_days,
        byrle.policy.max_cvss = policy.max_cvss,
        byrle.policy.install_scripts = %policy.install_scripts,
        byrle.policy.kev = %policy.kev,
        byrle.policy.provenance = %policy.provenance,
        byrle.policy.denials = policy.denials.len(),
        byrle.policy.exceptions = policy.packages.len(),
        "policy loaded and validated"
    );

    warn!(
        "ENFORCED: denials, install_scripts, cooldown_days, yanked, deprecated, provenance. \
         A refused version is removed from the metadata document so the resolver picks \
         another, and a pinned fetch of one is refused"
    );
    warn_cooldown_costs(&policy);
    warn_idle_exceptions(&policy, &report);
    Ok(Arc::new(policy))
}

/// Warn, per ecosystem, what a cooldown costs, when the policy sets one.
fn warn_cooldown_costs(policy: &Policy) {
    if !policy.uses_cooldown() {
        return;
    }
    for (ecosystem, cost) in crate::ecosystem::cooldown_costs() {
        warn!(
            byrle.policy.cooldown_days = policy.cooldown_days,
            byrle.ecosystem = %ecosystem,
            byrle.cooldown.cost = cost,
            "cooldown_days is enforced, at a cost to the ecosystem"
        );
    }
}

/// Warn about each exception that changes nothing or never wins, as `byrle policy check`
/// and `doctor` report them.
fn warn_idle_exceptions(policy: &Policy, report: &check::Report) {
    for &index in &report.unchanged {
        warn!(
            byrle.policy.exception = packages::label(index),
            byrle.policy.exception_reason = %policy.packages[index].reason,
            "policy exception changes nothing, so nothing it matches is affected by it"
        );
    }
    for shadowed in report.never_wins() {
        warn!(
            byrle.policy.exception = packages::label(shadowed.index),
            byrle.policy.exception_cover = %shadowed.cover(),
            "policy exception never wins"
        );
    }
}

/// Load the policy file again and put it in force, as startup loads it. The policy in
/// force stays when the file is unset, unreadable or refused.
pub fn reload_policy<L: Fn(&str) -> Option<OsString>>(proxy: &Proxy, environment: &Env<L>) {
    let digest = |policy: Option<&Policy>| policy.map_or("none".to_owned(), |p| p.digest.clone());
    let old = digest(proxy.policy().as_deref());
    let loaded = match environment.policy() {
        Err(e) => Err(e.to_string()),
        Ok(None) => Err(format!("{} is not set", env::POLICY)),
        Ok(Some(path)) => environment
            .expiry_ceiling_days()
            .map_err(|e| e.to_string())
            .and_then(|ceiling| report_policy(&path, ceiling).map_err(|e| e.to_string())),
    };
    match loaded {
        Ok(policy) => {
            let new = digest(Some(&policy));
            proxy.replace_policy(Some(policy));
            info!(byrle.policy.digest_from = %old, byrle.policy.digest_to = %new, "policy reloaded");
        }
        Err(why) => {
            error!(byrle.policy.digest = %old, byrle.reason = %why, "policy not reloaded")
        }
    }
}

/// [`reload_policy`] on each `SIGHUP`, for as long as the process runs.
#[cfg(unix)]
pub fn reload_on_hangup<L: Fn(&str) -> Option<OsString> + Send + Sync>(
    proxy: Proxy,
    environment: Env<L>,
) -> impl std::future::Future<Output = ()> + Send {
    let hangups = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("SIGHUP can be listened for");
    let hangups = futures_util::stream::unfold(hangups, |mut hangups| async move {
        hangups.recv().await.map(|()| ((), hangups))
    });
    reload_each(proxy, environment, hangups)
}

/// [`reload_policy`] once for each item of `hangups`, until it ends.
async fn reload_each<L: Fn(&str) -> Option<OsString>>(
    proxy: Proxy,
    environment: Env<L>,
    hangups: impl futures_util::Stream<Item = ()>,
) {
    use futures_util::StreamExt as _;
    let mut hangups = std::pin::pin!(hangups);
    while hangups.next().await.is_some() {
        reload_policy(&proxy, &environment);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ecosystem::{npm, pypi};
    use crate::env::testing::with;
    use crate::identity::Ecosystem;
    use std::path::PathBuf;

    /// `pairs`, with a spool directory of this test's own. Tests run at once in one
    /// process, and a second proxy on one directory is refused.
    fn spooled(
        label: &str,
        pairs: &[(env::Var, &str)],
    ) -> (PathBuf, Env<impl Fn(&str) -> Option<OsString> + use<>>) {
        let dir = crate::util::test_support::tempdir(label);
        let mut pairs = pairs.to_vec();
        let spool = dir.join("spool").display().to_string();
        pairs.push((env::SPOOL_DIR, &spool));
        if !pairs.iter().any(|(var, _)| *var == env::REQUIRE_TOKEN) {
            pairs.push((env::REQUIRE_TOKEN, "0"));
        }
        (dir, with(&pairs))
    }

    /// The failure `pairs` starts with. `Proxy` is not `Debug`, so `expect_err` cannot
    /// print the proxy it did build.
    async fn refused(pairs: &[(env::Var, &str)]) -> StartupError {
        match proxy(&with(pairs)).await {
            Err(e) => e,
            Ok(_) => panic!("{pairs:?} should not start a proxy"),
        }
    }

    /// Tokens are required by default, and without a database there is nowhere to check
    /// them, so the proxy is not started. With the requirement off it starts, and says so.
    #[tokio::test]
    async fn a_required_token_needs_the_database_and_turning_it_off_is_logged() {
        let StartupError::Unusable(why) = refused(&[]).await else {
            panic!("no database is unusable, not a parse error");
        };
        assert!(why.starts_with(env::DATABASE_URL.name), "{why}");
        assert!(why.contains(&format!("{}=0", env::REQUIRE_TOKEN)), "{why}");

        let (started, logs) = logged("startup-no-token", &[]).await;
        assert!(started);
        assert!(logs.contains("proxy tokens NOT required"), "{logs}");
    }

    /// With a store, a required token gives a gate.
    #[test]
    fn a_required_token_with_a_store_is_a_gate() {
        let accounts = std::sync::Arc::new(crate::account::InMemory::new("2026-10-11T00:00:00Z"));
        assert!(gate(&with(&[]), Some(accounts)).unwrap().is_some());
    }

    /// A console whose path the proxy's contains on their shared listener is not started,
    /// and one with a path of its own is.
    #[tokio::test]
    async fn the_console_starts_only_at_a_path_of_its_own() {
        let StartupError::Env(e) = refused(&[(env::CONSOLE_URL, "https://h/admin/")]).await else {
            panic!("a console inside the proxy's path is an environment error");
        };
        assert_eq!(e.var, env::CONSOLE_URL.name);

        let (dir, environment) = spooled(
            "startup-console",
            &[
                (env::PROXY_URL, "https://h/registry/"),
                (env::CONSOLE_URL, "https://h/admin/"),
            ],
        );
        let Err(StartupError::Unusable(why)) = proxy(&environment).await else {
            panic!("a console without a database is not started");
        };
        assert!(why.contains(env::DATABASE_URL.name), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With a store, the console runs, writing logins to the event log when one is set and
    /// refusing to start when it cannot be opened.
    #[test]
    fn the_console_runs_against_the_account_store() {
        let accounts: Arc<dyn crate::account::Accounts> =
            Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let vars = [
            (env::PROXY_URL, "https://h/registry/"),
            (env::CONSOLE_URL, "https://h/admin/"),
        ];
        let console = || crate::console::Console::from_env(&with(&vars), "127.0.0.1:8080").unwrap();
        assert!(
            site(&with(&vars), None, Some(accounts.clone()))
                .unwrap()
                .is_none()
        );
        let running = site(&with(&vars), console(), Some(accounts.clone())).unwrap();
        assert_eq!(running.unwrap().console.mount.to_string(), "/admin/");

        let dir = crate::util::test_support::tempdir("startup-console-events");
        let log = dir.join("events.log");
        let logged = with(&[(env::ACCOUNT_EVENT_LOG, log.to_str().unwrap())]);
        assert!(
            site(&logged, console(), Some(accounts.clone()))
                .unwrap()
                .is_some()
        );
        assert!(log.exists());
        let missing = dir.join("no-such-dir").join("events.log");
        let unopened = with(&[(env::ACCOUNT_EVENT_LOG, missing.to_str().unwrap())]);
        let Err(StartupError::Unusable(why)) = site(&unopened, console(), Some(accounts.clone()))
        else {
            panic!("an event log that cannot be opened stops the console");
        };
        assert!(why.starts_with(env::ACCOUNT_EVENT_LOG.name), "{why}");
        let bad_days = with(&[
            (env::ACCOUNT_EVENT_LOG, log.to_str().unwrap()),
            (env::LOG_RETENTION_DAYS, "0"),
        ]);
        assert!(site(&bad_days, console(), Some(accounts.clone())).is_err());
        let unreadable = crate::env::testing::with_unreadable(&[], env::ACCOUNT_EVENT_LOG);
        let Err(StartupError::Env(e)) = site(&unreadable, console(), Some(accounts)) else {
            panic!("an unreadable event log path is an environment error");
        };
        assert_eq!(e.var, env::ACCOUNT_EVENT_LOG.name);
        for bad in [(env::ARGON2_PASSES, "0"), (env::SESSION_HOURS, "0")] {
            let accounts: Arc<dyn crate::account::Accounts> =
                Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
            let Err(StartupError::Env(e)) = site(&with(&[bad]), console(), Some(accounts)) else {
                panic!("{} out of range stops the console", bad.0);
            };
            assert_eq!(e.var, bad.0.name);
        }
    }

    /// What `proxy` logs at INFO and above for `pairs`, with whether it started.
    async fn logged(label: &str, pairs: &[(env::Var, &str)]) -> (bool, String) {
        let (dir, environment) = spooled(label, pairs);
        let (guard, buf) = crate::util::test_support::capture(tracing::Level::INFO);
        let started = proxy(&environment).await.is_ok();
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
        (started, crate::util::test_support::text(&buf))
    }

    /// Each setting that reduces what the proxy examines is warned about at startup.
    #[tokio::test]
    async fn each_setting_that_reduces_what_is_examined_is_warned_about() {
        let dir = crate::util::test_support::tempdir("startup-warned-policy");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\n").unwrap();
        let mut pairs = vec![
            (env::REWRITE_ARTIFACTS, "0"),
            (env::REFUSAL_STATUS, "default=503"),
            (env::MODE, "observe"),
            (env::REFUSE_UNSERVABLE, "0"),
            (env::POLICY, policy.to_str().unwrap()),
        ];
        if cfg!(debug_assertions) {
            pairs.push((env::DEFER_TEST, "503:1:all"));
        }
        let (started, log) = logged("startup-warned", &pairs).await;

        assert!(started, "{log}");
        let mut expected = vec![
            "artifact URL rewriting is OFF",
            "a refusal configured with this status will read as the proxy being broken",
            "observe mode: what the policy refuses is served and logged",
            "set to 0: artifacts published off this registry are forwarded",
            "policy loaded and validated",
            "cooldown_days is enforced, at a cost to the ecosystem",
            "no audit log configured, so policy decisions are not recorded",
            "NOT ENFORCED: known_malware, max_cvss and kev",
        ];
        if cfg!(debug_assertions) {
            expected.push("set: matching requests are answered with a deferral");
        }
        for message in expected {
            assert!(log.contains(message), "{message}: {log}");
        }
        assert!(
            !log.contains("not set: `npm ci` fails"),
            "rewriting is off: {log}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With rewriting on and no public URL, the lockfile address is warned about; a
    /// forward proxy is named.
    #[tokio::test]
    async fn an_unset_proxy_url_is_warned_about_and_a_forward_proxy_named() {
        let (started, log) = logged(
            "startup-public",
            &[(env::FORWARD_HTTPS, "http://egress.example:3128")],
        )
        .await;

        assert!(started, "{log}");
        assert!(log.contains("not set: `npm ci` fails"), "{log}");
        assert!(
            log.contains("upstream traffic goes through a forward proxy"),
            "{log}"
        );
        assert!(!log.contains("observe mode"), "{log}");
        assert!(
            !log.contains("no audit log configured"),
            "no policy, no log: {log}"
        );
    }

    /// Each exception that changes nothing or never wins is warned about, and a policy with
    /// no cooldown has no cost to warn about.
    #[tokio::test]
    async fn a_policy_names_its_idle_exceptions_and_a_cooldown_its_cost() {
        let dead = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/policy-check/dead.yaml"
        );
        let (started, log) = logged("startup-dead", &[(env::POLICY, dead)]).await;
        assert!(started, "{log}");
        assert!(
            log.contains("policy exception changes nothing")
                && log.contains("byrle.policy.exception=\"packages[6]\""),
            "{log}"
        );
        assert!(
            log.contains("policy exception never wins")
                && log.contains("byrle.policy.exception=\"packages[0]\""),
            "{log}"
        );

        let dir = crate::util::test_support::tempdir("startup-no-cooldown");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\ncooldown_days: 0\n").unwrap();
        let (started, log) = logged(
            "startup-no-cooldown-run",
            &[(env::POLICY, policy.to_str().unwrap())],
        )
        .await;
        assert!(started, "{log}");
        assert!(!log.contains("cooldown_days is enforced"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CA bundle is loaded and said to be, and one that does not load refuses the start.
    #[tokio::test]
    async fn a_ca_bundle_is_loaded_or_refuses_the_start() {
        let bundle = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/test-ca.pem"
        );
        let (started, log) = logged(
            "startup-bundle",
            &[(env::CA_BUNDLE, bundle), (env::CA_BUNDLE_EXCLUSIVE, "1")],
        )
        .await;
        assert!(started, "{log}");
        assert!(log.contains("upstream CA bundle loaded"), "{log}");
        assert!(log.contains("public roots are NOT trusted"), "{log}");

        let (started, log) = logged(
            "startup-bundle-missing",
            &[(env::CA_BUNDLE, "/nonexistent/ca.pem")],
        )
        .await;
        assert!(!started, "{log}");
    }

    /// A detector that says its version is on and said to be, and one that does not refuses
    /// the start, naming the variable.
    #[tokio::test]
    async fn a_detector_is_asked_its_version_or_refuses_the_start() {
        let fake = crate::analysis::detector::tests::installed(
            "startup-detector",
            crate::analysis::detector::tests::FAKE,
        );
        let spec = format!(
            "fake={} scan {{ecosystem}} {{name}} {{version}}",
            fake.display()
        );
        let (started, log) = logged("startup-detector-on", &[(env::DETECTORS, &spec)]).await;
        assert!(started, "{log}");
        assert!(
            log.contains("detector on") && log.contains("byrle.detector.version=\"9.9.9\""),
            "{log}"
        );

        let (dir, environment) = spooled(
            "startup-detector-bad",
            &[(env::DETECTORS, "fake=/nonexistent/detector")],
        );
        let Err(StartupError::Unusable(why)) = proxy(&environment).await.map(drop) else {
            panic!("a detector that does not start refuses the start");
        };
        assert!(why.starts_with(&env::DETECTORS.to_string()), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_watch_interval_of_0_turns_the_watcher_off() {
        let (started, log) = logged("startup-watch-off", &[(env::WATCH_INTERVAL, "0")]).await;
        assert!(started, "{log}");
        assert!(log.contains("watcher off"), "{log}");
    }

    /// VirusTotal is said to be off without a key, and on with its mode and limits with one;
    /// a setting that does not parse refuses the start. The key is never logged.
    #[tokio::test]
    async fn virustotal_is_reported_on_or_off_at_startup() {
        let (started, log) = logged("startup-vt-off", &[]).await;
        assert!(started && log.contains("virustotal off"), "{log}");
        let (started, log) = logged(
            "startup-vt-on",
            &[
                (env::VIRUSTOTAL_API_KEY, "not-a-real-key"),
                (env::VIRUSTOTAL_MODE, "upload"),
            ],
        )
        .await;
        assert!(started && log.contains("virustotal on"), "{log}");
        assert!(log.contains("byrle.virustotal.mode=\"upload\""), "{log}");
        assert!(!log.contains("not-a-real-key"), "{log}");
        let (started, log) = logged(
            "startup-vt-bad",
            &[
                (env::VIRUSTOTAL_API_KEY, "k"),
                (env::VIRUSTOTAL_PER_DAY, "0"),
            ],
        )
        .await;
        assert!(!started, "{log}");
    }

    /// An audit log is opened and said to be, and one that cannot be opened refuses the
    /// start, naming the variable.
    #[tokio::test]
    async fn an_audit_log_is_opened_or_refuses_the_start() {
        let dir = crate::util::test_support::tempdir("startup-audit-file");
        let log_path = dir.join("audit.jsonl");
        let (started, log) = logged(
            "startup-audit",
            &[(env::AUDIT_LOG, log_path.to_str().unwrap())],
        )
        .await;
        assert!(started, "{log}");
        assert!(log.contains("audit log open"), "{log}");

        let (dir2, environment) = spooled(
            "startup-audit-bad",
            &[(env::AUDIT_LOG, "/nonexistent/dir/audit.jsonl")],
        );
        let Err(StartupError::Unusable(why)) = proxy(&environment).await.map(drop) else {
            panic!("an audit log that cannot be opened refuses the start");
        };
        assert!(why.starts_with(&env::AUDIT_LOG.to_string()), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// Nothing set but the spool directory: npm's and PyPI's own registries, no policy, no
    /// store, and artifact URLs pointed at the proxy.
    #[tokio::test]
    async fn an_empty_environment_starts_the_default_proxy() {
        let (dir, environment) = spooled("startup-empty", &[]);
        let started = proxy(&environment).await.expect("the defaults are usable");
        assert_eq!(started.listen, env::DEFAULT_LISTEN);
        assert!(started.console.is_none());
        assert_eq!(
            started.watch,
            Some(std::time::Duration::from_secs(
                env::DEFAULT_WATCH_INTERVAL_SECONDS
            ))
        );
        assert_eq!(
            started.proxy.upstreams().get(Ecosystem::Npm),
            npm::DEFAULT_REGISTRY
        );
        assert_eq!(started.proxy.upstreams().get(Ecosystem::PyPI), pypi::INDEX);
        let health = started.proxy.health();
        assert_eq!(
            health.upstreams.get("npm").map(String::as_str),
            Some(npm::DEFAULT_REGISTRY)
        );
        assert!(health.rewrite_artifacts);
        assert!(health.refuse_unservable);
        assert_eq!(health.mode, "enforce");
        assert_eq!(health.public_base, None);
        assert_eq!(health.allowed_direct_origins, Vec::<String>::new());
        assert_eq!(
            health.spool_dir,
            Some(dir.join("spool").display().to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A spool directory another proxy holds refuses the start, naming the variable.
    #[tokio::test]
    async fn a_spool_directory_in_use_refuses_the_start() {
        let (dir, environment) = spooled("startup-spool", &[]);
        let _first = proxy(&environment).await.expect("the first proxy starts");
        let second = match proxy(&environment).await {
            Err(e) => e,
            Ok(_) => panic!("a second proxy on one spool directory should not start"),
        };
        assert!(matches!(second, StartupError::Unusable(_)), "{second}");
        assert!(
            second
                .to_string()
                .starts_with(&format!("{}: ", env::SPOOL_DIR)),
            "{second}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const DENY: &str = "version: 1\ncooldown_days: 0\n\
                        denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n";
    const ALLOW: &str = "version: 1\ncooldown_days: 0\n";

    fn digest(proxy: &Proxy) -> Option<String> {
        proxy.policy().map(|p| p.digest.clone())
    }

    /// A policy that loads replaces the one in force. One that does not, or no file,
    /// leaves it in force.
    #[test]
    fn a_reload_keeps_the_policy_in_force_unless_the_new_one_loads() {
        let dir = crate::util::test_support::tempdir("startup-reload");
        let path = dir.join("policy.yaml");
        let file = path.to_str().unwrap();
        let proxy = Proxy::new(reqwest::Client::new())
            .with_policy(Some(Arc::new(Policy::parse(DENY).unwrap())));

        std::fs::write(&path, ALLOW).unwrap();
        reload_policy(&proxy, &with(&[(env::POLICY, file)]));
        assert_eq!(digest(&proxy), Some(crate::policy::digest_of(ALLOW)));

        std::fs::write(&path, "version: 2\n").unwrap();
        reload_policy(&proxy, &with(&[(env::POLICY, file)]));
        assert_eq!(
            digest(&proxy),
            Some(crate::policy::digest_of(ALLOW)),
            "refused"
        );

        reload_policy(&proxy, &with(&[]));
        assert_eq!(
            digest(&proxy),
            Some(crate::policy::digest_of(ALLOW)),
            "no file"
        );

        reload_policy(
            &proxy,
            &with(&[(env::POLICY, file), (env::EXPIRY_CEILING_DAYS, "x")]),
        );
        assert_eq!(
            digest(&proxy),
            Some(crate::policy::digest_of(ALLOW)),
            "bad ceiling"
        );

        let unreadable = crate::env::testing::with_unreadable(&[], env::POLICY);
        reload_policy(&proxy, &unreadable);
        assert_eq!(
            digest(&proxy),
            Some(crate::policy::digest_of(ALLOW)),
            "not UTF-8"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `SIGHUP` reloads the policy. The handler is registered before the signal is sent,
    /// so the signal never reaches the default action of ending the test process.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hangup_reloads_the_policy() {
        let _registered =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        let dir = crate::util::test_support::tempdir("startup-hangup");
        let path = dir.join("policy.yaml");
        std::fs::write(&path, ALLOW).unwrap();
        let proxy = Proxy::new(reqwest::Client::new())
            .with_policy(Some(Arc::new(Policy::parse(DENY).unwrap())));
        tokio::spawn(reload_on_hangup(
            proxy.clone(),
            with(&[(env::POLICY, path.to_str().unwrap())]),
        ));

        let reloaded = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while digest(&proxy) != Some(crate::policy::digest_of(ALLOW)) {
                std::process::Command::new("kill")
                    .args(["-HUP", &std::process::id().to_string()])
                    .status()
                    .unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(reloaded.is_ok(), "SIGHUP did not reload the policy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each configured value reaches the proxy it builds.
    #[tokio::test]
    async fn the_environment_reaches_the_proxy() {
        let (dir, environment) = spooled(
            "startup-values",
            &[
                (env::LISTEN, "127.0.0.1:9999"),
                (env::UPSTREAM_NPM, "https://npm.mirror.example/"),
                (env::UPSTREAM_PYPI, "https://pypi.mirror.example/simple"),
                (env::PROXY_URL, "http://byrle.corp.example"),
                (env::ARTIFACT_ORIGINS, "https://cdn.example"),
                (env::ALLOW_DIRECT_ORIGINS, "https://direct.example"),
                (env::REWRITE_ARTIFACTS, "0"),
                (env::REFUSE_UNSERVABLE, "0"),
                (env::MODE, "observe"),
            ],
        );
        let started = proxy(&environment).await.expect("every value is usable");
        assert_eq!(started.listen, "127.0.0.1:9999");
        let health = started.proxy.health();
        assert_eq!(
            health.upstreams.get("npm").map(String::as_str),
            Some("https://npm.mirror.example")
        );
        assert_eq!(
            health.upstreams.get("pypi").map(String::as_str),
            Some("https://pypi.mirror.example/simple")
        );
        assert_eq!(
            started.proxy.upstreams().get(Ecosystem::PyPI),
            "https://pypi.mirror.example/simple"
        );
        assert_eq!(
            health.public_base.as_deref(),
            Some("http://byrle.corp.example")
        );
        assert!(!health.rewrite_artifacts && !health.refuse_unservable);
        assert_eq!(health.mode, "observe");
        assert!(
            health
                .served_origins
                .contains(&"https://cdn.example".to_owned()),
            "{:?}",
            health.served_origins
        );
        assert_eq!(health.allowed_direct_origins, ["https://direct.example"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A variable that does not parse is `Env`, which exits 2. Something the operator
    /// asked for and that is not there is `Unusable`, which refuses to start.
    #[tokio::test]
    async fn a_bad_value_and_a_missing_file_are_different_failures() {
        let bad = refused(&[(env::UPSTREAM_NPM, "nope")]).await;
        assert!(matches!(bad, StartupError::Env(_)), "{bad}");
        assert!(bad.to_string().contains("nope"), "{bad}");

        let absent = refused(&[(env::POLICY, "/nonexistent/policy.yaml")]).await;
        assert!(matches!(absent, StartupError::Unusable(_)), "{absent}");
        assert!(absent.to_string().contains("policy.yaml"), "{absent}");
    }

    /// A policy that loads is in force, and its exceptions are reported.
    #[tokio::test]
    async fn a_policy_that_loads_is_carried_into_the_proxy() {
        let path = crate::util::test_support::tempdir("startup-policy-file").join("policy.yaml");
        std::fs::write(&path, "version: 1\ncooldown_days: 7\n").expect("writes");
        let (dir, environment) = spooled(
            "startup-policy",
            &[(env::POLICY, &path.display().to_string())],
        );
        let started = proxy(&environment).await.expect("the policy loads");
        let policy = started.proxy.policy().expect("the proxy holds it");
        assert_eq!(policy.cooldown_days, 7);
        assert!(policy.uses_cooldown());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&path);
    }

    /// Each variable `proxy` reads refuses the start when its value is not UTF-8, naming
    /// the variable, before anything after it is read.
    #[tokio::test]
    async fn each_variable_that_cannot_be_read_refuses_the_start() {
        use crate::env::testing::with_unreadable;
        let dir = crate::util::test_support::tempdir("startup-unreadable");
        let spool = dir.join("spool").display().to_string();
        let bundle = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/test-ca.pem"
        );
        let mut cases = vec![
            (vec![], env::LISTEN),
            (vec![], env::UPSTREAM_NPM),
            (vec![], env::CA_BUNDLE),
            (vec![(env::CA_BUNDLE, bundle)], env::CA_BUNDLE_EXCLUSIVE),
            (vec![], env::MAX_METADATA_BYTES),
            (vec![], env::MAX_RECORDS),
            (vec![], env::MAX_VERIFIED),
            (vec![], env::PROXY_URL),
            (vec![], env::REWRITE_ARTIFACTS),
            (vec![], env::MAX_CONCURRENT_METADATA),
            (vec![], env::ARTIFACT_ORIGINS),
            (vec![], env::ALLOW_DIRECT_ORIGINS),
            (vec![], env::REFUSAL_STATUS),
            (vec![], env::FORWARD_HTTPS),
            (vec![], env::MODE),
            (vec![], env::REFUSE_UNSERVABLE),
            (vec![], env::POLICY),
            (vec![], env::AUDIT_LOG),
            (vec![], env::SPOOL_DIR),
            (vec![(env::SPOOL_DIR, &spool)], env::MAX_ARTIFACT_BYTES),
            (vec![(env::SPOOL_DIR, &spool)], env::MAX_CONCURRENT_ANALYSES),
            (vec![(env::SPOOL_DIR, &spool)], env::SOURCE_ARCHIVES),
            (vec![(env::SPOOL_DIR, &spool)], env::DETECTORS),
            (vec![(env::SPOOL_DIR, &spool)], env::MAX_TRAFFIC_CLIENTS),
            (vec![(env::SPOOL_DIR, &spool)], env::WATCH_INTERVAL),
        ];
        if cfg!(debug_assertions) {
            cases.push((vec![], env::DEFER_TEST));
        }
        let policy = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/policy-check/dead.yaml"
        );
        cases.push((vec![(env::POLICY, policy)], env::EXPIRY_CEILING_DAYS));
        cases.push((
            vec![(env::AUDIT_LOG, "audit.jsonl")],
            env::LOG_RETENTION_DAYS,
        ));
        cases.push((vec![(env::SPOOL_DIR, &spool)], env::DECISION_RETENTION_DAYS));
        cases.push((vec![], env::REQUIRE_TOKEN));
        for (mut pairs, var) in cases {
            if var != env::REQUIRE_TOKEN {
                pairs.push((env::REQUIRE_TOKEN, "0"));
            }
            let Err(StartupError::Env(e)) = proxy(&with_unreadable(&pairs, var)).await.map(drop)
            else {
                panic!("{} refuses the start", var.name);
            };
            assert_eq!(e.var, var.name);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unusable bundle, database URL or artifact origin refuses the start.
    /// A bundle that merges with the public roots starts one.
    #[tokio::test]
    async fn an_unusable_bundle_database_or_origin_refuses_the_start() {
        let refused = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/refused.pem"
        );
        for (label, pairs) in [
            ("startup-bundle-refused", vec![(env::CA_BUNDLE, refused)]),
            ("startup-database", vec![(env::DATABASE_URL, "not a url")]),
            ("startup-origin", vec![(env::ARTIFACT_ORIGINS, "not a url")]),
        ] {
            let (spool, environment) = spooled(label, &pairs);
            let Err(StartupError::Unusable(_)) = proxy(&environment).await.map(drop) else {
                panic!("{label} refuses the start");
            };
            let _ = std::fs::remove_dir_all(&spool);
        }
        let bundle = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/test-ca.pem"
        );
        let (started, log) = logged("startup-bundle-merged", &[(env::CA_BUNDLE, bundle)]).await;
        assert!(started, "{log}");
        assert!(!log.contains("public roots are NOT trusted"), "{log}");
    }

    /// With a store, what a policy enforces is said, then each gap in its snapshot. A store
    /// with no snapshot, or one that errors, has no gaps to say.
    #[tokio::test]
    async fn a_store_says_what_it_enforces_and_its_gaps() {
        use crate::intel::store::testing::{FixedIntel, knowing_nothing};
        let said = async |store: FixedIntel| {
            let (guard, buf) = crate::util::test_support::capture(tracing::Level::WARN);
            warn_enforcement(Some(&store)).await;
            drop(guard);
            crate::util::test_support::text(&buf)
        };
        let loaded = said(knowing_nothing()).await;
        assert!(
            loaded.contains("ENFORCED: known_malware and max_cvss"),
            "{loaded}"
        );
        assert!(loaded.contains("the intel snapshot has a gap"), "{loaded}");
        for store in [FixedIntel(Ok(None)), FixedIntel(Err(()))] {
            let log = said(store).await;
            assert!(
                log.contains("ENFORCED: known_malware and max_cvss"),
                "{log}"
            );
            assert!(!log.contains("gap"), "{log}");
        }
    }

    /// Each hangup reloads the policy, and the loop ends with the stream.
    #[tokio::test]
    async fn each_hangup_reloads_until_the_stream_ends() {
        let dir = crate::util::test_support::tempdir("startup-reload-each");
        let path = dir.join("policy.yaml");
        std::fs::write(&path, ALLOW).unwrap();
        let proxy = Proxy::new(reqwest::Client::new());
        let environment = with(&[(env::POLICY, path.to_str().unwrap())]);
        reload_each(proxy.clone(), environment, futures_util::stream::iter([()])).await;
        assert_eq!(digest(&proxy), Some(crate::policy::digest_of(ALLOW)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With rewriting on and a public URL set, there is nothing to warn about.
    #[test]
    fn a_proxy_url_with_rewriting_on_is_not_warned_about() {
        let (base, rewriting) =
            artifact_urls(&with(&[(env::PROXY_URL, "http://proxy.internal")])).expect("reads");
        assert_eq!(base.as_deref(), Some("http://proxy.internal"));
        assert!(rewriting);
    }
}
