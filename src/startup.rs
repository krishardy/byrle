//! Building the proxy from the environment, the way `waharoa` runs it.
//!
//! Every value comes from `crate::env`, and what each one means is said here as the proxy
//! starts: what is enforced, what is not, and what an unset variable leaves off. `main`
//! keeps the logging setup, the listener and the exit codes.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{error, info, warn};

use crate::analysis::postgres::PgAnalyses;
use crate::analysis::run::Analyser;
use crate::analysis::store::{Analyses, InProcess};
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
    let upstreams = environment.upstreams()?;

    // reqwest 0.13 defaults to rustls with rustls-platform-verifier, so the upstream leg
    // validates against the OS trust store. The inbound leg stays plain HTTP on
    // loopback: decision #3 is reverse proxy first, CA-terminating forward proxy later.
    //
    // The `gzip` feature is off, so reqwest never decompresses behind our back and
    // bodies can be forwarded with their `Content-Encoding` intact.
    //
    // A connect timeout and a read timeout, and no total one: an upstream that stops
    // sending ends the request it holds, and a slow download that keeps arriving does not.
    let mut builder = crate::http::client_builder(crate::http::READ_TIMEOUT);
    let mut bundle_path: Option<PathBuf> = None;

    // A private registry with an internal CA, or a corporate TLS-inspecting middlebox,
    // needs roots the OS store may not carry. `env::CA_BUNDLE_EXCLUSIVE` set to 1 drops the
    // public roots entirely, which pins the upstream to whoever issued the bundle.
    if let Some(path) = environment.ca_bundle()? {
        let exclusive = environment.ca_bundle_exclusive()?;
        let mode = if exclusive {
            TrustMode::Exclusive
        } else {
            TrustMode::Merge
        };
        // Refusing to start is right: the operator asked for a trust anchor and it is not
        // there, and continuing would fall back to the platform roots without saying so.
        let certificates =
            tls::load_bundle(&path).map_err(|e| StartupError::Unusable(e.to_string()))?;
        info!(
            waharoa.tls.bundle = %path.display(),
            waharoa.tls.certificates = certificates.len(),
            waharoa.tls.mode = ?mode,
            "upstream CA bundle loaded"
        );
        if exclusive {
            info!("public roots are NOT trusted for the upstream connection");
        }
        builder = tls::apply(builder, certificates, mode);
        bundle_path = Some(path);
    }

    let client = match bundle_path.as_deref() {
        Some(path) => {
            tls::build(builder, path).map_err(|e| StartupError::Unusable(e.to_string()))?
        }
        None => builder
            .build()
            .map_err(|e| StartupError::Unusable(format!("upstream HTTP client: {e}")))?,
    };

    let max_metadata_bytes = environment.max_metadata_bytes()?;
    let max_records = environment.max_records()?;
    let max_verified = environment.max_verified()?;

    // Artifact URLs are pointed at the proxy so every client in the ecosystem fetches
    // through it. Setting `env::PUBLIC_URL` pins the address written into them, which is
    // what lockfiles record; without it the request's own Host is used.
    let public_base = environment.public_url()?;
    let rewrite_artifacts = environment.rewrite_artifacts()?;
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
            waharoa.config.variable = %env::PUBLIC_URL,
            waharoa.config.consequence = doctor::WITHOUT_PUBLIC_URL,
            "not set: `npm ci` fails if the address lockfiles record later becomes \
             unreachable. Set it to a stable name"
        );
    }

    let max_concurrent = environment.max_concurrent_metadata()?;

    // Additional origins whose artifacts this proxy serves, for a registry that publishes
    // them somewhere else. The upstream and the default registry are always included.
    let served_origins = environment.artifact_origins()?;

    // Origins the proxy does not serve and permits anyway, so the client fetches those
    // artifacts directly and unexamined. Without this the only escape from a refusal is
    // setting `env::REFUSE_UNSERVABLE` to 0, which trades one origin's exemption for every
    // origin's.
    let allowed_direct = environment.allow_direct_origins()?;

    // What a policy refusal answers with: `env::DEFAULT_REFUSAL_STATUS` unless an operator
    // finds a client that mishandles it.
    let refusal = environment.refusal_status()?;
    for status in refusal.misleading() {
        warn!(
            waharoa.refusal.status = status,
            "a refusal configured with this status will read as the proxy being broken rather \
             than as policy denying the request (plan §5 reserves 5xx for not-ready)"
        );
    }

    // Versions whose artifacts are published where this proxy cannot see them are removed
    // from the packument, so a resolver picks one that can be examined. Setting this to 0
    // forwards them instead, and the client then fetches those artifacts directly.
    if let Some([https, http, direct]) = environment.upstream_proxy()?.fields() {
        info!(
            waharoa.forward_proxy.https = https,
            waharoa.forward_proxy.http = http,
            waharoa.forward_proxy.direct = direct,
            "upstream traffic goes through a forward proxy"
        );
    }
    let mode = environment.mode()?;
    if mode == crate::refusal::Mode::Observe {
        warn!(
            waharoa.config.variable = %env::MODE,
            "observe mode: what the policy refuses is served and logged, not refused"
        );
    }
    let refuse_unservable = environment.refuse_unservable()?;
    if !refuse_unservable {
        warn!(
            waharoa.config.variable = %env::REFUSE_UNSERVABLE,
            "set to 0: artifacts published off this registry are forwarded, and the client \
             fetches them without the proxy seeing them"
        );
    }

    // Debug builds only, and the module is not compiled into a release binary at all: an
    // env var that makes a proxy turn traffic away is a denial-of-service switch. The
    // warning is loud because a proxy answering 429 to everything looks like a bug.
    #[cfg(debug_assertions)]
    let defer_test = environment.defer_test()?.inspect(|deferral| {
        warn!(
            waharoa.defer_test = %deferral,
            waharoa.config.variable = %env::DEFER_TEST,
            "set: matching requests are answered with a deferral and never fetched. This is \
             a measurement harness, not a feature"
        );
    });

    // Loaded, validated and reported. Not consulted for any decision: the engine is
    // Stage 2 work in progress, and a policy that silently did nothing would be worse
    // than no policy at all, so the log says so every time.
    let policy = match environment.policy()? {
        Some(path) => Some(report_policy(&path, environment.expiry_ceiling_days()?)?),
        None => None,
    };

    // An operator who asked for an audit log and silently did not get one would believe
    // decisions were being recorded.
    let audit = match environment.audit_log()? {
        Some(path) => {
            let log = AuditLog::open(&path).map_err(|e| {
                StartupError::Unusable(format!("{} {}: {e}", env::AUDIT_LOG, path.display()))
            })?;
            info!(waharoa.audit.path = %path.display(), "audit log open");
            Some(Arc::new(log))
        }
        None => None,
    };
    if audit.is_none() && policy.is_some() {
        warn!(
            waharoa.config.variable = %env::AUDIT_LOG,
            "no audit log configured, so policy decisions are not recorded"
        );
    }

    // Refusing to start is right, as for the audit log: an operator who configured a store
    // and silently did not get one would believe known_malware was being enforced.
    let intel = postgres::from_env(environment)
        .await
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::DATABASE_URL)))?;
    match (&intel, &policy) {
        (Some(store), Some(_)) => {
            warn!(
                waharoa.config.variable = %env::DATABASE_URL,
                "ENFORCED: known_malware and max_cvss, from the intel store, and kev once the \
                 store has loaded the KEV catalogue. A store that cannot answer, or holds no \
                 snapshot, is a 503 for every package"
            );
            // The snapshot loaded now. `waharoa doctor` reports the same for a later one.
            if let Ok(Some(snapshot)) = store.snapshot().await {
                for gap in snapshot.gaps() {
                    warn!(waharoa.intel.gap = %gap, "the intel snapshot has a gap");
                }
            }
        }
        (None, Some(_)) => warn!(
            waharoa.config.variable = %env::DATABASE_URL,
            "NOT ENFORCED: known_malware, max_cvss and kev. The variable is not set, so there \
             is no intel store to ask"
        ),
        _ => {}
    }

    // What analysing an artifact found is kept in the intel store's database when there is
    // one, and otherwise in this process only, so a restart analyses each artifact again.
    let analyses: Arc<dyn Analyses> = match &intel {
        Some(store) => Arc::new(PgAnalyses::new(store.pool().clone())),
        None => Arc::new(InProcess::new(max_verified)),
    };
    let intel = intel.map(|store| Arc::new(store) as Arc<dyn Intel>);

    // Refusing to start is right: a second proxy on the same directory would remove the
    // first one's files, and a directory that cannot be written is a proxy that cannot
    // analyse. Every spool file present now was left by a process that ended.
    let spool_dir = environment.spool_dir()?;
    let (spool, swept) = Spool::open(&spool_dir, environment.max_artifact_bytes()?)
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::SPOOL_DIR)))?;
    info!(
        waharoa.spool.path = %spool_dir.display(),
        waharoa.spool.ceiling = spool.ceiling(),
        waharoa.spool.swept = swept,
        "spool open; files left by an earlier process removed"
    );
    let spool = Arc::new(spool);

    let proxy = Proxy::new(client.clone())
        .with_upstreams(upstreams)
        .with_intel(intel)
        .with_spool(Some(spool.clone()))
        .with_analyser(Some(Arc::new(Analyser::new(
            client.clone(),
            spool,
            analyses,
            environment.max_concurrent_analyses()?,
            max_verified,
        ))))
        .with_refusal_status(refusal)
        .with_refuse_unservable(refuse_unservable)
        .with_mode(mode)
        .with_origin_policy(
            served_origins.iter().map(String::as_str),
            allowed_direct.iter().map(String::as_str),
        )
        // Refusing to start is right: an origin the operator named and that was quietly
        // dropped would leave them believing those artifacts are covered.
        .map_err(|e| StartupError::Unusable(format!("origin configuration: {e}")))?
        .with_max_concurrent_documents(max_concurrent)
        .with_max_traffic_clients(environment.max_traffic_clients()?)
        .with_policy(policy)
        .with_audit_log(audit)
        .with_max_metadata_bytes(max_metadata_bytes)
        .with_max_records(max_records)
        .with_max_verified(max_verified)
        .with_artifact_rewriting(rewrite_artifacts)
        .with_public_base(public_base);
    #[cfg(debug_assertions)]
    let proxy = proxy.with_defer_test(defer_test);

    Ok(Started { proxy, listen })
}

/// Load a policy and report what it says.
///
/// An unusable policy is [`StartupError::Unusable`]: an operator who pointed at a policy
/// and got a running proxy would reasonably believe it was in force.
fn report_policy(path: &Path, ceiling: i64) -> Result<Arc<Policy>, StartupError> {
    let (policy, report) = check::load(path, today(), ceiling)
        .map_err(|e| StartupError::Unusable(format!("{}: {e}", env::POLICY)))?;

    info!(
        waharoa.policy.path = %path.display(),
        waharoa.policy.cooldown_days = policy.cooldown_days,
        waharoa.policy.max_cvss = policy.max_cvss,
        waharoa.policy.install_scripts = %policy.install_scripts,
        waharoa.policy.kev = %policy.kev,
        waharoa.policy.provenance = %policy.provenance,
        waharoa.policy.denials = policy.denials.len(),
        waharoa.policy.exceptions = policy.packages.len(),
        "policy loaded and validated"
    );

    // What is configured and what can actually fire are different things, and the gap
    // has to be said out loud rather than discovered by a package getting through.
    warn!(
        "ENFORCED: denials, install_scripts, cooldown_days, yanked, deprecated, provenance. \
         A refused version is removed from the metadata document so the resolver picks \
         another, and a pinned fetch of one is refused"
    );
    if policy.uses_cooldown() {
        for (ecosystem, cost) in crate::ecosystem::cooldown_costs() {
            warn!(
                waharoa.policy.cooldown_days = policy.cooldown_days,
                waharoa.ecosystem = %ecosystem,
                waharoa.cooldown.cost = cost,
                "cooldown_days is enforced, at a cost to the ecosystem"
            );
        }
    }
    // An entry that does nothing is valid and worth saying out loud. `waharoa policy check`
    // and `doctor` report the same entries.
    for &index in &report.unchanged {
        warn!(
            waharoa.policy.exception = packages::label(index),
            waharoa.policy.exception_reason = %policy.packages[index].reason,
            "policy exception changes nothing, so nothing it matches is affected by it"
        );
    }
    for shadowed in report.never_wins() {
        warn!(
            waharoa.policy.exception = packages::label(shadowed.index),
            waharoa.policy.exception_cover = %shadowed.cover(),
            "policy exception never wins"
        );
    }

    Ok(Arc::new(policy))
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
            info!(waharoa.policy.digest_from = %old, waharoa.policy.digest_to = %new, "policy reloaded");
        }
        Err(why) => {
            error!(waharoa.policy.digest = %old, waharoa.reason = %why, "policy not reloaded")
        }
    }
}

/// [`reload_policy`] on each `SIGHUP`, for as long as the process runs.
#[cfg(unix)]
pub async fn reload_on_hangup<L: Fn(&str) -> Option<OsString>>(proxy: Proxy, environment: Env<L>) {
    let mut hangups = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hangups) => hangups,
        Err(e) => {
            error!(error.message = %e, "SIGHUP cannot be listened for, so the policy is never reloaded");
            return;
        }
    };
    while hangups.recv().await.is_some() {
        reload_policy(&proxy, &environment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{npm, pypi};
    use crate::env::testing::with;
    use crate::identity::Ecosystem;

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
    async fn an_unset_public_url_is_warned_about_and_a_forward_proxy_named() {
        let (started, log) = logged(
            "startup-public",
            &[(env::HTTPS_PROXY, "http://egress.example:3128")],
        )
        .await;

        assert!(started, "{log}");
        assert!(log.contains("not set: `npm ci` fails"), "{log}");
        assert!(
            log.contains("upstream traffic goes through a forward proxy"),
            "{log}"
        );
        assert!(!log.contains("observe mode"), "{log}");
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

        use std::os::unix::ffi::OsStringExt;
        let unreadable = Env::from_lookup(|_: &str| Some(OsString::from_vec(vec![0x66, 0xff])));
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
                (env::PUBLIC_URL, "http://waharoa.corp.example"),
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
            Some("http://waharoa.corp.example")
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
        let path = std::env::temp_dir().join(format!("waharoa-policy-{}.yaml", std::process::id()));
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
}
