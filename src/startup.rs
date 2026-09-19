//! Building the proxy from the environment, the way `waharoa` runs it.
//!
//! Every value comes from `crate::env`, and what each one means is said here as the proxy
//! starts: what is enforced, what is not, and what an unset variable leaves off. `main`
//! keeps the logging setup, the listener and the exit codes.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::audit::AuditLog;
use crate::doctor;
use crate::env::{self, Env};
use crate::intel::postgres;
use crate::intel::store::Intel;
use crate::policy::{Policy, check, packages, today};
use crate::proxy::Proxy;
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
    let mut builder =
        reqwest::Client::builder().user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")));
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
            "{} is not set, so {}. `npm ci` fails if that address later becomes unreachable. \
             Set it to a stable name.",
            env::PUBLIC_URL,
            doctor::WITHOUT_PUBLIC_URL
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
            status,
            "a refusal configured to answer {status} will read as the proxy being broken \
             rather than as policy denying the request (plan §5 reserves 5xx for not-ready)"
        );
    }

    // Versions whose artifacts are published where this proxy cannot see them are removed
    // from the packument, so a resolver picks one that can be examined. Setting this to 0
    // forwards them instead, and the client then fetches those artifacts directly.
    let refuse_unservable = environment.refuse_unservable()?;
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
    let defer_test = environment.defer_test()?.inspect(|deferral| {
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
            info!(path = %path.display(), "audit log open");
            Some(Arc::new(log))
        }
        None => None,
    };
    if audit.is_none() && policy.is_some() {
        warn!(
            "no audit log configured; set {} to record policy decisions",
            env::AUDIT_LOG
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
                "ENFORCED: known_malware and max_cvss, from the intel store at {}, and kev once \
                 the store has loaded the KEV catalogue. A store that cannot answer, or holds no \
                 snapshot, is a 503 for every package",
                env::DATABASE_URL
            );
            // The snapshot loaded now. `waharoa doctor` reports the same for a later one.
            if let Ok(Some(snapshot)) = store.snapshot().await {
                for gap in snapshot.gaps() {
                    warn!("{gap}");
                }
            }
        }
        (None, Some(_)) => warn!(
            "NOT ENFORCED: known_malware, max_cvss and kev. {} is not set, so there is no \
             intel store to ask",
            env::DATABASE_URL
        ),
        _ => {}
    }
    let intel = intel.map(|store| Arc::new(store) as Arc<dyn Intel>);

    let proxy = Proxy::new(client)
        .with_upstreams(upstreams)
        .with_intel(intel)
        .with_refusal_status(refusal)
        .with_refuse_unservable(refuse_unservable)
        .with_origin_policy(
            served_origins.iter().map(String::as_str),
            allowed_direct.iter().map(String::as_str),
        )
        // Refusing to start is right: an origin the operator named and that was quietly
        // dropped would leave them believing those artifacts are covered.
        .map_err(|e| StartupError::Unusable(format!("origin configuration: {e}")))?
        .with_max_concurrent_documents(max_concurrent)
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

    Ok(Arc::new(policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::{npm, pypi};
    use crate::env::testing::with;
    use crate::identity::Ecosystem;

    /// The failure `pairs` starts with. `Proxy` is not `Debug`, so `expect_err` cannot
    /// print the proxy it did build.
    async fn refused(pairs: &[(env::Var, &str)]) -> StartupError {
        match proxy(&with(pairs)).await {
            Err(e) => e,
            Ok(_) => panic!("{pairs:?} should not start a proxy"),
        }
    }

    /// Nothing set: npm's and PyPI's own registries, no policy, no store, and artifact
    /// URLs pointed at the proxy.
    #[tokio::test]
    async fn an_empty_environment_starts_the_default_proxy() {
        let started = proxy(&with(&[])).await.expect("the defaults are usable");
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
        assert_eq!(health.public_base, None);
        assert_eq!(health.allowed_direct_origins, Vec::<String>::new());
    }

    /// Each configured value reaches the proxy it builds.
    #[tokio::test]
    async fn the_environment_reaches_the_proxy() {
        let started = proxy(&with(&[
            (env::LISTEN, "127.0.0.1:9999"),
            (env::UPSTREAM_NPM, "https://npm.mirror.example/"),
            (env::UPSTREAM_PYPI, "https://pypi.mirror.example/simple"),
            (env::PUBLIC_URL, "http://waharoa.corp.example"),
            (env::ARTIFACT_ORIGINS, "https://cdn.example"),
            (env::ALLOW_DIRECT_ORIGINS, "https://direct.example"),
            (env::REWRITE_ARTIFACTS, "0"),
            (env::REFUSE_UNSERVABLE, "0"),
        ]))
        .await
        .expect("every value is usable");
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
        assert!(
            health
                .served_origins
                .contains(&"https://cdn.example".to_owned()),
            "{:?}",
            health.served_origins
        );
        assert_eq!(health.allowed_direct_origins, ["https://direct.example"]);
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
        let dir = crate::util::test_support::tempdir("startup-policy");
        let path = dir.join("policy.yaml");
        std::fs::write(&path, "version: 1\ncooldown_days: 7\n").expect("writes");
        let started = proxy(&with(&[(env::POLICY, &path.display().to_string())]))
            .await
            .expect("the policy loads");
        let policy = started.proxy.policy().expect("the proxy holds it");
        assert_eq!(policy.cooldown_days, 7);
        assert!(policy.uses_cooldown());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
