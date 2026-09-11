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
use waharoa::doctor;
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::npm;
use waharoa::proxy::{DEFAULT_MAX_CONCURRENT_PACKUMENTS, DEFAULT_MAX_PACKUMENT_BYTES, Proxy};
use waharoa::refusal::RefusalStatus;
use waharoa::store::DEFAULT_MAX_RECORDS;
use waharoa::tls::{self, TrustMode};

const USAGE: &str = "\
usage: waharoa [command]

  (no command)  run the proxy
  doctor        check whether this machine installs through the proxy
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
  WAHAROA_MAX_CONCURRENT_PACKUMENTS packuments decoded at once (8)
  WAHAROA_REFUSAL_STATUS            status a refusal answers with, per client, e.g.
                                    \"default=403,npm/pnpm=451\" (default 403)
  WAHAROA_REFUSE_UNSERVABLE=0       forward versions whose artifacts this proxy cannot
                                    see, instead of removing them from the packument
  WAHAROA_BLOCK                     THROWAWAY: refuse one package by name
";

/// A comma-separated environment variable, blanks dropped.
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

/// How many entries a client cache holds. `None` when there is no cache to look at.
fn cache_entries(client: &str) -> Option<u64> {
    let dir = match client {
        "npm" => {
            let output = std::process::Command::new("npm")
                .args(["config", "get", "cache"])
                .output()
                .ok()?;
            std::path::PathBuf::from(String::from_utf8(output.stdout).ok()?.trim()).join("_cacache")
        }
        _ => return None,
    };
    let index = dir.join("index-v5");
    if !index.is_dir() {
        return Some(0);
    }
    // Every cached response is one file under index-v5, nested two levels deep.
    Some(doctor::count_files(&index))
}

fn run_doctor() -> std::process::ExitCode {
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
    findings.push(doctor::check_cache("npm", cache_entries("npm")));

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
        Some("doctor") => return run_doctor(),
        Some("help" | "-h" | "--help") => {
            print!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        Some(other) => {
            eprintln!("waharoa: unknown command `{other}`\n");
            eprint!("{USAGE}");
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

    let client = tls::build(builder, bundle_path.as_deref()).unwrap_or_else(|e| panic!("{e}"));

    let blocked = std::env::var("WAHAROA_BLOCK")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|name| {
            PackageKey::from_registry_name(Ecosystem::Npm, &name)
                .unwrap_or_else(|e| panic!("WAHAROA_BLOCK={name} is not a package name: {e}"))
        });
    if let Some(key) = &blocked {
        info!(package = %key, "THROWAWAY hardcoded block active (Stage 1 interception proof)");
    }

    let max_packument_bytes = std::env::var("WAHAROA_MAX_PACKUMENT_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_PACKUMENT_BYTES);

    let max_records = std::env::var("WAHAROA_MAX_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_RECORDS);

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
            "artifact URL rewriting is OFF; pnpm and yarn will fetch artifacts directly \
             and nothing about them is observed"
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

    let proxy = Proxy::new(client, upstream)
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
        .with_blocked(blocked)
        .with_max_packument_bytes(max_packument_bytes)
        .with_max_records(max_records)
        .with_artifact_rewriting(rewrite_artifacts)
        .with_public_base(public_base);

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
