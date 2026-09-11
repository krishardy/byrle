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
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::npm;
use waharoa::proxy::{DEFAULT_MAX_PACKUMENT_BYTES, Proxy};
use waharoa::store::DEFAULT_MAX_RECORDS;
use waharoa::tls::{self, TrustMode};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() {
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

    let proxy = Proxy::new(client, upstream)
        .with_blocked(blocked)
        .with_max_packument_bytes(max_packument_bytes)
        .with_max_records(max_records)
        .with_artifact_rewriting(rewrite_artifacts)
        .with_public_base(public_base);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));

    info!(listen = %listen, upstream = %proxy.upstream(), "waharoa listening");
    info!("point npm at it with:  npm config set registry http://{listen}/");

    axum::serve(listener, proxy.router())
        .await
        .expect("server failed");
}
