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

use tracing::info;
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::npm;
use waharoa::proxy::{DEFAULT_MAX_PACKUMENT_BYTES, Proxy};

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
    let client = reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build upstream HTTP client");

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

    let proxy = Proxy::new(client, upstream)
        .with_blocked(blocked)
        .with_max_packument_bytes(max_packument_bytes);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));

    info!(listen = %listen, upstream = %proxy.upstream(), "waharoa listening");
    info!("point npm at it with:  npm config set registry http://{listen}/");

    axum::serve(listener, proxy.router())
        .await
        .expect("server failed");
}
