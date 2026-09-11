//! Stage 1: pass-through reverse proxy in front of an npm registry.
//!
//! No policy, no normalizer, no adapter trait (decision #12: Stage 1 calls reqwest
//! concretely). The point of this stage is that installs work through us and that we
//! can see every request, so the logging below is load-bearing rather than decoration.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
};
use std::time::Instant;
use tracing::{error, info};

/// Headers that describe a single hop and must not be forwarded to the next one.
/// `Host` is handled separately: reqwest sets it from the upstream URL.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
struct Proxy {
    client: reqwest::Client,
    /// Upstream registry base, no trailing slash.
    upstream: String,
    /// THROWAWAY. One hardcoded package name, to prove interception happens before
    /// anything is fetched. Stage 2 replaces this with the policy engine; there is
    /// deliberately no config file behind it, so it cannot quietly become a feature.
    blocked: Option<String>,
}

/// Recover the package name from an npm registry path.
///
/// Packument: `/lodash`, `/@babel%2fcore` (npm percent-encodes the scope separator).
/// Tarball:   `/lodash/-/lodash-4.17.21.tgz`, `/@babel/core/-/core-7.0.0.tgz`.
fn package_name_from_path(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    // Tarball paths carry the name before the `/-/` separator.
    let name = path.split("/-/").next().unwrap_or(path);
    let decoded = name.replace("%2f", "/").replace("%2F", "/");
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

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
    let upstream = env_or("WAHAROA_UPSTREAM", "https://registry.npmjs.org")
        .trim_end_matches('/')
        .to_string();

    // reqwest 0.13 defaults to rustls with rustls-platform-verifier, so the upstream
    // leg validates against the OS trust store. The inbound leg stays plain HTTP on
    // loopback: decision #3 is reverse proxy first, CA-terminating forward proxy later.
    let client = reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build upstream HTTP client");

    let blocked = std::env::var("WAHAROA_BLOCK")
        .ok()
        .filter(|s| !s.is_empty());
    if let Some(name) = &blocked {
        info!(package = %name, "THROWAWAY hardcoded block active (Stage 1 interception proof)");
    }

    let state = Proxy {
        client,
        upstream,
        blocked,
    };

    let app = Router::new()
        .route("/{*path}", axum::routing::any(proxy))
        .route("/", axum::routing::any(proxy))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {listen}: {e}"));

    info!(listen = %listen, upstream = %state.upstream, "waharoa listening");
    info!("point npm at it with:  npm config set registry http://{listen}/");

    axum::serve(listener, app).await.expect("server failed");
}

async fn proxy(State(proxy): State<Proxy>, req: Request) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();

    // The client's own user-agent tells us which package manager is talking, which is
    // what the status-code table in §5 will key off later.
    let client_ua = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // The block is evaluated on the way in, so it fires on the packument request and
    // the tarball is never fetched. 403 is correct here and only here: it means policy
    // denied you. Not-ready states use 502/503/429 (§5), never a 4xx.
    let package = package_name_from_path(&path_and_query);
    if let (Some(blocked), Some(package)) = (&proxy.blocked, &package)
        && blocked == package
    {
        info!(
            %method,
            path = %path_and_query,
            status = 403u16,
            package = %package,
            client = %client_ua,
            "blocked"
        );
        return (
            StatusCode::FORBIDDEN,
            format!("waharoa: {package} is blocked by policy\n"),
        )
            .into_response();
    }

    let url = format!("{}{}", proxy.upstream, path_and_query);

    let mut outbound = proxy.client.request(method.clone(), &url);
    for (name, value) in req.headers() {
        if is_hop_by_hop(name) || name == axum::http::header::HOST {
            continue;
        }
        outbound = outbound.header(name, value);
    }

    let upstream_response = match outbound.send().await {
        Ok(r) => r,
        Err(e) => {
            // §5: upstream unreachable or malformed is 502. Never a 4xx, which from a
            // registry proxy reads as "policy denied you".
            error!(%method, path = %path_and_query, error = %e, "upstream request failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("waharoa: upstream request failed: {e}\n"),
            )
                .into_response();
        }
    };

    let status = upstream_response.status();
    let upstream_len = upstream_response.content_length();

    info!(
        %method,
        path = %path_and_query,
        status = status.as_u16(),
        bytes = upstream_len.unwrap_or(0),
        elapsed_ms = started.elapsed().as_millis() as u64,
        client = %client_ua,
        "proxied"
    );

    let mut headers = HeaderMap::new();
    for (name, value) in upstream_response.headers() {
        if is_hop_by_hop(name) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }

    // Bodies pass through verbatim, `Content-Encoding` intact: reqwest's `gzip` feature
    // is deliberately off, so nothing is decompressed behind our back. Forwarding a
    // decompressed body under an unchanged `Content-Encoding: gzip` would hand npm a
    // JSON parse error that looks like our bug.
    let body = Body::from_stream(upstream_response.bytes_stream());

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
        headers,
        body,
    )
        .into_response()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}
