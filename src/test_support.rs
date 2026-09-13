//! Helpers for unit tests in more than one module.

/// An empty directory for one test. `label` has to differ between the tests that call this,
/// because the directory is emptied first.
pub fn tempdir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("waharoa-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory should be creatable");
    dir
}

/// The address of a server that accepts each connection and closes it without a response.
///
/// For tests that need an upstream that sends nothing. Binding a port and dropping the
/// listener leaves the port free for another process to take before the test connects.
/// `the_only_4xx_this_proxy_produces_is_a_policy_refusal` did that and failed once on
/// 2026-09-14, under parallel load. This server keeps the port bound until the test's
/// runtime ends.
pub async fn closing_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port should bind");
    let addr = listener
        .local_addr()
        .expect("a bound listener has an address");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    addr
}
