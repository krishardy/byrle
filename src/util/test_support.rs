//! Helpers for unit tests in more than one module.

/// An upstream address where a request fails at once, for a test that should send none.
///
/// Loopback, so the request never leaves the machine, and port 9, the reserved discard
/// service, which nothing runs: a connection is refused in microseconds. A public host
/// would send traffic out, a TEST-NET address would wait for a connect timeout, and a
/// `.invalid` name would ask a resolver first.
///
/// A test that needs an upstream to answer wants [`closing_server`] or its own stub. This
/// is for one whose store or configuration is meant to answer without any request.
pub const NO_UPSTREAM: &str = "http://127.0.0.1:9";

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

/// The address of a server that sends response headers and then nothing, holding the
/// connection open. For a test that a read timeout ends a stalled body.
pub async fn stalling_server() -> std::net::SocketAddr {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port should bind");
    let addr = listener
        .local_addr()
        .expect("a bound listener has an address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // A body that is declared and never sent. The connection stays open, which
                // is what a stalled download looks like.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

/// One answer a [`scripted`] server gives.
#[derive(Debug, Clone)]
pub enum Answer {
    /// Accept the connection and close it without a response.
    Close,
    /// A status with an empty body.
    Status(u16),
    /// 200 with this body, and a `Content-Length` of `declared` rather than its length.
    Body {
        bytes: Vec<u8>,
        declared: Option<usize>,
    },
    /// 200 with this body in one chunk, and no `Content-Length` at all: the length is
    /// known only as the body arrives.
    Chunked(Vec<u8>),
}

impl Answer {
    pub fn body(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Body {
            bytes: bytes.into(),
            declared: None,
        }
    }
}

/// The address of a server that answers requests with `answers` in order, repeating the
/// last one once they run out.
///
/// For tests of a fetch: a status it must not retry, a body over a ceiling, a connection
/// that closes before the second attempt succeeds.
pub async fn scripted(answers: Vec<Answer>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port should bind");
    let addr = listener
        .local_addr()
        .expect("a bound listener has an address");
    tokio::spawn(async move {
        let mut request = 0_usize;
        while let Ok((mut stream, _)) = listener.accept().await {
            let answer = answers[request.min(answers.len() - 1)].clone();
            request += 1;
            tokio::spawn(async move {
                // The request is read and dropped: what it asked for does not change the
                // answer, and a client that gets a response before it finished writing
                // sees a broken pipe instead.
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let response = match answer {
                    Answer::Close => return,
                    Answer::Status(code) => format!(
                        "HTTP/1.1 {code} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .into_bytes(),
                    Answer::Chunked(bytes) => {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: \
                             chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                            bytes.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&bytes);
                        out.extend_from_slice(b"\r\n0\r\n\r\n");
                        out
                    }
                    Answer::Body { bytes, declared } => {
                        let length = declared.unwrap_or(bytes.len());
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \
                             \"tag\"\r\nLast-Modified: Wed, 17 Sep 2026 00:00:00 \
                             GMT\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                        )
                        .into_bytes();
                        out.extend_from_slice(&bytes);
                        out
                    }
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            });
        }
    });
    addr
}

/// A gzipped tar holding `files`, as an npm tarball or an sdist is.
pub fn tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, *bytes)
            .expect("appends");
    }
    let tar = builder.into_inner().expect("builds");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).expect("compresses");
    gz.finish().expect("finishes")
}
