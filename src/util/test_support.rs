//! Helpers for unit tests in more than one module.

/// Loopback port 9, where nothing listens, so a request a test should not send fails at once.
pub const NO_UPSTREAM: &str = "http://127.0.0.1:9";

/// The `log` logger `tracing`'s `log-always` hands every event to in tests.
struct Routing;

impl log::Log for Routing {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let level = match record.level() {
            log::Level::Error => tracing::Level::ERROR,
            log::Level::Warn => tracing::Level::WARN,
            log::Level::Info => tracing::Level::INFO,
            log::Level::Debug => tracing::Level::DEBUG,
            log::Level::Trace => tracing::Level::TRACE,
        };
        if let Some(buf) = capturing(&level) {
            let line = format!(
                "{:>5} {}: {}\n",
                record.level(),
                record.target(),
                record.args()
            );
            buf.lock().unwrap().extend_from_slice(line.as_bytes());
        }
    }

    fn flush(&self) {}
}

/// Installed before `main`, so no event in any test runs before it. Safe, as `ctor`
/// asks: it touches only `log`'s two globals, which need nothing set up.
#[ctor::ctor(unsafe)]
fn route_log_records() {
    let _ = log::set_logger(&Routing);
    log::set_max_level(log::LevelFilter::Trace);
}

/// An empty directory for one test. `label` has to differ between the tests that call this,
/// because the directory is emptied first.
pub fn tempdir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("waharoa-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory should be creatable");
    dir
}

/// Set `path`'s permission bits to `mode`.
pub fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("sets the mode");
}

/// A directory with its permission bits set to `mode` until this drops, then `0755`.
pub struct Restricted<'a>(&'a std::path::Path);

impl<'a> Restricted<'a> {
    pub fn new(path: &'a std::path::Path, mode: u32) -> Self {
        set_mode(path, mode);
        Self(path)
    }
}

impl Drop for Restricted<'_> {
    fn drop(&mut self) {
        set_mode(self.0, 0o755);
    }
}

/// A server that accepts each connection and closes it without a response. It keeps
/// the port bound until the runtime ends, so no other process can take it.
/// Returns its address.
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
    /// 200 with this body in one chunk, and no `Content-Length`.
    Chunked(Vec<u8>),
}

impl Answer {
    pub fn body(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Body {
            bytes: bytes.into(),
            declared: None,
        }
    }

    /// A body that ends before its `Content-Length`: one byte sent of 64 declared.
    pub fn cut_short() -> Self {
        Self::Body {
            bytes: b"{".to_vec(),
            declared: Some(64),
        }
    }
}

/// A server that answers requests with `answers` in order, repeating the last one once
/// they run out. `answers` must not be empty.
/// Returns its address.
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

/// Each thread capturing logs: the most verbose level it keeps, and its buffer.
type Captures = std::sync::Mutex<
    std::collections::HashMap<
        std::thread::ThreadId,
        (tracing::Level, std::sync::Arc<std::sync::Mutex<Vec<u8>>>),
    >,
>;

fn captures() -> &'static Captures {
    static CAPTURES: std::sync::OnceLock<Captures> = std::sync::OnceLock::new();
    CAPTURES.get_or_init(Captures::default)
}

/// This thread's buffer, when it is capturing at `level` or more verbosely.
fn capturing(level: &tracing::Level) -> Option<std::sync::Arc<std::sync::Mutex<Vec<u8>>>> {
    let captures = captures().lock().unwrap();
    let (keeps, buf) = captures.get(&std::thread::current().id())?;
    (level <= keeps).then(|| buf.clone())
}

/// Stops this thread's capture when dropped.
pub struct Capture(std::thread::ThreadId);

impl Drop for Capture {
    fn drop(&mut self) {
        captures().lock().unwrap().remove(&self.0);
    }
}

/// Keep this thread's logs at `level` and above in the returned buffer, until the
/// [`Capture`] drops.
pub fn capture(level: tracing::Level) -> (Capture, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let thread = std::thread::current().id();
    captures()
        .lock()
        .unwrap()
        .insert(thread, (level, buf.clone()));
    (Capture(thread), buf)
}

pub fn text(buf: &std::sync::Mutex<Vec<u8>>) -> String {
    String::from_utf8(buf.lock().unwrap().clone()).unwrap()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod capture_tests {
    use super::{capture, text};

    /// A capture keeps its own thread's events at its level or less verbose, and nothing
    /// from another thread or after it stops.
    #[test]
    fn a_capture_keeps_its_own_threads_events_at_its_level() {
        let (guard, buf) = capture(tracing::Level::INFO);
        tracing::info!("kept here");
        tracing::warn!("kept too");
        tracing::debug!("too verbose");
        std::thread::spawn(|| tracing::info!("another thread"))
            .join()
            .unwrap();
        drop(guard);
        tracing::info!("after the capture");

        let log = text(&buf);
        assert!(
            log.contains("kept here") && log.contains("kept too"),
            "{log}"
        );
        for absent in ["too verbose", "another thread", "after the capture"] {
            assert!(!log.contains(absent), "{absent}: {log}");
        }
    }
}
