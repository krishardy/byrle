//! Fetching a stream's bundle: one GET, or GitHub's paged POST, with the byte ceilings and
//! retries. Progress goes to `notice`, so `waharoa refresh` owns its output and a test can
//! read it.

use super::history::NotLoaded;
use super::providers::osv::bundle::Tally;
use super::refresh::{ATTEMPTS, FetchFailure, RETRY_WAIT, StreamDigest, retried, sha256_hex};
use super::stream::{Payload, Stream, Transport};

/// Where a fetch's progress lines go.
pub type Notice<'a> = &'a dyn Fn(&str);

/// A body a refresh fetched, with the headers a snapshot records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Fetched {
    /// The body as a snapshot records it under `stream`.
    pub fn stream(&self, stream: &str) -> StreamDigest {
        StreamDigest {
            stream: stream.to_owned(),
            sha256: sha256_hex(&self.bytes),
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
        }
    }
}

/// One stream's bundle, fetched with [`ATTEMPTS`] attempts.
///
/// A transient failure is fetched again after [`RETRY_WAIT`], because `osv/npm` is
/// `Required` and a refresh that gives up on it loads nothing. Each attempt starts the
/// request over: the bundle is one GET with no range request, so there is nothing to resume.
pub async fn stream_bundle(
    http: &reqwest::Client,
    declared: &Stream,
    github_token: Option<&str>,
    notice: Notice<'_>,
) -> Result<Fetched, String> {
    let mut attempt = 1;
    loop {
        let got = match declared.transport {
            Transport::Get => bundle(http, declared.url, declared.ceiling, notice).await,
            Transport::GithubGraphql { query } => match github_token {
                Some(token) => {
                    graphql(http, declared.url, declared.ceiling, token, query, notice).await
                }
                None => Err(FetchFailure::settled(format!(
                    "{} is unset, so this stream is not read",
                    crate::env::GITHUB_TOKEN
                ))),
            },
        };
        match got {
            Ok(fetched) => return Ok(fetched),
            Err(failure) if retried(&failure, attempt) => {
                notice(&format!(
                    "attempt {attempt} of {ATTEMPTS}: {failure}; again in {}s",
                    RETRY_WAIT.as_secs()
                ));
                tokio::time::sleep(RETRY_WAIT).await;
                attempt += 1;
            }
            Err(failure) => return Err(failure.why),
        }
    }
}

/// The body at `url`, refused past `ceiling` bytes.
pub async fn bundle(
    http: &reqwest::Client,
    url: &str,
    ceiling: usize,
    notice: Notice<'_>,
) -> Result<Fetched, FetchFailure> {
    use futures_util::StreamExt;

    notice(&format!("fetching {url}"));
    let response = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| failed(&format!("fetching {url}"), e))?;
    let header = |name: reqwest::header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let (etag, last_modified) = (
        header(reqwest::header::ETAG),
        header(reqwest::header::LAST_MODIFIED),
    );
    if let Some(declared) = response.content_length().filter(|&n| n > ceiling as u64) {
        return Err(FetchFailure::settled(format!(
            "{url} declares {declared} bytes, over the {ceiling} byte ceiling"
        )));
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| failed(&format!("reading {url}"), e))?;
        if bytes.len() + chunk.len() > ceiling {
            return Err(FetchFailure::settled(format!(
                "{url} is over the {ceiling} byte ceiling"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        bytes,
        etag,
        last_modified,
    })
}

/// One stream's bundle, read and waiting to be encoded.
#[derive(Debug)]
pub struct Loaded {
    pub source: &'static str,
    pub payload: Payload,
    pub tally: Option<Tally>,
    /// The bundle it was read from, as a snapshot records it.
    pub streams: [StreamDigest; 1],
}

/// What reading every stream produced.
#[derive(Debug, Default)]
pub struct Read {
    pub loaded: Vec<Loaded>,
    pub not_loaded: Vec<NotLoaded>,
}

/// Fetch and parse each stream in `streams`, in order.
///
/// A stream that does not load is one [`NotLoaded`], and the rest still load. One stream's
/// bytes are freed before the next is fetched.
pub async fn read_streams(
    http: &reqwest::Client,
    streams: &'static [Stream],
    github_token: Option<&str>,
    notice: Notice<'_>,
) -> Read {
    let mut read = Read::default();
    for declared in streams {
        let got = stream_bundle(http, declared, github_token, notice).await;
        let parsed = match got {
            Ok(fetched) => {
                let bundle = fetched.stream(declared.stream);
                match (declared.parse)(&fetched.bytes) {
                    Ok(parsed) => Ok((parsed, bundle)),
                    Err(error) => Err((Some(bundle), error)),
                }
            }
            Err(error) => Err((None, error)),
        };
        let (parsed, bundle) = match parsed {
            Ok(parsed) => parsed,
            Err((bundle, error)) => {
                notice(&format!(
                    "{} is not loaded, and its last load stays: {error}",
                    declared.stream
                ));
                read.not_loaded.push(NotLoaded {
                    source: declared.stream.to_owned(),
                    stream: declared.stream.to_owned(),
                    bundle,
                    error,
                    unconfigured: matches!(declared.transport, Transport::GithubGraphql { .. })
                        && github_token.is_none(),
                });
                continue;
            }
        };
        read.loaded.push(Loaded {
            source: declared.stream,
            payload: parsed.payload,
            tally: parsed.tally,
            streams: [bundle],
        });
    }
    read
}

/// A request error, as the refresh reports it/// A request error, as the refresh reports it: transient unless the host chose the status.
///
/// A 404 or a 403 is the same on every attempt. A refused connection, a read that timed out
/// and a body that stopped mid-stream are what another attempt can get past.
fn failed(doing: &str, e: reqwest::Error) -> FetchFailure {
    let why = format!("{doing}: {e}");
    if e.is_status() {
        FetchFailure::settled(why)
    } else {
        FetchFailure::transient(why)
    }
}

/// Every page of GitHub's advisory connection, as one JSON array of response bodies.
///
/// [`crate::intel::providers::github::parse`] reads that array, so paging stays here and the descriptor's
/// `parse` keeps taking one buffer. `ceiling` bounds the whole array rather than one page.
///
/// A page that is not JSON, or that carries no `pageInfo`, ends the fetch: the bytes are
/// still handed to `parse`, which reports what GitHub said.
pub async fn graphql(
    http: &reqwest::Client,
    url: &str,
    ceiling: usize,
    token: &str,
    query: &str,
    notice: Notice<'_>,
) -> Result<Fetched, FetchFailure> {
    let mut bytes = vec![b'['];
    let mut after: Option<String> = None;
    let mut pages = 0_usize;
    notice(&format!("fetching {url}"));
    loop {
        let body = serde_json::json!({
            "query": query,
            "variables": { "after": after },
        });
        let body = serde_json::to_vec(&body).expect("a JSON value serialises");
        let response = http
            .post(url)
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| failed(&format!("fetching {url}"), e))?;
        let page = response
            .bytes()
            .await
            .map_err(|e| failed(&format!("reading {url}"), e))?;
        if bytes.len() + page.len() + 1 > ceiling {
            return Err(FetchFailure::settled(format!(
                "{url} is over the {ceiling} byte ceiling after {pages} pages"
            )));
        }
        if pages > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(&page);
        pages += 1;

        let parsed: serde_json::Value = serde_json::from_slice(&page)
            .map_err(|e| FetchFailure::settled(format!("reading {url}: {e}")))?;
        let info = &parsed["data"]["securityVulnerabilities"]["pageInfo"];
        if info["hasNextPage"].as_bool() != Some(true) {
            break;
        }
        match info["endCursor"].as_str() {
            Some(cursor) => after = Some(cursor.to_owned()),
            None => break,
        }
    }
    bytes.push(b']');
    notice(&format!("{pages} pages from {url}"));
    Ok(Fetched {
        bytes,
        etag: None,
        last_modified: None,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::intel::refresh::http_client;
    use crate::util::test_support::{Answer, scripted};

    /// A client with a short read timeout, so a stalled test server ends quickly.
    fn client() -> reqwest::Client {
        http_client(Duration::from_millis(200)).expect("a client")
    }

    /// Collects what would have been printed.
    #[derive(Default)]
    struct Printed(Mutex<Vec<String>>);

    impl Printed {
        fn notice(&self) -> impl Fn(&str) + '_ {
            |line: &str| self.0.lock().expect("notice lock").push(line.to_owned())
        }

        fn lines(&self) -> Vec<String> {
            self.0.lock().expect("notice lock").clone()
        }
    }

    async fn fetch_from(answers: Vec<Answer>, ceiling: usize) -> Result<Fetched, FetchFailure> {
        let addr = scripted(answers).await;
        let printed = Printed::default();
        let got = bundle(
            &client(),
            &format!("http://{addr}/all.zip"),
            ceiling,
            &printed.notice(),
        )
        .await;
        assert_eq!(
            printed.lines(),
            [format!("fetching http://{addr}/all.zip")],
            "one line per fetch, whatever it answered"
        );
        got
    }

    /// The body, and the headers a snapshot records with it.
    #[tokio::test]
    async fn a_body_under_the_ceiling_is_read_with_its_headers() {
        let fetched = fetch_from(vec![Answer::body("one two three")], 13)
            .await
            .expect("13 bytes under a 13 byte ceiling");
        assert_eq!(fetched.bytes, b"one two three");
        assert_eq!(fetched.etag.as_deref(), Some("\"tag\""));
        assert_eq!(
            fetched.last_modified.as_deref(),
            Some("Wed, 17 Sep 2026 00:00:00 GMT")
        );
        let digest = fetched.stream("osv/npm");
        assert_eq!(digest.stream, "osv/npm");
        assert_eq!(digest.sha256, sha256_hex(b"one two three"));
        assert_eq!(digest.etag, fetched.etag);
    }

    /// A declared length over the ceiling is refused before the body is read, and a body
    /// with no declared length as it passes the ceiling.
    #[tokio::test]
    async fn a_bundle_over_the_ceiling_is_refused_by_either_check() {
        let declared = fetch_from(
            vec![Answer::Body {
                bytes: b"aaaa".to_vec(),
                declared: Some(5_000),
            }],
            100,
        )
        .await
        .expect_err("5,000 declared over a 100 byte ceiling");
        assert!(
            declared
                .why
                .ends_with("declares 5000 bytes, over the 100 byte ceiling"),
            "{}",
            declared.why
        );
        assert!(!declared.again, "the same on every attempt");

        let streamed = fetch_from(vec![Answer::Chunked(vec![b'a'; 200])], 100)
            .await
            .expect_err("200 bytes over a 100 byte ceiling");
        assert!(
            streamed.why.ends_with("is over the 100 byte ceiling"),
            "{}",
            streamed.why
        );
        assert!(!streamed.again);
    }

    /// A body exactly at the ceiling is read. The ceilings are measured from real bundles,
    /// so an off-by-one here refuses a bundle that fits.
    #[tokio::test]
    async fn a_bundle_at_the_ceiling_is_read() {
        let fetched = fetch_from(vec![Answer::body(vec![b'a'; 100])], 100)
            .await
            .expect("100 bytes at a 100 byte ceiling");
        assert_eq!(fetched.bytes.len(), 100);
    }

    /// A status the host chose is not retried: every attempt gets it again.
    #[tokio::test]
    async fn a_status_is_settled_and_a_stall_is_not() {
        let status = fetch_from(vec![Answer::Status(404)], 100)
            .await
            .expect_err("404");
        assert!(status.why.contains("404"), "{}", status.why);
        assert!(!status.again);

        let closed = fetch_from(vec![Answer::Close], 100)
            .await
            .expect_err("nothing was sent");
        assert!(closed.again, "{}", closed.why);
    }

    /// A transient failure is fetched again, and the notice says so. It waits `RETRY_WAIT`
    /// for real: a paused clock fires the connect timeout before a local connection completes.
    #[tokio::test]
    async fn a_transient_failure_is_fetched_again() {
        let addr = scripted(vec![Answer::Close, Answer::body("{}")]).await;
        let printed = Printed::default();
        let declared = Stream {
            url: Box::leak(format!("http://{addr}/all.zip").into_boxed_str()),
            ..crate::intel::stream::ALL[0]
        };
        let fetched = stream_bundle(&client(), &declared, None, &printed.notice())
            .await
            .expect("the second attempt answers");
        assert_eq!(fetched.bytes, b"{}");
        let lines = printed.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[1].starts_with("attempt 1 of 3:"), "{lines:?}");
        assert!(lines[1].ends_with("again in 2s"), "{lines:?}");
    }

    /// One GitHub page whose `pageInfo` says there is no next one: the array holds that
    /// page and nothing else.
    #[tokio::test]
    async fn a_single_graphql_page_is_the_whole_array() {
        let page = br#"{"data":{"securityVulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}"#;
        let addr = scripted(vec![Answer::body(page.to_vec())]).await;
        let printed = Printed::default();
        let url = format!("http://{addr}/graphql");
        let fetched = graphql(&client(), &url, 4096, "token", "query", &printed.notice())
            .await
            .expect("one page");
        let array: serde_json::Value = serde_json::from_slice(&fetched.bytes).expect("an array");
        assert_eq!(array.as_array().map(Vec::len), Some(1));
        assert_eq!(fetched.etag, None, "a page carries no bundle headers");
        assert_eq!(
            printed.lines(),
            [format!("fetching {url}"), format!("1 pages from {url}")]
        );
    }

    /// Paging stops at the ceiling rather than following the cursor forever. The server
    /// answers every page with `hasNextPage`, so the ceiling is what ends it.
    #[tokio::test]
    async fn graphql_paging_stops_at_the_ceiling() {
        let page = br#"{"data":{"securityVulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"next"}}}}"#;
        let addr = scripted(vec![Answer::body(page.to_vec())]).await;
        let printed = Printed::default();
        let url = format!("http://{addr}/graphql");
        let failure = graphql(
            &client(),
            &url,
            page.len() + 8,
            "token",
            "query",
            &printed.notice(),
        )
        .await
        .expect_err("the second page is over the ceiling");
        assert!(
            failure.why.ends_with("byte ceiling after 1 pages"),
            "{}",
            failure.why
        );
        assert!(!failure.again, "the same on every attempt");
    }

    /// A page that is not JSON ends the fetch rather than being followed.
    #[tokio::test]
    async fn a_graphql_page_that_is_not_json_ends_the_fetch() {
        let addr = scripted(vec![Answer::body("not json")]).await;
        let printed = Printed::default();
        let failure = graphql(
            &client(),
            &format!("http://{addr}/graphql"),
            4096,
            "token",
            "query",
            &printed.notice(),
        )
        .await
        .expect_err("not JSON");
        assert!(failure.why.starts_with("reading http"), "{}", failure.why);
        assert!(!failure.again);
    }

    /// A table of two streams served by one scripted server.
    fn two_streams(first_parses: bool) -> &'static [Stream] {
        fn ok(_: &[u8]) -> Result<crate::intel::stream::Parsed, String> {
            Ok(crate::intel::stream::Parsed {
                payload: crate::intel::stream::Payload::Exploited(Default::default()),
                tally: None,
            })
        }
        fn unreadable(_: &[u8]) -> Result<crate::intel::stream::Parsed, String> {
            Err("not a bundle".to_owned())
        }
        Box::leak(Box::new([
            Stream {
                stream: "first/one",
                parse: if first_parses { ok } else { unreadable },
                ..crate::intel::stream::ALL[0]
            },
            Stream {
                stream: "second/one",
                parse: ok,
                ..crate::intel::stream::ALL[0]
            },
        ]))
    }

    /// Both streams read, in order.
    #[tokio::test]
    async fn every_stream_that_reads_is_loaded() {
        let addr = scripted(vec![Answer::body("{}")]).await;
        let url: &'static str = Box::leak(format!("http://{addr}/b").into_boxed_str());
        let streams: Vec<Stream> = two_streams(true)
            .iter()
            .map(|declared| Stream { url, ..*declared })
            .collect();
        let printed = Printed::default();
        let read = read_streams(
            &client(),
            Box::leak(streams.into_boxed_slice()),
            None,
            &printed.notice(),
        )
        .await;
        assert_eq!(
            read.loaded
                .iter()
                .map(|l| (l.source, l.streams[0].stream.as_str()))
                .collect::<Vec<_>>(),
            [("first/one", "first/one"), ("second/one", "second/one")]
        );
        assert!(read.not_loaded.is_empty());
    }

    /// A stream that does not parse does not stop the ones after it: `osv/pypi` failing
    /// does not hold back `osv/npm`. Its bundle is recorded, because it was fetched.
    #[tokio::test]
    async fn a_stream_that_does_not_read_leaves_the_others_loading() {
        let addr = scripted(vec![Answer::body("{}")]).await;
        let url: &'static str = Box::leak(format!("http://{addr}/b").into_boxed_str());
        let streams: Vec<Stream> = two_streams(false)
            .iter()
            .map(|declared| Stream { url, ..*declared })
            .collect();
        let printed = Printed::default();
        let read = read_streams(
            &client(),
            Box::leak(streams.into_boxed_slice()),
            None,
            &printed.notice(),
        )
        .await;
        assert_eq!(
            read.loaded.iter().map(|l| l.source).collect::<Vec<_>>(),
            ["second/one"]
        );
        assert_eq!(read.not_loaded.len(), 1);
        assert_eq!(read.not_loaded[0].stream, "first/one");
        assert_eq!(read.not_loaded[0].source, "first/one");
        assert_eq!(read.not_loaded[0].error, "not a bundle");
        assert!(
            read.not_loaded[0].bundle.is_some(),
            "the bundle was fetched, so it is recorded"
        );
        assert_eq!(
            printed.lines(),
            [
                format!("fetching {url}"),
                "first/one is not loaded, and its last load stays: not a bundle".to_owned(),
                format!("fetching {url}"),
            ]
        );
    }

    /// An optional stream that cannot be fetched leaves the others loading, and says so.
    #[tokio::test]
    async fn an_optional_stream_that_cannot_be_fetched_is_skipped() {
        let (good, bad) = (
            scripted(vec![Answer::body("{}")]).await,
            scripted(vec![Answer::Status(500)]).await,
        );
        let streams: Vec<Stream> = two_streams(true)
            .iter()
            .zip([good, bad])
            .map(|(declared, addr)| Stream {
                url: Box::leak(format!("http://{addr}/b").into_boxed_str()),
                ..*declared
            })
            .collect();
        let printed = Printed::default();
        let read = read_streams(
            &client(),
            Box::leak(streams.into_boxed_slice()),
            None,
            &printed.notice(),
        )
        .await;
        assert_eq!(read.loaded.len(), 1);
        assert_eq!(read.not_loaded.len(), 1);
        assert!(read.not_loaded[0].bundle.is_none(), "nothing was fetched");
        assert!(
            !read.not_loaded[0].unconfigured,
            "a stream that failed was configured"
        );
        assert!(
            printed
                .lines()
                .iter()
                .any(|line| line.starts_with("second/one is not loaded, and its last load stays")),
            "{:?}",
            printed.lines()
        );
    }

    /// GitHub's stream is not read without a token, and that is not retried.
    #[tokio::test]
    async fn the_github_stream_without_a_token_is_not_fetched() {
        let printed = Printed::default();
        let github = crate::intel::stream::by_stream(crate::intel::providers::github::NPM_STREAM)
            .expect("this build declares it");
        let why = stream_bundle(&client(), github, None, &printed.notice())
            .await
            .expect_err("no token");
        assert!(
            why.ends_with("is unset, so this stream is not read"),
            "{why}"
        );
        assert!(printed.lines().is_empty(), "nothing was fetched");
    }

    /// A stream not read for want of its token is recorded as unconfigured.
    #[tokio::test]
    async fn a_stream_not_read_for_want_of_a_token_is_recorded_as_unconfigured() {
        const GITHUB: &[Stream] = &[crate::intel::stream::GITHUB_NPM];
        let printed = Printed::default();
        let read = read_streams(&client(), GITHUB, None, &printed.notice()).await;
        assert_eq!(read.not_loaded.len(), 1);
        assert!(read.not_loaded[0].unconfigured);
    }

    /// With a token, GitHub's stream is read page by page, a page naming no cursor is the
    /// last, and the pages are one array.
    #[tokio::test]
    async fn the_github_stream_is_read_with_a_token() {
        let first = br#"{"data":{"securityVulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}"#;
        let last =
            br#"{"data":{"securityVulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}"#;
        let addr = scripted(vec![
            Answer::body(first.to_vec()),
            Answer::body(last.to_vec()),
        ])
        .await;
        let github = crate::intel::stream::by_stream(crate::intel::providers::github::NPM_STREAM)
            .expect("this build declares it");
        let declared = Stream {
            url: Box::leak(format!("http://{addr}/graphql").into_boxed_str()),
            ..*github
        };
        let printed = Printed::default();
        let fetched = stream_bundle(&client(), &declared, Some("token"), &printed.notice())
            .await
            .expect("two pages");
        let array: serde_json::Value = serde_json::from_slice(&fetched.bytes).expect("an array");
        assert_eq!(array.as_array().map(Vec::len), Some(2));
    }

    /// A GitHub page that cannot be fetched, or arrives cut short, fails the fetch, and so
    /// does a bundle cut short.
    #[tokio::test]
    async fn a_page_or_bundle_that_cannot_be_read_fails() {
        let printed = Printed::default();
        let closed = crate::util::test_support::closing_server().await;
        let failure = graphql(
            &client(),
            &format!("http://{closed}/graphql"),
            4096,
            "token",
            "query",
            &printed.notice(),
        )
        .await
        .expect_err("nothing answers");
        assert!(failure.why.starts_with("fetching http"), "{}", failure.why);

        let cut = scripted(vec![Answer::cut_short()]).await;
        let failure = graphql(
            &client(),
            &format!("http://{cut}/graphql"),
            4096,
            "token",
            "query",
            &printed.notice(),
        )
        .await
        .expect_err("cut short");
        assert!(failure.why.starts_with("reading http"), "{}", failure.why);
        let failure = bundle(
            &client(),
            &format!("http://{cut}/all.zip"),
            4096,
            &printed.notice(),
        )
        .await
        .expect_err("cut short");
        assert!(failure.why.starts_with("reading http"), "{}", failure.why);
    }
}
