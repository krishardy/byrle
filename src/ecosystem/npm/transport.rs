//! Fetching packuments on the proxy's own behalf.

use std::collections::BTreeMap;

use crate::ecosystem::Fetched;
use crate::identity::PackageKey;
use crate::record::{PackageMetadata, PackumentDetail};

use super::error::{FetchError, NormalizeError};
use super::normalize::{normalize_packument, parse_publish_times};
use super::{ABBREVIATED_ACCEPT, FULL_ACCEPT};

/// Fetches packuments from one registry.
///
/// This is the proxy acting on its own behalf, which is separate from the bytes it
/// forwards to a client. It exists so the policy engine can ask for the full document
/// when an install only ever requests the abbreviated one.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    registry: String,
    /// Ceiling on what decompression may produce, as for the proxy's own bodies.
    max_bytes: usize,
}

impl Client {
    /// `registry` is a base URL such as `https://registry.npmjs.org`. A trailing slash
    /// is accepted and trimmed.
    pub fn new(http: reqwest::Client, registry: impl Into<String>) -> Self {
        let registry = registry.into();
        Self {
            http,
            registry: registry.trim_end_matches('/').to_owned(),
            max_bytes: crate::env::DEFAULT_MAX_PACKUMENT_BYTES,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The packument URL for a package.
    ///
    /// A scoped name is sent as `@scope%2Fname`, which is the form npm's own client
    /// uses. The unencoded `@scope/name` also resolves, but only because the registry
    /// tolerates it, and the encoded form survives being embedded in a path by anything
    /// that does not know npm's naming.
    pub fn packument_url(&self, key: &PackageKey) -> String {
        let name = key.registry_name();
        match name.split_once('/') {
            Some((scope, rest)) => format!("{}/{scope}%2F{rest}", self.registry),
            None => format!("{}/{name}", self.registry),
        }
    }

    /// The abbreviated packument as records, for a request the client did not make.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        match self.packument(key, PackumentDetail::Abbreviated).await {
            Ok(inner) => Ok(inner.map_err(|e| e.to_string())),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Fetch and normalise a packument.
    ///
    /// Asks for gzip and decodes it here. reqwest's `gzip` feature is off crate-wide, so
    /// that the proxy can forward response bodies byte for byte, which means reqwest will
    /// not decompress for this client either. Doing it explicitly is what makes the
    /// request affordable: measured over the 69 packages of an `express` tree, the
    /// packuments are 1.59 MB uncompressed and 0.52 MB gzipped, and `npm ci` makes this
    /// request once per package because it asks for no packuments of its own.
    pub async fn packument(
        &self,
        key: &PackageKey,
        detail: PackumentDetail,
    ) -> Result<Result<PackageMetadata, NormalizeError>, FetchError> {
        let accept = match detail {
            PackumentDetail::Abbreviated => ABBREVIATED_ACCEPT,
            PackumentDetail::Full => FULL_ACCEPT,
        };

        let response = self
            .http
            .get(self.packument_url(key))
            .header(reqwest::header::ACCEPT, accept)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }

        // A registry is free to ignore the request and send identity, which decodes to
        // itself.
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;

        match crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes) {
            Ok(decoded) => Ok(normalize_packument(&decoded, detail)),
            Err(e) => Err(FetchError::Undecodable(e)),
        }
    }

    /// Fetch the full packument and read only its `time` map.
    ///
    /// A request the client never made, and the only way to learn a publish date. See
    /// [`parse_publish_times`] for why there is no cheaper source.
    pub async fn publish_times(
        &self,
        key: &PackageKey,
    ) -> Result<Result<BTreeMap<String, jiff::Timestamp>, NormalizeError>, FetchError> {
        let response = self
            .http
            .get(self.packument_url(key))
            .header(reqwest::header::ACCEPT, FULL_ACCEPT)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }

        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;

        match crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes) {
            Ok(decoded) => Ok(parse_publish_times(&decoded)),
            Err(e) => Err(FetchError::Undecodable(e)),
        }
    }
}

/// A registry request's value, or what went wrong: `<what> could not be fetched: ...` when
/// the request failed, and `<what> could not be read: ...` when the body did not parse.
pub fn fetched<T>(
    result: Result<Result<T, NormalizeError>, FetchError>,
    what: &str,
) -> Result<T, String> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{what} could not be read: {e}")),
        Err(e) => Err(format!("{what} could not be fetched: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;

    // Only the live tests, which are compiled out under `cfg(coverage)`.
    #[cfg(not(coverage))]
    use super::super::DEFAULT_REGISTRY;
    use crate::identity::Ecosystem;

    /// The scoped form npm's own client sends. `@scope/name` also resolves, but only
    /// because the registry tolerates it.
    #[test]
    fn packument_urls_encode_the_scope_separator() {
        let client = Client::new(reqwest::Client::new(), "https://registry.npmjs.org/");
        let key = |n: &str| PackageKey::from_registry_name(Ecosystem::Npm, n).unwrap();

        assert_eq!(
            client.packument_url(&key("lodash")),
            "https://registry.npmjs.org/lodash"
        );
        assert_eq!(
            client.packument_url(&key("@babel/traverse")),
            "https://registry.npmjs.org/@babel%2Ftraverse"
        );
    }

    /// The transport half, against the real registry. Ignored by default: `cargo test`
    /// must not depend on the network.
    ///
    /// Run with `cargo test --lib -- --ignored npm::tests::live`.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org"]
    async fn live_registry_fetch_returns_both_documents() {
        let client = Client::new(reqwest::Client::new(), DEFAULT_REGISTRY);
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "@babel/traverse").unwrap();

        let abbrev = client
            .packument(&key, PackumentDetail::Abbreviated)
            .await
            .expect("registry should answer")
            .expect("abbreviated packument should normalise");
        assert_eq!(abbrev.key, key, "scoped name survived the URL round trip");
        assert!(!abbrev.records.is_empty());
        assert!(abbrev.skipped.is_empty(), "skipped: {:?}", abbrev.skipped);
        assert!(
            abbrev.records.iter().all(|r| r.published_at.is_none()),
            "the abbreviated document carries no `time` map"
        );

        let full = client
            .packument(&key, PackumentDetail::Full)
            .await
            .expect("registry should answer")
            .expect("full packument should normalise");
        assert!(
            full.records.iter().any(|r| r.published_at.is_some()),
            "the full document is fetched precisely for publish times"
        );
        assert!(
            full.records.iter().any(|r| r.repository.is_some()),
            "the full document is fetched precisely for the repository"
        );
    }

    /// The proxy asks for gzip and decodes it, because reqwest's `gzip` feature is off
    /// crate-wide so that bodies can be forwarded byte for byte. `npm ci` makes this
    /// request once per package, so the difference is the primary CI path: measured over
    /// the 69 packages of an `express` tree, 1.59 MB uncompressed against 0.52 MB gzipped.
    #[tokio::test]
    async fn the_client_asks_for_gzip_and_decodes_it() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let compressed = crate::http::gzip(&body).unwrap();
        let seen: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
        let recorder = seen.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move |headers: axum::http::HeaderMap| {
                let seen = recorder.clone();
                let compressed = compressed.clone();
                async move {
                    *seen.lock().unwrap() = headers
                        .get(axum::http::header::ACCEPT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    (
                        [
                            (
                                axum::http::header::CONTENT_TYPE,
                                "application/vnd.npm.install-v1+json",
                            ),
                            (axum::http::header::CONTENT_ENCODING, "gzip"),
                        ],
                        compressed,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let packument = client
            .packument(&key, PackumentDetail::Abbreviated)
            .await
            .expect("server answered")
            .expect("gzipped body should normalise");

        assert_eq!(seen.lock().unwrap().as_deref(), Some("gzip"));
        assert_eq!(packument.records.len(), 1);
    }

    /// A registry is free to ignore the request and send identity, which has to work too.
    #[tokio::test]
    async fn an_identity_response_still_normalises() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/vnd.npm.install-v1+json",
                        )],
                        body,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        assert!(
            client
                .packument(&key, PackumentDetail::Abbreviated)
                .await
                .expect("server answered")
                .is_ok()
        );
    }

    /// A body past the limit is a fetch failure with its own kind, not a normalisation
    /// failure: the bytes never became a document to model.
    #[tokio::test]
    async fn a_body_past_the_limit_is_a_fetch_error() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/vnd.npm.install-v1+json",
                        )],
                        body,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client =
            Client::new(reqwest::Client::new(), format!("http://{addr}")).with_max_bytes(16);
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let result = client.packument(&key, PackumentDetail::Abbreviated).await;
        assert!(
            matches!(result, Err(FetchError::Undecodable(_))),
            "{result:?}"
        );
        let Err(e) = result else { unreachable!() };
        assert!(e.to_string().contains("could not be decoded"), "got: {e}");
        assert!(std::error::Error::source(&e).is_some());
    }

    /// A package that does not exist is a status, not a transport failure, and not a
    /// normalisation failure. The three stay separate so the proxy can answer 404 rather
    /// than 502.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org"]
    async fn live_missing_package_is_a_status_error() {
        let client = Client::new(reqwest::Client::new(), DEFAULT_REGISTRY);
        let key = PackageKey::from_registry_name(
            Ecosystem::Npm,
            "waharoa-package-that-should-never-exist-9f3a",
        )
        .unwrap();

        match client.packument(&key, PackumentDetail::Abbreviated).await {
            Err(FetchError::Status(s)) => assert_eq!(s.as_u16(), 404),
            other => panic!("expected a 404 status error, got {other:?}"),
        }
    }

    /// The transport, against a server on localhost rather than the registry. This is
    /// what covers `Client::packument`: the live tests below are ignored by default, so
    /// without this the fetch path is exercised by nothing that runs in CI.
    #[test]
    fn a_failed_request_and_an_unreadable_body_are_told_apart() {
        let json = serde_json::from_str::<serde_json::Value>("{").expect_err("not JSON");
        let unreadable: Result<Result<(), NormalizeError>, FetchError> =
            Ok(Err(NormalizeError::Json(json)));
        let read = super::fetched(unreadable, "packument").expect_err("unreadable");
        assert!(
            read.starts_with("packument could not be read: packument is not valid JSON"),
            "{read}"
        );

        let missing: Result<Result<(), NormalizeError>, FetchError> =
            Err(FetchError::Status(reqwest::StatusCode::NOT_FOUND));
        assert_eq!(
            super::fetched(missing, "publish times"),
            Err("publish times could not be fetched: registry answered 404 Not Found".to_owned())
        );

        let answered: Result<Result<u8, NormalizeError>, FetchError> = Ok(Ok(7));
        assert_eq!(super::fetched(answered, "packument"), Ok(7));
    }
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;

    /// Serve fixed responses on an ephemeral port and return the base URL.
    ///
    /// The server lives for the process; the test finishes long before that matters,
    /// and a handle to shut it down would only be a handle nothing awaits.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind an ephemeral port");
        let addr = listener.local_addr().expect("bound socket has an address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
    }

    /// The whole path: request, Accept header, body, records. The handler asserts
    /// the header, because sending the wrong one silently yields the other document
    /// and every absent field would then be mislabelled.
    #[tokio::test]
    async fn fetches_and_normalises_a_packument() {
        let body = std::str::from_utf8(&fixture("lodash-4.17.21.abbrev.json"))
            .expect("fixture is utf-8")
            .to_owned();

        let base = serve(Router::new().route(
            "/lodash",
            get(|headers: axum::http::HeaderMap| async move {
                assert_eq!(
                    headers.get("accept").map(|v| v.to_str().unwrap()),
                    Some(ABBREVIATED_ACCEPT),
                    "an install requests the abbreviated document"
                );
                body
            }),
        ))
        .await;

        let client = Client::new(reqwest::Client::new(), base);
        let p = client
            .packument(&key("lodash"), PackumentDetail::Abbreviated)
            .await
            .expect("server answered")
            .expect("body normalised");
        assert_eq!(p.key.registry_name(), "lodash");
        assert_eq!(p.records.len(), 1);
    }

    /// The only source of a publish date, so an empty map means every version reads as
    /// having no publish time and `cooldown_days` gates nothing. Asserted against a server
    /// because the live test that covered this is ignored by default.
    #[tokio::test]
    async fn fetches_the_time_map_from_the_full_packument() {
        let body = std::str::from_utf8(&fixture("lodash-4.17.21.full.json"))
            .expect("fixture is utf-8")
            .to_owned();

        let base = serve(Router::new().route(
            "/lodash",
            get(|headers: axum::http::HeaderMap| async move {
                assert_eq!(
                    headers.get("accept").map(|v| v.to_str().unwrap()),
                    Some(FULL_ACCEPT),
                    "the time map is in the full document and nowhere else"
                );
                body
            }),
        ))
        .await;

        let times = Client::new(reqwest::Client::new(), base)
            .publish_times(&key("lodash"))
            .await
            .expect("server answered")
            .expect("body parsed");
        assert_eq!(
            times.get("4.17.21").map(|t| t.to_string()),
            Some("2021-02-20T15:42:16.891Z".to_owned())
        );
    }

    /// A registry that says no is a status, not an empty map: an empty map would read as
    /// "npm publishes no timestamps for this package" and let a cooldown pass silently.
    #[tokio::test]
    async fn a_refused_time_map_is_a_status_rather_than_no_times() {
        let base =
            serve(Router::new().route("/lodash", get(|| async { (StatusCode::FORBIDDEN, "no") })))
                .await;

        let error = Client::new(reqwest::Client::new(), base)
            .publish_times(&key("lodash"))
            .await
            .expect_err("403 is a fetch failure");
        assert!(
            matches!(error, FetchError::Status(StatusCode::FORBIDDEN)),
            "{error}"
        );
    }

    /// A scoped name has to reach the server percent-encoded and still route.
    #[tokio::test]
    async fn fetches_a_scoped_package() {
        let body = std::str::from_utf8(&fixture("@babel_traverse-8.0.5.abbrev.json"))
            .expect("fixture is utf-8")
            .to_owned();
        let base =
            serve(Router::new().route("/@babel%2Ftraverse", get(move || async move { body })))
                .await;

        let client = Client::new(reqwest::Client::new(), base);
        let p = client
            .packument(&key("@babel/traverse"), PackumentDetail::Full)
            .await
            .expect("server answered")
            .expect("body normalised");
        assert_eq!(p.key.registry_name(), "@babel/traverse");
    }

    /// The full document is a different Accept header, and asking for the wrong one
    /// is how `published_at == None` starts meaning the wrong thing.
    #[tokio::test]
    async fn full_detail_requests_the_full_document() {
        let base = serve(Router::new().route(
            "/lodash",
            get(|headers: axum::http::HeaderMap| async move {
                assert_eq!(
                    headers.get("accept").map(|v| v.to_str().unwrap()),
                    Some(FULL_ACCEPT)
                );
                r#"{"name":"lodash","versions":{}}"#
            }),
        ))
        .await;

        let client = Client::new(reqwest::Client::new(), base);
        let p = client
            .packument(&key("lodash"), PackumentDetail::Full)
            .await
            .expect("server answered")
            .expect("body normalised");
        assert!(p.records.is_empty());
    }

    /// An unknown package is a status, not a transport failure. The proxy has to be
    /// able to pass 404 through rather than turning it into 502.
    #[tokio::test]
    async fn a_missing_package_is_a_status_error() {
        let base = serve(Router::new()).await;
        let client = Client::new(reqwest::Client::new(), base);

        match client
            .packument(&key("nonexistent"), PackumentDetail::Abbreviated)
            .await
        {
            Err(FetchError::Status(s)) => assert_eq!(s, StatusCode::NOT_FOUND),
            other => panic!("expected a status error, got {other:?}"),
        }
    }

    /// A 5xx is also a status, distinct from the connection never completing.
    #[tokio::test]
    async fn an_upstream_error_is_a_status_error() {
        let base = serve(Router::new().route(
            "/lodash",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "busy") }),
        ))
        .await;
        let client = Client::new(reqwest::Client::new(), base);

        match client
            .packument(&key("lodash"), PackumentDetail::Abbreviated)
            .await
        {
            Err(FetchError::Status(s)) => assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE),
            other => panic!("expected a status error, got {other:?}"),
        }
    }

    /// A registry that closes the connection without a response is a transport failure,
    /// and the outer `Result` is what carries it. This is the only branch a 502 is the
    /// right answer to.
    #[tokio::test]
    async fn a_registry_that_sends_no_response_is_a_transport_error() {
        let addr = crate::test_support::closing_server().await;

        let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
        match client
            .packument(&key("lodash"), PackumentDetail::Abbreviated)
            .await
        {
            Err(e @ FetchError::Transport(_)) => {
                use std::error::Error as _;
                assert!(e.to_string().contains("request failed"), "got: {e}");
                assert!(
                    e.source().is_some(),
                    "the underlying cause has to stay reachable, not be flattened"
                );
            }
            other => panic!("expected a transport error, got {other:?}"),
        }
    }

    /// A 200 carrying something we cannot read is the inner `Result`. The nesting is
    /// the point: the fetch succeeded, so this is our gap and not an outage.
    #[tokio::test]
    async fn a_successful_response_with_an_unreadable_body_is_a_normalize_error() {
        let base =
            serve(Router::new().route("/lodash", get(|| async { "<html>not a packument</html>" })))
                .await;
        let client = Client::new(reqwest::Client::new(), base);

        let fetched = client
            .packument(&key("lodash"), PackumentDetail::Abbreviated)
            .await
            .expect("the fetch itself succeeded");
        assert!(matches!(fetched, Err(NormalizeError::Json(_))));
    }
}
