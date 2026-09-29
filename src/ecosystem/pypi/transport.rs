//! Fetching a project index on the proxy's own behalf.

use super::error::PypiError;
use super::normalize::normalize;
use super::paths::index_url;
use super::wire::{Project, parse};
use super::{MAX_INDEX_BYTES, SIMPLE_JSON};
use crate::ecosystem::Fetched;
use crate::identity::PackageKey;

/// Fetches project indexes from one simple index.
///
/// Deliberately the same shape as `npm::Client` (an `http`, a base, a byte ceiling) and
/// deliberately not sharing code with it. Stage 3 extracts the transport interface from
/// the two once both work, and two concrete implementations side by side are what that
/// extraction reads.
///
/// Where they differ is the useful part:
///
/// | | `npm::Client` | this |
/// |---|---|---|
/// | content negotiation | `Accept` picks abbreviated or full | `Accept` picks JSON over HTML, and an index may refuse |
/// | redirects | the registry serves the name as given | PEP 503 301s to the normalised name, and `normalise` avoids the round trip |
/// | encoding | asks for gzip and decodes it here | the same, for the same reason |
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    index: String,
    max_bytes: usize,
}

#[derive(Debug)]
pub enum FetchError {
    /// The request never completed: DNS, TLS, connection, timeout.
    Transport(reqwest::Error),
    /// The index answered, with something other than success.
    Status(reqwest::StatusCode),
    /// The body arrived and could not be decoded.
    Undecodable(crate::http::DecodeError),
    /// The index served something other than PEP 691 JSON. Its own HTML is the likely
    /// answer, which this build does not read.
    NotJson(Option<String>),
    /// The name or the body was unusable. Carries [`PypiError`] rather than restating it.
    Unreadable(PypiError),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "index request failed: {e}"),
            Self::Status(s) => write!(f, "index answered {s}"),
            Self::Undecodable(e) => write!(f, "index body could not be decoded: {e}"),
            Self::NotJson(got) => write!(
                f,
                "the index served `{}` rather than PEP 691 JSON",
                got.as_deref().unwrap_or("no content type")
            ),
            Self::Unreadable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl Client {
    /// `index` is a base URL such as `https://pypi.org/simple`. A trailing slash is
    /// accepted and trimmed.
    pub fn new(http: reqwest::Client, index: impl Into<String>) -> Self {
        let index = index.into();
        Self {
            http,
            index: index.trim_end_matches('/').to_owned(),
            max_bytes: MAX_INDEX_BYTES,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// One project's index as records, for a request the client did not make.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        match self.project(key.name()).await {
            Ok(project) => Ok(normalize(&project).map_err(|e| e.to_string())),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Fetch one project's index and read it.
    ///
    /// The name is normalised before the request rather than after a redirect: PEP 503
    /// says the index redirects a non-normalised name, so asking for the normalised one
    /// saves the round trip and makes one project one request whatever the client spelled.
    ///
    /// Both simple-index forms are read: PEP 691 JSON, and the PEP 503 page an index that
    /// has not implemented PEP 691 answers with. Anything else is an error rather than a
    /// silent empty project.
    pub async fn project(&self, name: &str) -> Result<Project, FetchError> {
        let url = index_url(&self.index, name).map_err(FetchError::Unreadable)?;
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, SIMPLE_JSON)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // PEP 691 names the type exactly. A plain `application/json` is accepted too: an
        // index may serve the right document under the generic type. An index that has
        // not implemented PEP 691 answers the PEP 503 page, which `html` reads.
        let format = match crate::ecosystem::of(crate::identity::Ecosystem::PyPI)
            .document(content_type.as_deref())
        {
            Some(crate::route::DocumentKind::SimpleIndex(format)) => format,
            _ => return Err(FetchError::NotJson(content_type)),
        };
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;
        let decoded = crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes)
            .map_err(FetchError::Undecodable)?;
        match format {
            crate::route::IndexFormat::Json => parse(name, &decoded),
            crate::route::IndexFormat::Html => super::html::parse(name, &url, &decoded),
        }
        .map_err(FetchError::Unreadable)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    use super::super::fixture;

    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::routing::get;

    /// Serve fixed responses on an ephemeral port and return the base URL. The same
    /// shape `npm`'s transport tests use.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind an ephemeral port");
        let addr = listener.local_addr().expect("bound socket has an address");
        tokio::spawn(axum::serve(listener, router).into_future());
        format!("http://{addr}")
    }

    fn client(base: &str) -> Client {
        Client::new(reqwest::Client::new(), base)
    }

    /// The whole path: the normalised name in the URL, the `Accept` header, the body,
    /// the records. The handler asserts the header, because an index that is not asked
    /// for JSON answers HTML and the parse would then fail for the wrong reason.
    #[tokio::test]
    async fn asks_for_json_under_the_normalised_name_and_reads_the_index() {
        let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
        let base = serve(Router::new().route(
            // `Zope.Interface` normalises to this before the request is made, so no
            // redirect is involved.
            "/zope-interface/",
            get(|headers: axum::http::HeaderMap| async move {
                assert_eq!(
                    headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()),
                    Some(SIMPLE_JSON),
                    "an index not asked for JSON answers HTML"
                );
                ([(header::CONTENT_TYPE, SIMPLE_JSON)], body)
            }),
        ))
        .await;

        let project = client(&base)
            .project("Zope.Interface")
            .await
            .expect("the index reads");
        // The document names itself `requests`, and the document wins: it is what the
        // index says this project is.
        assert_eq!(project.name, "requests");
        assert_eq!(project.versions().len(), 3);
    }

    /// A PEP 503 page is read, with its relative hrefs resolved against the page's own
    /// URL. `www.piwheels.org` writes them that way.
    #[tokio::test]
    async fn a_pep_503_page_is_read_and_its_relative_hrefs_resolved() {
        const PAGE: &str = r#"<a href="x-1.0.tar.gz#sha256=ab">x-1.0.tar.gz</a>"#;
        let base = serve(Router::new().route(
            "/x/",
            get(|| async { ([(header::CONTENT_TYPE, "text/html")], PAGE) }),
        ))
        .await;
        let project = client(&base).project("x").await.expect("the page reads");
        assert_eq!(project.files.len(), 1);
        assert_eq!(
            project.files[0].url,
            format!("{base}/x/x-1.0.tar.gz#sha256=ab")
        );
    }

    /// A body that is neither form is an error rather than an empty project: an empty
    /// project reads as a package the index does not have.
    #[tokio::test]
    async fn a_body_that_is_neither_form_is_refused() {
        let base = serve(Router::new().route(
            "/x/",
            get(|| async { ([(header::CONTENT_TYPE, "application/octet-stream")], "...") }),
        ))
        .await;
        let error = client(&base).project("x").await.expect_err("not an index");
        assert!(
            matches!(&error, FetchError::NotJson(Some(t)) if t.starts_with("application/octet-stream")),
            "{error}"
        );
    }

    /// An HTML page with no distribution on it is an error too.
    #[tokio::test]
    async fn html_with_no_files_is_refused_rather_than_read_as_no_versions() {
        let base = serve(Router::new().route(
            "/x/",
            get(|| async { ([(header::CONTENT_TYPE, "text/html")], "<html></html>") }),
        ))
        .await;
        let error = client(&base).project("x").await.expect_err("no files");
        assert!(
            matches!(&error, FetchError::Unreadable(PypiError::NotHtml(_))),
            "{error}"
        );
    }

    /// An index may serve the right document under the generic type.
    #[tokio::test]
    async fn a_generic_json_content_type_is_accepted() {
        let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
        let base = serve(Router::new().route(
            "/requests/",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], body) }),
        ))
        .await;
        assert!(client(&base).project("requests").await.is_ok());
    }

    #[tokio::test]
    async fn a_project_the_index_does_not_have_is_its_status() {
        let base = serve(Router::new().route(
            "/missing/",
            get(|| async { (StatusCode::NOT_FOUND, "no such project") }),
        ))
        .await;
        let error = client(&base).project("missing").await.expect_err("404");
        assert!(
            matches!(error, FetchError::Status(StatusCode::NOT_FOUND)),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_body_past_the_ceiling_is_refused() {
        let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
        let base = serve(Router::new().route(
            "/requests/",
            get(|| async { ([(header::CONTENT_TYPE, SIMPLE_JSON)], body) }),
        ))
        .await;
        let error = client(&base)
            .with_max_bytes(16)
            .project("requests")
            .await
            .expect_err("over the ceiling");
        assert!(matches!(error, FetchError::Undecodable(_)), "{error}");
    }

    #[tokio::test]
    async fn an_index_that_is_not_there_is_a_transport_error() {
        // Bound and dropped, so the port refuses rather than answering.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let addr = listener.local_addr().expect("has an address");
        drop(listener);
        let error = client(&format!("http://{addr}"))
            .project("x")
            .await
            .expect_err("nothing is listening");
        assert!(matches!(error, FetchError::Transport(_)), "{error}");
    }

    #[tokio::test]
    async fn a_name_that_normalises_to_nothing_never_reaches_the_network() {
        let error = client("http://127.0.0.1:1")
            .project("...")
            .await
            .expect_err("not a usable name");
        assert!(
            matches!(error, FetchError::Unreadable(PypiError::UnusableName(_))),
            "{error}"
        );
        assert!(!error.to_string().is_empty());
    }

    /// Each way a fetch for a record fails, in the words `metadata` passes on.
    #[tokio::test]
    async fn each_failure_is_said_in_its_own_words() {
        use crate::util::test_support::{Answer, closing_server, scripted};

        let json =
            |body: &'static [u8]| async move { ([(header::CONTENT_TYPE, SIMPLE_JSON)], body) };
        let base = serve(
            Router::new()
                .route("/missing/", get(|| async { StatusCode::NOT_FOUND }))
                .route(
                    "/text/",
                    get(|| async { ([(header::CONTENT_TYPE, "text/plain")], "hello") }),
                )
                .route("/untyped/", get(|| async { StatusCode::OK }))
                .route(
                    "/gzipped/",
                    get(|| async {
                        (
                            [
                                (header::CONTENT_TYPE, SIMPLE_JSON),
                                (header::CONTENT_ENCODING, "gzip"),
                            ],
                            "not gzip",
                        )
                    }),
                )
                .route(
                    "/nameless/",
                    get(move || {
                        json(
                            br#"{"name": "", "files": [{"filename": "x-1.0.tar.gz",
                            "url": "https://f/x-1.0.tar.gz", "hashes": {}}]}"#,
                        )
                    }),
                ),
        )
        .await;
        let key = |name: &str| {
            PackageKey::from_registry_name(crate::identity::Ecosystem::PyPI, name).expect("a name")
        };
        let said = |result: Fetched| match result {
            Ok(Ok(_)) => "read".to_owned(),
            Ok(Err(e)) | Err(e) => e,
        };
        for (name, starts) in [
            ("missing", "index answered 404"),
            (
                "text",
                "the index served `text/plain` rather than PEP 691 JSON",
            ),
            (
                "untyped",
                "the index served `no content type` rather than PEP 691 JSON",
            ),
            ("gzipped", "index body could not be decoded: "),
            ("nameless", "`` is not a usable project name"),
        ] {
            let got = said(client(&base).metadata(&key(name)).await);
            assert!(got.starts_with(starts), "{name}: {got}");
        }

        let closed = format!("http://{}", closing_server().await);
        let got = said(client(&closed).metadata(&key("x")).await);
        assert!(got.starts_with("index request failed: "), "{got}");

        let cut = scripted(vec![Answer::cut_short()]).await;
        let got = said(client(&format!("http://{cut}")).metadata(&key("x")).await);
        assert!(got.starts_with("index request failed: "), "{got}");
    }
}
