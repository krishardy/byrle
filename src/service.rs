//! One upstream service's client: the headers it may send, and the redirects it follows.
//! See docs/engineering_decisions/0133-a-client-for-each-service.md.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Certificate, IntoUrl, Method, Url};

use crate::tls::{TrustError, TrustMode};

/// The most redirects one request follows, as reqwest's default policy has it.
pub const MAX_REDIRECTS: usize = 10;

/// The headers that carry a credential, which keep a redirect on its first URL's origin.
pub const CREDENTIALS: [&str; 5] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    crate::analysis::virustotal::KEY,
    crate::account::gate::TOKEN,
];

/// How each service connects: its read timeout, CA bundle, and a credential on every request.
#[derive(Clone)]
pub struct Connection {
    read_timeout: Duration,
    bundle: Option<(Vec<Certificate>, TrustMode, PathBuf)>,
    credential: Option<(HeaderName, HeaderValue)>,
    /// The client its services without a credential share, then those with one: see 0133.
    built: Arc<[OnceLock<reqwest::Client>; 2]>,
}

impl Default for Connection {
    /// [`crate::http::READ_TIMEOUT`] and the platform's roots.
    fn default() -> Self {
        Self::timing_out(crate::http::READ_TIMEOUT)
    }
}

impl Connection {
    /// The platform's roots, waiting `read_timeout` per read.
    pub fn timing_out(read_timeout: Duration) -> Self {
        Self {
            read_timeout,
            bundle: None,
            credential: None,
            built: Arc::default(),
        }
    }

    /// The same, sending `name: value` on every request each service makes.
    pub fn carrying(self, name: HeaderName, mut value: HeaderValue) -> Self {
        value.set_sensitive(true);
        Self {
            credential: Some((name, value)),
            built: Arc::default(),
            ..self
        }
    }

    /// The same, trusting `certificates` from `path` as `mode` says. Errors when the TLS
    /// backend refuses them, so each service's client builds after this.
    pub fn trusting(
        self,
        certificates: Vec<Certificate>,
        mode: TrustMode,
        path: &Path,
    ) -> Result<Self, TrustError> {
        let trusting = Self {
            bundle: Some((certificates, mode, path.to_owned())),
            built: Arc::default(),
            ..self
        };
        let builder = trusting.builder(reqwest::redirect::Policy::none());
        crate::tls::build(builder, path)?;
        Ok(trusting)
    }

    /// The client for a service that carries a credential, or for one that does not.
    fn client(&self, credentialed: bool) -> reqwest::Client {
        let made = || {
            self.builder(redirects(credentialed))
                .build()
                .expect("the connection's bundle built a client when it was made")
        };
        self.built[usize::from(credentialed)]
            .get_or_init(made)
            .clone()
    }

    /// No total timeout: see [`crate::http::READ_TIMEOUT`]. HTTP/2's window grows with the
    /// link: at hyper's default, scipy's 35 MB wheel came through a forward proxy at half
    /// curl's rate.
    fn builder(&self, redirects: reqwest::redirect::Policy) -> reqwest::ClientBuilder {
        let builder = reqwest::Client::builder()
            .user_agent(concat!("byrle/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(crate::http::CONNECT_TIMEOUT)
            .read_timeout(self.read_timeout)
            .http2_adaptive_window(true)
            .redirect(redirects);
        match &self.bundle {
            Some((certificates, mode, _)) => {
                crate::tls::apply(builder, certificates.clone(), *mode)
            }
            None => builder,
        }
    }
}

/// A service's name, for a panic, and every header it sets on a request, in lower case.
#[derive(Debug, Clone, Copy)]
pub struct Declared {
    pub name: &'static str,
    pub headers: &'static [&'static str],
}

/// A client for one service, sending only its declared headers and its connection's credential.
#[derive(Clone)]
pub struct Service {
    declared: Declared,
    credential: Option<(HeaderName, HeaderValue)>,
    http: reqwest::Client,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("name", &self.declared.name)
            .finish_non_exhaustive()
    }
}

impl Service {
    /// A client for `declared`, connecting as `connection` says, following [`may_follow`].
    pub fn new(declared: Declared, connection: &Connection) -> Self {
        let credential = connection.credential.clone();
        let credentialed =
            credential.is_some() || declared.headers.iter().any(|h| CREDENTIALS.contains(h));
        let http = connection.client(credentialed);
        Self {
            declared,
            credential,
            http,
        }
    }

    pub fn name(&self) -> &'static str {
        self.declared.name
    }

    pub fn get(&self, url: impl IntoUrl) -> Asking {
        self.request(Method::GET, url)
    }

    pub fn head(&self, url: impl IntoUrl) -> Asking {
        self.request(Method::HEAD, url)
    }

    pub fn post(&self, url: impl IntoUrl) -> Asking {
        self.request(Method::POST, url)
    }

    pub fn request(&self, method: Method, url: impl IntoUrl) -> Asking {
        let mut inner = self.http.request(method, url);
        if let Some((name, value)) = &self.credential {
            inner = inner.header(name, value);
        }
        Asking {
            declared: self.declared,
            credential: self.credential.as_ref().map(|(name, _)| name.clone()),
            inner,
        }
    }
}

/// A request being built for a service, sent only with headers it declares.
pub struct Asking {
    declared: Declared,
    credential: Option<HeaderName>,
    inner: reqwest::RequestBuilder,
}

impl Asking {
    pub fn header<K, V>(self, name: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<axum::http::Error>,
        header::HeaderValue: TryFrom<V>,
        <header::HeaderValue as TryFrom<V>>::Error: Into<axum::http::Error>,
    {
        self.map(|inner| inner.header(name, value))
    }

    pub fn headers(self, headers: HeaderMap) -> Self {
        self.map(|inner| inner.headers(headers))
    }

    pub fn basic_auth(
        self,
        user: impl std::fmt::Display,
        password: Option<impl std::fmt::Display>,
    ) -> Self {
        self.map(|inner| inner.basic_auth(user, password))
    }

    pub fn body(self, body: impl Into<reqwest::Body>) -> Self {
        self.map(|inner| inner.body(body))
    }

    pub fn timeout(self, timeout: Duration) -> Self {
        self.map(|inner| inner.timeout(timeout))
    }

    fn map(self, change: impl FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder) -> Self {
        Self {
            inner: change(self.inner),
            ..self
        }
    }

    /// Send the request. Panics on a header the service does not declare: each is set in code.
    pub async fn send(self) -> reqwest::Result<reqwest::Response> {
        let (http, request) = self.inner.build_split();
        let request = request?;
        let credential = self.credential.as_ref().map(HeaderName::as_str);
        let declared = self.declared.headers.iter().copied().chain(credential);
        if let Some(name) = undeclared(request.headers(), declared) {
            let service = self.declared.name;
            panic!("the {service} service sends `{name}`, a header it does not declare");
        }
        http.execute(request).await
    }
}

/// The redirects a client follows: those [`may_follow`] allows.
fn redirects(credentialed: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let previous = attempt.previous();
        let (first, last) = (previous.first(), previous.last());
        let (first, last) = (
            first.expect("a redirect follows a request"),
            last.expect("one"),
        );
        match may_follow(first, last, attempt.url(), previous.len(), credentialed) {
            true => attempt.follow(),
            false => attempt.stop(),
        }
    })
}

/// The first header in `headers` that is not in `declared`.
pub fn undeclared<'a>(
    headers: &HeaderMap,
    declared: impl Iterator<Item = &'a str> + Clone,
) -> Option<HeaderName> {
    headers
        .keys()
        .find(|name| !declared.clone().any(|d| d == name.as_str()))
        .cloned()
}

/// Whether a redirect from `last` to `next` is followed, `hops` URLs after `first`: at most
/// [`MAX_REDIRECTS`], never from https to anything else, and on `first`'s origin when the
/// request carries a credential.
pub fn may_follow(first: &Url, last: &Url, next: &Url, hops: usize, credentialed: bool) -> bool {
    let downgrade = last.scheme() == "https" && next.scheme() != "https";
    let elsewhere = credentialed && first.origin() != next.origin();
    hops <= MAX_REDIRECTS && !downgrade && !elsewhere
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const PLAIN: Declared = Declared {
        name: "plain",
        headers: &["accept"],
    };

    const KEYED: Declared = Declared {
        name: "keyed",
        headers: &["authorization"],
    };

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn a_header_not_declared_is_found() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "a".parse().unwrap());
        assert_eq!(undeclared(&headers, ["accept"].into_iter()), None);
        headers.insert(header::COOKIE, "c".parse().unwrap());
        assert_eq!(
            undeclared(&headers, ["accept"].into_iter()),
            Some(header::COOKIE)
        );
    }

    #[test]
    fn a_redirect_is_followed_within_the_limit_without_a_downgrade() {
        let (a, b) = (url("https://a.test/x"), url("https://b.test/y"));
        assert!(may_follow(&a, &a, &b, 1, false));
        assert!(may_follow(&a, &a, &b, MAX_REDIRECTS, false));
        assert!(!may_follow(&a, &a, &b, MAX_REDIRECTS + 1, false));
        assert!(!may_follow(&a, &a, &url("http://b.test/y"), 1, false));
        let plain = url("http://127.0.0.1:1/x");
        assert!(may_follow(
            &plain,
            &plain,
            &url("http://127.0.0.1:2/y"),
            1,
            false
        ));
        assert!(
            !may_follow(&a, &a, &b, 1, true),
            "a credential stays on its origin"
        );
        assert!(may_follow(&a, &b, &url("https://a.test/z"), 2, true));
        assert!(!may_follow(&a, &a, &url("https://a.test:444/z"), 1, true));
    }

    /// A request with a credential follows a redirect on its own origin and stops at another.
    #[tokio::test]
    async fn a_credential_follows_a_redirect_only_on_its_origin() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let (other, asked) =
            crate::util::test_support::recorded(vec![crate::util::test_support::Answer::Status(
                204,
            )])
            .await;
        let elsewhere = format!("http://{other}/there");
        let base = crate::proxy::testing::serve(
            axum::Router::new()
                .route("/here", axum::routing::get(|| async { "here" }))
                .route(
                    "/same",
                    axum::routing::get(|| async {
                        (StatusCode::FOUND, [(header::LOCATION, "/here")]).into_response()
                    }),
                )
                .route(
                    "/away",
                    axum::routing::get(move || {
                        let to = elsewhere.clone();
                        async move { (StatusCode::FOUND, [(header::LOCATION, to)]).into_response() }
                    }),
                ),
        )
        .await;
        let connection = Connection::default();
        let keyed = Service::new(KEYED, &connection);
        assert_eq!(keyed.name(), "keyed");
        assert!(format!("{keyed:?}").contains("keyed"));
        let same = keyed
            .get(format!("{base}/same"))
            .header(header::AUTHORIZATION, "Bearer k")
            .send()
            .await
            .unwrap();
        assert_eq!(same.text().await.unwrap(), "here");
        let away = keyed.get(format!("{base}/away")).send().await.unwrap();
        assert_eq!(away.status(), 302);
        assert!(asked.lock().unwrap().is_empty());
        let token = HeaderValue::from_static("t");
        let carrying = Connection::default().carrying(crate::account::gate::TOKEN_HEADER, token);
        let tokened = Service::new(PLAIN, &carrying);
        let away = tokened.get(format!("{base}/away")).send().await.unwrap();
        assert_eq!(
            away.status(),
            302,
            "a connection's credential stays on its origin"
        );
        assert!(asked.lock().unwrap().is_empty());
        let plain = Service::new(PLAIN, &connection);
        let followed = plain.head(format!("{base}/away")).send().await.unwrap();
        assert_eq!(
            followed.status(),
            204,
            "no credential, so the redirect is followed"
        );
        assert_eq!(asked.lock().unwrap().len(), 1);
    }

    /// Each way a request is built sends only what it was given; another header panics.
    #[tokio::test]
    async fn a_request_is_sent_with_what_it_declares() {
        let (addr, asked) =
            crate::util::test_support::recorded(vec![crate::util::test_support::Answer::Status(
                204,
            )])
            .await;
        let plain = Service::new(PLAIN, &Connection::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "a/b".parse().unwrap());
        let sent = plain
            .post(format!("http://{addr}/x"))
            .headers(headers)
            .body("b")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap();
        assert_eq!(sent.status(), 204);
        let request = String::from_utf8(asked.lock().unwrap()[0].clone()).unwrap();
        assert!(request.starts_with("POST /x "), "{request}");
        assert!(plain.get("not a url").send().await.is_err());
        let undeclared = tokio::spawn(async move {
            plain
                .request(Method::GET, format!("http://{addr}/x"))
                .header(header::COOKIE, "c")
                .send()
                .await
        });
        let said = undeclared.await.unwrap_err().into_panic();
        let said = said.downcast_ref::<String>().unwrap();
        assert_eq!(
            said,
            "the plain service sends `cookie`, a header it does not declare"
        );
    }

    /// A bundle the TLS backend takes builds; one it refuses is an error naming it.
    #[test]
    fn a_connection_trusting_a_bundle_builds() {
        let fixture = |name: &str| {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/tls")
                .join(name);
            (crate::tls::load_bundle(&path).unwrap(), path)
        };
        let (certificates, path) = fixture("test-ca.pem");
        let trusting = Connection::default()
            .trusting(certificates, TrustMode::Merge, &path)
            .unwrap();
        Service::new(PLAIN, &trusting);
        let (certificates, path) = fixture("refused.pem");
        let refused = Connection::default().trusting(certificates, TrustMode::Merge, &path);
        assert!(matches!(refused, Err(TrustError::Rejected { .. })));
    }
}
