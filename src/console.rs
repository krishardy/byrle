//! The admin console: where it answers, and its routes. Stage 4.9 builds it up from here:
//! its health check, login, logout and session. See docs/admin-plan.md.

pub mod alerts;
pub mod api;
pub mod config;
pub mod login;
pub mod logs;
pub mod openapi;
pub mod routes;
pub mod status;
pub mod usage;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;

use crate::account::Accounts;
use crate::account::events::EventLog;
use crate::account::gate::Gate;
use crate::account::password::Hasher;
use crate::env::{self, EnvError};
use crate::mount::{self, Mount};

/// Under the console's path, answered with no session or token, for an outside monitor.
pub const HEALTH_PATH: &str = "/api/v1/health";

/// Under the console's path: `POST` an account and password for a session.
pub const LOGIN_PATH: &str = "/api/v1/login";

/// Under the console's path: `POST` to end the session.
pub const LOGOUT_PATH: &str = "/api/v1/logout";

/// Under the console's path: `GET` who the caller is.
pub const SESSION_PATH: &str = "/api/v1/session";

/// Where the console answers, read from [`env::CONSOLE_URL`] and [`env::CONSOLE_LISTEN`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Console {
    pub url: String,
    pub mount: Mount,
    /// The console's own listener. `None` when it shares the proxy's.
    pub listen: Option<String>,
    /// The key nginx sends, which makes `X-Forwarded-For` name the client.
    pub rp_key: Option<crate::reverse_proxy::RpKey>,
    /// Where the proxy answers, [`env::PROXY_URL`]'s path, for the status checks.
    pub proxy_mount: Mount,
}

impl Console {
    /// The console the environment asks for, or `None`. Refused when its path is the
    /// proxy's, when the two share a listener and either path contains the other, or when
    /// [`env::CONSOLE_LISTEN`] is set without [`env::CONSOLE_URL`].
    pub fn from_env<L: Fn(&str) -> Option<std::ffi::OsString>>(
        environment: &env::Env<L>,
        proxy_listen: &str,
    ) -> Result<Option<Console>, EnvError> {
        let configured = environment.console_listen()?;
        let Some((url, mount)) = environment.console_url()? else {
            return match configured {
                Some(value) => Err(EnvError {
                    var: env::CONSOLE_LISTEN.name,
                    value,
                    reason: format!(
                        "is set, and {} is not: there is no console",
                        env::CONSOLE_URL
                    ),
                }),
                None => Ok(None),
            };
        };
        if let Some(reason) = insecure(&url) {
            return Err(EnvError {
                var: env::CONSOLE_URL.name,
                value: url,
                reason: reason.to_owned(),
            });
        }
        let listen = configured.filter(|listen| listen != proxy_listen);
        let proxy = environment.proxy_mount()?;
        if let Some(reason) = mount::conflict(&proxy, &mount, listen.is_none()) {
            return Err(EnvError {
                var: env::CONSOLE_URL.name,
                value: url,
                reason: format!("{reason} ({} is {})", env::PROXY_URL, proxy),
            });
        }
        Ok(Some(Console {
            url,
            mount,
            listen,
            rp_key: environment.rp_key()?,
            proxy_mount: proxy,
        }))
    }
}

/// Why `url` cannot carry the session cookie, which is `Secure`: `http` to a host other
/// than loopback, where a browser does not keep it. `None` for any other.
fn insecure(url: &str) -> Option<&'static str> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    (parsed.scheme() == "http" && !loopback).then_some(
        "is http to a host other than loopback, where a browser does not keep the session \
         cookie; use https, through nginx as docs/fronting-tls.md shows",
    )
}

/// The console as it runs: where it answers, and the accounts it logs in against.
pub struct Site {
    pub console: Console,
    login: login::Login,
    gate: Gate,
    store: Arc<dyn Accounts>,
    /// The usage tables. `None` until [`Site::with_usage`] is called.
    usage: Option<Arc<dyn crate::usage::Usage>>,
    /// The proxy beside it. `None` until [`Site::with_proxy`] is called.
    configured: Option<config::Configured>,
    /// [`env::AUDIT_LOG`], for R5 and R9.
    audit_log: Option<std::path::PathBuf>,
    /// [`env::ACCOUNT_EVENT_LOG`], for R8.
    event_log: Option<std::path::PathBuf>,
    /// `scheme://host[:port]` of [`Console::url`], which a browser's `Origin` matches.
    origin: String,
    /// The usage rows dropped when last checked, for R10.
    dropped: std::sync::Mutex<status::Dropped>,
    /// The last round of R10's checks.
    checked: status::Cache,
}

impl Site {
    /// `console`, logging in against `store` with `hasher` and within `limits`, writing
    /// logins to `events`.
    pub fn new(
        console: Console,
        store: Arc<dyn Accounts>,
        (hasher, limits): (Hasher, login::Limits),
        events: Option<Arc<EventLog>>,
    ) -> Self {
        let origin = reqwest::Url::parse(&console.url)
            .map(|url| url.origin().ascii_serialization())
            .expect("the console URL parsed when it was read");
        Self {
            login: login::Login::new(store.clone(), hasher, limits, events),
            gate: Gate::new(store.clone()),
            store,
            usage: None,
            configured: None,
            audit_log: None,
            event_log: None,
            origin,
            dropped: std::sync::Mutex::default(),
            checked: std::sync::Mutex::default(),
            console,
        }
    }

    /// Read R3 and R6 from `usage`.
    pub fn with_usage(mut self, usage: Arc<dyn crate::usage::Usage>) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Read R5 and R9 from `audit_log`, and R8 from `event_log`, each with its rotated
    /// files.
    pub fn with_logs(
        mut self,
        audit_log: Option<std::path::PathBuf>,
        event_log: Option<std::path::PathBuf>,
    ) -> Self {
        self.audit_log = audit_log;
        self.event_log = event_log;
        self
    }

    /// Describe `proxy`, started with `settings` and answering at `reached_at`, for R7 and
    /// R10.
    pub fn with_proxy(
        mut self,
        proxy: crate::proxy::Proxy,
        settings: Vec<crate::env::Setting>,
        reached_at: String,
    ) -> Self {
        self.configured = Some(config::Configured {
            proxy,
            settings,
            reached_at,
        });
        self
    }

    /// The console's [`routes::ROUTES`], each under its path. Any other request goes to
    /// `rest`.
    fn router(self: &Arc<Self>, rest: Router) -> Router {
        let under = self.console.mount.to_string();
        routes::router(self.clone(), under.trim_end_matches('/')).fallback_service(rest)
    }
}

/// Each address to listen on and what it serves. The proxy's `listen` serves `proxy`, with
/// the console's routes in front of it when the two share it; the proxy answers 404
/// outside its own path. A console with a listener of its own is served there alone.
pub fn listeners(proxy: Router, listen: &str, site: Option<&Arc<Site>>) -> Vec<(String, Router)> {
    match site {
        None => vec![(listen.to_owned(), proxy)],
        Some(site) => match &site.console.listen {
            None => vec![(listen.to_owned(), site.router(proxy))],
            Some(own) => vec![
                (listen.to_owned(), proxy),
                (
                    own.clone(),
                    site.router(Router::new().fallback(|| async { StatusCode::NOT_FOUND })),
                ),
            ],
        },
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::env::testing::with;
    use crate::proxy::testing::serve;

    /// `console` running against `store` and empty usage tables, with a cheap hasher, no
    /// event log, and a proxy served beside it.
    pub async fn site(console: Console, store: Arc<dyn Accounts>) -> Arc<Site> {
        let usage = Arc::new(crate::usage::tests::Kept::default());
        let intel = Arc::new(crate::intel::store::testing::knowing_nothing());
        let proxy = crate::proxy::Proxy::new(reqwest::Client::new()).with_intel(Some(intel));
        let at = serve(proxy.clone().router()).await;
        let missing = |name: &str| Some(std::path::Path::new("/nonexistent/byrle").join(name));
        Arc::new(
            unread(console, store)
                .with_usage(usage)
                .with_proxy(proxy, Vec::new(), at)
                .with_logs(missing("audit.log"), missing("events.log")),
        )
    }

    /// [`site`] with no usage tables.
    pub fn unread(console: Console, store: Arc<dyn Accounts>) -> Site {
        let hasher = crate::account::password::tests::cheap();
        let limits = crate::console::login::tests::limits();
        Site::new(console, store, (hasher, limits), None)
    }

    /// The console at `https://h/admin/` on its own listener, served, with its base URL.
    pub async fn served(store: Arc<dyn Accounts>) -> (Arc<Site>, String) {
        let console = Console {
            url: "https://h/admin/".into(),
            mount: Mount::from_url("https://h/admin/").unwrap(),
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: Mount::ROOT,
        };
        let site = site(console, store).await;
        let (_, router) = listeners(Router::new(), LISTEN, Some(&site)).pop().unwrap();
        (site, serve(router).await)
    }

    /// Plain http keeps the session cookie only on loopback.
    #[test]
    fn a_console_on_http_must_be_on_loopback() {
        for url in [
            "http://localhost:8080/admin/",
            "http://127.0.0.1/",
            "http://[::1]:9090/",
            "https://h/admin/",
        ] {
            assert_eq!(insecure(url), None, "{url}");
        }
        for url in [
            "http://h/admin/",
            "http://10.0.0.1/",
            "http://[2001:db8::1]/",
        ] {
            assert!(insecure(url).unwrap().contains("use https"), "{url}");
        }
        assert_eq!(insecure("not a url"), None);
        assert_eq!(insecure("mailto:admin@h"), None, "a URL with no host");
        let refused = console(&[
            (env::PROXY_URL, "https://h/registry/"),
            (env::CONSOLE_URL, "http://h/admin/"),
        ])
        .unwrap_err();
        assert_eq!(refused.var, env::CONSOLE_URL.name);
    }

    const LISTEN: &str = "127.0.0.1:8080";

    fn console(vars: &[(env::Var, &str)]) -> Result<Option<Console>, EnvError> {
        Console::from_env(&with(vars), LISTEN)
    }

    #[test]
    fn no_console_url_is_no_console() {
        assert_eq!(console(&[]), Ok(None));
        assert_eq!(
            console(&[(env::PROXY_URL, "https://h/registry/")]),
            Ok(None)
        );
    }

    #[test]
    fn an_unreadable_console_listener_is_refused_by_name() {
        let unread = crate::env::testing::with_unreadable(
            &[(env::CONSOLE_URL, "https://h/admin/")],
            env::CONSOLE_LISTEN,
        );
        let refused = Console::from_env(&unread, LISTEN).unwrap_err();
        assert_eq!(refused.var, env::CONSOLE_LISTEN.name);
    }

    #[test]
    fn a_console_listener_without_a_console_url_is_refused() {
        let refused = console(&[(env::CONSOLE_LISTEN, "127.0.0.1:9090")]).unwrap_err();
        assert_eq!(refused.var, env::CONSOLE_LISTEN.name);
        assert!(refused.reason.contains(env::CONSOLE_URL.name), "{refused}");
    }

    /// On the proxy's listener, the console needs a path the proxy's does not contain; the
    /// default, `/`, contains all. Naming the proxy's own listener is sharing it.
    #[test]
    fn a_console_on_the_proxys_listener_needs_a_path_the_proxy_does_not_contain() {
        let shared = console(&[
            (env::PROXY_URL, "https://h/registry/"),
            (env::CONSOLE_URL, "https://h/admin/"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(shared.listen, None);
        assert_eq!(shared.mount.to_string(), "/admin/");
        assert_eq!(shared.rp_key, None);
        let short_key = console(&[
            (env::PROXY_URL, "https://h/registry/"),
            (env::CONSOLE_URL, "https://h/admin/"),
            (env::RP_KEY, "short"),
        ])
        .unwrap_err();
        assert_eq!(short_key.var, env::RP_KEY.name);

        let refused = console(&[(env::CONSOLE_URL, "https://h/admin/")]).unwrap_err();
        assert_eq!(refused.var, env::CONSOLE_URL.name);
        let named_proxy = format!("{} is /", env::PROXY_URL);
        assert!(refused.reason.contains(&named_proxy), "{refused}");

        let named = console(&[
            (env::CONSOLE_URL, "https://h/admin/"),
            (env::CONSOLE_LISTEN, LISTEN),
        ]);
        assert!(named.is_err());
    }

    /// On its own listener the console may be under the proxy's path, not at it. The proxy
    /// is at `/` by default, so a console at `/` is refused.
    #[test]
    fn a_console_on_a_listener_of_its_own_needs_only_a_different_path() {
        let alone = console(&[
            (env::CONSOLE_URL, "https://admin.h:8443/admin/"),
            (env::CONSOLE_LISTEN, "127.0.0.1:9090"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(alone.listen.as_deref(), Some("127.0.0.1:9090"));

        let same = console(&[
            (env::CONSOLE_URL, "https://admin.h:8443/"),
            (env::CONSOLE_LISTEN, "127.0.0.1:9090"),
        ]);
        assert!(
            same.unwrap_err()
                .reason
                .starts_with("is the proxy's path too")
        );
    }

    #[test]
    fn a_console_url_that_names_no_path_is_refused_as_the_proxy_url_is() {
        let refused = console(&[(env::CONSOLE_URL, "ftp://h/admin/")]).unwrap_err();
        assert_eq!(refused.var, env::CONSOLE_URL.name);
        let proxy = console(&[
            (env::PROXY_URL, "https://h/?x"),
            (env::CONSOLE_URL, "https://h/admin/"),
        ]);
        assert_eq!(proxy.unwrap_err().var, env::PROXY_URL.name);
    }

    fn teapot() -> Router {
        Router::new().fallback(|| async { (StatusCode::IM_A_TEAPOT, "proxy") })
    }

    async fn status(base: &str, path: &str) -> StatusCode {
        reqwest::get(format!("{base}{path}"))
            .await
            .unwrap()
            .status()
    }

    /// Sharing the proxy's listener, the console answers under its path and the proxy
    /// answers the rest.
    #[tokio::test]
    async fn a_shared_listener_serves_the_console_under_its_path_and_the_proxy_elsewhere() {
        let shared = Console {
            url: "https://h/admin/".into(),
            mount: Mount::from_url("https://h/admin/").unwrap(),
            listen: None,
            rp_key: None,
            proxy_mount: Mount::ROOT,
        };
        let store = Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let served = listeners(teapot(), LISTEN, Some(&site(shared, store).await));
        assert_eq!(served.len(), 1);
        let (at, router) = served.into_iter().next().unwrap();
        assert_eq!(at, LISTEN);
        let base = serve(router).await;

        let health = reqwest::get(format!("{base}/admin{HEALTH_PATH}"))
            .await
            .unwrap();
        assert_eq!(health.status(), 200);
        assert_eq!(
            health.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        assert_eq!(health.text().await.unwrap(), r#"{"status":"up"}"#);
        assert_eq!(status(&base, "/lodash").await, StatusCode::IM_A_TEAPOT);
        assert_eq!(status(&base, HEALTH_PATH).await, StatusCode::IM_A_TEAPOT);
    }

    /// With a listener of its own, the console answers there, at the root if its path is
    /// the root, and 404 to anything else. The proxy's listener serves the proxy alone.
    #[tokio::test]
    async fn a_console_listener_of_its_own_serves_the_console_alone() {
        let alone = Console {
            url: "https://admin.h/".into(),
            mount: Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: Mount::ROOT,
        };
        let store = Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let served = listeners(teapot(), LISTEN, Some(&site(alone, store).await));
        let addresses: Vec<&str> = served.iter().map(|(at, _)| at.as_str()).collect();
        assert_eq!(addresses, [LISTEN, "127.0.0.1:9090"]);
        let mut routers = served.into_iter().map(|(_, router)| router);
        let proxy = serve(routers.next().unwrap()).await;
        let console = serve(routers.next().unwrap()).await;

        assert_eq!(status(&proxy, HEALTH_PATH).await, StatusCode::IM_A_TEAPOT);
        assert_eq!(status(&console, HEALTH_PATH).await, StatusCode::OK);
        assert_eq!(status(&console, "/lodash").await, StatusCode::NOT_FOUND);
    }

    /// Without a console, the proxy's listener serves the proxy.
    #[tokio::test]
    async fn no_console_is_the_proxy_alone() {
        let served = listeners(teapot(), LISTEN, None);
        assert_eq!(served.len(), 1);
        let base = serve(served.into_iter().next().unwrap().1).await;
        assert_eq!(status(&base, HEALTH_PATH).await, StatusCode::IM_A_TEAPOT);
    }
}
