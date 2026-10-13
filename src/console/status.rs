//! R10: whether the proxy, its readiness, the database and the usage writes are up. See
//! docs/admin-plan.md §4.9.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use utoipa::ToSchema;

use super::Site;
use super::api::{Problem, json};
use crate::proxy::{Health, Readiness};

/// How long each check waits for an answer.
pub const TIMEOUT: Duration = Duration::from_secs(2);

/// How long one round of checks answers `health` and `status`, however often they are asked.
pub const CACHED_FOR: Duration = Duration::from_secs(5);

/// How long usage rows dropped keep the usage writes degraded.
pub const DROPPED_FOR: Duration = Duration::from_secs(15 * 60);

/// How a component is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Up,
    Degraded,
    Down,
}

/// One component checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Component {
    /// `proxy`, `readiness`, `database` or `usage-writes`.
    pub name: &'static str,
    pub status: State,
    /// Why it is not up.
    pub reason: Option<String>,
    /// When it was checked, RFC 3339.
    pub checked: String,
}

/// Each component, checked now.
#[derive(Debug, Serialize, ToSchema)]
pub struct Status {
    pub components: Vec<Component>,
}

/// The console's health: `up`, or the worst state and the components not up, by name.
#[derive(Debug, Serialize, ToSchema)]
pub struct Up {
    pub status: State,
    /// The components not up; absent when every one is.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<&'static str>,
}

/// The usage rows dropped when last checked, and when that count last rose.
#[derive(Debug, Default)]
pub struct Dropped {
    seen: u64,
    rose: Option<Instant>,
}

/// The base URL the console asks the proxy at: `listen`, with an unspecified address made
/// loopback, and the proxy's `mount`.
pub fn reached_at(listen: &str, mount: &crate::mount::Mount) -> String {
    let listen = match listen.parse::<std::net::SocketAddr>() {
        Ok(mut address) if address.ip().is_unspecified() => {
            address.set_ip(match address {
                std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
                std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
            });
            address.to_string()
        }
        _ => listen.to_owned(),
    };
    format!("http://{listen}{}", mount.to_string().trim_end_matches('/'))
}

fn component(name: &'static str, status: State, reason: Option<String>) -> Component {
    Component {
        name,
        status,
        reason,
        checked: crate::usage::second(jiff::Timestamp::now()),
    }
}

/// The usage writes, from `dropped` rows the proxy reports now.
fn usage_writes(seen: &Mutex<Dropped>, dropped: u64, now: Instant) -> Component {
    let mut seen = seen.lock().expect("dropped lock");
    if dropped > seen.seen {
        seen.seen = dropped;
        seen.rose = Some(now);
    }
    match seen
        .rose
        .filter(|rose| now.saturating_duration_since(*rose) < DROPPED_FOR)
    {
        Some(_) => component(
            "usage-writes",
            State::Degraded,
            Some(format!(
                "{dropped} usage rows dropped since the proxy started, the last within 15 minutes"
            )),
        ),
        None => component("usage-writes", State::Up, None),
    }
}

/// The last round of checks, and when it ran.
pub type Cache = Mutex<Option<(Instant, Vec<Component>)>>;

/// Each component, as checked at most [`CACHED_FOR`] before `now`.
pub async fn checked(site: &Site, now: Instant) -> Vec<Component> {
    let cached = site.checked.lock().expect("status cache lock").clone();
    if let Some((_, components)) =
        cached.filter(|(at, _)| now.saturating_duration_since(*at) < CACHED_FOR)
    {
        return components;
    }
    let components = check(site).await;
    *site.checked.lock().expect("status cache lock") = Some((now, components.clone()));
    components
}

/// Each component, checked now.
async fn check(site: &Site) -> Vec<Component> {
    let mut components = Vec::new();
    match &site.configured {
        Some(configured) => {
            let at = configured.reached_at.as_str();
            let health =
                crate::doctor::probe::within::<Health>(at, crate::proxy::HEALTH_PATH, TIMEOUT)
                    .await;
            components.push(match health {
                Ok(_) => component("proxy", State::Up, None),
                Err(why) => component("proxy", State::Down, Some(format!("{at}: {why}"))),
            });
            let ready =
                crate::doctor::probe::within::<Readiness>(at, crate::proxy::READY_PATH, TIMEOUT)
                    .await;
            components.push(match ready {
                Ok(ready) if ready.ready => component("readiness", State::Up, None),
                Ok(ready) => component(
                    "readiness",
                    State::Degraded,
                    Some(format!(
                        "intel {:?}; gaps: {}",
                        ready.intel,
                        ready.gaps.join(", ")
                    )),
                ),
                Err(why) => component("readiness", State::Down, Some(why)),
            });
            let dropped = configured.proxy.health().usage_unrecorded;
            components.push(usage_writes(&site.dropped, dropped, Instant::now()));
        }
        None => components.push(component(
            "proxy",
            State::Down,
            Some("this console runs beside no proxy".to_owned()),
        )),
    }
    components.push(
        match tokio::time::timeout(TIMEOUT, site.store.ping()).await {
            Ok(Ok(())) => component("database", State::Up, None),
            Ok(Err(e)) => component("database", State::Down, Some(e.to_string())),
            Err(_) => component(
                "database",
                State::Down,
                Some("no answer within 2 s".to_owned()),
            ),
        },
    );
    components
}

/// `GET status`: each component, checked now. R10.
#[utoipa::path(
    get,
    path = super::routes::STATUS_PATH,
    tag = "status",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("status.read"))),
    responses(
        (status = 200, description = "Each component, checked now", body = Status),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant status.read", body = Problem),
    ),
)]
pub async fn status(site: Arc<Site>) -> Response {
    json(
        StatusCode::OK,
        &Status {
            components: checked(&site, Instant::now()).await,
        },
    )
}

/// `GET health`: 200 when every component is up, else 503 naming those that are not.
#[utoipa::path(
    get,
    path = super::HEALTH_PATH,
    tag = "status",
    security(()),
    responses(
        (status = 200, description = "Every component is up", body = Up),
        (status = 503, description = "The worst state, and the components not up, by name", body = Up),
    ),
)]
pub async fn health(site: Arc<Site>) -> Response {
    let components = checked(&site, Instant::now()).await;
    let worst = components
        .iter()
        .map(|c| c.status)
        .max()
        .unwrap_or(State::Up);
    let not_up = components
        .iter()
        .filter(|c| c.status != State::Up)
        .map(|c| c.name)
        .collect();
    let code = if worst == State::Up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json(
        code,
        &Up {
            status: worst,
            components: not_up,
        },
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::testing::Failing;
    use crate::account::{Accounts, Pending};
    use crate::proxy::Proxy;
    use crate::proxy::testing::serve;

    fn console() -> crate::console::Console {
        crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        }
    }

    /// A console against `store`, beside `proxy` answering at `at`, or beside none.
    async fn site(store: Arc<dyn Accounts>, proxy: Option<(Proxy, String)>) -> Site {
        let site = crate::console::tests::unread(console(), store);
        match proxy {
            Some((proxy, at)) => site.with_proxy(proxy, Vec::new(), at),
            None => site,
        }
    }

    /// A proxy served, and where.
    async fn served(proxy: Proxy) -> (Proxy, String) {
        let at = serve(proxy.clone().router()).await;
        (proxy, at)
    }

    fn states(components: &[Component]) -> Vec<(&str, State)> {
        components.iter().map(|c| (c.name, c.status)).collect()
    }

    #[test]
    fn the_proxy_is_asked_on_loopback_under_its_path() {
        let registry = crate::mount::Mount::from_url("https://h/registry/").unwrap();
        assert_eq!(
            reached_at("0.0.0.0:8080", &registry),
            "http://127.0.0.1:8080/registry"
        );
        assert_eq!(
            reached_at("[::]:8080", &crate::mount::Mount::ROOT),
            "http://[::1]:8080"
        );
        for kept in ["10.0.0.5:8080", "10.0.0.0:8080", "localhost:8080"] {
            assert_eq!(
                reached_at(kept, &crate::mount::Mount::ROOT),
                format!("http://{kept}")
            );
        }
    }

    /// Rows dropped keep the usage writes degraded for 15 minutes from the last rise.
    #[test]
    fn usage_writes_are_degraded_for_15_minutes_after_rows_are_dropped() {
        let seen = Mutex::new(Dropped::default());
        let start = Instant::now();
        assert_eq!(usage_writes(&seen, 0, start).status, State::Up);
        let dropped = usage_writes(&seen, 3, start);
        assert_eq!(dropped.status, State::Degraded);
        assert!(dropped.reason.unwrap().starts_with("3 usage rows dropped"));
        let fourteen_minutes = start + Duration::from_secs(14 * 60);
        assert_eq!(
            usage_writes(&seen, 3, fourteen_minutes).status,
            State::Degraded
        );
        let later = start + DROPPED_FOR - Duration::from_secs(1);
        assert_eq!(usage_writes(&seen, 3, later).status, State::Degraded);
        assert_eq!(
            usage_writes(&seen, 3, start + DROPPED_FOR).status,
            State::Up
        );
        assert_eq!(
            usage_writes(&seen, 4, start + DROPPED_FOR).status,
            State::Degraded
        );
    }

    #[tokio::test]
    async fn every_component_up_is_up() {
        let store = Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let site = site(
            store,
            Some(served(Proxy::new(reqwest::Client::new())).await),
        )
        .await;
        let checked = check(&site).await;
        assert_eq!(
            states(&checked),
            [
                ("proxy", State::Up),
                ("readiness", State::Up),
                ("usage-writes", State::Up),
                ("database", State::Up),
            ]
        );
        assert!(
            checked
                .iter()
                .all(|c| c.reason.is_none() && c.checked.ends_with('Z'))
        );
    }

    /// A proxy whose intel store is empty is degraded; one that does not answer is down,
    /// as is a console beside none; a database that errors is down.
    #[tokio::test]
    async fn each_component_reports_why_it_is_not_up() {
        let policy = Arc::new(crate::policy::Policy::parse("version: 1").unwrap());
        let empty = Arc::new(crate::intel::store::testing::FixedIntel(Ok(None)));
        let unready = Proxy::new(reqwest::Client::new())
            .with_policy(Some(policy))
            .with_intel(Some(empty));
        let store: Arc<dyn Accounts> = Arc::new(Failing {
            inner: Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z")),
            fails: "ping",
        });
        let degraded = check(&site(store.clone(), Some(served(unready).await)).await).await;
        assert_eq!(degraded[1].status, State::Degraded);
        assert!(
            degraded[1]
                .reason
                .as_deref()
                .unwrap()
                .starts_with("intel Empty"),
            "{:?}",
            degraded[1]
        );
        assert_eq!(
            (degraded[3].name, degraded[3].status),
            ("database", State::Down)
        );

        let gone = (
            Proxy::new(reqwest::Client::new()),
            "http://127.0.0.1:9".to_owned(),
        );
        let down = check(&site(store.clone(), Some(gone)).await).await;
        assert_eq!(
            states(&down)[..2],
            [("proxy", State::Down), ("readiness", State::Down)]
        );
        assert!(
            down[0]
                .reason
                .as_deref()
                .unwrap()
                .starts_with("http://127.0.0.1:9: ")
        );

        let alone = check(&site(store, None).await).await;
        assert_eq!(
            states(&alone),
            [("proxy", State::Down), ("database", State::Down)]
        );
    }

    /// A database that gives no answer within 2 s is down.
    #[tokio::test]
    async fn a_database_that_does_not_answer_in_time_is_down() {
        let store = Arc::new(hanging(true));
        let checked = check(&site(store, None).await).await;
        assert_eq!(checked[1].status, State::Down);
        assert_eq!(checked[1].reason.as_deref(), Some("no answer within 2 s"));
    }

    /// The in-memory store, except that `ping` never answers.
    struct Hanging(
        crate::account::InMemory,
        std::sync::atomic::AtomicUsize,
        bool,
    );

    impl Accounts for Hanging {
        fn create_account<'a>(
            &'a self,
            n: &'a crate::account::Name,
            r: &'a [crate::account::Role],
        ) -> Pending<'a, ()> {
            self.0.create_account(n, r)
        }
        fn disable_account<'a>(&'a self, n: &'a crate::account::Name) -> Pending<'a, ()> {
            self.0.disable_account(n)
        }
        fn accounts(&self) -> Pending<'_, Vec<crate::account::Account>> {
            self.0.accounts()
        }
        fn create_token<'a>(
            &'a self,
            a: &'a crate::account::Name,
            n: &'a crate::account::Name,
            d: &'a crate::account::TokenDigest,
        ) -> Pending<'a, ()> {
            self.0.create_token(a, n, d)
        }
        fn revoke_token<'a>(
            &'a self,
            a: &'a crate::account::Name,
            n: &'a crate::account::Name,
        ) -> Pending<'a, ()> {
            self.0.revoke_token(a, n)
        }
        fn tokens<'a>(
            &'a self,
            a: Option<&'a crate::account::Name>,
        ) -> Pending<'a, Vec<crate::account::Token>> {
            self.0.tokens(a)
        }
        fn holder<'a>(
            &'a self,
            d: &'a crate::account::TokenDigest,
        ) -> Pending<'a, Option<crate::account::Holder>> {
            self.0.holder(d)
        }
        fn set_password<'a>(&'a self, a: &'a crate::account::Name, h: &'a str) -> Pending<'a, ()> {
            self.0.set_password(a, h)
        }
        fn password<'a>(&'a self, a: &'a crate::account::Name) -> Pending<'a, Option<String>> {
            self.0.password(a)
        }
        fn roles<'a>(
            &'a self,
            a: &'a crate::account::Name,
        ) -> Pending<'a, Vec<crate::account::Role>> {
            self.0.roles(a)
        }
        fn create_session<'a>(
            &'a self,
            a: &'a crate::account::Name,
            d: &'a crate::account::TokenDigest,
            e: &'a str,
        ) -> Pending<'a, ()> {
            self.0.create_session(a, d, e)
        }
        fn session<'a>(
            &'a self,
            d: &'a crate::account::TokenDigest,
        ) -> Pending<'a, Option<crate::account::Caller>> {
            self.0.session(d)
        }
        fn end_session<'a>(&'a self, d: &'a crate::account::TokenDigest) -> Pending<'a, ()> {
            self.0.end_session(d)
        }
        fn ping(&self) -> Pending<'_, ()> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.2 {
                Box::pin(std::future::pending())
            } else {
                self.0.ping()
            }
        }
        fn link_oidc<'a>(
            &'a self,
            a: &'a crate::account::Name,
            i: &'a str,
            s: &'a str,
        ) -> Pending<'a, ()> {
            self.0.link_oidc(a, i, s)
        }
        fn oidc_account<'a>(
            &'a self,
            i: &'a str,
            s: &'a str,
        ) -> Pending<'a, Option<crate::account::Name>> {
            self.0.oidc_account(i, s)
        }
    }

    fn hanging(hangs: bool) -> Hanging {
        let inner = crate::account::InMemory::new("2026-10-13T00:00:00Z");
        Hanging(inner, std::sync::atomic::AtomicUsize::new(0), hangs)
    }

    /// One round of checks answers for [`CACHED_FOR`]; then the next request checks again.
    #[tokio::test]
    async fn a_round_of_checks_answers_for_five_seconds() {
        let store = Arc::new(hanging(false));
        let site = site(store.clone(), None).await;
        let pings = || store.1.load(std::sync::atomic::Ordering::Relaxed);
        let start = Instant::now();
        let first = checked(&site, start).await;
        assert_eq!(
            checked(&site, start + CACHED_FOR - Duration::from_millis(1)).await,
            first
        );
        assert_eq!(pings(), 1);
        checked(&site, start + CACHED_FOR).await;
        assert_eq!(pings(), 2);
        assert_eq!(CACHED_FOR, Duration::from_secs(5));
    }

    /// `GET health` names what is not up, and only that; `GET status` gives every reason.
    #[tokio::test]
    async fn health_names_what_is_not_up_and_status_says_why() {
        let store = Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let gone = (
            Proxy::new(reqwest::Client::new()),
            "http://127.0.0.1:9".to_owned(),
        );
        let site = Arc::new(site(store.clone(), Some(gone)).await);
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        let base = serve(router).await;
        let health = reqwest::get(format!("{base}{}", crate::console::HEALTH_PATH))
            .await
            .unwrap();
        assert_eq!(health.status(), 503);
        let body: serde_json::Value = serde_json::from_str(&health.text().await.unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "status": "down", "components": ["proxy", "readiness"] })
        );

        let up = Arc::new(site_up(store).await);
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&up))
                .pop()
                .unwrap();
        let base = serve(router).await;
        let health = reqwest::get(format!("{base}{}", crate::console::HEALTH_PATH))
            .await
            .unwrap();
        assert_eq!(
            (health.status().as_u16(), health.text().await.unwrap()),
            (200, r#"{"status":"up"}"#.to_owned())
        );

        let status = reqwest::Client::new()
            .get(format!("{base}{}", crate::console::routes::STATUS_PATH))
            .send()
            .await
            .unwrap();
        assert_eq!(status.status(), 401, "status needs status.read");
        let response = status_of(&up).await;
        assert_eq!(response.status(), 200);
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = body["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["proxy", "readiness", "usage-writes", "database"]);
    }

    async fn site_up(store: Arc<crate::account::InMemory>) -> Site {
        site(
            store,
            Some(served(Proxy::new(reqwest::Client::new())).await),
        )
        .await
    }

    async fn status_of(site: &Arc<Site>) -> Response {
        status(site.clone()).await
    }
}
