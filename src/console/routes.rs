//! Every console route, with who may call it. A route is answered only through
//! [`ROUTES`], so one without a guard cannot be served. See docs/admin-plan.md §4.2.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;

use super::{Site, api};
use crate::account::{Caller, Permission, role};

/// A handler that finds its caller itself, if it needs one.
pub type Open = fn(Arc<Site>, Request) -> BoxFuture<'static, Response>;

/// A handler given what [`Asked`] holds, its caller already found to hold the permission.
pub type Permitted = fn(Arc<Site>, Asked) -> BoxFuture<'static, Response>;

/// A request a guard let through, and what the guard learned.
pub struct Asked {
    pub caller: Caller,
    /// The session's CSRF token, for a page to put in its forms. `None` for a token.
    pub csrf: Option<String>,
    pub parts: Parts,
    /// A page `POST`'s form fields, read by the guard to find its `csrf`. Else empty.
    pub form: Vec<(String, String)>,
}

/// What a route answers with, which decides how a refusal is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// JSON, in the OpenAPI document; a refusal is `{"error": ...}`.
    Api,
    /// HTML for a browser; a refusal is a page, the login form for a 401.
    Page,
}

/// Who may call a route.
#[derive(Clone, Copy)]
pub enum Guard {
    /// Anyone: the health check and login.
    Public(Open),
    /// Any caller with a session or token; the handler finds which.
    Authenticated(Open),
    /// A caller whose roles grant the permission. Otherwise 401, or 403.
    Needs(Permission, Permitted),
}

/// A method and path under the console's, what it answers with, and its guard.
#[derive(Clone)]
pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub kind: Kind,
    pub guard: Guard,
}

/// Under the console's path: `GET` every account.
pub const ACCOUNTS_PATH: &str = "/api/v1/accounts";

/// Under the console's path: `GET` the versions served, R3.
pub const DEPENDENCIES_PATH: &str = "/api/v1/dependencies";

/// Under the console's path: `GET` failures by hour and case, R6.
pub const FAILURES_PATH: &str = "/api/v1/metrics/failures";

/// Under the console's path: `GET` the configuration, R7.
pub const CONFIG_PATH: &str = "/api/v1/config";

/// Under the console's path: `GET` audit log lines, R5 and R9.
pub const REQUESTS_PATH: &str = "/api/v1/requests";

/// Under the console's path: `GET` a day of the audit log, R9.
pub const LOGS_PATH: &str = "/api/v1/logs/{day}";

/// Under the console's path: `GET` account event log lines, R8.
pub const EVENTS_PATH: &str = "/api/v1/events";

/// Under the console's path: `GET` versions served before a malware advisory named them, R4.
pub const ALERTS_PATH: &str = "/api/v1/alerts";

/// Under the console's path: `GET` each component's status, R10.
pub const STATUS_PATH: &str = "/api/v1/status";

/// Every console route.
pub const ROUTES: [Route; 28] = [
    Route {
        method: Method::GET,
        path: super::pages::HOME_PATH,
        kind: Kind::Page,
        guard: Guard::Public(|site, request| Box::pin(super::pages::home(site, request))),
    },
    Route {
        method: Method::GET,
        path: super::pages::CSS_PATH,
        kind: Kind::Page,
        guard: Guard::Public(|_, _| Box::pin(super::pages::css())),
    },
    Route {
        method: Method::GET,
        path: super::pages::OIDC_LOGIN_PATH,
        kind: Kind::Page,
        guard: Guard::Public(|site, request| Box::pin(super::pages::oidc_login(site, request))),
    },
    Route {
        method: Method::GET,
        path: super::oidc::CALLBACK_PATH,
        kind: Kind::Page,
        guard: Guard::Public(|site, request| Box::pin(super::pages::oidc_callback(site, request))),
    },
    Route {
        method: Method::POST,
        path: super::pages::LOGIN_FORM_PATH,
        kind: Kind::Page,
        guard: Guard::Public(|site, request| Box::pin(super::pages::login(site, request))),
    },
    Route {
        method: Method::POST,
        path: super::pages::LOGOUT_FORM_PATH,
        kind: Kind::Page,
        guard: Guard::Authenticated(|site, request| Box::pin(super::pages::logout(site, request))),
    },
    Route {
        method: Method::GET,
        path: super::pages::STATUS_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::StatusRead, |site, asked| {
            Box::pin(super::pages::status(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::DEPENDENCIES_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::pages::dependencies(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::ALERTS_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::AlertsRead, |site, asked| {
            Box::pin(super::pages::alerts(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::REQUESTS_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::pages::requests(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::EVENTS_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::EventsRead, |site, asked| {
            Box::pin(super::pages::events(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::CONFIG_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::ConfigRead, |site, asked| {
            Box::pin(super::pages::config(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::FAILURES_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::pages::failures(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::pages::ACCOUNTS_PAGE_PATH,
        kind: Kind::Page,
        guard: Guard::Needs(Permission::AccountsRead, |site, asked| {
            Box::pin(super::pages::accounts(site, asked))
        }),
    },
    Route {
        method: Method::GET,
        path: super::HEALTH_PATH,
        kind: Kind::Api,
        guard: Guard::Public(|site, _| Box::pin(super::status::health(site))),
    },
    Route {
        method: Method::GET,
        path: super::openapi::OPENAPI_PATH,
        kind: Kind::Api,
        guard: Guard::Public(|site, _| Box::pin(super::openapi::openapi(site))),
    },
    Route {
        method: Method::POST,
        path: super::LOGIN_PATH,
        kind: Kind::Api,
        guard: Guard::Public(|site, request| Box::pin(api::login(State(site), request))),
    },
    Route {
        method: Method::POST,
        path: super::LOGOUT_PATH,
        kind: Kind::Api,
        guard: Guard::Authenticated(|site, request| Box::pin(api::logout(State(site), request))),
    },
    Route {
        method: Method::GET,
        path: super::SESSION_PATH,
        kind: Kind::Api,
        guard: Guard::Authenticated(|site, request| Box::pin(api::session(State(site), request))),
    },
    Route {
        method: Method::GET,
        path: ACCOUNTS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::AccountsRead, |site, _| {
            Box::pin(api::accounts(site))
        }),
    },
    Route {
        method: Method::GET,
        path: DEPENDENCIES_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::usage::dependencies(site, asked.parts))
        }),
    },
    Route {
        method: Method::GET,
        path: REQUESTS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::logs::requests(site, asked.parts))
        }),
    },
    Route {
        method: Method::GET,
        path: LOGS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::logs::day(site, asked.parts))
        }),
    },
    Route {
        method: Method::GET,
        path: STATUS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::StatusRead, |site, _| {
            Box::pin(super::status::status(site))
        }),
    },
    Route {
        method: Method::GET,
        path: ALERTS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::AlertsRead, |site, asked| {
            Box::pin(super::alerts::alerts(site, asked.parts))
        }),
    },
    Route {
        method: Method::GET,
        path: EVENTS_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::EventsRead, |site, asked| {
            Box::pin(super::logs::events(site, asked.parts))
        }),
    },
    Route {
        method: Method::GET,
        path: CONFIG_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::ConfigRead, |site, _| {
            Box::pin(super::config::config(site))
        }),
    },
    Route {
        method: Method::GET,
        path: FAILURES_PATH,
        kind: Kind::Api,
        guard: Guard::Needs(Permission::RequestsRead, |site, asked| {
            Box::pin(super::usage::failures(site, asked.parts))
        }),
    },
];

/// A page `POST`'s form fields. A body too large or not a form has none.
async fn form(kind: Kind, parts: &Parts, body: axum::body::Body) -> Vec<(String, String)> {
    if kind == Kind::Api || parts.method != Method::POST {
        return Vec::new();
    }
    axum::body::to_bytes(body, api::MAX_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_urlencoded::from_bytes(&bytes).ok())
        .unwrap_or_default()
}

/// Answer `request` on a route of `kind` guarded by `guard`.
async fn guarded(kind: Kind, guard: Guard, site: Arc<Site>, request: Request) -> Response {
    match guard {
        Guard::Public(handler) | Guard::Authenticated(handler) => handler(site, request).await,
        Guard::Needs(permission, handler) => {
            let (parts, body) = request.into_parts();
            let form = form(kind, &parts, body).await;
            let sent = form
                .iter()
                .find(|(field, _)| field == "csrf")
                .map(|(_, value)| value.as_str());
            match site.caller_sending(&parts, sent).await {
                Ok((caller, id)) if role::permits(&caller.roles, permission) => {
                    let csrf = id.as_deref().map(api::csrf);
                    let asked = Asked {
                        caller,
                        csrf,
                        parts,
                        form,
                    };
                    handler(site, asked).await
                }
                Ok(_) if kind == Kind::Page => super::pages::forbidden(&site, permission),
                Ok(_) => api::forbidden(permission),
                Err(denied) if kind == Kind::Page => super::pages::denied(&site, denied),
                Err(denied) => denied.into_response(),
            }
        }
    }
}

/// [`ROUTES`] under `under`, the console's path without its trailing `/`.
pub fn router(site: Arc<Site>, under: &str) -> Router {
    ROUTES
        .iter()
        .fold(Router::new(), |router, route| {
            let (kind, guard) = (route.kind, route.guard);
            let filter = axum::routing::MethodFilter::try_from(route.method.clone())
                .expect("each route's method is one axum routes by");
            router.route(
                &format!("{under}{}", route.path),
                axum::routing::on(
                    filter,
                    move |State(site): State<Arc<Site>>, request: Request| {
                        guarded(kind, guard, site, request)
                    },
                ),
            )
        })
        .with_state(site)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::{Accounts, Name, TokenDigest};
    use crate::console::login::tests::{PASSWORD, store};
    use crate::console::tests::served;

    /// Only these are answered without a permission. A route added to [`ROUTES`] with
    /// any other guard fails here until it is listed.
    #[test]
    fn only_these_are_without_a_permission() {
        let unpermitted: Vec<(Method, &str)> = ROUTES
            .iter()
            .filter(|route| !matches!(route.guard, Guard::Needs(..)))
            .map(|route| (route.method.clone(), route.path))
            .collect();
        assert_eq!(
            unpermitted,
            [
                (Method::GET, crate::console::pages::HOME_PATH),
                (Method::GET, crate::console::pages::CSS_PATH),
                (Method::GET, crate::console::pages::OIDC_LOGIN_PATH),
                (Method::GET, crate::console::oidc::CALLBACK_PATH),
                (Method::POST, crate::console::pages::LOGIN_FORM_PATH),
                (Method::POST, crate::console::pages::LOGOUT_FORM_PATH),
                (Method::GET, crate::console::HEALTH_PATH),
                (Method::GET, crate::console::openapi::OPENAPI_PATH),
                (Method::POST, crate::console::LOGIN_PATH),
                (Method::POST, crate::console::LOGOUT_PATH),
                (Method::GET, crate::console::SESSION_PATH),
            ]
        );
    }

    /// Stage 4.9's exit: each route needing a permission is 401 with no credential, 403 to a
    /// non-admin by session or token, 200 to an admin. One needing a caller is 401 without.
    #[tokio::test]
    async fn every_route_that_needs_a_permission_refuses_an_account_without_it() {
        let store = store().await;
        let (bob, laptop) = (Name::parse("bob").unwrap(), Name::parse("laptop").unwrap());
        store
            .create_token(&bob, &laptop, &TokenDigest::of("byrle_bob"))
            .await
            .unwrap();
        let (_, base) = served(store).await;
        let client = reqwest::Client::new();
        let log_in = |account: &str| {
            let body = serde_json::json!({ "account": account, "password": PASSWORD });
            client
                .post(format!("{base}/admin{}", crate::console::LOGIN_PATH))
                .body(body.to_string())
                .send()
        };
        let cookie = |response: reqwest::Response| {
            let set = response.headers()["set-cookie"].to_str().unwrap();
            set.split(';').next().unwrap().to_owned()
        };
        let (admin, user) = (
            cookie(log_in("alice").await.unwrap()),
            cookie(log_in("bob").await.unwrap()),
        );

        for route in ROUTES.iter() {
            let url = format!("{base}/admin{}", route.path.replace("{day}", "2026-10-13"));
            let request = || client.request(route.method.clone(), &url);
            let status = |builder: reqwest::RequestBuilder| async move {
                builder.send().await.unwrap().status()
            };
            match route.guard {
                Guard::Needs(permission, _) => {
                    let name = permission.name();
                    assert_eq!(status(request()).await, 401, "{url}, {name}");
                    let by_session = request().header("cookie", &user);
                    assert_eq!(status(by_session).await, 403, "{url}, {name}");
                    let by_token = request().bearer_auth("byrle_bob");
                    assert_eq!(status(by_token).await, 403, "{url}, {name}");
                    let admin = request().header("cookie", &admin);
                    assert_eq!(status(admin).await, 200, "{url}, {name}");
                }
                Guard::Authenticated(_) => {
                    assert_eq!(status(request()).await, 401, "{url}");
                }
                Guard::Public(_) => {}
            }
        }
        let other = client.get(format!("{base}/admin/api/v1/nothing"));
        assert_eq!(other.send().await.unwrap().status(), 404);
    }

    /// A page `POST` that needs a permission takes its CSRF token from the form, as no
    /// form sets a header, and hands the form on; without the token it is a 403 page.
    #[tokio::test]
    async fn a_page_form_carries_its_csrf_token_to_the_guard() {
        let store = store().await;
        let (bob, laptop) = (Name::parse("bob").unwrap(), Name::parse("laptop").unwrap());
        store
            .create_token(&bob, &laptop, &TokenDigest::of("byrle_bob"))
            .await
            .unwrap();
        let (site, base) = served(store).await;
        let body = serde_json::json!({ "account": "alice", "password": PASSWORD });
        let login = reqwest::Client::new()
            .post(format!("{base}/admin{}", crate::console::LOGIN_PATH))
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let id = cookie.strip_prefix("byrle_session=").unwrap();
        let guard = Guard::Needs(Permission::AccountsWrite, |_, asked| {
            let note = format!("{:?} {:?}", asked.form, asked.csrf.is_some());
            Box::pin(async move { note.into_response() })
        });
        let post = |body: String| {
            axum::http::Request::post("/admin/x")
                .header("cookie", &cookie)
                .body(axum::body::Body::from(body))
                .unwrap()
        };
        let pad = "p".repeat(2000);
        let sent = format!("csrf={}&name=ci&pad={pad}", api::csrf(id));
        let answered = guarded(Kind::Page, guard, site.clone(), post(sent)).await;
        assert_eq!(answered.status(), 200);
        let text = axum::body::to_bytes(answered.into_body(), 1 << 16)
            .await
            .unwrap();
        let text = String::from_utf8(text.to_vec()).unwrap();
        assert!(
            text.contains(r#"("name", "ci")"#) && text.ends_with("true"),
            "{text}"
        );
        let refused = guarded(Kind::Page, guard, site.clone(), post("name=ci".into())).await;
        assert_eq!(refused.status(), 403);
        let big = guarded(
            Kind::Page,
            guard,
            site.clone(),
            post("a".repeat(api::MAX_BODY + 1)),
        )
        .await;
        assert_eq!(big.status(), 403, "a form too large has no token");

        let api_form = format!("csrf={}", api::csrf(id));
        let api = guarded(Kind::Api, guard, site.clone(), post(api_form)).await;
        assert_eq!(
            api.status(),
            403,
            "an API request sends its token as a header"
        );
        assert_eq!(api.headers()["content-type"], "application/json");
        let anonymous = axum::http::Request::post("/admin/x")
            .body(axum::body::Body::empty())
            .unwrap();
        let unauthorized = guarded(Kind::Api, guard, site.clone(), anonymous).await;
        assert_eq!(unauthorized.status(), 401);
        assert_eq!(unauthorized.headers()["content-type"], "application/json");
        let by_token = axum::http::Request::get("/admin/x")
            .header("authorization", "Bearer byrle_bob")
            .body(axum::body::Body::empty())
            .unwrap();
        let forbidden = guarded(Kind::Api, guard, site, by_token).await;
        assert_eq!(forbidden.status(), 403);
        assert_eq!(forbidden.headers()["content-type"], "application/json");
    }

    /// docs/console-api.md lists each API route, with the permission it needs.
    #[test]
    fn the_endpoint_reference_lists_every_api_route() {
        let reference = include_str!("../../docs/console-api.md");
        for route in ROUTES.iter().filter(|route| route.kind == Kind::Api) {
            let needs = match route.guard {
                Guard::Needs(permission, _) => format!("`{}`", permission.name()),
                Guard::Authenticated(_) => "a session".to_owned(),
                Guard::Public(_) => "nothing".to_owned(),
            };
            let row = format!(
                "| {} | `{}` | {needs}",
                route.method,
                route.path.trim_start_matches('/')
            );
            let found = reference.lines().any(|line| line.starts_with(&row));
            assert!(found, "docs/console-api.md has no row starting {row}");
        }
    }
}
