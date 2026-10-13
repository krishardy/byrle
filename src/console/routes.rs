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

/// A handler given the request and a caller already found to hold the route's permission.
pub type Permitted = fn(Arc<Site>, Caller, Parts) -> BoxFuture<'static, Response>;

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

/// A method and path under the console's, and its guard.
#[derive(Clone)]
pub struct Route {
    pub method: Method,
    pub path: &'static str,
    pub guard: Guard,
}

/// Under the console's path: `GET` every account.
pub const ACCOUNTS_PATH: &str = "/api/v1/accounts";

/// Under the console's path: `GET` the versions served, R3.
pub const DEPENDENCIES_PATH: &str = "/api/v1/dependencies";

/// Under the console's path: `GET` failures by hour and case, R6.
pub const FAILURES_PATH: &str = "/api/v1/metrics/failures";

/// Every console route.
pub const ROUTES: [Route; 8] = [
    Route {
        method: Method::GET,
        path: super::HEALTH_PATH,
        guard: Guard::Public(|_, _| Box::pin(super::health())),
    },
    Route {
        method: Method::GET,
        path: super::openapi::OPENAPI_PATH,
        guard: Guard::Public(|site, _| Box::pin(super::openapi::openapi(site))),
    },
    Route {
        method: Method::POST,
        path: super::LOGIN_PATH,
        guard: Guard::Public(|site, request| Box::pin(api::login(State(site), request))),
    },
    Route {
        method: Method::POST,
        path: super::LOGOUT_PATH,
        guard: Guard::Authenticated(|site, request| Box::pin(api::logout(State(site), request))),
    },
    Route {
        method: Method::GET,
        path: super::SESSION_PATH,
        guard: Guard::Authenticated(|site, request| Box::pin(api::session(State(site), request))),
    },
    Route {
        method: Method::GET,
        path: ACCOUNTS_PATH,
        guard: Guard::Needs(Permission::AccountsRead, |site, _, _| {
            Box::pin(api::accounts(site))
        }),
    },
    Route {
        method: Method::GET,
        path: DEPENDENCIES_PATH,
        guard: Guard::Needs(Permission::RequestsRead, |site, _, parts| {
            Box::pin(super::usage::dependencies(site, parts))
        }),
    },
    Route {
        method: Method::GET,
        path: FAILURES_PATH,
        guard: Guard::Needs(Permission::RequestsRead, |site, _, parts| {
            Box::pin(super::usage::failures(site, parts))
        }),
    },
];

/// Answer `request` on a route guarded by `guard`.
async fn guarded(guard: Guard, site: Arc<Site>, request: Request) -> Response {
    match guard {
        Guard::Public(handler) | Guard::Authenticated(handler) => handler(site, request).await,
        Guard::Needs(permission, handler) => {
            let (parts, _) = request.into_parts();
            match site.caller(&parts).await {
                Ok((caller, _)) if role::permits(&caller.roles, permission) => {
                    handler(site, caller, parts).await
                }
                Ok(_) => api::forbidden(permission),
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
            let guard = route.guard;
            let filter = axum::routing::MethodFilter::try_from(route.method.clone())
                .expect("each route's method is one axum routes by");
            router.route(
                &format!("{under}{}", route.path),
                axum::routing::on(
                    filter,
                    move |State(site): State<Arc<Site>>, request: Request| {
                        guarded(guard, site, request)
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
    fn only_health_the_document_login_logout_and_session_are_without_a_permission() {
        let unpermitted: Vec<(Method, &str)> = ROUTES
            .iter()
            .filter(|route| !matches!(route.guard, Guard::Needs(..)))
            .map(|route| (route.method.clone(), route.path))
            .collect();
        assert_eq!(
            unpermitted,
            [
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
            let url = format!("{base}/admin{}", route.path);
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
}
