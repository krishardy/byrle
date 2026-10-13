//! The console's login, logout and session endpoints, and who a console request is from:
//! a session cookie, or a proxy token. See docs/admin-plan.md §4.6.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::Site;
use super::login::Attempt;
use crate::account::gate::Refused;
use crate::account::{Caller, TokenDigest};

/// The cookie the session id is kept in.
pub const COOKIE: &str = "byrle_session";

/// The header a request changing something with a session cookie carries [`csrf`] in.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-byrle-csrf");

/// The largest login body read.
const MAX_BODY: usize = 8 * 1024;

/// The CSRF token of the session `id`: a page from the console has it, another site
/// does not, and it is never stored.
pub fn csrf(id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"byrle-csrf\0");
    hasher.update(id.as_bytes());
    crate::util::hex(&hasher.finalize())
}

/// `body` as JSON with `status`, never cached.
fn json(status: StatusCode, body: serde_json::Value) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body),
    )
        .into_response()
}

/// `{"error": why}` with `status`. A 401 asks for nothing, so a browser shows no dialog.
fn refused(status: StatusCode, why: &str) -> Response {
    json(status, serde_json::json!({ "error": why }))
}

fn unauthorized() -> Response {
    refused(StatusCode::UNAUTHORIZED, "log in, or send a token")
}

fn unanswered() -> Response {
    refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "the account store did not answer",
    )
}

/// Why a console request has no caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// No session or token, or one not good.
    Unauthorized,
    /// A session request changing something without its CSRF token.
    NoCsrf,
    /// The account store did not answer.
    Unanswered,
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => unauthorized(),
            Self::NoCsrf => refused(
                StatusCode::FORBIDDEN,
                "a request with a session cookie needs its x-byrle-csrf header",
            ),
            Self::Unanswered => unanswered(),
        }
    }
}

/// The caller as JSON.
fn described(caller: &Caller) -> serde_json::Value {
    let roles: Vec<&str> = caller.roles.iter().map(|role| role.name()).collect();
    serde_json::json!({ "account": caller.account.as_str(), "roles": roles })
}

/// The session id in a `Cookie` header of `headers`.
fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .map(str::to_owned)
}

impl Site {
    /// Whether a request with `headers` came from a page of another origin. A request
    /// with no `Origin`, such as curl's, did not.
    fn foreign(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::ORIGIN)
            .is_some_and(|origin| origin.as_bytes() != self.origin.as_bytes())
    }

    /// Who a request is from, and its session id when it came with one. A session request
    /// other than GET or HEAD needs its [`CSRF_HEADER`].
    pub async fn caller(&self, parts: &Parts) -> Result<(Caller, Option<String>), Denied> {
        let Some(id) = session_id(&parts.headers) else {
            return match self.gate.admit(&parts.headers).await {
                Ok(holder) => match self.store.roles(&holder.account).await {
                    Ok(roles) => Ok((
                        Caller {
                            account: holder.account,
                            roles,
                        },
                        None,
                    )),
                    Err(_) => Err(Denied::Unanswered),
                },
                Err(Refused::Unauthorized) => Err(Denied::Unauthorized),
                Err(Refused::Unanswered) => Err(Denied::Unanswered),
            };
        };
        let caller = match self.store.session(&TokenDigest::of(&id)).await {
            Ok(Some(caller)) => caller,
            Ok(None) => return Err(Denied::Unauthorized),
            Err(_) => return Err(Denied::Unanswered),
        };
        let changes = !matches!(parts.method, Method::GET | Method::HEAD);
        let sent = parts.headers.get(CSRF_HEADER).map(HeaderValue::as_bytes);
        if changes && sent != Some(csrf(&id).as_bytes()) {
            return Err(Denied::NoCsrf);
        }
        Ok((caller, Some(id)))
    }

    /// The client's address, through nginx when it sent the key.
    fn source(&self, parts: &Parts) -> Option<std::net::IpAddr> {
        crate::reverse_proxy::client(
            &parts.headers,
            crate::reverse_proxy::peer(&parts.extensions),
            self.console.rp_key.as_ref(),
        )
    }

    /// The `Set-Cookie` value holding `id` for `max_age` seconds; 0 ends it.
    fn cookie(&self, id: &str, max_age: i64) -> HeaderValue {
        HeaderValue::from_str(&format!(
            "{COOKIE}={id}; Path={}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict",
            self.console.mount
        ))
        .expect("a session id and a mount are header text")
    }
}

#[derive(Deserialize)]
struct Credentials {
    account: String,
    password: String,
}

/// `POST login`, with `{"account", "password"}`: 200 with the caller and its CSRF token,
/// and the session cookie; 401, 429 or 503 otherwise.
pub async fn login(State(site): State<Arc<Site>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if site.foreign(&parts.headers) {
        return refused(StatusCode::FORBIDDEN, "a login from another site");
    }
    let credentials = axum::body::to_bytes(body, MAX_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Credentials>(&bytes).ok());
    let Some(credentials) = credentials else {
        return refused(
            StatusCode::BAD_REQUEST,
            "the body is not {\"account\": ..., \"password\": ...}",
        );
    };
    let source = site.source(&parts);
    match site
        .login
        .attempt(&credentials.account, &credentials.password, source)
        .await
    {
        Attempt::Started(started) => {
            let mut body = described(&started.caller);
            body["csrf"] = csrf(&started.id).into();
            body["expires"] = started.expires.to_string().into();
            let mut response = json(StatusCode::OK, body);
            let max_age = site.login.limits().session.as_secs();
            response
                .headers_mut()
                .insert(header::SET_COOKIE, site.cookie(&started.id, max_age));
            response
        }
        Attempt::Refused => refused(
            StatusCode::UNAUTHORIZED,
            "the account or the password is wrong",
        ),
        Attempt::Limited => {
            let mut response = refused(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed logins; try again later",
            );
            let retry = site.login.limits().window.as_secs().to_string();
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry).expect("digits"),
            );
            response
        }
        Attempt::Unanswered => unanswered(),
    }
}

/// `POST logout`: ends the session the cookie names, 204, and clears the cookie.
pub async fn logout(State(site): State<Arc<Site>>, request: Request<Body>) -> Response {
    let (parts, _) = request.into_parts();
    if site.foreign(&parts.headers) {
        return refused(StatusCode::FORBIDDEN, "a logout from another site");
    }
    let (caller, id) = match site.caller(&parts).await {
        Ok(found) => found,
        Err(denied) => return denied.into_response(),
    };
    let Some(id) = id else {
        return refused(StatusCode::BAD_REQUEST, "a token has no session to end");
    };
    match site.login.end(&id, &caller, site.source(&parts)).await {
        Ok(()) => (
            StatusCode::NO_CONTENT,
            [(header::SET_COOKIE, site.cookie("", 0))],
        )
            .into_response(),
        Err(_) => unanswered(),
    }
}

/// `GET session`: who the caller is, and whether by a session or a token.
pub async fn session(State(site): State<Arc<Site>>, request: Request<Body>) -> Response {
    let (parts, _) = request.into_parts();
    match site.caller(&parts).await {
        Ok((caller, id)) => {
            let mut body = described(&caller);
            body["by"] = if id.is_some() { "session" } else { "token" }.into();
            json(StatusCode::OK, body)
        }
        Err(denied) => denied.into_response(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::testing::Failing;
    use crate::account::{Accounts, InMemory, Name};
    use crate::console::login::tests::{PASSWORD, store};
    use crate::console::tests::served;
    use crate::console::{LOGIN_PATH, LOGOUT_PATH, SESSION_PATH};

    const TOKEN: &str = "byrle_alice-laptop";

    /// [`store`], with [`TOKEN`] for alice.
    async fn accounts() -> Arc<InMemory> {
        let store = store().await;
        let (alice, laptop) = (
            Name::parse("alice").unwrap(),
            Name::parse("laptop").unwrap(),
        );
        store
            .create_token(&alice, &laptop, &TokenDigest::of(TOKEN))
            .await
            .unwrap();
        store
    }

    fn post(base: &str, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new().post(format!("{base}/admin{path}"))
    }

    fn get(base: &str, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new().get(format!("{base}/admin{path}"))
    }

    async fn log_in(base: &str, account: &str, password: &str) -> reqwest::Response {
        let credentials = serde_json::json!({ "account": account, "password": password });
        post(base, LOGIN_PATH)
            .body(credentials.to_string())
            .send()
            .await
            .unwrap()
    }

    async fn body(response: reqwest::Response) -> serde_json::Value {
        serde_json::from_str(&response.text().await.unwrap()).unwrap()
    }

    /// The session id in a `Set-Cookie`.
    fn id_in(response: &reqwest::Response) -> String {
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        cookie
            .strip_prefix("byrle_session=")
            .and_then(|rest| rest.split(';').next())
            .unwrap()
            .to_owned()
    }

    /// The right password gives the cookie, under the console's path and out of reach of
    /// scripts and other sites, and the CSRF token; the wrong one gives 401 and no dialog.
    #[tokio::test]
    async fn a_login_sets_the_session_cookie_and_returns_its_csrf_token() {
        let (_, base) = served(accounts().await).await;
        let wrong = log_in(&base, "alice", "wrong horse battery").await;
        assert_eq!(wrong.status(), 401);
        assert!(wrong.headers().get(header::WWW_AUTHENTICATE).is_none());
        assert!(wrong.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(
            body(wrong).await["error"],
            "the account or the password is wrong"
        );

        let right = log_in(&base, "alice", PASSWORD).await;
        assert_eq!(right.status(), 200);
        assert_eq!(right.headers()[header::CACHE_CONTROL], "no-store");
        let id = id_in(&right);
        let cookie = right.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            cookie,
            format!(
                "byrle_session={id}; Path=/admin/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict"
            )
        );
        let answered = body(right).await;
        assert_eq!(answered["account"], "alice");
        assert_eq!(answered["roles"], serde_json::json!(["admin"]));
        assert_eq!(answered["csrf"], csrf(&id));
        assert!(answered["expires"].as_str().unwrap().ends_with('Z'));
    }

    /// A session reads with its cookie alone, changes nothing without its CSRF token, and
    /// ends at logout; a token is a caller with no session to end.
    #[tokio::test]
    async fn a_session_is_used_and_ended_with_its_csrf_token() {
        let (_, base) = served(accounts().await).await;
        let id = id_in(&log_in(&base, "alice", PASSWORD).await);
        let cookie = format!("theme=dark; byrle_session={id}");
        let who = get(&base, SESSION_PATH)
            .header(header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(who.status(), 200);
        let who = body(who).await;
        assert_eq!(
            (who["account"].as_str(), who["by"].as_str()),
            (Some("alice"), Some("session"))
        );

        for csrf_sent in [None, Some("wrong")] {
            let mut request = post(&base, LOGOUT_PATH).header(header::COOKIE, &cookie);
            if let Some(sent) = csrf_sent {
                request = request.header(CSRF_HEADER, sent);
            }
            assert_eq!(request.send().await.unwrap().status(), 403, "{csrf_sent:?}");
        }
        let out = post(&base, LOGOUT_PATH)
            .header(header::COOKIE, &cookie)
            .header(CSRF_HEADER, csrf(&id))
            .send()
            .await
            .unwrap();
        assert_eq!(out.status(), 204);
        assert!(
            out.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .starts_with("byrle_session=; Path=/admin/; Max-Age=0;")
        );
        let ended = get(&base, SESSION_PATH).header(header::COOKIE, &cookie);
        assert_eq!(ended.send().await.unwrap().status(), 401);

        let by_token = get(&base, SESSION_PATH)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(body(by_token).await["by"], "token");
        let token_out = post(&base, LOGOUT_PATH)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(token_out.status(), 400);
        let nobody = get(&base, SESSION_PATH).send().await.unwrap();
        assert_eq!(nobody.status(), 401);
        assert!(nobody.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    /// A page of another origin cannot log in or out; the console's own, or no `Origin`,
    /// can. A body that is not credentials is 400.
    #[tokio::test]
    async fn another_origin_and_a_body_not_credentials_are_refused() {
        let (_, base) = served(accounts().await).await;
        let credentials = serde_json::json!({ "account": "alice", "password": PASSWORD });
        let from = |origin: &str| {
            post(&base, LOGIN_PATH)
                .header(header::ORIGIN, origin)
                .body(credentials.to_string())
        };
        assert_eq!(
            from("https://evil.example").send().await.unwrap().status(),
            403
        );
        assert_eq!(from("https://h").send().await.unwrap().status(), 200);
        let out = post(&base, LOGOUT_PATH).header(header::ORIGIN, "https://evil.example");
        assert_eq!(out.send().await.unwrap().status(), 403);
        let garbled = post(&base, LOGIN_PATH)
            .body("account=alice")
            .send()
            .await
            .unwrap();
        assert_eq!(garbled.status(), 400);
    }

    /// The token is the SHA-256 of a fixed prefix and the id, so it is checked against a
    /// value computed apart from this code.
    #[test]
    fn the_csrf_token_is_the_digest_of_the_prefixed_session_id() {
        assert_eq!(
            csrf("session-id"),
            "b86abd5ac54dc09a45fd4cde66859d9a34685c70896f532e52225dbc8f217898"
        );
    }

    /// A body of a few kilobytes is read: a 1,024-byte password is checked, and refused.
    #[tokio::test]
    async fn a_long_password_is_read_and_refused() {
        let (_, base) = served(accounts().await).await;
        let long = "a".repeat(crate::account::password::MAX_BYTES);
        assert_eq!(log_in(&base, "alice", &long).await.status(), 401);
    }

    /// Through nginx with the key, the failed login is logged from the client's address.
    #[tokio::test]
    async fn a_login_is_logged_from_the_address_nginx_names() {
        const KEY: &str = "0123456789abcdef0123456789abcdef";
        let dir = crate::util::test_support::tempdir("console-api-source");
        let path = dir.join("events.log");
        let events = Arc::new(crate::account::events::EventLog::open(&path, 30).unwrap());
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: Some(crate::reverse_proxy::RpKey::parse(KEY).unwrap()),
        };
        let hasher = crate::account::password::tests::cheap();
        let limits = crate::console::login::tests::limits();
        let site = Arc::new(Site::new(
            console,
            accounts().await,
            (hasher, limits),
            Some(events),
        ));
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        let base = crate::proxy::testing::serve(router).await;
        let refused = reqwest::Client::new()
            .post(format!("{base}{LOGIN_PATH}"))
            .header("x-byrle-rp-key", KEY)
            .header("x-forwarded-for", "203.0.113.7")
            .body(r#"{"account":"alice","password":"wrong horse battery"}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), 401);
        let logged: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(logged["source"], "203.0.113.7");
    }

    #[tokio::test]
    async fn too_many_failures_are_429_with_when_to_try_again() {
        let (_, base) = served(accounts().await).await;
        for _ in 0..crate::console::login::tests::limits().per_account {
            log_in(&base, "alice", "wrong horse battery").await;
        }
        let limited = log_in(&base, "alice", PASSWORD).await;
        assert_eq!(limited.status(), 429);
        assert_eq!(limited.headers()[header::RETRY_AFTER], "900");
    }

    /// Each place the store is asked answers 503 when it cannot.
    #[tokio::test]
    async fn a_store_that_cannot_answer_is_503() {
        for fails in ["password", "session", "holder", "roles", "end_session"] {
            let inner = accounts().await;
            let (_, base) = served(Arc::new(Failing { inner, fails })).await;
            let id = match fails {
                "session" | "end_session" => id_in(&log_in(&base, "bob", PASSWORD).await),
                _ => String::new(),
            };
            let status = match fails {
                "password" => log_in(&base, "alice", PASSWORD).await.status(),
                "session" => get(&base, SESSION_PATH)
                    .header(header::COOKIE, format!("byrle_session={id}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                "end_session" => post(&base, LOGOUT_PATH)
                    .header(header::COOKIE, format!("byrle_session={id}"))
                    .header(CSRF_HEADER, csrf(&id))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                _ => get(&base, SESSION_PATH)
                    .bearer_auth(TOKEN)
                    .send()
                    .await
                    .unwrap()
                    .status(),
            };
            assert_eq!(status, 503, "{fails}");
        }
    }
}
