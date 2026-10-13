//! The console's pages, rendered with `maud` from the data the API serves. Every page is
//! sent with a `Content-Security-Policy` that allows only this origin and no framing, and
//! a form that changes something carries the session's CSRF token. See
//! docs/engineering_decisions/console-web-interface.md and docs/admin-plan.md §4.7.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

use super::Site;
use super::api::Denied;
use super::login::Attempt;
use super::routes::Asked;
use super::status::{Component, State};
use crate::account::{Caller, Permission};

/// Under the console's path: the stylesheet every page links.
pub const CSS_PATH: &str = "/console.css";

/// Under the console's path: the home page, or the login form without a session.
pub const HOME_PATH: &str = "/";

/// Under the console's path: where the login form posts.
pub const LOGIN_FORM_PATH: &str = "/login";

/// Under the console's path: where the logout form posts.
pub const LOGOUT_FORM_PATH: &str = "/logout";

/// Under the console's path: each component's status, R10.
pub const STATUS_PAGE_PATH: &str = "/status";

/// What every page may load: this origin only, and no page of another may frame it.
pub const CSP: &str =
    "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

/// The stylesheet, served from this origin since the CSP refuses inline styles.
const CSS: &str = include_str!("console.css");

/// A page links, under the console's path, and the permission it needs.
const NAV: [(&str, &str, Permission); 1] = [("Status", STATUS_PAGE_PATH, Permission::StatusRead)];

/// `markup` as a page with `status`, with the headers every page carries.
fn sent(status: StatusCode, markup: Markup) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "same-origin"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        markup.into_string(),
    )
        .into_response()
}

impl Site {
    /// `path`, under the console's path.
    pub(super) fn href(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.console.mount.to_string().trim_end_matches('/'),
            path
        )
    }
}

/// Who is looking at a page: the caller and the session's CSRF token for its forms.
pub struct Viewer<'a> {
    pub caller: &'a Caller,
    pub csrf: Option<&'a str>,
}

/// `body` in the console's layout, titled `title`, with the links `viewer` may follow.
fn layout(
    site: &Site,
    title: &str,
    viewer: Option<&Viewer<'_>>,
    refresh: bool,
    body: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                @if refresh { meta http-equiv="refresh" content="15"; }
                title { (title) " · byrle" }
                link rel="stylesheet" href=(site.href(CSS_PATH));
            }
            body {
                header {
                    a.brand href=(site.href(HOME_PATH)) { "byrle" }
                    @if let Some(viewer) = viewer {
                        nav {
                            @for (label, path, permission) in NAV {
                                @if crate::account::role::permits(&viewer.caller.roles, permission) {
                                    a href=(site.href(path)) { (label) }
                                }
                            }
                        }
                        @if let Some(csrf) = viewer.csrf {
                            form.logout method="post" action=(site.href(LOGOUT_FORM_PATH)) {
                                input type="hidden" name="csrf" value=(csrf);
                                span { (viewer.caller.account.as_str()) }
                                button type="submit" { "Log out" }
                            }
                        }
                    }
                }
                main {
                    h1 { (title) }
                    (body)
                }
            }
        }
    }
}

/// The login form, saying `why` the last attempt failed when one did.
fn login_form(site: &Site, why: Option<&str>) -> Markup {
    layout(
        site,
        "Log in",
        None,
        false,
        html! {
            @if let Some(why) = why { p.refused { (why) } }
            form.login method="post" action=(site.href(LOGIN_FORM_PATH)) {
                label { "Account" input name="account" autocomplete="username" required; }
                label { "Password" input type="password" name="password" autocomplete="current-password" required; }
                button type="submit" { "Log in" }
            }
        },
    )
}

/// A page saying `why`, with `status`.
fn refusal(site: &Site, status: StatusCode, why: &str) -> Response {
    sent(
        status,
        layout(
            site,
            "Not shown",
            None,
            false,
            html! { p.refused { (why) } },
        ),
    )
}

/// The page for a request the guard refused: the login form for 401.
pub fn denied(site: &Site, denied: Denied) -> Response {
    match denied {
        Denied::Unauthorized => sent(StatusCode::UNAUTHORIZED, login_form(site, None)),
        Denied::NoCsrf => refusal(
            site,
            StatusCode::FORBIDDEN,
            "the form did not come from this console",
        ),
        Denied::Unanswered => refusal(
            site,
            StatusCode::SERVICE_UNAVAILABLE,
            "the account store did not answer",
        ),
    }
}

/// The page for a caller whose roles do not grant `permission`.
pub fn forbidden(site: &Site, permission: Permission) -> Response {
    refusal(
        site,
        StatusCode::FORBIDDEN,
        &format!("this page needs the {} permission", permission.name()),
    )
}

/// `GET console.css`.
pub async fn css() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        CSS,
    )
        .into_response()
}

/// `GET /`: the pages the caller may see, or the login form without a session.
pub async fn home(site: Arc<Site>, request: Request) -> Response {
    let (parts, _) = request.into_parts();
    match site.caller(&parts).await {
        Ok((caller, id)) => {
            let csrf = id.as_deref().map(super::api::csrf);
            let viewer = Viewer {
                caller: &caller,
                csrf: csrf.as_deref(),
            };
            let body = html! {
                p { "Logged in as " strong { (caller.account.as_str()) } "." }
                ul {
                    @for (label, path, permission) in NAV {
                        @if crate::account::role::permits(&caller.roles, permission) {
                            li { a href=(site.href(path)) { (label) } }
                        }
                    }
                }
            };
            sent(
                StatusCode::OK,
                layout(&site, "Console", Some(&viewer), false, body),
            )
        }
        Err(Denied::Unanswered) => denied(&site, Denied::Unanswered),
        Err(_) => sent(StatusCode::OK, login_form(&site, None)),
    }
}

#[derive(Deserialize)]
struct Credentials {
    account: String,
    password: String,
}

/// `POST login`, from the form: 303 home with the session cookie, or the form again.
pub async fn login(site: Arc<Site>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if site.foreign(&parts.headers) {
        return refusal(&site, StatusCode::FORBIDDEN, "a login from another site");
    }
    let credentials = axum::body::to_bytes(body, super::api::MAX_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_urlencoded::from_bytes::<Credentials>(&bytes).ok());
    let Some(credentials) = credentials else {
        return sent(
            StatusCode::BAD_REQUEST,
            login_form(&site, Some("give an account and a password")),
        );
    };
    let attempt = site
        .login
        .attempt(
            &credentials.account,
            &credentials.password,
            site.source(&parts),
        )
        .await;
    match attempt {
        Attempt::Started(started) => {
            let max_age = site.login.limits().session.as_secs();
            let home =
                HeaderValue::from_str(&site.href(HOME_PATH)).expect("a mount is header text");
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, home),
                    (header::SET_COOKIE, site.cookie(&started.id, max_age)),
                ],
            )
                .into_response()
        }
        Attempt::Refused => sent(
            StatusCode::UNAUTHORIZED,
            login_form(&site, Some("the account or the password is wrong")),
        ),
        Attempt::Limited => sent(
            StatusCode::TOO_MANY_REQUESTS,
            login_form(&site, Some("too many failed logins; try again later")),
        ),
        Attempt::Unanswered => denied(&site, Denied::Unanswered),
    }
}

/// `POST logout`, from the form with the session's CSRF token: 303 to the login form.
pub async fn logout(site: Arc<Site>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if site.foreign(&parts.headers) {
        return refusal(&site, StatusCode::FORBIDDEN, "a logout from another site");
    }
    #[derive(Deserialize)]
    struct Sent {
        csrf: Option<String>,
    }
    let sent_csrf = axum::body::to_bytes(body, super::api::MAX_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_urlencoded::from_bytes::<Sent>(&bytes).ok())
        .and_then(|form| form.csrf);
    let (caller, id) = match site.caller_sending(&parts, sent_csrf.as_deref()).await {
        Ok(found) => found,
        Err(why) => return denied(&site, why),
    };
    let Some(id) = id else {
        return refusal(
            &site,
            StatusCode::BAD_REQUEST,
            "a token has no session to end",
        );
    };
    match site.login.end(&id, &caller, site.source(&parts)).await {
        Ok(()) => {
            let home =
                HeaderValue::from_str(&site.href(HOME_PATH)).expect("a mount is header text");
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, home),
                    (header::SET_COOKIE, site.cookie("", 0)),
                ],
            )
                .into_response()
        }
        Err(_) => denied(&site, Denied::Unanswered),
    }
}

/// The word and class a state is shown with.
fn shown(state: State) -> &'static str {
    match state {
        State::Up => "up",
        State::Degraded => "degraded",
        State::Down => "down",
    }
}

/// `GET status`: each component, reloaded every 15 s. R10.
pub async fn status(site: Arc<Site>, asked: Asked) -> Response {
    let components: Vec<Component> = super::status::checked(&site, std::time::Instant::now()).await;
    let viewer = Viewer {
        caller: &asked.caller,
        csrf: asked.csrf.as_deref(),
    };
    let body = html! {
        table {
            thead { tr { th { "Component" } th { "Status" } th { "Why" } th { "Checked" } } }
            tbody {
                @for component in &components {
                    tr {
                        td { (component.name) }
                        td class=(shown(component.status)) { (shown(component.status)) }
                        td { (component.reason.as_deref().unwrap_or("")) }
                        td { (component.checked) }
                    }
                }
            }
        }
    };
    sent(
        StatusCode::OK,
        layout(&site, "Status", Some(&viewer), true, body),
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::testing::Failing;
    use crate::console::login::tests::{PASSWORD, store};
    use crate::console::tests::served;

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    async fn form(base: &str, path: &str, body: &str) -> reqwest::Response {
        client()
            .post(format!("{base}/admin{path}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.to_owned())
            .send()
            .await
            .unwrap()
    }

    async fn page(base: &str, path: &str, cookie: Option<&str>) -> (u16, String) {
        let mut request = client().get(format!("{base}/admin{path}"));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let answered = request.send().await.unwrap();
        (answered.status().as_u16(), answered.text().await.unwrap())
    }

    /// The session cookie a login form for `account` sets.
    async fn logged_in(base: &str, account: &str) -> String {
        let answered = form(
            base,
            LOGIN_FORM_PATH,
            &format!("account={account}&password={}", PASSWORD.replace(' ', "+")),
        )
        .await;
        assert_eq!(answered.status(), 303);
        assert_eq!(answered.headers()["location"], "/admin/");
        answered.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    /// Without a session the home page is the login form; the form logs in and sets the
    /// cookie; with it, home lists the pages the caller's roles allow.
    #[tokio::test]
    async fn the_login_form_starts_a_session_and_home_lists_what_the_caller_may_see() {
        let (_, base) = served(store().await).await;
        let answered = client().get(format!("{base}/admin/")).send().await.unwrap();
        assert_eq!(answered.status(), 200);
        assert_eq!(answered.headers()["content-security-policy"], CSP);
        assert_eq!(answered.headers()["x-content-type-options"], "nosniff");
        let body = answered.text().await.unwrap();
        assert!(
            body.contains(r#"<form class="login" method="post" action="/admin/login">"#),
            "{body}"
        );

        let admin = logged_in(&base, "alice").await;
        let (status, home) = page(&base, HOME_PATH, Some(&admin)).await;
        assert_eq!(status, 200);
        assert!(
            home.contains(r#"<a href="/admin/status">Status</a>"#),
            "{home}"
        );
        assert!(
            home.contains(r#"<input type="hidden" name="csrf" value=""#),
            "{home}"
        );
        let user = logged_in(&base, "bob").await;
        let (_, home) = page(&base, HOME_PATH, Some(&user)).await;
        assert!(
            !home.contains("/admin/status"),
            "bob's roles grant no page: {home}"
        );

        let wrong = form(
            &base,
            LOGIN_FORM_PATH,
            "account=alice&password=wrong+horse+battery",
        )
        .await;
        assert_eq!(wrong.status(), 401);
        let padded = format!("account=alice&password={}", "w".repeat(2000));
        let long = form(&base, LOGIN_FORM_PATH, &padded).await;
        assert_eq!(long.status(), 401, "a form of 2 KB is read");
        assert!(
            wrong
                .text()
                .await
                .unwrap()
                .contains("the account or the password is wrong")
        );
        let garbled = form(&base, LOGIN_FORM_PATH, "account=alice").await;
        assert_eq!(garbled.status(), 400);
        let foreign = client()
            .post(format!("{base}/admin{LOGIN_FORM_PATH}"))
            .header("origin", "https://evil.example")
            .body("account=alice")
            .send()
            .await
            .unwrap();
        assert_eq!(foreign.status(), 403);
        for _ in 0..crate::console::login::tests::limits().per_account {
            form(&base, LOGIN_FORM_PATH, "account=carol&password=x").await;
        }
        assert_eq!(
            form(&base, LOGIN_FORM_PATH, "account=carol&password=x")
                .await
                .status(),
            429
        );
    }

    /// Logout needs the session's CSRF token in the form, and ends the session.
    #[tokio::test]
    async fn the_logout_form_needs_its_csrf_token() {
        let store = store().await;
        let (alice, laptop) = (
            crate::account::Name::parse("alice").unwrap(),
            crate::account::Name::parse("laptop").unwrap(),
        );
        let digest = crate::account::TokenDigest::of("byrle_alice");
        crate::account::Accounts::create_token(store.as_ref(), &alice, &laptop, &digest)
            .await
            .unwrap();
        let (_, base) = served(store).await;
        let cookie = logged_in(&base, "alice").await;
        let id = cookie.strip_prefix("byrle_session=").unwrap();
        let post = |body: String, cookie: Option<String>| {
            let base = base.clone();
            async move {
                let mut request = client()
                    .post(format!("{base}/admin{LOGOUT_FORM_PATH}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body);
                if let Some(cookie) = cookie {
                    request = request.header("cookie", cookie);
                }
                request.send().await.unwrap()
            }
        };
        assert_eq!(
            post("csrf=wrong".into(), Some(cookie.clone()))
                .await
                .status(),
            403
        );
        assert_eq!(post(String::new(), None).await.status(), 401);
        let csrf = crate::console::api::csrf(id);
        let padded = format!("csrf={csrf}&pad={}", "p".repeat(2000));
        let out = post(padded, Some(cookie.clone())).await;
        assert_eq!(out.status(), 303);
        assert!(
            out.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let (status, body) = page(&base, STATUS_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 401, "the session has ended");
        assert!(body.contains("Log in"), "{body}");
        let foreign = client()
            .post(format!("{base}/admin{LOGOUT_FORM_PATH}"))
            .header("origin", "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(foreign.status(), 403);
        let by_token = client()
            .post(format!("{base}/admin{LOGOUT_FORM_PATH}"))
            .bearer_auth("byrle_none")
            .send()
            .await
            .unwrap();
        assert_eq!(by_token.status(), 401);
        let token = client()
            .post(format!("{base}/admin{LOGOUT_FORM_PATH}"))
            .bearer_auth("byrle_alice")
            .send()
            .await
            .unwrap();
        assert_eq!(token.status(), 400, "a token has no session to end");
    }

    /// The status page lists each component and reloads itself.
    #[tokio::test]
    async fn the_status_page_lists_each_component() {
        let (_, base) = served(store().await).await;
        let admin = logged_in(&base, "alice").await;
        let (status, body) = page(&base, STATUS_PAGE_PATH, Some(&admin)).await;
        assert_eq!(status, 200);
        assert!(
            body.contains(r#"<meta http-equiv="refresh" content="15">"#),
            "{body}"
        );
        for name in ["proxy", "readiness", "usage-writes", "database"] {
            assert!(body.contains(&format!("<td>{name}</td>")), "{name}: {body}");
        }
        assert!(body.contains(r#"<td class="up">up</td>"#), "{body}");
        let (status, body) = page(
            &base,
            STATUS_PAGE_PATH,
            Some(&logged_in(&base, "bob").await),
        )
        .await;
        assert_eq!(status, 403);
        assert!(
            body.contains("this page needs the status.read permission"),
            "{body}"
        );
        let (status, css) = page(&base, CSS_PATH, None).await;
        assert_eq!(status, 200);
        assert!(css.contains("td.down"));
        assert_eq!(shown(State::Degraded), "degraded");
        assert_eq!(shown(State::Down), "down");
    }

    /// A store that does not answer is a page saying so.
    #[tokio::test]
    async fn a_store_that_does_not_answer_is_a_503_page() {
        for fails in ["session", "password", "end_session"] {
            let inner = store().await;
            let (_, base) = served(Arc::new(Failing { inner, fails })).await;
            let status = match fails {
                "password" => form(&base, LOGIN_FORM_PATH, "account=alice&password=x")
                    .await
                    .status()
                    .as_u16(),
                "session" => {
                    let cookie = logged_in(&base, "alice").await;
                    let home = page(&base, HOME_PATH, Some(&cookie)).await.0;
                    assert_eq!(home, 503, "home");
                    page(&base, STATUS_PAGE_PATH, Some(&cookie)).await.0
                }
                _ => {
                    let cookie = logged_in(&base, "alice").await;
                    let id = cookie.strip_prefix("byrle_session=").unwrap().to_owned();
                    client()
                        .post(format!("{base}/admin{LOGOUT_FORM_PATH}"))
                        .header("cookie", cookie)
                        .body(format!("csrf={}", crate::console::api::csrf(&id)))
                        .send()
                        .await
                        .unwrap()
                        .status()
                        .as_u16()
                }
            };
            assert_eq!(status, 503, "{fails}");
        }
    }
}
