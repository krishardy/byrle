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
use super::api::{Denied, Refused};
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

/// Under the console's path: where a login through the OIDC provider begins.
pub const OIDC_LOGIN_PATH: &str = "/oidc/login";

/// A login's OIDC state, nonce and PKCE; `__Host-`, so no other host can plant one.
pub const OIDC_COOKIE: &str = "__Host-byrle_oidc";

/// Seconds a login through the OIDC provider may take.
const OIDC_SECONDS: u32 = 600;

/// Under the console's path: where the logout form posts.
pub const LOGOUT_FORM_PATH: &str = "/logout";

/// Under the console's path: each component's status, R10.
pub const STATUS_PAGE_PATH: &str = "/status";

/// Under the console's path: the versions served, R3.
pub const DEPENDENCIES_PAGE_PATH: &str = "/dependencies";

/// Under the console's path: versions served before a malware advisory named them, R4.
pub const ALERTS_PAGE_PATH: &str = "/alerts";

/// Under the console's path: the audit log, R5 and R9.
pub const REQUESTS_PAGE_PATH: &str = "/requests";

/// Under the console's path: the account event log, R8.
pub const EVENTS_PAGE_PATH: &str = "/events";

/// Under the console's path: the configuration, R7.
pub const CONFIG_PAGE_PATH: &str = "/config";

/// Under the console's path: the accounts.
pub const ACCOUNTS_PAGE_PATH: &str = "/accounts";

/// Under the console's path: failures by hour and case, R6.
pub const FAILURES_PAGE_PATH: &str = "/failures";

/// The most hours the failures chart draws: 31 days.
const MAX_BARS: usize = 31 * 24;

/// The chart's drawing area, in its own units.
const CHART: (f64, f64) = (720.0, 200.0);

/// The colour of each `answered` case in the chart, in the order the cases are named.
const PALETTE: [&str; 8] = [
    "#cf222e", "#9a6700", "#0969da", "#8250df", "#1a7f37", "#bc4c00", "#57606a", "#bf3989",
];

/// The most days of the audit log a requests page links to.
const MAX_DAY_LINKS: usize = 31;

/// What every page may load: this origin only, and no page of another may frame it.
pub const CSP: &str =
    "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

/// The stylesheet, served from this origin since the CSP refuses inline styles.
const CSS: &str = include_str!("console.css");

/// A page links, under the console's path, and the permission it needs.
const NAV: [(&str, &str, Permission); 8] = [
    ("Status", STATUS_PAGE_PATH, Permission::StatusRead),
    ("Failures", FAILURES_PAGE_PATH, Permission::RequestsRead),
    (
        "Dependencies",
        DEPENDENCIES_PAGE_PATH,
        Permission::RequestsRead,
    ),
    ("Alerts", ALERTS_PAGE_PATH, Permission::AlertsRead),
    ("Requests", REQUESTS_PAGE_PATH, Permission::RequestsRead),
    ("Events", EVENTS_PAGE_PATH, Permission::EventsRead),
    ("Configuration", CONFIG_PAGE_PATH, Permission::ConfigRead),
    ("Accounts", ACCOUNTS_PAGE_PATH, Permission::AccountsRead),
];

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
            @if site.oidc.is_some() {
                p { a.oidc href=(site.href(OIDC_LOGIN_PATH)) { "Log in through your identity provider" } }
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
            super::api::UNANSWERED,
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

/// Where the OIDC provider sends the browser back.
fn redirect_uri(site: &Site) -> String {
    format!(
        "{}{}",
        site.console.url.trim_end_matches('/'),
        super::oidc::CALLBACK_PATH
    )
}

/// The `Set-Cookie` value carrying `value` for `max_age` seconds; 0 ends it. `Lax`, since
/// the provider sends the browser back from another site.
fn oidc_cookie(value: &str, max_age: u32) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{OIDC_COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"
    ))
    .expect("base64url and digits are header text")
}

/// `GET oidc/login`: to the provider, carrying a new login's state in a cookie.
pub async fn oidc_login(site: Arc<Site>, _: Request) -> Response {
    let Some(provider) = &site.oidc else {
        return refusal(&site, StatusCode::NOT_FOUND, "no OIDC provider is set");
    };
    match provider.begin(&redirect_uri(&site)).await {
        Ok((pending, url)) => (
            StatusCode::SEE_OTHER,
            [
                (
                    header::LOCATION,
                    HeaderValue::from_str(&url).expect("a URL is header text"),
                ),
                (
                    header::SET_COOKIE,
                    oidc_cookie(&pending.cookie(), OIDC_SECONDS),
                ),
            ],
        )
            .into_response(),
        Err(why) => refusal(
            &site,
            StatusCode::BAD_GATEWAY,
            &format!("the identity provider: {why}"),
        ),
    }
}

/// What the provider sends the browser back with.
#[derive(Debug, Default, Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// A session started through the provider: a page setting the session cookie and clearing
/// the login's, then reloading home. A redirect would come from the provider's site, and a
/// `SameSite=Strict` cookie is not sent on it; the reload comes from this one.
fn oidc_started(site: &Site, started: &super::login::Started) -> Response {
    let home = site.href(HOME_PATH);
    let page = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta http-equiv="refresh" content=(format!("0; url={home}"));
                title { "Logged in · byrle" }
            }
            body { p { "Logged in as " (started.caller.account.as_str()) ". " a href=(home) { "Go on" } } }
        }
    };
    let mut response = sent(StatusCode::OK, page);
    let max_age = site.login.limits().session.as_secs();
    let headers = response.headers_mut();
    headers.append(header::SET_COOKIE, site.cookie(&started.id, max_age));
    headers.append(header::SET_COOKIE, oidc_cookie("", 0));
    response
}

/// `GET oidc/callback`: the provider's answer. Its state must be the cookie's before the
/// code is exchanged; each failure counts against the address and is logged.
pub async fn oidc_callback(site: Arc<Site>, request: Request) -> Response {
    let Some(provider) = &site.oidc else {
        return refusal(&site, StatusCode::NOT_FOUND, "no OIDC provider is set");
    };
    let (parts, _) = request.into_parts();
    let source = site.source(&parts);
    if !site.login.oidc_allows(source) {
        return refusal(
            &site,
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed logins; try again later",
        );
    }
    let asked: Callback =
        serde_urlencoded::from_str(parts.uri.query().unwrap_or_default()).unwrap_or_default();
    let pending = super::api::cookie_named(&parts.headers, OIDC_COOKIE)
        .and_then(|cookie| super::oidc::Pending::parse(&cookie))
        .filter(|pending| asked.state.as_deref() == Some(pending.state.as_str()));
    let (status, why, subject) = match (pending, asked.error, asked.code) {
        (None, _, _) => (
            StatusCode::BAD_REQUEST,
            "this login did not begin here".to_owned(),
            None,
        ),
        (Some(_), Some(error), _) => (
            StatusCode::UNAUTHORIZED,
            format!("the identity provider refused: {error}"),
            None,
        ),
        (Some(_), None, None) => (
            StatusCode::BAD_REQUEST,
            "the identity provider sent no code".to_owned(),
            None,
        ),
        (Some(pending), None, Some(code)) => {
            match provider.finish(&code, &pending, &redirect_uri(&site)).await {
                Ok(claims) => match site.store.oidc_account(&claims.iss, &claims.sub).await {
                    Ok(Some(name)) => match site.login.start(name, source).await {
                        Attempt::Started(started) => return oidc_started(&site, &started),
                        _ => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            super::api::UNANSWERED.to_owned(),
                            None,
                        ),
                    },
                    Ok(None) => (
                        StatusCode::FORBIDDEN,
                        format!(
                            "{} at {} is not linked to an account",
                            claims.sub, claims.iss
                        ),
                        Some(claims.sub),
                    ),
                    Err(_) => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        super::api::UNANSWERED.to_owned(),
                        None,
                    ),
                },
                Err(super::oidc::Failed::Provider(why)) => (
                    StatusCode::BAD_GATEWAY,
                    format!("the identity provider: {why}"),
                    None,
                ),
                Err(super::oidc::Failed::Refused(why)) => (StatusCode::UNAUTHORIZED, why, None),
            }
        }
    };
    site.login
        .oidc_failed(subject.as_deref().unwrap_or("(oidc)"), source);
    let mut response = refusal(&site, status, &why);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, oidc_cookie("", 0));
    response
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

/// The query string of `asked`, as pairs, in order.
fn pairs(asked: &Asked) -> Vec<(String, String)> {
    serde_urlencoded::from_str(asked.parts.uri.query().unwrap_or_default()).unwrap_or_default()
}

/// The value of `field` in `pairs`, or nothing.
fn value<'a>(pairs: &'a [(String, String)], field: &str) -> &'a str {
    pairs
        .iter()
        .find(|(name, _)| name == field)
        .map_or("", |(_, value)| value.as_str())
}

/// A form that reads `path` again with `fields`, each filled with what `pairs` gave.
fn filters(site: &Site, path: &str, fields: &[&str], pairs: &[(String, String)]) -> Markup {
    html! {
        form.filters method="get" action=(site.href(path)) {
            @for field in fields {
                label { (field) input name=(field) value=(value(pairs, field)); }
            }
            button type="submit" { "Show" }
        }
    }
}

/// A link to the next page: `path` with `pairs`, `after` set to `next`.
fn next_link(site: &Site, path: &str, pairs: &[(String, String)], next: Option<String>) -> Markup {
    let Some(next) = next else {
        return html! {};
    };
    let mut pairs: Vec<(String, String)> = pairs
        .iter()
        .filter(|(name, _)| name != "after")
        .cloned()
        .collect();
    pairs.push(("after".to_owned(), next));
    let query = serde_urlencoded::to_string(&pairs).expect("pairs of text encode");
    html! { p { a.next href=(format!("{}?{query}", site.href(path))) { "Next page" } } }
}

/// `data` rendered on a page titled `title` for `asked`, or the page saying why not.
fn shown_page<T>(
    site: &Site,
    asked: &Asked,
    title: &str,
    data: Result<T, Refused>,
    render: impl FnOnce(T) -> Markup,
) -> Response {
    match data {
        Ok(data) => {
            let viewer = Viewer {
                caller: &asked.caller,
                csrf: asked.csrf.as_deref(),
            };
            sent(
                StatusCode::OK,
                layout(site, title, Some(&viewer), false, render(data)),
            )
        }
        Err(Refused(status, why)) => refusal(site, status, &why),
    }
}

/// A JSON value as text: a string as itself, nothing as empty, anything else as JSON.
fn text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `GET dependencies`: the versions served, a page at a time. R3.
pub async fn dependencies(site: Arc<Site>, asked: Asked) -> Response {
    let pairs = pairs(&asked);
    let data = super::usage::versions(&site, &asked.parts).await;
    shown_page(&site, &asked, "Dependencies", data, |page| {
        html! {
            (filters(&site, DEPENDENCIES_PAGE_PATH, &["ecosystem", "name", "account", "since", "until", "limit"], &pairs))
            table {
                thead { tr { th { "Account" } th { "Ecosystem" } th { "Name" } th { "Version" } th { "First served" } th { "Last served" } } }
                tbody {
                    @for row in &page.versions {
                        tr {
                            td { (row.account.as_deref().unwrap_or("no token")) }
                            td { (row.ecosystem) } td { (row.name) } td { (row.version) }
                            td { (row.first_served) } td { (row.last_served) }
                        }
                    }
                }
            }
            (next_link(&site, DEPENDENCIES_PAGE_PATH, &pairs, page.next.map(|id| id.to_string())))
        }
    })
}

/// `GET alerts`: versions served before a malware advisory named them. R4.
pub async fn alerts(site: Arc<Site>, asked: Asked) -> Response {
    let pairs = pairs(&asked);
    let data = super::alerts::found(&site, &asked.parts).await;
    shown_page(&site, &asked, "Alerts", data, |found| {
        html! {
            p { (found.scanned) " served versions looked up; " (found.alerts.len()) " alerts." }
            table {
                thead { tr { th { "Account" } th { "Package" } th { "Version" } th { "First served" } th { "Advisory" } th { "Loaded" } } }
                tbody {
                    @for alert in &found.alerts {
                        tr {
                            td { (alert.served.account.as_deref().unwrap_or("no token")) }
                            td { (alert.served.ecosystem) " " (alert.served.name) }
                            td { (alert.served.version) }
                            td { (alert.served.first_served) }
                            td { (alert.advisory_id) " (" (alert.source) ")" }
                            td { (alert.loaded.as_deref().unwrap_or("unknown")) }
                        }
                    }
                }
            }
            (next_link(&site, ALERTS_PAGE_PATH, &pairs, found.next.map(|id| id.to_string())))
        }
    })
}

/// The days from `since` to `until`, UTC, at most [`MAX_DAY_LINKS`].
fn days(pairs: &[(String, String)]) -> Vec<jiff::civil::Date> {
    let now = jiff::Timestamp::now();
    let asked = (
        None,
        None,
        Some(value(pairs, "since")).filter(|v| !v.is_empty()),
        Some(value(pairs, "until")).filter(|v| !v.is_empty()),
    );
    let Ok(range) = super::logs::range(asked, now) else {
        return Vec::new();
    };
    let utc = |at: jiff::Timestamp| at.to_zoned(jiff::tz::TimeZone::UTC).date();
    let (first, last) = (utc(range.since), utc(range.until));
    std::iter::successors(Some(first), |day| day.tomorrow().ok())
        .take_while(|day| *day <= last)
        .take(MAX_DAY_LINKS)
        .collect()
}

/// `GET requests`: the audit log, filtered, a page at a time, and a link to each day. R5, R9.
pub async fn requests(site: Arc<Site>, asked: Asked) -> Response {
    let pairs = pairs(&asked);
    let data =
        super::logs::paged::<super::logs::RequestFilters>(site.audit_log.as_ref(), &asked.parts)
            .await;
    shown_page(&site, &asked, "Requests", data, |page| {
        html! {
            (filters(&site, REQUESTS_PAGE_PATH, &["ecosystem", "name", "account", "answered", "check", "path", "since", "until", "limit"], &pairs))
            p { (page.files_read) " files read." }
            table {
                thead { tr { th { "At" } th { "Account" } th { "Package" } th { "Version" } th { "Answered" } th { "Checks" } } }
                tbody {
                    @for line in &page.lines {
                        tr {
                            td { (text(&line["at"])) }
                            td { (text(&line["account"])) }
                            td { (text(&line["ecosystem"])) " " (text(&line["name"])) }
                            td { (text(&line["version"])) }
                            td { (text(&line["answered"])) " " (text(&line["action"])) }
                            td { (text(&line["checks"])) }
                        }
                    }
                }
            }
            (next_link(&site, REQUESTS_PAGE_PATH, &pairs, page.next))
            p.days {
                "Each day as written: "
                @for day in days(&pairs) {
                    a href=(site.href(&super::routes::LOGS_PATH.replace("{day}", &day.to_string()))) { (day.to_string()) } " "
                }
            }
        }
    })
}

/// `GET events`: the account event log, filtered, a page at a time. R8.
pub async fn events(site: Arc<Site>, asked: Asked) -> Response {
    let pairs = pairs(&asked);
    let data =
        super::logs::paged::<super::logs::EventFilters>(site.event_log.as_ref(), &asked.parts)
            .await;
    shown_page(&site, &asked, "Events", data, |page| {
        html! {
            (filters(&site, EVENTS_PAGE_PATH, &["account", "action", "actor", "since", "until", "limit"], &pairs))
            table {
                thead { tr { th { "At" } th { "Actor" } th { "Action" } th { "Account" } th { "Role or token" } th { "Source" } } }
                tbody {
                    @for line in &page.lines {
                        tr {
                            td { (text(&line["at"])) }
                            td { (text(&line["actor"])) }
                            td { (text(&line["action"])) }
                            td { (text(&line["account"])) }
                            td { (text(&line["role"])) (text(&line["token"])) }
                            td { (text(&line["source"])) }
                        }
                    }
                }
            }
            (next_link(&site, EVENTS_PAGE_PATH, &pairs, page.next))
        }
    })
}

/// `GET config`: the proxy's health, its policy and its environment. R7.
pub async fn config(site: Arc<Site>, asked: Asked) -> Response {
    let data = super::config::loaded(&site).await;
    shown_page(&site, &asked, "Configuration", data, |config| {
        let health = serde_json::to_value(&config.proxy).expect("health serialises");
        html! {
            h2 { "Proxy" }
            table {
                tbody {
                    @for (key, value) in health.as_object().into_iter().flatten() {
                        tr { th { (key) } td { (text(value)) } }
                    }
                }
            }
            h2 { "Policy" }
            @match &config.policy {
                Some(policy) => { p { "Digest " code { (policy.digest) } } pre { (policy.report) } }
                None => { p { "No policy is set." } }
            }
            h2 { "Environment" }
            table {
                thead { tr { th { "Variable" } th { "Value" } th { "Default" } } }
                tbody {
                    @for setting in &config.environment {
                        tr {
                            td { code { (setting.name) } }
                            td { (setting.value.as_deref().unwrap_or("")) }
                            td { (setting.default.as_deref().unwrap_or("")) }
                        }
                    }
                }
            }
        }
    })
}

/// The hours from `since` up to `until`, at most [`MAX_BARS`], each as the tables write it.
fn hours(since: &str, until: &str) -> Vec<String> {
    let (Ok(since), Ok(until)) = (
        since.parse::<jiff::Timestamp>(),
        until.parse::<jiff::Timestamp>(),
    ) else {
        return Vec::new();
    };
    let hour = jiff::SignedDuration::from_hours(1);
    let first = crate::usage::hour_of(since);
    std::iter::successors(Some(first), |at| at.checked_add(hour).ok())
        .take_while(|at| *at < until)
        .take(MAX_BARS)
        .map(crate::usage::second)
        .collect()
}

/// One bar's piece: its case, count, colour, and where it starts and how tall it is.
struct Piece<'a> {
    case: &'a str,
    count: i64,
    colour: &'static str,
    top: f64,
    tall: f64,
}

/// The pieces of the bar for `hour`, stacked from the bottom, scaled to `busiest`.
fn stacked<'a>(
    failures: &'a super::usage::Failures,
    cases: &[&'a str],
    hour: &str,
    busiest: i64,
) -> Vec<Piece<'a>> {
    let height = CHART.1;
    let mut top = height;
    let mut pieces = Vec::new();
    for (n, case) in cases.iter().enumerate() {
        let count: i64 = failures
            .failures
            .iter()
            .filter(|row| row.hour == hour && row.answered == *case)
            .map(|row| row.count)
            .sum();
        if count > 0 {
            let tall = height * count as f64 / busiest as f64;
            top = (top - tall).max(0.0);
            pieces.push(Piece {
                case,
                count,
                colour: PALETTE[n % PALETTE.len()],
                top,
                tall,
            });
        }
    }
    pieces
}

/// `failures` as bars, one an hour, stacked by case, scaled to the busiest hour.
fn chart(failures: &super::usage::Failures) -> Markup {
    let hours = hours(&failures.since, &failures.until);
    let mut cases: Vec<&str> = failures
        .failures
        .iter()
        .map(|row| row.answered.as_str())
        .collect();
    cases.sort_unstable();
    cases.dedup();
    let totals: Vec<i64> = hours
        .iter()
        .map(|hour| {
            stacked(failures, &cases, hour, 1)
                .iter()
                .map(|p| p.count)
                .sum()
        })
        .collect();
    let busiest = totals.iter().copied().max().unwrap_or(0).max(1);
    let (width, height) = CHART;
    let bar = width / hours.len().max(1) as f64;
    html! {
        svg.chart viewBox=(format!("0 0 {width} {height}")) role="img" aria-label="Failures by hour" {
            @for (n, hour) in hours.iter().enumerate() {
                @for piece in stacked(failures, &cases, hour, busiest) {
                    rect x=(format!("{:.2}", n as f64 * bar)) y=(format!("{:.2}", piece.top))
                        width=(format!("{:.2}", bar * 0.9)) height=(format!("{:.2}", piece.tall)) fill=(piece.colour) {
                        title { (hour) " " (piece.case) ": " (piece.count) }
                    }
                }
            }
        }
        p { "Busiest hour: " (busiest) ". " (failures.since) " to " (failures.until) "." }
        ul.legend {
            @for (n, case) in cases.iter().enumerate() {
                li {
                    svg width="12" height="12" { rect width="12" height="12" fill=(PALETTE[n % PALETTE.len()]) {} }
                    " " (case)
                }
            }
        }
    }
}

/// `GET failures`: counts by hour and case, as a chart and a table. R6.
pub async fn failures(site: Arc<Site>, asked: Asked) -> Response {
    let pairs = pairs(&asked);
    let data = super::usage::counts(&site, &asked.parts).await;
    shown_page(&site, &asked, "Failures", data, |failures| {
        html! {
            (filters(&site, FAILURES_PAGE_PATH, &["ecosystem", "answered", "since", "until"], &pairs))
            (chart(&failures))
            table {
                thead { tr { th { "Hour" } th { "Ecosystem" } th { "Answered" } th { "Count" } } }
                tbody {
                    @for row in &failures.failures {
                        tr { td { (row.hour) } td { (row.ecosystem) } td { (row.answered) } td { (row.count) } }
                    }
                }
            }
        }
    })
}

/// `GET accounts`: each account and its roles.
pub async fn accounts(site: Arc<Site>, asked: Asked) -> Response {
    let data = super::api::listed(&site).await;
    shown_page(&site, &asked, "Accounts", data, |listed| {
        html! {
            table {
                thead { tr { th { "Account" } th { "Roles" } th { "Created" } th { "Disabled" } } }
                tbody {
                    @for account in &listed.accounts {
                        tr {
                            td { (account.account) }
                            td { (account.roles.join(", ")) }
                            td { (account.created) }
                            td { (account.disabled.as_deref().unwrap_or("")) }
                        }
                    }
                }
            }
        }
    })
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

    /// A console with a served version, an alert, two log lines and a policy, logged in as
    /// alice, its files under a directory named for `label`: its base URL and her cookie.
    async fn full(label: &str) -> (String, String) {
        use crate::usage::Use;
        let dir = crate::util::test_support::tempdir(label);
        let audit = dir.join("audit.log");
        let now = jiff::Timestamp::now();
        let line = serde_json::json!({
            "at": now.to_string(), "path": "pinned", "ecosystem": "npm",
            "name": "<script>alert(1)</script>", "version": "1.0.0", "answered": "refused",
            "checks": ["known_malware"], "account": "alice",
        });
        std::fs::write(&audit, format!("{line}\n")).unwrap();
        let events = dir.join("events.log");
        let failed = serde_json::json!({
            "at": now.to_string(), "action": "login-failed",
            "account": "<script>steal()</script>", "source": "192.0.2.1",
        });
        std::fs::write(&events, format!("{failed}\n")).unwrap();
        let usage = Arc::new(crate::usage::tests::Kept::default());
        let hour = crate::usage::hour_of(now - jiff::SignedDuration::from_hours(2));
        usage.0.lock().unwrap().extend([
            Use::Failed {
                hour,
                ecosystem: "npm".into(),
                answered: crate::audit::Answered::UpstreamUnreachable,
            },
            Use::Failed {
                hour,
                ecosystem: "npm".into(),
                answered: crate::audit::Answered::UpstreamUnreachable,
            },
        ]);
        usage.0.lock().unwrap().push(Use::Served {
            account: None,
            ecosystem: "npm".into(),
            name: "left-pad".into(),
            version: "1.0.0".into(),
            at: "2026-10-13T09:00:00Z".parse().unwrap(),
        });
        let malware = crate::intel::store::Record {
            advisory_id: "MAL-1".into(),
            aliases: vec![],
            source: "ossf-malicious".into(),
            cvss: None,
            cvss_source: None,
            band: None,
            exploited: false,
            malware: true,
            cached: None,
        };
        let intel = Arc::new(crate::intel::store::testing::FixedIntel(Ok(Some(
            crate::intel::store::PackageIntel {
                snapshot: "s1".into(),
                records: vec![(None, malware)],
                ranges: vec![],
                exploitation_loaded: false,
            },
        ))));
        let policy =
            Arc::new(crate::policy::Policy::parse("version: 1\ncooldown_days: 3\n").unwrap());
        let proxy = crate::proxy::Proxy::new(reqwest::Client::new())
            .with_policy(Some(policy))
            .with_intel(Some(intel));
        let settings = crate::env::testing::with(&[(crate::env::GITHUB_TOKEN, "ghp_x")]).settings();
        let console = crate::console::Console {
            url: "https://h/admin/".into(),
            mount: crate::mount::Mount::from_url("https://h/admin/").unwrap(),
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let site = crate::console::tests::unread(console, store().await)
            .with_usage(usage)
            .with_proxy(proxy, settings, "http://127.0.0.1:9".into())
            .with_logs(Some(audit), Some(events));
        let site = Arc::new(site);
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        let base = crate::proxy::testing::serve(router).await;
        let cookie = logged_in(&base, "alice").await;
        (base, cookie)
    }

    /// Each data page shows its data; a name from a registry or a username someone tried
    /// is escaped, never markup.
    #[tokio::test]
    async fn each_data_page_shows_its_data_escaped() {
        let (base, cookie) = full("pages-full-shown").await;
        let (status, home) = page(&base, HOME_PATH, Some(&cookie)).await;
        assert_eq!(status, 200);
        for (label, path, _) in NAV {
            assert!(
                home.contains(&format!(r#"<a href="/admin{path}">{label}</a>"#)),
                "{label}"
            );
        }

        let (status, body) = page(&base, REQUESTS_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{body}"
        );
        assert!(!body.contains("<script>"), "{body}");
        assert!(body.contains("[&quot;known_malware&quot;]"), "{body}");
        assert!(body.contains("1 files read."), "{body}");
        assert!(body.contains("/admin/api/v1/logs/"), "{body}");

        let (status, body) = page(&base, EVENTS_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("&lt;script&gt;steal()&lt;/script&gt;"),
            "{body}"
        );
        assert!(!body.contains("<script>"), "{body}");
        assert!(body.contains("<td>192.0.2.1</td>"), "{body}");

        let (status, body) = page(&base, DEPENDENCIES_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("<td>left-pad</td>") && body.contains("no token"),
            "{body}"
        );

        let (status, body) = page(&base, ALERTS_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains("MAL-1 (ossf-malicious)") && body.contains("<td>unknown</td>"),
            "{body}"
        );
        assert!(
            body.contains("1 served versions looked up; 1 alerts."),
            "{body}"
        );
        assert!(
            body.contains(r#"<a class="next" href="/admin/alerts?after=1">"#),
            "{body}"
        );

        let (status, body) = page(&base, CONFIG_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<th>service</th><td>byrle</td>"), "{body}");
        assert!(body.contains("cooldown_days    3"), "{body}");
        assert!(
            body.contains(&format!(
                "<code>{}</code></td><td>set</td>",
                crate::env::GITHUB_TOKEN
            )),
            "{body}"
        );
        assert!(!body.contains("ghp_x"));

        let (status, body) = page(&base, ACCOUNTS_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<td>alice</td><td>admin</td>"), "{body}");
    }

    /// The next page keeps the filters; a filter that does not parse is a 400 page.
    #[tokio::test]
    async fn a_page_keeps_its_filters_and_refuses_one_that_does_not_parse() {
        let (base, cookie) = full("pages-full-filters").await;
        let (_, body) = page(
            &base,
            &format!("{DEPENDENCIES_PAGE_PATH}?limit=1&ecosystem=npm"),
            Some(&cookie),
        )
        .await;
        assert!(
            body.contains(r#"href="/admin/dependencies?limit=1&amp;ecosystem=npm&amp;after=1""#),
            "{body}"
        );
        assert!(body.contains(r#"name="ecosystem" value="npm""#), "{body}");
        let (status, body) = page(
            &base,
            &format!("{DEPENDENCIES_PAGE_PATH}?limit=0"),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("limit is not from 1 to 1000"), "{body}");
        let (status, body) = page(
            &base,
            &format!("{REQUESTS_PAGE_PATH}?since=2026-10-10T00:00:00Z&until=2026-10-12T12:00:00Z"),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, 200);
        for day in ["2026-10-10", "2026-10-11", "2026-10-12"] {
            assert!(body.contains(&format!(">{day}</a>")), "{day}: {body}");
        }
        assert!(!body.contains(">2026-10-13</a>"), "{body}");
        assert!(days(&[("since".into(), "x".into())]).is_empty());
        let year = [
            ("since".into(), "2025-01-01T00:00:00Z".into()),
            ("until".into(), "2026-01-01T00:00:00Z".into()),
        ];
        assert_eq!(days(&year).len(), MAX_DAY_LINKS);
        assert_eq!(text(&serde_json::Value::Null), "");
        assert_eq!(text(&serde_json::json!(3)), "3");
    }

    fn row(hour: &str, answered: &str, count: i64) -> crate::usage::FailureRow {
        crate::usage::FailureRow {
            hour: hour.into(),
            ecosystem: "npm".into(),
            answered: answered.into(),
            count,
        }
    }

    /// The hours start on the hour, end before `until`, and are at most 31 days.
    #[test]
    fn the_chart_draws_each_hour_from_the_one_since_falls_in() {
        assert_eq!(
            hours("2026-10-13T09:27:00Z", "2026-10-13T11:00:00Z"),
            ["2026-10-13T09:00:00Z", "2026-10-13T10:00:00Z"]
        );
        assert!(hours("never", "2026-10-13T11:00:00Z").is_empty());
        assert_eq!(
            hours("2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z").len(),
            744,
            "31 days of hours"
        );
    }

    /// A bar is its cases stacked from the bottom, scaled so the busiest hour fills the
    /// chart; each piece is named in its title; a ninth case takes the first colour again.
    #[test]
    fn each_bar_stacks_its_cases_scaled_to_the_busiest_hour() {
        let failures = super::super::usage::Failures {
            since: "2026-10-13T09:00:00Z".into(),
            until: "2026-10-13T11:00:00Z".into(),
            failures: vec![
                row("2026-10-13T09:00:00Z", "refused", 4),
                row("2026-10-13T09:00:00Z", "unauthorized", 2),
                row("2026-10-13T10:00:00Z", "refused", 3),
            ],
        };
        let svg = chart(&failures).into_string();
        assert!(svg.contains(r##"<rect x="0.00" y="66.67" width="324.00" height="133.33" fill="#cf222e"><title>2026-10-13T09:00:00Z refused: 4</title></rect>"##), "{svg}");
        assert!(svg.contains(r##"<rect x="0.00" y="0.00" width="324.00" height="66.67" fill="#9a6700"><title>2026-10-13T09:00:00Z unauthorized: 2</title></rect>"##), "{svg}");
        assert!(
            svg.contains(
                r##"<rect x="360.00" y="100.00" width="324.00" height="100.00" fill="#cf222e">"##
            ),
            "{svg}"
        );
        assert!(svg.contains("Busiest hour: 6."), "{svg}");
        assert_eq!(
            svg.matches("<rect x=").count(),
            3,
            "no piece for a case an hour does not have: {svg}"
        );
        assert!(
            svg.contains(
                r##"<rect width="12" height="12" fill="#9a6700"></rect></svg> unauthorized"##
            ),
            "a legend rect is closed, so its label is not inside the drawing: {svg}"
        );

        let many: Vec<_> = (0..9)
            .map(|n| row("2026-10-13T09:00:00Z", &format!("case-{n}"), 1))
            .collect();
        let nine = super::super::usage::Failures {
            since: String::new(),
            until: String::new(),
            failures: many.clone(),
        };
        let pieces = stacked(
            &nine,
            &many.iter().map(|r| r.answered.as_str()).collect::<Vec<_>>(),
            "2026-10-13T09:00:00Z",
            9,
        );
        assert_eq!(pieces[8].colour, pieces[0].colour);
        let empty = super::super::usage::Failures {
            since: "x".into(),
            until: "y".into(),
            failures: vec![],
        };
        assert!(chart(&empty).into_string().contains("Busiest hour: 1."));
    }

    #[tokio::test]
    async fn the_failures_page_draws_the_counts_and_lists_them() {
        let (base, cookie) = full("pages-full-failures").await;
        let (status, body) = page(&base, FAILURES_PAGE_PATH, Some(&cookie)).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.contains(r#"<svg class="chart" viewBox="0 0 720 200""#),
            "{body}"
        );
        assert!(
            body.contains("<td>upstream-unreachable</td><td>2</td>"),
            "{body}"
        );
        assert!(body.contains("upstream-unreachable: 2</title>"), "{body}");
        let (status, _) = page(
            &base,
            &format!("{FAILURES_PAGE_PATH}?until=never"),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, 400);
    }

    /// A console with OIDC through `provider`, logins logged to a file: its base URL and
    /// the log's path.
    async fn with_oidc(
        provider: Option<crate::console::oidc::Provider>,
        label: &str,
    ) -> (String, std::path::PathBuf) {
        let (_, base, log) = oidc_site(provider, label).await;
        (base, log)
    }

    /// [`with_oidc`], with the site as well.
    async fn oidc_site(
        provider: Option<crate::console::oidc::Provider>,
        label: &str,
    ) -> (Arc<Site>, String, std::path::PathBuf) {
        oidc_site_over(store().await, provider, label).await
    }

    /// [`oidc_site`] over the account store `accounts`.
    async fn oidc_site_over(
        accounts: Arc<dyn crate::account::Accounts>,
        provider: Option<crate::console::oidc::Provider>,
        label: &str,
    ) -> (Arc<Site>, String, std::path::PathBuf) {
        let dir = crate::util::test_support::tempdir(label);
        let log = dir.join("events.log");
        let events = Arc::new(crate::account::events::EventLog::open(&log, 30).unwrap());
        let console = crate::console::Console {
            url: "https://h/admin/".into(),
            mount: crate::mount::Mount::from_url("https://h/admin/").unwrap(),
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let hasher = crate::account::password::tests::cheap();
        let limits = crate::console::login::tests::limits();
        let site = crate::console::Site::new(console, accounts, (hasher, limits), Some(events))
            .with_oidc(provider);
        let site = Arc::new(site);
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        (site, crate::proxy::testing::serve(router).await, log)
    }

    /// Past 20 failed OIDC logins from an address in the window, the callback is 429
    /// before anything is checked.
    #[tokio::test]
    async fn too_many_failed_oidc_logins_from_an_address_are_429() {
        let down = crate::console::oidc::Provider::new(
            crate::console::oidc::tests::at("http://127.0.0.1:9"),
            reqwest::Client::new(),
        );
        let (site, _, _) = oidc_site(Some(down), "pages-oidc-limited").await;
        let from = |address: [u8; 4]| {
            axum::http::Request::get("/admin/oidc/callback?code=c&state=s")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    address, 4000,
                ))))
                .body(axum::body::Body::empty())
                .unwrap()
        };
        for _ in 0..crate::console::login::tests::limits().per_address {
            assert_eq!(
                oidc_callback(site.clone(), from([192, 0, 2, 1]))
                    .await
                    .status(),
                400
            );
        }
        assert_eq!(
            oidc_callback(site.clone(), from([192, 0, 2, 1]))
                .await
                .status(),
            429
        );
        assert_eq!(
            oidc_callback(site, from([192, 0, 2, 2])).await.status(),
            400
        );
    }

    /// Begin, come back with the code, and be told the identity is linked to no account,
    /// logged as `login-failed`; the cookie that carried the login is cleared.
    #[tokio::test]
    async fn an_oidc_login_reaches_the_provider_and_comes_back_verified() {
        use crate::console::oidc::tests::{CLIENT, at, key, provider, signed};
        let (issuer, held) = provider().await;
        let (signing, jwk) = key("k1");
        held.lock().unwrap().keys = vec![jwk];
        let oidc = crate::console::oidc::Provider::new(at(&issuer), reqwest::Client::new());
        let (base, log) = with_oidc(Some(oidc), "pages-oidc").await;

        let (_, form) = page(&base, HOME_PATH, None).await;
        assert!(form.contains(r#"href="/admin/oidc/login""#), "{form}");
        let begun = client()
            .get(format!("{base}/admin{OIDC_LOGIN_PATH}"))
            .send()
            .await
            .unwrap();
        assert_eq!(begun.status(), 303);
        let location = begun.headers()["location"].to_str().unwrap().to_owned();
        let set = begun.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert!(
            set.ends_with("; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax"),
            "{set}"
        );
        let cookie = set.split(';').next().unwrap().to_owned();
        let asked: std::collections::BTreeMap<String, String> = reqwest::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(asked["redirect_uri"], "https://h/admin/oidc/callback");
        held.lock().unwrap().challenge = asked["code_challenge"].clone();
        held.lock().unwrap().token = signed(
            &signing,
            "k1",
            &serde_json::json!({
                "iss": issuer, "sub": "user-42", "aud": CLIENT, "nonce": asked["nonce"],
                "exp": jsonwebtoken::get_current_timestamp() + 3600,
            }),
        );
        let back = |query: String, cookie: Option<&str>| {
            let mut request = client().get(format!(
                "{base}/admin{}?{query}",
                crate::console::oidc::CALLBACK_PATH
            ));
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.send()
        };
        let state = &asked["state"];
        let answered = back(format!("code=c1&state={state}"), Some(&cookie))
            .await
            .unwrap();
        assert_eq!(answered.status(), 403);
        assert!(
            answered.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .starts_with("__Host-byrle_oidc=; Path=/; Max-Age=0;")
        );
        let body = answered.text().await.unwrap();
        assert!(
            body.contains(&format!("user-42 at {issuer} is not linked to an account")),
            "{body}"
        );
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains(r#""action":"login-failed","account":"user-42""#),
            "{logged}"
        );

        for (query, cookie, status, said) in [
            (
                format!("code=c1&state={state}"),
                None,
                400,
                "this login did not begin here",
            ),
            (
                "code=c1&state=other".to_owned(),
                Some(cookie.as_str()),
                400,
                "this login did not begin here",
            ),
            (
                format!("error=access_denied&state={state}"),
                Some(cookie.as_str()),
                401,
                "the identity provider refused: access_denied",
            ),
            (
                format!("state={state}"),
                Some(cookie.as_str()),
                400,
                "the identity provider sent no code",
            ),
        ] {
            let answered = back(query.clone(), cookie).await.unwrap();
            assert_eq!(answered.status(), status, "{query}");
            assert!(answered.text().await.unwrap().contains(said), "{query}");
        }
        held.lock().unwrap().token = "not a token".into();
        let refused = back(format!("code=c1&state={state}"), Some(&cookie))
            .await
            .unwrap();
        assert_eq!(refused.status(), 401);
    }

    /// No provider set is 404; one that does not answer is 502.
    #[tokio::test]
    async fn oidc_without_a_provider_or_with_one_down() {
        let (base, _) = with_oidc(None, "pages-oidc-none").await;
        for path in [OIDC_LOGIN_PATH, crate::console::oidc::CALLBACK_PATH] {
            assert_eq!(page(&base, path, None).await.0, 404, "{path}");
        }
        let (_, form) = page(&base, HOME_PATH, None).await;
        assert!(!form.contains("oidc/login"), "{form}");
        let down = crate::console::oidc::Provider::new(
            crate::console::oidc::tests::at("http://127.0.0.1:9"),
            reqwest::Client::new(),
        );
        let (base, _) = with_oidc(Some(down), "pages-oidc-down").await;
        assert_eq!(page(&base, OIDC_LOGIN_PATH, None).await.0, 502);
        let pending = crate::console::oidc::Pending::begin();
        let answered = client()
            .get(format!(
                "{base}/admin{}?code=c&state={}",
                crate::console::oidc::CALLBACK_PATH,
                pending.state
            ))
            .header("cookie", format!("{OIDC_COOKIE}={}", pending.cookie()))
            .send()
            .await
            .unwrap();
        assert_eq!(answered.status(), 502);
    }

    /// Log in through the fake provider as `user-42` against `accounts`: the callback's
    /// answer, and the account event log's text.
    async fn through_the_provider(
        accounts: Arc<dyn crate::account::Accounts>,
        label: &str,
    ) -> (reqwest::Response, String, String) {
        use crate::console::oidc::tests::{CLIENT, at, key, provider, signed};
        let (issuer, held) = provider().await;
        let (signing, jwk) = key("k1");
        held.lock().unwrap().keys = vec![jwk];
        let oidc = crate::console::oidc::Provider::new(at(&issuer), reqwest::Client::new());
        let (_, base, log) = oidc_site_over(accounts, Some(oidc), label).await;
        let begun = client()
            .get(format!("{base}/admin{OIDC_LOGIN_PATH}"))
            .send()
            .await
            .unwrap();
        let location = begun.headers()["location"].to_str().unwrap().to_owned();
        let cookie = begun.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let asked: std::collections::BTreeMap<String, String> = reqwest::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        held.lock().unwrap().challenge = asked["code_challenge"].clone();
        held.lock().unwrap().token = signed(
            &signing,
            "k1",
            &serde_json::json!({
                "iss": issuer, "sub": "user-42", "aud": CLIENT, "nonce": asked["nonce"],
                "exp": jsonwebtoken::get_current_timestamp() + 3600,
            }),
        );
        let callback = format!(
            "{base}/admin{}?code=c1&state={}",
            crate::console::oidc::CALLBACK_PATH,
            asked["state"]
        );
        let answered = client()
            .get(callback)
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        let logged = std::fs::read_to_string(&log).unwrap_or_default();
        (answered, logged, issuer)
    }

    /// A linked identity starts a session as its account: the page sets the cookie and
    /// reloads home, where the session works; the login is logged with its actor.
    #[tokio::test]
    async fn a_linked_oidc_identity_logs_in_as_its_account() {
        let accounts = store().await;
        let linked = Arc::new(Linking(accounts, std::sync::Mutex::default()));
        let (answered, logged, issuer) =
            through_the_provider(linked.clone(), "pages-oidc-linked").await;
        assert_eq!(
            *linked.1.lock().unwrap(),
            [(issuer, "user-42".to_owned())],
            "the account is looked up by the token's iss and sub"
        );
        assert_eq!(answered.status(), 200);
        let cookies: Vec<String> = answered
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert!(
            cookies[0].starts_with("byrle_session=") && cookies[0].contains("SameSite=Strict"),
            "{cookies:?}"
        );
        assert!(
            cookies[1].starts_with("__Host-byrle_oidc=; Path=/; Max-Age=0;"),
            "{cookies:?}"
        );
        let body = answered.text().await.unwrap();
        assert!(
            body.contains(r#"<meta http-equiv="refresh" content="0; url=/admin/">"#),
            "{body}"
        );
        assert!(body.contains("Logged in as alice."), "{body}");
        assert!(
            logged.contains(r#""actor":"alice","action":"login","account":"alice""#),
            "{logged}"
        );
    }

    /// The account store failing to say whose the identity is, or to start the session.
    #[tokio::test]
    async fn a_store_that_does_not_answer_ends_an_oidc_login_with_503() {
        for fails in ["oidc_account", "create_session"] {
            let inner = store().await;
            let failing = Linking(
                Arc::new(Failing { inner, fails }),
                std::sync::Mutex::default(),
            );
            let (answered, _, _) =
                through_the_provider(Arc::new(failing), &format!("pages-oidc-{fails}")).await;
            assert_eq!(answered.status(), 503, "{fails}");
        }
    }

    /// `accounts`, linking any OIDC identity to alice and keeping each one asked about.
    struct Linking(
        Arc<dyn crate::account::Accounts>,
        std::sync::Mutex<Vec<(String, String)>>,
    );

    impl crate::account::Accounts for Linking {
        fn create_account<'a>(
            &'a self,
            n: &'a crate::account::Name,
            r: &'a [crate::account::Role],
        ) -> crate::account::Pending<'a, ()> {
            self.0.create_account(n, r)
        }
        fn disable_account<'a>(
            &'a self,
            n: &'a crate::account::Name,
        ) -> crate::account::Pending<'a, ()> {
            self.0.disable_account(n)
        }
        fn accounts(&self) -> crate::account::Pending<'_, Vec<crate::account::Account>> {
            self.0.accounts()
        }
        fn create_token<'a>(
            &'a self,
            a: &'a crate::account::Name,
            n: &'a crate::account::Name,
            d: &'a crate::account::TokenDigest,
        ) -> crate::account::Pending<'a, ()> {
            self.0.create_token(a, n, d)
        }
        fn revoke_token<'a>(
            &'a self,
            a: &'a crate::account::Name,
            n: &'a crate::account::Name,
        ) -> crate::account::Pending<'a, ()> {
            self.0.revoke_token(a, n)
        }
        fn tokens<'a>(
            &'a self,
            a: Option<&'a crate::account::Name>,
        ) -> crate::account::Pending<'a, Vec<crate::account::Token>> {
            self.0.tokens(a)
        }
        fn holder<'a>(
            &'a self,
            d: &'a crate::account::TokenDigest,
        ) -> crate::account::Pending<'a, Option<crate::account::Holder>> {
            self.0.holder(d)
        }
        fn set_password<'a>(
            &'a self,
            a: &'a crate::account::Name,
            h: &'a str,
        ) -> crate::account::Pending<'a, ()> {
            self.0.set_password(a, h)
        }
        fn password<'a>(
            &'a self,
            a: &'a crate::account::Name,
        ) -> crate::account::Pending<'a, Option<String>> {
            self.0.password(a)
        }
        fn roles<'a>(
            &'a self,
            a: &'a crate::account::Name,
        ) -> crate::account::Pending<'a, Vec<crate::account::Role>> {
            self.0.roles(a)
        }
        fn create_session<'a>(
            &'a self,
            a: &'a crate::account::Name,
            d: &'a crate::account::TokenDigest,
            e: &'a str,
        ) -> crate::account::Pending<'a, ()> {
            self.0.create_session(a, d, e)
        }
        fn session<'a>(
            &'a self,
            d: &'a crate::account::TokenDigest,
        ) -> crate::account::Pending<'a, Option<crate::account::Caller>> {
            self.0.session(d)
        }
        fn end_session<'a>(
            &'a self,
            d: &'a crate::account::TokenDigest,
        ) -> crate::account::Pending<'a, ()> {
            self.0.end_session(d)
        }
        fn ping(&self) -> crate::account::Pending<'_, ()> {
            self.0.ping()
        }
        fn link_oidc<'a>(
            &'a self,
            a: &'a crate::account::Name,
            i: &'a str,
            s: &'a str,
        ) -> crate::account::Pending<'a, ()> {
            self.0.link_oidc(a, i, s)
        }
        fn oidc_account<'a>(
            &'a self,
            i: &'a str,
            s: &'a str,
        ) -> crate::account::Pending<'a, Option<crate::account::Name>> {
            let alice = crate::account::Name::parse("alice").unwrap();
            self.1.lock().unwrap().push((i.to_owned(), s.to_owned()));
            let asked = self.0.oidc_account(i, s);
            Box::pin(async move { asked.await.map(|_| Some(alice)) })
        }
    }
}
