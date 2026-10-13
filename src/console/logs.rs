//! R5 and R9: the audit log's lines, a page at a time, and a day of it whole, read from
//! the file and those rotated from it. See docs/admin-plan.md §4.3 and §4.6.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use jiff::civil::Date;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::Site;
use super::api::{Problem, json, refused};
use super::usage::{query, time};

/// Lines a page has when `limit` is not given.
pub const DEFAULT_LIMIT: usize = 100;

/// The most lines a page may ask for.
pub const MAX_LIMIT: usize = 1000;

/// How far back lines are read when `since` is not given.
pub const DEFAULT_SPAN: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

/// What part of a log to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// Lines at or after this time.
    pub since: Timestamp,
    /// Lines before this time.
    pub until: Timestamp,
    /// Lines after this time: the `next` of the page before.
    pub after: Option<Timestamp>,
    pub limit: usize,
}

/// One line, as written and as read.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub text: String,
    pub value: serde_json::Value,
}

/// Lines in a range, oldest first, and how many files were read for them.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub lines: Vec<Line>,
    /// The `at` of the last line, when the page is full.
    pub next: Option<String>,
    pub files_read: usize,
}

/// Whether a file rotated for `day` can hold lines in `range`. A day early is read too:
/// `byrle account` appends to the live file, which the proxy can rotate later.
fn may_hold(day: Option<Date>, range: &Range) -> bool {
    let utc = |at: Timestamp| at.to_zoned(jiff::tz::TimeZone::UTC).date();
    day.is_none_or(|day| {
        day.tomorrow().is_ok_and(|after| after >= utc(range.since)) && day <= utc(range.until)
    })
}

/// The lines of `path` and the files rotated from it in `range` that `wanted` keeps,
/// oldest first. A log with no file yet is empty. Errors when a file does not read.
pub fn page(
    path: &Path,
    range: &Range,
    wanted: &dyn Fn(&serde_json::Value) -> bool,
) -> Result<Page, String> {
    let mut page = Page {
        lines: Vec::new(),
        next: None,
        files_read: 0,
    };
    let files = match crate::rotation::days(path) {
        Ok(files) => files,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(page),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    for (_, file) in files.into_iter().filter(|(day, _)| may_hold(*day, range)) {
        let text = crate::rotation::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        page.files_read += 1;
        for text in text.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                continue;
            };
            let Some(at) = value["at"]
                .as_str()
                .and_then(|at| at.parse::<Timestamp>().ok())
            else {
                continue;
            };
            let in_range =
                at >= range.since && at < range.until && range.after.is_none_or(|after| at > after);
            if in_range && wanted(&value) {
                page.lines.push(Line {
                    text: text.to_owned(),
                    value,
                });
                if page.lines.len() == range.limit {
                    page.next = Some(at.to_string());
                    return Ok(page);
                }
            }
        }
    }
    Ok(page)
}

/// A page of lines, as served.
#[derive(Serialize, ToSchema)]
pub struct Lines {
    /// Each line as the log holds it: docs/engineering_decisions/audit-log.md.
    #[schema(value_type = Vec<Object>)]
    pub lines: Vec<serde_json::Value>,
    /// `after` for the next page; absent on the last.
    pub next: Option<String>,
    /// How many files were read for this page.
    pub files_read: usize,
}

/// `GET requests`'s query string, each value as given.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RequestFilters {
    /// The `next` of the page before.
    #[param(value_type = Option<String>, format = DateTime)]
    after: Option<String>,
    /// Lines on a page, 1 to 1000; 100 without it.
    #[param(value_type = Option<u32>, minimum = 1, maximum = 1000)]
    limit: Option<String>,
    /// Lines from this time; 24 hours before `until` without it.
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<String>,
    /// Lines before this time; now without it.
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<String>,
    /// `npm` or `pypi`.
    ecosystem: Option<String>,
    /// The registry name, npm's with its scope.
    name: Option<String>,
    /// The account whose token the request carried.
    account: Option<String>,
    /// What a pinned request was answered, such as `refused`.
    answered: Option<String>,
    /// A check among those that decided, such as `known_malware`.
    check: Option<String>,
    /// `pinned` for one version asked for, `resolution` for a document filtered.
    path: Option<String>,
}

/// The range a query string asks for, read as of `now`.
pub fn range(
    (after, limit, since, until): (Option<&str>, Option<&str>, Option<&str>, Option<&str>),
    now: Timestamp,
) -> Result<Range, String> {
    let until = time("until", until)?.unwrap_or(now);
    let since =
        time("since", since)?.unwrap_or_else(|| until.saturating_sub(DEFAULT_SPAN).expect("hours"));
    let limit = match limit {
        Some(value) => value
            .parse()
            .ok()
            .filter(|limit| (1..=MAX_LIMIT).contains(limit))
            .ok_or_else(|| format!("limit is not from 1 to {MAX_LIMIT}: `{value}`"))?,
        None => DEFAULT_LIMIT,
    };
    Ok(Range {
        since,
        until,
        after: time("after", after)?,
        limit,
    })
}

/// Whether a field of `line` is `wanted`, when a value is wanted.
fn matches(line: &serde_json::Value, field: &str, wanted: Option<&str>) -> bool {
    wanted.is_none_or(|wanted| line[field] == wanted)
}

impl RequestFilters {
    /// Whether `line` passes every request filter given.
    fn keeps(&self, line: &serde_json::Value) -> bool {
        matches(line, "ecosystem", self.ecosystem.as_deref())
            && matches(line, "name", self.name.as_deref())
            && matches(line, "account", self.account.as_deref())
            && matches(line, "answered", self.answered.as_deref())
            && matches(line, "path", self.path.as_deref())
            && self.check.as_deref().is_none_or(|check| {
                line["checks"]
                    .as_array()
                    .is_some_and(|checks| checks.iter().any(|c| c == check))
            })
    }
}

/// `log`, read on a blocking thread. The error says why not, for a 503.
async fn read(
    log: Option<&PathBuf>,
    range: Range,
    wanted: Box<dyn Fn(&serde_json::Value) -> bool + Send>,
) -> Result<Page, String> {
    let Some(log) = log.cloned() else {
        return Err("no log is kept".to_owned());
    };
    tokio::task::spawn_blocking(move || page(&log, &range, &*wanted))
        .await
        .expect("reading a log does not panic")
}

/// Serve `page` as JSON.
pub fn served(page: Page) -> Response {
    json(
        StatusCode::OK,
        &Lines {
            lines: page.lines.into_iter().map(|line| line.value).collect(),
            next: page.next,
            files_read: page.files_read,
        },
    )
}

/// `GET requests`: audit log lines, oldest first, a page at a time. R5 and R9.
#[utoipa::path(
    get,
    path = super::routes::REQUESTS_PATH,
    tag = "logs",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("requests.read"))),
    params(RequestFilters),
    responses(
        (status = 200, description = "A page of audit log lines", body = Lines),
        (status = 400, description = "A filter that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant requests.read", body = Problem),
        (status = 503, description = "No audit log is kept, or a file did not read", body = Problem),
    ),
)]
pub async fn requests(site: Arc<Site>, parts: Parts) -> Response {
    paged::<RequestFilters>(site.audit_log.as_ref(), &parts).await
}

/// A query string that pages through a log, and keeps the lines its filters match.
trait Filtered: serde::de::DeserializeOwned + Send + 'static {
    /// `after`, `limit`, `since` and `until`, as given.
    fn asked(&self) -> (Option<&str>, Option<&str>, Option<&str>, Option<&str>);

    /// Whether `line` passes every filter given.
    fn keeps(&self, line: &serde_json::Value) -> bool;
}

impl Filtered for RequestFilters {
    fn asked(&self) -> (Option<&str>, Option<&str>, Option<&str>, Option<&str>) {
        (
            self.after.as_deref(),
            self.limit.as_deref(),
            self.since.as_deref(),
            self.until.as_deref(),
        )
    }

    fn keeps(&self, line: &serde_json::Value) -> bool {
        RequestFilters::keeps(self, line)
    }
}

/// A page of `log` that the query string of `parts`, read as `F`, asks for.
async fn paged<F: Filtered>(log: Option<&PathBuf>, parts: &Parts) -> Response {
    let read_range = query::<F>(parts)
        .and_then(|filters| range(filters.asked(), Timestamp::now()).map(|range| (filters, range)));
    let (filters, range) = match read_range {
        Ok(read) => read,
        Err(why) => return refused(StatusCode::BAD_REQUEST, &why),
    };
    match read(log, range, Box::new(move |line| filters.keeps(line))).await {
        Ok(page) => served(page),
        Err(why) => refused(StatusCode::SERVICE_UNAVAILABLE, &why),
    }
}

/// `GET events`'s query string, each value as given.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventFilters {
    /// The `next` of the page before.
    #[param(value_type = Option<String>, format = DateTime)]
    after: Option<String>,
    /// Lines on a page, 1 to 1000; 100 without it.
    #[param(value_type = Option<u32>, minimum = 1, maximum = 1000)]
    limit: Option<String>,
    /// Lines from this time; 24 hours before `until` without it.
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<String>,
    /// Lines before this time; now without it.
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<String>,
    /// The account acted on, or the username a failed login tried.
    account: Option<String>,
    /// Such as `login-failed` or `token-created`.
    action: Option<String>,
    /// The account that acted.
    actor: Option<String>,
}

impl Filtered for EventFilters {
    fn asked(&self) -> (Option<&str>, Option<&str>, Option<&str>, Option<&str>) {
        (
            self.after.as_deref(),
            self.limit.as_deref(),
            self.since.as_deref(),
            self.until.as_deref(),
        )
    }

    fn keeps(&self, line: &serde_json::Value) -> bool {
        matches(line, "account", self.account.as_deref())
            && matches(line, "action", self.action.as_deref())
            && matches(line, "actor", self.actor.as_deref())
    }
}

/// `GET events`: account event log lines, oldest first, a page at a time. R8.
#[utoipa::path(
    get,
    path = super::routes::EVENTS_PATH,
    tag = "logs",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("events.read"))),
    params(EventFilters),
    responses(
        (status = 200, description = "A page of account event log lines", body = Lines),
        (status = 400, description = "A filter that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant events.read", body = Problem),
        (status = 503, description = "No account event log is kept, or a file did not read", body = Problem),
    ),
)]
pub async fn events(site: Arc<Site>, parts: Parts) -> Response {
    paged::<EventFilters>(site.event_log.as_ref(), &parts).await
}

/// `GET logs/{day}`: a UTC day of the audit log, its lines as written. R9.
#[utoipa::path(
    get,
    path = super::routes::LOGS_PATH,
    tag = "logs",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("requests.read"))),
    params(("day" = String, Path, description = "A UTC day, YYYY-MM-DD", format = Date)),
    responses(
        (status = 200, description = "The day's lines, one JSON object each", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "Not a day", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant requests.read", body = Problem),
        (status = 503, description = "No audit log is kept, or a file did not read", body = Problem),
    ),
)]
pub async fn day(site: Arc<Site>, parts: Parts) -> Response {
    let asked = parts.uri.path().rsplit('/').next().unwrap_or_default();
    let Ok(day) = asked.parse::<Date>() else {
        return refused(
            StatusCode::BAD_REQUEST,
            &format!("`{asked}` is not a day, YYYY-MM-DD"),
        );
    };
    let start = |day: Date| {
        day.to_zoned(jiff::tz::TimeZone::UTC)
            .map(|at| at.timestamp())
            .ok()
    };
    let Some(since) = start(day) else {
        return refused(
            StatusCode::BAD_REQUEST,
            &format!("`{asked}` is past the last day read"),
        );
    };
    let range = Range {
        since,
        until: day
            .tomorrow()
            .ok()
            .and_then(start)
            .unwrap_or(Timestamp::MAX),
        after: None,
        limit: usize::MAX,
    };
    match read(site.audit_log.as_ref(), range, Box::new(|_| true)).await {
        Ok(page) => {
            let text: String = page
                .lines
                .iter()
                .map(|line| format!("{}\n", line.text))
                .collect();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/x-ndjson"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                text,
            )
                .into_response()
        }
        Err(why) => refused(StatusCode::SERVICE_UNAVAILABLE, &why),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::console::routes::{EVENTS_PATH, LOGS_PATH, REQUESTS_PATH};
    use std::io::Write as _;

    fn line(at: &str, name: &str, answered: &str, checks: &[&str]) -> String {
        serde_json::json!({
            "at": at, "path": "pinned", "ecosystem": "npm", "name": name,
            "version": "1.0.0", "answered": answered, "checks": checks, "account": "alice",
        })
        .to_string()
    }

    /// `audit.log` rotated for the 10th, compressed for the 11th, and live for the 12th,
    /// with a line that is not JSON and one with no time.
    fn log(label: &str) -> PathBuf {
        let dir = crate::util::test_support::tempdir(label);
        let path = dir.join("audit.log");
        let tenth = [
            line("2026-10-10T08:00:00Z", "a", "served", &[]),
            line("2026-10-10T09:00:00Z", "b", "refused", &["known_malware"]),
        ];
        std::fs::write(
            dir.join("audit.log.2026-10-10"),
            tenth.join("\n") + "\nnot json\n",
        )
        .unwrap();
        let eleventh = line("2026-10-11T08:00:00Z", "c", "refused", &["cooldown"]) + "\n";
        let file = std::fs::File::create(dir.join("audit.log.2026-10-11.bz2")).unwrap();
        let mut compressed = bzip2::write::BzEncoder::new(file, bzip2::Compression::best());
        compressed.write_all(eleventh.as_bytes()).unwrap();
        compressed.finish().unwrap();
        let twelfth = [
            line("2026-10-12T08:00:00Z", "d", "served", &[]),
            r#"{"name":"untimed"}"#.to_owned(),
        ];
        std::fs::write(&path, twelfth.join("\n") + "\n").unwrap();
        path
    }

    fn at(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn whole(since: &str, until: &str) -> Range {
        Range {
            since: at(since),
            until: at(until),
            after: None,
            limit: 100,
        }
    }

    fn names(page: &Page) -> Vec<&str> {
        page.lines
            .iter()
            .map(|line| line.value["name"].as_str().unwrap())
            .collect()
    }

    /// Every file in range is read, oldest first, the compressed one too; lines that are
    /// not JSON or have no time are skipped; a range of one day reads the day before too.
    #[test]
    fn a_range_reads_the_files_that_can_hold_it() {
        let path = log("logs-range");
        let all = page(
            &path,
            &whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
            &|_| true,
        )
        .unwrap();
        assert_eq!(names(&all), ["a", "b", "c", "d"]);
        assert_eq!((all.files_read, all.next), (3, None));
        assert_eq!(
            all.lines[0].text,
            line("2026-10-10T08:00:00Z", "a", "served", &[])
        );

        let twelfth = page(
            &path,
            &whole("2026-10-12T00:00:00Z", "2026-10-13T00:00:00Z"),
            &|_| true,
        )
        .unwrap();
        assert_eq!(names(&twelfth), ["d"]);
        assert_eq!(
            twelfth.files_read, 2,
            "the 11th, a day early, and the live file"
        );
        let early = page(
            &path,
            &whole("2026-10-01T00:00:00Z", "2026-10-09T23:00:00Z"),
            &|_| true,
        )
        .unwrap();
        assert_eq!(
            early.files_read, 1,
            "only the live file, which can hold any day"
        );
        let bounds = page(
            &path,
            &whole("2026-10-10T08:00:00Z", "2026-10-10T09:00:00Z"),
            &|_| true,
        )
        .unwrap();
        assert_eq!(names(&bounds), ["a"], "since is kept and until is not");
    }

    /// A full page names its last line's time; the next page starts after it.
    #[test]
    fn a_page_ends_at_its_limit_and_the_next_starts_after_it() {
        let path = log("logs-pages");
        let mut range = whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z");
        range.limit = 2;
        let first = page(&path, &range, &|_| true).unwrap();
        assert_eq!(
            (names(&first), first.next.as_deref()),
            (vec!["a", "b"], Some("2026-10-10T09:00:00Z"))
        );
        assert_eq!(first.files_read, 1);
        range.after = Some(at("2026-10-10T09:00:00Z"));
        let second = page(&path, &range, &|_| true).unwrap();
        assert_eq!(names(&second), ["c", "d"]);
        let refused = page(
            &path,
            &whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
            &|line| line["answered"] == "refused",
        )
        .unwrap();
        assert_eq!(names(&refused), ["b", "c"]);
    }

    #[test]
    fn no_log_is_empty_and_a_file_that_does_not_read_is_an_error() {
        let dir = crate::util::test_support::tempdir("logs-missing");
        let empty = page(
            &dir.join("audit.log"),
            &whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
            &|_| true,
        )
        .unwrap();
        assert_eq!((empty.lines.len(), empty.files_read), (0, 0));
        let path = dir.join("audit.log");
        std::fs::write(&path, "").unwrap();
        std::fs::write(dir.join("audit.log.2026-10-10.bz2"), "not bzip2").unwrap();
        let broken = page(
            &path,
            &whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
            &|_| true,
        )
        .unwrap_err();
        assert!(broken.contains("audit.log.2026-10-10.bz2"), "{broken}");
        let not_a_directory = dir.join("audit.log").join("audit.log");
        let unlisted = page(
            &not_a_directory,
            &whole("2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"),
            &|_| true,
        )
        .unwrap_err();
        assert!(
            unlisted.starts_with(&not_a_directory.display().to_string()),
            "{unlisted}"
        );
    }

    #[test]
    fn a_query_gives_a_range_or_says_which_value_is_wrong() {
        let now = at("2026-10-13T12:00:00Z");
        let given = range(
            (
                Some("2026-10-13T01:00:00Z"),
                Some("5"),
                Some("2026-10-12T00:00:00Z"),
                Some("2026-10-13T00:00:00Z"),
            ),
            now,
        )
        .unwrap();
        assert_eq!(
            given,
            Range {
                since: at("2026-10-12T00:00:00Z"),
                until: at("2026-10-13T00:00:00Z"),
                after: Some(at("2026-10-13T01:00:00Z")),
                limit: 5,
            }
        );
        let defaults = range((None, None, None, None), now).unwrap();
        assert_eq!(
            (defaults.since, defaults.until, defaults.limit),
            (at("2026-10-12T12:00:00Z"), now, DEFAULT_LIMIT)
        );
        for (asked, said) in [
            ((None, Some("0"), None, None), "limit is not from 1 to 1000"),
            (
                (None, Some("1001"), None, None),
                "limit is not from 1 to 1000",
            ),
            (
                (Some("x"), None, None, None),
                "after is not an RFC 3339 time",
            ),
            (
                (None, None, Some("x"), None),
                "since is not an RFC 3339 time",
            ),
            (
                (None, None, None, Some("x")),
                "until is not an RFC 3339 time",
            ),
        ] {
            assert!(
                range(asked, now).unwrap_err().starts_with(said),
                "{asked:?}"
            );
        }
        assert_eq!(
            range((None, Some("1000"), None, None), now).unwrap().limit,
            1000
        );
    }

    #[test]
    fn each_request_filter_narrows_the_lines() {
        let refused = serde_json::from_str::<serde_json::Value>(&line(
            "2026-10-10T09:00:00Z",
            "b",
            "refused",
            &["known_malware"],
        ))
        .unwrap();
        let filters = |q: &str| -> RequestFilters { serde_urlencoded_like(q) };
        assert!(filters("").keeps(&refused));
        assert!(filters("answered=refused&check=known_malware").keeps(&refused));
        for wrong in [
            "ecosystem=pypi",
            "name=a",
            "account=bob",
            "answered=served",
            "path=resolution",
            "check=cooldown",
        ] {
            assert!(!filters(wrong).keeps(&refused), "{wrong}");
        }
        let unchecked = serde_json::json!({ "name": "x" });
        assert!(!filters("check=known_malware").keeps(&unchecked));
    }

    /// `RequestFilters` from a query string, as the handler reads one.
    fn serde_urlencoded_like(query: &str) -> RequestFilters {
        let uri: axum::http::Uri = format!("/x?{query}").parse().unwrap();
        axum::extract::Query::<RequestFilters>::try_from_uri(&uri)
            .unwrap()
            .0
    }

    /// The console with `audit_log`, served, and alice's session cookie.
    async fn console(audit_log: Option<PathBuf>) -> (String, String) {
        with_logs(audit_log, None).await
    }

    /// The console with both logs, served, and alice's session cookie.
    async fn with_logs(audit_log: Option<PathBuf>, event_log: Option<PathBuf>) -> (String, String) {
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
        };
        let store = crate::console::login::tests::store().await;
        let site =
            Arc::new(crate::console::tests::unread(console, store).with_logs(audit_log, event_log));
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        let base = crate::proxy::testing::serve(router).await;
        let body = serde_json::json!({ "account": "alice", "password": crate::console::login::tests::PASSWORD });
        let login = reqwest::Client::new()
            .post(format!("{base}{}", crate::console::LOGIN_PATH))
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
        (base, cookie)
    }

    async fn get(base: &str, cookie: &str, path: &str) -> (u16, String, String) {
        let answered = reqwest::Client::new()
            .get(format!("{base}{path}"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        let kind = answered
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned())
            .unwrap_or_default();
        (
            answered.status().as_u16(),
            kind,
            answered.text().await.unwrap(),
        )
    }

    /// R5: the refusals for malware, as a page, through the console.
    #[tokio::test]
    async fn the_requests_refused_as_malware_are_read_through_the_console() {
        let (base, cookie) = console(Some(log("logs-console"))).await;
        let query = "?since=2026-10-01T00:00:00Z&until=2026-10-31T00:00:00Z&answered=refused&check=known_malware";
        let (status, _, body) = get(&base, &cookie, &format!("{REQUESTS_PATH}{query}")).await;
        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["lines"].as_array().unwrap().len(), 1);
        assert_eq!(body["lines"][0]["name"], "b");
        assert_eq!(
            (&body["next"], &body["files_read"]),
            (&serde_json::Value::Null, &serde_json::json!(3))
        );
        let (status, _, body) = get(&base, &cookie, &format!("{REQUESTS_PATH}?limit=0")).await;
        assert_eq!(status, 400, "{body}");
    }

    /// A day is its lines as written, as NDJSON; a value not a day is 400.
    #[tokio::test]
    async fn a_day_of_the_log_is_its_lines_as_written() {
        let (base, cookie) = console(Some(log("logs-day"))).await;
        let (status, kind, body) =
            get(&base, &cookie, &LOGS_PATH.replace("{day}", "2026-10-10")).await;
        assert_eq!((status, kind.as_str()), (200, "application/x-ndjson"));
        assert_eq!(
            body,
            format!(
                "{}\n{}\n",
                line("2026-10-10T08:00:00Z", "a", "served", &[]),
                line("2026-10-10T09:00:00Z", "b", "refused", &["known_malware"])
            )
        );
        let (status, _, _) = get(&base, &cookie, &LOGS_PATH.replace("{day}", "yesterday")).await;
        assert_eq!(status, 400);
        let (status, _, body) =
            get(&base, &cookie, &LOGS_PATH.replace("{day}", "9999-12-31")).await;
        assert_eq!(
            status, 400,
            "midnight of the last day is past jiff's last time: {body}"
        );
        let (status, _, body) =
            get(&base, &cookie, &LOGS_PATH.replace("{day}", "9999-12-30")).await;
        assert_eq!(
            (status, body.as_str()),
            (200, ""),
            "the day before it is not"
        );
    }

    /// No log configured, or one whose file does not read, is 503.
    #[tokio::test]
    async fn no_log_or_one_that_does_not_read_is_503() {
        let (base, cookie) = console(None).await;
        for path in [
            REQUESTS_PATH.to_owned(),
            LOGS_PATH.replace("{day}", "2026-10-10"),
        ] {
            let (status, _, body) = get(&base, &cookie, &path).await;
            assert_eq!(status, 503, "{path}: {body}");
            assert!(body.contains("no log is kept"), "{body}");
        }
        let dir = crate::util::test_support::tempdir("logs-unread");
        std::fs::write(dir.join("audit.log"), "").unwrap();
        std::fs::write(dir.join("audit.log.2026-10-12.bz2"), "not bzip2").unwrap();
        let (base, cookie) = console(Some(dir.join("audit.log"))).await;
        let (status, _, body) = get(
            &base,
            &cookie,
            &format!("{REQUESTS_PATH}?since=2026-10-12T00:00:00Z"),
        )
        .await;
        assert_eq!(status, 503, "{body}");
    }

    /// R8: logins and failed logins, filtered by action, account and actor.
    #[tokio::test]
    async fn the_account_events_are_read_through_the_console() {
        let dir = crate::util::test_support::tempdir("logs-events");
        let path = dir.join("events.log");
        let events = [
            r#"{"at":"2026-10-13T08:00:00Z","action":"login-failed","account":"alice","source":"192.0.2.1"}"#,
            r#"{"at":"2026-10-13T08:01:00Z","actor":"alice","action":"login","account":"alice","source":"192.0.2.1"}"#,
            r#"{"at":"2026-10-13T08:02:00Z","action":"token-created","account":"bob","token":"ci","source":"cli"}"#,
        ];
        std::fs::write(&path, events.join("\n") + "\n").unwrap();
        let (base, cookie) = with_logs(None, Some(path)).await;
        let range = "since=2026-10-13T00:00:00Z&until=2026-10-14T00:00:00Z";
        for (filter, expected) in [
            ("", 3),
            ("&action=login-failed", 1),
            ("&account=alice", 2),
            ("&actor=alice", 1),
        ] {
            let (status, _, body) =
                get(&base, &cookie, &format!("{EVENTS_PATH}?{range}{filter}")).await;
            assert_eq!(status, 200, "{body}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                body["lines"].as_array().unwrap().len(),
                expected,
                "{filter}"
            );
        }
        let (status, _, _) = get(&base, &cookie, &format!("{EVENTS_PATH}?until=never")).await;
        assert_eq!(status, 400);
        let (base, cookie) = console(None).await;
        let (status, _, _) = get(&base, &cookie, EVENTS_PATH).await;
        assert_eq!(status, 503);
    }
}
