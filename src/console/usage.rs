//! R3 and R6: the versions served to each account, and failures by hour and case, read
//! from the usage tables. See docs/admin-plan.md §4.3 and §4.6.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::Site;
use super::api::{Problem, json, refused};
use crate::usage::{FailureQuery, FailureRow, ServedQuery, ServedRow};

/// Rows a page of served versions has when `limit` is not given.
pub const DEFAULT_LIMIT: u32 = 100;

/// The most rows a page may ask for.
pub const MAX_LIMIT: u32 = 1000;

/// How far back failures are read when `since` is not given.
pub const DEFAULT_FAILURE_SPAN: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

/// Why a read of the usage tables is 503.
const UNANSWERED: &str = "the usage tables did not answer";

/// 503 from a console with no usage tables to read.
fn not_kept() -> Response {
    refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "this console reads no usage tables",
    )
}

/// `GET dependencies`'s query string, each value as given.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DependencyFilters {
    /// The `next` of the page before; the first page without it.
    #[param(value_type = Option<i64>)]
    after: Option<String>,
    /// Rows on a page, 1 to 1000; 100 without it.
    #[param(value_type = Option<u32>, minimum = 1, maximum = 1000)]
    limit: Option<String>,
    /// `npm` or `pypi`.
    ecosystem: Option<String>,
    /// The registry name, npm's with its scope.
    name: Option<String>,
    /// The account served.
    account: Option<String>,
    /// Last served at or after this time.
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<String>,
    /// First served before this time.
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<String>,
}

/// `GET metrics/failures`'s query string, each value as given.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FailureFilters {
    /// `npm` or `pypi`.
    ecosystem: Option<String>,
    /// An `answered` case, such as `upstream-unreachable`.
    answered: Option<String>,
    /// Hours from this time; 24 hours before `until` without it.
    #[param(value_type = Option<String>, format = DateTime)]
    since: Option<String>,
    /// Hours before this time; now without it.
    #[param(value_type = Option<String>, format = DateTime)]
    until: Option<String>,
}

/// A page of served versions.
#[derive(Serialize, ToSchema)]
pub struct Versions {
    pub versions: Vec<ServedRow>,
    /// `after` for the next page; absent on the last.
    pub next: Option<i64>,
}

/// Failure counts, by hour, ecosystem and case.
#[derive(Serialize, ToSchema)]
pub struct Failures {
    pub failures: Vec<FailureRow>,
}

/// The query string of `parts` as `T`. Unknown keys are ignored.
fn query<T: serde::de::DeserializeOwned>(parts: &Parts) -> Result<T, String> {
    axum::extract::Query::<T>::try_from_uri(&parts.uri)
        .map(|query| query.0)
        .map_err(|e| format!("the query string is not understood: {e}"))
}

/// `value` of `field` as a time, when given.
fn time(field: &str, value: Option<&str>) -> Result<Option<Timestamp>, String> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|_| format!("{field} is not an RFC 3339 time: `{value}`"))
        })
        .transpose()
}

impl DependencyFilters {
    fn read(self) -> Result<ServedQuery, String> {
        let after = match self.after.as_deref() {
            Some(value) => value
                .parse()
                .map_err(|_| format!("after is not a row id: `{value}`"))?,
            None => 0,
        };
        let limit = match self.limit.as_deref() {
            Some(value) => value
                .parse()
                .ok()
                .filter(|limit| (1..=MAX_LIMIT).contains(limit))
                .ok_or_else(|| format!("limit is not from 1 to {MAX_LIMIT}: `{value}`"))?,
            None => DEFAULT_LIMIT,
        };
        Ok(ServedQuery {
            after,
            limit,
            since: time("since", self.since.as_deref())?,
            until: time("until", self.until.as_deref())?,
            ecosystem: self.ecosystem,
            name: self.name,
            account: self.account,
        })
    }
}

impl FailureFilters {
    fn read(self, now: Timestamp) -> Result<FailureQuery, String> {
        let until = time("until", self.until.as_deref())?.unwrap_or(now);
        let since = time("since", self.since.as_deref())?
            .unwrap_or_else(|| until.saturating_sub(DEFAULT_FAILURE_SPAN).expect("hours"));
        Ok(FailureQuery {
            since,
            until,
            ecosystem: self.ecosystem,
            answered: self.answered,
        })
    }
}

/// `GET dependencies`: served versions by row id, a page at a time. R3.
#[utoipa::path(
    get,
    path = super::routes::DEPENDENCIES_PATH,
    tag = "usage",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("requests.read"))),
    params(DependencyFilters),
    responses(
        (status = 200, description = "A page of served versions", body = Versions),
        (status = 400, description = "A filter that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant requests.read", body = Problem),
        (status = 503, description = "The usage tables did not answer", body = Problem),
    ),
)]
pub async fn dependencies(site: Arc<Site>, parts: Parts) -> Response {
    let Some(usage) = &site.usage else {
        return not_kept();
    };
    let query = match query::<DependencyFilters>(&parts).and_then(DependencyFilters::read) {
        Ok(query) => query,
        Err(why) => return refused(StatusCode::BAD_REQUEST, &why),
    };
    match usage.served(&query).await {
        Ok(rows) => {
            let next = rows
                .last()
                .filter(|_| rows.len() == query.limit as usize)
                .map(|row| row.id);
            json(
                StatusCode::OK,
                &Versions {
                    versions: rows,
                    next,
                },
            )
        }
        Err(_) => refused(StatusCode::SERVICE_UNAVAILABLE, UNANSWERED),
    }
}

/// `GET metrics/failures`: counts by hour, ecosystem and case, the last 24 hours by default. R6.
#[utoipa::path(
    get,
    path = super::routes::FAILURES_PATH,
    tag = "usage",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("requests.read"))),
    params(FailureFilters),
    responses(
        (status = 200, description = "Counts by hour, ecosystem and case", body = Failures),
        (status = 400, description = "A filter that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant requests.read", body = Problem),
        (status = 503, description = "The usage tables did not answer", body = Problem),
    ),
)]
pub async fn failures(site: Arc<Site>, parts: Parts) -> Response {
    let Some(usage) = &site.usage else {
        return not_kept();
    };
    let query = match query::<FailureFilters>(&parts).and_then(|f| f.read(Timestamp::now())) {
        Ok(query) => query,
        Err(why) => return refused(StatusCode::BAD_REQUEST, &why),
    };
    match usage.failures(&query).await {
        Ok(rows) => json(StatusCode::OK, &Failures { failures: rows }),
        Err(_) => refused(StatusCode::SERVICE_UNAVAILABLE, UNANSWERED),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::audit::Answered;
    use crate::console::login::tests::store;
    use crate::console::routes::{DEPENDENCIES_PATH, FAILURES_PATH};
    use crate::usage::tests::Kept;
    use crate::usage::{Read, Usage, Use};

    /// Usage tables that never answer.
    struct Down;

    impl Usage for Down {
        fn served<'a>(&'a self, _: &'a ServedQuery) -> Read<'a, Vec<ServedRow>> {
            Box::pin(async { Err("closed".to_owned()) })
        }
        fn failures<'a>(&'a self, _: &'a FailureQuery) -> Read<'a, Vec<FailureRow>> {
            Box::pin(async { Err("closed".to_owned()) })
        }
    }

    /// The console with `usage`, or none, served; alice is an admin.
    async fn console(usage: Option<Arc<dyn Usage>>) -> String {
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
        };
        let site = crate::console::tests::unread(console, store().await);
        let site = Arc::new(match usage {
            Some(usage) => site.with_usage(usage),
            None => site,
        });
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        crate::proxy::testing::serve(router).await
    }

    /// `path?query` as alice: its status and body.
    async fn read(base: &str, path: &str, query: &str) -> (u16, serde_json::Value) {
        let body = serde_json::json!({ "account": "alice", "password": crate::console::login::tests::PASSWORD });
        let client = reqwest::Client::new();
        let login = client
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
        let answered = client
            .get(format!("{base}{path}?{query}"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        let status = answered.status().as_u16();
        (
            status,
            serde_json::from_str(&answered.text().await.unwrap()).unwrap(),
        )
    }

    fn served(account: Option<&str>, name: &str, at: &str) -> Use {
        Use::Served {
            account: account.map(str::to_owned),
            ecosystem: "npm".into(),
            name: name.into(),
            version: "1.0.0".into(),
            at: at.parse().unwrap(),
        }
    }

    fn names(body: &serde_json::Value) -> Vec<String> {
        body["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap().to_owned())
            .collect()
    }

    /// A page ends at `limit` and names the next; each filter narrows it.
    #[tokio::test]
    async fn the_versions_served_are_read_a_page_at_a_time_and_filtered() {
        let kept = Arc::new(Kept::default());
        kept.0.lock().unwrap().extend([
            served(Some("alice"), "a", "2026-10-01T00:00:00Z"),
            served(None, "b", "2026-10-05T00:00:00Z"),
            served(Some("alice"), "c", "2026-10-09T00:00:00Z"),
        ]);
        let base = console(Some(kept)).await;
        let (status, first) = read(&base, DEPENDENCIES_PATH, "limit=2").await;
        assert_eq!(status, 200);
        assert_eq!(names(&first), ["a", "b"]);
        assert_eq!(first["next"], 2);
        assert_eq!(first["versions"][0]["account"], "alice");
        assert_eq!(first["versions"][1]["account"], serde_json::Value::Null);
        assert_eq!(first["versions"][0]["first_served"], "2026-10-01T00:00:00Z");
        let (_, rest) = read(&base, DEPENDENCIES_PATH, "limit=2&after=2").await;
        assert_eq!(
            (names(&rest), &rest["next"]),
            (vec!["c".to_owned()], &serde_json::Value::Null)
        );
        let (_, all) = read(&base, DEPENDENCIES_PATH, "").await;
        assert_eq!(names(&all), ["a", "b", "c"]);
        for (query, expected) in [
            ("account=alice", vec!["a", "c"]),
            ("name=b&ecosystem=npm", vec!["b"]),
            ("ecosystem=pypi", vec![]),
            ("since=2026-10-05T00:00:00Z", vec!["b", "c"]),
            ("until=2026-10-05T00:00:00Z", vec!["a"]),
        ] {
            let (_, page) = read(&base, DEPENDENCIES_PATH, query).await;
            assert_eq!(names(&page), expected, "{query}");
        }
    }

    #[tokio::test]
    async fn a_filter_that_does_not_parse_is_400() {
        let base = console(Some(Arc::new(Kept::default()))).await;
        for (path, query, said) in [
            (DEPENDENCIES_PATH, "after=x", "after is not a row id"),
            (DEPENDENCIES_PATH, "limit=0", "limit is not from 1 to 1000"),
            (
                DEPENDENCIES_PATH,
                "limit=1001",
                "limit is not from 1 to 1000",
            ),
            (
                DEPENDENCIES_PATH,
                "since=yesterday",
                "since is not an RFC 3339 time",
            ),
            (
                DEPENDENCIES_PATH,
                "until=2026-13-01",
                "until is not an RFC 3339 time",
            ),
            (
                DEPENDENCIES_PATH,
                "after=1&after=2",
                "the query string is not understood",
            ),
            (FAILURES_PATH, "until=soon", "until is not an RFC 3339 time"),
            (FAILURES_PATH, "since=then", "since is not an RFC 3339 time"),
        ] {
            let (status, body) = read(&base, path, query).await;
            assert_eq!(status, 400, "{query}");
            assert!(
                body["error"].as_str().unwrap().starts_with(said),
                "{query}: {body}"
            );
        }
    }

    /// The last 24 hours by default; `since` reaches further back; each filter narrows.
    #[tokio::test]
    async fn failures_are_counted_by_hour_for_the_last_day_unless_asked() {
        let now = Timestamp::now();
        let hour = |back: i64| {
            let at = now - jiff::SignedDuration::from_hours(back);
            at.round(
                jiff::TimestampRound::new()
                    .smallest(jiff::Unit::Hour)
                    .mode(jiff::RoundMode::Trunc),
            )
            .unwrap()
        };
        let failed = |back: i64, ecosystem: &str, answered: Answered| Use::Failed {
            hour: hour(back),
            ecosystem: ecosystem.into(),
            answered,
        };
        let kept = Arc::new(Kept::default());
        kept.0.lock().unwrap().extend([
            failed(2, "npm", Answered::Refused),
            failed(2, "npm", Answered::Refused),
            failed(1, "pypi", Answered::Unauthorized),
            failed(30, "npm", Answered::Refused),
        ]);
        let base = console(Some(kept)).await;
        let counts = |body: &serde_json::Value| -> Vec<(String, String, i64)> {
            body["failures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        row["ecosystem"].as_str().unwrap().to_owned(),
                        row["answered"].as_str().unwrap().to_owned(),
                        row["count"].as_i64().unwrap(),
                    )
                })
                .collect()
        };
        let (status, recent) = read(&base, FAILURES_PATH, "").await;
        assert_eq!(status, 200);
        assert_eq!(
            counts(&recent),
            [
                ("npm".into(), "refused".into(), 2),
                ("pypi".into(), "unauthorized".into(), 1),
            ]
        );
        assert_eq!(recent["failures"][0]["hour"], crate::usage::second(hour(2)));
        let since = crate::usage::second(hour(48));
        let (_, all) = read(&base, FAILURES_PATH, &format!("since={since}")).await;
        assert_eq!(counts(&all).len(), 3);
        let (_, npm) = read(
            &base,
            FAILURES_PATH,
            &format!("since={since}&ecosystem=npm"),
        )
        .await;
        assert_eq!(counts(&npm).len(), 2);
        let (_, unauthorized) = read(&base, FAILURES_PATH, "answered=unauthorized").await;
        assert_eq!(
            counts(&unauthorized),
            [("pypi".into(), "unauthorized".into(), 1)]
        );
        let until = crate::usage::second(hour(29));
        let (_, old) = read(&base, FAILURES_PATH, &format!("until={until}")).await;
        assert_eq!(
            counts(&old),
            [("npm".into(), "refused".into(), 1)],
            "the 24 hours before until"
        );
    }

    /// No usage tables, or tables that do not answer, are 503.
    #[tokio::test]
    async fn usage_tables_absent_or_down_are_503() {
        for usage in [None, Some(Arc::new(Down) as Arc<dyn Usage>)] {
            let absent = usage.is_none();
            let base = console(usage).await;
            for path in [DEPENDENCIES_PATH, FAILURES_PATH] {
                let (status, body) = read(&base, path, "").await;
                assert_eq!(status, 503, "{path}");
                let said = if absent {
                    "this console reads no usage tables"
                } else {
                    UNANSWERED
                };
                assert_eq!(body["error"], said, "{path}");
            }
        }
    }
}
