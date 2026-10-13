//! R4: each version served to an account that a malware advisory loaded later names. See
//! docs/admin-plan.md §4.4.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::Site;
use super::api::{Problem, json, refused};
use super::usage::query;
use crate::intel::store::{Intel, PackageIntel};
use crate::usage::{ServedQuery, ServedRow, Usage};

/// The most served versions one request looks up.
pub const MAX_SCANNED: usize = 10_000;

/// Served versions read from the table at a time.
const BATCH: usize = 1000;

/// One served version a malware advisory names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Alert {
    /// The served version, as `GET dependencies` lists it.
    pub served: ServedRow,
    pub advisory_id: String,
    pub aliases: Vec<String>,
    /// The stream it came from.
    pub source: String,
    /// When byrle first stored the advisory, RFC 3339; absent when the store does not say.
    pub loaded: Option<String>,
}

/// Alerts found, and where the next request goes on from.
#[derive(Debug, Serialize, ToSchema)]
pub struct Alerts {
    pub alerts: Vec<Alert>,
    /// `after` for the next request; absent once every served version is looked up.
    pub next: Option<i64>,
    /// Served versions looked up for this answer.
    pub scanned: usize,
}

/// `GET alerts`'s query string, each value as given.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AlertFilters {
    /// The `next` of the answer before; the first served version without it.
    #[param(value_type = Option<i64>)]
    after: Option<String>,
}

/// Whether `advisory`, loaded at `loaded`, was unknown when `served` was first served.
fn after_serving(loaded: Option<&str>, served: &ServedRow) -> bool {
    let first = served.first_served.parse::<Timestamp>().ok();
    match (loaded.and_then(|at| at.parse::<Timestamp>().ok()), first) {
        (Some(loaded), Some(first)) => loaded > first,
        _ => true,
    }
}

/// The alerts among served versions after `after`, looking up about `most`, a batch at a
/// time, each package once.
pub async fn scan(
    usage: &dyn Usage,
    intel: &dyn Intel,
    after: i64,
    most: usize,
) -> Result<Alerts, String> {
    let mut found = Alerts {
        alerts: Vec::new(),
        next: None,
        scanned: 0,
    };
    let mut known: HashMap<(String, String), Option<PackageIntel>> = HashMap::new();
    let mut cursor = after;
    while found.scanned < most {
        let page = ServedQuery {
            after: cursor,
            limit: (most - found.scanned).min(BATCH) as u32,
            ..ServedQuery::default()
        };
        let rows = usage.served(&page).await?;
        let Some(last) = rows.last() else {
            return Ok(found);
        };
        cursor = last.id;
        for row in rows {
            let key = (row.ecosystem.clone(), row.name.clone());
            if !known.contains_key(&key) {
                let package = intel.package(&row.ecosystem, &row.name).await;
                known.insert(key.clone(), package.map_err(|e| e.to_string())?);
            }
            let records = known[&key]
                .as_ref()
                .map(|package| package.for_version(&row.ecosystem, &row.version))
                .unwrap_or_default();
            for record in records.into_iter().filter(|r| r.malware) {
                if after_serving(record.cached.as_deref(), &row) {
                    found.alerts.push(Alert {
                        served: row.clone(),
                        advisory_id: record.advisory_id.clone(),
                        aliases: record.aliases.clone(),
                        source: record.source.clone(),
                        loaded: record.cached.clone(),
                    });
                }
            }
            found.scanned += 1;
        }
        found.next = Some(cursor);
    }
    Ok(found)
}

/// `GET alerts`: served versions a malware advisory loaded after their serving names. R4.
#[utoipa::path(
    get,
    path = super::routes::ALERTS_PATH,
    tag = "usage",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("alerts.read"))),
    params(AlertFilters),
    responses(
        (status = 200, description = "Alerts, and where to go on from", body = Alerts),
        (status = 400, description = "`after` is not a row id", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant alerts.read", body = Problem),
        (status = 503, description = "No usage tables or intel store, or one did not answer", body = Problem),
    ),
)]
pub async fn alerts(site: Arc<Site>, parts: Parts) -> Response {
    let after = query::<AlertFilters>(&parts).and_then(|filters| match filters.after {
        Some(after) => after
            .parse::<i64>()
            .map_err(|_| format!("after is not a row id: `{after}`")),
        None => Ok(0),
    });
    let after = match after {
        Ok(after) => after,
        Err(why) => return refused(StatusCode::BAD_REQUEST, &why),
    };
    let intel = site
        .configured
        .as_ref()
        .and_then(|configured| configured.proxy.intel_store());
    let (Some(usage), Some(intel)) = (&site.usage, intel) else {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "alerts need the usage tables and an intel store",
        );
    };
    match scan(usage.as_ref(), intel.as_ref(), after, MAX_SCANNED).await {
        Ok(alerts) => json(StatusCode::OK, &alerts),
        Err(why) => refused(StatusCode::SERVICE_UNAVAILABLE, &why),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::intel::store::Record;
    use crate::intel::store::testing::FixedIntel;
    use crate::usage::Use;
    use crate::usage::tests::Kept;

    fn served(name: &str, version: &str, at: &str) -> Use {
        Use::Served {
            account: Some("alice".into()),
            ecosystem: "npm".into(),
            name: name.into(),
            version: version.into(),
            at: at.parse().unwrap(),
        }
    }

    fn record(id: &str, malware: bool, cached: Option<&str>) -> Record {
        Record {
            advisory_id: id.into(),
            aliases: vec![format!("{id}-alias")],
            source: "ossf-malicious".into(),
            cvss: None,
            cvss_source: None,
            band: None,
            exploited: false,
            malware,
            cached: cached.map(str::to_owned),
        }
    }

    /// An intel store naming version `1.0.0` of every package with `records`.
    fn naming(records: Vec<Record>) -> FixedIntel {
        FixedIntel(Ok(Some(PackageIntel {
            snapshot: "s1".into(),
            records: records
                .into_iter()
                .map(|r| (Some("1.0.0".into()), r))
                .collect(),
            ranges: Vec::new(),
            exploitation_loaded: false,
        })))
    }

    /// A malware advisory loaded after the version was first served, or at a time the
    /// store does not give, is an alert; one loaded before, or not malware, is not.
    #[tokio::test]
    async fn a_version_served_before_its_malware_advisory_loaded_is_an_alert() {
        let usage = Kept::default();
        usage.0.lock().unwrap().extend([
            served("a", "1.0.0", "2026-10-13T09:00:00Z"),
            served("a", "2.0.0", "2026-10-13T09:00:00Z"),
        ]);
        let intel = naming(vec![
            record("MAL-later", true, Some("2026-10-13T10:00:00Z")),
            record("MAL-earlier", true, Some("2026-10-13T08:00:00Z")),
            record("MAL-same", true, Some("2026-10-13T09:00:00Z")),
            record("MAL-unknown", true, None),
            record("GHSA-cve", false, Some("2026-10-13T10:00:00Z")),
        ]);
        let found = scan(&usage, &intel, 0, MAX_SCANNED).await.unwrap();
        let ids: Vec<&str> = found
            .alerts
            .iter()
            .map(|a| a.advisory_id.as_str())
            .collect();
        assert_eq!(ids, ["MAL-later", "MAL-unknown"]);
        assert_eq!((found.scanned, found.next), (2, Some(2)));
        let alert = &found.alerts[0];
        assert_eq!(
            (alert.served.version.as_str(), alert.loaded.as_deref()),
            ("1.0.0", Some("2026-10-13T10:00:00Z"))
        );
        assert_eq!(alert.aliases, ["MAL-later-alias"]);
        let resumed = scan(&usage, &intel, 2, MAX_SCANNED).await.unwrap();
        assert_eq!(
            (resumed.alerts.len(), resumed.scanned, resumed.next),
            (0, 0, None)
        );
        assert!(after_serving(Some("not a time"), &found.alerts[0].served));
    }

    /// One request looks up at most `most` versions, and says where to go on.
    #[tokio::test]
    async fn a_scan_stops_at_its_most_and_says_where_to_go_on() {
        let usage = Kept::default();
        usage
            .0
            .lock()
            .unwrap()
            .extend((0..4).map(|n| served(&format!("p{n}"), "1.0.0", "2026-10-13T09:00:00Z")));
        let found = scan(&usage, &naming(Vec::new()), 0, 3).await.unwrap();
        assert_eq!((found.scanned, found.next), (3, Some(3)));
        let rest = scan(&usage, &naming(Vec::new()), 3, 3).await.unwrap();
        assert_eq!((rest.scanned, rest.next), (1, Some(4)));
    }

    /// [`Kept`], counting the pages read.
    #[derive(Default)]
    struct Counted(Kept, std::sync::atomic::AtomicUsize);

    impl Usage for Counted {
        fn served<'a>(&'a self, query: &'a ServedQuery) -> crate::usage::Read<'a, Vec<ServedRow>> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.0.served(query)
        }
        fn failures<'a>(
            &'a self,
            query: &'a crate::usage::FailureQuery,
        ) -> crate::usage::Read<'a, Vec<crate::usage::FailureRow>> {
            self.0.failures(query)
        }
    }

    /// A second batch asks for only what is left of `most`, and a scan that has read
    /// `most` asks for no more.
    #[tokio::test]
    async fn the_last_batch_asks_only_for_what_is_left() {
        let usage = Counted::default();
        usage
            .0
            .0
            .lock()
            .unwrap()
            .extend((0..1200).map(|n| served(&format!("p{n}"), "1.0.0", "2026-10-13T09:00:00Z")));
        let found = scan(&usage, &naming(Vec::new()), 0, 1100).await.unwrap();
        assert_eq!((found.scanned, found.next), (1100, Some(1100)));
        assert_eq!(usage.1.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn a_store_that_does_not_answer_is_an_error_and_no_snapshot_is_no_alert() {
        let usage = Kept::default();
        usage
            .0
            .lock()
            .unwrap()
            .push(served("a", "1.0.0", "2026-10-13T09:00:00Z"));
        assert!(
            scan(&usage, &FixedIntel(Err(())), 0, MAX_SCANNED)
                .await
                .is_err()
        );
        let down = crate::console::usage::tests::Down;
        let unread = scan(&down, &naming(Vec::new()), 0, MAX_SCANNED).await;
        assert_eq!(unread.unwrap_err(), "closed");
        let empty = scan(&usage, &FixedIntel(Ok(None)), 0, MAX_SCANNED)
            .await
            .unwrap();
        assert_eq!((empty.alerts.len(), empty.scanned), (0, 1));
    }

    /// The console with `usage` and a proxy with `intel`, served, and alice's cookie.
    async fn console(
        usage: Option<Arc<dyn Usage>>,
        intel: Option<Arc<dyn Intel>>,
    ) -> (String, String) {
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
        };
        let store = crate::console::login::tests::store().await;
        let proxy = crate::proxy::Proxy::new(reqwest::Client::new()).with_intel(intel);
        let site = crate::console::tests::unread(console, store).with_proxy(proxy, Vec::new());
        let site = Arc::new(match usage {
            Some(usage) => site.with_usage(usage),
            None => site,
        });
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

    async fn get(base: &str, cookie: &str, query: &str) -> (u16, serde_json::Value) {
        let path = crate::console::routes::ALERTS_PATH;
        let answered = reqwest::Client::new()
            .get(format!("{base}{path}{query}"))
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

    #[tokio::test]
    async fn the_alerts_are_read_through_the_console() {
        let usage = Arc::new(Kept::default());
        usage
            .0
            .lock()
            .unwrap()
            .push(served("a", "1.0.0", "2026-10-13T09:00:00Z"));
        let intel = Arc::new(naming(vec![record(
            "MAL-1",
            true,
            Some("2026-10-13T10:00:00Z"),
        )]));
        let (base, cookie) = console(Some(usage.clone()), Some(intel.clone())).await;
        let (status, body) = get(&base, &cookie, "").await;
        assert_eq!(status, 200);
        assert_eq!(body["alerts"][0]["advisory_id"], "MAL-1");
        assert_eq!(body["alerts"][0]["served"]["name"], "a");
        assert_eq!(
            (&body["next"], &body["scanned"]),
            (&serde_json::json!(1), &serde_json::json!(1))
        );
        let (status, body) = get(&base, &cookie, "?after=1").await;
        assert_eq!((status, &body["alerts"]), (200, &serde_json::json!([])));
        let (status, body) = get(&base, &cookie, "?after=x").await;
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("after is not a row id: `x`"))
        );

        let (base, cookie) = console(Some(usage.clone()), None).await;
        assert_eq!(get(&base, &cookie, "").await.0, 503, "no intel store");
        let (base, cookie) = console(None, Some(intel)).await;
        assert_eq!(get(&base, &cookie, "").await.0, 503, "no usage tables");
        let (base, cookie) = console(Some(usage), Some(Arc::new(FixedIntel(Err(()))))).await;
        assert_eq!(
            get(&base, &cookie, "").await.0,
            503,
            "an intel store that does not answer"
        );
    }
}
