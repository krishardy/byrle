//! Asking crates.io's API who published each version of a crate, for the `trustpub`
//! detector: `/api/v1/crates/{name}/versions`, 100 versions a page, newest first, one
//! request each interval. See docs/engineering_decisions/0110-cargo-provenance.md.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::time::Instant;

use crate::analysis::detector::trustpub::{NAME, OPENED, Published, VERSION, detection};
use crate::analysis::detector::{Detecting, Detection, Detector, Target};
use crate::env::ApiSetting;
use crate::identity::Ecosystem;

/// crates.io's API, asked when cargo's upstream is crates.io's index.
pub const API: &str = "https://crates.io";

/// The most pages of 100 versions asked for one crate.
pub const MAX_PAGES: usize = 20;

/// Who the requests name: crates.io asks for a way to reach the client's authors.
const USER_AGENT: &str = concat!(
    "byrle/",
    env!("CARGO_PKG_VERSION"),
    " (https://github.com/krishardy/byrle)"
);

/// The detector, when `setting` names an API, or leaves it unset and `upstream` is
/// crates.io's index, which crates.io's API describes. Requests are `interval` apart.
pub fn made(
    http: &reqwest::Client,
    _: crate::ecosystem::Repository,
    upstream: &str,
    setting: &ApiSetting,
    interval: Duration,
) -> Option<Arc<dyn Detector>> {
    let api = match setting {
        ApiSetting::Off => None,
        ApiSetting::At(api) => Some(api.as_str()),
        ApiSetting::Unset => (upstream.trim_end_matches('/') == super::INDEX).then_some(API),
    }?;
    Some(Arc::new(TrustPub::new(http.clone(), api, interval)))
}

#[derive(Deserialize)]
struct Page {
    versions: Vec<WireVersion>,
    #[serde(default)]
    meta: Meta,
}

#[derive(Deserialize, Default)]
struct Meta {
    next_page: Option<String>,
}

#[derive(Deserialize)]
struct WireVersion {
    num: String,
    created_at: String,
    #[serde(default)]
    trustpub_data: Option<serde_json::Value>,
    #[serde(default)]
    published_by: Option<User>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

impl From<WireVersion> for Published {
    fn from(wire: WireVersion) -> Self {
        Self {
            version: wire.num,
            created_at: wire.created_at,
            identity: wire.trustpub_data.as_ref().map(identity),
            publisher: wire.published_by.map(|user| user.login),
        }
    }
}

/// The provider and where it builds: GitHub's `repository` or GitLab's `project_path`.
fn identity(data: &serde_json::Value) -> String {
    let field = |key: &str| data.get(key).and_then(serde_json::Value::as_str);
    format!(
        "{} {}",
        field("provider").unwrap_or("an unnamed provider"),
        field("repository")
            .or_else(|| field("project_path"))
            .unwrap_or("an unnamed repository")
    )
}

/// Asks crates.io's API who published each version of a crate.
pub struct TrustPub {
    http: reqwest::Client,
    api: String,
    interval: Duration,
    /// When the next request may start, an interval after the last one started.
    next: tokio::sync::Mutex<Instant>,
}

impl TrustPub {
    /// Asks `api`, at most one request each `interval`.
    pub fn new(http: reqwest::Client, api: &str, interval: Duration) -> Self {
        Self {
            http,
            api: api.trim_end_matches('/').to_owned(),
            interval,
            next: tokio::sync::Mutex::new(Instant::now()),
        }
    }

    /// The page at `url`. Errors with why it was not read.
    async fn page(&self, url: &str) -> Result<Page, String> {
        let mut next = self.next.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = Instant::now() + self.interval;
        drop(next);
        let response = self
            .http
            .get(url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("{url} answered {}", response.status().as_u16()));
        }
        let body = crate::http::capped_body(response, crate::env::DEFAULT_MAX_METADATA_BYTES)
            .await
            .map_err(|e| format!("{url}: body not read: {e}"))?;
        serde_json::from_slice(&body).map_err(|e| format!("{url}: body not understood: {e}"))
    }

    /// Every version of `name` crates.io lists, newest first, back to the first page that
    /// reaches before [`OPENED`], and whether the pages reached it.
    async fn published(&self, name: &str) -> Result<(Vec<Published>, bool), String> {
        let base = format!("{}/api/v1/crates/{name}/versions", self.api);
        let mut query = "?per_page=100&sort=date".to_owned();
        let mut published = Vec::new();
        for _ in 0..MAX_PAGES {
            let page = self.page(&format!("{base}{query}")).await?;
            let reached = page.versions.iter().any(|v| v.created_at.as_str() < OPENED);
            published.extend(page.versions.into_iter().map(Published::from));
            match page.meta.next_page {
                Some(next) if !reached => query = next,
                _ => return Ok((published, reached)),
            }
        }
        Ok((published, false))
    }
}

impl Detector for TrustPub {
    fn name(&self) -> &str {
        NAME
    }

    fn version(&self) -> &str {
        VERSION
    }

    fn reads(&self, at: crate::ecosystem::Repository) -> bool {
        at.ecosystem() == Ecosystem::Cargo
    }

    /// One interval: most crates need one page.
    fn awaited(&self) -> Option<Duration> {
        Some(self.interval)
    }

    fn configured_by(&self) -> Option<crate::env::Var> {
        Some(crate::env::CRATES_API)
    }

    /// A version the pages do not list is older than [`OPENED`] when they reached it, and
    /// nothing fires. Otherwise it is not listed yet, and nothing is stored.
    fn detect<'a>(&'a self, target: &'a Target) -> Detecting<'a> {
        Box::pin(async move {
            let (published, reached) = self.published(&target.name).await?;
            match detection(&published, &target.version) {
                Some(detection) => Ok(detection),
                None if reached => Ok(Detection::default()),
                None => Err(format!(
                    "crates.io lists no version {} of {} since {OPENED}",
                    target.version, target.name
                )),
            }
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::detector::trustpub::RULES;
    use crate::util::test_support::{Answer, Requests, recorded, scripted};

    /// GitHub names a repository, GitLab a project path. A provider this build does not know
    /// is still read.
    #[test]
    fn the_identity_is_the_provider_and_where_it_builds() {
        for (data, read) in [
            (
                r#"{"provider":"github","repository":"o/r","run_id":"1","sha":"a"}"#,
                "github o/r",
            ),
            (
                r#"{"provider":"gitlab","project_path":"g/p","job_id":"1","sha":"a"}"#,
                "gitlab g/p",
            ),
            (
                r#"{"provider":"forgejo","place":"x"}"#,
                "forgejo an unnamed repository",
            ),
            ("{}", "an unnamed provider an unnamed repository"),
        ] {
            assert_eq!(identity(&serde_json::from_str(data).unwrap()), read);
        }
    }

    /// Unset, the API is asked only in front of crates.io's index. `off` asks nothing, and
    /// a URL is asked whatever the upstream.
    #[test]
    fn crates_io_s_api_is_asked_only_for_crates_io_s_index() {
        let http = reqwest::Client::new();
        let made = |upstream: &str, setting: &ApiSetting| {
            let at = crate::ecosystem::Repository::of(Ecosystem::Cargo);
            made(&http, at, upstream, setting, Duration::ZERO).is_some()
        };
        let mirror = "https://mirror.example/index/";
        assert!(made("https://index.crates.io/", &ApiSetting::Unset));
        assert!(made(super::super::INDEX, &ApiSetting::Unset));
        assert!(!made(mirror, &ApiSetting::Unset));
        assert!(!made(super::super::INDEX, &ApiSetting::Off));
        assert!(made(
            mirror,
            &ApiSetting::At("https://api.mirror.example".to_owned())
        ));
    }

    fn page(versions: &[(&str, &str, Option<&str>)], next: Option<&str>) -> Answer {
        let versions: Vec<serde_json::Value> = versions
            .iter()
            .map(|(num, created_at, repository)| {
                serde_json::json!({
                    "num": num,
                    "created_at": created_at,
                    "trustpub_data": repository.map(|r| serde_json::json!({
                        "provider": "github", "repository": r, "run_id": "1", "sha": "a"
                    })),
                    "published_by": if repository.is_some() {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!({"login": "owner", "id": 1})
                    },
                })
            })
            .collect();
        Answer::body(
            serde_json::json!({"versions": versions, "meta": {"total": 9, "next_page": next}})
                .to_string(),
        )
    }

    fn target(ecosystem: Ecosystem, version: &str) -> Target {
        Target {
            repository: crate::ecosystem::Repository::of(ecosystem),
            name: "rand_core".to_owned(),
            version: version.to_owned(),
        }
    }

    fn asked(addr: std::net::SocketAddr, interval: Duration) -> TrustPub {
        TrustPub::new(reqwest::Client::new(), &format!("http://{addr}/"), interval)
    }

    fn paths(requests: &Requests) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                let text = String::from_utf8_lossy(r);
                text.split(' ').nth(1).unwrap_or_default().to_owned()
            })
            .collect()
    }

    /// Pages are followed until one reaches before [`OPENED`]; each request names byrle.
    #[tokio::test]
    async fn the_api_is_paged_back_to_when_trusted_publishing_opened() {
        let (addr, requests) = recorded(vec![
            page(
                &[("0.9.4", "2026-01-12T00:00:00Z", None)],
                Some("?per_page=100&sort=date&seek=a"),
            ),
            page(
                &[
                    (
                        "0.10.0-rc-2",
                        "2025-10-01T00:00:00Z",
                        Some("rust-random/core"),
                    ),
                    ("0.9.3", "2025-02-01T00:00:00Z", None),
                ],
                Some("?per_page=100&sort=date&seek=b"),
            ),
        ])
        .await;
        let found = asked(addr, Duration::ZERO)
            .detect(&target(Ecosystem::Cargo, "0.9.4"))
            .await
            .unwrap();
        assert_eq!(found.findings[0].rule, RULES[0]);
        assert_eq!(
            paths(&requests),
            [
                "/api/v1/crates/rand_core/versions?per_page=100&sort=date",
                "/api/v1/crates/rand_core/versions?per_page=100&sort=date&seek=a",
            ]
        );
        let first = String::from_utf8_lossy(&requests.lock().unwrap()[0]).to_lowercase();
        assert!(first.contains(&format!("user-agent: {}", USER_AGENT.to_lowercase())));
    }

    /// A version the pages do not reach is older than trusted publishing when they reached
    /// before it opened, and not listed yet when they did not.
    #[tokio::test]
    async fn an_unlisted_version_is_older_or_not_listed_yet() {
        let reached = scripted(vec![page(&[("0.9.3", "2025-02-01T00:00:00Z", None)], None)]).await;
        assert_eq!(
            asked(reached, Duration::ZERO)
                .detect(&target(Ecosystem::Cargo, "0.1.0"))
                .await,
            Ok(Detection::default())
        );
        let recent = scripted(vec![page(
            &[("0.10.0", "2026-02-01T00:00:00Z", None)],
            None,
        )])
        .await;
        assert_eq!(
            asked(recent, Duration::ZERO)
                .detect(&target(Ecosystem::Cargo, "0.10.1"))
                .await,
            Err("crates.io lists no version 0.10.1 of rand_core since 2025-07".to_owned())
        );
    }

    /// [`MAX_PAGES`] pages that never reach before trusted publishing opened are not enough.
    #[tokio::test]
    async fn paging_stops_at_its_limit() {
        let (addr, requests) = recorded(vec![page(
            &[("1.0.0", "2026-01-01T00:00:00Z", None)],
            Some("?seek=again"),
        )])
        .await;
        assert!(
            asked(addr, Duration::ZERO)
                .detect(&target(Ecosystem::Cargo, "0.1.0"))
                .await
                .is_err()
        );
        assert_eq!(requests.lock().unwrap().len(), MAX_PAGES);
    }

    /// A 429, a 404, a body that is not a page, or no answer at all is an error, and stores
    /// nothing.
    #[tokio::test]
    async fn an_api_that_does_not_answer_a_page_is_an_error() {
        for (answer, said) in [
            (Answer::Status(429), "answered 429"),
            (Answer::Status(404), "answered 404"),
            (Answer::body("{}"), "body not understood"),
            (Answer::cut_short(), "body not read"),
            (Answer::Close, "/api/v1/crates/rand_core/versions"),
        ] {
            let addr = scripted(vec![answer]).await;
            let error = asked(addr, Duration::ZERO)
                .detect(&target(Ecosystem::Cargo, "0.9.4"))
                .await
                .unwrap_err();
            assert!(error.contains(said), "{error}");
        }
    }

    /// Requests are `interval` apart, however many runs ask at once.
    #[tokio::test]
    async fn requests_are_spaced_by_the_interval() {
        let addr = scripted(vec![page(&[("0.9.3", "2025-02-01T00:00:00Z", None)], None)]).await;
        let detector = asked(addr, Duration::from_millis(200));
        let one = target(Ecosystem::Cargo, "0.9.3");
        let started = std::time::Instant::now();
        let (x, y, z) = tokio::join!(
            detector.detect(&one),
            detector.detect(&one),
            detector.detect(&one)
        );
        assert!(x.is_ok() && y.is_ok() && z.is_ok());
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert_eq!(detector.awaited(), Some(Duration::from_millis(200)));
    }

    #[test]
    fn it_reads_cargo_only_and_names_itself() {
        let detector = TrustPub::new(reqwest::Client::new(), API, Duration::ZERO);
        assert_eq!((detector.name(), detector.version()), (NAME, VERSION));
        assert!(detector.reads(crate::ecosystem::Repository::of(
            crate::identity::Ecosystem::Cargo
        )));
        assert!(!detector.reads(crate::ecosystem::Repository::of(
            crate::identity::Ecosystem::Npm
        )));
        assert!(!detector.reads(crate::ecosystem::Repository::of(
            crate::identity::Ecosystem::PyPI
        )));
        assert_eq!(detector.awaited(), Some(Duration::ZERO));
    }
}
