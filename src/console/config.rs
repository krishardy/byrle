//! R7: the proxy's configuration as loaded, with secrets removed. See docs/admin-plan.md
//! §4.6.

use std::sync::Arc;

use axum::response::Response;
use serde::Serialize;
use utoipa::ToSchema;

use super::Site;
use super::api::{Problem, Refused, answered};
use crate::env::Setting;
use crate::proxy::Health;

/// The proxy and the environment it was started with.
#[derive(Clone)]
pub struct Configured {
    pub proxy: crate::proxy::Proxy,
    /// Read once, at startup, with each secret removed.
    pub settings: Vec<Setting>,
    /// Where the console asks the proxy for its health and readiness.
    pub reached_at: String,
}

/// The policy in force.
#[derive(Serialize, ToSchema)]
pub struct PolicyShown {
    /// The SHA-256 of the file, as the audit log records it.
    pub digest: String,
    /// What `byrle explain --policy` prints for it.
    pub report: String,
}

/// The configuration as loaded.
#[derive(Serialize, ToSchema)]
pub struct Config {
    /// What `/-/byrle/health` answers.
    pub proxy: Health,
    /// Absent when no policy is set.
    pub policy: Option<PolicyShown>,
    /// Each runtime variable, set or not.
    pub environment: Vec<Setting>,
}

/// `GET config`: the proxy's health, its policy and its environment, secrets removed. R7.
#[utoipa::path(
    get,
    path = super::routes::CONFIG_PATH,
    tag = "config",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("config.read"))),
    responses(
        (status = 200, description = "The configuration as loaded", body = Config),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant config.read", body = Problem),
        (status = 503, description = "No proxy to describe, or the intel store did not answer", body = Problem),
    ),
)]
pub async fn config(site: Arc<Site>) -> Response {
    answered(loaded(&site).await)
}

/// The proxy's health, its policy and its environment, as loaded.
pub async fn loaded(site: &Site) -> Result<Config, Refused> {
    let configured = site
        .configured
        .as_ref()
        .ok_or_else(|| Refused::unavailable("this console runs beside no proxy"))?;
    let proxy = &configured.proxy;
    let policy = match proxy.policy() {
        Some(policy) => {
            let store = proxy.intel_store();
            let intel = crate::explain::intel_of(store.as_deref())
                .await
                .map_err(|_| Refused::unavailable("the intel store did not answer"))?;
            Some(PolicyShown {
                digest: policy.digest.clone(),
                report: crate::explain::policy_report(&policy, intel),
            })
        }
        None => None,
    };
    Ok(Config {
        proxy: proxy.health(),
        policy,
        environment: configured.settings.clone(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::console::routes::CONFIG_PATH;
    use crate::intel::store::testing::{Unsnapshotted, knowing_nothing};
    use crate::proxy::Proxy;

    /// `GET config` as alice from a console beside `proxy`, or none: status and body.
    async fn read(proxy: Option<Proxy>, settings: Vec<Setting>) -> (u16, serde_json::Value) {
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let store = crate::console::login::tests::store().await;
        let site = crate::console::tests::unread(console, store);
        let site = Arc::new(match proxy {
            Some(proxy) => site.with_proxy(proxy, settings, "http://127.0.0.1:9".into()),
            None => site,
        });
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        let base = crate::proxy::testing::serve(router).await;
        let answered = reqwest::Client::new()
            .get(format!("{base}{CONFIG_PATH}"))
            .basic_auth("alice", Some("unused"))
            .send()
            .await
            .unwrap();
        assert_eq!(answered.status(), 401, "a token alice has not got");
        let login = serde_json::json!({ "account": "alice", "password": crate::console::login::tests::PASSWORD });
        let client = reqwest::Client::new();
        let logged_in = client
            .post(format!("{base}{}", crate::console::LOGIN_PATH))
            .body(login.to_string())
            .send()
            .await
            .unwrap();
        let cookie = logged_in.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let answered = client
            .get(format!("{base}{CONFIG_PATH}"))
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

    fn policed() -> Proxy {
        let policy = crate::policy::Policy::parse("version: 1\ncooldown_days: 7\n").unwrap();
        Proxy::new(reqwest::Client::new()).with_policy(Some(Arc::new(policy)))
    }

    /// The proxy's health, the policy as `explain --policy` prints it, and the settings.
    #[tokio::test]
    async fn the_configuration_is_the_proxys_health_policy_and_environment() {
        let settings =
            crate::env::testing::with(&[(crate::env::GITHUB_TOKEN, "ghp_secret")]).settings();
        let proxy = policed().with_intel(Some(Arc::new(knowing_nothing())));
        let (status, body) = read(Some(proxy.clone()), settings).await;
        assert_eq!(status, 200);
        assert_eq!(body["proxy"]["service"], "byrle");
        assert_eq!(body["policy"]["digest"], proxy.policy().unwrap().digest);
        let report = body["policy"]["report"].as_str().unwrap();
        assert!(
            report.starts_with("settings\n  cooldown_days    7\n"),
            "{report}"
        );
        let token = body["environment"]
            .as_array()
            .unwrap()
            .iter()
            .find(|setting| setting["name"] == crate::env::GITHUB_TOKEN.name)
            .unwrap();
        assert_eq!(token["value"], "set");
        assert!(!body.to_string().contains("ghp_secret"));
    }

    #[tokio::test]
    async fn no_policy_is_null_and_no_proxy_or_intel_is_503() {
        let (status, body) = read(Some(Proxy::new(reqwest::Client::new())), vec![]).await;
        assert_eq!((status, &body["policy"]), (200, &serde_json::Value::Null));
        let (status, body) = read(None, vec![]).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (503, Some("this console runs beside no proxy"))
        );
        let unanswered = policed().with_intel(Some(Arc::new(Unsnapshotted)));
        let (status, body) = read(Some(unanswered), vec![]).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (503, Some("the intel store did not answer"))
        );
    }
}
