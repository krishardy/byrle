//! The analysis commands a remote `byrle` asks, answered from the proxy beside the console:
//! docs/engineering_decisions/0118-remote-analysis-commands.md.

use std::sync::Arc;

use axum::http::request::Parts;
use axum::response::Response;
use serde::Deserialize;
use utoipa::IntoParams;

use super::Site;
use super::api::{Problem, Refused, answered};
use super::usage::query;
use crate::remote::Printed;

/// `GET explain`'s query string.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExplainQuery {
    /// The package version, such as `pkg:npm/lodash@4.17.21`. Without it, the policy.
    purl: Option<String>,
}

/// `GET explain`: what `byrle explain` prints on the deployment, for `purl` or the policy.
#[utoipa::path(
    get,
    path = super::routes::EXPLAIN_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    params(ExplainQuery),
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "A query string that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy to answer from", body = Problem),
    ),
)]
pub async fn explain(site: Arc<Site>, parts: Parts) -> Response {
    answered(explained(&site, &parts).await)
}

/// What `byrle explain` prints for the query string of `parts`, on the proxy beside `site`.
async fn explained(site: &Site, parts: &Parts) -> Result<Printed, Refused> {
    let asked = query::<ExplainQuery>(parts).map_err(Refused::bad)?;
    let proxy = super::config::beside(site)?;
    let target = crate::cli::Explain {
        policy: asked.purl.is_none(),
        purl: asked.purl,
    };
    let policy = proxy.policy();
    let store = proxy.intel_store();
    let answered = crate::explain::run_on(
        &target,
        policy.as_deref(),
        store.as_deref(),
        proxy.clients(),
    )
    .await;
    Ok(Printed::of(
        "explain",
        &answered.notes,
        answered.answer,
        answered.code,
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::account::{Accounts, Name, Role, TokenDigest};
    use crate::env::{REMOTE_URL, TOKEN};
    use crate::proxy::Proxy;
    use crate::remote::Remote;

    /// A console beside `proxy`, served, holding alice the admin, carol the reader and bob
    /// with no role, each with a token `byrle_<name>`. Its URL.
    pub(crate) async fn console_beside(proxy: Proxy) -> String {
        let store = crate::console::login::tests::store().await;
        let carol = Name::parse("carol").unwrap();
        store.create_account(&carol, &[Role::Reader]).await.unwrap();
        let laptop = Name::parse("laptop").unwrap();
        for name in ["alice", "bob", "carol"] {
            store
                .create_token(
                    &Name::parse(name).unwrap(),
                    &laptop,
                    &TokenDigest::of(&format!("byrle_{name}")),
                )
                .await
                .unwrap();
        }
        let (_, base) =
            crate::console::tests::served_asking(store, (proxy, "http://127.0.0.1:9".into())).await;
        format!("{base}/admin/")
    }

    /// The deployment at `url`, asked with `name`'s token.
    pub(crate) fn asking(url: &str, name: &str) -> Remote {
        let token = format!("byrle_{name}");
        Remote::from_env(&crate::env::testing::with(&[
            (REMOTE_URL, url),
            (TOKEN, &token),
        ]))
        .unwrap()
        .expect("a deployment is named")
    }

    fn policed() -> Proxy {
        let policy = crate::policy::Policy::parse("version: 1\ncooldown_days: 7\n").unwrap();
        Proxy::new(reqwest::Client::new()).with_policy(Some(Arc::new(policy)))
    }

    /// A reader and an admin are answered what `explain` prints on the deployment; an
    /// account with no role is refused.
    #[tokio::test]
    async fn explain_is_answered_as_the_deployment_prints_it() {
        let url = console_beside(policed()).await;
        for name in ["alice", "carol"] {
            let printed = asking(&url, name)
                .get("explain", crate::console::routes::EXPLAIN_PATH, &[])
                .await;
            assert_eq!(printed.code, 0, "{name}: {printed:?}");
            assert!(printed.stdout.contains("cooldown_days    7"), "{printed:?}");
        }
        let bad = asking(&url, "carol")
            .get(
                "explain",
                crate::console::routes::EXPLAIN_PATH,
                &[("purl", "not a purl".to_owned())],
            )
            .await;
        assert_eq!(bad.code, 2);
        assert!(
            bad.stderr
                .starts_with("byrle explain: `not a purl` is not a package reference"),
            "{bad:?}"
        );
        let refused = asking(&url, "bob")
            .get("explain", crate::console::routes::EXPLAIN_PATH, &[])
            .await;
        assert_eq!(refused.code, 2);
        assert!(
            refused.stderr.contains("403 Forbidden") && refused.stderr.contains("packages.read"),
            "{refused:?}"
        );
    }

    /// A deployment with no policy says so; a console beside no proxy is 503, and a query
    /// that does not parse 400.
    #[tokio::test]
    async fn a_deployment_with_no_policy_or_no_proxy_says_so() {
        let parts = |uri: &str| {
            axum::http::Request::builder()
                .uri(uri)
                .body(())
                .unwrap()
                .into_parts()
                .0
        };
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: None,
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let store = crate::console::login::tests::store().await;
        let alone = crate::console::tests::unread(console, store);
        let Err(Refused(status, _)) = explained(&alone, &parts("/x")).await else {
            panic!("no proxy to answer from");
        };
        assert_eq!(status, 503);
        let Err(Refused(status, why)) = explained(&alone, &parts("/x?purl=a&purl=b")).await else {
            panic!("a purl given twice");
        };
        assert_eq!(status, 400, "{why}");
        let url = console_beside(Proxy::new(reqwest::Client::new())).await;
        let printed = asking(&url, "alice")
            .get("explain", crate::console::routes::EXPLAIN_PATH, &[])
            .await;
        assert_eq!(
            (printed.code, printed.stderr.as_str()),
            (2, "byrle explain: the deployment has no policy in force\n")
        );
    }
}
