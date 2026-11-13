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
use crate::policy::diff;
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
        &proxy.date_reader(),
    )
    .await;
    Ok(Printed::of(
        "explain",
        &answered.notes,
        answered.answer,
        answered.code,
    ))
}

/// `GET artifact`'s query string.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ArtifactQuery {
    /// A digest, such as `sha512-...`, or one version's purl, such as `pkg:npm/ms@2.1.3`.
    artifact: String,
}

/// `GET artifact`: what `byrle artifact show` prints on the deployment.
#[utoipa::path(
    get,
    path = super::routes::ARTIFACT_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    params(ArtifactQuery),
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "An artifact that is neither a digest nor a purl", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy, or one keeping no analyses", body = Problem),
    ),
)]
pub async fn artifact(site: Arc<Site>, parts: Parts) -> Response {
    answered(shown(&site, &parts).await)
}

/// What `byrle artifact show` prints for the query string of `parts`.
async fn shown(site: &Site, parts: &Parts) -> Result<Printed, Refused> {
    let asked = query::<ArtifactQuery>(parts).map_err(Refused::bad)?;
    let artifact =
        crate::analysis::decision::Artifact::parse(&asked.artifact).map_err(Refused::bad)?;
    let store = analyses(site)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code =
        crate::analysis::decision::command::show(&*store, &artifact, &mut out, &mut err).await;
    Ok(Printed::written(&out, &err, code))
}

/// `GET artifacts`'s query string.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ArtifactsQuery {
    /// The first day, `YYYY-MM-DD`, UTC.
    since: Option<String>,
    /// The last day, `YYYY-MM-DD`, UTC, included.
    until: Option<String>,
}

/// `GET artifacts`: what `byrle artifact export` prints on the deployment, its JSON Lines.
#[utoipa::path(
    get,
    path = super::routes::ARTIFACTS_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    params(ArtifactsQuery),
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "A day that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy, or one keeping no analyses", body = Problem),
    ),
)]
pub async fn artifacts(site: Arc<Site>, parts: Parts) -> Response {
    answered(exported(&site, &parts).await)
}

/// What `byrle artifact export` prints for the query string of `parts`.
async fn exported(site: &Site, parts: &Parts) -> Result<Printed, Refused> {
    let asked = query::<ArtifactsQuery>(parts).map_err(Refused::bad)?;
    let day = |given: Option<String>| {
        given
            .map(|day| crate::analysis::decision::day(&day))
            .transpose()
            .map_err(Refused::bad)
    };
    let (since, until) = (day(asked.since)?, day(asked.until)?);
    let store = analyses(site)?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code =
        crate::analysis::decision::command::export(&*store, since, until, &mut out, &mut err).await;
    Ok(Printed::written(&out, &err, code))
}

/// `GET intel/history`'s query string.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// Most entries to print, 20 unless given.
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    crate::cli::DEFAULT_HISTORY_LIMIT
}

/// `GET intel/history`: what `byrle intel history` prints on the deployment.
#[utoipa::path(
    get,
    path = super::routes::INTEL_HISTORY_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    params(HistoryQuery),
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "A limit that is not a whole number from 1", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy, or one with no intel store", body = Problem),
    ),
)]
pub async fn history(site: Arc<Site>, parts: Parts) -> Response {
    answered(histories(&site, &parts).await)
}

/// What `byrle intel history` prints for the query string of `parts`.
async fn histories(site: &Site, parts: &Parts) -> Result<Printed, Refused> {
    let asked = query::<HistoryQuery>(parts).map_err(Refused::bad)?;
    if asked.limit == 0 {
        return Err(Refused::bad("limit is at least 1".to_owned()));
    }
    let store = super::config::beside(site)?
        .intel_store()
        .ok_or_else(|| Refused::unavailable("the deployment has no intel store"))?;
    Ok(match store.history(asked.limit).await {
        Ok(entries) => Printed::of(
            "intel history",
            &[],
            crate::intel::history::render(&entries),
            0,
        ),
        Err(e) => Printed::of("intel history", &[e.to_string()], String::new(), 1),
    })
}

/// `GET ecosystems`: what `byrle status` prints on the deployment.
#[utoipa::path(
    get,
    path = super::routes::ECOSYSTEMS_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy to answer from", body = Problem),
    ),
)]
pub async fn ecosystems(site: Arc<Site>) -> Response {
    answered(statused(&site).await)
}

/// What `byrle status` prints on the proxy beside `site`.
async fn statused(site: &Site) -> Result<Printed, Refused> {
    let proxy = super::config::beside(site)?;
    let mut notes = Vec::new();
    let snapshot = match proxy.intel_store() {
        Some(store) => store.snapshot().await.unwrap_or_else(|e| {
            notes.push(format!("the intel store could not be read: {e}"));
            None
        }),
        None => None,
    };
    let report = crate::status::report(proxy.upstreams(), snapshot.as_ref());
    Ok(Printed::of("status", &notes, report, 0))
}

/// `POST policy/check`: what `byrle policy check` prints on the deployment of the policy sent.
#[utoipa::path(
    post,
    path = super::routes::POLICY_CHECK_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    request_body = crate::remote::CheckAsked,
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "A body or date that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 503, description = "No proxy to answer from", body = Problem),
    ),
)]
pub async fn policy_check(site: Arc<Site>, body: Vec<u8>) -> Response {
    answered(policy_checked(&site, &body).await)
}

/// What `byrle policy check` prints of the policy `body` sends.
async fn policy_checked(site: &Site, body: &[u8]) -> Result<Printed, Refused> {
    let asked: crate::remote::CheckAsked = serde_json::from_slice(body)
        .map_err(|e| Refused::bad(format!("the body is not a policy check: {e}")))?;
    let as_of = match asked.as_of {
        Some(day) => day
            .parse::<jiff::civil::Date>()
            .map_err(|_| Refused::bad(format!("as_of is not a YYYY-MM-DD date: `{day}`")))?,
        None => crate::policy::today(),
    };
    let proxy = super::config::beside(site)?;
    let loaded = crate::policy::check::checked(
        crate::policy::Policy::parse(&asked.policy),
        as_of,
        site.expiry_ceiling_days(),
    );
    let fetch = asked.fetch.then(|| proxy.clients());
    let answer = crate::policy::check::answer(loaded, SENT, as_of, (asked.strict, fetch)).await;
    Ok(Printed::of(
        "policy check",
        &answer.notes,
        answer.report,
        answer.code,
    ))
}

/// How a remote command's notes name the policy it sent.
const SENT: &str = "the policy sent";

/// `POST policy/diff`: what `byrle policy diff` prints on the deployment of the policy sent.
#[utoipa::path(
    post,
    path = super::routes::POLICY_DIFF_PATH,
    tag = "commands",
    security(("session" = []), ("token" = [])),
    extensions(("x-byrle-permission" = json!("packages.read"))),
    request_body = crate::remote::DiffAsked,
    responses(
        (status = 200, description = "What the command printed, and its exit code", body = Printed),
        (status = 400, description = "A body, date or repository that does not parse", body = Problem),
        (status = 401, description = "No session or token", body = Problem),
        (status = 403, description = "The caller's roles do not grant packages.read", body = Problem),
        (status = 429, description = "Another policy diff is running", body = Problem),
        (status = 503, description = "No proxy to answer from", body = Problem),
    ),
)]
pub async fn policy_diff(site: Arc<Site>, body: Vec<u8>) -> Response {
    answered(policy_diffed(&site, &body).await)
}

/// What `byrle policy diff` prints of the deployment's policy and the one `body` sends.
async fn policy_diffed(site: &Site, body: &[u8]) -> Result<Printed, Refused> {
    let asked: crate::remote::DiffAsked = serde_json::from_slice(body)
        .map_err(|e| Refused::bad(format!("the body is not a policy diff: {e}")))?;
    let when = |day: Option<String>| {
        day.map(|day| crate::cli::when(&day))
            .transpose()
            .map_err(Refused::bad)
    };
    let dates = [when(asked.from_date)?, when(asked.to_date)?];
    if asked.versions.len() > site.max_diff_versions() {
        return Err(Refused::bad(format!(
            "{} package versions were sent; {} allows {}",
            asked.versions.len(),
            crate::env::MAX_DIFF_VERSIONS,
            site.max_diff_versions()
        )));
    }
    let sent = asked
        .versions
        .into_iter()
        .map(crate::remote::Sent::listed)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Refused::bad)?;
    let proxy = super::config::beside(site)?;
    let Ok(_running) = site.diffing.try_lock() else {
        return Err(Refused::busy(
            "another policy diff is running; send this one when it ends",
        ));
    };
    let stopped = |note: String| Printed::of("policy diff", &[note], String::new(), diff::ERROR);
    let Some(in_force) = proxy.policy() else {
        return Ok(stopped("the deployment has no policy in force".to_owned()));
    };
    let candidate = match crate::policy::Policy::parse(&asked.policy) {
        Ok(candidate) => candidate,
        Err(e) => return Ok(stopped(format!("{SENT}: {e}"))),
    };
    let run = diff::run_on(
        [(*in_force).clone(), candidate],
        dates,
        (site.audit_log(), sent),
        proxy.intel_store(),
        proxy.date_reader(),
    )
    .await;
    let notes: Vec<String> = run.notes.into_iter().chain(run.summary).collect();
    Ok(Printed::of("policy diff", &notes, run.report, run.code))
}

/// The analysis store of the proxy beside `site`. 503 when it keeps none.
fn analyses(site: &Site) -> Result<Arc<dyn crate::analysis::store::Analyses>, Refused> {
    super::config::beside(site)?
        .analyses()
        .ok_or_else(|| Refused::unavailable("the deployment keeps no analyses"))
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
        let at = (proxy, "http://127.0.0.1:9".to_owned());
        let (_, base) = crate::console::tests::served_asking(accounts().await, at).await;
        format!("{base}/admin/")
    }

    /// [`console_beside`], reading the audit log at `audit_log`.
    async fn console_logging(proxy: Proxy, audit_log: std::path::PathBuf) -> String {
        let console = crate::console::Console {
            url: "https://h/admin/".into(),
            mount: crate::mount::Mount::from_url("https://h/admin/").unwrap(),
            listen: Some("127.0.0.1:9090".into()),
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let site = Arc::new(
            crate::console::tests::unread(console, accounts().await)
                .with_proxy(proxy, Vec::new(), "http://127.0.0.1:9".into())
                .with_logs(Some(audit_log), None),
        );
        let (_, router) =
            crate::console::listeners(axum::Router::new(), "127.0.0.1:8080", Some(&site))
                .pop()
                .unwrap();
        format!("{}/admin/", crate::proxy::testing::serve(router).await)
    }

    /// alice the admin, carol the reader and bob with no role, each with `byrle_<name>`.
    async fn accounts() -> Arc<crate::account::InMemory> {
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
        store
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

    /// A proxy with a policy, asking an npm registry that does not answer.
    fn policed() -> Proxy {
        let policy = crate::policy::Policy::parse("version: 1\ncooldown_days: 7\n").unwrap();
        Proxy::new(crate::service::Connection::default())
            .with_upstream(
                crate::identity::Ecosystem::Npm,
                crate::util::test_support::NO_UPSTREAM,
            )
            .with_policy(Some(Arc::new(policy)))
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

    /// `artifact show` and `export` are answered from the deployment's analysis store; one
    /// keeping none is 503, and an artifact or day that does not parse 400.
    #[tokio::test]
    async fn artifacts_are_answered_from_the_deployments_analyses() {
        use crate::analysis::store::Analyses;
        let store = Arc::new(crate::analysis::store::InProcess::new(8));
        let rows = [
            crate::analysis::decision::tests::decided("a", "sha512-1"),
            crate::analysis::decision::tests::decided("b", "sha512-2"),
        ];
        store.put_decisions(&rows).await.unwrap();
        let analyser = crate::analysis::run::tests::analyser("remote-artifacts", 1 << 20, store);
        let url = console_beside(policed().with_analyser(Some(Arc::new(analyser)))).await;
        let carol = asking(&url, "carol");
        let shown = carol
            .get(
                "artifact",
                crate::console::routes::ARTIFACT_PATH,
                &[("artifact", "pkg:npm/a@1.0.0".to_owned())],
            )
            .await;
        assert_eq!(shown.code, 0, "{shown:?}");
        assert_eq!(shown.stdout.lines().count(), 1, "{shown:?}");
        let exported = carol
            .get(
                "artifact",
                crate::console::routes::ARTIFACTS_PATH,
                &[("since", "2000-01-01".to_owned())],
            )
            .await;
        assert_eq!(
            (exported.code, exported.stdout.lines().count()),
            (0, 2),
            "{exported:?}"
        );
        for (path, query) in [
            (crate::console::routes::ARTIFACT_PATH, ("artifact", "ms")),
            (
                crate::console::routes::ARTIFACTS_PATH,
                ("until", "yesterday"),
            ),
            (
                crate::console::routes::ARTIFACTS_PATH,
                ("since", "yesterday"),
            ),
        ] {
            let refused = carol
                .get("artifact", path, &[(query.0, query.1.to_owned())])
                .await;
            assert!(refused.stderr.contains("400 Bad Request"), "{refused:?}");
        }

        let none = console_beside(policed()).await;
        for path in [
            crate::console::routes::ARTIFACT_PATH,
            crate::console::routes::ARTIFACTS_PATH,
        ] {
            let refused = asking(&none, "carol")
                .get(
                    "artifact",
                    path,
                    &[("artifact", "pkg:npm/a@1.0.0".to_owned())],
                )
                .await;
            assert!(
                refused.stderr.contains("the deployment keeps no analyses"),
                "{refused:?}"
            );
        }
    }

    /// `intel history` and `status` are answered from the deployment's intel store and
    /// upstreams; a store that cannot be read says so.
    #[tokio::test]
    async fn intel_history_and_status_are_answered_from_the_deployment() {
        use crate::console::routes::{ECOSYSTEMS_PATH, INTEL_HISTORY_PATH};
        use crate::intel::store::testing::{Unsnapshotted, knowing_nothing};
        let knowing = policed().with_intel(Some(Arc::new(knowing_nothing())));
        let url = console_beside(knowing).await;
        let carol = asking(&url, "carol");
        let history = carol.get("intel history", INTEL_HISTORY_PATH, &[]).await;
        assert_eq!(history.code, 0, "{history:?}");
        assert_eq!(
            history.stdout,
            crate::intel::history::render(&[]),
            "a store that records no ingestion"
        );
        let status = carol.get("status", ECOSYSTEMS_PATH, &[]).await;
        assert_eq!(status.code, 0, "{status:?}");
        assert!(status.stdout.starts_with("byrle status\n"), "{status:?}");
        let zero = carol
            .get(
                "intel history",
                INTEL_HISTORY_PATH,
                &[("limit", "0".to_owned())],
            )
            .await;
        assert!(zero.stderr.contains("limit is at least 1"), "{zero:?}");
        let word = carol
            .get(
                "intel history",
                INTEL_HISTORY_PATH,
                &[("limit", "some".to_owned())],
            )
            .await;
        assert!(word.stderr.contains("400 Bad Request"), "{word:?}");

        let broken = console_beside(policed().with_intel(Some(Arc::new(Unsnapshotted)))).await;
        let carol = asking(&broken, "carol");
        let history = carol.get("intel history", INTEL_HISTORY_PATH, &[]).await;
        assert_eq!(history.code, 1, "{history:?}");
        assert!(
            history.stderr.starts_with("byrle intel history: "),
            "{history:?}"
        );
        let status = carol.get("status", ECOSYSTEMS_PATH, &[]).await;
        assert!(
            status
                .stderr
                .starts_with("byrle status: the intel store could not be read"),
            "{status:?}"
        );
        let storeless = console_beside(policed()).await;
        let refused = asking(&storeless, "carol")
            .get("intel history", INTEL_HISTORY_PATH, &[])
            .await;
        assert!(
            refused.stderr.contains("the deployment has no intel store"),
            "{refused:?}"
        );
        let plain = asking(&storeless, "carol")
            .get("status", ECOSYSTEMS_PATH, &[])
            .await;
        assert_eq!((plain.code, plain.stderr.as_str()), (0, ""));
    }

    /// `policy check` judges the policy sent, `--strict` failing on an entry doing nothing;
    /// a policy that does not load exits as it does locally.
    #[tokio::test]
    async fn policy_check_is_answered_for_the_policy_sent() {
        use crate::console::routes::POLICY_CHECK_PATH;
        use crate::remote::CheckAsked;
        let url = console_beside(policed()).await;
        let carol = asking(&url, "carol");
        let idle = "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: ms }\n    \
                    set: { cooldown_days: 7 }\n    reason: r\n";
        let asked = |policy: &str, strict: bool| CheckAsked {
            policy: policy.to_owned(),
            as_of: Some("2026-09-13".to_owned()),
            strict,
            fetch: true,
        };
        let checked = carol
            .post("policy check", POLICY_CHECK_PATH, &asked(idle, false))
            .await;
        assert_eq!(checked.code, 0, "{checked:?}");
        assert!(checked.stdout.contains("changes nothing"), "{checked:?}");
        let strict = carol
            .post("policy check", POLICY_CHECK_PATH, &asked(idle, true))
            .await;
        assert_eq!(strict.code, 1, "{strict:?}");
        assert!(
            strict.stderr.contains("--strict: changes nothing: 1"),
            "{strict:?}"
        );
        let refused = carol
            .post(
                "policy check",
                POLICY_CHECK_PATH,
                &asked("version: 2\n", false),
            )
            .await;
        assert_eq!(refused.code, 1, "{refused:?}");
        assert!(
            refused
                .stderr
                .starts_with("byrle policy check: the policy sent: "),
            "{refused:?}"
        );
        let undated = CheckAsked {
            as_of: Some("today".to_owned()),
            ..asked(idle, false)
        };
        let undated = carol
            .post("policy check", POLICY_CHECK_PATH, &undated)
            .await;
        assert!(
            undated.stderr.contains("as_of is not a YYYY-MM-DD date"),
            "{undated:?}"
        );
        let today = CheckAsked {
            as_of: None,
            fetch: false,
            ..asked(idle, false)
        };
        let today = carol.post("policy check", POLICY_CHECK_PATH, &today).await;
        assert_eq!(today.code, 0, "{today:?}");
        let garbled = carol
            .post("policy check", POLICY_CHECK_PATH, &"not a check")
            .await;
        assert!(
            garbled.stderr.contains("the body is not a policy check"),
            "{garbled:?}"
        );
        let expiring = |day: &str| {
            format!(
                "version: 1\ncooldown_days: 7\npackages:\n  - match: {{ ecosystem: npm, name: ms }}\n    \
                 set: {{ cooldown_days: 0 }}\n    reason: r\n    expires: \"{day}\"\n"
            )
        };
        let within = carol
            .post(
                "policy check",
                POLICY_CHECK_PATH,
                &asked(&expiring("2026-10-13"), false),
            )
            .await;
        assert_eq!(
            within.code, 0,
            "30 days, under the 90-day ceiling: {within:?}"
        );
        let past = carol
            .post(
                "policy check",
                POLICY_CHECK_PATH,
                &asked(&expiring("2027-06-01"), false),
            )
            .await;
        assert!(past.stderr.contains("90-day ceiling"), "{past:?}");
        let large = format!("version: 1\n# {}\n", "x".repeat(2 << 20));
        let large = carol
            .post("policy check", POLICY_CHECK_PATH, &asked(&large, false))
            .await;
        assert_eq!(large.code, 0, "a 2 MiB policy is read whole: {large:?}");
    }

    /// `policy diff` compares the policy in force with the one sent, over the versions sent;
    /// no policy in force, a candidate that does not load, or an unread log stops it.
    #[tokio::test]
    async fn policy_diff_compares_the_policy_in_force_with_the_one_sent() {
        use crate::console::routes::POLICY_DIFF_PATH;
        use crate::remote::{DiffAsked, Sent};
        let missing = console_beside(policed()).await;
        let unlogged = asking(&missing, "carol")
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &DiffAsked {
                    policy: "version: 1\n".to_owned(),
                    ..DiffAsked::default()
                },
            )
            .await;
        assert!(unlogged.stderr.contains("audit.log"), "{unlogged:?}");
        let dir = crate::util::test_support::tempdir("remote-diff");
        let log = dir.join("audit.jsonl");
        std::fs::write(&log, "").unwrap();
        let url = console_logging(policed(), log).await;
        let carol = asking(&url, "carol");
        let lodash = Sent {
            repository: None,
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
        };
        let asked = |policy: &str, versions: Vec<Sent>| DiffAsked {
            policy: policy.to_owned(),
            from_date: None,
            to_date: Some("+1d".to_owned()),
            versions,
        };
        let diffed = carol
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &asked("version: 1\ncooldown_days: 0\n", vec![lodash.clone()]),
            )
            .await;
        assert!(diffed.stderr.contains("<FROM> as of"), "{diffed:?}");
        assert!(
            diffed.stderr.contains("pkg:npm/lodash@4.17.21: "),
            "the registry: {diffed:?}"
        );
        let bare = carol
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &asked("version: 1\n", vec![]),
            )
            .await;
        assert!(bare.stdout.starts_with("0 packages evaluated"), "{bare:?}");
        let broken = carol
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &asked("version: 2\n", vec![lodash.clone()]),
            )
            .await;
        assert!(
            broken
                .stderr
                .starts_with("byrle policy diff: the policy sent: "),
            "{broken:?}"
        );
        let elsewhere = Sent {
            repository: Some("nowhere".to_owned()),
            ..lodash.clone()
        };
        let unknown = carol
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &asked("version: 1\n", vec![elsewhere]),
            )
            .await;
        assert!(
            unknown.stderr.contains("`nowhere` is not a repository"),
            "{unknown:?}"
        );
        for (from_date, to_date) in [(Some("soon"), None), (None, Some("later"))] {
            let undated = DiffAsked {
                from_date: from_date.map(str::to_owned),
                to_date: to_date.map(str::to_owned),
                ..asked("version: 1\n", vec![])
            };
            let undated = carol.post("policy diff", POLICY_DIFF_PATH, &undated).await;
            assert!(undated.stderr.contains("400 Bad Request"), "{undated:?}");
        }
        let garbled = carol
            .post("policy diff", POLICY_DIFF_PATH, &"not a diff")
            .await;
        assert!(
            garbled.stderr.contains("the body is not a policy diff"),
            "{garbled:?}"
        );

        let unpoliced = console_beside(Proxy::new(crate::service::Connection::default())).await;
        let none = asking(&unpoliced, "carol")
            .post(
                "policy diff",
                POLICY_DIFF_PATH,
                &asked("version: 1\n", vec![lodash]),
            )
            .await;
        assert_eq!(
            (none.code, none.stderr.as_str()),
            (
                diff::ERROR,
                "byrle policy diff: the deployment has no policy in force\n"
            )
        );
    }

    /// More package versions than [`crate::env::MAX_DIFF_VERSIONS`] allows are 400, and a
    /// diff sent while another runs is 429, without either being compared.
    #[tokio::test]
    async fn a_diff_past_its_cap_or_beside_a_running_one_is_refused() {
        let console = crate::console::Console {
            url: "https://h/".into(),
            mount: crate::mount::Mount::ROOT,
            listen: None,
            rp_key: None,
            proxy_mount: crate::mount::Mount::ROOT,
        };
        let site =
            crate::console::tests::unread(console, crate::console::login::tests::store().await)
                .with_proxy(policed(), Vec::new(), "http://127.0.0.1:9".into())
                .with_max_diff_versions(1);
        let lodash = crate::remote::Sent {
            repository: None,
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
        };
        let body = |versions: usize| {
            serde_json::to_vec(&crate::remote::DiffAsked {
                policy: "version: 1\n".to_owned(),
                versions: vec![lodash.clone(); versions],
                ..crate::remote::DiffAsked::default()
            })
            .unwrap()
        };
        let Err(Refused(status, why)) = policy_diffed(&site, &body(2)).await else {
            panic!("2 versions past a cap of 1");
        };
        assert_eq!(status, 400);
        assert_eq!(
            why,
            format!(
                "2 package versions were sent; {} allows 1",
                crate::env::MAX_DIFF_VERSIONS
            )
        );
        let running = site.diffing.lock().await;
        let Err(Refused(status, _)) = policy_diffed(&site, &body(0)).await else {
            panic!("another diff is running");
        };
        assert_eq!(status, 429);
        drop(running);
        assert!(policy_diffed(&site, &body(0)).await.is_ok());

        let hanging = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", hanging.local_addr().unwrap());
        let console = site.console.clone();
        let waiting =
            crate::console::tests::unread(console, crate::console::login::tests::store().await)
                .with_proxy(
                    policed().with_upstream(crate::identity::Ecosystem::Npm, &upstream),
                    Vec::new(),
                    "http://127.0.0.1:9".into(),
                );
        let one = body(1);
        let mut first = Box::pin(policy_diffed(&waiting, &one));
        let unanswered = std::time::Duration::from_millis(200);
        assert!(tokio::time::timeout(unanswered, &mut first).await.is_err());
        assert!(
            waiting.diffing.try_lock().is_err(),
            "a diff waiting on its registry holds the lock"
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
        for refused in [
            shown(&alone, &parts("/x?artifact=pkg:npm/a@1.0.0")).await,
            exported(&alone, &parts("/x")).await,
        ] {
            assert!(matches!(refused, Err(Refused(status, _)) if status == 503));
        }
        assert!(matches!(statused(&alone).await, Err(Refused(status, _)) if status == 503));
        let alone_history = histories(&alone, &parts("/x")).await;
        assert!(matches!(alone_history, Err(Refused(status, _)) if status == 503));
        let check = br#"{"policy":"version: 1\n","as_of":null,"strict":false,"fetch":false}"#;
        assert!(
            matches!(policy_checked(&alone, check).await, Err(Refused(status, _)) if status == 503)
        );
        let diffing = br#"{"policy":"version: 1\n","from_date":null,"to_date":null,"versions":[]}"#;
        assert!(
            matches!(policy_diffed(&alone, diffing).await, Err(Refused(status, _)) if status == 503)
        );
        let twice = exported(&alone, &parts("/x?since=2026-01-01&since=2026-01-02")).await;
        assert!(matches!(twice, Err(Refused(status, _)) if status == 400));
        let url = console_beside(Proxy::new(crate::service::Connection::default())).await;
        let printed = asking(&url, "alice")
            .get("explain", crate::console::routes::EXPLAIN_PATH, &[])
            .await;
        assert_eq!(
            (printed.code, printed.stderr.as_str()),
            (2, "byrle explain: the deployment has no policy in force\n")
        );
    }
}
