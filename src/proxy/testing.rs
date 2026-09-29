//! Test support shared by the proxy's tests and the commands that talk to a proxy.

use std::sync::Arc;

use axum::Router;
use axum::http::header;
use axum::routing::get;
use tokio::sync::Semaphore;

use super::{Analyser, Proxy};
use crate::audit::AuditLog;
use crate::identity::Ecosystem;
use crate::policy::Policy;
use crate::refusal::Mode;
use crate::spool::Spool;

pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum::serve(listener, router).into_future());
    format!("http://{addr}")
}

pub(crate) fn policy(yaml: &str) -> std::sync::Arc<Policy> {
    std::sync::Arc::new(Policy::parse(yaml).expect("policy should load"))
}

pub(crate) fn sri_of(data: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(data))
    )
}

pub(crate) const RUNS_POSTINSTALL: &[u8] =
    br#"{"name":"widget","version":"1.0.0","scripts":{"postinstall":"node x.js"}}"#;

pub(crate) const RUNS_NOTHING: &[u8] = br#"{"name":"widget","version":"1.0.0"}"#;

/// A registry serving `widget` 1.0.0 behind a proxy with an analyser. `version` is
/// written into the version's object and `dist` into its `dist`, each ending in a
/// comma. The analyser is returned so a test can wait for its jobs.
pub(crate) async fn analysing(
    label: &str,
    version: &str,
    dist: &str,
    tarball: Vec<u8>,
    yaml: Option<&str>,
) -> (String, Arc<Analyser>) {
    let store = Arc::new(crate::analysis::store::InProcess::new(8));
    analysing_with(
        label,
        version,
        dist,
        tarball,
        yaml,
        store,
        Extras::default(),
    )
    .await
}

pub(crate) const ALLOW_ALL: &str = "version: 1\ncooldown_days: 0\n";

/// What [`analysing_with`] adds to the proxy it builds.
#[derive(Default)]
pub(crate) struct Extras {
    /// Holds the tarball route until the test adds permits.
    pub(crate) gate: Option<Arc<Semaphore>>,
    pub(crate) audit: Option<Arc<AuditLog>>,
    pub(crate) mode: Mode,
}

/// [`analysing`], keeping analyses in `store`.
pub(crate) async fn analysing_with(
    label: &str,
    version: &str,
    dist: &str,
    tarball: Vec<u8>,
    yaml: Option<&str>,
    store: Arc<dyn crate::analysis::store::Analyses>,
    extras: Extras,
) -> (String, Arc<Analyser>) {
    let gate = extras.gate;
    let packument = format!(
        r#"{{"name":"widget","dist-tags":{{"latest":"1.0.0"}},"versions":{{
            "1.0.0":{{"version":"1.0.0",{version}"dist":{{{dist}
                "tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}}}}}"#
    );
    let router = Router::new()
        .route(
            "/widget",
            get(move || {
                let packument = packument.clone();
                async move {
                    (
                        [(header::CONTENT_TYPE, "application/vnd.npm.install-v1+json")],
                        packument,
                    )
                }
            }),
        )
        .route(
            "/widget/-/widget-1.0.0.tgz",
            get(move || {
                let tarball = tarball.clone();
                let gate = gate.clone();
                async move {
                    if let Some(gate) = gate {
                        gate.acquire().await.expect("open").forget();
                    }
                    tarball
                }
            }),
        );
    let (spool, _) =
        Spool::open(&crate::util::test_support::tempdir(label), 1 << 20).expect("opens");
    let analyser = Arc::new(Analyser::new(
        reqwest::Client::new(),
        Arc::new(spool),
        store,
        2,
        8,
    ));
    let base = serve(
        Proxy::new(reqwest::Client::new())
            .with_upstream(Ecosystem::Npm, serve(router).await)
            .with_policy(yaml.map(policy))
            .with_analyser(Some(analyser.clone()))
            .with_audit_log(extras.audit)
            .with_mode(extras.mode)
            .router(),
    )
    .await;
    reqwest::get(format!("{base}/widget")).await.unwrap();
    (base, analyser)
}

pub(crate) fn integrity(tarball: &[u8]) -> String {
    format!(r#""integrity":"{}","#, sri_of(tarball))
}

pub(crate) const BLOCK: &str = "version: 1\ncooldown_days: 0\ninstall_scripts: block\n";
