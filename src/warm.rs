//! `waharoa warm`: ask a running proxy for every artifact a lockfile locks, so each is
//! analysed before a client asks for it.
//!
//! See `docs/engineering_decisions/warm.md`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures_util::StreamExt;

use crate::ecosystem::{Clients, Upstreams};
use crate::env::{Env, EnvError};
use crate::identity::Ecosystem;
use crate::lockfile::{Locked, LockfileError, Target};

/// How long one artifact may stay deferred for its analysis before warm stops asking.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(900);

/// Metadata documents, and then artifacts, asked for at once.
const IN_FLIGHT: usize = 16;

/// Exit bit: an artifact or a package's metadata could not be fetched.
pub const FAILED: u8 = 1;
/// Exit bit: an artifact was still being analysed at the deadline.
pub const STILL_DEFERRED: u8 = 2;
/// Exit code, on its own: a lockfile does not read, or the proxy's address is not set.
pub const UNREAD: u8 = 4;

/// What the proxy answered for one artifact, or for a locked version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Answered 2xx or 304: analysed, and served.
    Warmed,
    /// Answered this 4xx. The policy's answer, which needs no analysis.
    Refused(u16),
    /// The proxy's metadata does not list the version: the policy removed it, or its
    /// artifacts are on an origin the proxy does not serve.
    NotListed,
    /// Answered 503 for a reason waiting does not clear, named by
    /// `x-waharoa-not-ready`.
    NotReady(String),
    /// Still 503 for its analysis at the deadline.
    StillDeferred,
    Failed(String),
}

/// What `waharoa warm` prints, and its exit code.
#[derive(Debug, PartialEq)]
pub struct Warmed {
    /// For stderr: why nothing was asked.
    pub notes: Vec<String>,
    pub report: String,
    /// The OR of [`FAILED`] and [`STILL_DEFERRED`], or [`UNREAD`] on its own.
    pub code: u8,
}

/// `waharoa warm`: read `lockfiles` and ask the proxy at `proxy`, or the environment's, for
/// each artifact they lock that installs on one of `targets`, or on any platform when
/// `targets` is `None`, waiting up to `deadline` for each analysis.
pub async fn run<L: Fn(&str) -> Option<std::ffi::OsString>>(
    lockfiles: &[PathBuf],
    proxy: Option<&str>,
    targets: Option<&[Target]>,
    deadline: Duration,
    environment: &Env<L>,
) -> Warmed {
    let unread = |note: String| Warmed {
        notes: vec![note],
        report: String::new(),
        code: UNREAD,
    };
    let base = match proxy
        .map(str::to_owned)
        .map_or_else(|| proxy_base(environment), Ok)
    {
        Ok(base) => base.trim_end_matches('/').to_owned(),
        Err(e) => return unread(e.to_string()),
    };
    let plan = match plan(lockfiles, targets) {
        Ok(plan) => plan,
        Err(e) => return unread(e.to_string()),
    };
    let outcomes = warm(&base, &plan, deadline).await;
    Warmed {
        notes: Vec::new(),
        report: render(&outcomes, plan.skipped),
        code: code(&outcomes),
    }
}

/// What warm asks the proxy for.
#[derive(Debug, Default, PartialEq)]
struct Plan {
    /// Labelled artifact paths, from a lockfile that records them.
    direct: Vec<(String, String)>,
    /// Versions whose artifacts are found through the proxy's metadata.
    versions: Vec<Locked>,
    /// Artifacts left out because they install on none of the targets.
    skipped: usize,
}

/// The artifacts `lockfiles` lock that install on `targets`, each path once, and the
/// versions of lockfiles with no artifact reader.
fn plan(lockfiles: &[PathBuf], targets: Option<&[Target]>) -> Result<Plan, LockfileError> {
    let mut plan = Plan::default();
    let mut seen = std::collections::HashSet::new();
    for path in lockfiles {
        let Some(artifacts) = crate::lockfile::artifacts(path)? else {
            plan.versions.extend(crate::lockfile::read(path)?);
            continue;
        };
        for artifact in artifacts {
            let installs = targets.is_none_or(|targets| {
                targets
                    .iter()
                    .any(|target| artifact.platform.allows(target))
            });
            if !installs {
                plan.skipped += 1;
            } else if seen.insert(artifact.path.clone()) {
                let (ecosystem, name, version) = &artifact.locked;
                let file = artifact.path.rsplit('/').next().unwrap_or_default();
                let label = format!("pkg:{ecosystem}/{name}@{version} {file}");
                plan.direct.push((label, artifact.path));
            }
        }
    }
    Ok(plan)
}

/// The proxy's own address: [`crate::env::PUBLIC_URL`] when set, otherwise where it
/// listens.
fn proxy_base<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &Env<L>,
) -> Result<String, EnvError> {
    match environment.public_url()? {
        Some(url) => Ok(url),
        None => Ok(format!("http://{}", environment.listen()?)),
    }
}

/// `plan`'s artifacts asked of the proxy at `base`, labelled. Every artifact is asked for
/// once, which starts each analysis, before any is asked for again.
async fn warm(base: &str, plan: &Plan, deadline: Duration) -> Vec<(String, Outcome)> {
    let http = crate::http::client_builder(crate::http::READ_TIMEOUT)
        .build()
        .expect("a client with no TLS settings of its own builds");
    let upstreams = Upstreams::defaults().with(Ecosystem::Npm, base).with(
        Ecosystem::PyPI,
        &format!(
            "{base}{}",
            crate::ecosystem::pypi::SIMPLE.trim_end_matches('/')
        ),
    );
    let clients = Clients::new(
        http.clone(),
        &upstreams,
        crate::env::DEFAULT_MAX_METADATA_BYTES,
    );
    let versions = crate::lockfile::references(plan.versions.iter().cloned());
    let found: Vec<Vec<(String, Ask)>> = futures_util::stream::iter(&versions)
        .map(|(purl, reference, version)| {
            let clients = &clients;
            async move { asks_for(base, purl, clients.record(reference.key(), version).await) }
        })
        .buffered(IN_FLIGHT)
        .collect()
        .await;
    let direct = plan
        .direct
        .iter()
        .map(|(label, path)| (label.clone(), Ask::Fetch(format!("{base}{path}"))));
    let asks: Vec<(String, Ask)> = direct.chain(found.into_iter().flatten()).collect();
    let first: Vec<(String, Answer, Option<String>)> = futures_util::stream::iter(asks)
        .map(|(label, ask)| {
            let http = http.clone();
            async move {
                match ask {
                    Ask::Known(outcome) => (label, Answer::Final(outcome), None),
                    Ask::Fetch(url) => (label, ask_once(&http, &url).await, Some(url)),
                }
            }
        })
        .buffered(IN_FLIGHT)
        .collect()
        .await;
    futures_util::stream::iter(first)
        .map(|(label, answer, url)| {
            let http = http.clone();
            async move {
                let outcome = match answer {
                    Answer::Final(outcome) => outcome,
                    Answer::Deferred(since) => {
                        let url = url.expect("only a fetched artifact is deferred");
                        ask_until_analysed(&http, &url, since, deadline).await
                    }
                };
                (label, outcome)
            }
        })
        .buffered(IN_FLIGHT)
        .collect()
        .await
}

/// What to ask for one locked version, given its record from the proxy.
fn asks_for(
    base: &str,
    purl: &str,
    record: Result<Option<crate::record::PackageRecord>, String>,
) -> Vec<(String, Ask)> {
    match record {
        Err(e) => vec![(purl.to_owned(), Ask::Known(Outcome::Failed(e)))],
        Ok(None) => vec![(purl.to_owned(), Ask::Known(Outcome::NotListed))],
        Ok(Some(record)) => record
            .artifacts
            .iter()
            .map(|artifact| {
                let label = format!("{purl} {}", artifact.filename);
                (label, Ask::Fetch(on_proxy(base, &artifact.url)))
            })
            .collect(),
    }
}

/// What to do for one label: an answer already known, or an artifact URL to ask for.
enum Ask {
    Known(Outcome),
    Fetch(String),
}

/// `url`'s path and query on `base`. The proxy writes artifact URLs with its public
/// address, which the machine running warm may not reach.
fn on_proxy(base: &str, url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed) => match parsed.query() {
            Some(query) => format!("{base}{}?{query}", parsed.path()),
            None => format!("{base}{}", parsed.path()),
        },
        Err(_) => url.to_owned(),
    }
}

/// One answer for an artifact: its outcome, or deferred for its analysis since then.
enum Answer {
    Final(Outcome),
    Deferred(Instant),
}

/// Ask for `url` once. The body is never read.
async fn ask_once(http: &reqwest::Client, url: &str) -> Answer {
    let response = match http.get(url).send().await {
        Ok(response) => response,
        Err(e) => return Answer::Final(Outcome::Failed(e.to_string())),
    };
    let status = response.status().as_u16();
    let not_ready = response
        .headers()
        .get(crate::proxy::NOT_READY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    drop(response);
    Answer::Final(match (status, not_ready.as_deref()) {
        (200..=299 | 304, _) => Outcome::Warmed,
        (503, Some("artifact-analysis")) => return Answer::Deferred(Instant::now()),
        (503, reason) => Outcome::NotReady(reason.unwrap_or("503").to_owned()),
        (400..=499, _) => Outcome::Refused(status),
        _ => Outcome::Failed(format!("answered {status}")),
    })
}

/// Ask for `url` each second until the answer is not a 503 for its analysis, or
/// `deadline` has passed `since` its first one.
async fn ask_until_analysed(
    http: &reqwest::Client,
    url: &str,
    since: Instant,
    deadline: Duration,
) -> Outcome {
    loop {
        if since.elapsed() >= deadline {
            return Outcome::StillDeferred;
        }
        tokio::time::sleep(Duration::from_secs(1).min(deadline)).await;
        if let Answer::Final(outcome) = ask_once(http, url).await {
            return outcome;
        }
    }
}

/// One line per artifact not warmed, then the counts, with the artifacts `skipped` for
/// other platforms.
fn render(outcomes: &[(String, Outcome)], skipped: usize) -> String {
    let mut out = String::new();
    let mut counts = [0usize; 6];
    for (label, outcome) in outcomes {
        let (index, line) = match outcome {
            Outcome::Warmed => (0, None),
            Outcome::Refused(status) => (1, Some(format!("refused {status}"))),
            Outcome::NotListed => (2, Some("not listed by the proxy".to_owned())),
            Outcome::NotReady(reason) => (3, Some(format!("not ready: {reason}"))),
            Outcome::StillDeferred => (4, Some("still being analysed".to_owned())),
            Outcome::Failed(why) => (5, Some(format!("failed: {why}"))),
        };
        counts[index] += 1;
        if let Some(line) = line {
            out.push_str(&format!("{label}: {line}\n"));
        }
    }
    let [warmed, refused, not_listed, not_ready, deferred, failed] = counts;
    out.push_str(&format!(
        "{warmed} warmed, {refused} refused, {not_listed} not listed, {not_ready} not ready, \
         {deferred} still being analysed, {failed} failed; {skipped} skipped for other \
         platforms\n"
    ));
    out
}

/// [`FAILED`] for a failure or a 503 waiting does not clear, and [`STILL_DEFERRED`].
fn code(outcomes: &[(String, Outcome)]) -> u8 {
    outcomes.iter().fold(0, |code, (_, outcome)| {
        code | match outcome {
            Outcome::Failed(_) | Outcome::NotReady(_) => FAILED,
            Outcome::StillDeferred => STILL_DEFERRED,
            _ => 0,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::testing::with;
    use crate::proxy::testing::{
        BLOCK, Extras, RUNS_NOTHING, RUNS_POSTINSTALL, analysing, analysing_with, integrity, serve,
    };
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use std::sync::Arc;

    const SHORT: Duration = Duration::from_secs(2);

    /// A `package-lock.json` locking `widget` 1.0.0, in a directory of the test's own.
    fn lockfile(label: &str) -> PathBuf {
        let path = crate::util::test_support::tempdir(label).join("package-lock.json");
        std::fs::write(
            &path,
            r#"{"lockfileVersion": 3, "packages": {"": {"name": "app", "version": "1.0.0"},
                "node_modules/widget": {"version": "1.0.0"}}}"#,
        )
        .unwrap();
        path
    }

    async fn warmed(label: &str, base: &str, deadline: Duration) -> Warmed {
        run(&[lockfile(label)], Some(base), None, deadline, &with(&[])).await
    }

    fn tarball() -> Vec<u8> {
        crate::util::test_support::tarball(&[("package/package.json", RUNS_NOTHING)])
    }

    #[tokio::test]
    async fn an_artifact_is_asked_for_until_it_has_been_analysed() {
        let tarball = tarball();
        let (base, _) = analysing("warm-analysed", "", &integrity(&tarball), tarball, None).await;

        let warmed = warmed("warm-analysed-lock", &base, SHORT).await;

        assert_eq!(
            warmed.report,
            "1 warmed, 0 refused, 0 not listed, 0 not ready, 0 still being analysed, 0 failed; \
             0 skipped for other platforms\n"
        );
        assert_eq!(warmed.code, 0);
    }

    /// The metadata claims no script and the tarball runs one: listed, deferred, then
    /// refused once the analysis finds it.
    #[tokio::test]
    async fn a_refusal_is_the_policy_answering_and_not_a_failure() {
        let tarball =
            crate::util::test_support::tarball(&[("package/package.json", RUNS_POSTINSTALL)]);
        let (base, _) = analysing(
            "warm-refused",
            "",
            &integrity(&tarball),
            tarball,
            Some(BLOCK),
        )
        .await;

        let warmed = warmed("warm-refused-lock", &base, SHORT).await;

        assert!(
            warmed
                .report
                .starts_with("pkg:npm/widget@1.0.0 widget-1.0.0.tgz: refused 403\n"),
            "{}",
            warmed.report
        );
        assert_eq!(warmed.code, 0);
    }

    /// A denied version's artifact is asked for by the path the lockfile gives, and refused.
    #[tokio::test]
    async fn a_denied_version_is_refused_at_its_artifact() {
        let tarball = tarball();
        let deny = "version: 1\ncooldown_days: 0\n\
                    denials:\n  - purl: pkg:npm/widget@1.0.0\n    reason: t\n";
        let (base, _) = analysing(
            "warm-unlisted",
            "",
            &integrity(&tarball),
            tarball,
            Some(deny),
        )
        .await;

        let warmed = warmed("warm-unlisted-lock", &base, SHORT).await;

        assert!(
            warmed
                .report
                .starts_with("pkg:npm/widget@1.0.0 widget-1.0.0.tgz: refused 403\n"),
            "{}",
            warmed.report
        );
        assert_eq!(warmed.code, 0);
    }

    /// The upstream never lets the analysis fetch the artifact.
    #[tokio::test]
    async fn an_analysis_that_does_not_finish_by_the_deadline_is_still_deferred() {
        let tarball = tarball();
        let (base, _) = analysing_with(
            "warm-deferred",
            "",
            &integrity(&tarball),
            tarball,
            None,
            Arc::new(crate::analysis::store::InProcess::new(8)),
            Extras {
                gate: Some(Arc::new(tokio::sync::Semaphore::new(0))),
                ..Extras::default()
            },
        )
        .await;

        let warmed = warmed("warm-deferred-lock", &base, SHORT).await;

        assert!(
            warmed.report.contains("still being analysed\n"),
            "{}",
            warmed.report
        );
        assert_eq!(warmed.code, STILL_DEFERRED);
    }

    #[tokio::test]
    async fn a_proxy_that_does_not_answer_fails_each_version() {
        let addr = crate::util::test_support::closing_server().await;

        let warmed = warmed("warm-closed-lock", &format!("http://{addr}"), SHORT).await;

        assert!(
            warmed
                .report
                .starts_with("pkg:npm/widget@1.0.0 widget-1.0.0.tgz: failed: "),
            "{}",
            warmed.report
        );
        assert_eq!(warmed.code, FAILED);
    }

    /// Only a 503 for an analysis is asked again. Each answer is asked for once here.
    #[tokio::test]
    async fn each_answer_is_one_outcome() {
        let not_ready = |reason: &'static str| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(crate::proxy::NOT_READY, reason)],
            )
        };
        let base = serve(
            Router::new()
                .route(
                    "/intel",
                    get(move || async move { not_ready("intel-store") }),
                )
                .route("/bare", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
                .route(
                    "/broken",
                    get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
                )
                .route("/cached", get(|| async { StatusCode::NOT_MODIFIED })),
        )
        .await;
        let http = reqwest::Client::new();
        let ask = |path: &str| {
            let url = format!("{base}{path}");
            let http = http.clone();
            async move {
                match ask_once(&http, &url).await {
                    Answer::Final(outcome) => outcome,
                    Answer::Deferred(_) => panic!("{url} is not deferred"),
                }
            }
        };

        assert_eq!(
            ask("/intel").await,
            Outcome::NotReady("intel-store".to_owned())
        );
        assert_eq!(ask("/bare").await, Outcome::NotReady("503".to_owned()));
        assert_eq!(
            ask("/broken").await,
            Outcome::Failed("answered 500".to_owned())
        );
        assert_eq!(ask("/cached").await, Outcome::Warmed);
        assert_eq!(ask("/missing").await, Outcome::Refused(404));
    }

    /// A lockfile with no artifact reader is warmed through the proxy's metadata: a
    /// listed version's files are asked for, and an unlisted version is reported.
    #[tokio::test]
    async fn a_lockfile_without_artifact_paths_is_warmed_through_the_metadata() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let index = format!(
            r#"{{"meta":{{"api-version":"1.0"}},"name":"x","files":[{{"filename":"x-1.0.tar.gz",
                "url":"https://waharoa.example/packages/x-1.0.tar.gz",
                "hashes":{{"sha256":"{}"}}}}]}}"#,
            "a".repeat(64)
        );
        let router = Router::new()
            .route(
                "/simple/x/",
                get(move || {
                    let index = index.clone();
                    async move {
                        (
                            [(
                                axum::http::header::CONTENT_TYPE,
                                crate::ecosystem::pypi::SIMPLE_JSON,
                            )],
                            index,
                        )
                    }
                }),
            )
            .route("/packages/x-1.0.tar.gz", get(|| async { "bytes" }));
        tokio::spawn(axum::serve(listener, router).into_future());
        let path = crate::util::test_support::tempdir("warm-pypi").join("requirements.txt");
        std::fs::write(&path, "x==1.0\nx==2.0\n").unwrap();

        let warmed = run(&[path], Some(&base), None, SHORT, &with(&[])).await;

        assert_eq!(
            warmed.report,
            "pkg:pypi/x@2.0: not listed by the proxy\n\
             1 warmed, 0 refused, 1 not listed, 0 not ready, 0 still being analysed, 0 failed; \
             0 skipped for other platforms\n"
        );
    }

    /// Only artifacts that install on a target are asked for, each path once.
    #[test]
    fn the_plan_keeps_what_installs_on_a_target() {
        let dir = crate::util::test_support::tempdir("warm-plan");
        let path = dir.join("package-lock.json");
        std::fs::write(
            &path,
            r#"{"lockfileVersion": 3, "packages": {"": {"name": "app"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/b/node_modules/a": {"version": "1.0.0"},
                "node_modules/@x/mac": {"version": "2.0.0", "os": ["darwin"], "cpu": ["arm64"]},
                "node_modules/@x/musl": {"version": "2.0.0", "os": ["linux"], "cpu": ["x64"],
                    "libc": ["musl"]}}}"#,
        )
        .unwrap();
        let linux = Target::parse("linux-x64").unwrap();

        let plan = super::plan(std::slice::from_ref(&path), Some(&[linux])).unwrap();

        assert_eq!(
            plan.direct,
            [(
                "pkg:npm/a@1.0.0 a-1.0.0.tgz".to_owned(),
                "/a/-/a-1.0.0.tgz".to_owned()
            )]
        );
        assert_eq!(plan.skipped, 2);
        assert_eq!(super::plan(&[path], None).unwrap().direct.len(), 3);
    }

    #[test]
    fn every_outcome_is_counted_and_sets_its_exit_bit() {
        let outcomes: Vec<(String, Outcome)> = [
            Outcome::Warmed,
            Outcome::Refused(403),
            Outcome::NotListed,
            Outcome::NotReady("intel-store".to_owned()),
            Outcome::StillDeferred,
            Outcome::Failed("x".to_owned()),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, outcome)| (format!("p{i}"), outcome))
        .collect();

        assert_eq!(
            render(&outcomes, 2),
            "p1: refused 403\np2: not listed by the proxy\np3: not ready: intel-store\n\
             p4: still being analysed\np5: failed: x\n\
             1 warmed, 1 refused, 1 not listed, 1 not ready, 1 still being analysed, 1 failed; \
             2 skipped for other platforms\n"
        );
        assert_eq!(code(&outcomes), FAILED | STILL_DEFERRED);
        assert_eq!(code(&outcomes[..3]), 0);
        assert_eq!(code(&outcomes[3..4]), FAILED);
    }

    #[tokio::test]
    async fn a_lockfile_that_does_not_read_is_an_error_on_its_own() {
        let missing = PathBuf::from("/nonexistent/package-lock.json");

        let warmed = run(
            &[missing],
            Some("http://127.0.0.1:1"),
            None,
            SHORT,
            &with(&[]),
        )
        .await;

        assert_eq!(warmed.code, UNREAD);
        assert!(warmed.report.is_empty());
    }

    #[test]
    fn the_proxy_is_its_public_url_or_where_it_listens() {
        use crate::env::{LISTEN, PUBLIC_URL};
        assert_eq!(
            proxy_base(&with(&[(PUBLIC_URL, "https://waharoa.example")])).unwrap(),
            "https://waharoa.example"
        );
        assert_eq!(
            proxy_base(&with(&[(LISTEN, "127.0.0.1:9000")])).unwrap(),
            "http://127.0.0.1:9000"
        );
        assert!(proxy_base(&with(&[(LISTEN, "")])).is_ok());
    }

    /// An artifact URL keeps its path and query and takes warm's address for the proxy.
    #[test]
    fn an_artifact_is_asked_of_the_proxy_warm_was_given() {
        let base = "http://10.0.0.5:8080";
        assert_eq!(
            on_proxy(base, "https://waharoa.example/widget/-/widget-1.0.0.tgz"),
            "http://10.0.0.5:8080/widget/-/widget-1.0.0.tgz"
        );
        assert_eq!(
            on_proxy(base, "https://waharoa.example/packages/a/x-1.0.tar.gz?h=1"),
            "http://10.0.0.5:8080/packages/a/x-1.0.tar.gz?h=1"
        );
        assert_eq!(on_proxy(base, "not a url"), "not a url");
    }
}
