//! `byrle warm`: ask a running proxy for every artifact a lockfile locks, so each is
//! analysed before a client asks for it.
//!
//! See `docs/engineering_decisions/warm.md`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures_util::StreamExt;

use crate::ecosystem::{Clients, Upstreams};
use crate::env::Env;
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
    /// The proxy's metadata does not list the version: refused, or on an origin it does not serve.
    NotListed,
    /// Answered 503 for the reason `x-byrle-not-ready` names, which waiting does not clear.
    NotReady(String),
    /// Still 503 for its analysis at the deadline.
    StillDeferred,
    Failed(String),
}

/// What `byrle warm` prints, and its exit code.
#[derive(Debug, PartialEq)]
pub struct Warmed {
    /// For stderr: why nothing was asked.
    pub notes: Vec<String>,
    pub report: String,
    /// The OR of [`FAILED`] and [`STILL_DEFERRED`], or [`UNREAD`] on its own.
    pub code: u8,
}

/// `byrle warm`: read `lockfiles` and ask the proxy at `proxy`, or the environment's, for
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
        .map_or_else(|| environment.proxy_base(), Ok)
    {
        Ok(base) => base.trim_end_matches('/').to_owned(),
        Err(e) => return unread(e.to_string()),
    };
    let http = match environment
        .token()
        .map_err(|e| e.to_string())
        .and_then(client)
    {
        Ok(http) => http,
        Err(e) => return unread(e),
    };
    let plan = match plan(lockfiles, targets) {
        Ok(plan) => plan,
        Err(e) => return unread(e.to_string()),
    };
    let (outcomes, skipped) = warm(&http, &base, (&plan, targets), deadline).await;
    Warmed {
        notes: Vec::new(),
        report: render(&outcomes, plan.skipped + skipped),
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

/// The client warm asks the proxy with, sending `token` on every request when there is one.
fn client(token: Option<String>) -> Result<reqwest::Client, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = token {
        let mut value = reqwest::header::HeaderValue::from_str(&token).map_err(|_| {
            format!(
                "{} is not a value an HTTP header can carry",
                crate::env::TOKEN
            )
        })?;
        value.set_sensitive(true);
        headers.insert(crate::account::gate::TOKEN_HEADER, value);
    }
    Ok(crate::http::client_builder(crate::http::READ_TIMEOUT)
        .default_headers(headers)
        .build()
        .expect("a client with no TLS settings of its own builds"))
}

/// `plan`'s artifacts asked of the proxy at `base`, labelled. Every artifact is asked for
/// once, which starts each analysis, before any is asked for again.
/// Each artifact's outcome, and how many files of the versions read through the proxy were
/// left out for other platforms.
async fn warm(
    http: &reqwest::Client,
    base: &str,
    (plan, targets): (&Plan, Option<&[Target]>),
    deadline: Duration,
) -> (Vec<(String, Outcome)>, usize) {
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
    let found: Vec<(Vec<(String, Ask)>, usize)> = futures_util::stream::iter(&versions)
        .map(|(purl, reference, version)| {
            let clients = &clients;
            async move {
                let record = clients.record(reference.key(), version).await;
                asks_for(base, purl, record, targets)
            }
        })
        .buffered(IN_FLIGHT)
        .collect()
        .await;
    let skipped = found.iter().map(|(_, skipped)| skipped).sum();
    let direct = plan
        .direct
        .iter()
        .map(|(label, path)| (label.clone(), Ask::Fetch(format!("{base}{path}"))));
    let asks: Vec<(String, Ask)> = direct
        .chain(found.into_iter().flat_map(|(asks, _)| asks))
        .collect();
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
    let outcomes = futures_util::stream::iter(first)
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
        .await;
    (outcomes, skipped)
}

/// What to ask for one locked version, given its record from the proxy, and how many of
/// its files were left out. A PyPI version's files are those an install on one of
/// `targets` could fetch: its wheels for them, or its sdist when it has none.
fn asks_for(
    base: &str,
    purl: &str,
    record: Result<Option<crate::record::PackageRecord>, String>,
    targets: Option<&[Target]>,
) -> (Vec<(String, Ask)>, usize) {
    let record = match record {
        Err(e) => return (vec![(purl.to_owned(), Ask::Known(Outcome::Failed(e)))], 0),
        Ok(None) => return (vec![(purl.to_owned(), Ask::Known(Outcome::NotListed))], 0),
        Ok(Some(record)) => record,
    };
    let mut files: Vec<&crate::record::Artifact> = record.artifacts.iter().collect();
    if let (Ecosystem::PyPI, Some(targets)) = (record.package.key().ecosystem(), targets) {
        let wheel = |filename: &str| {
            targets
                .iter()
                .any(|t| crate::ecosystem::pypi::wheel::installs_on(filename, t))
        };
        let wheels = files.iter().any(|a| wheel(&a.filename));
        files.retain(|a| wheel(&a.filename) || !wheels && !a.filename.ends_with(".whl"));
    }
    let asks = files
        .iter()
        .map(|artifact| {
            let label = format!("{purl} {}", artifact.filename);
            (label, Ask::Fetch(on_proxy(base, &artifact.url)))
        })
        .collect();
    (asks, record.artifacts.len() - files.len())
}

/// What to do for one label: an answer already known, or an artifact URL to ask for.
enum Ask {
    Known(Outcome),
    Fetch(String),
}

/// `url`'s path and query on `base`. The proxy writes artifact URLs with its public
/// address, which the machine running warm may not reach. A path under `base`'s own path
/// is taken from below it, so `/registry/widget` on `http://h/registry` is not doubled.
fn on_proxy(base: &str, url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return url.to_owned();
    };
    let below = crate::mount::Mount::from_url(base)
        .ok()
        .and_then(|mount| mount.strip(parsed.path()))
        .unwrap_or_else(|| parsed.path().to_owned());
    let base = base.trim_end_matches('/');
    match parsed.query() {
        Some(query) => format!("{base}{below}?{query}"),
        None => format!("{base}{below}"),
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
        (401, _) => Outcome::Failed(format!(
            "answered 401: set {} to a token from `byrle token create`",
            crate::env::TOKEN
        )),
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
                .route("/cached", get(|| async { StatusCode::NOT_MODIFIED }))
                .route("/no-token", get(|| async { StatusCode::UNAUTHORIZED })),
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
        let Outcome::Failed(why) = ask("/no-token").await else {
            panic!("a 401 is a failure");
        };
        assert!(why.contains(crate::env::TOKEN.name), "{why}");
        assert_eq!(ask("/missing").await, Outcome::Refused(404));
    }

    /// 401 unless the request carries the token `byrle_t`.
    async fn needs_token(
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        match request.headers().get(crate::account::gate::TOKEN_HEADER) {
            Some(token) if token == "byrle_t" => next.run(request).await,
            _ => StatusCode::UNAUTHORIZED.into_response(),
        }
    }

    /// A proxy serving project `x`'s JSON index listing `files`, each served at
    /// `/packages/<file>` behind a token but those in `missing`, which are 404, and its URL.
    async fn index_of(files: &[&str], missing: &[&str]) -> String {
        let missing: Vec<String> = missing.iter().map(|m| (*m).to_owned()).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let listed: Vec<String> = files
            .iter()
            .map(|file| {
                format!(
                    r#"{{"filename":"{file}","url":"https://byrle.example/packages/{file}",
                        "hashes":{{"sha256":"{}"}}}}"#,
                    "a".repeat(64)
                )
            })
            .collect();
        let index = format!(
            r#"{{"meta":{{"api-version":"1.0"}},"name":"x","files":[{}]}}"#,
            listed.join(",")
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
            .route(
                "/packages/{file}",
                get(
                    move |axum::extract::Path(file): axum::extract::Path<String>| async move {
                        if missing.contains(&file) {
                            Err(StatusCode::NOT_FOUND)
                        } else {
                            Ok("bytes")
                        }
                    },
                ),
            )
            .layer(axum::middleware::from_fn(needs_token));
        tokio::spawn(axum::serve(listener, router).into_future());
        base
    }

    /// A lockfile with no artifact reader is warmed through the proxy's metadata, sending
    /// [`crate::env::TOKEN`]: a listed version's files are asked for, an unlisted one reported.
    #[tokio::test]
    async fn a_lockfile_without_artifact_paths_is_warmed_through_the_metadata() {
        let base = index_of(&["x-1.0.tar.gz"], &[]).await;
        let path = crate::util::test_support::tempdir("warm-pypi").join("requirements.txt");
        std::fs::write(&path, "x==1.0\nx==2.0\n").unwrap();

        let environment = with(&[(crate::env::TOKEN, "byrle_t")]);
        let warmed = run(&[path], Some(&base), None, SHORT, &environment).await;

        assert_eq!(
            warmed.report,
            "pkg:pypi/x@2.0: not listed by the proxy\n\
             1 warmed, 0 refused, 1 not listed, 0 not ready, 0 still being analysed, 0 failed; \
             0 skipped for other platforms\n"
        );
    }

    /// For a target, a version's wheels for it are asked for, or its sdist when it has none.
    /// Every other file is skipped, and 404, so asking for one would be reported.
    #[tokio::test]
    async fn a_pypi_version_is_warmed_with_the_files_its_target_installs() {
        let files = [
            "x-1.0.tar.gz",
            "x-1.0-cp313-cp313-manylinux_2_17_x86_64.whl",
            "x-1.0-cp313-cp313-win_amd64.whl",
            "x-2.0.tar.gz",
            "x-2.0-cp313-cp313-win_amd64.whl",
        ];
        let base = index_of(&files, &[files[0], files[2], files[4]]).await;
        let path = crate::util::test_support::tempdir("warm-pypi-target").join("requirements.txt");
        std::fs::write(&path, "x==1.0\nx==2.0\n").unwrap();
        let environment = with(&[(crate::env::TOKEN, "byrle_t")]);
        let linux = [Target::parse("linux-x64").unwrap()];
        let warmed = run(
            std::slice::from_ref(&path),
            Some(&base),
            Some(&linux),
            SHORT,
            &environment,
        )
        .await;
        assert_eq!(
            warmed.report,
            "2 warmed, 0 refused, 0 not listed, 0 not ready, 0 still being analysed, 0 failed; \
             3 skipped for other platforms\n"
        );
        let every = run(&[path], Some(&base), None, SHORT, &environment).await;
        assert!(
            every.report.contains("2 warmed, 3 refused"),
            "every platform's files are asked for: {}",
            every.report
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

    /// An artifact URL keeps its path and query and takes warm's address for the proxy.
    #[test]
    fn an_artifact_is_asked_of_the_proxy_warm_was_given() {
        let base = "http://10.0.0.5:8080";
        assert_eq!(
            on_proxy(base, "https://byrle.example/widget/-/widget-1.0.0.tgz"),
            "http://10.0.0.5:8080/widget/-/widget-1.0.0.tgz"
        );
        assert_eq!(
            on_proxy(base, "https://byrle.example/packages/a/x-1.0.tar.gz?h=1"),
            "http://10.0.0.5:8080/packages/a/x-1.0.tar.gz?h=1"
        );
        assert_eq!(on_proxy(base, "not a url"), "not a url");

        let under = "http://10.0.0.5:8080/registry/";
        assert_eq!(
            on_proxy(
                under,
                "https://byrle.example/registry/widget/-/widget-1.0.0.tgz"
            ),
            "http://10.0.0.5:8080/registry/widget/-/widget-1.0.0.tgz"
        );
        assert_eq!(
            on_proxy(under, "https://byrle.example/widget/-/widget-1.0.0.tgz"),
            "http://10.0.0.5:8080/registry/widget/-/widget-1.0.0.tgz"
        );
    }

    /// With no proxy given, warm asks the environment for one, and a variable it cannot read,
    /// or a token no header can carry, stops it before anything is asked.
    #[tokio::test]
    async fn the_proxy_comes_from_the_environment_or_warm_stops() {
        use crate::env::testing::with_unreadable;
        use crate::env::{LISTEN, PROXY_URL};

        for environment in [
            with_unreadable(&[], PROXY_URL),
            with_unreadable(&[], LISTEN),
            with_unreadable(&[], crate::env::TOKEN),
            with(&[(crate::env::TOKEN, "two\nlines")]),
        ] {
            let warmed = run(&[], None, None, SHORT, &environment).await;
            assert_eq!(warmed.code, UNREAD);
            assert_eq!(warmed.notes.len(), 1);
        }
        let warmed = run(&[], None, None, SHORT, &with(&[(LISTEN, "127.0.0.1:1")])).await;
        assert_eq!(warmed.code, 0, "{:?}", warmed.notes);
    }

    /// A lockfile read for its versions, rather than its artifacts, that cannot be read is
    /// an error, and a record that could not be fetched fails its version.
    #[test]
    fn a_version_lockfile_or_record_that_cannot_be_read_fails() {
        let missing = PathBuf::from("/nonexistent/requirements.txt");
        assert!(plan(&[missing], None).is_err());
        let (asked, skipped) = asks_for(
            "http://p",
            "pkg:npm/a@1.0.0",
            Err("unreachable".to_owned()),
            None,
        );
        assert_eq!(skipped, 0);
        assert!(matches!(
            asked.as_slice(),
            [(purl, Ask::Known(Outcome::Failed(why)))] if purl == "pkg:npm/a@1.0.0" && why == "unreachable"
        ));
    }
}
