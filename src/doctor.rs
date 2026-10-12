//! `byrle doctor`: whether this machine is actually installing through the proxy, from
//! the client side. The checks are pure; [`probe`] runs the package managers.
//!
//! See docs/engineering_decisions/enforcement-tiers.md.

use crate::env;
use crate::lockfile::{Lockfile, Pins};
use crate::policy::check::Report;
use crate::policy::packages;
use crate::proxy::{IntelState, READY_PATH, Readiness};
use std::collections::BTreeSet;
use std::fmt;

/// The title of the findings about the address the running proxy writes into artifact URLs.
const PROXY_URL_IN_USE: &str = "proxy URL in use";

/// What follows from a proxy with no proxy URL, said by `doctor` and by the proxy at startup.
pub const WITHOUT_PROXY_URL: &str =
    "artifact URLs use whatever Host each client used, and that address is what lockfiles record";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Nothing to do.
    Ok,
    /// Worth knowing, and not a failure on its own.
    Warn,
    /// Installs are not going through the proxy, or are about to stop working.
    Problem,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "WARN",
            Self::Problem => "PROBLEM",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// What to do about it, when there is something to do.
    pub fix: Option<String>,
}

impl Finding {
    fn new(severity: Severity, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity,
            title: title.into(),
            detail: detail.into(),
            fix: None,
        }
    }

    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fix = self
            .fix
            .as_ref()
            .map(|fix| format!("\n         fix: {fix}"))
            .unwrap_or_default();
        write!(
            f,
            "{:>7}  {}: {}{fix}",
            self.severity.label(),
            self.title,
            self.detail
        )
    }
}

/// How a client is asked for its registry.
pub struct RegistryQuery {
    /// Arguments that make the client print the registry it resolves to.
    pub args: &'static [&'static str],
    /// What the client prints for a key with no value.
    pub unset: &'static str,
}

/// The index a client installs from, and the other indexes it also asks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Indexes {
    /// The configured index, or the client's own default when none is configured.
    pub index: String,
    /// Indexes asked beside it. What they serve never reaches the proxy.
    pub extra: Vec<String>,
}

/// Where `doctor` learns which registry a client uses.
pub enum RegistrySource {
    /// The client prints it: npm, pnpm and yarn.
    Asked(RegistryQuery),
    /// A function of the client's ecosystem module reads it: pip and uv.
    Read {
        read: fn(&Machine) -> Result<Option<Indexes>, env::EnvError>,
        /// What points the client at `url`.
        set_index: fn(&str) -> String,
        /// What removes an extra index.
        drop_extra: fn() -> String,
    },
}

/// A package manager `doctor` checks, as its [`crate::ecosystem::TABLE`] row lists it.
pub struct Client {
    /// The program, and the name findings use.
    pub name: &'static str,
    /// How to learn the registry the client uses. `None` when it is not checked.
    pub registry: Option<RegistrySource>,
    /// The command that points the client at a registry, before the address.
    pub set_registry: &'static str,
    pub cache: CacheLocation,
    pub bypass: CacheBypass,
    /// The command that empties the cache.
    pub clear_cache: &'static str,
}

/// Where a client keeps its cache.
pub enum CacheLocation {
    /// The client prints a directory when run with `args`. The cache is `under` it.
    Asked {
        args: &'static [&'static str],
        under: Option<&'static str>,
    },
    /// A variable names the directory, else it is `under_home` in the home directory.
    Configured {
        configured: fn(&env::Process) -> Result<Option<std::path::PathBuf>, env::EnvError>,
        under_home: &'static str,
    },
}

/// What `doctor` reads from the machine: the environment, the directory and the programs.
pub struct Machine<'a> {
    pub environment: &'a env::Process,
    /// Where lockfiles and uv's project configuration are read from.
    pub dir: &'a std::path::Path,
    /// Run a program and return what it printed, trimmed; `None` when it failed.
    pub run: &'a (dyn Fn(&str, &[&str]) -> Option<String> + Sync),
}

impl<'a> Machine<'a> {
    /// This machine: programs run with [`probe::run`].
    pub fn this(environment: &'a env::Process, dir: &'a std::path::Path) -> Self {
        Self {
            environment,
            dir,
            run: &probe::run,
        }
    }

    /// What `program` printed, `None` also when it printed nothing.
    pub fn ask(&self, program: &str, args: &[&str]) -> Option<String> {
        (self.run)(program, args).filter(|printed| !printed.is_empty())
    }
}

/// Every client any ecosystem lists, in table order.
pub fn clients() -> impl Iterator<Item = &'static Client> {
    crate::ecosystem::TABLE
        .iter()
        .flat_map(|registry| registry.clients)
}

/// Artifact origins a lockfile records, read as text from each line holding `key`.
/// See docs/engineering_decisions/doctor-lockfile-urls.md.
/// `contents` is the lockfile. Returns nothing when it pins no absolute URL.
pub fn recorded_origins(key: &str, contents: &str) -> BTreeSet<String> {
    let mut origins = BTreeSet::new();
    for line in contents.lines() {
        let Some(after) = line.split(key).nth(1) else {
            continue;
        };
        let found = after.match_indices("http").find_map(|(start, _)| {
            let url: String = after[start..]
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | ',' | '}' | '#'))
                .collect();
            crate::origin::origin_of_url(&url)
        });
        origins.extend(found);
    }
    origins
}

/// Whether a package manager is pointed at the proxy. A credential in the configured URL
/// is not printed.
pub fn check_registry(client: &Client, configured: Option<&str>, proxy: &str) -> Finding {
    let title = format!("{} registry", client.name);
    let Some(configured) = configured.map(str::trim).filter(|s| !s.is_empty()) else {
        return Finding::new(
            Severity::Warn,
            title,
            "not installed, or its configuration could not be read",
        );
    };
    let shown = crate::origin::without_credentials(configured);

    if same_origin(configured, proxy) {
        return Finding::new(Severity::Ok, title, shown);
    }
    Finding::new(
        Severity::Problem,
        title,
        format!("points at {shown}, not the proxy at {proxy}"),
    )
    .with_fix({
        let url = format!("{proxy}{}", index_path(client).trim_end_matches('/'));
        match &client.registry {
            Some(RegistrySource::Read { set_index, .. }) => set_index(&url),
            _ => format!("{} {url}", client.set_registry),
        }
    })
}

/// The path the proxy serves `client`'s ecosystem under: `/simple/` for PyPI.
fn index_path(client: &Client) -> &'static str {
    crate::ecosystem::TABLE
        .iter()
        .find(|registry| registry.clients.iter().any(|c| c.name == client.name))
        .map_or("", |registry| registry.setup.path)
}

/// Whether a client asks any index besides the one it is pointed at. An extra index serves
/// its own files, which the proxy never sees: pip with an `extra-index-url` in its
/// configuration fetched every file from that index on 2026-09-16, and the proxy saw no
/// `/packages/` request at all.
pub fn check_extra_indexes(
    client: &Client,
    extra: &[String],
    drop_extra: &str,
    proxy: &str,
) -> Finding {
    let title = format!("{} extra indexes", client.name);
    let elsewhere: Vec<String> = extra
        .iter()
        .filter(|url| !same_origin(url, proxy))
        .map(|url| crate::origin::without_credentials(url))
        .collect();
    if elsewhere.is_empty() {
        return Finding::new(Severity::Ok, title, "none");
    }
    Finding::new(
        Severity::Problem,
        title,
        format!(
            "also asks {}, whose files never reach the proxy",
            elsewhere.join(", ")
        ),
    )
    .with_fix(drop_extra)
}

/// Whether a lockfile is evidence that the proxy produced it.
///
/// npm, yarn and bun record the artifact URL, bun for every registry but npmjs.org.
/// pnpm omits it for the configured registry, so its lockfiles prove nothing either way.
pub fn check_lockfile(lockfile: &Lockfile, pins: &Pins, contents: &str, proxy: &str) -> Finding {
    let title = lockfile.name.to_owned();
    let origins = recorded_origins(pins.key, contents);

    let locks_nothing = || matches!((lockfile.read)(contents), Ok(locked) if locked.is_empty());
    if origins.is_empty() && pins.absent_is_off_proxy && !locks_nothing() {
        return Finding::new(Severity::Warn, title, pins.when_absent).with_fix(pins.reinstall);
    }
    if origins.is_empty() {
        return Finding::new(Severity::Ok, title, pins.when_absent);
    }

    let proxy_origin = crate::origin::origin_of_url(proxy).unwrap_or_else(|| proxy.to_owned());
    let (ours, theirs): (Vec<&String>, Vec<&String>) =
        origins.iter().partition(|o| **o == proxy_origin);

    if theirs.is_empty() {
        return Finding::new(
            Severity::Ok,
            title,
            format!(
                "every artifact is pinned to {proxy_origin}, so this was installed through the proxy"
            ),
        );
    }
    if ours.is_empty() {
        return Finding::new(
            Severity::Warn,
            title,
            format!(
                "artifacts are pinned to {}, so this was not installed through the proxy",
                join(&theirs)
            ),
        )
        .with_fix(pins.reinstall);
    }
    Finding::new(
        Severity::Problem,
        title,
        format!(
            "artifacts are split between {proxy_origin} and {}, so part of this install does \
             not go through the proxy",
            join(&theirs)
        ),
    )
    .with_fix(pins.reinstall)
}

/// Whether the address written into artifact URLs is pinned, so it is not whatever `Host`
/// each client used. `recorded` are the origins the lockfiles hold.
pub fn check_proxy_url(configured: Option<&str>, recorded: &BTreeSet<String>) -> Finding {
    let title = "proxy URL".to_owned();
    let Some(configured) = configured.map(str::trim).filter(|s| !s.is_empty()) else {
        return Finding::new(
            Severity::Warn,
            title,
            format!("{} is not set, so {WITHOUT_PROXY_URL}", env::PROXY_URL),
        )
        .with_fix(format!(
            "set {} to a stable name everyone who uses the lockfile can reach",
            env::PROXY_URL
        ));
    };

    let origin = crate::origin::origin_of_url(configured).unwrap_or_else(|| configured.to_owned());
    let stale: Vec<&String> = recorded
        .iter()
        .filter(|o| **o != origin && !looks_like_a_registry(o))
        .collect();

    if stale.is_empty() {
        return Finding::new(Severity::Ok, title, origin);
    }
    Finding::new(
        Severity::Problem,
        title,
        format!(
            "lockfiles pin artifacts to {}, which is not {origin}. `npm ci` fetches the \
             address in the lockfile and does not fall back, so it fails once that address \
             stops answering",
            join(&stale)
        ),
    )
    .with_fix("serve the proxy at the recorded address, or reinstall to rewrite the lockfiles")
}

/// How much of an install a warm cache supplies without asking the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheBypass {
    /// The whole install is served locally.
    Complete,
    /// Metadata is still fetched; artifacts are not.
    ArtifactsOnly,
    /// Every install still asks the registry for the index and the files.
    None,
}

/// Which form the configured PyPI index serves, and so where a cooldown is answered: the
/// index, or a PEP 503 file's `Last-Modified`.
/// See docs/engineering_decisions/pep-503-html-index.md.
pub fn check_index_format(index: &str, content_type: Option<&str>, uses_cooldown: bool) -> Finding {
    let title = "pypi index form";
    let shown = crate::origin::without_credentials(index);
    let format = content_type
        .and_then(|t| crate::ecosystem::of(crate::identity::Ecosystem::PyPI).document(Some(t)));
    match format {
        Some(crate::route::DocumentKind::SimpleIndex(crate::route::IndexFormat::Json)) => {
            Finding::new(Severity::Ok, title, format!("{shown} serves PEP 691 JSON"))
        }
        Some(crate::route::DocumentKind::SimpleIndex(crate::route::IndexFormat::Html))
            if uses_cooldown =>
        {
            Finding::new(
                Severity::Warn,
                title,
                format!(
                    "{shown} serves PEP 503 HTML, which carries no publish time, so \
                     cooldown_days is answered on the artifact request rather than while \
                     filtering the index"
                ),
            )
            .with_fix(
                "nothing to change here; a version too new is refused when its file is fetched",
            )
        }
        Some(_) => Finding::new(Severity::Ok, title, format!("{shown} serves PEP 503 HTML")),
        None => Finding::new(
            Severity::Warn,
            title,
            format!("{shown} did not say which form it serves"),
        ),
    }
}

/// A warm client cache serves without the registry, so what it supplies is never examined.
/// See docs/engineering_decisions/client-caches.md.
/// `cache` is where the client would look from this directory, `None` when nothing is there.
pub fn check_cache(client: &Client, cache: Option<&std::path::Path>) -> Finding {
    let title = format!("{} cache", client.name);
    let Some(cache) = cache else {
        return Finding::new(
            Severity::Ok,
            title,
            "empty or absent, so installs reach the proxy",
        );
    };

    let effect = match client.bypass {
        CacheBypass::None => {
            return Finding::new(
                Severity::Ok,
                title,
                format!(
                    "{} holds cached packages, and a warm cache still asks the proxy",
                    cache.display()
                ),
            );
        }
        CacheBypass::Complete => {
            "A warm cache supplies the whole install, so those packages never reach the proxy"
        }
        CacheBypass::ArtifactsOnly => {
            "A warm cache still fetches metadata but serves artifacts locally, so those \
             artifacts are never examined"
        }
    };
    Finding::new(
        Severity::Warn,
        title,
        format!("{} holds cached packages. {effect}", cache.display()),
    )
    .with_fix(client.clear_cache)
}

/// Whether the proxy is there, and whether it is configured the way this check expects.
/// `health` is what [`crate::proxy::HEALTH_PATH`] returned, or why nothing answered.
pub fn check_proxy(health: Result<&crate::proxy::Health, &Unreached>, proxy: &str) -> Vec<Finding> {
    let title = "proxy".to_owned();
    let health = match health {
        Ok(health) => health,
        Err(unreached) => return vec![unanswered(title, unreached, proxy)],
    };

    let upstreams = crate::ecosystem::written(
        health
            .upstreams
            .iter()
            .map(|(ecosystem, base)| (ecosystem, base.as_str())),
    );
    let mut findings = vec![Finding::new(
        Severity::Ok,
        title,
        format!(
            "{} {} at {proxy}, forwarding to {upstreams}",
            health.service, health.version
        ),
    )];

    match health.public_base.as_deref() {
        Some(base) if same_origin(base, proxy) => {}
        Some(base) => findings.push(
            Finding::new(
                Severity::Warn,
                PROXY_URL_IN_USE,
                format!(
                    "the proxy writes {base} into artifact URLs, but this check reached it at \
                     {proxy}. Lockfiles will record {base}"
                ),
            )
            .with_fix(format!(
                "check which address clients use, and set {} to it",
                env::PROXY_URL
            )),
        ),
        None => findings.push(
            Finding::new(
                Severity::Warn,
                PROXY_URL_IN_USE,
                format!(
                    "the proxy has no {}, so {WITHOUT_PROXY_URL}",
                    env::PROXY_URL
                ),
            )
            .with_fix(format!(
                "set {} on the proxy to a stable name",
                env::PROXY_URL
            )),
        ),
    }

    if !health.rewrite_artifacts {
        findings.push(
            Finding::new(
                Severity::Warn,
                "proxy artifact rewriting",
                "off, so every client except npm fetches artifacts without the proxy \
                 seeing them",
            )
            .with_fix(format!("unset {} on the proxy", env::REWRITE_ARTIFACTS)),
        );
    }
    if !health.refuse_unservable {
        findings.push(Finding::new(
            Severity::Warn,
            "proxy refusal",
            "off, so versions whose artifacts the proxy cannot see are forwarded rather than \
             removed",
        ));
    }
    if health.mode == crate::refusal::Mode::Observe.as_str() {
        findings.push(
            Finding::new(
                Severity::Warn,
                "proxy mode",
                "observe, so what the policy refuses is served and logged",
            )
            .with_fix(format!("unset {} on the proxy", env::MODE)),
        );
    }
    findings.push(tokens_finding(health.tokens_required));
    if !health.allowed_direct_origins.is_empty() {
        findings.push(Finding::new(
            Severity::Warn,
            "proxy allowed origins",
            format!(
                "artifacts on {} are fetched directly and never examined, by configuration",
                health.allowed_direct_origins.join(", ")
            ),
        ));
    }
    findings
}

/// Whether the proxy asks each request for a token, and where a client's is configured.
fn tokens_finding(required: bool) -> Finding {
    if required {
        return Finding::new(
            Severity::Ok,
            PROXY_TOKENS,
            format!(
                "required: a client without one is answered 401. {TOKEN_GUIDE} lists where each \
                 client puts its token"
            ),
        );
    }
    Finding::new(
        Severity::Warn,
        PROXY_TOKENS,
        "not required, so a request is answered without being tied to an account",
    )
    .with_fix(format!("unset {} on the proxy", env::REQUIRE_TOKEN))
}

/// The title of each finding about proxy tokens.
const PROXY_TOKENS: &str = "proxy tokens";

/// Where each client's token configuration is listed.
pub const TOKEN_GUIDE: &str = "docs/quickstart.md §6";

/// The title of every finding about readiness.
const READINESS_TITLE: &str = "proxy readiness";

/// The fix for a snapshot that is missing or cannot match a served ecosystem.
const REFRESH_FIX: &str = "run `byrle refresh` on the proxy's database";

/// A loaded snapshot's finding: ready with no gaps, else not ready, listing each gap.
/// `snapshot` names the snapshot, and the proxy answers 503 for an ecosystem with `gaps`.
fn ready_using(snapshot: String, gaps: &[crate::intel::Gap]) -> Finding {
    if gaps.is_empty() {
        return Finding::new(
            Severity::Ok,
            READINESS_TITLE,
            format!("ready, using {snapshot}"),
        );
    }
    let gaps: Vec<String> = gaps.iter().map(ToString::to_string).collect();
    Finding::new(
        Severity::Problem,
        READINESS_TITLE,
        format!("not ready, using {snapshot}: {}", gaps.join("; ")),
    )
    .with_fix(REFRESH_FIX)
}

/// Whether the proxy can decide on packages now, which a healthy proxy with an empty or
/// down intel store cannot. `readiness` is what [`READY_PATH`] returned, if readable.
pub fn check_readiness(readiness: Option<&Readiness>, proxy: &str) -> Finding {
    let Some(readiness) = readiness else {
        return Finding::new(
            Severity::Warn,
            READINESS_TITLE,
            format!(
                "nothing readable at {proxy}{READY_PATH}. A proxy older than this doctor does \
                 not serve it"
            ),
        )
        .with_fix("upgrade the proxy");
    };
    match readiness.intel {
        IntelState::Loaded => {
            let Some(snapshot) = readiness.snapshot.as_ref() else {
                return Finding::new(Severity::Ok, READINESS_TITLE, "ready");
            };
            let named = format!(
                "intel snapshot {}, taken {}",
                snapshot.digest, snapshot.taken_at
            );
            ready_using(named, &snapshot.gaps())
        }
        IntelState::NotConsulted => Finding::new(
            Severity::Warn,
            READINESS_TITLE,
            "ready, but uses no intel store, so known_malware and max_cvss are not enforced",
        )
        .with_fix(format!(
            "set both {} and {} on the proxy",
            env::POLICY,
            env::DATABASE_URL
        )),
        IntelState::Empty => Finding::new(
            Severity::Problem,
            READINESS_TITLE,
            "not ready: the intel store holds no snapshot, so every package request is \
             answered 503",
        )
        .with_fix(REFRESH_FIX),
        IntelState::Unavailable => Finding::new(
            Severity::Problem,
            READINESS_TITLE,
            "not ready: the intel store cannot answer, so every package request is answered 503",
        )
        .with_fix("the proxy's log gives the cause"),
    }
}

/// Why the proxy's health endpoint gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreached {
    /// Its host does not resolve on this machine, and why.
    Unresolved(String),
    /// Its host resolves, or is an address, and nothing answered there, and why.
    Unanswered(String),
}

/// The problem `title` reports when nothing answered at `proxy`, and the fix for `unreached`.
fn unanswered(title: String, unreached: &Unreached, proxy: &str) -> Finding {
    match unreached {
        Unreached::Unresolved(why) => Finding::new(
            Severity::Problem,
            title,
            format!("nothing answered at {proxy}: {why}"),
        )
        .with_fix(format!(
            "check the host in {}, and the DNS this machine uses",
            env::PROXY_URL
        )),
        Unreached::Unanswered(why) => Finding::new(
            Severity::Problem,
            title,
            format!(
                "nothing answered at {proxy}{}: {why}",
                crate::proxy::HEALTH_PATH
            ),
        )
        .with_fix("start the proxy, or point this at the address clients actually use"),
    }
}

/// Why nothing answered at `proxy`, given the probe's error `why`: whether its host
/// resolves here, and to what. An address is not looked up.
pub async fn unreached(proxy: &str, why: String) -> Unreached {
    let Some((host, port)) = reqwest::Url::parse(proxy)
        .ok()
        .and_then(|url| Some((url.host_str()?.to_owned(), url.port_or_known_default()?)))
        .filter(|(host, _)| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_err()
        })
    else {
        return Unreached::Unanswered(why);
    };
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Err(e) => Unreached::Unresolved(format!("{host} does not resolve on this machine: {e}")),
        Ok(addresses) => {
            let addresses: Vec<String> = addresses.map(|a| a.ip().to_string()).collect();
            Unreached::Unanswered(format!(
                "{host} resolves to {}, and {why}",
                addresses.join(", ")
            ))
        }
    }
}

/// Where the proxy is expected to be reachable: `public`, [`env::PROXY_URL`], which
/// lockfiles record, or else the `listen` address, which may be `0.0.0.0`.
pub fn expected_proxy_url(public: Option<&str>, listen: &str) -> String {
    match public.map(str::trim).filter(|s| !s.is_empty()) {
        Some(url) => url.trim_end_matches('/').to_owned(),
        None => format!("http://{}", listen.trim_end_matches('/')),
    }
}

/// Count the files under a directory, following subdirectories.
///
/// Used for a client cache, where one file is one cached response.
pub fn count_files(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                count_files(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

/// The exit status: anything unresolved means a non-zero exit.
pub fn worst(findings: &[Finding]) -> Severity {
    findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Ok)
}

/// The title of every finding about the policy file.
const POLICY_TITLE: &str = "policy";

/// What `byrle policy check --strict` fails on, for the policy the proxy is configured with.
///
/// `loaded` is the report from [`crate::policy::check::load`], or its refusal as text. A
/// refused policy is a problem, because the proxy does not start with it. An entry that
/// changes nothing or never wins is a warning.
pub fn check_policy(path: &str, loaded: Result<&Report, &str>) -> Vec<Finding> {
    let report = match loaded {
        Ok(report) => report,
        Err(e) => {
            return vec![Finding::new(
                Severity::Problem,
                POLICY_TITLE,
                format!("{path}: {e}. The proxy does not start with it"),
            )];
        }
    };
    let mut findings: Vec<Finding> = report
        .unchanged
        .iter()
        .map(|&index| {
            Finding::new(
                Severity::Warn,
                POLICY_TITLE,
                format!(
                    "{} changes nothing: every value it sets is already the global setting",
                    packages::label(index)
                ),
            )
            .with_fix("delete it")
        })
        .collect();
    findings.extend(report.never_wins().map(|shadowed| {
        Finding::new(
            Severity::Warn,
            POLICY_TITLE,
            format!(
                "{} never wins: {}",
                packages::label(shadowed.index),
                shadowed.cover()
            ),
        )
        .with_fix("delete it")
    }));
    if findings.is_empty() {
        findings.push(Finding::new(
            Severity::Ok,
            POLICY_TITLE,
            format!("{path} loads, and every package entry can take effect"),
        ));
    }
    findings
}

fn same_origin(a: &str, b: &str) -> bool {
    match (
        crate::origin::origin_of_url(a),
        crate::origin::origin_of_url(b),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => a.trim_end_matches('/') == b.trim_end_matches('/'),
    }
}

/// A public registry in a lockfile is a different problem from a stale proxy address, and
/// saying "this is not your proxy" about registry.npmjs.org would be noise. Every origin a
/// row of [`crate::ecosystem::TABLE`] always reaches is one.
fn looks_like_a_registry(origin: &str) -> bool {
    crate::ecosystem::TABLE
        .iter()
        .flat_map(|registry| registry.always_reachable)
        .any(|reachable| crate::origin::origin_of_url(reachable).as_deref() == Some(origin))
}

fn join(origins: &[&String]) -> String {
    origins
        .iter()
        .map(|o| o.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `byrle doctor` prints and exits with.
#[derive(Debug)]
pub struct Checked {
    pub report: String,
    pub code: u8,
}

/// Every check, run against this machine and the proxy the environment names.
///
/// Reads client configuration, runs each client, reads the lockfiles in the working
/// directory and asks the proxy about itself. The report is built rather than printed, so
/// `main` prints it and a test can read it.
pub async fn run(machine: &Machine<'_>) -> Result<Checked, env::EnvError> {
    use std::fmt::Write as _;

    let environment = machine.environment;
    let mut report = String::new();
    let listen = environment.listen()?;
    let public = environment.proxy_url()?;
    let proxy = expected_proxy_url(public.as_deref(), &listen);

    let _ = writeln!(report, "byrle doctor");
    let _ = writeln!(report, "  proxy expected at {proxy}");
    let _ = writeln!(report, "  checking from {}", machine.dir.display());
    report.push('\n');

    let mut findings = proxy_findings(&proxy).await;
    findings.extend(policy_findings(environment).await?);
    findings.extend(registry_findings(machine, &proxy)?);
    findings.extend(lockfile_findings(machine.dir, public.as_deref(), &proxy));
    findings.extend(cache_findings(machine)?);

    for finding in &findings {
        let _ = writeln!(report, "{finding}");
    }
    report.push('\n');

    let code = match worst(&findings) {
        Severity::Ok => {
            let _ = writeln!(report, "Everything checked is pointing at the proxy.");
            0
        }
        Severity::Warn => {
            let _ = writeln!(report, "Installs reach the proxy, with the caveats above.");
            0
        }
        Severity::Problem => {
            let _ = writeln!(
                report,
                "Some installs are not going through the proxy. See above."
            );
            1
        }
    };
    Ok(Checked { report, code })
}

/// Whether the thing at the other end is there at all, and what it says it does.
/// Everything after this reads client configuration, which can be perfect while nothing is
/// listening.
async fn proxy_findings(proxy: &str) -> Vec<Finding> {
    let health: Result<crate::proxy::Health, String> =
        probe::own(proxy, crate::proxy::HEALTH_PATH).await;
    let unreached = match &health {
        Ok(_) => None,
        Err(why) => Some(unreached(proxy, why.clone()).await),
    };
    let mut findings = check_proxy(
        health
            .as_ref()
            .map_err(|_| unreached.as_ref().expect("set when the probe failed")),
        proxy,
    );
    if health.is_ok() {
        let readiness: Option<crate::proxy::Readiness> =
            probe::own(proxy, crate::proxy::READY_PATH).await.ok();
        findings.push(check_readiness(readiness.as_ref(), proxy));
    }
    findings
}

/// The PyPI index form when a cooldown is configured, and the policy the proxy is
/// configured with.
async fn policy_findings(environment: &env::Process) -> Result<Vec<Finding>, env::EnvError> {
    let Some(path) = environment.policy()? else {
        return Ok(Vec::new());
    };
    let mut findings = Vec::new();
    let uses_cooldown = crate::policy::Policy::load(&path)
        .map(|policy| policy.uses_cooldown())
        .unwrap_or(false);
    if uses_cooldown {
        let index = environment
            .upstreams()?
            .get(crate::identity::Ecosystem::PyPI)
            .to_owned();
        let content_type = probe::index_content_type(&index).await;
        findings.push(check_index_format(&index, content_type.as_deref(), true));
    }

    let loaded = crate::policy::check::load(
        &path,
        crate::policy::today(),
        environment.expiry_ceiling_days()?,
    )
    .map(|(_, report)| report)
    .map_err(|e| e.to_string());
    findings.extend(check_policy(
        &path.display().to_string(),
        loaded.as_ref().map_err(String::as_str),
    ));
    Ok(findings)
}

/// The registry and extra indexes each client is configured with.
fn registry_findings(machine: &Machine, proxy: &str) -> Result<Vec<Finding>, env::EnvError> {
    let mut findings = Vec::new();
    for client in clients() {
        match &client.registry {
            None => {}
            Some(RegistrySource::Asked(query)) => findings.push(check_registry(
                client,
                probe::configured_registry(machine, client, query).as_deref(),
                proxy,
            )),
            Some(RegistrySource::Read {
                read, drop_extra, ..
            }) => match read(machine)? {
                None => findings.push(check_registry(client, None, proxy)),
                Some(indexes) => {
                    findings.push(check_registry(client, Some(&indexes.index), proxy));
                    findings.push(check_extra_indexes(
                        client,
                        &indexes.extra,
                        &drop_extra(),
                        proxy,
                    ));
                }
            },
        }
    }
    Ok(findings)
}

/// Lockfiles in `dir` are the record of what actually happened, as opposed to what is
/// configured now. The origins they record are checked against `public`.
fn lockfile_findings(dir: &std::path::Path, public: Option<&str>, proxy: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut recorded = std::collections::BTreeSet::new();
    for (lockfile, pins) in crate::lockfile::pinning() {
        let Ok(contents) = std::fs::read_to_string(dir.join(lockfile.name)) else {
            continue;
        };
        recorded.extend(recorded_origins(pins.key, &contents));
        findings.push(check_lockfile(lockfile, pins, &contents, proxy));
    }
    findings.push(check_proxy_url(public, &recorded));
    findings
}

/// Every client caches, and what a warm cache supplies never reaches the proxy. How much
/// it supplies differs, so each installed client is reported with what was measured for it.
fn cache_findings(machine: &Machine) -> Result<Vec<Finding>, env::EnvError> {
    let mut findings = Vec::new();
    for client in clients() {
        if (machine.run)(client.name, &["--version"]).is_some() {
            let warm = probe::warm_cache(machine, client)?;
            findings.push(check_cache(client, warm.as_deref()));
        }
    }
    Ok(findings)
}

/// Asking an installed client about itself. The one part of `doctor` that runs programs.
pub mod probe {
    use super::{CacheLocation, Client, Machine, RegistryQuery};

    use crate::env::EnvError;
    use std::path::PathBuf;

    /// How long a probe waits. A proxy or index that takes seconds is not working.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

    /// Run `program` with `args` and return what it printed, trimmed, empty included.
    /// `None` when it could not run or failed.
    pub fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
    }

    /// The registry a client is configured to use, asked with `query`.
    ///
    /// Its own resolved configuration, not a file this could read: only the client knows
    /// which of its configuration files set the value.
    pub fn configured_registry(
        machine: &Machine,
        client: &Client,
        query: &RegistryQuery,
    ) -> Option<String> {
        machine
            .ask(client.name, query.args)
            .filter(|value| value != query.unset)
    }

    /// Where a client keeps its cache. `Ok(None)` when the client does not say, or no home
    /// directory is set.
    pub fn cache_dir(machine: &Machine, client: &Client) -> Result<Option<PathBuf>, EnvError> {
        let environment = machine.environment;
        Ok(match client.cache {
            CacheLocation::Asked { args, under } => machine.ask(client.name, args).map(|printed| {
                let dir = PathBuf::from(printed);
                match under {
                    Some(under) => dir.join(under),
                    None => dir,
                }
            }),
            CacheLocation::Configured {
                configured,
                under_home,
            } => match configured(environment)? {
                Some(dir) => Some(dir),
                None => environment.home()?.map(|home| home.join(under_home)),
            },
        })
    }

    /// What the index answers a `HEAD` with, which says which form it serves without
    /// fetching a body. Measured 2026-09-21: pypi.org answers
    /// `application/vnd.pypi.simple.v1+json`, and www.piwheels.org, pypi.nvidia.com and
    /// download.pytorch.org answer `text/html`, to the same request.
    pub async fn index_content_type(index: &str) -> Option<String> {
        let response = reqwest::Client::new()
            .head(index)
            .timeout(TIMEOUT)
            .header(reqwest::header::ACCEPT, crate::ecosystem::pypi::SIMPLE_JSON)
            .send()
            .await
            .ok()?;
        Some(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)?
                .to_str()
                .ok()?
                .to_owned(),
        )
    }

    /// Ask the proxy about itself at `path`, whatever the status, since readiness answers
    /// with its JSON on a 503. Async, because a blocking client's own runtime panics when
    /// dropped inside doctor's. Errors with why nothing answered with the JSON expected.
    pub async fn own<T: serde::de::DeserializeOwned>(proxy: &str, path: &str) -> Result<T, String> {
        let response = reqwest::Client::new()
            .get(format!("{proxy}{path}"))
            .timeout(TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("the request failed: {}", causes(&e)))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("the answer did not arrive: {}", causes(&e)))?;
        serde_json::from_str(&body)
            .map_err(|_| format!("it answered {status}, which is not the proxy's {path}"))
    }

    /// `error` and each error under it, joined, since reqwest's own text stops at the first.
    fn causes(error: &dyn std::error::Error) -> String {
        std::iter::successors(Some(error), |e| e.source())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(": ")
    }

    /// The client's cache when it holds something, `Ok(None)` when it is empty or absent.
    pub fn warm_cache(machine: &Machine, client: &Client) -> Result<Option<PathBuf>, EnvError> {
        Ok(cache_dir(machine, client)?.filter(|dir| dir.is_dir() && super::count_files(dir) > 0))
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    mod tests {
        use super::super::CacheBypass;
        use super::*;
        use crate::env::testing;

        /// This machine, with nothing set in the environment, checking `/`.
        fn here(environment: &crate::env::Process) -> Machine<'_> {
            Machine::this(environment, std::path::Path::new("/"))
        }

        fn echoing(cache: CacheLocation) -> Client {
            Client {
                name: "echo",
                registry: None,
                set_registry: "",
                cache,
                bypass: CacheBypass::Complete,
                clear_cache: "",
            }
        }

        /// A `HEAD` says which form an index serves without fetching its body.
        #[tokio::test]
        async fn an_index_is_asked_which_form_it_serves() {
            use crate::util::test_support::closing_server;
            use axum::Router;
            use axum::routing::any;

            let router = Router::new().fallback(any(|| async {
                (
                    [(reqwest::header::CONTENT_TYPE, "text/html")],
                    "<html></html>",
                )
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port should bind");
            let addr = listener
                .local_addr()
                .expect("a bound listener has an address");
            tokio::spawn(axum::serve(listener, router).into_future());
            assert_eq!(
                index_content_type(&format!("http://{addr}/simple/"))
                    .await
                    .as_deref(),
                Some("text/html")
            );

            let silent = closing_server().await;
            assert_eq!(
                index_content_type(&format!("http://{silent}/simple/")).await,
                None,
                "nothing is listening for this"
            );
        }

        /// An index that names no type, or one that is not text, says nothing about its form.
        #[tokio::test]
        async fn an_index_type_that_cannot_be_read_is_none() {
            use axum::Router;
            use axum::http::HeaderValue;
            use axum::routing::any;

            let router = Router::new()
                .route("/untyped/", any(|| async { axum::http::StatusCode::OK }))
                .route(
                    "/unreadable/",
                    any(|| async {
                        (
                            [(
                                reqwest::header::CONTENT_TYPE,
                                HeaderValue::from_bytes(b"text/\xffhtml").expect("obs-text"),
                            )],
                            "",
                        )
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port should bind");
            let addr = listener
                .local_addr()
                .expect("a bound listener has an address");
            tokio::spawn(axum::serve(listener, router).into_future());
            assert_eq!(
                index_content_type(&format!("http://{addr}/untyped/")).await,
                None
            );
            assert_eq!(
                index_content_type(&format!("http://{addr}/unreadable/")).await,
                None
            );
        }

        /// The proxy's own JSON, or why nothing there answered with it.
        #[tokio::test]
        async fn the_proxy_is_asked_about_itself() {
            use crate::util::test_support::{Answer, closing_server, scripted};
            let ask = |addr: std::net::SocketAddr| async move {
                own::<serde_json::Value>(&format!("http://{addr}"), "/-/byrle/ready").await
            };

            let serving = scripted(vec![Answer::body(r#"{"ready":true}"#)]).await;
            assert_eq!(ask(serving).await, Ok(serde_json::json!({"ready": true})));
            let not_json = ask(scripted(vec![Answer::body("not json")]).await).await;
            assert_eq!(
                not_json,
                Err("it answered 200 OK, which is not the proxy's /-/byrle/ready".to_owned()),
                "anything that is not a byrle"
            );
            let short = ask(scripted(vec![Answer::cut_short()]).await)
                .await
                .unwrap_err();
            assert!(short.starts_with("the answer did not arrive"), "{short}");
            let nothing = ask(closing_server().await).await.unwrap_err();
            assert!(nothing.starts_with("the request failed"), "{nothing}");
            assert!(
                nothing.ends_with("connection closed before message completed"),
                "the cause reqwest's own text leaves out: {nothing}"
            );
        }

        #[test]
        fn a_program_is_asked_for_what_it_prints() {
            let empty = testing::empty();
            let machine = here(&empty);
            assert_eq!(
                machine.ask("echo", &["  printed  "]).as_deref(),
                Some("printed")
            );
            assert_eq!(machine.ask("echo", &[""]), None, "printed nothing");
            assert_eq!(machine.ask("false", &[]), None, "failed");
            assert_eq!(
                machine.ask("byrle-no-such-program", &[]),
                None,
                "not installed"
            );
            assert_eq!(machine.ask("printf", &["\\377"]), None, "not UTF-8");
        }

        #[test]
        fn an_undefined_registry_is_no_registry() {
            let client = echoing(CacheLocation::Asked {
                args: &[],
                under: None,
            });
            let query = |args| RegistryQuery {
                args,
                unset: "undefined",
            };
            let empty = testing::empty();
            let machine = here(&empty);
            assert_eq!(
                configured_registry(&machine, &client, &query(&["undefined"])),
                None
            );
            assert_eq!(
                configured_registry(&machine, &client, &query(&["http://proxy/"])).as_deref(),
                Some("http://proxy/")
            );
        }

        #[test]
        fn an_asked_cache_is_what_the_client_prints_joined_with_under() {
            let under = echoing(CacheLocation::Asked {
                args: &["/c"],
                under: Some("_cacache"),
            });
            assert_eq!(
                cache_dir(&here(&testing::empty()), &under).unwrap(),
                Some(PathBuf::from("/c/_cacache"))
            );
            let bare = echoing(CacheLocation::Asked {
                args: &["/c"],
                under: None,
            });
            assert_eq!(
                cache_dir(&here(&testing::empty()), &bare).unwrap(),
                Some(PathBuf::from("/c"))
            );
        }

        #[test]
        fn a_cache_is_warm_only_when_it_holds_a_file() {
            let dir = crate::util::test_support::tempdir("doctor-warm-cache");
            let path: &'static str = Box::leak(dir.display().to_string().into_boxed_str());
            let args: &'static [&'static str] = Box::leak(Box::new([path]));
            let client = echoing(CacheLocation::Asked { args, under: None });
            assert_eq!(warm_cache(&here(&testing::empty()), &client).unwrap(), None);
            std::fs::write(dir.join("entry"), b"x").expect("writes");
            assert_eq!(
                warm_cache(&here(&testing::empty()), &client).unwrap(),
                Some(dir.clone())
            );
            let absent = echoing(CacheLocation::Asked {
                args: &["/nonexistent/byrle-cache"],
                under: None,
            });
            assert_eq!(warm_cache(&here(&testing::empty()), &absent).unwrap(), None);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// bun's cache is its variable when set, else under the home directory.
        #[test]
        fn a_configured_cache_is_the_variable_then_the_home_directory() {
            let bun = crate::ecosystem::npm::clients::named("bun");
            let set = testing::bun_cache_and_home();
            assert_eq!(
                cache_dir(&here(&set), bun).unwrap(),
                Some(PathBuf::from("/bun"))
            );
            let home = testing::home_only();
            assert_eq!(
                cache_dir(&here(&home), bun).unwrap(),
                Some(PathBuf::from("/home/u/.bun/install/cache"))
            );
            assert_eq!(cache_dir(&here(&testing::empty()), bun).unwrap(), None);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Which form the index serves is reported, because a PEP 503 page carries no publish time.
    #[test]
    fn the_index_form_says_what_a_cooldown_can_be_answered_from() {
        use super::{Severity, check_index_format};
        let json = check_index_format(
            "https://pypi.org/simple/",
            Some(crate::ecosystem::pypi::SIMPLE_JSON),
            true,
        );
        assert_eq!(json.severity, Severity::Ok);
        assert!(json.detail.contains("PEP 691 JSON"), "{}", json.detail);

        let html = check_index_format("https://www.piwheels.org/simple/", Some("text/html"), true);
        assert_eq!(html.severity, Severity::Warn);
        assert!(
            html.detail.contains("answered on the artifact request"),
            "{}",
            html.detail
        );

        let quiet =
            check_index_format("https://www.piwheels.org/simple/", Some("text/html"), false);
        assert_eq!(quiet.severity, Severity::Ok);

        let silent = check_index_format("https://example.test/simple/", None, true);
        assert_eq!(silent.severity, Severity::Warn);
        assert!(silent.detail.contains("did not say"), "{}", silent.detail);

        let credential = check_index_format(
            "https://user:secret@example.test/simple/",
            Some("text/html"),
            true,
        );
        assert!(
            !credential.detail.contains("secret"),
            "{}",
            credential.detail
        );
    }
    use crate::ecosystem::npm::clients::named;

    fn lockfile(name: &str) -> &'static Lockfile {
        crate::lockfile::pinning()
            .find(|(lockfile, _)| lockfile.name == name)
            .map(|(lockfile, _)| lockfile)
            .expect("this lockfile records artifact URLs")
    }

    fn pins(name: &str) -> &'static Pins {
        crate::lockfile::pinning()
            .find(|(lockfile, _)| lockfile.name == name)
            .map(|(_, pins)| pins)
            .expect("this lockfile records artifact URLs")
    }
    use std::path::Path;

    const PROXY: &str = "http://127.0.0.1:8080";

    fn origins(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn policy_report(source: &str, as_of: jiff::civil::Date) -> Report {
        let policy = crate::policy::Policy::parse(source).expect("policy should load");
        Report::of(&policy, as_of)
    }

    #[test]
    fn a_policy_entry_that_does_nothing_is_a_warning() {
        let report = policy_report(
            include_str!("../tests/fixtures/policy-check/dead.yaml"),
            jiff::civil::date(2026, 9, 13),
        );
        let found = check_policy("dead.yaml", Ok(&report));
        let details: Vec<&str> = found.iter().map(|f| f.detail.as_str()).collect();
        assert_eq!(
            details,
            [
                "packages[6] changes nothing: every value it sets is already the global setting",
                "packages[0] never wins: packages[1] and packages[2] match every package it does",
            ]
        );
        assert!(found.iter().all(|f| f.severity == Severity::Warn));
    }

    #[test]
    fn a_policy_the_proxy_refuses_is_a_problem() {
        let found = check_policy("p.yaml", Err("policy is not valid: x"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Problem);
        assert_eq!(
            found[0].detail,
            "p.yaml: policy is not valid: x. The proxy does not start with it"
        );
    }

    #[test]
    fn a_policy_whose_entries_all_take_effect_is_ok() {
        let report = policy_report(
            include_str!("../examples/policy.yaml"),
            jiff::civil::date(2026, 9, 1),
        );
        let found = check_policy("policy.yaml", Ok(&report));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Ok);
    }

    #[test]
    fn a_client_pointed_at_the_proxy_is_ok() {
        assert_eq!(
            check_registry(named("npm"), Some(PROXY), PROXY).severity,
            Severity::Ok
        );
        assert_eq!(
            check_registry(named("npm"), Some("http://127.0.0.1:8080/"), PROXY).severity,
            Severity::Ok,
            "a trailing slash is the same registry"
        );
    }

    /// The bypass the README calls advisory: a developer who resets the registry URL.
    #[test]
    fn a_client_pointed_elsewhere_is_a_problem_with_a_fix() {
        let finding = check_registry(named("npm"), Some("https://registry.npmjs.org"), PROXY);
        assert_eq!(finding.severity, Severity::Problem);
        assert!(finding.detail.contains("registry.npmjs.org"));
        assert_eq!(
            finding.fix.as_deref(),
            Some("npm config set registry http://127.0.0.1:8080")
        );
    }

    #[test]
    fn a_client_that_is_not_installed_is_not_a_problem() {
        let finding = check_registry(named("yarn"), None, PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("not installed"));
    }

    /// npm and yarn record the absolute artifact URL, so the lockfile is evidence.
    #[test]
    fn npm_and_yarn_lockfiles_record_where_artifacts_came_from() {
        let npm = r#"{"packages":{"node_modules/lodash":{
            "resolved":"http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz"}}}"#;
        assert_eq!(
            recorded_origins(pins("package-lock.json").key, npm),
            origins(&["http://127.0.0.1:8080"])
        );

        let yarn = r#"lodash@^4.17.21:
  version "4.17.21"
  resolved "http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz#abc123"
  integrity sha512-AAAA"#;
        assert_eq!(
            recorded_origins(pins("yarn.lock").key, yarn),
            origins(&["http://127.0.0.1:8080"])
        );
    }

    /// pnpm omits the URL when it matches the configured registry, so there is nothing to
    /// read and nothing is wrong.
    #[test]
    fn a_pnpm_lockfile_without_tarball_urls_is_not_a_fault() {
        let pnpm = "  lodash@4.17.21:\n    resolution: {integrity: sha512-AAAA}\n";
        assert!(recorded_origins(pins("pnpm-lock.yaml").key, pnpm).is_empty());

        let finding = check_lockfile(
            lockfile("pnpm-lock.yaml"),
            pins("pnpm-lock.yaml"),
            pnpm,
            PROXY,
        );
        assert_eq!(finding.severity, Severity::Ok);
        assert!(
            finding.detail.contains("portable"),
            "got: {}",
            finding.detail
        );
    }

    /// bun 1.4.2 writes the URL for any registry but registry.npmjs.org, where it writes `""`.
    #[test]
    fn a_bun_lockfile_records_the_registry_unless_it_is_npmjs() {
        let through_proxy = r#"    "ms": ["ms@2.1.3", "http://127.0.0.1:8080/ms/-/ms-2.1.3.tgz", {}, "sha512-AAAA"],"#;
        assert_eq!(
            recorded_origins(pins("bun.lock").key, through_proxy),
            origins(&["http://127.0.0.1:8080"])
        );
        let named_http = r#"    "httpie": ["httpie@1.0.0", "http://127.0.0.1:8080/httpie/-/httpie-1.0.0.tgz", {}, "sha512-AAAA"],"#;
        assert_eq!(
            recorded_origins(pins("bun.lock").key, named_http),
            origins(&["http://127.0.0.1:8080"]),
            "a name starting with http does not hide the URL after it"
        );

        let from_npmjs = bun_lock(r#"    "ms": ["ms@2.1.3", "", {}, "sha512-AAAA"],"#);
        let finding = check_lockfile(lockfile("bun.lock"), pins("bun.lock"), &from_npmjs, PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("not"), "got: {}", finding.detail);
        assert!(finding.fix.is_some(), "a reinstall is suggested");

        let nothing_locked = bun_lock("");
        let finding = check_lockfile(
            lockfile("bun.lock"),
            pins("bun.lock"),
            &nothing_locked,
            PROXY,
        );
        assert_eq!(
            finding.severity,
            Severity::Ok,
            "a bun.lock that locks no package says nothing about the registry"
        );
    }

    /// A text `bun.lock` as bun 1.4.2 writes it, holding `packages`.
    fn bun_lock(packages: &str) -> String {
        format!(
            "{{\n  \"lockfileVersion\": 2,\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"t\",\n    }},\n  }},\n  \"packages\": {{\n{packages}\n  }}\n}}\n"
        )
    }

    #[test]
    fn a_pnpm_lockfile_with_tarball_urls_is_read() {
        let pnpm = "    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/a/-/a-1.0.0.tgz}\n";
        assert_eq!(
            recorded_origins(pins("pnpm-lock.yaml").key, pnpm),
            origins(&["https://registry.npmjs.org"])
        );
    }

    #[test]
    fn a_lockfile_pinned_to_the_proxy_is_evidence_it_was_used() {
        let npm = r#"{"packages":{"a":{"resolved":"http://127.0.0.1:8080/a/-/a-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(
            lockfile("package-lock.json"),
            pins("package-lock.json"),
            npm,
            PROXY,
        );
        assert_eq!(finding.severity, Severity::Ok);
        assert!(finding.detail.contains("through the proxy"));
    }

    #[test]
    fn a_lockfile_pinned_elsewhere_says_so() {
        let npm = r#"{"packages":{"a":{"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(
            lockfile("package-lock.json"),
            pins("package-lock.json"),
            npm,
            PROXY,
        );
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.fix.is_some());
    }

    /// An address with no origin, such as a listen address written without a scheme, is
    /// compared as written.
    #[test]
    fn an_address_with_no_origin_is_compared_as_written() {
        let npm = r#"{"packages":{"a":{"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(
            lockfile("package-lock.json"),
            pins("package-lock.json"),
            npm,
            "127.0.0.1:8080",
        );
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(
            finding.detail,
            "artifacts are pinned to https://registry.npmjs.org, so this was not installed \
             through the proxy"
        );

        let public = check_proxy_url(Some("proxy.internal"), &BTreeSet::new());
        assert_eq!(public.severity, Severity::Ok);
        assert_eq!(public.detail, "proxy.internal");

        assert!(same_origin("proxy.internal/", "proxy.internal"));
        assert!(!same_origin("http://proxy.internal", "proxy.internal"));
    }

    /// A lockfile naming two places installs from both, and only one is examined. That is
    /// worse than one that names neither.
    #[test]
    fn a_split_lockfile_is_a_problem() {
        let npm = r#"{"packages":{
            "a":{"resolved":"http://127.0.0.1:8080/a/-/a-1.0.0.tgz"},
            "b":{"resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(
            lockfile("package-lock.json"),
            pins("package-lock.json"),
            npm,
            PROXY,
        );
        assert_eq!(finding.severity, Severity::Problem);
        assert!(finding.detail.contains("part of this install"));
    }

    /// Measured: `npm ci` fetches the address in the lockfile and does not fall back, so
    /// an address that stops answering fails the build.
    #[test]
    fn a_lockfile_pinned_to_another_proxy_address_is_a_problem() {
        let finding = check_proxy_url(
            Some("http://npm.corp.example"),
            &origins(&["http://127.0.0.1:8080"]),
        );
        assert_eq!(finding.severity, Severity::Problem);
        assert!(finding.detail.contains("does not fall back"));
    }

    /// A public registry in a lockfile is the client-config problem, reported elsewhere.
    /// Calling it a stale proxy address here would be noise.
    #[test]
    fn the_public_registry_is_not_reported_as_a_stale_address() {
        let finding = check_proxy_url(
            Some("http://npm.corp.example"),
            &origins(&["https://registry.npmjs.org", "http://npm.corp.example"]),
        );
        assert_eq!(finding.severity, Severity::Ok);
    }

    #[test]
    fn an_unpinned_proxy_url_is_a_warning_with_the_reason() {
        let finding = check_proxy_url(None, &BTreeSet::new());
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("whatever Host"));
        assert!(finding.fix.is_some());
    }

    /// A warm cache is reported as skipping the proxy, per client.
    #[test]
    fn a_warm_cache_is_reported_as_skipping_the_proxy() {
        assert_eq!(check_cache(named("npm"), None).severity, Severity::Ok);

        let path = Path::new("/home/someone/.npm/_cacache");
        let finding = check_cache(named("npm"), Some(path));
        assert_eq!(finding.severity, Severity::Warn);
        assert!(
            finding.detail.contains("never reach the proxy"),
            "{}",
            finding.detail
        );
        assert!(
            finding.detail.contains("/home/someone/.npm/_cacache"),
            "the location is what an operator acts on: {}",
            finding.detail
        );
        assert_eq!(finding.fix.as_deref(), Some("npm cache clean --force"));
    }

    /// yarn re-fetches the packument and serves the artifact locally, which is a
    /// different exposure from npm's and is described as such.
    #[test]
    fn a_partial_bypass_says_what_it_still_fetches() {
        let finding = check_cache(named("yarn"), Some(Path::new("/tmp/yarn")));
        assert_eq!(finding.severity, Severity::Warn);
        assert!(
            finding.detail.contains("still fetches metadata"),
            "{}",
            finding.detail
        );
        assert!(
            finding.detail.contains("never examined"),
            "{}",
            finding.detail
        );
    }

    /// `npm cache clean` is not the command for every client.
    #[test]
    fn each_client_gets_its_own_way_to_clear_the_cache() {
        assert_eq!(
            check_cache(named("bun"), Some(Path::new("/tmp/b")))
                .fix
                .as_deref(),
            Some("bun pm cache rm")
        );
        assert!(
            check_cache(named("pnpm"), Some(Path::new("/tmp/p")))
                .fix
                .as_deref()
                .is_some_and(|f| f.contains("pnpm store prune"))
        );
        assert_eq!(
            check_cache(named("yarn"), Some(Path::new("/tmp/y")))
                .fix
                .as_deref(),
            Some("yarn cache clean --force")
        );
    }

    #[test]
    fn the_exit_status_is_the_worst_finding() {
        assert_eq!(worst(&[]), Severity::Ok);
        assert_eq!(
            worst(&[
                Finding::new(Severity::Ok, "a", "a"),
                Finding::new(Severity::Warn, "b", "b"),
            ]),
            Severity::Warn
        );
        assert_eq!(
            worst(&[
                Finding::new(Severity::Warn, "a", "a"),
                Finding::new(Severity::Problem, "b", "b"),
            ]),
            Severity::Problem
        );
    }

    #[test]
    fn a_finding_prints_its_severity_and_its_fix() {
        let finding = Finding::new(Severity::Problem, "npm registry", "points elsewhere")
            .with_fix("npm config set registry ...");
        let text = finding.to_string();
        assert!(text.contains("PROBLEM"), "got: {text}");
        assert!(
            text.contains("npm registry: points elsewhere"),
            "got: {text}"
        );
        assert!(
            text.contains("fix: npm config set registry ..."),
            "got: {text}"
        );
        assert!(
            !Finding::new(Severity::Ok, "a", "b")
                .to_string()
                .contains("fix:"),
            "no fix line when there is nothing to do"
        );
    }

    /// Junk must not produce phantom findings.
    #[test]
    fn unreadable_lockfiles_yield_nothing() {
        for (lockfile, pins) in crate::lockfile::pinning() {
            assert!(recorded_origins(pins.key, "").is_empty());
            assert!(recorded_origins(pins.key, "not a lockfile at all").is_empty());
            assert!(
                recorded_origins(pins.key, "resolved tarball not-a-url").is_empty(),
                "{}",
                lockfile.name
            );
            assert!(
                recorded_origins(pins.key, &format!("{} http://", pins.key)).is_empty(),
                "a URL with no host: {}",
                lockfile.name
            );
        }
    }

    fn health() -> crate::proxy::Health {
        crate::proxy::Health {
            service: "byrle".into(),
            version: "0.1.0".into(),
            upstreams: [
                ("npm".to_owned(), "https://registry.npmjs.org".to_owned()),
                ("pypi".to_owned(), "https://pypi.org/simple".to_owned()),
            ]
            .into(),
            public_base: Some(PROXY.into()),
            rewrite_artifacts: true,
            refuse_unservable: true,
            mode: "enforce".into(),
            tokens_required: true,
            served_origins: vec!["https://registry.npmjs.org".into()],
            allowed_direct_origins: vec![],
            packages_held: 0,
            records_held: 0,
            artifacts_verified: 0,
            spool_dir: None,
            artifacts_revalidated: 0,
            artifacts_with_direct_dependencies: 0,
            documents_uninspected: 0,
            clients_without_artifacts: Default::default(),
            decisions_unrecorded: 0,
        }
    }

    /// A host that does not resolve is said to, with a fix naming the proxy URL; an address
    /// and a URL with no host give the probe's own reason.
    #[tokio::test]
    async fn an_unanswered_proxy_says_whether_its_host_resolves() {
        let unresolved = unreached("http://proxy.invalid:8080", "why".to_owned()).await;
        assert!(
            matches!(&unresolved, Unreached::Unresolved(why) if why.starts_with("proxy.invalid does not resolve on this machine")),
            "{unresolved:?}"
        );
        let finding = &check_proxy(Err(&unresolved), "http://proxy.invalid:8080")[0];
        assert_eq!(finding.severity, Severity::Problem);
        assert!(
            finding
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains(env::PROXY_URL.name)),
            "{finding:?}"
        );
        assert_eq!(
            unreached("http://localhost:1", "refused".to_owned()).await,
            Unreached::Unanswered(format!(
                "localhost resolves to {}, and refused",
                tokio::net::lookup_host(("localhost", 1))
                    .await
                    .expect("localhost resolves")
                    .map(|a| a.ip().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        );
        for address in ["http://127.0.0.1:1", "http://[::1]:1"] {
            assert_eq!(
                unreached(address, "refused".to_owned()).await,
                Unreached::Unanswered("refused".to_owned()),
                "{address} is not looked up"
            );
        }
        for no_host_or_port in ["not a url", "data:text/plain,x", "proxy://proxy.invalid"] {
            assert_eq!(
                unreached(no_host_or_port, "why".to_owned()).await,
                Unreached::Unanswered("why".to_owned()),
                "{no_host_or_port}"
            );
        }
    }

    /// Every other check reads what a client is configured to do. This one asks whether
    /// the thing at the other end exists.
    #[test]
    fn a_proxy_that_does_not_answer_is_a_problem() {
        let findings = check_proxy(Err(&Unreached::Unanswered("refused".to_owned())), PROXY);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Problem);
        assert_eq!(
            findings[0].detail,
            format!("nothing answered at {PROXY}/-/byrle/health: refused")
        );
        assert_eq!(
            findings[0].fix.as_deref(),
            Some("start the proxy, or point this at the address clients actually use")
        );
    }

    const MATCH: (&str, &str) = ("match", "originate a finding for it");
    const MALWARE: (&str, &str) = ("malware", "report malware for it");

    /// How one gap reads in a finding.
    fn gap(ecosystem: &str, (capability, effect): (&str, &str)) -> String {
        format!(
            "`{ecosystem}` is served with no stream providing {capability}, so a policy \
             answers 503 for its packages. Nothing can {effect}"
        )
    }

    fn readiness(intel: IntelState) -> Readiness {
        Readiness {
            ready: matches!(intel, IntelState::Loaded | IntelState::NotConsulted),
            gaps: Vec::new(),
            intel,
            snapshot: (intel == IntelState::Loaded).then(|| crate::intel::store::LoadedSnapshot {
                digest: "sha256:ab".into(),
                taken_at: "2026-09-13T01:02:03Z".into(),
                sources: ["cisa/kev", "osv"].map(str::to_owned).to_vec(),
                streams: std::iter::once("cisa/kev")
                    .chain(
                        crate::ecosystem::TABLE
                            .iter()
                            .flat_map(|registry| registry.streams.iter().map(|s| s.stream)),
                    )
                    .map(|stream| crate::intel::refresh::StreamDigest {
                        stream: stream.to_owned(),
                        sha256: "aa".to_owned(),
                        etag: None,
                        last_modified: None,
                    })
                    .collect(),
                unconfigured: Vec::new(),
            }),
        }
    }

    /// A snapshot with no stream an ecosystem needs leaves the proxy not ready.
    #[test]
    fn a_snapshot_with_a_gap_is_not_ready() {
        let mut ready = readiness(IntelState::Loaded);
        ready
            .snapshot
            .as_mut()
            .expect("a loaded snapshot")
            .streams
            .retain(|s| s.stream == "cisa/kev");
        let finding = check_readiness(Some(&ready), PROXY);
        assert_eq!(finding.severity, Severity::Problem);
        assert!(
            finding.detail.starts_with(&format!(
                "not ready, using intel snapshot sha256:ab, taken 2026-09-13T01:02:03Z: {}; {}; \
                 {}; {}; ",
                gap("npm", MATCH),
                gap("pypi", MATCH),
                gap("npm", MALWARE),
                gap("pypi", MALWARE),
            )),
            "{}",
            finding.detail
        );
        assert!(
            finding.detail.contains("`npm` lists `osv/npm`"),
            "a missing stream is named: {}",
            finding.detail
        );
        assert!(finding.fix.is_some());

        ready.snapshot = None;
        assert_eq!(
            check_readiness(Some(&ready), PROXY).detail,
            "ready",
            "a readiness answer without its snapshot"
        );
    }

    /// Answering its health request is not the same as serving packages.
    #[test]
    fn a_proxy_whose_intel_store_cannot_decide_is_a_problem_with_a_fix() {
        for (intel, cause) in [
            (IntelState::Empty, "holds no snapshot"),
            (IntelState::Unavailable, "cannot answer"),
        ] {
            let finding = check_readiness(Some(&readiness(intel)), PROXY);
            assert_eq!(finding.severity, Severity::Problem, "{intel:?}");
            assert!(
                finding.detail.contains(cause) && finding.detail.contains("503"),
                "{finding}"
            );
            assert!(finding.fix.is_some(), "{intel:?}");
        }
    }

    #[test]
    fn a_snapshot_with_no_gaps_is_ok() {
        let finding = ready_using("intel snapshot s1".to_owned(), &[]);
        assert_eq!(finding.severity, Severity::Ok);
        assert_eq!(finding.detail, "ready, using intel snapshot s1");
        assert!(finding.fix.is_none());
    }

    /// A snapshot holding every listed stream reports the snapshot it uses.
    #[test]
    fn a_ready_proxy_reports_the_snapshot_it_uses() {
        let finding = check_readiness(Some(&readiness(IntelState::Loaded)), PROXY);
        assert_eq!(finding.severity, Severity::Ok);
        assert_eq!(
            finding.detail,
            "ready, using intel snapshot sha256:ab, taken 2026-09-13T01:02:03Z"
        );
    }

    #[test]
    fn a_proxy_that_uses_no_intel_store_warns_that_intel_checks_are_off() {
        let finding = check_readiness(Some(&readiness(IntelState::NotConsulted)), PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("known_malware"), "{finding}");
        assert!(finding.fix.is_some());
    }

    #[test]
    fn a_proxy_without_the_readiness_endpoint_warns() {
        let finding = check_readiness(None, PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains(READY_PATH), "{finding}");
    }

    #[test]
    fn a_healthy_proxy_reports_what_it_forwards_to() {
        let findings = check_proxy(Ok(&health()), PROXY);
        assert_eq!(worst(&findings), Severity::Ok);
        assert!(findings[0].detail.contains("byrle 0.1.0"));
        assert!(
            findings[0].detail.contains(
                "forwarding to npm=https://registry.npmjs.org pypi=https://pypi.org/simple"
            )
        );
    }

    /// The address the proxy writes into artifact URLs is what lockfiles record, so a
    /// mismatch with the address clients actually use is worth saying out loud.
    #[test]
    fn a_proxy_answering_at_a_different_address_than_it_advertises_warns() {
        let mut h = health();
        h.public_base = Some("https://npm.corp.example".into());
        let findings = check_proxy(Ok(&h), PROXY);
        assert_eq!(worst(&findings), Severity::Warn);
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("npm.corp.example")),
            "{findings:?}"
        );

        h.public_base = None;
        assert!(
            check_proxy(Ok(&h), PROXY)
                .iter()
                .any(|f| f.detail.contains("whatever Host")),
        );
    }

    /// Settings that decide what gets examined are reported, because a proxy that is
    /// running and not looking is the failure this whole command exists to surface.
    #[test]
    fn settings_that_reduce_what_is_examined_are_reported() {
        let mut h = health();
        h.rewrite_artifacts = false;
        h.refuse_unservable = false;
        h.mode = "observe".into();
        h.tokens_required = false;
        h.allowed_direct_origins = vec!["https://cdn.example".into()];

        let findings = check_proxy(Ok(&h), PROXY);
        assert_eq!(worst(&findings), Severity::Warn);
        let text: String = findings.iter().map(|f| f.detail.clone()).collect();
        assert!(text.contains("every client except npm"), "{text}");
        assert!(text.contains("rather than removed"), "{text}");
        assert!(text.contains("served and logged"), "{text}");
        assert!(text.contains("tied to an account"), "{text}");
        assert!(
            check_proxy(Ok(&health()), PROXY)
                .iter()
                .any(|f| f.detail.contains(TOKEN_GUIDE))
        );
        assert!(text.contains("cdn.example"), "{text}");
    }

    #[test]
    fn the_expected_proxy_url_prefers_the_configured_public_one() {
        assert_eq!(
            expected_proxy_url(Some("https://npm.corp.example/"), "0.0.0.0:8080"),
            "https://npm.corp.example"
        );
        assert_eq!(
            expected_proxy_url(None, "127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            expected_proxy_url(Some("  "), "127.0.0.1:8080"),
            "http://127.0.0.1:8080",
            "a blank value is not a configured address"
        );
    }

    #[test]
    fn counting_files_follows_subdirectories() {
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/target/tmp"))
            .join(format!("doctor-{}", std::process::id()));
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(root.join("one"), b"x").unwrap();
        std::fs::write(nested.join("two"), b"x").unwrap();
        std::fs::write(nested.join("three"), b"x").unwrap();

        assert_eq!(count_files(&root), 3);
        assert_eq!(
            count_files(&root.join("missing")),
            0,
            "a directory that is not there holds nothing"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The lockfiles that record artifact URLs, each with the text before its URLs.
    #[test]
    fn the_checked_lockfiles_are_those_that_record_artifact_urls() {
        let checked: Vec<(&str, &str)> = crate::lockfile::pinning()
            .map(|(lockfile, pins)| (lockfile.name, pins.key))
            .collect();
        assert_eq!(
            checked,
            [
                ("package-lock.json", "resolved"),
                ("npm-shrinkwrap.json", "resolved"),
                ("yarn.lock", "resolved"),
                ("pnpm-lock.yaml", "tarball"),
                ("bun.lock", "\": ["),
                ("uv.lock", "url"),
            ]
        );
    }

    /// Registry checks run for npm, pnpm and yarn; bun's registry is not asked.
    #[test]
    fn each_client_is_listed_once_and_bun_is_not_asked_its_registry() {
        let names: Vec<(&str, bool)> = clients()
            .map(|client| (client.name, client.registry.is_some()))
            .collect();
        assert_eq!(
            names,
            [
                ("npm", true),
                ("pnpm", true),
                ("yarn", true),
                ("bun", false),
                ("pip", true),
                ("uv", true)
            ]
        );
    }

    /// pip and uv are told how to point at the proxy's index, `/simple` included, and a
    /// credential in the URL they use now is not printed.
    #[test]
    fn a_misdirected_pypi_client_is_told_the_index_and_no_credential_is_printed() {
        use crate::ecosystem::pypi::clients::{PIP, UV};
        let finding = check_registry(
            &PIP,
            Some("https://user:secret@example.jfrog.io/simple/"),
            PROXY,
        );
        assert_eq!(finding.severity, Severity::Problem);
        assert!(!finding.detail.contains("secret"), "{}", finding.detail);
        assert!(finding.detail.contains("https://example.jfrog.io/simple/"));
        assert_eq!(
            finding.fix.as_deref(),
            Some("pip config set global.index-url http://127.0.0.1:8080/simple")
        );
        let finding = check_registry(&UV, Some("https://pypi.org/simple"), PROXY);
        assert!(
            finding
                .fix
                .as_deref()
                .is_some_and(|fix| fix
                    .contains("to http://127.0.0.1:8080/simple, or `index-url` in uv.toml")),
            "{finding}"
        );
        assert_eq!(
            check_registry(&PIP, Some("http://127.0.0.1:8080/simple/"), PROXY).severity,
            Severity::Ok
        );
    }

    /// An extra index serves files the proxy never sees. One on the proxy's own origin is
    /// not extra.
    #[test]
    fn an_extra_index_elsewhere_is_a_problem_and_its_credential_is_not_printed() {
        use crate::ecosystem::pypi::clients::PIP;
        let none = check_extra_indexes(&PIP, &[], "drop it", PROXY);
        assert_eq!(
            (none.severity, none.detail.as_str()),
            (Severity::Ok, "none")
        );
        let own = check_extra_indexes(&PIP, &[format!("{PROXY}/simple/")], "drop it", PROXY);
        assert_eq!(own.severity, Severity::Ok);
        let elsewhere = check_extra_indexes(
            &PIP,
            &["https://user:secret@example.jfrog.io/api/pypi/simple/".to_owned()],
            "drop it",
            PROXY,
        );
        assert_eq!(elsewhere.severity, Severity::Problem);
        assert_eq!(
            elsewhere.detail,
            "also asks https://example.jfrog.io/api/pypi/simple/, whose files never reach the proxy"
        );
        assert_eq!(elsewhere.fix.as_deref(), Some("drop it"));
        let drop_extra = |client: &Client| match &client.registry {
            Some(RegistrySource::Read { drop_extra, .. }) => Some(drop_extra()),
            _ => None,
        };
        assert!(
            drop_extra(&PIP)
                .expect("pip is read")
                .starts_with("pip config unset global.extra-index-url")
        );
        assert_eq!(drop_extra(named("npm")), None, "npm is asked");
    }

    /// pip asks the index and the files again with a warm cache, measured 2026-09-19.
    #[test]
    fn a_cache_that_still_asks_the_proxy_is_not_a_warning() {
        use crate::ecosystem::pypi::clients::{PIP, UV};
        let dir = std::path::Path::new("/c");
        assert_eq!(check_cache(&PIP, Some(dir)).severity, Severity::Ok);
        assert_eq!(check_cache(&UV, Some(dir)).severity, Severity::Warn);
    }

    /// The fix names the client's own command.
    #[test]
    fn a_misdirected_client_is_told_its_own_command() {
        let finding = check_registry(named("pnpm"), Some("https://registry.npmjs.org"), PROXY);
        assert_eq!(
            finding.fix.as_deref(),
            Some("pnpm config set registry http://127.0.0.1:8080")
        );
    }

    /// Every origin a row always reaches is a registry, whichever ecosystem it serves.
    #[test]
    fn every_always_reachable_origin_is_a_registry() {
        assert!(looks_like_a_registry("https://registry.npmjs.org"));
        assert!(looks_like_a_registry("https://pypi.org"));
        assert!(looks_like_a_registry("https://files.pythonhosted.org"));
        assert!(!looks_like_a_registry("http://127.0.0.1:8080"));
    }

    /// A fake proxy whose health names `public` as its public URL, whose readiness is
    /// `ready`, and which answers anything else as a PEP 503 index. Returns its URL.
    async fn fake_proxy(public: bool, ready: Readiness) -> String {
        use axum::Router;
        use axum::routing::{any, get};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port should bind");
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("a bound listener has an address")
        );
        let mut health = health();
        health.public_base = public.then(|| url.clone());
        let router = Router::new()
            .route(
                crate::proxy::HEALTH_PATH,
                get(move || {
                    let health = health.clone();
                    async move { axum::Json(health) }
                }),
            )
            .route(
                READY_PATH,
                get(move || {
                    let ready = ready.clone();
                    async move { axum::Json(ready) }
                }),
            )
            .fallback(any(|| async {
                ([(reqwest::header::CONTENT_TYPE, "text/html")], "")
            }));
        tokio::spawn(axum::serve(listener, router).into_future());
        url
    }

    /// Every program is missing.
    fn nothing_installed(_: &str, _: &[&str]) -> Option<String> {
        None
    }

    /// `doctor` run from `dir` with `environment` and programs answering as `run` does.
    async fn doctored(
        environment: &env::Process,
        dir: &std::path::Path,
        run: &(dyn Fn(&str, &[&str]) -> Option<String> + Sync),
    ) -> Result<Checked, env::EnvError> {
        super::run(&Machine {
            environment,
            dir,
            run,
        })
        .await
    }

    /// Every client pointed at a proxy that answers, with nothing cached and no lockfile,
    /// is the one report that exits 0 with nothing to say.
    #[tokio::test]
    async fn every_client_at_a_ready_proxy_exits_0() {
        let ready = Readiness {
            ready: true,
            intel: IntelState::Loaded,
            snapshot: None,
            gaps: Vec::new(),
        };
        let url = fake_proxy(true, ready).await;
        let index = format!("{url}/simple/");
        let at_proxy = |program: &str, args: &[&str]| match (program, args) {
            (_, ["--version"]) => Some("1.0".to_owned()),
            ("npm" | "pnpm" | "yarn", ["config", "get", "registry"]) => Some(format!("{url}/")),
            ("pip", ["config", "list"]) => Some(format!("global.index-url='{index}'")),
            _ => None,
        };
        let environment = crate::env::testing::with(&[
            (env::PROXY_URL, &url),
            (env::UV_DEFAULT, &index),
            (env::UV_NO_FILES, "1"),
        ]);
        let dir = crate::util::test_support::tempdir("doctor-run-ok");

        let checked = doctored(&environment, &dir, &at_proxy).await.expect("runs");
        assert_eq!(checked.code, 0, "{}", checked.report);
        assert!(
            checked.report.starts_with(&format!(
                "byrle doctor\n  proxy expected at {url}\n  checking from {}\n\n",
                dir.display()
            )),
            "{}",
            checked.report
        );
        assert!(
            checked
                .report
                .ends_with("\nEverything checked is pointing at the proxy.\n"),
            "{}",
            checked.report
        );
        assert!(!checked.report.contains("WARN"), "{}", checked.report);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing installed, a proxy with no proxy URL and no intel store, and a cooldown
    /// against an index serving PEP 503 are each a warning, so the exit is still 0.
    #[tokio::test]
    async fn warnings_alone_exit_0() {
        let url = fake_proxy(false, readiness(IntelState::NotConsulted)).await;
        let dir = crate::util::test_support::tempdir("doctor-run-warn");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\ncooldown_days: 3\n").expect("writes");
        std::fs::write(
            dir.join("package-lock.json"),
            format!(
                r#"{{"packages":{{"node_modules/a":{{"resolved":"{url}/a/-/a-1.0.0.tgz"}}}}}}"#
            ),
        )
        .expect("writes");
        let environment = crate::env::testing::with(&[
            (env::PROXY_URL, &url),
            (env::POLICY, &policy.display().to_string()),
            (env::UPSTREAM_PYPI, &format!("{url}/simple/")),
        ]);

        let checked = doctored(&environment, &dir, &nothing_installed)
            .await
            .expect("runs");
        assert_eq!(checked.code, 0, "{}", checked.report);
        for expected in [
            "npm registry: not installed, or its configuration could not be read",
            "pip registry: not installed, or its configuration could not be read",
            &format!(
                "{PROXY_URL_IN_USE}: the proxy has no {}",
                env::PROXY_URL.name
            ),
            "proxy readiness: ready, but uses no intel store",
            &format!("{}", policy.display()),
            "serves PEP 503 HTML",
            "package-lock.json: ",
            "Installs reach the proxy, with the caveats above.",
        ] {
            assert!(
                checked.report.contains(expected),
                "{expected}\n{}",
                checked.report
            );
        }
        assert!(!checked.report.contains("PROBLEM"), "{}", checked.report);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A proxy that does not answer, clients pointed elsewhere, and a lockfile recording
    /// another address are problems, and the exit is 1.
    #[tokio::test]
    async fn a_problem_exits_1() {
        let proxy = format!(
            "http://{}",
            crate::util::test_support::closing_server().await
        );
        let dir = crate::util::test_support::tempdir("doctor-run-problem");
        let cache = dir.join("npm-cache");
        std::fs::create_dir_all(cache.join("_cacache/index-v5")).expect("creates");
        std::fs::write(cache.join("_cacache/index-v5/entry"), b"x").expect("writes");
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"packages":{"node_modules/a":{"resolved":"http://old.example:8080/a/-/a-1.0.0.tgz"}}}"#,
        )
        .expect("writes");
        let cache_dir = cache.display().to_string();
        let elsewhere = |program: &str, args: &[&str]| match (program, args) {
            ("npm" | "uv", ["--version"]) => Some("1.0".to_owned()),
            ("npm", ["config", "get", "registry"]) => {
                Some("https://registry.npmjs.org/".to_owned())
            }
            ("npm", ["config", "get", "cache"]) => Some(cache_dir.clone()),
            ("pip", ["config", "list"]) => Some(
                "global.index-url='https://pypi.org/simple/'\n\
                 global.extra-index-url='https://extra.example/simple/'"
                    .to_owned(),
            ),
            _ => None,
        };
        let missing = dir.join("missing.yaml").display().to_string();
        let environment = crate::env::testing::with(&[
            (env::PROXY_URL, &proxy),
            (env::POLICY, &missing),
            (env::UV_DEFAULT, "https://pypi.org/simple/"),
            (env::UV_NO_FILES, "1"),
        ]);

        let checked = doctored(&environment, &dir, &elsewhere)
            .await
            .expect("runs");
        assert_eq!(checked.code, 1, "{}", checked.report);
        for expected in [
            "proxy: nothing answered at",
            "npm registry: points at https://registry.npmjs.org/, not the proxy",
            "pip registry: points at https://pypi.org/simple/",
            "pip extra indexes",
            "uv registry: points at https://pypi.org/simple/",
            "proxy URL",
            "http://old.example:8080",
            "npm cache",
            &format!("PROBLEM  policy: {missing}: "),
            "Some installs are not going through the proxy. See above.",
        ] {
            assert!(
                checked.report.contains(expected),
                "{expected}\n{}",
                checked.report
            );
        }
        assert!(
            !checked.report.contains(READINESS_TITLE),
            "readiness is not asked of a proxy that does not answer\n{}",
            checked.report
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A variable that cannot be read stops `doctor` with that variable's error, before any
    /// finding is printed.
    #[tokio::test]
    async fn an_unreadable_variable_is_the_error() {
        use crate::env::Var;
        use crate::env::testing::{with, with_unreadable};

        let proxy = format!(
            "http://{}",
            crate::util::test_support::closing_server().await
        );
        let dir = crate::util::test_support::tempdir("doctor-run-unreadable");
        let cooldown = dir.join("cooldown.yaml");
        std::fs::write(&cooldown, "version: 1\ncooldown_days: 3\n").expect("writes");
        let cooldown = cooldown.display().to_string();
        let installed = |program: &str, args: &[&str]| match (program, args) {
            ("uv" | "bun", ["--version"]) => Some("1.0".to_owned()),
            _ => None,
        };
        let base: &[(Var, &str)] = &[(env::PROXY_URL, &proxy)];
        let cases: Vec<(env::Process, Var)> = vec![
            (with_unreadable(&[], env::LISTEN), env::LISTEN),
            (with_unreadable(&[], env::PROXY_URL), env::PROXY_URL),
            (with_unreadable(base, env::POLICY), env::POLICY),
            (
                with(&[
                    (env::PROXY_URL, &proxy),
                    (env::POLICY, &cooldown),
                    (env::UPSTREAM_PYPI, "ftp://pypi.example/simple/"),
                ]),
                env::UPSTREAM_PYPI,
            ),
            (
                with(&[
                    (env::PROXY_URL, &proxy),
                    (env::POLICY, &cooldown),
                    (env::EXPIRY_CEILING_DAYS, "soon"),
                ]),
                env::EXPIRY_CEILING_DAYS,
            ),
            (with_unreadable(base, env::UV_NO_FILES), env::UV_NO_FILES),
            (with_unreadable(base, env::BUN_CACHE), env::BUN_CACHE),
            (
                with_unreadable(
                    &[(env::PROXY_URL, &proxy), (env::UV_NO_FILES, "1")],
                    env::HOME_DIR,
                ),
                env::HOME_DIR,
            ),
        ];
        for (environment, var) in &cases {
            let error = doctored(environment, &dir, &installed)
                .await
                .expect_err(var.name);
            assert!(
                error.to_string().starts_with(var.name),
                "{}: {error}",
                var.name
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
