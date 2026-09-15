//! `waharoa doctor`: whether this machine is actually installing through the proxy.
//!
//! Every enforcement tier below a controlled network is advisory (see
//! `docs/engineering_decisions/enforcement-tiers.md`), so the interesting question is not
//! "is the proxy running" but "is anything using it". These checks answer that from the
//! client side: what each package manager is configured to talk to, what the lockfiles in
//! this directory record, and what would silently skip the proxy.
//!
//! The checks are pure. Reading files and running package managers happens in the binary,
//! so what is decided here can be tested against fixed inputs.

use crate::env;
use crate::policy::check::Report;
use crate::policy::packages;
use crate::proxy::{IntelState, READY_PATH, Readiness};
use std::collections::BTreeSet;
use std::fmt;

/// What follows from a proxy with no public URL, said by `doctor` and by the proxy at startup.
pub const WITHOUT_PUBLIC_URL: &str =
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
        write!(
            f,
            "{:>7}  {}: {}",
            self.severity.label(),
            self.title,
            self.detail
        )?;
        if let Some(fix) = &self.fix {
            write!(f, "\n         fix: {fix}")?;
        }
        Ok(())
    }
}

/// The lockfile formats this understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockfile {
    NpmPackageLock,
    YarnLock,
    PnpmLock,
}

impl Lockfile {
    pub const ALL: [Self; 3] = [Self::NpmPackageLock, Self::YarnLock, Self::PnpmLock];

    pub fn filename(self) -> &'static str {
        match self {
            Self::NpmPackageLock => "package-lock.json",
            Self::YarnLock => "yarn.lock",
            Self::PnpmLock => "pnpm-lock.yaml",
        }
    }

    pub fn client(self) -> &'static str {
        match self {
            Self::NpmPackageLock => "npm",
            Self::YarnLock => "yarn",
            Self::PnpmLock => "pnpm",
        }
    }
}

/// Artifact origins a lockfile records.
///
/// Empty means the file pins no absolute artifact URL. For pnpm that is the normal case
/// and not a fault: it omits `resolution.tarball` when the URL matches the configured
/// registry and derives it at install time, which is why its lockfiles stay portable and
/// why they cannot evidence which registry produced them.
///
/// Deliberately textual rather than a real parse of each format. What is wanted is every
/// absolute artifact URL the file pins, and all three write those as `<key>: <url>` or
/// `<key> "<url>"` on one line.
pub fn recorded_origins(kind: Lockfile, contents: &str) -> BTreeSet<String> {
    let key = match kind {
        Lockfile::NpmPackageLock | Lockfile::YarnLock => "resolved",
        Lockfile::PnpmLock => "tarball",
    };

    let mut origins = BTreeSet::new();
    for line in contents.lines() {
        let Some(after) = line.split(key).nth(1) else {
            continue;
        };
        // What follows is `": "https://..."`, `  "https://..."`, or `: https://...`.
        let Some(start) = after.find("http") else {
            continue;
        };
        let url: String = after[start..]
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | ',' | '}' | '#'))
            .collect();
        if let Some(origin) = crate::npm::origin_of_url(&url) {
            origins.insert(origin);
        }
    }
    origins
}

/// Whether a package manager is pointed at the proxy.
pub fn check_registry(client: &str, configured: Option<&str>, proxy: &str) -> Finding {
    let title = format!("{client} registry");
    let Some(configured) = configured.map(str::trim).filter(|s| !s.is_empty()) else {
        return Finding::new(
            Severity::Warn,
            title,
            "not installed, or its configuration could not be read",
        );
    };

    if same_origin(configured, proxy) {
        return Finding::new(Severity::Ok, title, configured.to_owned());
    }
    Finding::new(
        Severity::Problem,
        title,
        format!("points at {configured}, not the proxy at {proxy}"),
    )
    .with_fix(format!("{client} config set registry {proxy}"))
}

/// Whether a lockfile is evidence that the proxy produced it.
///
/// npm and yarn record the absolute artifact URL, so a lockfile written through the proxy
/// names it and CI can check that. pnpm omits the URL when it matches the configured
/// registry, so its lockfiles are portable and prove nothing either way.
pub fn check_lockfile(kind: Lockfile, contents: &str, proxy: &str) -> Finding {
    let title = kind.filename().to_owned();
    let origins = recorded_origins(kind, contents);

    if origins.is_empty() {
        let detail = match kind {
            Lockfile::PnpmLock => {
                "records no artifact URLs, which is normal: pnpm derives them from the \
                 configured registry, so the lockfile is portable and is not evidence \
                 either way"
            }
            _ => "records no artifact URLs",
        };
        return Finding::new(Severity::Ok, title, detail);
    }

    let proxy_origin = crate::npm::origin_of_url(proxy).unwrap_or_else(|| proxy.to_owned());
    let (ours, theirs): (Vec<&String>, Vec<&String>) =
        origins.iter().partition(|o| **o == proxy_origin);

    match (ours.is_empty(), theirs.is_empty()) {
        (false, true) => Finding::new(
            Severity::Ok,
            title,
            format!(
                "every artifact is pinned to {proxy_origin}, so this was installed through the proxy"
            ),
        ),
        (true, false) => Finding::new(
            Severity::Warn,
            title,
            format!(
                "artifacts are pinned to {}, so this was not installed through the proxy",
                join(&theirs)
            ),
        )
        .with_fix("delete the lockfile and node_modules, then install again through the proxy"),
        // A lockfile that names two places installs from both, and only one is examined.
        (false, false) => Finding::new(
            Severity::Problem,
            title,
            format!(
                "artifacts are split between {proxy_origin} and {}, so part of this install \
                 does not go through the proxy",
                join(&theirs)
            ),
        )
        .with_fix("delete the lockfile and node_modules, then install again through the proxy"),
        (true, true) => unreachable!("origins is not empty"),
    }
}

/// Whether the address written into artifact URLs is pinned.
///
/// Without it the proxy uses whatever `Host` each client happened to use, and that address
/// goes into lockfiles. Measured: `npm ci` against a lockfile whose recorded address is
/// unreachable fails outright and does not fall back to the registry it was given on the
/// command line.
pub fn check_public_url(configured: Option<&str>, recorded: &BTreeSet<String>) -> Finding {
    let title = "public URL".to_owned();
    let Some(configured) = configured.map(str::trim).filter(|s| !s.is_empty()) else {
        return Finding::new(
            Severity::Warn,
            title,
            format!("{} is not set, so {WITHOUT_PUBLIC_URL}", env::PUBLIC_URL),
        )
        .with_fix(format!(
            "set {} to a stable name everyone who uses the lockfile can reach",
            env::PUBLIC_URL
        ));
    };

    let origin = crate::npm::origin_of_url(configured).unwrap_or_else(|| configured.to_owned());
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
///
/// Measured by installing the same package twice through the proxy with one cache, and
/// counting what the proxy saw the second time:
///
/// | Client | Second install |
/// |---|---|
/// | npm 11, pnpm 10, bun 1.3 | nothing reached the proxy |
/// | yarn 1, yarn 4 | the packument did, the artifact did not |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheBypass {
    /// The whole install is served locally.
    Complete,
    /// Metadata is still fetched; artifacts are not.
    ArtifactsOnly,
}

/// A warm client cache serves without consulting the registry, so what it supplies never
/// reaches the proxy to be examined.
///
/// `cache` is where the client would look **from this directory**, and `None` means there
/// is nothing there. Which cache is in play is a per-directory question: `pnpm store path`
/// answers with a store on the project's own filesystem, so it is `/tmp/.pnpm-store` in a
/// directory under `/tmp` and the user's store elsewhere.
///
/// Reports presence and location rather than a count. Every client lays its cache out
/// differently, so one number would mean packages for one and files for another: the same
/// yarn cache is 12,983 entries or 749,073 files depending on which you count.
pub fn check_cache(client: &str, cache: Option<&std::path::Path>, bypass: CacheBypass) -> Finding {
    let title = format!("{client} cache");
    let Some(cache) = cache else {
        return Finding::new(
            Severity::Ok,
            title,
            "empty or absent, so installs reach the proxy",
        );
    };

    let effect = match bypass {
        CacheBypass::Complete => {
            "A warm cache supplies the whole install, so those packages never reach the proxy"
        }
        CacheBypass::ArtifactsOnly => {
            "A warm cache still fetches metadata but serves artifacts locally, so those \
             artifacts are never examined"
        }
    };
    let fix = match client {
        "bun" => "bun pm cache rm".to_owned(),
        "pnpm" => "pnpm store prune, or delete the store directory".to_owned(),
        other => format!("{other} cache clean --force"),
    };
    Finding::new(
        Severity::Warn,
        title,
        format!("{} holds cached packages. {effect}", cache.display()),
    )
    .with_fix(fix)
}

/// Whether the proxy is there, and whether it is configured the way this check expects.
///
/// Everything else here reads what a client is configured to do. This is the one that
/// asks whether the thing at the other end exists and answers.
///
/// `health` is what [`crate::proxy::HEALTH_PATH`] returned, or `None` when nothing
/// answered there.
pub fn check_proxy(health: Option<&crate::proxy::Health>, proxy: &str) -> Vec<Finding> {
    let title = "proxy".to_owned();
    let Some(health) = health else {
        return vec![
            Finding::new(
                Severity::Problem,
                title,
                format!("nothing answered at {proxy}{}", crate::proxy::HEALTH_PATH),
            )
            .with_fix("start the proxy, or point this at the address clients actually use"),
        ];
    };

    let mut findings = vec![Finding::new(
        Severity::Ok,
        title,
        format!(
            "{} {} at {proxy}, forwarding to {}",
            health.service, health.version, health.upstream
        ),
    )];

    // The address the proxy writes into artifact URLs is the one lockfiles record, so a
    // proxy that does not know its own address writes whatever Host each client used.
    match health.public_base.as_deref() {
        Some(base) if same_origin(base, proxy) => {}
        Some(base) => findings.push(
            Finding::new(
                Severity::Warn,
                "proxy public URL",
                format!(
                    "the proxy writes {base} into artifact URLs, but this check reached it at \
                     {proxy}. Lockfiles will record {base}"
                ),
            )
            .with_fix(format!(
                "check which address clients use, and set {} to it",
                env::PUBLIC_URL
            )),
        ),
        None => findings.push(
            Finding::new(
                Severity::Warn,
                "proxy public URL",
                format!(
                    "the proxy has no {}, so {WITHOUT_PUBLIC_URL}",
                    env::PUBLIC_URL
                ),
            )
            .with_fix(format!(
                "set {} on the proxy to a stable name",
                env::PUBLIC_URL
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

/// The title of every finding about readiness.
const READINESS_TITLE: &str = "proxy readiness";

/// The fix for a snapshot that is missing or cannot match a served ecosystem.
const REFRESH_FIX: &str = "run `waharoa refresh` on the proxy's database";

/// Whether the proxy can decide on packages now.
///
/// A proxy can answer its health request and still answer every package with 503 while its
/// intel store is empty or down. `readiness` is what [`READY_PATH`] returned, or `None` when
/// nothing there could be read. Run only when the health request in [`check_proxy`]
/// succeeded.
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
            let using = format!(
                "ready, using intel snapshot {}, taken {}",
                snapshot.digest, snapshot.taken_at
            );
            let gaps = snapshot.gaps();
            if gaps.is_empty() {
                return Finding::new(Severity::Ok, READINESS_TITLE, using);
            }
            let gaps: Vec<String> = gaps.iter().map(ToString::to_string).collect();
            Finding::new(
                Severity::Warn,
                READINESS_TITLE,
                format!("{using}, but {}", gaps.join("; ")),
            )
            .with_fix(REFRESH_FIX)
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

/// Where the proxy is expected to be reachable.
///
/// [`env::PUBLIC_URL`] is the address written into artifact URLs and therefore into
/// lockfiles, so it is the one that matters. Otherwise the listen address is the best
/// guess available, and it is often wrong in the way the public URL check reports:
/// `0.0.0.0` is not an address a client reaches the proxy on.
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
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => count_files(&entry.path()),
            Ok(_) => 1,
            Err(_) => 0,
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

/// What `waharoa policy check --strict` fails on, for the policy the proxy is configured with.
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
    match (crate::npm::origin_of_url(a), crate::npm::origin_of_url(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a.trim_end_matches('/') == b.trim_end_matches('/'),
    }
}

/// A public registry in a lockfile is a different problem from a stale proxy address, and
/// saying "this is not your proxy" about registry.npmjs.org would be noise.
fn looks_like_a_registry(origin: &str) -> bool {
    origin == crate::npm::DEFAULT_REGISTRY
}

fn join(origins: &[&String]) -> String {
    origins
        .iter()
        .map(|o| o.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
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
            check_registry("npm", Some(PROXY), PROXY).severity,
            Severity::Ok
        );
        assert_eq!(
            check_registry("npm", Some("http://127.0.0.1:8080/"), PROXY).severity,
            Severity::Ok,
            "a trailing slash is the same registry"
        );
    }

    /// The bypass the README calls advisory: a developer who resets the registry URL.
    #[test]
    fn a_client_pointed_elsewhere_is_a_problem_with_a_fix() {
        let finding = check_registry("npm", Some("https://registry.npmjs.org"), PROXY);
        assert_eq!(finding.severity, Severity::Problem);
        assert!(finding.detail.contains("registry.npmjs.org"));
        assert_eq!(
            finding.fix.as_deref(),
            Some("npm config set registry http://127.0.0.1:8080")
        );
    }

    #[test]
    fn a_client_that_is_not_installed_is_not_a_problem() {
        let finding = check_registry("yarn", None, PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("not installed"));
    }

    /// npm and yarn record the absolute artifact URL, so the lockfile is evidence.
    #[test]
    fn npm_and_yarn_lockfiles_record_where_artifacts_came_from() {
        let npm = r#"{"packages":{"node_modules/lodash":{
            "resolved":"http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz"}}}"#;
        assert_eq!(
            recorded_origins(Lockfile::NpmPackageLock, npm),
            origins(&["http://127.0.0.1:8080"])
        );

        let yarn = r#"lodash@^4.17.21:
  version "4.17.21"
  resolved "http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz#abc123"
  integrity sha512-AAAA"#;
        assert_eq!(
            recorded_origins(Lockfile::YarnLock, yarn),
            origins(&["http://127.0.0.1:8080"])
        );
    }

    /// pnpm omits the URL when it matches the configured registry, so there is nothing to
    /// read and nothing is wrong.
    #[test]
    fn a_pnpm_lockfile_without_tarball_urls_is_not_a_fault() {
        let pnpm = "  lodash@4.17.21:\n    resolution: {integrity: sha512-AAAA}\n";
        assert!(recorded_origins(Lockfile::PnpmLock, pnpm).is_empty());

        let finding = check_lockfile(Lockfile::PnpmLock, pnpm, PROXY);
        assert_eq!(finding.severity, Severity::Ok);
        assert!(
            finding.detail.contains("portable"),
            "got: {}",
            finding.detail
        );
    }

    #[test]
    fn a_pnpm_lockfile_with_tarball_urls_is_read() {
        let pnpm = "    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/a/-/a-1.0.0.tgz}\n";
        assert_eq!(
            recorded_origins(Lockfile::PnpmLock, pnpm),
            origins(&["https://registry.npmjs.org"])
        );
    }

    #[test]
    fn a_lockfile_pinned_to_the_proxy_is_evidence_it_was_used() {
        let npm = r#"{"packages":{"a":{"resolved":"http://127.0.0.1:8080/a/-/a-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(Lockfile::NpmPackageLock, npm, PROXY);
        assert_eq!(finding.severity, Severity::Ok);
        assert!(finding.detail.contains("through the proxy"));
    }

    #[test]
    fn a_lockfile_pinned_elsewhere_says_so() {
        let npm = r#"{"packages":{"a":{"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(Lockfile::NpmPackageLock, npm, PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.fix.is_some());
    }

    /// A lockfile naming two places installs from both, and only one is examined. That is
    /// worse than one that names neither.
    #[test]
    fn a_split_lockfile_is_a_problem() {
        let npm = r#"{"packages":{
            "a":{"resolved":"http://127.0.0.1:8080/a/-/a-1.0.0.tgz"},
            "b":{"resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz"}}}"#;
        let finding = check_lockfile(Lockfile::NpmPackageLock, npm, PROXY);
        assert_eq!(finding.severity, Severity::Problem);
        assert!(finding.detail.contains("part of this install"));
    }

    /// Measured: `npm ci` fetches the address in the lockfile and does not fall back, so
    /// an address that stops answering fails the build.
    #[test]
    fn a_lockfile_pinned_to_another_proxy_address_is_a_problem() {
        let finding = check_public_url(
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
        let finding = check_public_url(
            Some("http://npm.corp.example"),
            &origins(&["https://registry.npmjs.org", "http://npm.corp.example"]),
        );
        assert_eq!(finding.severity, Severity::Ok);
    }

    #[test]
    fn an_unpinned_public_url_is_a_warning_with_the_reason() {
        let finding = check_public_url(None, &BTreeSet::new());
        assert_eq!(finding.severity, Severity::Warn);
        assert!(finding.detail.contains("whatever Host"));
        assert!(finding.fix.is_some());
    }

    /// Every client has a cache that serves without consulting the registry. Plan §7
    /// records it as a bypass vector, and it is measured per client rather than assumed
    /// to work like npm's.
    #[test]
    fn a_warm_cache_is_reported_as_skipping_the_proxy() {
        assert_eq!(
            check_cache("npm", None, CacheBypass::Complete).severity,
            Severity::Ok
        );

        let path = Path::new("/home/someone/.npm/_cacache");
        let finding = check_cache("npm", Some(path), CacheBypass::Complete);
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
        let finding = check_cache(
            "yarn",
            Some(Path::new("/tmp/yarn")),
            CacheBypass::ArtifactsOnly,
        );
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
            check_cache("bun", Some(Path::new("/tmp/b")), CacheBypass::Complete)
                .fix
                .as_deref(),
            Some("bun pm cache rm")
        );
        assert!(
            check_cache("pnpm", Some(Path::new("/tmp/p")), CacheBypass::Complete)
                .fix
                .as_deref()
                .is_some_and(|f| f.contains("pnpm store prune"))
        );
        assert_eq!(
            check_cache(
                "yarn",
                Some(Path::new("/tmp/y")),
                CacheBypass::ArtifactsOnly
            )
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
        for kind in Lockfile::ALL {
            assert!(recorded_origins(kind, "").is_empty());
            assert!(recorded_origins(kind, "not a lockfile at all").is_empty());
            assert!(
                recorded_origins(kind, "resolved tarball not-a-url").is_empty(),
                "{kind:?}"
            );
        }
    }

    fn health() -> crate::proxy::Health {
        crate::proxy::Health {
            service: "waharoa".into(),
            version: "0.1.0".into(),
            upstream: "https://registry.npmjs.org".into(),
            public_base: Some(PROXY.into()),
            rewrite_artifacts: true,
            refuse_unservable: true,
            served_origins: vec!["https://registry.npmjs.org".into()],
            allowed_direct_origins: vec![],
            packuments_held: 0,
            records_held: 0,
            artifacts_verified: 0,
        }
    }

    /// Every other check reads what a client is configured to do. This one asks whether
    /// the thing at the other end exists.
    #[test]
    fn a_proxy_that_does_not_answer_is_a_problem() {
        let findings = check_proxy(None, PROXY);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Problem);
        assert!(findings[0].detail.contains("nothing answered"));
        assert!(findings[0].fix.is_some());
    }

    fn readiness(intel: IntelState) -> Readiness {
        Readiness {
            ready: matches!(intel, IntelState::Loaded | IntelState::NotConsulted),
            intel,
            snapshot: (intel == IntelState::Loaded).then(|| crate::intel::store::LoadedSnapshot {
                digest: "sha256:ab".into(),
                taken_at: "2026-09-13T01:02:03Z".into(),
                streams: ["cisa/kev", "osv/npm"]
                    .map(|stream| crate::intel::refresh::StreamDigest {
                        stream: stream.to_owned(),
                        sha256: "aa".to_owned(),
                        etag: None,
                        last_modified: None,
                    })
                    .to_vec(),
            }),
        }
    }

    /// A snapshot with no stream able to originate a finding for npm serves every package.
    #[test]
    fn a_ready_proxy_whose_snapshot_cannot_match_npm_warns() {
        let mut ready = readiness(IntelState::Loaded);
        if let Some(snapshot) = ready.snapshot.as_mut() {
            snapshot.streams.retain(|s| s.stream == "cisa/kev");
        }
        let finding = check_readiness(Some(&ready), PROXY);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(
            finding.detail,
            "ready, using intel snapshot sha256:ab, taken 2026-09-13T01:02:03Z, but `npm` is \
             served with no stream providing match. Nothing can originate a finding for it"
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
        let findings = check_proxy(Some(&health()), PROXY);
        assert_eq!(worst(&findings), Severity::Ok);
        assert!(findings[0].detail.contains("waharoa 0.1.0"));
        assert!(findings[0].detail.contains("registry.npmjs.org"));
    }

    /// The address the proxy writes into artifact URLs is what lockfiles record, so a
    /// mismatch with the address clients actually use is worth saying out loud.
    #[test]
    fn a_proxy_answering_at_a_different_address_than_it_advertises_warns() {
        let mut h = health();
        h.public_base = Some("https://npm.corp.example".into());
        let findings = check_proxy(Some(&h), PROXY);
        assert_eq!(worst(&findings), Severity::Warn);
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("npm.corp.example")),
            "{findings:?}"
        );

        h.public_base = None;
        assert!(
            check_proxy(Some(&h), PROXY)
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
        h.allowed_direct_origins = vec!["https://cdn.example".into()];

        let findings = check_proxy(Some(&h), PROXY);
        assert_eq!(worst(&findings), Severity::Warn);
        let text: String = findings.iter().map(|f| f.detail.clone()).collect();
        assert!(text.contains("every client except npm"), "{text}");
        assert!(text.contains("rather than removed"), "{text}");
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
        // Under `target/`, not the shared temp directory: a predictable name there is
        // writable by anyone on the machine.
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

    #[test]
    fn lockfiles_name_their_client() {
        assert_eq!(Lockfile::NpmPackageLock.client(), "npm");
        assert_eq!(Lockfile::YarnLock.filename(), "yarn.lock");
        assert_eq!(Lockfile::PnpmLock.filename(), "pnpm-lock.yaml");
    }
}
