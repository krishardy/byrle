//! npm: fetching packuments and normalising them into [`PackageRecord`].
//!
//! Written concretely against npm alone. There is no `Registry` trait here, and there
//! should not be one until PyPI gives a second shape to design against (plan §4); an
//! interface drawn around one caller gets the abstraction wrong.
//!
//! # Unknown fields are accepted here, and rejected in the config loader
//!
//! The wire types below ignore keys they do not model. npm adds fields to packuments
//! without notice, and a registry doing that must never break an install passing
//! through the proxy. The policy loader takes the opposite position, rejecting unknown
//! keys, because a typo in an operator's policy must fail loudly rather than disable a
//! rule (see `docs/engineering_decisions/config-format-yaml-serde-saphyr.md`). Both
//! are deliberate; neither is a default to "fix".
//!
//! # What is measured rather than assumed
//!
//! Against 24,852 versions across 47 packages, each fetched as both documents (Sept
//! 2026). The set mixes current packages with ones published in 2011 and 2012, because
//! npm's oldest metadata is where the shapes stop being uniform.
//!
//! - Every version carried `dist.tarball`, and every version carried `dist.shasum`. A
//!   version without a tarball URL is therefore treated as a document defect and
//!   skipped, rather than modelled as an optional URL: with no artifact to fetch there
//!   is nothing to hash or gate.
//! - `dist.integrity` was **not** universal. Two versions lacked it, both published in
//!   2012 (`event-stream@0.9.1`, `vue@0.8.6`), leaving SHA-1 as the only digest npm
//!   offers for them. Hence `Artifact::integrity` is `Option`.
//! - The `versions` map key and the version object's own `version` field never
//!   disagreed. The key is used as the authority anyway, because that is what npm
//!   resolves a range against.
//! - `hasInstallScript` appeared as `true` on 901 versions and was absent on the rest.
//!   It was never present and `false`, so absence is read as "no install script".
//! - `repository` was an object 24,477 times and a bare string 5 times
//!   (`bower@1.8.11` through `1.8.14`, `rimraf@1.0.0`). The string form is rare and
//!   real, which is why the polymorphism is hand-written below.
//! - The abbreviated and full documents agreed on `has_install_scripts` for all 24,852
//!   version pairs, by their two different routes.
//!
//! `real_packuments_normalise_without_skipping_anything` in the tests re-runs all of
//! this against a corpus on disk.
//!
//! # Skipping is visible
//!
//! A version that cannot be normalised lands in [`NormalizedPackument::skipped`]
//! instead of being dropped. A package version that vanishes between the registry and
//! the policy engine is a version nothing gates, which is the shape of a bypass rather
//! than a parse detail.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::record::{
    Artifact, Maintainer, PackageRecord, PackumentDetail, Provenance, RegistrySignature,
    Repository, TrustedPublisher,
};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

/// npm's abbreviated packument media type, which is what `npm install` asks for.
pub const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";
/// The full document. Nothing in a normal install requests this; the proxy has to ask
/// for it on its own behalf to get publish times, maintainers and repository.
pub const FULL_ACCEPT: &str = "application/json";

/// The default registry, and the upstream the proxy points at unless configured.
pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

// ---------------------------------------------------------------------------
// Request paths
// ---------------------------------------------------------------------------

/// What a request path on an npm registry refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    /// A packument: `/lodash`, `/@babel%2fcore`, `/@babel/core`.
    Packument(PackageKey),
    /// A tarball: `/lodash/-/lodash-4.17.21.tgz`.
    Tarball {
        key: PackageKey,
        /// The version as the **filename** spells it, which is not always the version
        /// the packument uses. Of 24,852 tarball URLs measured, 38 differ: every
        /// prerelease of `express` before 3.0.0 and of `grunt` before 0.4.0 drops the
        /// hyphen, so `express@3.0.0-rc1` is served at `express-3.0.0rc1.tgz`.
        ///
        /// Nothing may treat this as an identity. Resolving it means matching the
        /// artifact against a record from the packument, which is the fetch-path work
        /// in plan §5.
        claimed_version: String,
    },
    /// Anything else the registry serves: `/-/v1/search`, `/-/whoami`, `/`.
    Other,
}

/// Classify a request path.
///
/// Paths that do not resolve to a package, including names this crate cannot turn into
/// an identity, come back as [`RequestTarget::Other`]. A path the proxy cannot classify
/// is still forwarded; it is not an error.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return RequestTarget::Other;
    }

    // Registry endpoints live under `/-/`. A package name cannot start with `-`, so a
    // leading segment of `-` is never a package.
    if path == "-" || path.starts_with("-/") {
        return RequestTarget::Other;
    }

    let (name, artifact) = match path.split_once("/-/") {
        Some((name, artifact)) => (name, Some(artifact)),
        None => (path, None),
    };

    // npm percent-encodes the scope separator on packument requests and leaves it bare
    // on tarball paths. Both spell the same package.
    let name = name.replace("%2f", "/").replace("%2F", "/");
    let Ok(key) = PackageKey::from_registry_name(Ecosystem::Npm, &name) else {
        return RequestTarget::Other;
    };

    let Some(artifact) = artifact else {
        return RequestTarget::Packument(key);
    };

    // `<unscoped name>-<version>.tgz`, with the scope absent from the filename.
    let Some(stem) = artifact.strip_suffix(".tgz") else {
        return RequestTarget::Other;
    };
    let Some(version) = stem
        .strip_prefix(key.name())
        .and_then(|rest| rest.strip_prefix('-'))
        .filter(|v| !v.is_empty())
    else {
        return RequestTarget::Other;
    };

    RequestTarget::Tarball {
        key,
        claimed_version: version.to_owned(),
    }
}

/// The origins whose artifacts the proxy serves.
///
/// One source of truth for two questions that must never disagree: which artifact URLs
/// get pointed at the proxy ([`rewrite_artifact_origins`]), and which are reported as
/// fetched directly ([`NormalizedPackument::bypassing_origins`]). If those sets differed,
/// an artifact could be rewritten and reported as bypassing, or left alone and reported
/// as fine.
///
/// Always holds the configured upstream and [`DEFAULT_REGISTRY`], because npm rewrites
/// `dist.tarball` to the configured registry when it names the default host. Additional
/// origins are for a registry that serves artifacts from somewhere else, a CDN in front
/// of a private registry being the case to expect. Zero of the 24,852 artifact URLs
/// measured on registry.npmjs.org needed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableOrigins {
    /// Every reachable origin, normalised to scheme, host and port. No path, no trailing
    /// slash.
    origins: Vec<String>,
    /// The subset the operator added because the upstream does not serve them. Only these
    /// are fetched from directly; see [`ReachableOrigins::routes_directly`].
    additional: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OriginError {
    pub value: String,
    pub reason: &'static str,
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a usable origin: {}",
            self.value, self.reason
        )
    }
}

impl std::error::Error for OriginError {}

impl ReachableOrigins {
    /// Build from the configured upstream plus any additional origins.
    ///
    /// [`DEFAULT_REGISTRY`] is always included. Anything that is not a URL with a host is
    /// an error rather than being dropped: an operator who names an origin and has it
    /// silently ignored would believe those artifacts are covered.
    pub fn new<'a>(
        upstream: &str,
        additional: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, OriginError> {
        let mut origins = vec![normalise_origin(upstream)?];
        let registry = normalise_origin(DEFAULT_REGISTRY)?;
        if !origins.contains(&registry) {
            origins.push(registry);
        }

        let mut extra = Vec::new();
        for base in additional {
            let base = base.trim();
            if base.is_empty() {
                continue;
            }
            let origin = normalise_origin(base)?;
            if !origins.contains(&origin) {
                origins.push(origin.clone());
                extra.push(origin);
            }
        }
        Ok(Self {
            origins,
            additional: extra,
        })
    }

    /// Every reachable origin, in the order they were configured.
    pub fn as_slice(&self) -> &[String] {
        &self.origins
    }

    /// Whether an artifact on this origin should be fetched from it rather than from the
    /// upstream.
    ///
    /// Only origins the operator added qualify. A packument that names the default
    /// registry still routes to the configured upstream, because a private mirror
    /// publishes artifact URLs on registry.npmjs.org while being the whole reason the
    /// proxy was pointed somewhere else: fetching from npmjs.org would go around it.
    pub fn routes_directly(&self, origin: &str) -> bool {
        self.additional.iter().any(|o| o == origin)
    }

    fn contains(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

fn normalise_origin(base: &str) -> Result<String, OriginError> {
    let url = reqwest::Url::parse(base).map_err(|_| OriginError {
        value: base.to_owned(),
        reason: "not a URL",
    })?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err(OriginError {
            value: base.to_owned(),
            reason: "no host",
        });
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OriginError {
            value: base.to_owned(),
            reason: "scheme is not http or https",
        });
    }
    Ok(origin_of(&url))
}

/// What happens to an artifact, decided by the origin it is published on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// The proxy fetches it, so it can be examined.
    Served,
    /// The client fetches it directly and nothing about it is observed. The operator has
    /// said that is acceptable for this origin.
    AllowedDirect(String),
    /// The proxy neither serves it nor permits it.
    Refused(String),
}

/// Which origins the proxy serves, and which it permits a client to fetch directly.
///
/// Three states, not two. Before the allow list the only escape from a refusal was to
/// turn refusing off everywhere, which trades one origin's exemption for every origin's.
///
/// What counts as served depends on how the proxy is deployed. In reverse-proxy mode it
/// is the upstream, the default registry and anything configured, because artifact URLs
/// are rewritten to point here. In the terminating mode described in
/// `docs/engineering_decisions/terminating-tls-certificates.md` it is the domains the
/// proxy holds certificates for, because those are the connections it actually sees. The
/// policy below does not change between them; only the set does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginPolicy {
    reachable: ReachableOrigins,
    /// Normalised origins the operator has exempted.
    allowed_direct: Vec<String>,
}

impl OriginPolicy {
    pub fn new<'a>(
        reachable: ReachableOrigins,
        allowed_direct: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, OriginError> {
        let mut allowed = Vec::new();
        for base in allowed_direct {
            let base = base.trim();
            if base.is_empty() {
                continue;
            }
            let origin = normalise_origin(base)?;
            if !allowed.contains(&origin) {
                allowed.push(origin);
            }
        }
        Ok(Self {
            reachable,
            allowed_direct: allowed,
        })
    }

    pub fn reachable(&self) -> &ReachableOrigins {
        &self.reachable
    }

    pub fn allowed_direct(&self) -> &[String] {
        &self.allowed_direct
    }

    /// What happens to an artifact published at this URL.
    ///
    /// A URL that does not parse is refused under its own text: it names no origin that
    /// could be served or allowed, and an artifact that cannot be located cannot be
    /// examined either.
    pub fn disposition(&self, artifact_url: &str) -> Disposition {
        let Some(origin) = origin_of_url(artifact_url) else {
            return Disposition::Refused(artifact_url.to_owned());
        };
        if self.reachable.contains(&origin) {
            return Disposition::Served;
        }
        if self.allowed_direct.contains(&origin) {
            return Disposition::AllowedDirect(origin);
        }
        Disposition::Refused(origin)
    }
}

impl NormalizedPackument {
    /// Artifact origins this document publishes that the proxy does not serve, split by
    /// whether the operator has allowed them.
    ///
    /// Both maps count versions. The allowed one has to stay visible: it is an accepted
    /// gap, and an accepted gap that stops being reported outlives the reason it was
    /// added.
    pub fn unserved_origins(
        &self,
        policy: &OriginPolicy,
    ) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
        let mut allowed = BTreeMap::new();
        let mut refused = BTreeMap::new();
        for record in &self.records {
            match policy.disposition(&record.artifact.url) {
                Disposition::Served => {}
                Disposition::AllowedDirect(origin) => *allowed.entry(origin).or_insert(0) += 1,
                Disposition::Refused(origin) => *refused.entry(origin).or_insert(0) += 1,
            }
        }
        (allowed, refused)
    }
}

/// Where a client will actually fetch an artifact from, when that is not the proxy.
///
/// Returns the origin it will go to directly, or `None` when the request will arrive at
/// the proxy.
///
/// npm rewrites `dist.tarball` to the configured registry **only when it names the
/// default registry host**. Tested against npm 9.9.4 with a controlled registry serving
/// the same package two ways: `https://registry.npmjs.org/...` was fetched through the
/// configured proxy, and another origin was fetched from that origin, with no tarball
/// request reaching the proxy at all.
///
/// So a registry that publishes artifacts on a host the proxy does not front has its
/// artifacts fetched unexamined. The packument is visible, which makes this detectable
/// at the moment the metadata goes past.
pub fn bypassing_origin(artifact_url: &str, reachable: &ReachableOrigins) -> Option<String> {
    let artifact = reqwest::Url::parse(artifact_url).ok()?;
    let found = origin_of(&artifact);
    if reachable.contains(&found) {
        None
    } else {
        Some(found)
    }
}

impl NormalizedPackument {
    /// Artifact origins in this document that the proxy does not front, with how many
    /// versions each accounts for. Empty in the normal case.
    ///
    /// A non-empty result means the client will fetch those artifacts directly, so
    /// nothing about them is observed: not the digest check, not the policy engine.
    pub fn bypassing_origins(&self, reachable: &ReachableOrigins) -> BTreeMap<String, usize> {
        let mut origins = BTreeMap::new();
        for record in &self.records {
            if let Some(origin) = bypassing_origin(&record.artifact.url, reachable) {
                *origins.entry(origin).or_insert(0) += 1;
            }
        }
        origins
    }
}

/// The result of pointing a packument's artifacts at the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    /// The document to forward.
    pub body: Vec<u8>,
    /// Distinct artifact URLs now pointing at the proxy.
    pub rewritten: usize,
    /// How many places in the document were changed. Higher than `rewritten` when a URL
    /// appears more than once: npm's `_resolved` repeats `dist.tarball` verbatim.
    pub occurrences: usize,
    /// Artifacts left as they were, because their origin is not one the proxy fronts.
    /// These are still fetched directly; see [`bypassing_origin`].
    pub left_alone: usize,
}

#[derive(Debug)]
pub enum RewriteError {
    /// The body is not UTF-8, so it is not JSON either.
    NotUtf8(std::str::Utf8Error),
    /// The body did not parse as JSON. Only the filtering path parses.
    NotJson(serde_json::Error),
    /// An artifact URL from the records was not found in the document as a complete
    /// quoted string. The document is shaped in a way this does not understand, and a
    /// partial rewrite would send some artifacts to the proxy and leave others pointing
    /// at the registry.
    Incomplete { expected: usize, found: usize },
}

impl fmt::Display for RewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8(e) => write!(f, "packument is not UTF-8: {e}"),
            Self::NotJson(e) => write!(f, "packument is not valid JSON: {e}"),
            Self::Incomplete { expected, found } => write!(
                f,
                "found {found} of {expected} artifact URLs to rewrite; \
                 the rest are not complete quoted strings"
            ),
        }
    }
}

impl std::error::Error for RewriteError {}

/// Point every artifact URL the proxy can serve at the proxy itself.
///
/// Necessary because clients disagree about `dist.tarball`. npm rewrites it to the
/// configured registry; pnpm 10, yarn 1, yarn 4 and bun 1.3 use it verbatim and fetch
/// from whatever host it names, so against a real registry their artifacts never reach
/// the proxy at all. Rewriting here makes every client in the ecosystem behave the same
/// way.
///
/// Only the **origin** changes. The path is kept, so the request that comes back is the
/// one [`classify_path`] already understands and the proxy forwards it upstream unchanged.
///
/// An artifact whose origin is not in `reachable` is left alone. Rewriting those would
/// mean the proxy fetching from an arbitrary host on a client's behalf, which is a
/// capability worth not having; they stay visible through [`bypassing_origin`] instead.
///
/// `dist.integrity` is untouched, and the registry signature covers
/// `<name>@<version>:<integrity>` rather than the URL (pacote `lib/registry.js`), so a
/// rewritten document still verifies.
///
/// # How, and why not a JSON value tree
///
/// `artifacts` are the URLs already found during normalisation, so the document is not
/// parsed again. Each is replaced wherever it appears as a **complete quoted string**,
/// leaving every other byte alone.
///
/// Parsing into a `serde_json::Value` and re-serialising was the obvious approach and
/// costs far more: the value tree dominated memory, with 24 simultaneous large packuments
/// reaching 1,348 MB against 27.6 MB of encoded bodies, plus 36 ms to parse and 10 ms to
/// serialise typescript. This walks the text once and allocates one output buffer.
///
/// It also produces a byte-identical document apart from the URLs, which re-serialising
/// cannot promise, and it catches `_resolved`, an npm internal field repeating
/// `dist.tarball` that a `dist.tarball`-only rewrite leaves pointing at the registry.
///
/// Measured against the corpus, both document kinds: of 49,704 artifact URLs, 49,702
/// appear exactly once as a complete quoted string and 2 appear twice, both as
/// `_resolved`. Escaped forward slashes occur in 2 of 94 documents and only inside README
/// prose, never in a URL.
///
/// If any URL is not found, the whole rewrite fails rather than half of it landing.
pub fn rewrite_artifact_origins<'a>(
    json: &[u8],
    artifacts: impl IntoIterator<Item = &'a str>,
    reachable: &ReachableOrigins,
    public_base: &str,
) -> Result<Rewritten, RewriteError> {
    let text = std::str::from_utf8(json).map_err(RewriteError::NotUtf8)?;
    let base = public_base.trim_end_matches('/');

    let mut replacements: HashMap<&str, String> = HashMap::new();
    let mut left_alone = 0;
    for url in artifacts {
        match reachable_path(url, reachable) {
            Some(path) => {
                replacements.insert(url, format!("{base}{path}"));
            }
            None => left_alone += 1,
        }
    }
    if replacements.is_empty() {
        return Ok(Rewritten {
            body: json.to_vec(),
            rewritten: 0,
            occurrences: 0,
            left_alone,
        });
    }

    // Every replaceable URL begins with one of these, so a scan per origin finds every
    // candidate. Searching for each URL separately would be thousands of passes over
    // megabytes.
    let prefixes: Vec<String> = reachable
        .as_slice()
        .iter()
        .map(|origin| format!("\"{origin}"))
        .collect();

    let mut out = String::with_capacity(text.len() + replacements.len() * 8);
    let mut found: HashSet<&str> = HashSet::new();
    let mut occurrences = 0;
    let mut cursor = 0;

    while let Some(open) = next_candidate(text, cursor, &prefixes) {
        // A URL contains no escaped quote, so the next quote ends the string.
        let Some(offset) = text[open + 1..].find('"') else {
            break;
        };
        let close = open + 1 + offset;
        let candidate = &text[open + 1..close];

        out.push_str(&text[cursor..=open]);
        match replacements.get(candidate) {
            Some(replacement) => {
                out.push_str(replacement);
                found.insert(candidate);
                occurrences += 1;
            }
            // Some other string on the same origin: a repository URL, a homepage.
            None => out.push_str(candidate),
        }
        out.push('"');
        cursor = close + 1;
    }
    out.push_str(&text[cursor..]);

    if found.len() != replacements.len() {
        return Err(RewriteError::Incomplete {
            expected: replacements.len(),
            found: found.len(),
        });
    }

    Ok(Rewritten {
        body: out.into_bytes(),
        rewritten: found.len(),
        occurrences,
        left_alone,
    })
}

/// Remove versions the proxy will not serve, then rewrite the rest.
///
/// This is the only control that works on an off-origin artifact. The client fetches
/// `dist.tarball` from whatever host it names, so a refusal at the artifact request never
/// happens: the request goes somewhere else. The packument is the last point at which the
/// version is visible, and dropping it there is what decision #4 already settles for
/// quarantine, letting the client's own resolver pick a version the proxy can see.
///
/// Structural, so unlike [`rewrite_artifact_origins`] it parses the document. That cost
/// is paid only when there is something to remove: zero of the 24,852 artifact URLs
/// measured on registry.npmjs.org were off-origin, so this path is not the normal one.
///
/// Versions with no `dist.tarball` at all are left alone. They produce no record, so
/// nothing can install them anyway, and removing them would be a second behaviour hiding
/// behind this one.
///
/// `refuse_unservable` says what happens to an artifact on an origin the proxy does not
/// front: dropped when true, and when false kept and left exactly as published, because
/// the operator chose to let the client fetch it directly.
///
/// A version is dropped for either of two reasons: its artifact is published somewhere
/// the proxy cannot see, or the package policy refuses it. They are separate questions
/// and share one pass because both remove from the same `versions` map and both leave a
/// `dist-tags` entry pointing at nothing.
pub fn filter_unservable_versions(
    json: &[u8],
    artifacts: impl IntoIterator<Item = (String, String)>,
    policy: &OriginPolicy,
    refused_by_policy: &HashSet<String>,
    refuse_unservable: bool,
    public_base: &str,
) -> Result<Filtered, RewriteError> {
    let mut document: serde_json::Value =
        serde_json::from_slice(json).map_err(RewriteError::NotJson)?;
    let base = public_base.trim_end_matches('/');

    let mut removed = Vec::new();
    let mut rewritten = 0;
    let mut allowed = 0;
    if let Some(versions) = document
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (version, url) in artifacts {
            // Asked first, because the policy's answer does not depend on where the
            // artifact lives. A version refused here is gone whatever its origin is.
            if refused_by_policy.contains(&version) {
                versions.remove(&version);
                removed.push(version);
                continue;
            }
            match policy.disposition(&url) {
                Disposition::Served => {
                    let Some(path) = reachable_path(&url, policy.reachable()) else {
                        continue;
                    };
                    if let Some(tarball) = versions
                        .get_mut(&version)
                        .and_then(|entry| entry.get_mut("dist"))
                        .and_then(|dist| dist.get_mut("tarball"))
                    {
                        *tarball = serde_json::Value::String(format!("{base}{path}"));
                        rewritten += 1;
                    }
                }
                // Left exactly as published, so the client fetches it where the registry
                // said. That is the point of allowing it.
                Disposition::AllowedDirect(_) => allowed += 1,
                Disposition::Refused(_) if refuse_unservable => {
                    versions.remove(&version);
                    removed.push(version);
                }
                Disposition::Refused(_) => allowed += 1,
            }
        }
    }

    // A tag pointing at a version that is gone would resolve to nothing. Dropping the tag
    // lets the resolver fall back to a version that is still there.
    let removed_set: HashSet<&str> = removed.iter().map(String::as_str).collect();
    if let Some(tags) = document
        .get_mut("dist-tags")
        .and_then(serde_json::Value::as_object_mut)
    {
        tags.retain(|_, value| value.as_str().is_none_or(|v| !removed_set.contains(v)));
    }

    removed.sort();
    Ok(Filtered {
        body: serde_json::to_vec(&document).map_err(RewriteError::NotJson)?,
        removed,
        rewritten,
        allowed,
    })
}

/// The result of removing versions the proxy will not serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filtered {
    pub body: Vec<u8>,
    /// Versions no longer in the document, sorted.
    pub removed: Vec<String>,
    /// Versions kept, with their artifact pointed at the proxy.
    pub rewritten: usize,
    /// Versions kept with their artifact left as published, because the operator allows
    /// that origin to be fetched directly.
    pub allowed: usize,
}

/// The earliest position at or after `from` where any prefix occurs.
fn next_candidate(text: &str, from: usize, prefixes: &[String]) -> Option<usize> {
    prefixes
        .iter()
        .filter_map(|prefix| text[from..].find(prefix.as_str()).map(|at| from + at))
        .min()
}

/// The path to keep, when this URL names an origin the proxy fronts.
fn reachable_path(url: &str, reachable: &ReachableOrigins) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !reachable.contains(&origin_of(&parsed)) {
        return None;
    }
    Some(match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    })
}

/// The scheme, host and port of a URL, or `None` when it is not a usable URL.
pub fn origin_of_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed.host_str()?;
    Some(origin_of(&parsed))
}

fn origin_of(url: &reqwest::Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or(""),
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    )
}

/// Which document a response body is, read from its `Content-Type`.
///
/// The response is authoritative and the request is not: npm asks with
/// `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*`, which
/// names both documents and settles nothing.
///
/// Across 18 responses from registry.npmjs.org (6 packages, scoped and unscoped, each
/// of the three Accept headers above), the value was exactly one of the two media types
/// with no `charset` parameter. Parameters and casing are handled anyway, since a mirror
/// or a CDN in front of one may add them. Anything else returns `None`, and the proxy
/// forwards that response without reading it.
pub fn detail_from_content_type(content_type: Option<&str>) -> Option<PackumentDetail> {
    let media_type = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    match media_type.as_str() {
        ABBREVIATED_ACCEPT => Some(PackumentDetail::Abbreviated),
        FULL_ACCEPT => Some(PackumentDetail::Full),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A packument could not be turned into records.
///
/// Deliberately distinct from a transport failure. The proxy must not answer 502
/// because a registry served a document shape we did not model: that is our gap, not
/// the upstream's outage.
#[derive(Debug)]
pub enum NormalizeError {
    /// The body was not JSON, or not a JSON object of the expected shape.
    Json(serde_json::Error),
    /// The document's `name` is not a usable package identity.
    Name(IdentityError),
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "packument is not valid JSON: {e}"),
            Self::Name(e) => write!(f, "packument name is unusable: {e}"),
        }
    }
}

impl std::error::Error for NormalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Name(e) => Some(e),
        }
    }
}

/// A fetch did not produce a packument body.
#[derive(Debug)]
pub enum FetchError {
    /// The request never completed: DNS, TLS, connection, timeout.
    Transport(reqwest::Error),
    /// The registry answered, with something other than success.
    Status(reqwest::StatusCode),
    /// The body arrived and could not be decoded: an encoding this does not handle, a
    /// corrupt stream, or more output than the limit allows.
    Undecodable(crate::http::DecodeError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "registry request failed: {e}"),
            Self::Status(s) => write!(f, "registry answered {s}"),
            Self::Undecodable(e) => write!(f, "registry body could not be decoded: {e}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Status(_) => None,
            Self::Undecodable(e) => Some(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One version that could not be normalised, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedVersion {
    /// The key it appeared under in the `versions` map.
    pub version: String,
    pub reason: String,
}

/// Every version of one package, normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPackument {
    /// Identity taken from the document's own `name`, never from the request path.
    /// A request for `/Lodash` can be answered with a document naming `lodash`, and the
    /// document is what the client installs (see `identity`).
    pub key: PackageKey,
    /// What `dist-tags.latest` points at, when the document carries one. Not resolved
    /// into a record here: a tag can name a version the `versions` map omits.
    pub latest: Option<String>,
    /// One record per usable version, ordered by the `versions` map key.
    pub records: Vec<PackageRecord>,
    /// Versions present in the document that produced no record. Empty in the normal
    /// case; never silently discarded.
    pub skipped: Vec<SkippedVersion>,
}

impl NormalizedPackument {
    /// The record for one exact version string, if the document carried it.
    pub fn version(&self, version: &str) -> Option<&PackageRecord> {
        self.records.iter().find(|r| r.package.version() == version)
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------
//
// These mirror npm's JSON and nothing else. They are private: the crate's contract is
// PackageRecord, and letting a registry's field names leak upward is how an ecosystem
// quirk becomes everyone's problem.

#[derive(Debug, Deserialize)]
struct WirePackument {
    name: String,
    #[serde(default, rename = "dist-tags")]
    dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    versions: BTreeMap<String, WireVersion>,
    /// Full packument only. Keyed by version string, plus the `created` and `modified`
    /// entries, which are document metadata and not versions.
    #[serde(default)]
    time: BTreeMap<String, String>,
    /// Package-level fallbacks. npm repeats both inside each version object, and the
    /// per-version copy is what was true at publish time, so it wins.
    #[serde(default)]
    maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default)]
    repository: Option<Repository>,
}

#[derive(Debug, Deserialize)]
struct WireVersion {
    #[serde(default)]
    dist: Option<WireDist>,
    /// Abbreviated only, and present only when true (measured: 3 of 9,321 versions
    /// carried the key, none of them `false`).
    #[serde(default, rename = "hasInstallScript")]
    has_install_script: Option<bool>,
    /// Full only.
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default)]
    repository: Option<Repository>,
    #[serde(default, rename = "_npmUser")]
    npm_user: Option<WireNpmUser>,
}

#[derive(Debug, Deserialize)]
struct WireDist {
    #[serde(default)]
    tarball: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    shasum: Option<String>,
    #[serde(default, rename = "fileCount")]
    file_count: Option<u64>,
    #[serde(default, rename = "unpackedSize")]
    unpacked_size: Option<u64>,
    #[serde(default)]
    attestations: Option<WireAttestations>,
    #[serde(default)]
    signatures: Option<Vec<WireSignature>>,
}

#[derive(Debug, Deserialize)]
struct WireAttestations {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    provenance: Option<WireProvenance>,
}

#[derive(Debug, Deserialize)]
struct WireProvenance {
    #[serde(default, rename = "predicateType")]
    predicate_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireSignature {
    keyid: String,
    sig: String,
}

#[derive(Debug, Deserialize)]
struct WireMaintainer {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireNpmUser {
    #[serde(default, rename = "trustedPublisher")]
    trusted_publisher: Option<WireTrustedPublisher>,
}

#[derive(Debug, Deserialize)]
struct WireTrustedPublisher {
    id: String,
}

/// `repository` is either an object or a shorthand string such as `github:user/repo`.
///
/// Hand-written rather than `#[serde(untagged)]` on purpose. `untagged` buffers into an
/// intermediate value and tries each variant, which silently discards any
/// `deny_unknown_fields` on the variants and turns a field-level mistake into "no
/// variant matched" (plan §5). Here it would also cost an allocation per version on a
/// document that can hold several thousand.
impl<'de> Deserialize<'de> for Repository {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RepositoryVisitor;

        impl<'de> Visitor<'de> for RepositoryVisitor {
            type Value = Repository;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a repository URL string or an object with a `url` field")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Repository {
                    url: value.to_owned(),
                    kind: None,
                    directory: None,
                })
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut url = None;
                let mut kind = None;
                let mut directory = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "url" => url = map.next_value::<Option<String>>()?,
                        "type" => kind = map.next_value::<Option<String>>()?,
                        "directory" => directory = map.next_value::<Option<String>>()?,
                        // Unknown keys are skipped, matching the rest of this module.
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Repository {
                    url: url.ok_or_else(|| de::Error::missing_field("url"))?,
                    kind,
                    directory,
                })
            }
        }

        deserializer.deserialize_any(RepositoryVisitor)
    }
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

/// Turn a packument body into records.
///
/// `detail` says which document this is, and comes from what was asked for: the
/// `Accept` header sent, or the `Content-Type` returned. It is not inferred from the
/// content, because it qualifies every absent field in the result. Labelling an
/// abbreviated document `Full` would report "npm publishes no timestamp for this
/// version" when the truth is that nobody asked for one, and [`PackageRecord`]'s whole
/// `source` field exists to keep those apart.
pub fn normalize_packument(
    body: &[u8],
    detail: PackumentDetail,
) -> Result<NormalizedPackument, NormalizeError> {
    let wire: WirePackument = serde_json::from_slice(body).map_err(NormalizeError::Json)?;
    normalize_wire(wire, detail)
}

fn normalize_wire(
    wire: WirePackument,
    detail: PackumentDetail,
) -> Result<NormalizedPackument, NormalizeError> {
    let key =
        PackageKey::from_registry_name(Ecosystem::Npm, &wire.name).map_err(NormalizeError::Name)?;

    let mut records = Vec::with_capacity(wire.versions.len());
    let mut skipped = Vec::new();

    for (version, entry) in &wire.versions {
        match version_record(&key, version, entry, &wire, detail) {
            Ok(record) => records.push(record),
            Err(reason) => skipped.push(SkippedVersion {
                version: version.clone(),
                reason,
            }),
        }
    }

    Ok(NormalizedPackument {
        key,
        latest: wire.dist_tags.get("latest").cloned(),
        records,
        skipped,
    })
}

/// Build one record, or say why not. The error is a plain string because it is
/// reported, not matched on.
fn version_record(
    key: &PackageKey,
    version: &str,
    entry: &WireVersion,
    wire: &WirePackument,
    detail: PackumentDetail,
) -> Result<PackageRecord, String> {
    let package = key.at_version(version).map_err(|e| format!("{e}"))?;

    let dist = entry.dist.as_ref().ok_or("version has no `dist` object")?;
    let url = dist
        .tarball
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or("version has no `dist.tarball`")?
        .to_owned();

    // Publish time comes from the document-level `time` map keyed by version. `created`
    // and `modified` live in the same map and describe the package, not a version; a
    // version literally named "created" would collide, and npm's own semver parsing
    // rejects that name, so the lookup is safe as written.
    let published_at = wire
        .time
        .get(version)
        .and_then(|raw| raw.parse::<jiff::Timestamp>().ok());

    let maintainers = entry
        .maintainers
        .as_ref()
        .or(wire.maintainers.as_ref())
        .map(|list| list.iter().map(maintainer).collect());

    let repository = entry.repository.clone().or_else(|| wire.repository.clone());

    Ok(PackageRecord {
        package,
        source: detail,
        published_at,
        maintainers,
        repository,
        has_install_scripts: has_install_scripts(entry),
        install_scripts: entry.scripts.as_ref().map(install_scripts),
        provenance: provenance(entry, dist),
        artifact: Artifact {
            url,
            // Absent on two versions in the measured corpus, both from 2012. A record
            // with no `integrity` has only a SHA-1 digest behind it, which the policy
            // engine has to be able to see rather than have papered over here.
            integrity: dist.integrity.clone(),
            legacy_sha1: dist.shasum.clone(),
            file_count: dist.file_count,
            unpacked_size: dist.unpacked_size,
        },
    })
}

/// The three lifecycle scripts npm runs on install. `prepare` and `prepublish` are
/// deliberately absent: they run when building from a git dependency or publishing, not
/// when installing a registry tarball.
const INSTALL_SCRIPT_NAMES: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Answer the same question from either document.
///
/// The abbreviated packument states it outright. The full packument never carries
/// `hasInstallScript` and has to be read from `scripts`. Checked equivalent across
/// 24,852 version pairs with no disagreement; see
/// `record::PackageRecord::has_install_scripts`.
fn has_install_scripts(entry: &WireVersion) -> bool {
    if let Some(flag) = entry.has_install_script {
        return flag;
    }
    entry.scripts.as_ref().is_some_and(|scripts| {
        INSTALL_SCRIPT_NAMES
            .iter()
            .any(|name| scripts.contains_key(*name))
    })
}

/// Keep only the scripts that run on install. The rest of `scripts` is build and test
/// tooling that a `npm install` of a published tarball never executes.
fn install_scripts(scripts: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    INSTALL_SCRIPT_NAMES
        .iter()
        .filter_map(|name| {
            scripts
                .get_key_value(*name)
                .map(|(k, v)| (k.clone(), v.clone()))
        })
        .collect()
}

fn maintainer(wire: &WireMaintainer) -> Maintainer {
    Maintainer {
        // No maintainer entry in the measured corpus lacked a name, but `name` is not
        // guaranteed by any schema. An entry missing one keeps an empty name rather
        // than being dropped, because the number of maintainers is itself a signal the
        // heuristics read.
        name: wire.name.clone().unwrap_or_default(),
        email: wire.email.clone(),
    }
}

fn provenance(entry: &WireVersion, dist: &WireDist) -> Provenance {
    Provenance {
        attestation_url: dist.attestations.as_ref().and_then(|a| a.url.clone()),
        predicate_type: dist
            .attestations
            .as_ref()
            .and_then(|a| a.provenance.as_ref())
            .and_then(|p| p.predicate_type.clone()),
        registry_signatures: dist
            .signatures
            .as_ref()
            .map(|sigs| {
                sigs.iter()
                    .map(|s| RegistrySignature {
                        key_id: s.keyid.clone(),
                        signature: s.sig.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        trusted_publisher: entry
            .npm_user
            .as_ref()
            .and_then(|u| u.trusted_publisher.as_ref())
            .map(|t| TrustedPublisher { id: t.id.clone() }),
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Fetches packuments from one registry.
///
/// This is the proxy acting on its own behalf, which is separate from the bytes it
/// forwards to a client. It exists so the policy engine can ask for the full document
/// when an install only ever requests the abbreviated one.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    registry: String,
    /// Ceiling on what decompression may produce, as for the proxy's own bodies.
    max_bytes: usize,
}

impl Client {
    /// `registry` is a base URL such as `https://registry.npmjs.org`. A trailing slash
    /// is accepted and trimmed.
    pub fn new(http: reqwest::Client, registry: impl Into<String>) -> Self {
        let registry = registry.into();
        Self {
            http,
            registry: registry.trim_end_matches('/').to_owned(),
            max_bytes: crate::env::DEFAULT_MAX_PACKUMENT_BYTES,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The packument URL for a package.
    ///
    /// A scoped name is sent as `@scope%2Fname`, which is the form npm's own client
    /// uses. The unencoded `@scope/name` also resolves, but only because the registry
    /// tolerates it, and the encoded form survives being embedded in a path by anything
    /// that does not know npm's naming.
    pub fn packument_url(&self, key: &PackageKey) -> String {
        let name = key.registry_name();
        match name.split_once('/') {
            Some((scope, rest)) => format!("{}/{scope}%2F{rest}", self.registry),
            None => format!("{}/{name}", self.registry),
        }
    }

    /// Fetch and normalise a packument.
    ///
    /// Asks for gzip and decodes it here. reqwest's `gzip` feature is off crate-wide, so
    /// that the proxy can forward response bodies byte for byte, which means reqwest will
    /// not decompress for this client either. Doing it explicitly is what makes the
    /// request affordable: measured over the 69 packages of an `express` tree, the
    /// packuments are 1.59 MB uncompressed and 0.52 MB gzipped, and `npm ci` makes this
    /// request once per package because it asks for no packuments of its own.
    pub async fn packument(
        &self,
        key: &PackageKey,
        detail: PackumentDetail,
    ) -> Result<Result<NormalizedPackument, NormalizeError>, FetchError> {
        let accept = match detail {
            PackumentDetail::Abbreviated => ABBREVIATED_ACCEPT,
            PackumentDetail::Full => FULL_ACCEPT,
        };

        let response = self
            .http
            .get(self.packument_url(key))
            .header(reqwest::header::ACCEPT, accept)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }

        // A registry is free to ignore the request and send identity, which decodes to
        // itself.
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;

        match crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes) {
            Ok(decoded) => Ok(normalize_packument(&decoded, detail)),
            Err(e) => Err(FetchError::Undecodable(e)),
        }
    }

    /// Fetch the full packument and read only its `time` map.
    ///
    /// A request the client never made, and the only way to learn a publish date. See
    /// [`parse_publish_times`] for why there is no cheaper source.
    pub async fn publish_times(
        &self,
        key: &PackageKey,
    ) -> Result<Result<BTreeMap<String, jiff::Timestamp>, NormalizeError>, FetchError> {
        let response = self
            .http
            .get(self.packument_url(key))
            .header(reqwest::header::ACCEPT, FULL_ACCEPT)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }

        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;

        match crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes) {
            Ok(decoded) => Ok(parse_publish_times(&decoded)),
            Err(e) => Err(FetchError::Undecodable(e)),
        }
    }
}

/// A registry request's value, or what went wrong: `<what> could not be fetched: ...` when
/// the request failed, and `<what> could not be read: ...` when the body did not parse.
pub fn fetched<T>(
    result: Result<Result<T, NormalizeError>, FetchError>,
    what: &str,
) -> Result<T, String> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{what} could not be read: {e}")),
        Err(e) => Err(format!("{what} could not be fetched: {e}")),
    }
}

/// Only the `time` map, out of a full packument.
///
/// npm publishes version timestamps in the full document and nowhere else. The
/// abbreviated document that `npm install` asks for has no `time` map at all, and the
/// registry serves no projection of one: `?fields=time` returns the whole document
/// unchanged and `/<package>/time` is a 404, both checked against registry.npmjs.org.
///
/// So reading a publish date means fetching the full document, which is 1.7x to 3.6x the
/// abbreviated one on eight packages measured, and 15.7 MB for typescript. This parses
/// only the map rather than normalising, because building 3,823 records to read one field
/// per version is the part worth not doing.
#[derive(Deserialize)]
struct WireTimes {
    #[serde(default)]
    time: BTreeMap<String, String>,
}

/// When each version was published, keyed by version.
///
/// `created` and `modified` share the map and describe the package rather than a version,
/// so they are dropped: npm's own semver parsing rejects both as version names.
pub fn parse_publish_times(json: &[u8]) -> Result<BTreeMap<String, jiff::Timestamp>, NormalizeError> {
    let wire: WireTimes = serde_json::from_slice(json).map_err(NormalizeError::Json)?;
    Ok(wire
        .time
        .into_iter()
        .filter(|(key, _)| key != "created" && key != "modified")
        .filter_map(|(version, raw)| Some((version, raw.parse::<jiff::Timestamp>().ok()?)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
        std::fs::read(format!("{path}{name}")).expect("fixture is missing")
    }

    fn normalize(name: &str, detail: PackumentDetail) -> NormalizedPackument {
        normalize_packument(&fixture(name), detail).expect("fixture should normalise")
    }

    #[test]
    fn publish_times_are_read_without_normalising() {
        let times = parse_publish_times(&fixture("lodash-4.17.21.full.json"))
            .expect("the full fixture carries a time map");

        assert_eq!(
            times.get("4.17.21").map(|t| t.to_string()),
            Some("2021-02-20T15:42:16.891Z".to_owned())
        );
    }

    /// `created` and `modified` sit in the same map and describe the package. A version
    /// named either would be rejected by npm's own semver parsing, so dropping them
    /// cannot lose a real version.
    #[test]
    fn the_package_level_timestamps_are_not_versions() {
        let times = parse_publish_times(
            br#"{"time":{"created":"2011-01-01T00:00:00.000Z",
                 "modified":"2021-01-01T00:00:00.000Z","1.0.0":"2012-06-01T00:00:00.000Z"}}"#,
        )
        .expect("should parse");

        assert_eq!(times.keys().collect::<Vec<_>>(), ["1.0.0"]);
    }

    /// The abbreviated document has no `time` map at all, which is why the full one has
    /// to be fetched.
    #[test]
    fn the_abbreviated_document_yields_no_times() {
        let times = parse_publish_times(&fixture("lodash-4.17.21.abbrev.json"))
            .expect("should parse");

        assert!(times.is_empty());
    }

    #[test]
    fn an_unparseable_timestamp_drops_that_version_rather_than_the_document() {
        let times = parse_publish_times(
            br#"{"time":{"1.0.0":"not a timestamp","1.0.1":"2012-06-01T00:00:00.000Z"}}"#,
        )
        .expect("should parse");

        assert_eq!(times.keys().collect::<Vec<_>>(), ["1.0.1"]);
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error() {
        assert!(parse_publish_times(b"<html>").is_err());
    }

    /// Nothing may be dropped quietly. A version the normaliser cannot read has to be
    /// visible, because a version that disappears is a version no policy gates.
    fn assert_nothing_skipped(p: &NormalizedPackument) {
        assert!(
            p.skipped.is_empty(),
            "unexpectedly skipped: {:?}",
            p.skipped
        );
    }

    #[test]
    fn abbreviated_carries_artifact_and_provenance_but_no_publish_time() {
        let p = normalize("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
        assert_nothing_skipped(&p);
        assert_eq!(p.key.registry_name(), "lodash");

        let r = p.version("4.17.21").expect("version 4.17.21");
        assert_eq!(
            r.artifact.url,
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        assert!(
            r.artifact
                .integrity
                .as_deref()
                .unwrap()
                .starts_with("sha512-")
        );
        assert_eq!(
            r.artifact.legacy_sha1.as_deref(),
            Some("679591c564c3bffaae8454cf0b3df370c3d6911c")
        );
        assert!(!r.has_install_scripts);

        assert!(r.published_at.is_none(), "abbreviated has no `time` map");
        assert!(r.maintainers.is_none());
        assert!(r.repository.is_none());
        assert!(r.may_be_incomplete());
    }

    /// The fields the full document adds, and the reason the proxy would ever fetch it.
    #[test]
    fn full_adds_publish_time_maintainers_and_repository() {
        let p = normalize("lodash-4.17.21.full.json", PackumentDetail::Full);
        assert_nothing_skipped(&p);

        let r = p.version("4.17.21").expect("version 4.17.21");
        assert_eq!(
            r.published_at.map(|t| t.to_string()).as_deref(),
            Some("2021-02-20T15:42:16.891Z")
        );
        let maintainers = r.maintainers.as_ref().expect("full carries maintainers");
        assert!(maintainers.iter().any(|m| m.name == "jdalton"));
        let repo = r.repository.as_ref().expect("full carries repository");
        assert_eq!(repo.url, "git+https://github.com/lodash/lodash.git");
        assert_eq!(repo.kind.as_deref(), Some("git"));
        assert!(!r.may_be_incomplete());
    }

    /// `dist-tags.latest` is kept as a string and never resolved into a record here.
    /// The lodash fixture is the case: it tags 4.18.1 as latest while carrying only
    /// 4.17.21 in `versions`, and a resolver that assumed the tag names a present
    /// version would panic or invent one.
    #[test]
    fn dist_tag_latest_may_name_a_version_the_document_does_not_carry() {
        let p = normalize("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
        assert_eq!(p.latest.as_deref(), Some("4.18.1"));
        assert!(p.version("4.18.1").is_none());
        assert_eq!(p.records.len(), 1);
    }

    /// `created` and `modified` share the `time` map with real versions and are package
    /// metadata. Reading either as a publish time would date every version to the same
    /// instant.
    #[test]
    fn time_map_metadata_keys_do_not_become_versions() {
        let p = normalize("lodash-4.17.21.full.json", PackumentDetail::Full);
        assert_eq!(p.records.len(), 1);
        assert!(p.version("created").is_none());
        assert!(p.version("modified").is_none());
    }

    /// The pairing is the point of the fixtures: the same package read both ways must
    /// agree on the install-script question, which each document answers by a different
    /// route.
    #[test]
    fn install_script_detection_agrees_across_both_documents() {
        for (abbrev, full, expected) in [
            (
                "lodash-4.17.21.abbrev.json",
                "lodash-4.17.21.full.json",
                false,
            ),
            (
                "esbuild-0.28.2.abbrev.json",
                "esbuild-0.28.2.full.json",
                true,
            ),
            (
                "@babel_traverse-8.0.5.abbrev.json",
                "@babel_traverse-8.0.5.full.json",
                false,
            ),
            (
                "sigstore-5.0.0.abbrev.json",
                "sigstore-5.0.0.full.json",
                false,
            ),
        ] {
            let a = normalize(abbrev, PackumentDetail::Abbreviated);
            let f = normalize(full, PackumentDetail::Full);
            for (x, name) in [(&a, abbrev), (&f, full)] {
                let r = x.records.first().expect("one version per fixture");
                assert_eq!(
                    r.has_install_scripts, expected,
                    "{name} disagreed on has_install_scripts"
                );
            }
        }
    }

    /// The flag is answerable from either document; the bodies are full-only.
    #[test]
    fn script_bodies_are_full_only_and_limited_to_install_hooks() {
        let abbrev = normalize("esbuild-0.28.2.abbrev.json", PackumentDetail::Abbreviated);
        let r = abbrev.version("0.28.2").unwrap();
        assert!(r.has_install_scripts);
        assert!(r.install_scripts.is_none());

        let full = normalize("esbuild-0.28.2.full.json", PackumentDetail::Full);
        let r = full.version("0.28.2").unwrap();
        let scripts = r.install_scripts.as_ref().expect("full carries bodies");
        assert_eq!(
            scripts.get("postinstall").map(String::as_str),
            Some("node install.js")
        );
        assert!(
            !scripts.contains_key("build"),
            "only install hooks belong here; the rest never run on install"
        );
    }

    /// Identity comes from the document's `name`, and a scoped name has to survive the
    /// trip into a purl. This is the case most likely to regress, because npm and OSV
    /// each write scopes differently.
    #[test]
    fn scoped_name_round_trips_from_document_to_purl() {
        let p = normalize(
            "@babel_traverse-8.0.5.abbrev.json",
            PackumentDetail::Abbreviated,
        );
        assert_eq!(p.key.registry_name(), "@babel/traverse");
        assert_eq!(p.key.namespace(), Some("@babel"));
        assert_eq!(p.key.name(), "traverse");

        let r = p.version("8.0.5").expect("version 8.0.5");
        assert_eq!(r.package.to_string(), "pkg:npm/%40babel/traverse@8.0.5");
    }

    /// Both documents carry attestations and signatures, so provenance does not depend
    /// on fetching the full packument.
    #[test]
    fn provenance_is_present_in_both_documents() {
        for (name, detail) in [
            ("sigstore-5.0.0.abbrev.json", PackumentDetail::Abbreviated),
            ("sigstore-5.0.0.full.json", PackumentDetail::Full),
        ] {
            let p = normalize(name, detail);
            let r = p.version("5.0.0").expect("version 5.0.0");
            assert_eq!(
                r.provenance.attestation_url.as_deref(),
                Some("https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0"),
                "{name}"
            );
            assert_eq!(
                r.provenance.predicate_type.as_deref(),
                Some("https://slsa.dev/provenance/v1"),
                "{name}"
            );
            assert_eq!(r.provenance.registry_signatures.len(), 1, "{name}");
            assert!(
                r.provenance.registry_signatures[0]
                    .key_id
                    .starts_with("SHA256:"),
                "{name}"
            );
        }
    }

    /// `trustedPublisher` says a CI identity published the version rather than a
    /// long-lived user token. It is in `_npmUser`, which the abbreviated document omits.
    #[test]
    fn trusted_publisher_is_full_only() {
        let abbrev = normalize("sigstore-5.0.0.abbrev.json", PackumentDetail::Abbreviated);
        assert!(
            abbrev
                .version("5.0.0")
                .unwrap()
                .provenance
                .trusted_publisher
                .is_none()
        );

        let full = normalize("sigstore-5.0.0.full.json", PackumentDetail::Full);
        let publisher = full
            .version("5.0.0")
            .unwrap()
            .provenance
            .trusted_publisher
            .as_ref()
            .expect("full carries _npmUser.trustedPublisher");
        assert_eq!(publisher.id, "github");
    }

    /// A monorepo package points at a subdirectory of its repository. Without it, source
    /// diffing compares the wrong tree.
    #[test]
    fn repository_directory_is_kept_for_monorepo_packages() {
        let p = normalize("@babel_traverse-8.0.5.full.json", PackumentDetail::Full);
        let repo = p.version("8.0.5").unwrap().repository.clone().unwrap();
        assert_eq!(repo.url, "https://github.com/babel/babel.git");
        assert_eq!(repo.directory.as_deref(), Some("packages/babel-traverse"));
    }

    /// npm accepts the shorthand string form. The object form is what registries
    /// normally serve, and both have to land in the same type.
    #[test]
    fn repository_parses_both_string_and_object_forms() {
        let object: Repository =
            serde_json::from_str(r#"{"type":"git","url":"git+https://x/y.git","extra":1}"#)
                .unwrap();
        assert_eq!(object.url, "git+https://x/y.git");
        assert_eq!(object.kind.as_deref(), Some("git"));

        let shorthand: Repository = serde_json::from_str(r#""github:user/repo""#).unwrap();
        assert_eq!(shorthand.url, "github:user/repo");
        assert_eq!(shorthand.kind, None);

        let no_url = serde_json::from_str::<Repository>(r#"{"type":"git"}"#);
        assert!(
            no_url.is_err(),
            "an object without a url is not a repository"
        );
    }

    /// A registry adding a field must not break an install passing through the proxy.
    /// This is the opposite of the policy loader, which rejects unknown keys.
    #[test]
    fn unknown_fields_are_ignored_rather_than_fatal() {
        let body = br#"{
            "name": "widget",
            "dist-tags": {"latest": "1.0.0"},
            "somethingNpmAddedLater": {"nested": true},
            "versions": {
                "1.0.0": {
                    "name": "widget",
                    "version": "1.0.0",
                    "brandNewField": 42,
                    "dist": {
                        "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
                        "integrity": "sha512-AAAA",
                        "futureDigest": "blake3-zzz"
                    }
                }
            }
        }"#;
        let p = normalize_packument(body, PackumentDetail::Abbreviated).expect("should parse");
        assert_nothing_skipped(&p);
        assert_eq!(p.records.len(), 1);
    }

    /// A version with no artifact cannot be fetched, hashed or gated, so it produces no
    /// record. It has to be reported rather than dropped.
    #[test]
    fn a_version_without_a_tarball_is_skipped_and_reported() {
        let body = br#"{
            "name": "widget",
            "versions": {
                "1.0.0": {"version": "1.0.0", "dist": {"integrity": "sha512-AAAA"}},
                "1.0.1": {"version": "1.0.1"},
                "1.0.2": {"version": "1.0.2", "dist": {
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.2.tgz"
                }}
            }
        }"#;
        let p = normalize_packument(body, PackumentDetail::Abbreviated).expect("should parse");
        assert_eq!(p.records.len(), 1);
        assert_eq!(
            p.version("1.0.2").map(|r| r.artifact.url.as_str()).unwrap(),
            "https://registry.npmjs.org/widget/-/widget-1.0.2.tgz"
        );
        assert_eq!(
            p.skipped,
            vec![
                SkippedVersion {
                    version: "1.0.0".into(),
                    reason: "version has no `dist.tarball`".into(),
                },
                SkippedVersion {
                    version: "1.0.1".into(),
                    reason: "version has no `dist` object".into(),
                },
            ]
        );
    }

    /// A body the normaliser cannot read is our gap, not an upstream outage. The error
    /// type keeps it separate from a transport failure so the proxy never answers 502
    /// for it.
    #[test]
    fn malformed_bodies_are_a_normalize_error_not_a_fetch_error() {
        assert!(matches!(
            normalize_packument(b"not json", PackumentDetail::Abbreviated),
            Err(NormalizeError::Json(_))
        ));
        assert!(matches!(
            normalize_packument(br#"{"versions":{}}"#, PackumentDetail::Abbreviated),
            Err(NormalizeError::Json(_)),
        ));
    }

    /// The scoped form npm's own client sends. `@scope/name` also resolves, but only
    /// because the registry tolerates it.
    #[test]
    fn packument_urls_encode_the_scope_separator() {
        let client = Client::new(reqwest::Client::new(), "https://registry.npmjs.org/");
        let key = |n: &str| PackageKey::from_registry_name(Ecosystem::Npm, n).unwrap();

        assert_eq!(
            client.packument_url(&key("lodash")),
            "https://registry.npmjs.org/lodash"
        );
        assert_eq!(
            client.packument_url(&key("@babel/traverse")),
            "https://registry.npmjs.org/@babel%2Ftraverse"
        );
    }

    /// The transport half, against the real registry. Ignored by default: `cargo test`
    /// must not depend on the network.
    ///
    /// Run with `cargo test --lib -- --ignored npm::tests::live`.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org"]
    async fn live_registry_fetch_returns_both_documents() {
        let client = Client::new(reqwest::Client::new(), DEFAULT_REGISTRY);
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "@babel/traverse").unwrap();

        let abbrev = client
            .packument(&key, PackumentDetail::Abbreviated)
            .await
            .expect("registry should answer")
            .expect("abbreviated packument should normalise");
        assert_eq!(abbrev.key, key, "scoped name survived the URL round trip");
        assert!(!abbrev.records.is_empty());
        assert!(abbrev.skipped.is_empty(), "skipped: {:?}", abbrev.skipped);
        assert!(
            abbrev.records.iter().all(|r| r.published_at.is_none()),
            "the abbreviated document carries no `time` map"
        );

        let full = client
            .packument(&key, PackumentDetail::Full)
            .await
            .expect("registry should answer")
            .expect("full packument should normalise");
        assert!(
            full.records.iter().any(|r| r.published_at.is_some()),
            "the full document is fetched precisely for publish times"
        );
        assert!(
            full.records.iter().any(|r| r.repository.is_some()),
            "the full document is fetched precisely for the repository"
        );
    }

    /// The proxy asks for gzip and decodes it, because reqwest's `gzip` feature is off
    /// crate-wide so that bodies can be forwarded byte for byte. `npm ci` makes this
    /// request once per package, so the difference is the primary CI path: measured over
    /// the 69 packages of an `express` tree, 1.59 MB uncompressed against 0.52 MB gzipped.
    #[tokio::test]
    async fn the_client_asks_for_gzip_and_decodes_it() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let compressed = crate::http::gzip(&body).unwrap();
        let seen: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
        let recorder = seen.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move |headers: axum::http::HeaderMap| {
                let seen = recorder.clone();
                let compressed = compressed.clone();
                async move {
                    *seen.lock().unwrap() = headers
                        .get(axum::http::header::ACCEPT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    (
                        [
                            (
                                axum::http::header::CONTENT_TYPE,
                                "application/vnd.npm.install-v1+json",
                            ),
                            (axum::http::header::CONTENT_ENCODING, "gzip"),
                        ],
                        compressed,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let packument = client
            .packument(&key, PackumentDetail::Abbreviated)
            .await
            .expect("server answered")
            .expect("gzipped body should normalise");

        assert_eq!(seen.lock().unwrap().as_deref(), Some("gzip"));
        assert_eq!(packument.records.len(), 1);
    }

    /// A registry is free to ignore the request and send identity, which has to work too.
    #[tokio::test]
    async fn an_identity_response_still_normalises() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/vnd.npm.install-v1+json",
                        )],
                        body,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        assert!(
            client
                .packument(&key, PackumentDetail::Abbreviated)
                .await
                .expect("server answered")
                .is_ok()
        );
    }

    /// A body past the limit is a fetch failure with its own kind, not a normalisation
    /// failure: the bytes never became a document to model.
    #[tokio::test]
    async fn a_body_past_the_limit_is_a_fetch_error() {
        use axum::routing::get;
        let body = fixture("lodash-4.17.21.abbrev.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/lodash",
            get(move || {
                let body = body.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/vnd.npm.install-v1+json",
                        )],
                        body,
                    )
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client =
            Client::new(reqwest::Client::new(), format!("http://{addr}")).with_max_bytes(16);
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        let result = client.packument(&key, PackumentDetail::Abbreviated).await;
        assert!(
            matches!(result, Err(FetchError::Undecodable(_))),
            "{result:?}"
        );
        let Err(e) = result else { unreachable!() };
        assert!(e.to_string().contains("could not be decoded"), "got: {e}");
        assert!(std::error::Error::source(&e).is_some());
    }

    /// A package that does not exist is a status, not a transport failure, and not a
    /// normalisation failure. The three stay separate so the proxy can answer 404 rather
    /// than 502.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org"]
    async fn live_missing_package_is_a_status_error() {
        let client = Client::new(reqwest::Client::new(), DEFAULT_REGISTRY);
        let key = PackageKey::from_registry_name(
            Ecosystem::Npm,
            "waharoa-package-that-should-never-exist-9f3a",
        )
        .unwrap();

        match client.packument(&key, PackumentDetail::Abbreviated).await {
            Err(FetchError::Status(s)) => assert_eq!(s.as_u16(), 404),
            other => panic!("expected a 404 status error, got {other:?}"),
        }
    }

    /// Fixtures are curated, so they only prove the normaliser handles what was chosen
    /// for it. This runs it over whole real packuments instead.
    ///
    /// Compiled out under `cfg(coverage)`, which `make coverage` sets, along with the
    /// two live tests below. None of them run in a coverage build, and counting the
    /// body of a test that cannot run reports a gap in the test suite that is not one.
    ///
    /// Ignored by default because it needs a corpus on disk. Populate one per document
    /// kind and point the two environment variables at them:
    ///
    /// ```text
    /// curl -H "Accept: application/vnd.npm.install-v1+json" \
    ///     https://registry.npmjs.org/typescript > abbrev/typescript.json
    /// curl -H "Accept: application/json" \
    ///     https://registry.npmjs.org/typescript > full/typescript.json
    /// cargo test --lib -- --ignored --nocapture
    /// ```
    ///
    /// with [`crate::env::NPM_CORPUS`] set to `abbrev` and [`crate::env::NPM_CORPUS_FULL`]
    /// to `full`.
    ///
    /// It fails on any skipped version. A registry shape the normaliser cannot read is
    /// exactly what fixtures will not surface.
    #[cfg(not(coverage))]
    #[test]
    #[ignore = "needs a corpus directory of packuments; see the doc comment"]
    fn real_packuments_normalise_without_skipping_anything() {
        use crate::env;
        let environment = env::process();
        let corpora: Vec<(String, PackumentDetail)> = [
            (environment.npm_corpus(), PackumentDetail::Abbreviated),
            (environment.npm_corpus_full(), PackumentDetail::Full),
        ]
        .into_iter()
        .filter_map(|(dir, detail)| {
            let dir = dir.unwrap_or_else(|e| panic!("{e}"))?;
            Some((dir.to_string_lossy().into_owned(), detail))
        })
        .collect();
        assert!(
            !corpora.is_empty(),
            "set {} and/or {} to corpus directories",
            env::NPM_CORPUS,
            env::NPM_CORPUS_FULL
        );

        for (dir, detail) in &corpora {
            check_corpus(dir, *detail);
        }

        // With both corpora present, the pairing is checkable at corpus scale: the same
        // version read two ways must agree on whether installing it runs a script, a
        // question each document answers by a different route.
        if corpora.len() == 2 {
            cross_check_install_scripts(&corpora[0].0, &corpora[1].0);
        }
    }

    #[cfg(not(coverage))]
    fn cross_check_install_scripts(abbrev_dir: &str, full_dir: &str) {
        let load = |dir: &str, file: &std::path::Path, detail| {
            let body = std::fs::read(std::path::Path::new(dir).join(file)).ok()?;
            normalize_packument(&body, detail).ok()
        };

        let mut pairs = 0usize;
        let mut disagreements = Vec::new();

        for entry in std::fs::read_dir(abbrev_dir).expect("abbreviated corpus") {
            let name = entry.expect("readable entry").file_name();
            let file = std::path::Path::new(&name);
            if file.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let (Some(a), Some(f)) = (
                load(abbrev_dir, file, PackumentDetail::Abbreviated),
                load(full_dir, file, PackumentDetail::Full),
            ) else {
                continue;
            };

            for record in &a.records {
                let Some(other) = f.version(record.package.version()) else {
                    continue;
                };
                pairs += 1;
                if record.has_install_scripts != other.has_install_scripts {
                    disagreements.push(format!(
                        "{}: abbreviated={} full={}",
                        record.package, record.has_install_scripts, other.has_install_scripts
                    ));
                }
            }
        }

        println!("compared has_install_scripts across {pairs} version pairs");
        assert!(pairs > 0, "no packages appeared in both corpora");
        assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    }

    #[cfg(not(coverage))]
    fn check_corpus(dir: &str, detail: PackumentDetail) {
        let mut packages = 0usize;
        let mut versions = 0usize;
        let mut rewrote = 0usize;
        let mut failures = Vec::new();

        for entry in std::fs::read_dir(dir).expect("corpus directory should be readable") {
            let path = entry.expect("readable entry").path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let body = std::fs::read(&path).expect("readable packument");
            match normalize_packument(&body, detail) {
                Ok(p) => {
                    packages += 1;
                    versions += p.records.len();
                    for skip in &p.skipped {
                        failures.push(format!(
                            "{}: {} skipped: {}",
                            path.display(),
                            skip.version,
                            skip.reason
                        ));
                    }
                    for record in &p.records {
                        assert_eq!(
                            record.package.key(),
                            &p.key,
                            "{}: version key drifted from the document name",
                            path.display()
                        );

                        // Every real tarball URL has to classify, and has to classify
                        // to the same package the document names.
                        let url_path = record
                            .artifact
                            .url
                            .split_once("://")
                            .and_then(|(_, rest)| rest.split_once('/'))
                            .map(|(_, p)| format!("/{p}"))
                            .unwrap_or_default();
                        // Every artifact a real registry publishes has to be one the
                        // proxy will see, or verification never gets a chance.
                        assert_eq!(
                            bypassing_origin(&record.artifact.url, &default_origins()),
                            None,
                            "{}: artifact published off the registry",
                            record.artifact.url
                        );
                        match classify_path(&url_path) {
                            RequestTarget::Tarball { key, .. } => assert_eq!(
                                key, p.key,
                                "{url_path}: classified as a different package"
                            ),
                            other => failures
                                .push(format!("{url_path}: expected a tarball, got {other:?}")),
                        }
                    }
                }
                Err(e) => failures.push(format!("{}: {e}", path.display())),
            }

            // Every real document has to survive the rewrite, and putting the URLs back
            // has to give the original bytes. That is the property re-serialising into a
            // JSON value could not offer.
            if let Ok(p) = normalize_packument(&body, detail) {
                let artifacts: Vec<String> =
                    p.records.iter().map(|r| r.artifact.url.clone()).collect();
                // Rewriting to the origin the URLs already name: every artifact is
                // found and replaced, and the result has to be the original bytes. That
                // exercises the whole copy path and checks that nothing but a URL moves.
                match rewrite_artifact_origins(
                    &body,
                    artifacts.iter().map(String::as_str),
                    &default_origins(),
                    DEFAULT_REGISTRY,
                ) {
                    Ok(out) => {
                        rewrote += 1;
                        assert_eq!(
                            out.rewritten,
                            artifacts.len(),
                            "{}: not every artifact URL was found",
                            path.display()
                        );
                        assert_eq!(
                            out.body,
                            body,
                            "{}: the rewrite changed something other than a URL",
                            path.display()
                        );
                    }
                    Err(e) => failures.push(format!("{}: rewrite failed: {e}", path.display())),
                }
            }
        }

        println!("{dir}: normalised {versions} versions across {packages} packages ({detail:?})");
        println!("{dir}: rewrote and restored {rewrote} documents byte for byte");
        assert!(packages > 0, "corpus at {dir} held no .json files");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// npm did not always publish SRI digests. `event-stream@0.9.1` (2012) carries only
    /// `dist.shasum`, so a record can exist with no `integrity` at all, and the policy
    /// engine has to be able to tell that apart from a strong digest it simply did not
    /// read.
    #[test]
    fn a_pre_sri_version_has_a_sha1_and_no_integrity() {
        let p = normalize(
            "event-stream-0.9.1.abbrev.json",
            PackumentDetail::Abbreviated,
        );
        assert_nothing_skipped(&p);

        let r = p.version("0.9.1").expect("version 0.9.1");
        assert_eq!(r.artifact.integrity, None);
        assert_eq!(
            r.artifact.legacy_sha1.as_deref(),
            Some("d13bd543138154f503146878ba500c005eb9d5cb")
        );
        assert_eq!(r.artifact.file_count, None);
        assert_eq!(r.artifact.unpacked_size, None);
    }

    /// `rimraf@1.0.0` is the shorthand string form in the wild, and its document also
    /// gives the package-level `repository` as an object. The version's own value is
    /// what was true at publish time, so it has to win.
    #[test]
    fn version_repository_overrides_the_package_level_one() {
        let p = normalize("rimraf-1.0.0.full.json", PackumentDetail::Full);
        let repo = p
            .version("1.0.0")
            .expect("version 1.0.0")
            .repository
            .clone()
            .expect("full carries repository");

        assert_eq!(repo.url, "git://github.com/isaacs/rimraf.git");
        assert_eq!(repo.kind, None, "the shorthand form states no type");
        assert_ne!(
            repo.url, "git+ssh://git@github.com/isaacs/rimraf.git",
            "the package-level object must not shadow the version's own value"
        );
    }

    /// A version whose only lifecycle entry is `test` runs nothing on install. `prepare`
    /// and `prepublish` are likewise excluded: they run when building from git or
    /// publishing, not when installing a registry tarball.
    #[test]
    fn non_install_lifecycle_scripts_do_not_set_the_flag() {
        let p = normalize("rimraf-1.0.0.full.json", PackumentDetail::Full);
        let r = p.version("1.0.0").expect("version 1.0.0");
        assert!(!r.has_install_scripts);
        assert_eq!(
            r.install_scripts.as_ref().map(BTreeMap::len),
            Some(0),
            "the document had scripts, none of which run on install"
        );

        let body = br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
            "scripts":{"prepare":"tsc","prepublish":"tsc","test":"jest"},
            "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}"#;
        let p = normalize_packument(body, PackumentDetail::Full).unwrap();
        assert!(!p.version("1.0.0").unwrap().has_install_scripts);
    }

    /// The transport, against a server on localhost rather than the registry. This is
    /// what covers `Client::packument`: the live tests below are ignored by default, so
    /// without this the fetch path is exercised by nothing that runs in CI.
    #[test]
    fn a_failed_request_and_an_unreadable_body_are_told_apart() {
        let json = serde_json::from_str::<serde_json::Value>("{").expect_err("not JSON");
        let unreadable: Result<Result<(), NormalizeError>, FetchError> =
            Ok(Err(NormalizeError::Json(json)));
        let read = super::fetched(unreadable, "packument").expect_err("unreadable");
        assert!(
            read.starts_with("packument could not be read: packument is not valid JSON"),
            "{read}"
        );

        let missing: Result<Result<(), NormalizeError>, FetchError> =
            Err(FetchError::Status(reqwest::StatusCode::NOT_FOUND));
        assert_eq!(
            super::fetched(missing, "publish times"),
            Err("publish times could not be fetched: registry answered 404 Not Found".to_owned())
        );

        let answered: Result<Result<u8, NormalizeError>, FetchError> = Ok(Ok(7));
        assert_eq!(super::fetched(answered, "packument"), Ok(7));
    }

    mod transport {
        use super::*;
        use axum::Router;
        use axum::http::StatusCode;
        use axum::routing::get;

        /// Serve fixed responses on an ephemeral port and return the base URL.
        ///
        /// The server lives for the process; the test finishes long before that matters,
        /// and a handle to shut it down would only be a handle nothing awaits.
        async fn serve(router: Router) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("should bind an ephemeral port");
            let addr = listener.local_addr().expect("bound socket has an address");
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            format!("http://{addr}")
        }

        fn key(name: &str) -> PackageKey {
            PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
        }

        /// The whole path: request, Accept header, body, records. The handler asserts
        /// the header, because sending the wrong one silently yields the other document
        /// and every absent field would then be mislabelled.
        #[tokio::test]
        async fn fetches_and_normalises_a_packument() {
            let body = std::str::from_utf8(&fixture("lodash-4.17.21.abbrev.json"))
                .expect("fixture is utf-8")
                .to_owned();

            let base = serve(Router::new().route(
                "/lodash",
                get(|headers: axum::http::HeaderMap| async move {
                    assert_eq!(
                        headers.get("accept").map(|v| v.to_str().unwrap()),
                        Some(ABBREVIATED_ACCEPT),
                        "an install requests the abbreviated document"
                    );
                    body
                }),
            ))
            .await;

            let client = Client::new(reqwest::Client::new(), base);
            let p = client
                .packument(&key("lodash"), PackumentDetail::Abbreviated)
                .await
                .expect("server answered")
                .expect("body normalised");
            assert_eq!(p.key.registry_name(), "lodash");
            assert_eq!(p.records.len(), 1);
        }

        /// A scoped name has to reach the server percent-encoded and still route.
        #[tokio::test]
        async fn fetches_a_scoped_package() {
            let body = std::str::from_utf8(&fixture("@babel_traverse-8.0.5.abbrev.json"))
                .expect("fixture is utf-8")
                .to_owned();
            let base =
                serve(Router::new().route("/@babel%2Ftraverse", get(move || async move { body })))
                    .await;

            let client = Client::new(reqwest::Client::new(), base);
            let p = client
                .packument(&key("@babel/traverse"), PackumentDetail::Full)
                .await
                .expect("server answered")
                .expect("body normalised");
            assert_eq!(p.key.registry_name(), "@babel/traverse");
        }

        /// The full document is a different Accept header, and asking for the wrong one
        /// is how `published_at == None` starts meaning the wrong thing.
        #[tokio::test]
        async fn full_detail_requests_the_full_document() {
            let base = serve(Router::new().route(
                "/lodash",
                get(|headers: axum::http::HeaderMap| async move {
                    assert_eq!(
                        headers.get("accept").map(|v| v.to_str().unwrap()),
                        Some(FULL_ACCEPT)
                    );
                    r#"{"name":"lodash","versions":{}}"#
                }),
            ))
            .await;

            let client = Client::new(reqwest::Client::new(), base);
            let p = client
                .packument(&key("lodash"), PackumentDetail::Full)
                .await
                .expect("server answered")
                .expect("body normalised");
            assert!(p.records.is_empty());
        }

        /// An unknown package is a status, not a transport failure. The proxy has to be
        /// able to pass 404 through rather than turning it into 502.
        #[tokio::test]
        async fn a_missing_package_is_a_status_error() {
            let base = serve(Router::new()).await;
            let client = Client::new(reqwest::Client::new(), base);

            match client
                .packument(&key("nonexistent"), PackumentDetail::Abbreviated)
                .await
            {
                Err(FetchError::Status(s)) => assert_eq!(s, StatusCode::NOT_FOUND),
                other => panic!("expected a status error, got {other:?}"),
            }
        }

        /// A 5xx is also a status, distinct from the connection never completing.
        #[tokio::test]
        async fn an_upstream_error_is_a_status_error() {
            let base = serve(Router::new().route(
                "/lodash",
                get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "busy") }),
            ))
            .await;
            let client = Client::new(reqwest::Client::new(), base);

            match client
                .packument(&key("lodash"), PackumentDetail::Abbreviated)
                .await
            {
                Err(FetchError::Status(s)) => assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE),
                other => panic!("expected a status error, got {other:?}"),
            }
        }

        /// A registry that closes the connection without a response is a transport failure,
        /// and the outer `Result` is what carries it. This is the only branch a 502 is the
        /// right answer to.
        #[tokio::test]
        async fn a_registry_that_sends_no_response_is_a_transport_error() {
            let addr = crate::test_support::closing_server().await;

            let client = Client::new(reqwest::Client::new(), format!("http://{addr}"));
            match client
                .packument(&key("lodash"), PackumentDetail::Abbreviated)
                .await
            {
                Err(e @ FetchError::Transport(_)) => {
                    use std::error::Error as _;
                    assert!(e.to_string().contains("request failed"), "got: {e}");
                    assert!(
                        e.source().is_some(),
                        "the underlying cause has to stay reachable, not be flattened"
                    );
                }
                other => panic!("expected a transport error, got {other:?}"),
            }
        }

        /// A 200 carrying something we cannot read is the inner `Result`. The nesting is
        /// the point: the fetch succeeded, so this is our gap and not an outage.
        #[tokio::test]
        async fn a_successful_response_with_an_unreadable_body_is_a_normalize_error() {
            let base = serve(
                Router::new().route("/lodash", get(|| async { "<html>not a packument</html>" })),
            )
            .await;
            let client = Client::new(reqwest::Client::new(), base);

            let fetched = client
                .packument(&key("lodash"), PackumentDetail::Abbreviated)
                .await
                .expect("the fetch itself succeeded");
            assert!(matches!(fetched, Err(NormalizeError::Json(_))));
        }
    }

    /// Errors are read by operators, so their text is part of the interface. `source()`
    /// keeps the underlying cause reachable rather than flattened into a string.
    #[test]
    fn error_messages_name_the_problem_and_keep_their_cause() {
        use std::error::Error as _;

        let Err(json) = normalize_packument(b"not json", PackumentDetail::Abbreviated) else {
            panic!("should not parse");
        };
        assert!(json.to_string().contains("not valid JSON"), "got: {json}");
        assert!(json.source().is_some());

        let Err(name) = normalize_packument(br#"{"name":"","versions":{}}"#, PackumentDetail::Full)
        else {
            panic!("an empty name is not a package identity");
        };
        assert!(name.to_string().contains("name is unusable"), "got: {name}");
        assert!(name.source().is_some());
        assert!(matches!(name, NormalizeError::Name(_)));

        let status = FetchError::Status(reqwest::StatusCode::NOT_FOUND);
        assert!(status.to_string().contains("404"), "got: {status}");
        assert!(
            status.source().is_none(),
            "a status is the whole story; there is nothing underneath it"
        );
    }

    /// The visitor's `expecting` is what a operator sees when `repository` is neither
    /// shape, so it has to describe both.
    #[test]
    fn a_repository_of_the_wrong_type_says_what_was_expected() {
        let err =
            serde_json::from_str::<Repository>("42").expect_err("a number is not a repository");
        let message = err.to_string();
        assert!(message.contains("repository URL string"), "got: {message}");
        assert!(message.contains("object"), "got: {message}");
    }

    /// The origins a default deployment fronts.
    fn default_origins() -> ReachableOrigins {
        ReachableOrigins::new(DEFAULT_REGISTRY, std::iter::empty()).expect("valid origins")
    }

    mod origins {
        use super::*;

        const UPSTREAM: &str = "https://registry.npmjs.org";

        fn reachable(additional: &[&str]) -> ReachableOrigins {
            ReachableOrigins::new(UPSTREAM, additional.iter().copied()).expect("valid origins")
        }

        /// The upstream and the default registry are always fronted, whatever else is
        /// configured. npm rewrites `dist.tarball` to the configured registry when it
        /// names the default host, so both are reachable by construction.
        #[test]
        fn the_upstream_and_the_default_registry_are_always_included() {
            let r = ReachableOrigins::new("https://npm.corp.example", std::iter::empty()).unwrap();
            assert!(
                r.as_slice()
                    .contains(&"https://npm.corp.example".to_owned())
            );
            assert!(
                r.as_slice()
                    .contains(&"https://registry.npmjs.org".to_owned())
            );
            assert_eq!(r.as_slice().len(), 2);
        }

        /// An upstream that is already the default registry is not listed twice.
        #[test]
        fn origins_are_not_duplicated() {
            let r = ReachableOrigins::new(
                "https://registry.npmjs.org/",
                [
                    "https://registry.npmjs.org",
                    "https://registry.npmjs.org/some/path",
                ],
            )
            .unwrap();
            assert_eq!(r.as_slice(), ["https://registry.npmjs.org"]);
        }

        /// A packument naming the default registry still routes to the upstream. A
        /// private mirror publishes registry.npmjs.org URLs and is the whole reason the
        /// proxy was pointed somewhere else; fetching from npmjs.org would go around it.
        #[test]
        fn only_origins_the_operator_added_are_fetched_from_directly() {
            let r = ReachableOrigins::new("https://npm.corp.example", ["https://cdn.corp.example"])
                .unwrap();

            assert!(r.routes_directly("https://cdn.corp.example"));
            assert!(
                !r.routes_directly("https://registry.npmjs.org"),
                "the mirror serves these, not npmjs.org"
            );
            assert!(
                !r.routes_directly("https://npm.corp.example"),
                "the upstream is where a request goes by default"
            );
            assert!(!r.routes_directly("https://elsewhere.example"));
        }

        /// An origin that is already the upstream adds nothing to route to.
        #[test]
        fn re_listing_the_upstream_does_not_make_it_a_direct_route() {
            let r = ReachableOrigins::new("https://npm.corp.example", ["https://npm.corp.example"])
                .unwrap();
            assert!(!r.routes_directly("https://npm.corp.example"));
            assert_eq!(r.as_slice().len(), 2, "upstream and the default registry");
        }

        /// A CDN in front of a private registry is the case this exists for.
        #[test]
        fn an_additional_origin_makes_its_artifacts_reachable() {
            let url = "https://cdn.corp.example/w/-/w-1.0.0.tgz";
            assert_eq!(
                bypassing_origin(url, &reachable(&[])),
                Some("https://cdn.corp.example".to_owned()),
                "not configured, so the client fetches it directly"
            );
            assert_eq!(
                bypassing_origin(url, &reachable(&["https://cdn.corp.example"])),
                None,
                "configured, so the proxy serves it"
            );
        }

        /// Rewriting and the offsite report read the same set, so an origin cannot be
        /// rewritten and reported as bypassing at the same time.
        #[test]
        fn rewriting_and_the_offsite_report_agree() {
            let body = br#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                "tarball":"https://cdn.corp.example/w/-/w-1.0.0.tgz"}}}}"#;
            let p = normalize_packument(body, PackumentDetail::Abbreviated).unwrap();

            for (set, expect_rewritten, expect_offsite) in [
                (reachable(&[]), 0, 1),
                (reachable(&["https://cdn.corp.example"]), 1, 0),
            ] {
                let artifacts: Vec<&str> =
                    p.records.iter().map(|r| r.artifact.url.as_str()).collect();
                let out = rewrite_artifact_origins(body, artifacts, &set, "http://127.0.0.1:8080")
                    .expect("should rewrite");
                assert_eq!(out.rewritten, expect_rewritten);
                assert_eq!(out.left_alone, expect_offsite);
                assert_eq!(p.bypassing_origins(&set).len(), expect_offsite);
            }
        }

        /// An origin the operator names and that is silently dropped would leave them
        /// believing those artifacts are covered.
        #[test]
        fn an_unusable_origin_is_an_error_rather_than_ignored() {
            for (bad, reason) in [
                ("not a url", "not a URL"),
                ("ftp://registry.example", "scheme is not http or https"),
                ("file:///tmp", "no host"),
            ] {
                let result = ReachableOrigins::new(UPSTREAM, [bad]);
                let Err(e) = result else {
                    panic!("{bad} should not be accepted");
                };
                assert_eq!(e.reason, reason, "{bad}");
                assert!(e.to_string().contains(bad), "got: {e}");
            }
        }

        /// Blank entries come from a trailing comma in the configured list.
        #[test]
        fn blank_entries_are_skipped() {
            let r = ReachableOrigins::new(UPSTREAM, ["", "  ", "https://cdn.example"]).unwrap();
            // UPSTREAM is the default registry here, so the two collapse into one.
            assert_eq!(
                r.as_slice(),
                ["https://registry.npmjs.org", "https://cdn.example"]
            );
        }

        /// The normal case: npm rewrites a default-registry tarball URL to whatever
        /// registry is configured, so the request arrives at the proxy.
        #[test]
        fn artifacts_on_the_default_registry_come_through_the_proxy() {
            assert_eq!(
                bypassing_origin(
                    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    &reachable(&[])
                ),
                None
            );
        }

        /// A private registry serving its own artifacts is not a bypass.
        #[test]
        fn artifacts_on_the_configured_upstream_come_through_the_proxy() {
            assert_eq!(
                bypassing_origin(
                    "https://npm.corp.example/lodash/-/lodash-4.17.21.tgz",
                    &ReachableOrigins::new("https://npm.corp.example", std::iter::empty()).unwrap()
                ),
                None,
                "this is the registry the operator pointed us at"
            );
            assert_eq!(
                bypassing_origin(
                    "http://127.0.0.1:8080/x/-/x-1.0.0.tgz",
                    &ReachableOrigins::new("http://127.0.0.1:8080", std::iter::empty()).unwrap()
                ),
                None,
                "port and scheme are part of the origin, and these match"
            );
        }

        /// Any other origin is fetched directly, and the proxy sees nothing.
        #[test]
        fn any_other_origin_is_reported() {
            assert_eq!(
                bypassing_origin("https://evil.example/lodash-4.17.21.tgz", &reachable(&[])),
                Some("https://evil.example".to_owned())
            );
            assert_eq!(
                bypassing_origin(
                    "https://registry.npmjs.org.evil.example/x.tgz",
                    &reachable(&[])
                ),
                Some("https://registry.npmjs.org.evil.example".to_owned()),
                "a suffix of the real host is a different host"
            );
            assert_eq!(
                bypassing_origin(
                    "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    &reachable(&[])
                ),
                Some("http://registry.npmjs.org".to_owned()),
                "a downgrade to http is a different origin"
            );
            assert_eq!(
                bypassing_origin("https://registry.npmjs.org:8443/x.tgz", &reachable(&[])),
                Some("https://registry.npmjs.org:8443".to_owned()),
                "a different port is a different origin"
            );
        }

        /// A URL that does not parse names no origin to compare, so there is nothing to
        /// report. The version carrying it has no usable artifact either way.
        #[test]
        fn an_unparseable_url_reports_nothing() {
            assert_eq!(bypassing_origin("not a url", &reachable(&[])), None);
            assert_eq!(
                bypassing_origin("/relative/path.tgz", &reachable(&[])),
                None
            );
        }

        /// The per-document view, which is what the proxy logs.
        #[test]
        fn a_packument_reports_its_offsite_origins_with_counts() {
            let body = br#"{"name":"widget","versions":{
                "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}},
                "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://evil.example/widget-1.0.1.tgz"}},
                "1.0.2":{"version":"1.0.2","dist":{"tarball":"https://evil.example/widget-1.0.2.tgz"}},
                "1.0.3":{"version":"1.0.3","dist":{"tarball":"https://other.example/widget-1.0.3.tgz"}}}}"#;
            let p = normalize_packument(body, PackumentDetail::Abbreviated).unwrap();

            let origins = p.bypassing_origins(&reachable(&[]));
            assert_eq!(origins.len(), 2);
            assert_eq!(origins.get("https://evil.example"), Some(&2));
            assert_eq!(origins.get("https://other.example"), Some(&1));
        }

        #[test]
        fn an_ordinary_packument_reports_nothing() {
            let p = normalize("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
            assert!(p.bypassing_origins(&reachable(&[])).is_empty());
        }
    }

    mod rewriting {
        use super::*;

        const UPSTREAM: &str = "https://registry.npmjs.org";
        const PROXY: &str = "http://127.0.0.1:8080";

        fn origins(additional: &[&str]) -> ReachableOrigins {
            ReachableOrigins::new(UPSTREAM, additional.iter().copied()).expect("valid origins")
        }

        /// Normalise, then rewrite with the artifact URLs that came out of it. This is
        /// the real sequence: the rewrite never parses the document itself.
        fn rewrite_with(json: &[u8], reachable: &ReachableOrigins, base: &str) -> Rewritten {
            let p = normalize_packument(json, PackumentDetail::Abbreviated)
                .expect("fixture should normalise");
            let artifacts: Vec<String> = p.records.iter().map(|r| r.artifact.url.clone()).collect();
            rewrite_artifact_origins(json, artifacts.iter().map(String::as_str), reachable, base)
                .expect("should rewrite")
        }

        fn rewrite(json: &str) -> Rewritten {
            rewrite_with(json.as_bytes(), &origins(&[]), PROXY)
        }

        /// Only the origin moves. The path is kept so the request that comes back is one
        /// `classify_path` understands and the proxy forwards upstream unchanged.
        #[test]
        fn the_origin_changes_and_the_path_does_not() {
            let out = rewrite(
                r#"{"name":"lodash","versions":{"4.17.21":{"version":"4.17.21","dist":{
                    "tarball":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}}"#,
            );
            assert_eq!(out.rewritten, 1);
            assert_eq!(out.left_alone, 0);

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                v["versions"]["4.17.21"]["dist"]["tarball"],
                serde_json::json!("http://127.0.0.1:8080/lodash/-/lodash-4.17.21.tgz")
            );
        }

        /// `dist.integrity` is what npm checks the downloaded bytes against, and what the
        /// registry signature covers. Touching it would break both.
        #[test]
        fn integrity_and_every_other_field_survive() {
            let original = fixture("sigstore-5.0.0.abbrev.json");
            let out = rewrite_with(&original, &origins(&[]), PROXY);
            assert_eq!(out.rewritten, 1);

            let served: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            let mut expected: serde_json::Value = serde_json::from_slice(&original).unwrap();
            expected["versions"]["5.0.0"]["dist"]["tarball"] =
                served["versions"]["5.0.0"]["dist"]["tarball"].clone();
            assert_eq!(served, expected);
            assert!(
                served["versions"]["5.0.0"]["dist"]["signatures"][0]["sig"].is_string(),
                "signatures have to come through untouched"
            );
        }

        /// An origin the proxy does not front is left alone. Rewriting it would mean the
        /// proxy fetching from an arbitrary host on a client's behalf.
        #[test]
        fn unreachable_origins_are_left_alone_and_counted() {
            let out = rewrite(
                r#"{"name":"widget","versions":{
                    "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}},
                    "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://elsewhere.example/widget-1.0.1.tgz"}}}}"#,
            );
            assert_eq!(out.rewritten, 1);
            assert_eq!(out.left_alone, 1);

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                v["versions"]["1.0.1"]["dist"]["tarball"],
                serde_json::json!("https://elsewhere.example/widget-1.0.1.tgz")
            );
        }

        /// A private registry's own artifacts are reachable, so they are rewritten too.
        #[test]
        fn a_private_registrys_own_artifacts_are_rewritten() {
            let out = rewrite_with(
                br#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                    "tarball":"https://npm.corp.example/w/-/w-1.0.0.tgz"}}}}"#,
                &origins(&["https://npm.corp.example"]),
                PROXY,
            );
            assert_eq!(out.rewritten, 1);
        }

        /// A query string is part of how the artifact is addressed, so it is kept.
        #[test]
        fn a_query_string_is_preserved() {
            let out = rewrite(
                r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                    "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz?token=abc"}}}}"#,
            );
            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                v["versions"]["1.0.0"]["dist"]["tarball"],
                serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz?token=abc")
            );
        }

        /// Documents with nothing to rewrite come back intact and say so.
        #[test]
        fn documents_with_no_artifacts_are_unchanged() {
            for json in [
                r#"{"name":"w","versions":{}}"#,
                r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0"}}}"#,
                r#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{}}}}"#,
                r#"{"name":"w"}"#,
            ] {
                let out = rewrite(json);
                assert_eq!(out.rewritten, 0, "{json}");
                assert_eq!(out.left_alone, 0, "{json}");
            }
        }

        fn policy(served: &[&str], allowed: &[&str]) -> OriginPolicy {
            OriginPolicy::new(origins(served), allowed.iter().copied()).expect("valid policy")
        }

        fn filter(json: &str, policy: &OriginPolicy) -> Filtered {
            filter_refusing(json, policy, &HashSet::new())
        }

        /// The same, with versions the package policy refuses.
        fn filter_refusing(
            json: &str,
            policy: &OriginPolicy,
            refused_by_policy: &HashSet<String>,
        ) -> Filtered {
            let p = normalize_packument(json.as_bytes(), PackumentDetail::Abbreviated)
                .expect("should normalise");
            let artifacts: Vec<(String, String)> = p
                .records
                .iter()
                .map(|r| (r.package.version().to_owned(), r.artifact.url.clone()))
                .collect();
            filter_unservable_versions(
                json.as_bytes(),
                artifacts,
                policy,
                refused_by_policy,
                true,
                PROXY,
            )
            .expect("should filter")
        }

        const MIXED: &str = r#"{"name":"w","dist-tags":{"latest":"1.0.2","old":"1.0.0"},
            "versions":{
                "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}},
                "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://elsewhere.example/w-1.0.1.tgz"}},
                "1.0.2":{"version":"1.0.2","dist":{"tarball":"https://elsewhere.example/w-1.0.2.tgz"}}}}"#;

        fn refusing(versions: &[&str]) -> HashSet<String> {
            versions.iter().map(|v| (*v).to_string()).collect()
        }

        /// Decision #4's resolution half: the version is gone, so the client's own
        /// resolver picks another and nobody is told no.
        #[test]
        fn a_version_the_package_policy_refuses_is_removed() {
            let out = filter_refusing(
                MIXED,
                &policy(&["https://elsewhere.example"], &[]),
                &refusing(&["1.0.0"]),
            );

            assert_eq!(out.removed, ["1.0.0"]);
            assert_eq!(out.rewritten, 2, "the other two are kept and repointed");
            let body: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert!(body["versions"].get("1.0.0").is_none());
            assert!(body["versions"].get("1.0.1").is_some());
        }

        /// A tag naming a removed version resolves to nothing, so the tag goes too.
        #[test]
        fn a_tag_pointing_at_a_refused_version_is_dropped() {
            let out = filter_refusing(
                MIXED,
                &policy(&["https://elsewhere.example"], &[]),
                &refusing(&["1.0.2"]),
            );

            let body: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert!(
                body["dist-tags"].get("latest").is_none(),
                "`latest` named the refused version"
            );
            assert_eq!(body["dist-tags"]["old"], "1.0.0", "other tags survive");
        }

        /// The policy's answer does not depend on where the artifact lives, so a version
        /// it refuses goes whether or not the origin is one the proxy fronts.
        #[test]
        fn policy_removes_a_version_the_origin_check_would_have_kept() {
            let out = filter_refusing(MIXED, &policy(&[], &["https://elsewhere.example"]), &refusing(&["1.0.1"]));

            assert_eq!(out.removed, ["1.0.1"]);
            assert_eq!(out.allowed, 1, "1.0.2 is still allowed direct");
        }

        /// Both reasons at once, in one pass over one document.
        #[test]
        fn the_two_reasons_to_drop_a_version_compose() {
            let out = filter_refusing(MIXED, &policy(&[], &[]), &refusing(&["1.0.0"]));

            assert_eq!(
                out.removed,
                ["1.0.0", "1.0.1", "1.0.2"],
                "one by policy and two off-origin"
            );
            assert_eq!(out.rewritten, 0);
        }

        /// With the origin check off, an off-origin version stays and is left as
        /// published, and only the policy removes anything.
        #[test]
        fn keeping_off_origin_versions_still_lets_policy_remove_one() {
            let p = normalize_packument(MIXED.as_bytes(), PackumentDetail::Abbreviated)
                .expect("should normalise");
            let artifacts: Vec<(String, String)> = p
                .records
                .iter()
                .map(|r| (r.package.version().to_owned(), r.artifact.url.clone()))
                .collect();
            let out = filter_unservable_versions(
                MIXED.as_bytes(),
                artifacts,
                &policy(&[], &[]),
                &refusing(&["1.0.0"]),
                false,
                PROXY,
            )
            .expect("should filter");

            assert_eq!(out.removed, ["1.0.0"]);
            assert_eq!(out.allowed, 2, "both off-origin versions are kept as published");
        }

        /// The only control that works on an off-origin artifact: the client fetches it
        /// from whatever host the packument names, so refusing the artifact request never
        /// happens. Dropping the version is what decision #4 settles for quarantine.
        #[test]
        fn versions_the_proxy_cannot_serve_are_removed() {
            let out = filter(MIXED, &policy(&[], &[]));
            assert_eq!(out.removed, ["1.0.1", "1.0.2"]);
            assert_eq!(out.rewritten, 1);

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            let versions = v["versions"].as_object().unwrap();
            assert_eq!(versions.len(), 1);
            assert_eq!(
                versions["1.0.0"]["dist"]["tarball"],
                serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz"),
                "what is left still points at the proxy"
            );
        }

        /// Three states, not two. Before the allow list the only escape from a refusal
        /// was turning refusing off everywhere, which trades one origin's exemption for
        /// every origin's.
        #[test]
        fn an_allowed_origin_is_kept_exactly_as_published() {
            let out = filter(MIXED, &policy(&[], &["https://elsewhere.example"]));
            assert!(out.removed.is_empty(), "allowed, so nothing is removed");
            assert_eq!(out.allowed, 2);
            assert_eq!(
                out.rewritten, 1,
                "the servable one still points at the proxy"
            );

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                v["versions"]["1.0.1"]["dist"]["tarball"],
                serde_json::json!("https://elsewhere.example/w-1.0.1.tgz"),
                "left where the registry published it, which is the point of allowing it"
            );
            assert_eq!(v["dist-tags"]["latest"], serde_json::json!("1.0.2"));
        }

        /// Served, allowed and refused are distinguished, and an unparseable URL is
        /// refused under its own text: it names no origin that could be served or
        /// allowed, and an artifact that cannot be located cannot be examined.
        #[test]
        fn the_policy_distinguishes_all_three_states() {
            let p = policy(&["https://cdn.example"], &["https://allowed.example"]);
            assert_eq!(
                p.disposition("https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
                Disposition::Served
            );
            assert_eq!(
                p.disposition("https://cdn.example/a-1.0.0.tgz"),
                Disposition::Served
            );
            assert_eq!(
                p.disposition("https://allowed.example/a-1.0.0.tgz"),
                Disposition::AllowedDirect("https://allowed.example".into())
            );
            assert_eq!(
                p.disposition("https://elsewhere.example/a-1.0.0.tgz"),
                Disposition::Refused("https://elsewhere.example".into())
            );
            assert_eq!(
                p.disposition("not a url"),
                Disposition::Refused("not a url".into())
            );
        }

        /// An accepted gap has to stay countable, or it stops being reported and outlives
        /// the reason it was added.
        #[test]
        fn allowed_and_refused_origins_are_counted_separately() {
            let doc = normalize_packument(MIXED.as_bytes(), PackumentDetail::Abbreviated).unwrap();

            let (allowed, refused) = doc.unserved_origins(&policy(&[], &[]));
            assert!(allowed.is_empty());
            assert_eq!(refused.get("https://elsewhere.example"), Some(&2));

            let (allowed, refused) =
                doc.unserved_origins(&policy(&[], &["https://elsewhere.example"]));
            assert_eq!(allowed.get("https://elsewhere.example"), Some(&2));
            assert!(refused.is_empty());
        }

        /// An origin the proxy serves is not "allowed direct" as well: serving it means
        /// the proxy sees it, which is the opposite of the exemption.
        #[test]
        fn serving_an_origin_wins_over_allowing_it() {
            let p = policy(&["https://both.example"], &["https://both.example"]);
            assert_eq!(
                p.disposition("https://both.example/a-1.0.0.tgz"),
                Disposition::Served
            );
        }

        #[test]
        fn an_unusable_allowed_origin_is_an_error() {
            let result = OriginPolicy::new(origins(&[]), ["ftp://nope.example"]);
            let Err(e) = result else {
                panic!("ftp is not an origin this can serve or reason about");
            };
            assert_eq!(e.reason, "scheme is not http or https");
        }

        /// When nothing survives, the document still has to be the filtered one. An
        /// empty `versions` map says there is no installable version; forwarding the
        /// original would put every refused version straight back.
        #[test]
        fn a_document_where_nothing_survives_is_still_filtered() {
            let json = r#"{"name":"w","dist-tags":{"latest":"1.0.0"},"versions":{
                "1.0.0":{"version":"1.0.0","dist":{"tarball":"https://elsewhere.example/w-1.0.0.tgz"}}}}"#;
            let out = filter(json, &policy(&[], &[]));
            assert_eq!(out.removed, ["1.0.0"]);
            assert_eq!(out.rewritten, 0);

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert!(v["versions"].as_object().unwrap().is_empty());
            assert!(v["dist-tags"].as_object().unwrap().is_empty());
        }

        /// A tag naming a version that is gone resolves to nothing. Dropping the tag lets
        /// the resolver fall back to one that is still there.
        #[test]
        fn tags_pointing_at_removed_versions_are_dropped() {
            let out = filter(MIXED, &policy(&[], &[]));
            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            let tags = v["dist-tags"].as_object().unwrap();
            assert!(
                !tags.contains_key("latest"),
                "latest named a removed version"
            );
            assert_eq!(
                tags["old"],
                serde_json::json!("1.0.0"),
                "this one still resolves"
            );
        }

        /// Configuring the origin makes the same document install in full.
        #[test]
        fn configuring_the_origin_keeps_every_version() {
            let out = filter(MIXED, &policy(&["https://elsewhere.example"], &[]));
            assert!(out.removed.is_empty());
            assert_eq!(out.rewritten, 3);

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(v["versions"].as_object().unwrap().len(), 3);
            assert_eq!(v["dist-tags"]["latest"], serde_json::json!("1.0.2"));
        }

        /// A version with no artifact produces no record, so nothing can install it. It is
        /// left alone rather than removed, so this does not become two behaviours.
        #[test]
        fn versions_without_an_artifact_are_left_alone() {
            let json = r#"{"name":"w","versions":{
                "1.0.0":{"version":"1.0.0"},
                "1.0.1":{"version":"1.0.1","dist":{"tarball":"https://registry.npmjs.org/w/-/w-1.0.1.tgz"}}}}"#;
            let out = filter(json, &policy(&[], &[]));
            assert!(out.removed.is_empty());

            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(v["versions"].as_object().unwrap().len(), 2);
        }

        #[test]
        fn filtering_a_body_that_is_not_json_is_an_error() {
            let result =
                filter_unservable_versions(
                    b"<html>",
                    std::iter::empty(),
                    &policy(&[], &[]),
                    &HashSet::new(),
                    true,
                    PROXY,
                );
            assert!(matches!(result, Err(RewriteError::NotJson(_))));
        }

        /// npm's `_resolved` repeats `dist.tarball` verbatim. A rewrite that only touched
        /// `dist.tarball` would leave it pointing at the registry. Measured in the corpus:
        /// 2 of 49,704 URLs appear twice, both this way.
        #[test]
        fn a_url_repeated_elsewhere_is_rewritten_everywhere() {
            let out = rewrite(
                r#"{"name":"react","versions":{"1.0.0":{"version":"1.0.0",
                    "_resolved":"https://registry.npmjs.org/react/-/react-1.0.0.tgz",
                    "dist":{"tarball":"https://registry.npmjs.org/react/-/react-1.0.0.tgz"}}}}"#,
            );
            assert_eq!(out.rewritten, 1, "one distinct URL");
            assert_eq!(out.occurrences, 2, "changed in both places");

            let text = String::from_utf8(out.body).unwrap();
            assert!(!text.contains("registry.npmjs.org/react"), "got: {text}");
            assert_eq!(
                text.matches("http://127.0.0.1:8080/react/-/react-1.0.0.tgz")
                    .count(),
                2
            );
        }

        /// Other strings on the same origin are not artifacts and must survive. Only the
        /// URLs the records named are replaced.
        #[test]
        fn other_urls_on_the_same_origin_are_untouched() {
            let out = rewrite(
                r#"{"name":"w","homepage":"https://registry.npmjs.org/w",
                    "bugs":{"url":"https://registry.npmjs.org/-/issues"},
                    "versions":{"1.0.0":{"version":"1.0.0","dist":{
                        "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
            );
            assert_eq!(out.occurrences, 1);
            let text = String::from_utf8(out.body).unwrap();
            assert!(
                text.contains(r#""homepage":"https://registry.npmjs.org/w""#),
                "got: {text}"
            );
            assert!(
                text.contains(r#""url":"https://registry.npmjs.org/-/issues""#),
                "got: {text}"
            );
        }

        /// A URL that only appears as part of a longer string is not a whole JSON string,
        /// so it is not an artifact reference and is left alone.
        #[test]
        fn a_url_embedded_in_prose_is_not_rewritten() {
            let out = rewrite(
                r#"{"name":"w",
                    "description":"download it from https://registry.npmjs.org/w/-/w-1.0.0.tgz today",
                    "versions":{"1.0.0":{"version":"1.0.0","dist":{
                        "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
            );
            assert_eq!(out.occurrences, 1, "only the artifact reference");
            let text = String::from_utf8(out.body).unwrap();
            assert!(
                text.contains("download it from https://registry.npmjs.org/w/-/w-1.0.0.tgz today"),
                "prose was rewritten: {text}"
            );
        }

        /// Everything the rewrite does not change has to come through byte for byte. This
        /// is what re-serialising could not promise.
        #[test]
        fn the_document_is_unchanged_apart_from_the_urls() {
            let original = fixture("@babel_traverse-8.0.5.full.json");
            let out = rewrite_with(&original, &origins(&[]), PROXY);
            assert_eq!(out.rewritten, 1);

            let restored = String::from_utf8(out.body).unwrap().replace(
                "http://127.0.0.1:8080/@babel/traverse/-/traverse-8.0.5.tgz",
                "https://registry.npmjs.org/@babel/traverse/-/traverse-8.0.5.tgz",
            );
            assert_eq!(
                restored.as_bytes(),
                original.as_slice(),
                "putting the URL back should give the original bytes"
            );
        }

        /// A document whose artifact URLs are not there to be found is refused outright.
        /// Half a rewrite would send some artifacts to the proxy and leave the rest
        /// pointing at the registry.
        #[test]
        fn a_url_that_cannot_be_found_fails_the_whole_rewrite() {
            let absent = ["https://registry.npmjs.org/ghost/-/ghost-1.0.0.tgz"];
            let result = rewrite_artifact_origins(
                br#"{"name":"w","versions":{}}"#,
                absent,
                &origins(&[]),
                PROXY,
            );
            let Err(e) = result else {
                panic!("a URL that is not in the document cannot be rewritten");
            };
            assert!(matches!(
                e,
                RewriteError::Incomplete {
                    expected: 1,
                    found: 0
                }
            ));
            assert!(e.to_string().contains("found 0 of 1"), "got: {e}");
        }

        #[test]
        fn a_body_that_is_not_utf8_is_an_error() {
            let result =
                rewrite_artifact_origins(&[0xff, 0xfe], std::iter::empty(), &origins(&[]), PROXY);
            assert!(matches!(result, Err(RewriteError::NotUtf8(_))));
        }

        /// A trailing slash on the base must not produce a doubled one in the URL.
        #[test]
        fn a_trailing_slash_on_the_base_does_not_double_up() {
            let out = rewrite_with(
                br#"{"name":"w","versions":{"1.0.0":{"version":"1.0.0","dist":{
                    "tarball":"https://registry.npmjs.org/w/-/w-1.0.0.tgz"}}}}"#,
                &origins(&[]),
                "http://127.0.0.1:8080/",
            );
            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            assert_eq!(
                v["versions"]["1.0.0"]["dist"]["tarball"],
                serde_json::json!("http://127.0.0.1:8080/w/-/w-1.0.0.tgz")
            );
        }

        /// A rewritten URL has to classify back to the package it came from, or the
        /// artifact request arrives as something the proxy does not recognise.
        #[test]
        fn a_rewritten_url_still_classifies_as_its_own_artifact() {
            let out = rewrite(
                r#"{"name":"@babel/core","versions":{"7.0.0":{"version":"7.0.0","dist":{
                    "tarball":"https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"}}}}"#,
            );
            let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
            let url = v["versions"]["7.0.0"]["dist"]["tarball"].as_str().unwrap();
            let path = url.strip_prefix(PROXY).unwrap();

            assert_eq!(
                classify_path(path),
                RequestTarget::Tarball {
                    key: PackageKey::from_registry_name(Ecosystem::Npm, "@babel/core").unwrap(),
                    claimed_version: "7.0.0".into()
                }
            );
        }
    }

    mod paths {
        use super::*;

        fn key(name: &str) -> PackageKey {
            PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
        }

        #[test]
        fn packument_paths_resolve_to_a_key() {
            assert_eq!(
                classify_path("/lodash"),
                RequestTarget::Packument(key("lodash"))
            );
            assert_eq!(
                classify_path("/@babel%2fcore"),
                RequestTarget::Packument(key("@babel/core")),
                "npm percent-encodes the scope separator"
            );
            assert_eq!(
                classify_path("/@babel%2Fcore"),
                RequestTarget::Packument(key("@babel/core"))
            );
            assert_eq!(
                classify_path("/@babel/core"),
                RequestTarget::Packument(key("@babel/core")),
                "the bare form resolves too"
            );
            assert_eq!(
                classify_path("/lodash?write=true"),
                RequestTarget::Packument(key("lodash")),
                "a query string is not part of the name"
            );
        }

        #[test]
        fn tarball_paths_carry_the_filename_version() {
            assert_eq!(
                classify_path("/lodash/-/lodash-4.17.21.tgz"),
                RequestTarget::Tarball {
                    key: key("lodash"),
                    claimed_version: "4.17.21".into()
                }
            );
            assert_eq!(
                classify_path("/@babel/core/-/core-7.0.0.tgz"),
                RequestTarget::Tarball {
                    key: key("@babel/core"),
                    claimed_version: "7.0.0".into()
                },
                "the scope is absent from the filename"
            );
        }

        /// A prerelease version contains hyphens, and the filename is split on the last
        /// hyphen of the package name, not the first hyphen in the string.
        #[test]
        fn prerelease_versions_survive_the_filename_split() {
            assert_eq!(
                classify_path("/react/-/react-18.3.0-canary-a1b2c3.tgz"),
                RequestTarget::Tarball {
                    key: key("react"),
                    claimed_version: "18.3.0-canary-a1b2c3".into()
                }
            );
            assert_eq!(
                classify_path("/is-odd/-/is-odd-3.0.1.tgz"),
                RequestTarget::Tarball {
                    key: key("is-odd"),
                    claimed_version: "3.0.1".into()
                },
                "hyphens in the package name are not version separators"
            );
        }

        /// 38 of 24,852 tarball URLs spell the version differently from the packument:
        /// every `express` prerelease before 3.0.0 and every `grunt` prerelease before
        /// 0.4.0 drops the hyphen. The path says `3.0.0rc1`, the packument says
        /// `3.0.0-rc1`.
        #[test]
        fn the_filename_version_is_what_the_filename_says() {
            let RequestTarget::Tarball {
                claimed_version, ..
            } = classify_path("/express/-/express-3.0.0rc1.tgz")
            else {
                panic!("should classify as a tarball");
            };
            assert_eq!(claimed_version, "3.0.0rc1");
            assert_ne!(
                claimed_version, "3.0.0-rc1",
                "the packument spells this version with a hyphen; the path does not"
            );
        }

        #[test]
        fn registry_endpoints_and_junk_are_not_packages() {
            for path in [
                "/",
                "",
                "/-/v1/search?text=lodash",
                "/-/whoami",
                "/-/npm/v1/attestations/sigstore@5.0.0",
                "/-",
                "/lodash/-/lodash-4.17.21.tar.gz",
                "/lodash/-/something-else.tgz",
                "/lodash/-/lodash-.tgz",
                "/@scope/",
            ] {
                assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
            }
        }

        /// npm asks for both documents in one Accept header, so the response is the only
        /// thing that says which arrived.
        #[test]
        fn detail_comes_from_the_response_content_type() {
            assert_eq!(
                detail_from_content_type(Some(
                    "application/vnd.npm.install-v1+json; charset=utf-8"
                )),
                Some(PackumentDetail::Abbreviated)
            );
            assert_eq!(
                detail_from_content_type(Some("application/json")),
                Some(PackumentDetail::Full)
            );
            assert_eq!(
                detail_from_content_type(Some("Application/JSON; charset=UTF-8")),
                Some(PackumentDetail::Full)
            );
            assert_eq!(
                detail_from_content_type(Some("application/octet-stream")),
                None
            );
            assert_eq!(detail_from_content_type(Some("text/html")), None);
            assert_eq!(detail_from_content_type(None), None);
        }
    }

    /// Casing is preserved end to end. `pkg:npm/AdultJS` is a malicious-package advisory
    /// and `pkg:npm/adultjs` matches nothing, so lowercasing anywhere on this path loses
    /// the match (see `identity`).
    #[test]
    fn document_name_casing_is_preserved() {
        let body = br#"{"name":"AdultJS","versions":{"1.0.0":{"version":"1.0.0","dist":{
            "tarball":"https://registry.npmjs.org/AdultJS/-/AdultJS-1.0.0.tgz"}}}}"#;
        let p = normalize_packument(body, PackumentDetail::Abbreviated).unwrap();
        assert_eq!(p.key.registry_name(), "AdultJS");
        assert_eq!(
            p.version("1.0.0").unwrap().package.to_string(),
            "pkg:npm/AdultJS@1.0.0"
        );
    }
}
