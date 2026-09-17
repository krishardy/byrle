//! Which origins the proxy fronts, and what happens to an artifact published elsewhere.
//!
//! Every ecosystem this proxy serves publishes artifacts on some host, and the questions
//! are the same for all of them: is this URL one the proxy can fetch through, may the
//! client go to it directly, or is it refused. npm's registry serves packuments and
//! tarballs from one host and PyPI serves its index from `pypi.org` and its files from
//! `files.pythonhosted.org`, so the set is per deployment and never per ecosystem.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::record::PackageMetadata;
use std::fmt;

/// The origins whose artifacts the proxy serves.
///
/// One source of truth for two questions that must never disagree: which artifact URLs
/// get pointed at the proxy ([`crate::ecosystem::npm::rewrite_artifact_origins`]), and which are reported as
/// fetched directly ([`crate::ecosystem::npm::PackageMetadata::bypassing_origins`]). If those sets differed,
/// an artifact could be rewritten and reported as bypassing, or left alone and reported
/// as fine.
///
/// Always holds every configured upstream and every origin each row of
/// [`crate::ecosystem::TABLE`] always reaches. The configured upstream is added beside
/// those, not instead of them: npm rewrites `dist.tarball` to the configured registry when
/// it names the default host, and a PyPI index published on a mirror still gives
/// `files.pythonhosted.org` URLs for files it does not hold itself.
///
/// Additional origins are for a registry that serves
/// artifacts from somewhere else, a CDN in front of a private registry being the case to
/// expect. Zero of the 24,852 artifact URLs measured on registry.npmjs.org needed one.
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
    /// Build from the configured upstreams plus any additional origins.
    ///
    /// Every row of [`crate::ecosystem::TABLE`] contributes its origins. Anything that is
    /// not a URL with a host is an error rather than being dropped: an operator who names
    /// an origin and has it silently ignored would believe those artifacts are covered.
    ///
    /// A packument can publish an artifact on any host, so which hosts the proxy can fetch
    /// through is a different question from which ecosystems it routes.
    pub fn new<'a, 'b>(
        upstreams: impl IntoIterator<Item = &'a str>,
        additional: impl IntoIterator<Item = &'b str>,
    ) -> Result<Self, OriginError> {
        let mut origins = Vec::new();
        for upstream in upstreams {
            let origin = normalise_origin(upstream)?;
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        for registry in crate::ecosystem::TABLE {
            for base in registry.always_reachable {
                let origin = normalise_origin(base)?;
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
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

    pub(crate) fn contains(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

pub(crate) fn normalise_origin(base: &str) -> Result<String, OriginError> {
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

/// The scheme, host and port of a URL, or `None` when it is not a usable URL.
pub fn origin_of_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed.host_str()?;
    Some(origin_of(&parsed))
}

pub(crate) fn origin_of(url: &reqwest::Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or(""),
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    )
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

/// The earliest position at or after `from` where any prefix occurs.
fn next_candidate(text: &str, from: usize, prefixes: &[String]) -> Option<usize> {
    prefixes
        .iter()
        .filter_map(|prefix| text[from..].find(prefix.as_str()).map(|at| from + at))
        .min()
}

/// The path to keep, when this URL names an origin the proxy fronts.
pub(crate) fn reachable_path(url: &str, reachable: &ReachableOrigins) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !reachable.contains(&origin_of(&parsed)) {
        return None;
    }
    Some(match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    })
}

impl PackageMetadata {
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
            // A version the registry named no file for has no origin to be served from.
            let Some(artifact) = record.artifact() else {
                continue;
            };
            match policy.disposition(&artifact.url) {
                Disposition::Served => {}
                Disposition::AllowedDirect(origin) => *allowed.entry(origin).or_insert(0) += 1,
                Disposition::Refused(origin) => *refused.entry(origin).or_insert(0) += 1,
            }
        }
        (allowed, refused)
    }
}

impl PackageMetadata {
    /// Artifact origins in this document that the proxy does not front, with how many
    /// versions each accounts for. Empty in the normal case.
    ///
    /// A non-empty result means the client will fetch those artifacts directly, so
    /// nothing about them is observed: not the digest check, not the policy engine.
    pub fn bypassing_origins(&self, reachable: &ReachableOrigins) -> BTreeMap<String, usize> {
        let mut origins = BTreeMap::new();
        for record in &self.records {
            let Some(artifact) = record.artifact() else {
                continue;
            };
            if let Some(origin) = bypassing_origin(&artifact.url, reachable) {
                *origins.entry(origin).or_insert(0) += 1;
            }
        }
        origins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;

    const UPSTREAM: &str = crate::ecosystem::npm::DEFAULT_REGISTRY;

    fn reachable(additional: &[&str]) -> ReachableOrigins {
        ReachableOrigins::new([UPSTREAM], additional.iter().copied()).expect("valid origins")
    }

    /// The set a default deployment fronts: npm's registry, PyPI's index and PyPI's file
    /// host. Every ecosystem's, not only the served ones.
    #[test]
    fn every_expressible_ecosystem_contributes_its_own_origins() {
        let r = ReachableOrigins::new(["https://npm.corp.example"], std::iter::empty()).unwrap();
        assert_eq!(
            r.as_slice(),
            [
                "https://npm.corp.example",
                "https://registry.npmjs.org",
                "https://pypi.org",
                "https://files.pythonhosted.org",
            ]
        );
    }

    /// Without this a PyPI artifact is on no reachable origin, so `disposition` refuses it
    /// and the proxy answers every PyPI fetch with a refusal.
    #[test]
    fn a_pypi_file_is_served_rather_than_refused() {
        let url = "https://files.pythonhosted.org/packages/a/b/c/requests-2.32.3.tar.gz";
        let policy = OriginPolicy::new(reachable(&[]), std::iter::empty()).unwrap();
        assert_eq!(policy.disposition(url), Disposition::Served);
        assert_eq!(bypassing_origin(url, &reachable(&[])), None);
    }

    #[test]
    fn each_ecosystem_names_the_origins_it_always_reaches() {
        assert_eq!(
            crate::ecosystem::of(Ecosystem::Npm).always_reachable,
            ["https://registry.npmjs.org"]
        );
        assert_eq!(
            crate::ecosystem::of(Ecosystem::PyPI).always_reachable,
            ["https://pypi.org/simple", "https://files.pythonhosted.org"]
        );
    }

    /// The upstream and the default registry are always fronted, whatever else is
    /// configured. npm rewrites `dist.tarball` to the configured registry when it
    /// names the default host, so both are reachable by construction.
    #[test]
    fn the_upstream_and_the_default_registry_are_always_included() {
        let r = ReachableOrigins::new(["https://npm.corp.example"], std::iter::empty()).unwrap();
        assert!(
            r.as_slice()
                .contains(&"https://npm.corp.example".to_owned())
        );
        assert!(
            r.as_slice()
                .contains(&"https://registry.npmjs.org".to_owned())
        );
    }

    /// An upstream that is already the default registry is not listed twice.
    #[test]
    fn origins_are_not_duplicated() {
        let r = ReachableOrigins::new(
            ["https://registry.npmjs.org/"],
            [
                "https://registry.npmjs.org",
                "https://registry.npmjs.org/some/path",
            ],
        )
        .unwrap();
        assert_eq!(
            r.as_slice(),
            [
                "https://registry.npmjs.org",
                "https://pypi.org",
                "https://files.pythonhosted.org",
            ],
            "the upstream is already the default registry, so it is listed once"
        );
    }

    /// A packument naming the default registry still routes to the upstream. A
    /// private mirror publishes registry.npmjs.org URLs and is the whole reason the
    /// proxy was pointed somewhere else; fetching from npmjs.org would go around it.
    #[test]
    fn only_origins_the_operator_added_are_fetched_from_directly() {
        let r = ReachableOrigins::new(["https://npm.corp.example"], ["https://cdn.corp.example"])
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
        let r = ReachableOrigins::new(["https://npm.corp.example"], ["https://npm.corp.example"])
            .unwrap();
        assert!(!r.routes_directly("https://npm.corp.example"));
        assert_eq!(
            r.as_slice().len(),
            4,
            "the upstream and the three origins an ecosystem always reaches"
        );
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
            let result = ReachableOrigins::new([UPSTREAM], [bad]);
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
        let r = ReachableOrigins::new([UPSTREAM], ["", "  ", "https://cdn.example"]).unwrap();
        // UPSTREAM is the default registry here, so the two collapse into one.
        assert_eq!(
            r.as_slice(),
            [
                "https://registry.npmjs.org",
                "https://pypi.org",
                "https://files.pythonhosted.org",
                "https://cdn.example",
            ]
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
                &ReachableOrigins::new(["https://npm.corp.example"], std::iter::empty()).unwrap()
            ),
            None,
            "this is the registry the operator pointed us at"
        );
        assert_eq!(
            bypassing_origin(
                "http://127.0.0.1:8080/x/-/x-1.0.0.tgz",
                &ReachableOrigins::new(["http://127.0.0.1:8080"], std::iter::empty()).unwrap()
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

    /// [`PackageMetadata::unserved_origins`] and [`PackageMetadata::bypassing_origins`]
    /// over whole documents. npm's normaliser builds the input because it is the shortest
    /// route to a real one; nothing in the code under test names an ecosystem.
    mod documents {
        use super::*;
        use crate::ecosystem::npm::{normalize_packument, normalized};
        use crate::record::PackumentDetail;

        const UPSTREAM: &str = "https://registry.npmjs.org";

        fn reachable(additional: &[&str]) -> ReachableOrigins {
            ReachableOrigins::new([UPSTREAM], additional.iter().copied()).expect("valid origins")
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
                let artifacts: Vec<&str> = p
                    .records
                    .iter()
                    .map(|r| r.artifact().expect("one file").url.as_str())
                    .collect();
                let out = rewrite_artifact_origins(body, artifacts, &set, "http://127.0.0.1:8080")
                    .expect("should rewrite");
                assert_eq!(out.rewritten, expect_rewritten);
                assert_eq!(out.left_alone, expect_offsite);
                assert_eq!(p.bypassing_origins(&set).len(), expect_offsite);
            }
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
            let p = normalized("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
            assert!(p.bypassing_origins(&reachable(&[])).is_empty());
        }
    }
}
