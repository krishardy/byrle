//! Which origins the proxy fronts, and what happens to an artifact published elsewhere.
//! The set is per deployment, never per ecosystem.
//!
//! See docs/engineering_decisions/enforcement-tiers.md.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::record::PackageMetadata;
use std::fmt;

/// The origins whose artifacts the proxy serves, which both rewriting and bypass reports read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableOrigins {
    /// Every reachable origin, as scheme, host and port only.
    origins: Vec<String>,
    /// The subset the operator added, the only origins fetched from directly.
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
    /// Build from the configured upstreams, every [`crate::ecosystem::TABLE`] row's origins,
    /// and any additional origins. Anything that is not a URL with a host is an error.
    pub fn new<'a, 'b>(
        upstreams: impl IntoIterator<Item = &'a str>,
        additional: impl IntoIterator<Item = &'b str>,
    ) -> Result<Self, OriginError> {
        Self::of(
            &upstreams.into_iter().collect::<Vec<_>>(),
            &additional.into_iter().collect::<Vec<_>>(),
        )
    }

    /// [`ReachableOrigins::new`] with its lists collected, so there is one body.
    fn of(upstreams: &[&str], additional: &[&str]) -> Result<Self, OriginError> {
        let mut origins = Vec::new();
        for upstream in upstreams {
            let origin = normalise_origin(upstream)?;
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        for registry in crate::ecosystem::TABLE {
            for base in registry.always_reachable {
                let origin = normalise_origin(base)
                    .expect("each row's always-reachable origin is a usable URL");
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
    /// upstream. Only an `origin` the operator added is.
    pub fn routes_directly(&self, origin: &str) -> bool {
        self.additional.iter().any(|o| o == origin)
    }

    pub(crate) fn contains(&self, origin: &str) -> bool {
        self.origins.iter().any(|o| o == origin)
    }
}

/// `url` with any `user:password@` removed, for printing. A configured index URL can carry a
/// credential, and `doctor` reports the URLs clients use.
pub fn without_credentials(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|at| at + 3) else {
        return url.to_owned();
    };
    let rest = &url[scheme_end..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    match authority.rfind('@') {
        Some(at) => format!("{}{}", &url[..scheme_end], &rest[at + 1..]),
        None => url.to_owned(),
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
    /// The client fetches it directly, unobserved, as the operator allowed for this origin.
    AllowedDirect(String),
    /// The proxy neither serves it nor permits it.
    Refused(String),
}

/// Which origins the proxy serves, and which it permits a client to fetch directly.
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
        Self::of(reachable, &allowed_direct.into_iter().collect::<Vec<_>>())
    }

    /// [`OriginPolicy::new`] with its list collected, so there is one body.
    fn of(reachable: ReachableOrigins, allowed_direct: &[&str]) -> Result<Self, OriginError> {
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
    /// `artifact_url` that does not parse is refused under its own text.
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
/// See docs/engineering_decisions/packument-tarball-url-rewriting.md.
/// Returns the origin, or `None` when the request will arrive at the proxy.
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
    /// How many places in the document were changed, counting npm's `_resolved` copies.
    pub occurrences: usize,
    /// Artifacts left as they were, because their origin is not one the proxy fronts.
    pub left_alone: usize,
}

#[derive(Debug)]
pub enum RewriteError {
    /// The body is not UTF-8, so it is not JSON either.
    NotUtf8(std::str::Utf8Error),
    /// The body did not parse as JSON. Only the filtering path parses.
    NotJson(serde_json::Error),
    /// An artifact URL was not found in the document as a complete quoted string.
    Incomplete { expected: usize, found: usize },
}

impl fmt::Display for RewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8(e) => write!(f, "document is not UTF-8: {e}"),
            Self::NotJson(e) => write!(f, "document is not valid JSON: {e}"),
            Self::Incomplete { expected, found } => write!(
                f,
                "found {found} of {expected} artifact URLs to rewrite; \
                 the rest are not complete quoted strings"
            ),
        }
    }
}

impl std::error::Error for RewriteError {}

/// Point every artifact URL on a reachable origin at the proxy, keeping its path, by
/// replacing each wherever it is a complete quoted string. Fails whole, never half done.
/// See docs/engineering_decisions/packument-tarball-url-rewriting.md.
/// `artifacts` are the URLs normalisation found, so the document is not parsed again.
/// `public_base` is the proxy's address the URLs are pointed at.
pub fn rewrite_artifact_origins<'a>(
    json: &[u8],
    artifacts: impl IntoIterator<Item = &'a str>,
    reachable: &ReachableOrigins,
    public_base: &str,
) -> Result<Rewritten, RewriteError> {
    let artifacts: Vec<&str> = artifacts.into_iter().collect();
    rewrite_listed(json, &artifacts, reachable, public_base)
}

/// [`rewrite_artifact_origins`] with its list collected, so there is one body.
fn rewrite_listed(
    json: &[u8],
    artifacts: &[&str],
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

    let prefixes: Vec<String> = reachable
        .as_slice()
        .iter()
        .map(|origin| format!("\"{origin}"))
        .collect();
    let mut candidates = Candidates::new(text, &prefixes);

    let mut out = String::with_capacity(text.len() + replacements.len() * 8);
    let mut found: HashSet<&str> = HashSet::new();
    let mut occurrences = 0;
    let mut cursor = 0;

    while let Some(open) = candidates.next(cursor) {
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

/// Where each prefix next occurs, found again only once passed: one read per prefix.
struct Candidates<'a> {
    text: &'a str,
    prefixes: &'a [String],
    /// Per prefix, its next position, or `None` once it occurs no more.
    next: Vec<Option<usize>>,
}

impl<'a> Candidates<'a> {
    fn new(text: &'a str, prefixes: &'a [String]) -> Self {
        let next = prefixes
            .iter()
            .map(|prefix| text.find(prefix.as_str()))
            .collect();
        Self {
            text,
            prefixes,
            next,
        }
    }

    /// The earliest position at or after `from` where any prefix occurs.
    fn next(&mut self, from: usize) -> Option<usize> {
        for (at, prefix) in self.next.iter_mut().zip(self.prefixes) {
            if at.is_some_and(|at| at < from) {
                *at = self.text[from..]
                    .find(prefix.as_str())
                    .map(|found| from + found);
            }
        }
        self.next.iter().flatten().min().copied()
    }
}

/// The path to keep, when this URL names an origin the proxy fronts, with its fragment,
/// where a PEP 503 index writes the digest pip checks.
pub(crate) fn reachable_path(url: &str, reachable: &ReachableOrigins) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !reachable.contains(&origin_of(&parsed)) {
        return None;
    }
    let mut path = parsed.path().to_owned();
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    if let Some(fragment) = parsed.fragment() {
        path.push('#');
        path.push_str(fragment);
    }
    Some(path)
}

impl PackageMetadata {
    /// Artifact origins this document publishes that the proxy does not serve, allowed and
    /// not, each with its count of versions. The allowed ones are still reported.
    pub fn unserved_origins(
        &self,
        policy: &OriginPolicy,
    ) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
        let mut allowed = BTreeMap::new();
        let mut refused = BTreeMap::new();
        for record in &self.records {
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
    /// Artifact origins in this document that the proxy does not front, which the client
    /// fetches directly and unobserved, with how many versions each accounts for.
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn a_credential_in_a_url_is_not_printed() {
        for (url, printed) in [
            (
                "https://user:secret@example.jfrog.io/api/pypi/simple/",
                "https://example.jfrog.io/api/pypi/simple/",
            ),
            (
                "https://token@example.org/simple",
                "https://example.org/simple",
            ),
            (
                "https://example.org/simple/?q=a@b",
                "https://example.org/simple/?q=a@b",
            ),
            ("https://example.org/a@b", "https://example.org/a@b"),
            ("not a url", "not a url"),
            ("https://a:b@c@host/x", "https://host/x"),
        ] {
            assert_eq!(super::without_credentials(url), printed, "{url}");
        }
    }

    use super::*;
    use crate::identity::Ecosystem;

    const UPSTREAM: &str = crate::ecosystem::npm::DEFAULT_REGISTRY;

    fn reachable(additional: &[&str]) -> ReachableOrigins {
        ReachableOrigins::new([UPSTREAM], additional.iter().copied()).expect("valid origins")
    }

    /// The rewrite keeps the digest a PEP 503 index writes in the href's fragment.
    #[test]
    fn a_rewritten_url_keeps_the_digest_a_simple_index_wrote_in_its_fragment() {
        let reachable = reachable(&[]);
        let href = "https://files.pythonhosted.org/packages/ab/cd/idna-3.10.tar.gz#sha256=12f6";
        let body = format!("<a href=\"{href}\">idna-3.10.tar.gz</a>");
        let out =
            rewrite_artifact_origins(body.as_bytes(), [href], &reachable, "http://127.0.0.1:8080")
                .expect("one href is rewritten");
        assert_eq!(
            String::from_utf8(out.body).unwrap(),
            "<a href=\"http://127.0.0.1:8080/packages/ab/cd/idna-3.10.tar.gz#sha256=12f6\">\
             idna-3.10.tar.gz</a>"
        );
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

    /// The upstream and the default registry are always fronted, whatever else is configured.
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

    /// A packument naming the default registry still routes to the upstream.
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

    /// [`PackageMetadata::unserved_origins`] and `bypassing_origins` over whole npm documents.
    mod documents {
        use super::*;
        use crate::ecosystem::npm::{normalize_packument, normalized};
        use crate::record::DocumentDetail;

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
            let p = normalize_packument(body, DocumentDetail::Abbreviated).unwrap();

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
            let p = normalize_packument(body, DocumentDetail::Abbreviated).unwrap();

            let origins = p.bypassing_origins(&reachable(&[]));
            assert_eq!(origins.len(), 2);
            assert_eq!(origins.get("https://evil.example"), Some(&2));
            assert_eq!(origins.get("https://other.example"), Some(&1));
        }

        /// A record with no file has no origin to report, served or not.
        #[test]
        fn a_record_with_no_file_names_no_origin() {
            let mut p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
            for record in &mut p.records {
                record.artifacts.clear();
            }
            assert!(p.bypassing_origins(&reachable(&[])).is_empty());
            let policy = OriginPolicy::new(reachable(&[]), std::iter::empty()).expect("valid");
            assert_eq!(
                p.unserved_origins(&policy),
                (BTreeMap::new(), BTreeMap::new())
            );
        }

        #[test]
        fn an_ordinary_packument_reports_nothing() {
            let p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
            assert!(p.bypassing_origins(&reachable(&[])).is_empty());
        }
    }

    /// A blank allowed origin is skipped and a repeated one is kept once.
    #[test]
    fn allowed_origins_are_kept_once_each() {
        let policy = OriginPolicy::new(
            reachable(&[]),
            [" ", "https://a.example", "https://a.example/"],
        )
        .expect("valid");
        assert_eq!(policy.allowed_direct, ["https://a.example"]);
    }

    /// A URL with no host, or none at all, has no origin and no path to keep.
    #[test]
    fn a_url_with_no_host_has_no_origin() {
        assert_eq!(origin_of_url("mailto:a@example.org"), None);
        assert_eq!(reachable_path("not a url", &reachable(&[])), None);
    }

    /// A body whose last candidate string never closes is left as it is from there on.
    #[test]
    fn an_unclosed_string_ends_the_scan() {
        let url = format!("{UPSTREAM}/a/-/a-1.0.0.tgz");
        let body = format!("{{\"tarball\":\"{url}\",\"x\":\"{UPSTREAM}/b");
        let out = rewrite_artifact_origins(
            body.as_bytes(),
            [url.as_str()],
            &reachable(&[]),
            "http://proxy",
        )
        .expect("rewrites");
        assert_eq!(out.rewritten, 1);
        assert!(
            String::from_utf8(out.body)
                .unwrap()
                .ends_with(&format!("\"{UPSTREAM}/b"))
        );
    }

    #[test]
    fn each_rewrite_error_says_what_the_document_was() {
        let not_utf8 = rewrite_artifact_origins(b"\xff", [], &reachable(&[]), "http://p")
            .expect_err("not UTF-8");
        assert!(not_utf8.to_string().starts_with("document is not UTF-8: "));
        let not_json = RewriteError::NotJson(serde_json::from_str::<()>("{").unwrap_err());
        assert!(
            not_json
                .to_string()
                .starts_with("document is not valid JSON: ")
        );
    }

    /// URLs on two served origins, interleaved, with a third served origin the text never
    /// names, are each rewritten: each prefix's next position is found again once passed.
    #[test]
    fn interleaved_origins_are_each_rewritten() {
        let reachable = ReachableOrigins::new(
            ["https://a.example", "https://b.example"],
            ["https://never.example"],
        )
        .expect("valid origins");
        let urls = [
            "https://a.example/1.tgz",
            "https://b.example/2.tgz",
            "https://a.example/3.tgz",
            "https://b.example/4.tgz",
        ];
        let json = format!(
            r#"["{}","{}","{}","{}"]"#,
            urls[0], urls[1], urls[2], urls[3]
        );
        let out = rewrite_artifact_origins(json.as_bytes(), urls, &reachable, "http://p")
            .expect("rewrites");
        assert_eq!(out.rewritten, 4);
        assert_eq!(
            String::from_utf8(out.body).unwrap(),
            r#"["http://p/1.tgz","http://p/2.tgz","http://p/3.tgz","http://p/4.tgz"]"#
        );
    }
}
