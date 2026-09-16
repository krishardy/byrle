//! Which origins the proxy fronts, and what happens to an artifact published elsewhere.
//!
//! Every ecosystem this proxy serves publishes artifacts on some host, and the questions
//! are the same for all of them: is this URL one the proxy can fetch through, may the
//! client go to it directly, or is it refused. npm's registry serves packuments and
//! tarballs from one host and PyPI serves its index from `pypi.org` and its files from
//! `files.pythonhosted.org`, so the set is per deployment and never per ecosystem.

use crate::identity::Ecosystem;
use std::fmt;

/// Origins an ecosystem reaches whatever the operator configured.
///
/// The configured upstream is added beside these, not instead of them: npm rewrites
/// `dist.tarball` to the configured registry when it names the default host, and a PyPI
/// index published on a mirror still gives `files.pythonhosted.org` URLs for files it does
/// not hold itself.
pub fn always_reachable(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &[crate::npm::DEFAULT_REGISTRY],
        Ecosystem::PyPI => &[crate::pypi::INDEX, crate::pypi::FILES],
    }
}

/// The origins whose artifacts the proxy serves.
///
/// One source of truth for two questions that must never disagree: which artifact URLs
/// get pointed at the proxy ([`crate::npm::rewrite_artifact_origins`]), and which are reported as
/// fetched directly ([`crate::npm::NormalizedPackument::bypassing_origins`]). If those sets differed,
/// an artifact could be rewritten and reported as bypassing, or left alone and reported
/// as fine.
///
/// Always holds every configured upstream and every origin [`always_reachable`] names, for
/// every ecosystem the crate can express. Additional origins are for a registry that serves
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
    /// Every ecosystem's [`always_reachable`] origins are included. Anything that is not a
    /// URL with a host is an error rather than being dropped: an operator who names an
    /// origin and has it silently ignored would believe those artifacts are covered.
    ///
    /// Every ecosystem, not only the served ones. A packument can publish an artifact on
    /// any host, and `Ecosystem::ALL` answers which ecosystems the proxy serves, which is a
    /// different question from which hosts it can fetch through.
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
        for ecosystem in Ecosystem::EXPRESSIBLE {
            for base in always_reachable(ecosystem) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const UPSTREAM: &str = crate::npm::DEFAULT_REGISTRY;

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
            always_reachable(Ecosystem::Npm),
            ["https://registry.npmjs.org"]
        );
        assert_eq!(
            always_reachable(Ecosystem::PyPI),
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
}
