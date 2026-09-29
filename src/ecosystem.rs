//! Which registry answers a request, and what that registry does differently: one
//! [`Registry`] row per ecosystem in [`TABLE`], so a field must be filled in for every one.
//!
//! See docs/engineering_decisions/adapter-interface.md.

pub mod npm;
pub mod pypi;

use crate::doctor::Client;
use crate::env::{Env, EnvError, Var};
use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::intel::range::VersionOrder;
use crate::intel::stream::{self, Stream};
use crate::lockfile::{Lockfile, Unread};
use crate::policy::facts::PublishTimes;
use crate::record::PackageMetadata;
use crate::route::{DocumentKind, RequestTarget};
use std::collections::BTreeMap;

/// Metadata the proxy fetched itself: the outer error is the fetch, the inner the document.
pub type Fetched = Result<Result<PackageMetadata, String>, String>;

/// Each ecosystem's registry client, chosen by the package key, for a caller with no document.
#[derive(Debug, Clone)]
pub struct Clients {
    npm: npm::Client,
    pypi: pypi::Client,
}

impl Clients {
    /// A client for each upstream. `max_bytes` bounds each decoded body.
    pub fn new(http: reqwest::Client, upstreams: &Upstreams, max_bytes: usize) -> Self {
        Self {
            npm: npm::Client::new(http.clone(), upstreams.get(Ecosystem::Npm))
                .with_max_bytes(max_bytes),
            pypi: pypi::Client::new(http, upstreams.get(Ecosystem::PyPI)).with_max_bytes(max_bytes),
        }
    }

    /// Clients for the upstreams and body limit the environment configures.
    pub fn from_env<L: Fn(&str) -> Option<std::ffi::OsString>>(
        environment: &Env<L>,
    ) -> Result<Self, EnvError> {
        Ok(Self::new(
            reqwest::Client::new(),
            &environment.upstreams()?,
            environment.max_metadata_bytes()?,
        ))
    }

    /// The package's metadata as records.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        match key.ecosystem() {
            Ecosystem::Npm => self.npm.metadata(key).await,
            Ecosystem::PyPI => self.pypi.metadata(key).await,
        }
    }

    /// The record for `version` of `key`, from its registry's metadata document.
    /// Errors when the document cannot be fetched or read.
    /// Returns `None` when the document does not list the version.
    pub async fn record(
        &self,
        key: &PackageKey,
        version: &str,
    ) -> Result<Option<crate::record::PackageRecord>, String> {
        Ok(fetched(self.metadata(key).await)?.version(version).cloned())
    }

    /// Publish times fetched separately from the records. `Ok(None)` for an ecosystem
    /// whose records carry `published_at`, which asks nothing.
    pub async fn publish_times(&self, key: &PackageKey) -> Result<Option<PublishTimes>, String> {
        Ok(self.full_document(key).await?.map(|full| full.times))
    }

    /// The full document, for an ecosystem whose client asks for less. `Ok(None)` for one
    /// whose records carry `published_at`, which asks nothing.
    pub async fn full_document(
        &self,
        key: &PackageKey,
    ) -> Result<Option<npm::transport::FullDocument>, String> {
        match of(key.ecosystem()).publish_times {
            PublishTimeSource::Record => Ok(None),
            PublishTimeSource::FullPackument => {
                npm::fetched(self.npm.full(key).await, "publish times").map(Some)
            }
        }
    }
}

/// The metadata, or what went wrong: `metadata could not be fetched: ...` when the request
/// failed, and `metadata could not be read: ...` when the document did not normalise.
pub fn fetched(result: Fetched) -> Result<PackageMetadata, String> {
    match result {
        Ok(Ok(metadata)) => Ok(metadata),
        Ok(Err(e)) => Err(format!("metadata could not be read: {e}")),
        Err(e) => Err(format!("metadata could not be fetched: {e}")),
    }
}

/// Where the policy reads a version's publish time from, for `cooldown_days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishTimeSource {
    /// The normaliser sets `published_at` from the document the client asked for.
    Record,
    /// npm's full packument, fetched separately; the abbreviated one has no `time` map.
    FullPackument,
}

impl PublishTimeSource {
    /// What a policy with `cooldown_days` costs, when it costs a request the client never
    /// made. `None` when the publish time is in the document the client asked for.
    pub fn cost(self) -> Option<&'static str> {
        match self {
            Self::Record => None,
            Self::FullPackument => Some(
                "a full-packument fetch per package that the client never asked for. npm \
                 publishes version timestamps only in the full document, measured at 1.7x to \
                 3.6x the abbreviated one",
            ),
        }
    }
}

/// Each served ecosystem whose cooldown costs a request, and what it costs.
pub fn cooldown_costs() -> Vec<(Ecosystem, &'static str)> {
    TABLE
        .iter()
        .filter_map(|registry| Some((registry.ecosystem, registry.publish_times.cost()?)))
        .collect()
}

/// What a metadata request answers when the intel snapshot has no stream for the ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncoveredMetadata {
    /// 503.
    Refuse,
    /// The document, with the versions removed that the checks needing no intel refuse.
    FilterWithoutIntel,
}

/// How an operator points this ecosystem's main client at the proxy.
pub struct Setup {
    /// The client.
    pub client: &'static str,
    /// The command that sets its registry, before the address.
    pub command: &'static str,
    /// The path the proxy serves this ecosystem under, after the address.
    pub path: &'static str,
}

impl Setup {
    /// The command line for a proxy listening on `listen`.
    pub fn command_line(&self, listen: &str) -> String {
        format!("{} http://{listen}{}", self.command, self.path)
    }
}

/// What one ecosystem answers.
pub struct Registry {
    /// The ecosystem this row is for.
    pub ecosystem: Ecosystem,

    /// Path prefixes this registry claims, whatever the path names. Empty for [`ROOT`].
    pub prefixes: &'static [&'static str],

    /// Origins the proxy may fetch from for this ecosystem whatever the operator configured.
    pub always_reachable: &'static [&'static str],

    /// What a request path under this registry refers to.
    pub classify_path: fn(&str) -> RequestTarget,

    /// Which metadata document a response body is, read from its `Content-Type`.
    pub read_media_type: fn(Option<&str>) -> Option<DocumentKind>,

    /// The media types [`Registry::read_media_type`] reads, for `waharoa status` to report.
    pub documents: &'static [&'static str],

    /// Whether a request that is neither metadata nor an artifact is a probe, logged at DEBUG.
    pub other_is_probe: bool,

    /// Where a version's publish time comes from.
    pub publish_times: PublishTimeSource,

    /// The package-keyed advisory streams for this ecosystem. Catalogues such as KEV are not.
    pub streams: &'static [&'static Stream],

    /// Lockfiles this ecosystem's clients write, by file name, and how each is read.
    pub lockfiles: &'static [Lockfile],

    /// File names a client writes that no reader takes, and what to write instead.
    pub unread_lockfiles: &'static [Unread],

    /// The package managers `waharoa doctor` checks for this ecosystem.
    pub clients: &'static [Client],

    /// What the startup log tells an operator to run.
    pub setup: Setup,

    /// What a metadata request answers when no intel stream covers this ecosystem.
    pub uncovered_metadata: UncoveredMetadata,

    /// How this ecosystem's versions order, which advisory ranges are read by.
    pub versions: VersionOrder,

    /// A non-empty registry name as a purl namespace and name.
    pub split_name: SplitName,

    /// A name as a policy selector compares it, prefix or exact.
    pub canonical_name: fn(&str) -> String,

    /// The variable naming where this ecosystem's requests are forwarded.
    pub upstream: Var,

    /// Where a request path goes, given the upstream base.
    pub upstream_url: fn(&str, &str) -> String,
}

/// Each served ecosystem's upstream base, with no trailing slash, one per [`TABLE`] row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstreams(BTreeMap<Ecosystem, String>);

impl Upstreams {
    /// Each ecosystem's public registry.
    pub fn defaults() -> Self {
        Self(
            TABLE
                .iter()
                .map(|registry| {
                    let base = registry
                        .upstream
                        .default_text()
                        .expect("an upstream variable names its default");
                    (registry.ecosystem, trimmed(base))
                })
                .collect(),
        )
    }

    /// These upstreams with `ecosystem`'s at `base`. A trailing slash is accepted.
    pub fn with(mut self, ecosystem: Ecosystem, base: &str) -> Self {
        self.0.insert(ecosystem, trimmed(base));
        self
    }

    /// `ecosystem`'s upstream base.
    pub fn get(&self, ecosystem: Ecosystem) -> &str {
        &self.0[&ecosystem]
    }

    /// Every upstream base, in ecosystem order.
    pub fn bases(&self) -> impl Iterator<Item = &str> {
        self.0.values().map(String::as_str)
    }

    /// Each ecosystem and its upstream base, in ecosystem order.
    pub fn iter(&self) -> impl Iterator<Item = (Ecosystem, &str)> {
        self.0
            .iter()
            .map(|(ecosystem, base)| (*ecosystem, base.as_str()))
    }
}

/// `npm=https://registry.npmjs.org pypi=https://pypi.org/simple`.
impl std::fmt::Display for Upstreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&written(self.iter()))
    }
}

/// `npm=<base> pypi=<base>`, the form the startup log and `doctor` print upstreams in.
pub fn written<'a>(upstreams: impl Iterator<Item = (impl std::fmt::Display, &'a str)>) -> String {
    let written: Vec<String> = upstreams
        .map(|(ecosystem, base)| format!("{ecosystem}={base}"))
        .collect();
    written.join(" ")
}

fn trimmed(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}

/// `name` as `ecosystem`, a purl type, compares it: a PyPI name PEP 503 normalised, an npm
/// name as written. As written for an ecosystem with no row, which nothing here serves.
pub fn canonical_name(ecosystem: &str, name: &str) -> String {
    match ecosystem.parse::<Ecosystem>() {
        Ok(known) => (of(known).canonical_name)(name),
        Err(_) => name.to_owned(),
    }
}

/// See [`Registry::split_name`].
pub type SplitName = fn(&str) -> Result<(Option<String>, String), IdentityError>;

impl Registry {
    /// Whether this registry claims `path`, its query dropped. `/simple` and `/packages`
    /// without the trailing slash are npm packages by those names.
    pub fn serves(&self, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        self.prefixes.iter().any(|prefix| path.starts_with(prefix))
    }

    /// What `path` refers to, in this registry's spelling.
    pub fn classify(&self, path: &str) -> RequestTarget {
        (self.classify_path)(path)
    }

    /// Which metadata document a body with this `Content-Type` is, if any.
    pub fn document(&self, content_type: Option<&str>) -> Option<DocumentKind> {
        (self.read_media_type)(content_type)
    }
}

/// The registry that answers a path no other registry claimed: npm, which asks for `/lodash`.
pub const ROOT: Ecosystem = Ecosystem::Npm;

pub const NPM: Registry = Registry {
    ecosystem: Ecosystem::Npm,
    prefixes: &[],
    always_reachable: &[npm::DEFAULT_REGISTRY],
    classify_path: npm::classify_path,
    read_media_type: npm::document_from_content_type,
    documents: &[npm::ABBREVIATED_ACCEPT, npm::FULL_ACCEPT],
    other_is_probe: false,
    publish_times: PublishTimeSource::FullPackument,
    streams: &[&stream::OSV_NPM, &stream::DATADOG_NPM, &stream::GITHUB_NPM],
    lockfiles: npm::lockfile::LOCKFILES,
    unread_lockfiles: npm::lockfile::UNREAD,
    clients: npm::clients::CLIENTS,
    setup: Setup {
        client: npm::clients::NPM.name,
        command: npm::clients::NPM.set_registry,
        path: "/",
    },
    uncovered_metadata: UncoveredMetadata::Refuse,
    versions: VersionOrder::SemVer,
    split_name: npm::paths::split_name,
    canonical_name: npm::paths::canonical_name,
    upstream: crate::env::UPSTREAM_NPM,
    upstream_url: npm::paths::upstream_url,
};

pub const PYPI: Registry = Registry {
    ecosystem: Ecosystem::PyPI,
    prefixes: &[pypi::SIMPLE, "/packages/"],
    always_reachable: &[pypi::INDEX, pypi::FILES],
    classify_path: pypi::classify_path,
    read_media_type: pypi::document_from_content_type,
    documents: &[pypi::SIMPLE_JSON, pypi::SIMPLE_HTML, "text/html"],
    other_is_probe: true,
    publish_times: PublishTimeSource::Record,
    streams: &[
        &stream::OSV_PYPI,
        &stream::DATADOG_PYPI,
        &stream::GITHUB_PYPI,
    ],
    lockfiles: pypi::lockfile::LOCKFILES,
    unread_lockfiles: pypi::lockfile::UNREAD,
    clients: pypi::clients::CLIENTS,
    setup: Setup {
        client: "pip",
        command: "pip config set global.index-url",
        path: pypi::SIMPLE,
    },
    uncovered_metadata: UncoveredMetadata::FilterWithoutIntel,
    versions: VersionOrder::Pep440,
    split_name: pypi::paths::split_name,
    canonical_name: pypi::paths::canonical_name,
    upstream: crate::env::UPSTREAM_PYPI,
    upstream_url: pypi::paths::upstream_url,
};

/// Every ecosystem the proxy routes, one row each, for which intel coverage is reported.
pub const TABLE: &[Registry] = &[NPM, PYPI];

/// The row for `ecosystem`.
///
/// Panics if the table has no row for it, which `every_expressible_ecosystem_has_a_row`
/// makes unreachable.
pub fn of(ecosystem: Ecosystem) -> &'static Registry {
    TABLE
        .iter()
        .find(|registry| registry.ecosystem == ecosystem)
        .expect("every ecosystem has a row in ecosystem::TABLE")
}

/// The row that answers `path`: the one whose prefixes claim it, else [`ROOT`]'s.
pub fn serving(path: &str) -> &'static Registry {
    TABLE
        .iter()
        .find(|registry| registry.serves(path))
        .unwrap_or_else(|| of(ROOT))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod table {
    use super::*;
    use crate::record::DocumentDetail;

    /// A limit that does not parse stops the clients being built, and a registry that cannot
    /// be reached is an error for a record rather than no record.
    #[tokio::test]
    async fn a_client_that_cannot_be_built_or_reach_its_registry_is_an_error() {
        use crate::env::testing::with;
        let Err(error) = Clients::from_env(&with(&[(crate::env::MAX_METADATA_BYTES, "lots")]))
        else {
            panic!("the limit does not parse");
        };
        assert_eq!(error.var, crate::env::MAX_METADATA_BYTES.name);

        let closed = crate::util::test_support::closing_server().await;
        let clients = Clients::from_env(&with(&[(
            crate::env::UPSTREAM_NPM,
            &format!("http://{closed}"),
        )]))
        .expect("builds");
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").expect("a name");
        let error = clients
            .record(&key, "4.17.21")
            .await
            .expect_err("unreachable");
        assert!(
            error.starts_with("metadata could not be fetched"),
            "{error}"
        );
    }

    /// The property the table exists for. A variant with no row makes `of` panic, and
    /// `of` is on the request path.
    #[test]
    fn every_expressible_ecosystem_has_a_row() {
        for ecosystem in Ecosystem::EXPRESSIBLE {
            let rows = TABLE
                .iter()
                .filter(|registry| registry.ecosystem == ecosystem)
                .count();
            assert_eq!(rows, 1, "{ecosystem} has {rows} rows in TABLE");
        }
        assert_eq!(TABLE.len(), Ecosystem::EXPRESSIBLE.len());
    }

    /// Exactly one row may fall through, or a path with no prefix has two answers.
    #[test]
    fn one_row_claims_no_prefix_and_it_is_the_root() {
        let rootless: Vec<_> = TABLE
            .iter()
            .filter(|registry| registry.prefixes.is_empty())
            .map(|registry| registry.ecosystem)
            .collect();
        assert_eq!(rootless, vec![ROOT]);
    }

    /// Two rows claiming the same prefix would make `serving` depend on table order.
    #[test]
    fn no_prefix_is_claimed_twice() {
        let mut claimed: Vec<&str> = TABLE
            .iter()
            .flat_map(|registry| registry.prefixes.iter().copied())
            .collect();
        let before = claimed.len();
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(claimed.len(), before, "a prefix is claimed by two rows");
    }

    #[test]
    fn a_prefixed_path_goes_to_the_row_that_claims_it() {
        for path in [
            "/simple/",
            "/simple/requests/",
            "/simple/nonsense",
            "/packages/a/b/c/requests-2.32.3-py3-none-any.whl",
            "/packages/nonsense",
            "/simple/requests/?foo=1",
        ] {
            assert_eq!(serving(path).ecosystem, Ecosystem::PyPI, "{path}");
        }
    }

    /// PyPI's index carries each file's upload time, so only npm's cooldown costs a fetch.
    #[test]
    fn only_an_ecosystem_that_fetches_publish_times_reports_a_cooldown_cost() {
        let costs = cooldown_costs();
        assert_eq!(
            costs.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
            [Ecosystem::Npm]
        );
        assert!(costs[0].1.contains("full-packument fetch"));
        assert_eq!(PublishTimeSource::Record.cost(), None);
    }

    #[test]
    fn each_setup_line_points_its_client_at_the_proxy() {
        let lines: Vec<String> = TABLE
            .iter()
            .map(|registry| registry.setup.command_line("127.0.0.1:8080"))
            .collect();
        assert_eq!(
            lines,
            [
                "npm config set registry http://127.0.0.1:8080/",
                "pip config set global.index-url http://127.0.0.1:8080/simple/",
            ]
        );
    }

    #[test]
    fn an_unclaimed_path_goes_to_the_root() {
        for path in [
            "/lodash",
            "/@babel%2fcore",
            "/lodash/-/lodash-4.17.21.tgz",
            "/simple",
            "/packages",
            "/-/v1/search?text=lodash",
            "/",
        ] {
            assert_eq!(serving(path).ecosystem, ROOT, "{path}");
        }
    }

    #[test]
    fn of_answers_with_the_row_it_was_asked_for() {
        for ecosystem in Ecosystem::EXPRESSIBLE {
            assert_eq!(of(ecosystem).ecosystem, ecosystem);
        }
    }

    /// Each row reads its own ecosystem's media types and no other's.
    #[test]
    fn each_row_reads_only_its_own_media_types() {
        assert_eq!(
            of(Ecosystem::Npm).document(Some(npm::ABBREVIATED_ACCEPT)),
            Some(DocumentKind::Packument(DocumentDetail::Abbreviated)),
        );
        assert_eq!(of(Ecosystem::Npm).document(Some(pypi::SIMPLE_JSON)), None);
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(pypi::SIMPLE_JSON)),
            Some(DocumentKind::SimpleIndex(crate::route::IndexFormat::Json)),
        );
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(npm::ABBREVIATED_ACCEPT)),
            None,
        );
        for registry in TABLE {
            for media_type in registry.documents {
                assert!(
                    registry.document(Some(media_type)).is_some(),
                    "{} names {media_type} and does not read it",
                    registry.ecosystem.as_str()
                );
            }
            assert!(
                !registry.documents.is_empty(),
                "{} reads no document",
                registry.ecosystem.as_str()
            );
        }
        assert_eq!(
            of(Ecosystem::PyPI).document(Some("text/html; charset=utf-8")),
            Some(DocumentKind::SimpleIndex(crate::route::IndexFormat::Html)),
        );
        assert_eq!(of(Ecosystem::Npm).document(Some("text/html")), None);
    }

    /// A listed stream that the refresh does not load would grant coverage nothing fetches.
    #[test]
    fn every_listed_stream_is_one_the_refresh_loads() {
        for registry in TABLE {
            for listed in registry.streams {
                assert!(
                    stream::by_stream(listed.stream).is_some(),
                    "{} lists {}, which stream::ALL does not hold",
                    registry.ecosystem,
                    listed.stream
                );
            }
        }
    }

    /// A stream is listed by a row exactly when one of its grants is scoped to the listing.
    #[test]
    fn a_stream_is_listed_by_one_row_exactly_when_a_grant_is_scoped_to_its_listing() {
        for declared in stream::ALL {
            let listed_by = TABLE
                .iter()
                .filter(|registry| {
                    registry
                        .streams
                        .iter()
                        .any(|listed| listed.stream == declared.stream)
                })
                .count();
            let scoped = declared
                .grants
                .iter()
                .any(|grant| grant.scope == stream::Scope::Listed);
            assert_eq!(
                listed_by,
                usize::from(scoped),
                "{} is listed by {listed_by} rows",
                declared.stream
            );
        }
    }

    /// A PyPI record carries its own `published_at`, so a cooldown asks no registry about it.
    #[tokio::test]
    async fn publish_times_for_pypi_ask_nothing() {
        let nowhere = crate::util::test_support::NO_UPSTREAM;
        let upstreams = Upstreams::defaults()
            .with(Ecosystem::Npm, nowhere)
            .with(Ecosystem::PyPI, nowhere);
        let clients = Clients::new(reqwest::Client::new(), &upstreams, 1024);
        let idna = "pkg:pypi/idna".parse().expect("a purl");
        assert_eq!(clients.publish_times(&idna).await, Ok(None));
        let lodash = "pkg:npm/lodash".parse().expect("a purl");
        assert!(
            clients
                .publish_times(&lodash)
                .await
                .is_err_and(|e| e.starts_with("publish times could not be fetched")),
            "npm is asked, and nothing answers"
        );
    }

    #[test]
    fn a_fetch_failure_and_a_read_failure_say_which() {
        assert_eq!(
            fetched(Err("refused".to_owned())),
            Err("metadata could not be fetched: refused".to_owned())
        );
        assert_eq!(
            fetched(Ok(Err("not json".to_owned()))),
            Err("metadata could not be read: not json".to_owned())
        );
    }

    /// With nothing set, the clients use each ecosystem's default registry.
    #[test]
    fn clients_from_an_empty_environment_use_the_defaults() {
        let clients = Clients::from_env(&crate::env::testing::empty()).expect("defaults");
        let debug = format!("{clients:?}");
        assert!(debug.contains(npm::DEFAULT_REGISTRY), "{debug}");
        assert!(debug.contains(pypi::INDEX), "{debug}");
    }

    /// npm's client is what fetches a full packument, so another row declaring it would
    /// have npm asked about a package in a different registry.
    #[test]
    fn only_npm_reads_publish_times_from_a_full_packument() {
        let fetching: Vec<_> = TABLE
            .iter()
            .filter(|registry| registry.publish_times == PublishTimeSource::FullPackument)
            .map(|registry| registry.ecosystem)
            .collect();
        assert_eq!(fetching, [Ecosystem::Npm]);
    }

    /// `ReachableOrigins` normalises each of these, and a row with none would leave that
    /// ecosystem's own packages unreachable under the default policy.
    #[test]
    fn every_row_names_at_least_one_https_origin() {
        for registry in TABLE {
            assert!(
                !registry.always_reachable.is_empty(),
                "{} names no origin of its own",
                registry.ecosystem
            );
            for origin in registry.always_reachable {
                assert!(origin.starts_with("https://"), "{origin}");
                assert!(!origin.ends_with('/'), "{origin}");
            }
        }
    }
}
