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
use crate::intel::stream::Stream;
use crate::lockfile::{Lockfile, Unread};
use crate::policy::facts::PublishTimes;
use crate::record::PackageMetadata;
use crate::route::{DocumentKind, RequestTarget};
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;

/// Metadata the proxy fetched itself: the outer error is the fetch, the inner the document.
pub type Fetched = Result<Result<PackageMetadata, String>, String>;

/// What an ecosystem's registry client answers for a request the proxy makes itself.
pub trait Fetch: Send + Sync + std::fmt::Debug {
    /// The package's metadata as records.
    fn metadata<'a>(&'a self, key: &'a PackageKey) -> BoxFuture<'a, Fetched>;

    /// The fuller document with publish times, for an ecosystem whose client asks for
    /// less. `Ok(None)` for one whose records carry `published_at`, which asks nothing.
    fn full<'a>(
        &'a self,
        key: &'a PackageKey,
    ) -> BoxFuture<'a, Result<Option<FullDocument>, String>>;
}

/// A metadata document the proxy read on its way to the client.
pub trait Document: Send + Sync {
    /// The records, when the document normalised.
    fn metadata(&self) -> Option<&PackageMetadata>;

    /// The body with refused versions removed and artifacts pointed at the proxy, or
    /// `None` to forward it as it came.
    fn rewrite(&self, rewriting: &Rewriting<'_>) -> Option<Vec<u8>>;
}

/// What an adapter's [`Registry::read`] is given: a metadata body on its way to the client.
pub struct Reading<'a> {
    pub decoded: &'a [u8],
    pub kind: DocumentKind,
    /// The upstream URL of the document, which relative links in it are resolved against.
    pub page: &'a str,
    pub store: &'a std::sync::Mutex<crate::store::RecordStore>,
    pub origins: &'a crate::origin::OriginPolicy,
    /// The body's size as it arrived, before decoding.
    pub encoded_bytes: usize,
    pub parse_started: std::time::Instant,
    pub path: &'a str,
}

/// What [`Document::rewrite`] is given.
pub struct Rewriting<'a> {
    pub decoded: &'a [u8],
    /// The proxy's own address, or `None` when artifacts are left on their own host.
    pub base: Option<&'a str>,
    pub origins: &'a crate::origin::OriginPolicy,
    /// Versions the policy refuses, which are removed.
    pub refused_by_policy: &'a std::collections::HashSet<String>,
    /// Whether a version on an origin the proxy does not serve is removed too.
    pub refuse_unservable: bool,
    pub path: &'a str,
}

/// What `byrle doctor` asks an upstream with `HEAD` under a cooldown, and what it makes of it.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamCheck {
    pub accept: &'static str,
    pub check: fn(&str, Option<&str>, bool) -> crate::doctor::Finding,
}

/// A document fetched for its publish times: [`Fetch::full`].
#[derive(Debug, Clone)]
pub struct FullDocument {
    /// Publish time by version, without `created` and `modified`.
    pub times: BTreeMap<String, jiff::Timestamp>,
    /// The records, or why the document did not normalise when its times did.
    pub metadata: Result<PackageMetadata, String>,
}

/// Each ecosystem's registry client, chosen by the package key, for a caller with no document.
#[derive(Debug, Clone)]
pub struct Clients(BTreeMap<Ecosystem, std::sync::Arc<dyn Fetch>>);

impl Clients {
    /// A client for each upstream. `max_bytes` bounds each decoded body.
    pub fn new(http: reqwest::Client, upstreams: &Upstreams, max_bytes: usize) -> Self {
        Self(
            TABLE
                .iter()
                .map(|row| {
                    let client =
                        (row.client)(http.clone(), upstreams.get(row.ecosystem), max_bytes);
                    (row.ecosystem, client)
                })
                .collect(),
        )
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

    fn of(&self, key: &PackageKey) -> &dyn Fetch {
        self.0[&key.ecosystem()].as_ref()
    }

    /// The package's metadata as records.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        self.of(key).metadata(key).await
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

    /// The full document, for an ecosystem whose client asks for less: [`Fetch::full`].
    pub async fn full_document(&self, key: &PackageKey) -> Result<Option<FullDocument>, String> {
        self.of(key).full(key).await
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
    /// The command line for a proxy reached at `base`, a URL without a trailing `/`.
    pub fn command_line(&self, base: &str) -> String {
        format!("{} {base}{}", self.command, self.path)
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

    /// The media types [`Registry::read_media_type`] reads, for `byrle status` to report.
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

    /// The package managers `byrle doctor` checks for this ecosystem.
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
    /// The registry client for the upstream, with each decoded body bounded.
    pub client: fn(reqwest::Client, &str, usize) -> std::sync::Arc<dyn Fetch>,
    /// A metadata body read on its way to the client, or `None` to forward it unread.
    pub read: fn(Reading<'_>) -> Option<Box<dyn Document>>,
    /// What reads an artifact file for the code it runs on install; `None` if it runs none.
    pub reader: fn(&str) -> Option<crate::analysis::Reader>,
    /// How an artifact file is laid out, or `None` for one the source comparison does not read.
    pub layout: fn(&str) -> Option<crate::analysis::source::Layout>,
    /// Where a record's source is; `None` when there is nothing to compare with.
    pub source: fn(&crate::record::PackageRecord) -> Option<crate::analysis::source::NamedSource>,
    /// The artifact's files against its repository's; `None` if it holds nothing of them.
    pub compare_source: fn(
        &crate::analysis::source::Tree,
        &crate::analysis::source::Tree,
        &crate::analysis::run::SourceJob,
    ) -> Option<crate::analysis::source::Comparison>,
    /// Why nothing was compared, when [`Registry::compare_source`] answers `None`.
    pub unfound_source: &'static str,
    /// Under a cooldown, what `byrle doctor` asks the upstream and makes of its answer.
    pub upstream_check: Option<UpstreamCheck>,
    /// Keeps of a version's files those that install on one of the targets, for `byrle warm`.
    pub keep_for_platforms: fn(&mut Vec<&crate::record::Artifact>, &[crate::lockfile::Target]),
    /// The name OSV gives this ecosystem, in `affected[].package.ecosystem` and its bundle's path.
    pub osv_name: &'static str,
    /// Whether a record's metadata would name a repository, so that naming none is a signal.
    pub metadata_names_repository: fn(&crate::record::PackageRecord) -> bool,
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

/// Every ecosystem the proxy routes, one row each, for which intel coverage is reported.
pub const TABLE: &[Registry] = &[npm::REGISTRY, pypi::REGISTRY];

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
    use crate::intel::stream;
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
            .map(|registry| registry.setup.command_line("http://127.0.0.1:8080"))
            .collect();
        assert_eq!(
            lines,
            [
                "npm config set registry http://127.0.0.1:8080/",
                "pip config set global.index-url http://127.0.0.1:8080/simple/",
            ]
        );
        assert_eq!(
            TABLE[0].setup.command_line("https://h/registry"),
            "npm config set registry https://h/registry/"
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
        for declared in stream::all() {
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

    /// Whether the item after a `#[cfg(test)]`, past other attributes, is a module.
    fn opens_module(after: &[&str]) -> bool {
        after
            .iter()
            .map(|line| line.trim())
            .find(|line| !line.starts_with("#["))
            .is_some_and(|line| line.starts_with("mod ") || line.starts_with("pub(crate) mod "))
    }

    /// An npm version installs the same file on every platform, so `warm` keeps every one.
    #[test]
    fn npm_keeps_every_file_for_any_platform() {
        let packument = npm::normalized(
            "lodash-4.17.21.abbrev.json",
            crate::record::DocumentDetail::Abbreviated,
        );
        let record = &packument.records[0];
        let mut files: Vec<&crate::record::Artifact> = record.artifacts.iter().collect();
        let before = files.len();
        let windows = crate::lockfile::Target::parse("win32-arm64").expect("a target");
        (npm::REGISTRY.keep_for_platforms)(&mut files, &[windows]);
        assert_eq!((files.len(), before), (1, 1));
    }

    /// A row reads only its own kind of document, and one it can parse; anything else is
    /// forwarded unread.
    #[test]
    fn a_row_reads_only_its_own_kind_of_document() {
        use crate::record::DocumentDetail;
        use crate::route::IndexFormat;
        let store = std::sync::Mutex::new(crate::store::RecordStore::new(10));
        let origins = crate::origin::OriginPolicy::new(
            crate::origin::ReachableOrigins::new([npm::DEFAULT_REGISTRY], std::iter::empty())
                .expect("valid origins"),
            std::iter::empty(),
        )
        .expect("valid policy");
        for (row, kind, body) in [
            (
                &npm::REGISTRY,
                DocumentKind::SimpleIndex(IndexFormat::Json),
                &b"{}"[..],
            ),
            (
                &pypi::REGISTRY,
                DocumentKind::Packument(DocumentDetail::Abbreviated),
                b"{}",
            ),
            (
                &pypi::REGISTRY,
                DocumentKind::SimpleIndex(IndexFormat::Json),
                b"not json",
            ),
        ] {
            let read = (row.read)(Reading {
                decoded: body,
                kind,
                page: "https://pypi.org/simple/x/",
                store: &store,
                origins: &origins,
                encoded_bytes: 2,
                parse_started: std::time::Instant::now(),
                path: "/x",
            });
            assert!(read.is_none(), "{:?}", row.ecosystem);
        }
    }

    /// Lines outside the adapters that name npm or PyPI, per file, until a file's tests:
    /// `npm::`, `pypi::`, `Ecosystem::Npm`, `Ecosystem::PyPI`.
    fn named_outside_adapters() -> std::collections::BTreeMap<String, usize> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        crate::util::test_support::rust_files(&root.join("src"), &mut files);
        let adapters = [
            root.join("src/ecosystem/npm"),
            root.join("src/ecosystem/pypi"),
        ];
        let identifier = |c: char| c.is_alphanumeric() || c == '_';
        let names = |line: &str| {
            ["npm::", "pypi::", "Ecosystem::Npm", "Ecosystem::PyPI"]
                .iter()
                .any(|name| {
                    line.match_indices(name)
                        .any(|(i, _)| !line[..i].chars().next_back().is_some_and(identifier))
                })
        };
        let mut found = std::collections::BTreeMap::new();
        for file in files
            .iter()
            .filter(|f| !adapters.iter().any(|a| f.starts_with(a)))
        {
            let text = std::fs::read_to_string(file).expect("readable");
            let lines: Vec<&str> = text.lines().collect();
            let tests = (0..lines.len())
                .find(|&i| lines[i].trim() == "#[cfg(test)]" && opens_module(&lines[i + 1..]))
                .unwrap_or(lines.len());
            let count = lines[..tests]
                .iter()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| names(line))
                .count();
            if count > 0 {
                let path = file.strip_prefix(root).unwrap_or(file);
                found.insert(path.display().to_string(), count);
            }
        }
        found
    }

    /// Stage 6's interface: what branches on npm or PyPI outside the adapters, per file. Each
    /// commit of docs/cargo-plan.md step 1 shortens this list; the step ends when it is empty.
    #[test]
    fn only_the_adapters_name_npm_or_pypi() {
        let allowed: std::collections::BTreeMap<String, usize> = [
            ("src/defer.rs", 1),
            ("src/ecosystem.rs", 2),
            ("src/env.rs", 4),
            ("src/identity.rs", 5),
            ("src/intel/range.rs", 1),
            ("src/intel/store.rs", 1),
            ("src/proxy.rs", 3),
            ("src/proxy/testing.rs", 1),
        ]
        .into_iter()
        .map(|(file, count): (&str, usize)| (file.to_owned(), count))
        .collect();
        assert_eq!(named_outside_adapters(), allowed);
    }
}
