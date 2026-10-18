//! Which registry answers a request, and what that registry does differently: one
//! [`Registry`] row per ecosystem in [`TABLE`], so a field must be filled in for every one.
//!
//! See docs/engineering_decisions/0047-adapter-interface.md.

pub mod cargo;
pub mod go;
pub mod maven;
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

    /// The record of `version` read on its own, for an ecosystem that serves versions its
    /// document does not list. `Ok(None)` for one that does not, or a version it lacks.
    fn version<'a>(
        &'a self,
        _key: &'a PackageKey,
        _version: &'a str,
    ) -> BoxFuture<'a, Result<Option<crate::record::PackageRecord>, String>> {
        Box::pin(async { Ok(None) })
    }

    /// A time for each of `metadata`'s versions, for an ecosystem whose document has none,
    /// read one version at a time until one is older than `before`. `Ok(None)` for others.
    fn dated<'a>(
        &'a self,
        _metadata: &'a PackageMetadata,
        _before: jiff::Timestamp,
    ) -> BoxFuture<'a, Result<Option<PublishTimes>, String>> {
        Box::pin(async { Ok(None) })
    }

    /// Where the file at `url` is served from after the repository's redirects, for one whose
    /// redirects say whose a file is. `Ok(None)` for others. Errors when it cannot be asked.
    fn located<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async { Ok(None) })
    }

    /// What a database beside the registry, or a file beside `file`, says of `version`'s
    /// files, for an ecosystem whose documents publish no digest. Errors when it cannot be
    /// asked or does not prove itself.
    fn claim<'a>(
        &'a self,
        _key: &'a PackageKey,
        _version: &'a str,
        _file: &'a str,
    ) -> BoxFuture<'a, Result<Claimed, String>> {
        Box::pin(async { Ok(Claimed::NotAsked) })
    }
}

/// What [`Fetch::claim`] found.
#[derive(Debug, Clone)]
pub enum Claimed {
    /// The registry's own documents publish the digests: nothing is asked.
    NotAsked,
    /// The database holds no record of the version, so its files cannot be checked.
    Unknown,
    /// The database's digests for the version's files.
    Known(Claim),
}

/// The digests a database publishes for a version's artifact and its manifest.
#[derive(Debug, Clone)]
pub struct Claim {
    /// The artifact's digest, in the database's own form, such as Go's `h1:`.
    pub artifact: String,
    /// The digest of an artifact's file, in that form.
    pub artifact_digest: fn(std::fs::File) -> Result<String, String>,
    /// The manifest's digest, in the same form: Go's `go.mod`.
    pub manifest: String,
    /// The digest of a manifest's bytes, in that form.
    pub manifest_digest: fn(&[u8]) -> String,
    /// What checks the file's signature, where the registry signs files: Maven's `.asc`.
    pub signer: Option<std::sync::Arc<dyn Signer>>,
}

/// What checks a file's detached signature, where the claim job holds the file's bytes.
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// What checks the signature, and by which rules, as its stored results are named.
    fn verifier(&self) -> &'static str;

    /// The file's signature and each key server's copy of the key it names, `None` when the
    /// file has no signature. Errors when the signature or a key server cannot be asked.
    fn material(&self) -> BoxFuture<'_, Result<Option<Material>, String>>;

    /// The most recent version before this one with a signature, for a file with none.
    /// Errors when the versions or their signatures cannot be asked.
    fn signed_before(&self) -> BoxFuture<'_, Result<Option<String>, String>>;

    /// What `material` says of `file`. Errors when `file` cannot be read.
    fn verify(&self, material: &Material, file: &mut dyn Source) -> std::io::Result<Signature>;
}

/// A file's bytes, read from any point: what a [`Signer`] checks.
pub trait Source: std::io::Read + std::io::Seek {}

impl<T: std::io::Read + std::io::Seek> Source for T {}

/// A file's signature, and each key server's copy of the key it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Material {
    pub signature: Vec<u8>,
    pub keys: Vec<String>,
}

/// What a file's signature says, stored by the digest of the bytes it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// It verified, made by the primary key with this fingerprint or one of its subkeys.
    Verified { key: String },
    /// It did not verify, and why.
    Failed { why: String },
    /// The file has none, and this earlier version's file had one.
    Dropped { previous: String },
    /// The file has none, nor did the versions before it that were asked.
    Unsigned,
}

impl Signature {
    /// The provenance fact it is: a failure is an attestation that does not verify, and a
    /// signature dropped is provenance dropped.
    pub fn provenance(&self) -> crate::policy::decide::Provenance {
        use crate::policy::decide::Provenance;
        match self {
            Self::Verified { .. } | Self::Unsigned => Provenance::Consistent,
            Self::Failed { why } => Provenance::Unverified { why: why.clone() },
            Self::Dropped { previous } => Provenance::Dropped {
                previous: previous.clone(),
                history: crate::policy::decide::History::default(),
            },
        }
    }
}

impl Claim {
    /// Whether `manifest` is the manifest this claims. Errors naming both digests when not.
    pub fn check_manifest(&self, manifest: &[u8]) -> Result<(), String> {
        let found = (self.manifest_digest)(manifest);
        if found == self.manifest {
            return Ok(());
        }
        Err(format!(
            "its digest is {found}, and the claim is {}",
            self.manifest
        ))
    }
}

/// A metadata document the proxy read on its way to the client.
pub trait Document: Send + Sync {
    /// The records, when the document normalised.
    fn metadata(&self) -> Option<&PackageMetadata>;

    /// The body with refused versions removed and artifacts pointed at the proxy, or
    /// `None` to forward it as it came.
    fn rewrite(&self, rewriting: &Rewriting<'_>) -> Option<Vec<u8>>;

    /// Whether removing `refused` leaves a document that names one version naming none,
    /// answered 404 as an absent one is.
    fn names_none(&self, _refused: &std::collections::HashSet<String>) -> bool {
        false
    }
}

/// What an adapter's [`Registry::read`] is given: a metadata body on its way to the client.
pub struct Reading<'a> {
    pub decoded: &'a [u8],
    pub kind: DocumentKind,
    /// The upstream URL of the document, which relative links in it are resolved against.
    pub page: &'a str,
    /// Where its records are kept, by the repository it came from.
    pub store: crate::store::Keeping<'a>,
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

/// What [`Registry::write`] is given: a request the proxy may answer itself.
pub struct Writing<'a> {
    pub path: &'a str,
    /// The address the client reached the proxy at, `None` when the request named none.
    pub base: Option<&'a str>,
    /// Whether the proxy asks every request for a token.
    pub tokens_required: bool,
}

/// A document [`Registry::write`] wrote.
pub struct Written {
    pub content_type: &'static str,
    pub body: Vec<u8>,
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

/// Each repository's registry client, for a caller with no document.
#[derive(Debug, Clone)]
pub struct Clients(BTreeMap<Repository, std::sync::Arc<dyn Fetch>>);

impl Clients {
    /// A client for each upstream. `max_bytes` bounds each decoded body.
    pub fn new(http: reqwest::Client, upstreams: &Upstreams, max_bytes: usize) -> Self {
        Self(
            upstreams
                .iter()
                .map(|(repository, base)| {
                    (repository, repository.client(http.clone(), base, max_bytes))
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

    /// These clients with `repository`'s replaced by `client`.
    #[cfg(test)]
    pub fn with(
        mut self,
        repository: impl Into<Repository>,
        client: std::sync::Arc<dyn Fetch>,
    ) -> Self {
        self.0.insert(repository.into(), client);
        self
    }

    /// `at`'s client, for `key`, a package of its ecosystem.
    fn of(&self, at: Repository, key: &PackageKey) -> &dyn Fetch {
        debug_assert_eq!(at.ecosystem(), key.ecosystem(), "{key} is not of {at}");
        self.0[&at].as_ref()
    }

    /// The package's metadata as records, from `at`.
    pub async fn metadata(&self, at: Repository, key: &PackageKey) -> Fetched {
        self.of(at, key).metadata(key).await
    }

    /// The record for `version` of `key`, from `at`'s metadata document.
    /// Errors when the document cannot be fetched or read.
    /// Returns `None` when the document does not list the version.
    pub async fn record(
        &self,
        at: Repository,
        key: &PackageKey,
        version: &str,
    ) -> Result<Option<crate::record::PackageRecord>, String> {
        Ok(fetched(self.metadata(at, key).await)?
            .version(version)
            .cloned())
    }

    /// Publish times fetched separately from the records. `Ok(None)` for an ecosystem
    /// whose records carry `published_at`, which asks nothing.
    pub async fn publish_times(
        &self,
        at: Repository,
        key: &PackageKey,
    ) -> Result<Option<PublishTimes>, String> {
        Ok(self.full_document(at, key).await?.map(|full| full.times))
    }

    /// The record of `version` read on its own: [`Fetch::version`].
    pub async fn version(
        &self,
        at: Repository,
        key: &PackageKey,
        version: &str,
    ) -> Result<Option<crate::record::PackageRecord>, String> {
        self.of(at, key).version(key, version).await
    }

    /// The record of `version` of `metadata`'s package: read on its own where the
    /// ecosystem serves versions its document does not list, else `metadata`'s.
    /// `Ok(None)` when neither has it.
    pub async fn version_of(
        &self,
        at: Repository,
        metadata: &PackageMetadata,
        version: &str,
    ) -> Result<Option<crate::record::PackageRecord>, String> {
        Ok(match self.version(at, &metadata.key, version).await? {
            Some(alone) => Some(alone),
            None => metadata.version(version).cloned(),
        })
    }

    /// A time for each of `metadata`'s versions: [`Fetch::dated`].
    pub async fn dated(
        &self,
        at: Repository,
        metadata: &PackageMetadata,
        before: jiff::Timestamp,
    ) -> Result<Option<PublishTimes>, String> {
        self.of(at, &metadata.key).dated(metadata, before).await
    }

    /// What a database beside the registry says of `version`'s `file`: [`Fetch::claim`].
    pub async fn claim(
        &self,
        at: Repository,
        key: &PackageKey,
        version: &str,
        file: &str,
    ) -> Result<Claimed, String> {
        self.of(at, key).claim(key, version, file).await
    }

    /// Where the file at `url` on `at` is served from: [`Fetch::located`].
    pub async fn located(&self, at: Repository, url: &str) -> Result<Option<String>, String> {
        self.0[&at].located(url).await
    }

    /// The full document, for an ecosystem whose client asks for less: [`Fetch::full`].
    pub async fn full_document(
        &self,
        at: Repository,
        key: &PackageKey,
    ) -> Result<Option<FullDocument>, String> {
        self.of(at, key).full(key).await
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
pub struct PublishTimeSource {
    /// Where the times are, as `byrle status` says it.
    pub said: &'static str,
    /// The `Accept` asking for the fuller document holding the times; `None` if the client's does.
    pub full_accept: Option<&'static str>,
    /// What a policy with `cooldown_days` costs, when it costs a request the client never made.
    pub cost: Option<&'static str>,
}

/// Each served ecosystem whose cooldown costs a request, and what it costs.
pub fn cooldown_costs() -> Vec<(Ecosystem, &'static str)> {
    TABLE
        .iter()
        .filter_map(|registry| Some((registry.ecosystem, registry.publish_times.cost?)))
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
    /// What points the client at `url`, the proxy's address with [`Setup::path`] after it.
    pub command: fn(&str) -> String,
    /// The path the proxy serves this ecosystem under, after the address.
    pub path: &'static str,
}

impl Setup {
    /// The command line for a proxy reached at `base`, a URL without a trailing `/`.
    pub fn command_line(&self, base: &str) -> String {
        (self.command)(&format!("{base}{}", self.path))
    }
}

/// Makes a [`Registry::publishers`] detector for a repository, `None` when its API is not asked.
pub type Publishers = fn(
    &reqwest::Client,
    Repository,
    &str,
    &crate::env::ApiSetting,
    std::time::Duration,
) -> Option<std::sync::Arc<dyn crate::analysis::detector::Detector>>;

/// What one ecosystem answers.
pub struct Registry {
    /// The ecosystem this row is for.
    pub ecosystem: Ecosystem,

    /// The path prefix this registry claims, whatever the path names, such as `/npm/`.
    pub prefix: &'static str,

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

    /// A `byrle doctor` check that fetches, such as Gradle's wrapper against its releases.
    pub fetched_check: Option<crate::doctor::FetchedCheck>,

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
    /// What reads a document of this ecosystem's attestations as a Sigstore bundle.
    pub provenance_bundle: fn(&[u8]) -> Result<sigstore_verify::types::Bundle, String>,
    /// The name OSV gives this ecosystem, in `affected[].package.ecosystem` and its bundle's path.
    pub osv_name: &'static str,
    /// The package an OSV record's name stands for, `None` for one that is no package here.
    pub advisory_package: fn(&str) -> Option<String>,
    /// Whether a record's metadata would name a repository, so that naming none is a signal.
    pub metadata_names_repository: fn(&crate::record::PackageRecord) -> bool,
    /// Why `install_scripts` is not analyzed until the artifact is read; `None` if metadata says.
    pub install_scripts_unread: Option<&'static str>,

    /// The detector asking the registry's API who published each version, where there is one.
    pub publishers: Option<Publishers>,
    /// The checks this ecosystem's registry gives no meaning to, such as npm's `yanked`.
    pub meaningless: &'static [crate::policy::merge::Rule],
    /// A document the proxy writes for this path rather than fetching; `None` to fetch it.
    pub write: fn(&Writing<'_>) -> Option<Result<Written, String>>,
    /// Whether an artifact's `HEAD` is refused as its `GET` is: Gradle reuses a file after one.
    pub decides_head: bool,
    /// The verifier whose stored signature results decide `provenance`, where files are signed.
    pub signatures: Option<&'static str>,
    /// The document a sidecar is the digest of, and that digest, where the proxy writes it.
    pub sidecar: fn(&str) -> Option<(String, Digest)>,
    /// The repositories this row serves besides its own, each under a prefix of its own.
    pub also: &'static [Also],
}

/// A repository a row serves besides its own: the Gradle plugin portal beside Central.
pub struct Also {
    /// The path prefix it is served under, such as `/gradle-plugins/`.
    pub prefix: &'static str,
    /// The variable naming its upstream.
    pub upstream: Var,
    /// The registry client for its upstream, with each decoded body bounded.
    pub client: fn(reqwest::Client, &str, usize) -> std::sync::Arc<dyn Fetch>,
    /// Where a redirect to says a file is the row's own repository's: the portal's to Central.
    pub own_at: &'static [&'static str],
}

/// A repository the proxy serves, a row's own or an [`Also`], keying what is read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Repository {
    ecosystem: Ecosystem,
    /// 0 for the row's own, else one more than its index in [`Registry::also`].
    index: u8,
}

impl Repository {
    /// `ecosystem`'s own repository.
    pub const fn of(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            index: 0,
        }
    }

    /// The `nth` of `ecosystem`'s row's [`Registry::also`], counted from 0.
    pub const fn also_of(ecosystem: Ecosystem, nth: u8) -> Self {
        Self {
            ecosystem,
            index: nth + 1,
        }
    }

    /// Every repository, in ecosystem order, each row's own first.
    pub fn all() -> impl Iterator<Item = Self> {
        TABLE.iter().flat_map(|row| {
            (0..=row.also.len()).map(move |index| Self {
                ecosystem: row.ecosystem,
                index: u8::try_from(index).expect("a row serves few repositories"),
            })
        })
    }

    /// The repository named `name`, as [`Repository::name`] writes it.
    pub fn named(name: &str) -> Option<Self> {
        Self::all().find(|repository| repository.name() == name)
    }

    pub fn ecosystem(self) -> Ecosystem {
        self.ecosystem
    }

    /// Whether it is its row's own, not one of its [`Also`].
    pub fn is_own(self) -> bool {
        self.index == 0
    }

    /// The row serving it.
    pub fn registry(self) -> &'static Registry {
        of(self.ecosystem)
    }

    /// The [`Also`] it is, `None` for a row's own.
    pub fn also(self) -> Option<&'static Also> {
        let index = usize::from(self.index).checked_sub(1)?;
        Some(&self.registry().also[index])
    }

    /// The path prefix it is served under.
    pub fn prefix(self) -> &'static str {
        self.also()
            .map_or(self.registry().prefix, |also| also.prefix)
    }

    /// The variable naming its upstream.
    pub fn upstream(self) -> Var {
        self.also()
            .map_or(self.registry().upstream, |also| also.upstream)
    }

    /// Its ecosystem's purl type for a row's own, `golang` and `maven`, and its prefix
    /// without slashes for an [`Also`], `gradle-plugins`.
    pub fn name(self) -> &'static str {
        self.also().map_or(self.ecosystem.as_str(), |also| {
            also.prefix.trim_matches('/')
        })
    }

    /// The registry client for `upstream`, with each decoded body bounded.
    fn client(
        self,
        http: reqwest::Client,
        upstream: &str,
        max_bytes: usize,
    ) -> std::sync::Arc<dyn Fetch> {
        let client = self
            .also()
            .map_or(self.registry().client, |also| also.client);
        client(http, upstream, max_bytes)
    }
}

/// [`Repository::name`].
impl std::fmt::Display for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl From<Ecosystem> for Repository {
    fn from(ecosystem: Ecosystem) -> Self {
        Self::of(ecosystem)
    }
}

/// A digest of a document's bytes, as hex: a [`Registry::sidecar`]'s.
pub type Digest = fn(&[u8]) -> String;

/// Each served repository's upstream base, with no trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstreams(BTreeMap<Repository, String>);

impl Upstreams {
    /// Each repository's public registry.
    pub fn defaults() -> Self {
        Self(
            Repository::all()
                .map(|repository| {
                    let base = repository
                        .upstream()
                        .default_text()
                        .expect("an upstream variable names its default");
                    (repository, trimmed(base))
                })
                .collect(),
        )
    }

    /// These upstreams with `repository`'s at `base`. A trailing slash is accepted.
    pub fn with(mut self, repository: impl Into<Repository>, base: &str) -> Self {
        self.0.insert(repository.into(), trimmed(base));
        self
    }

    /// `repository`'s upstream base.
    pub fn get(&self, repository: impl Into<Repository>) -> &str {
        &self.0[&repository.into()]
    }

    /// Every upstream base, in repository order.
    pub fn bases(&self) -> impl Iterator<Item = &str> {
        self.0.values().map(String::as_str)
    }

    /// Each repository and its upstream base, in repository order.
    pub fn iter(&self) -> impl Iterator<Item = (Repository, &str)> {
        self.0
            .iter()
            .map(|(repository, base)| (*repository, base.as_str()))
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
    /// What `path` refers to, in this registry's spelling.
    pub fn classify(&self, path: &str) -> RequestTarget {
        (self.classify_path)(path)
    }

    /// Which metadata document a body with this `Content-Type` is, if any.
    pub fn document(&self, content_type: Option<&str>) -> Option<DocumentKind> {
        (self.read_media_type)(content_type)
    }
}

/// Every ecosystem the proxy routes, one row each, for which intel coverage is reported.
pub const TABLE: &[Registry] = &[
    npm::REGISTRY,
    pypi::REGISTRY,
    cargo::REGISTRY,
    go::REGISTRY,
    maven::REGISTRY,
];

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

/// `path` without `prefix`'s final segment, keeping its leading `/`: `/npm/lodash` under
/// `/npm/` is `/lodash`. `None` when the path is not under it.
pub fn within<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    path.strip_prefix(prefix.trim_end_matches('/'))
        .filter(|rest| rest.starts_with('/'))
}

/// `name` itself, for [`Registry::advisory_package`] where an advisory names its package.
pub fn as_named(name: &str) -> Option<String> {
    Some(name.to_owned())
}

/// The repository whose prefix claims `path`, its query dropped. `None` when none does.
pub fn serving(path: &str) -> Option<Repository> {
    let path = path.split('?').next().unwrap_or(path);
    Repository::all().find(|repository| path.starts_with(repository.prefix()))
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
            .record(Repository::of(Ecosystem::Npm), &key, "4.17.21")
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

    /// The directory of a row's adapter, under `src/ecosystem/`: its prefix's name.
    fn adapter(registry: &Registry) -> &'static str {
        registry.prefix.trim_matches('/')
    }

    /// Each row's prefix names its adapter, so no path can be two rows'. Go's is `go`, not
    /// its purl type `golang`.
    #[test]
    fn each_row_claims_its_adapter_s_name() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ecosystem");
        for registry in TABLE {
            assert_eq!(registry.prefix, format!("/{}/", adapter(registry)));
            assert!(root.join(adapter(registry)).is_dir(), "{}", registry.prefix);
        }
        let mut claimed: Vec<&str> = Repository::all().map(Repository::prefix).collect();
        let before = claimed.len();
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(
            claimed.len(),
            before,
            "a prefix is claimed by two repositories"
        );
    }

    /// Each repository is named by its row's purl type or its own prefix, and found again
    /// by that name. The portal is Maven's, under a prefix and upstream of its own.
    #[test]
    fn a_repository_is_named_and_found_by_its_name() {
        let names: Vec<String> = Repository::all().map(|r| r.to_string()).collect();
        assert_eq!(
            names,
            ["npm", "pypi", "cargo", "golang", "maven", "gradle-plugins"]
        );
        for repository in Repository::all() {
            assert_eq!(Repository::named(repository.name()), Some(repository));
        }
        assert_eq!(Repository::named("central"), None);
        let portal = Repository::named("gradle-plugins").unwrap();
        assert_eq!(portal.ecosystem(), Ecosystem::Maven);
        assert!(!portal.is_own());
        assert!(Repository::of(Ecosystem::Maven).is_own());
        assert_eq!(portal.prefix(), "/gradle-plugins/");
        assert_eq!(portal.upstream(), crate::env::UPSTREAM_GRADLE_PLUGINS);
        assert_eq!(
            Upstreams::defaults().get(portal),
            "https://plugins.gradle.org/m2"
        );
        assert_eq!(
            serving("/gradle-plugins/com/github/ben-manes/versions/x/maven-metadata.xml"),
            Some(portal)
        );
    }

    /// A registry whose redirects say nothing of whose a file is is not asked where it is.
    #[tokio::test]
    async fn only_a_repository_whose_redirects_say_whose_a_file_is_is_asked_where_it_is() {
        let nowhere = crate::util::test_support::NO_UPSTREAM;
        let upstreams = Upstreams::defaults().with(Ecosystem::Npm, nowhere);
        let clients = Clients::new(reqwest::Client::new(), &upstreams, 1024);
        let npm = Repository::of(Ecosystem::Npm);
        assert_eq!(
            clients.located(npm, &format!("{nowhere}/x")).await,
            Ok(None)
        );
    }

    /// A client is asked of the repository named, not of its ecosystem's own.
    #[tokio::test]
    async fn each_repository_has_a_client_of_its_own() {
        use crate::util::test_support::{Answer, recorded};
        let (central, from_central) = recorded(vec![]).await;
        let (portal, from_portal) = recorded(vec![Answer::Status(404)]).await;
        let plugins = Repository::named("gradle-plugins").unwrap();
        let upstreams = Upstreams::defaults()
            .with(Ecosystem::Maven, &format!("http://{central}/maven2"))
            .with(plugins, &format!("http://{portal}/m2"));
        let clients = Clients::new(reqwest::Client::new(), &upstreams, 1024);
        let key = PackageKey::from_registry_name(Ecosystem::Maven, "a.b:c").unwrap();
        assert!(clients.metadata(plugins, &key).await.is_err());
        assert_eq!(from_portal.lock().unwrap().len(), 1);
        assert!(from_central.lock().unwrap().is_empty());
    }

    #[test]
    fn a_prefixed_path_goes_to_the_row_that_claims_it() {
        for (path, ecosystem) in [
            ("/npm/lodash", Ecosystem::Npm),
            ("/npm/cargo/-/cargo-0.8.0.tgz", Ecosystem::Npm),
            ("/npm/-/v1/search?text=lodash", Ecosystem::Npm),
            ("/pypi/simple/", Ecosystem::PyPI),
            ("/pypi/simple/requests/?foo=1", Ecosystem::PyPI),
            (
                "/pypi/packages/a/b/c/requests-2.32.3-py3-none-any.whl",
                Ecosystem::PyPI,
            ),
            ("/cargo/config.json", Ecosystem::Cargo),
            ("/cargo/crates/itoa/1.0.18/download", Ecosystem::Cargo),
            ("/go/golang.org/x/text/@v/list", Ecosystem::Go),
            ("/go/sumdb/sum.golang.org/latest", Ecosystem::Go),
            (
                "/maven/org/apache/commons/commons-lang3/maven-metadata.xml",
                Ecosystem::Maven,
            ),
            (
                "/gradle-plugins/org/apache/commons/commons-lang3/maven-metadata.xml",
                Ecosystem::Maven,
            ),
        ] {
            assert_eq!(
                serving(path).map(|r| r.ecosystem),
                Some(ecosystem),
                "{path}"
            );
        }
    }

    /// No row answers a path outside every prefix, npm's old root paths among them.
    #[test]
    fn an_unclaimed_path_is_no_row_s() {
        for path in [
            "/lodash",
            "/simple/requests/",
            "/npm",
            "/",
            "/golang/x/@v/list",
        ] {
            assert!(serving(path).is_none(), "{path}");
        }
    }

    /// PyPI's index and cargo's carry each version's time, so only npm's, Go's and Maven's
    /// cooldowns cost a fetch.
    #[test]
    fn only_an_ecosystem_that_fetches_publish_times_reports_a_cooldown_cost() {
        let costs = cooldown_costs();
        assert_eq!(
            costs.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
            [Ecosystem::Npm, Ecosystem::Go, Ecosystem::Maven]
        );
        assert!(costs[0].1.contains("full-packument fetch"));
        assert_eq!(pypi::REGISTRY.publish_times.cost, None);
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
                "npm config set registry http://127.0.0.1:8080/npm/",
                "pip config set global.index-url http://127.0.0.1:8080/pypi/simple/",
                &cargo::REGISTRY.setup.command_line("http://127.0.0.1:8080"),
                &go::REGISTRY.setup.command_line("http://127.0.0.1:8080"),
                &maven::REGISTRY.setup.command_line("http://127.0.0.1:8080"),
            ]
        );
        assert_eq!(
            TABLE[0].setup.command_line("https://h/registry"),
            "npm config set registry https://h/registry/npm/"
        );
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
        let at = |ecosystem| Repository::of(ecosystem);
        assert_eq!(
            clients.publish_times(at(Ecosystem::PyPI), &idna).await,
            Ok(None)
        );
        let lodash = "pkg:npm/lodash".parse().expect("a purl");
        assert!(
            clients
                .publish_times(at(Ecosystem::Npm), &lodash)
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
            .filter(|registry| registry.publish_times.full_accept.is_some())
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

    /// `text`'s lines outside each `#[cfg(test)]` or `#[cfg(kani)]` module, wherever it is.
    fn outside_tests(text: &str) -> Vec<&str> {
        let lines: Vec<&str> = text.lines().collect();
        let mut kept = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let gate = matches!(lines[i].trim(), "#[cfg(test)]" | "#[cfg(kani)]");
            if !(gate && opens_module(&lines[i + 1..])) {
                kept.push(lines[i]);
                i += 1;
                continue;
            }
            let mut depth = 0i64;
            let mut opened = false;
            while i < lines.len() {
                depth +=
                    lines[i].matches('{').count() as i64 - lines[i].matches('}').count() as i64;
                opened |= lines[i].contains('{');
                i += 1;
                if opened && depth == 0 || !opened && lines[i - 1].trim_end().ends_with(';') {
                    break;
                }
            }
        }
        kept
    }

    /// Whether the item after a `#[cfg(test)]`, past other attributes, is a module.
    fn opens_module(after: &[&str]) -> bool {
        after
            .iter()
            .map(|line| line.trim())
            .find(|line| !line.starts_with("#["))
            .is_some_and(|line| {
                ["mod ", "pub mod ", "pub(crate) mod "]
                    .iter()
                    .any(|start| line.starts_with(start))
            })
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
            (
                &cargo::REGISTRY,
                DocumentKind::SimpleIndex(IndexFormat::Json),
                b"{}",
            ),
        ] {
            let read = (row.read)(Reading {
                decoded: body,
                kind,
                page: "https://pypi.org/simple/x/",
                store: crate::store::Keeping {
                    store: &store,
                    at: Repository::of(row.ecosystem),
                },
                origins: &origins,
                encoded_bytes: 2,
                parse_started: std::time::Instant::now(),
                path: "/x",
            });
            assert!(read.is_none(), "{:?}", row.ecosystem);
        }
    }

    /// Lines outside the adapters that name a row's ecosystem, per file, until a file's
    /// tests: `npm::` or `Ecosystem::Npm`, and the same for each row.
    fn named_outside_adapters() -> std::collections::BTreeMap<String, usize> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        crate::util::test_support::rust_files(&root.join("src"), &mut files);
        let adapters: Vec<_> = TABLE
            .iter()
            .map(|row| root.join("src/ecosystem").join(adapter(row)))
            .collect();
        let spellings: Vec<String> = TABLE
            .iter()
            .flat_map(|row| {
                [
                    format!("{}::", adapter(row)),
                    format!("Ecosystem::{:?}", row.ecosystem),
                ]
            })
            .collect();
        let identifier = |c: char| c.is_alphanumeric() || c == '_';
        let names = |line: &str| {
            spellings.iter().any(|name| {
                line.match_indices(name)
                    .any(|(i, _)| !line[..i].chars().next_back().is_some_and(identifier))
            })
        };
        let mut found = std::collections::BTreeMap::new();
        for file in files
            .iter()
            .filter(|f| !adapters.iter().any(|a| f.starts_with(a)))
        {
            if file.ends_with("testing.rs") || file.ends_with("test_support.rs") {
                continue;
            }
            let text = std::fs::read_to_string(file).expect("readable");
            let count = outside_tests(&text)
                .into_iter()
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

    /// Stage 6's interface: only declarations name an ecosystem outside its adapter, the
    /// `Ecosystem` enum, `TABLE` and the environment's variables (docs/cargo-plan.md step 1).
    #[test]
    fn only_the_adapters_name_an_ecosystem() {
        let allowed: std::collections::BTreeMap<String, usize> = [
            ("src/ecosystem.rs", 5),
            ("src/env.rs", 8),
            ("src/identity.rs", 15),
        ]
        .into_iter()
        .map(|(file, count): (&str, usize)| (file.to_owned(), count))
        .collect();
        assert_eq!(named_outside_adapters(), allowed);
    }
}
