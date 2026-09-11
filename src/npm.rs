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
use std::collections::BTreeMap;
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
/// at the moment the metadata goes past. All 24,852 artifact URLs measured are on
/// `registry.npmjs.org`.
///
/// `upstream` is the proxy's own upstream base, so a private registry serving its own
/// artifacts is not flagged.
pub fn bypassing_origin(artifact_url: &str, upstream: &str) -> Option<String> {
    let artifact = reqwest::Url::parse(artifact_url).ok()?;
    let origin = |url: &reqwest::Url| {
        format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap_or(""),
            url.port().map(|p| format!(":{p}")).unwrap_or_default()
        )
    };

    let found = origin(&artifact);
    let allowed = [upstream, DEFAULT_REGISTRY]
        .iter()
        .filter_map(|base| reqwest::Url::parse(base).ok())
        .map(|url| origin(&url))
        .collect::<Vec<_>>();

    if allowed.contains(&found) {
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
    pub fn bypassing_origins(&self, upstream: &str) -> BTreeMap<String, usize> {
        let mut origins = BTreeMap::new();
        for record in &self.records {
            if let Some(origin) = bypassing_origin(&record.artifact.url, upstream) {
                *origins.entry(origin).or_insert(0) += 1;
            }
        }
        origins
    }
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
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "registry request failed: {e}"),
            Self::Status(s) => write!(f, "registry answered {s}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Status(_) => None,
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
}

impl Client {
    /// `registry` is a base URL such as `https://registry.npmjs.org`. A trailing slash
    /// is accepted and trimmed.
    pub fn new(http: reqwest::Client, registry: impl Into<String>) -> Self {
        let registry = registry.into();
        Self {
            http,
            registry: registry.trim_end_matches('/').to_owned(),
        }
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
    /// Note that no `Accept-Encoding` is sent: reqwest's `gzip` feature is off
    /// crate-wide so the proxy forwards response bodies byte for byte, and enabling it
    /// for this client alone is not possible. Packuments therefore arrive uncompressed,
    /// which for a package like typescript is several megabytes. That cost is accepted
    /// for now rather than compromising the pass-through path.
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
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }

        let body = response.bytes().await.map_err(FetchError::Transport)?;
        Ok(normalize_packument(&body, detail))
    }
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
    /// WAHAROA_NPM_CORPUS=abbrev WAHAROA_NPM_CORPUS_FULL=full \
    ///     cargo test --lib -- --ignored --nocapture
    /// ```
    ///
    /// It fails on any skipped version. A registry shape the normaliser cannot read is
    /// exactly what fixtures will not surface.
    #[cfg(not(coverage))]
    #[test]
    #[ignore = "needs WAHAROA_NPM_CORPUS pointing at a directory of packuments"]
    fn real_packuments_normalise_without_skipping_anything() {
        let corpora: Vec<(String, PackumentDetail)> = [
            ("WAHAROA_NPM_CORPUS", PackumentDetail::Abbreviated),
            ("WAHAROA_NPM_CORPUS_FULL", PackumentDetail::Full),
        ]
        .iter()
        .filter_map(|(var, detail)| std::env::var(var).ok().map(|dir| (dir, *detail)))
        .collect();
        assert!(
            !corpora.is_empty(),
            "set WAHAROA_NPM_CORPUS and/or WAHAROA_NPM_CORPUS_FULL to corpus directories"
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
                            bypassing_origin(&record.artifact.url, DEFAULT_REGISTRY),
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
        }

        println!("{dir}: normalised {versions} versions across {packages} packages ({detail:?})");
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

        /// Nothing listening is a transport failure, and the outer `Result` is what
        /// carries it. This is the only branch a 502 is the right answer to.
        #[tokio::test]
        async fn an_unreachable_registry_is_a_transport_error() {
            // Bind and drop, so the port is one nothing is listening on.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);

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

    mod origins {
        use super::*;

        const UPSTREAM: &str = "https://registry.npmjs.org";

        /// The normal case: npm rewrites a default-registry tarball URL to whatever
        /// registry is configured, so the request arrives at the proxy.
        #[test]
        fn artifacts_on_the_default_registry_come_through_the_proxy() {
            assert_eq!(
                bypassing_origin(
                    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    UPSTREAM
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
                    "https://npm.corp.example"
                ),
                None,
                "this is the registry the operator pointed us at"
            );
            assert_eq!(
                bypassing_origin(
                    "http://127.0.0.1:8080/x/-/x-1.0.0.tgz",
                    "http://127.0.0.1:8080"
                ),
                None,
                "port and scheme are part of the origin, and these match"
            );
        }

        /// Any other origin is fetched directly, and the proxy sees nothing.
        #[test]
        fn any_other_origin_is_reported() {
            assert_eq!(
                bypassing_origin("https://evil.example/lodash-4.17.21.tgz", UPSTREAM),
                Some("https://evil.example".to_owned())
            );
            assert_eq!(
                bypassing_origin("https://registry.npmjs.org.evil.example/x.tgz", UPSTREAM),
                Some("https://registry.npmjs.org.evil.example".to_owned()),
                "a suffix of the real host is a different host"
            );
            assert_eq!(
                bypassing_origin(
                    "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    UPSTREAM
                ),
                Some("http://registry.npmjs.org".to_owned()),
                "a downgrade to http is a different origin"
            );
            assert_eq!(
                bypassing_origin("https://registry.npmjs.org:8443/x.tgz", UPSTREAM),
                Some("https://registry.npmjs.org:8443".to_owned()),
                "a different port is a different origin"
            );
        }

        /// A URL that does not parse names no origin to compare, so there is nothing to
        /// report. The version carrying it has no usable artifact either way.
        #[test]
        fn an_unparseable_url_reports_nothing() {
            assert_eq!(bypassing_origin("not a url", UPSTREAM), None);
            assert_eq!(bypassing_origin("/relative/path.tgz", UPSTREAM), None);
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

            let origins = p.bypassing_origins(UPSTREAM);
            assert_eq!(origins.len(), 2);
            assert_eq!(origins.get("https://evil.example"), Some(&2));
            assert_eq!(origins.get("https://other.example"), Some(&1));
        }

        #[test]
        fn an_ordinary_packument_reports_nothing() {
            let p = normalize("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
            assert!(p.bypassing_origins(UPSTREAM).is_empty());
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
