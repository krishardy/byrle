//! The common package record: registry metadata normalised into one shape.
//!
//! This is the contract between the per-ecosystem normalisers and everything above
//! them (plan §4). The policy engine operates only on this type and never sees a
//! packument, a PEP 503 index, or a sparse index entry.
//!
//! # What the proxy can actually see, and why so much is `Option`
//!
//! npm asks for the *abbreviated* packument
//! (`Accept: application/vnd.npm.install-v1+json`), and a pass-through proxy sees only
//! what the client asked for. Measured against real packuments (Sept 2026):
//!
//! | Field | Abbreviated | Full |
//! |---|---|---|
//! | name, version, `dist.*` | yes | yes |
//! | `hasInstallScript` | yes | **no**, use `scripts` |
//! | `dist.attestations`, `dist.signatures` | yes | yes |
//! | publish time (`time`) | **no** | yes |
//! | `maintainers` | **no** | yes |
//! | `repository` | **no** | yes |
//! | `scripts` bodies | **no** | yes |
//!
//! So cooldown, maintainer heuristics and source diffing all need a document npm never
//! requests. At Stage 1 those fields are `None` for every record, which is correct
//! rather than a gap: fetching the full document is fetch-path work that has not
//! started.
//!
//! [`DocumentDetail`] is what makes `None` readable. `published_at == None` with
//! [`DocumentDetail::Abbreviated`] means "not fetched"; with
//! [`DocumentDetail::Full`] it means "the registry does not publish it". A policy
//! engine has to tell those apart, or a missing timestamp silently reads as "not in
//! cooldown" and fails open. Deriving that distinction belongs with the rule that
//! consumes it, in Stage 2.

use crate::identity::{PackageKey, PackageRef};
use std::collections::BTreeMap;

/// Which document a record was built from. See the module docs: this is what
/// distinguishes "we did not fetch it" from "the registry does not have it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentDetail {
    /// npm's `application/vnd.npm.install-v1+json`, which is what installs request.
    Abbreviated,
    /// The complete document, which carries publish times, maintainers and repository.
    Full,
}

/// One version that could not be normalised, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedVersion {
    /// The version as the document spelled it: npm's `versions` map key, PyPI's version
    /// read from a filename.
    pub version: String,
    pub reason: String,
}

/// Every version of one package, normalised.
///
/// What each ecosystem's normaliser produces and the record store holds: npm's packument
/// and PyPI's simple index both reach this shape, and nothing above it sees either
/// document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMetadata {
    /// Identity taken from the document's own name, never from the request path.
    /// A request for `/Lodash` can be answered with a document naming `lodash`, and the
    /// document is what the client installs (see `identity`).
    pub key: PackageKey,
    /// The version a client takes when it names none, when the document says. npm's
    /// `dist-tags.latest`; `None` for PyPI, whose index has no equivalent.
    ///
    /// Not resolved into a record here: a tag can name a version the document omits.
    pub latest: Option<String>,
    /// One record per usable version, in the order the document listed them.
    pub records: Vec<PackageRecord>,
    /// Versions present in the document that produced no record. Empty in the normal
    /// case; never silently discarded.
    pub skipped: Vec<SkippedVersion>,
}

impl PackageMetadata {
    /// The record for one exact version string, if the document carried it.
    pub fn version(&self, version: &str) -> Option<&PackageRecord> {
        self.records.iter().find(|r| r.package.version() == version)
    }
}

/// One version of one package, as the policy engine sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    /// Ecosystem, name and version. Casing is preserved exactly; see `identity`.
    pub package: PackageRef,
    /// Which document this came from, which qualifies every `None` below.
    pub detail: DocumentDetail,

    /// When this version was published. Drives cooldown (plan §3, Tier 1).
    ///
    /// Comes from the packument-level `time` map keyed by version string, not from the
    /// version object. Full packument only.
    pub published_at: Option<jiff::Timestamp>,

    /// Full packument only. Feeds the maintainer-age and sudden-maintainer-change
    /// heuristics.
    pub maintainers: Option<Vec<Maintainer>>,

    /// Full packument only. Needed for registry-versus-source diffing, and its absence
    /// is itself a metadata heuristic.
    pub repository: Option<Repository>,

    /// The reason the registry gave for withdrawing every file this version offers.
    ///
    /// A resolver ignores a yanked file unless the requirement pins that version
    /// (PEP 592), so a version with one file left is still a version to resolve to, and
    /// this is `None`. It is about the version; [`Artifact::yanked`] is about the file a
    /// request names.
    pub yanked: Option<String>,

    /// The message the publisher left when deprecating this version, where they left one.
    ///
    /// npm's `deprecated`. Reported, never refused: npm installs a deprecated version
    /// after printing a warning, and no npm client skips one. See
    /// `docs/engineering_decisions/yanked-files.md`. PyPI has no equivalent.
    pub deprecated: Option<String>,

    /// Whether installing this version runs a lifecycle script.
    ///
    /// Not optional, because both documents can answer it, by different routes.
    /// Abbreviated sets `hasInstallScript: true` and omits the key otherwise; the full
    /// packument never carries that key and requires reading `scripts` for
    /// `preinstall`, `install` or `postinstall`. Verified equivalent across 24,852
    /// version pairs from 47 packages, with no disagreement.
    pub has_install_scripts: bool,

    /// The lifecycle script bodies, when we have them. Full packument only, so
    /// `has_install_scripts` can be true while this is `None`.
    pub install_scripts: Option<BTreeMap<String, String>>,

    /// Attestations and signatures. Present in both documents.
    pub provenance: Provenance,

    /// The files this version offers, the one a resolver would take first.
    ///
    /// npm holds exactly one: a version resolves to a tarball. PyPI holds one per file
    /// the index lists for the version, wheels before sdists, because `requests` 2.32.3
    /// is a wheel and an sdist with different digests and different install behaviour.
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

/// A source repository, stored as the registry reported it.
///
/// npm accepts two shapes, an object with `url` and `type`, and the shorthand string
/// form such as `github:user/repo`. Both normalise to this. The `Deserialize` that does
/// it lives in `npm` and is hand-written rather than `#[serde(untagged)]`, which
/// silently defeats unknown-field rejection (plan §5).
///
/// The URL is kept verbatim, including any `git+https://` prefix. Canonicalising it
/// into something comparable against a git remote is source-diffing work (Stage 4),
/// and doing it here would lose what the registry actually said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub url: String,
    /// `git`, `svn`, and so on. Absent in the shorthand form.
    pub kind: Option<String>,
    /// Subdirectory within the repository holding this package, as npm's `directory`
    /// field. Set for monorepo packages: `@babel/traverse` reports
    /// `packages/babel-traverse`. Source diffing that ignores it compares the package
    /// against the whole repository tree.
    pub directory: Option<String>,
}

/// Evidence about who produced this artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    /// `dist.attestations.url`, where the attestation bundle can be fetched.
    ///
    /// Presence means the package *claims* provenance. The claim is verified by the
    /// `provenance` check: see `docs/engineering_decisions/provenance-check.md`.
    pub attestation_url: Option<String>,
    /// `dist.attestations.provenance.predicateType`, e.g. the SLSA provenance URI.
    pub predicate_type: Option<String>,
    /// `dist.signatures`: the registry's own signature over the artifact. This attests
    /// that the registry served it, not that the named maintainer built it.
    pub registry_signatures: Vec<RegistrySignature>,
    /// `_npmUser.trustedPublisher`, present when the version was published by a
    /// trusted OIDC publisher such as GitHub Actions rather than a user token. Full
    /// packument only.
    pub trusted_publisher: Option<TrustedPublisher>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySignature {
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPublisher {
    /// The publisher identity, e.g. `github`.
    pub id: String,
}

/// One file a version offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// The filename as the registry serves it, which is what a request names. On PyPI
    /// two files of one version differ only here.
    pub filename: String,

    /// Whether installing **this file** runs the package's own code.
    ///
    /// Equal to `PackageRecord::has_install_scripts` on npm, where a version is one file.
    /// On PyPI a wheel runs nothing and an sdist runs `setup.py`, so the version-level
    /// answer is about the file a resolver would take and this one is about the file
    /// actually fetched.
    pub runs_install_scripts: bool,

    /// Absolute URL as the registry gave it.
    ///
    /// npm rewrites this to the configured registry **only when it names the default
    /// registry host**. Tested against npm 9.9.4: a packument advertising
    /// `https://registry.npmjs.org/...` was fetched through the configured proxy, and
    /// one advertising another origin was fetched from that origin directly, which the
    /// proxy never saw. An earlier note here said npm ignores this host outright; that
    /// is wrong, and the difference is a bypass vector (README, plan §7).
    pub url: String,

    /// `dist.integrity`, a Subresource Integrity string, in practice `sha512-<base64>`.
    ///
    /// Optional because npm predates it: of 24,852 versions measured, two published in
    /// 2012 carry only `shasum`. For those, SHA-1 is the strongest digest the registry
    /// offers.
    ///
    /// Plan §5: this is a **cache key, not a trust anchor**. It is what the registry
    /// claims, so it decides whether this artifact has been analysed before; it does
    /// not establish that the bytes are honest. We verify what actually arrives
    /// against it, and a mismatch is a finding.
    pub integrity: Option<String>,

    /// The reason the registry gave for withdrawing this file, empty when it gave none.
    ///
    /// PyPI's PEP 592 yank: the file stays in the index and stays downloadable, with the
    /// reason beside it. `None` is not yanked, which is every npm artifact.
    pub yanked: Option<String>,

    /// `dist.shasum`, a legacy SHA-1 digest.
    ///
    /// Deliberately its own field rather than sitting in a list beside `integrity`:
    /// SHA-1 is collision-broken, and a weak digest indistinguishable from a strong
    /// one invites code that treats them alike.
    pub legacy_sha1: Option<String>,

    pub file_count: Option<u64>,
    pub unpacked_size: Option<u64>,
}

impl PackageRecord {
    /// The file a resolver would take, which is the first.
    ///
    /// `None` when the registry named no file for this version. npm never does; the
    /// caller treats it the same as a missing digest, which is to serve the bytes and
    /// say they were not verified.
    pub fn artifact(&self) -> Option<&Artifact> {
        self.artifacts.first()
    }

    /// The file a request named.
    pub fn artifact_named(&self, filename: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.filename == filename)
    }

    /// Whether installing the file a request named runs the package's own code.
    ///
    /// Falls back to the version-level answer when the filename names no file this
    /// record holds, which is the conservative direction: a PyPI version offering a
    /// wheel and an sdist answers `false` there, so an unrecognised filename is checked
    /// again at [`Self::artifact_named`] by the caller before it is served.
    pub fn runs_install_scripts(&self, filename: Option<&str>) -> bool {
        match filename.and_then(|f| self.artifact_named(f)) {
            Some(artifact) => artifact.runs_install_scripts,
            None => self.has_install_scripts,
        }
    }

    /// This record as it applies to one file.
    ///
    /// `has_install_scripts` becomes that file's own answer and `artifacts` holds it
    /// alone, so a policy decision made from the result is about the bytes the client
    /// asked for. `None` when the record names no such file.
    pub fn narrowed_to(&self, filename: &str) -> Option<Self> {
        let artifact = self.artifact_named(filename)?.clone();
        Some(Self {
            has_install_scripts: artifact.runs_install_scripts,
            yanked: artifact.yanked.clone(),
            artifacts: vec![artifact],
            ..self.clone()
        })
    }

    /// Whether a field being `None` could be explained by not having fetched enough.
    ///
    /// Callers deciding a verdict must not read `None` as a negative when this is
    /// true: an unknown publish time is not the same as a package being old enough.
    pub fn may_be_incomplete(&self) -> bool {
        self.detail == DocumentDetail::Abbreviated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};

    fn reference(name: &str, version: &str) -> PackageRef {
        PackageKey::from_registry_name(Ecosystem::Npm, name)
            .unwrap()
            .at_version(version)
            .unwrap()
    }

    fn abbreviated(name: &str, version: &str, has_scripts: bool) -> PackageRecord {
        PackageRecord {
            package: reference(name, version),
            detail: DocumentDetail::Abbreviated,
            published_at: None,
            maintainers: None,
            repository: None,
            deprecated: None,
            has_install_scripts: has_scripts,
            yanked: None,
            install_scripts: None,
            provenance: Provenance::default(),
            artifacts: vec![Artifact {
                filename: format!("{name}-{version}.tgz"),
                runs_install_scripts: has_scripts,
                yanked: None,
                url: format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                integrity: Some("sha512-AAAA".into()),
                legacy_sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".into()),
                file_count: Some(9),
                unpacked_size: Some(37893),
            }],
        }
    }

    /// The distinction the whole `source` field exists for.
    #[test]
    fn missing_fields_are_qualified_by_the_document_they_came_from() {
        let abbrev = abbreviated("lodash", "4.17.21", false);
        assert!(abbrev.published_at.is_none());
        assert!(
            abbrev.may_be_incomplete(),
            "an abbreviated record cannot carry a publish time, so None means unfetched"
        );

        let full = PackageRecord {
            detail: DocumentDetail::Full,
            ..abbreviated("lodash", "4.17.21", false)
        };
        assert!(
            !full.may_be_incomplete(),
            "in a full record None means the registry does not publish it"
        );
    }

    /// `has_install_scripts` is answerable from either document, so it is not optional.
    /// The script bodies are a separate question and often unavailable.
    #[test]
    fn install_scripts_flag_is_definite_even_when_bodies_are_not() {
        let record = abbreviated("esbuild", "0.28.2", true);
        assert!(record.has_install_scripts);
        assert!(
            record.install_scripts.is_none(),
            "abbreviated packuments carry the flag but never the bodies"
        );
    }

    /// The two digests must stay distinguishable. SHA-1 is collision-broken and must
    /// never be reachable through the same accessor as the SRI digest.
    #[test]
    fn weak_and_strong_digests_are_separate_fields() {
        let record = abbreviated("lodash", "4.17.21", false);
        let artifact = record.artifact().expect("one file");
        assert!(
            artifact
                .integrity
                .as_deref()
                .expect("an SRI digest")
                .starts_with("sha512-")
        );
        assert_eq!(artifact.legacy_sha1.as_deref().expect("a shasum").len(), 40);
    }

    /// A record holding no file answers `None` rather than panicking. The proxy treats it
    /// the same as a missing digest: serve the bytes, say they were not verified.
    #[test]
    fn a_record_naming_no_file_has_no_preferred_file() {
        let mut record = abbreviated("lodash", "4.17.21", false);
        record.artifacts.clear();
        assert!(record.artifact().is_none());
        assert!(record.artifact_named("lodash-4.17.21.tgz").is_none());
        assert!(record.narrowed_to("lodash-4.17.21.tgz").is_none());
    }

    /// An npm version is one file, so the version-level install-scripts answer and the
    /// file's own are the same answer, and narrowing changes nothing.
    #[test]
    fn narrowing_an_npm_record_to_its_only_file_changes_nothing() {
        let record = abbreviated("lodash", "4.17.21", true);
        let narrowed = record
            .narrowed_to("lodash-4.17.21.tgz")
            .expect("its own file");
        assert_eq!(narrowed, record);
        assert!(record.runs_install_scripts(Some("lodash-4.17.21.tgz")));
    }

    /// A filename the record does not hold falls back to the version-level answer, which
    /// is what the proxy logs and warns about.
    #[test]
    fn an_unknown_filename_falls_back_to_the_versions_own_answer() {
        let record = abbreviated("lodash", "4.17.21", true);
        assert!(record.runs_install_scripts(Some("lodash-4.17.20.tgz")));
        assert!(record.runs_install_scripts(None));
        assert!(!abbreviated("lodash", "4.17.21", false).runs_install_scripts(None));
    }

    #[test]
    fn provenance_defaults_to_claiming_nothing() {
        let p = Provenance::default();
        assert!(p.attestation_url.is_none());
        assert!(p.predicate_type.is_none());
        assert!(p.trusted_publisher.is_none());
        assert!(p.registry_signatures.is_empty());
    }

    #[test]
    fn record_identity_round_trips_through_purl() {
        let record = abbreviated("@babel/traverse", "7.23.1", false);
        assert_eq!(
            record.package.to_string(),
            "pkg:npm/%40babel/traverse@7.23.1"
        );
        assert_eq!(record.package.key().registry_name(), "@babel/traverse");
    }
}
