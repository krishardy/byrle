//! The common package record: registry metadata normalised into one shape, the contract
//! between the per-ecosystem normalisers and everything above them (plan §4).
//!
//! See docs/engineering_decisions/npm-packument-shapes.md for what each document carries.

use crate::identity::{PackageKey, PackageRef};
use std::collections::BTreeMap;

/// Which document a record was built from, so `None` can mean "not fetched" or "not published".
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
    /// The version as the document spelled it: npm's `versions` key, or PyPI's filename.
    pub version: String,
    pub reason: String,
}

/// Every version of one package, normalised, as the record store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMetadata {
    /// Identity taken from the document's own name, never from the request path.
    pub key: PackageKey,
    /// npm's `dist-tags.latest`, unresolved, since it can name a version the document omits.
    pub latest: Option<String>,
    /// One record per usable version, in the order the document listed them.
    pub records: Vec<PackageRecord>,
    /// Versions present in the document that produced no record.
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

    /// When this version was published, from the full packument's `time` map.
    pub published_at: Option<jiff::Timestamp>,

    /// Full packument only.
    pub maintainers: Option<Vec<Maintainer>>,

    /// Full packument only.
    pub repository: Option<Repository>,

    /// The reason the registry gave for withdrawing every file this version offers.
    pub yanked: Option<String>,

    /// npm's `deprecated` message for this version, where the publisher left one.
    pub deprecated: Option<String>,

    /// Whether installing this version runs a lifecycle script, which both documents answer.
    pub has_install_scripts: bool,

    /// The lifecycle script bodies. Full packument only.
    pub install_scripts: Option<BTreeMap<String, String>>,

    /// Attestations and signatures. Present in both documents.
    pub provenance: Provenance,

    /// Dependencies named by a git repository, a URL or a path, which bypass the proxy.
    pub direct_dependencies: Vec<DirectDependency>,

    /// The files this version offers, the one a resolver would take first: wheels first.
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

/// A source repository, with its URL verbatim as the registry reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub url: String,
    /// `git`, `svn`, and so on. Absent in the shorthand form.
    pub kind: Option<String>,
    /// npm's `directory`: the subdirectory holding a monorepo package.
    pub directory: Option<String>,
}

/// A dependency a client fetches from where its specifier points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectDependency {
    pub name: String,
    /// As the manifest wrote it: `github:o/r#v1`, `https://host/x.tgz`, `file:../x`.
    pub spec: String,
}

/// Evidence about who produced this artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    /// `dist.attestations.url`, where the attestation bundle the version claims is.
    pub attestation_url: Option<String>,
    /// `dist.attestations.provenance.predicateType`, e.g. the SLSA provenance URI.
    pub predicate_type: Option<String>,
    /// `dist.signatures`: the registry's own signature, not the maintainer's.
    pub registry_signatures: Vec<RegistrySignature>,
    /// `_npmUser.trustedPublisher`, an OIDC publisher such as GitHub Actions. Full only.
    pub trusted_publisher: Option<TrustedPublisher>,
    /// `_npmUser.name`, the account that published this version. Full only.
    pub publisher: Option<String>,
    /// npm's `gitHead`, the commit this version was published from. Full only.
    pub git_head: Option<String>,
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
    /// The filename as the registry serves it, which is what a request names.
    pub filename: String,

    /// Whether installing this file, not the version, runs the package's own code.
    pub runs_install_scripts: bool,

    /// Absolute URL as the registry gave it.
    pub url: String,

    /// `dist.integrity`, a Subresource Integrity string: a cache key, not a trust anchor.
    pub integrity: Option<String>,

    /// PyPI's PEP 592 yank reason for this file, empty when none was given. `None` is not yanked.
    pub yanked: Option<String>,

    /// `dist.shasum`, a SHA-1 digest, kept apart from `integrity` because SHA-1 is broken.
    pub legacy_sha1: Option<String>,

    /// Where the registry serves this file's attestations, when it claims any.
    pub attestation_url: Option<String>,

    pub file_count: Option<u64>,
    pub unpacked_size: Option<u64>,
}

impl PackageRecord {
    /// The file a resolver would take, which is the first.
    /// Returns `None` when the registry named no file for this version.
    pub fn artifact(&self) -> Option<&Artifact> {
        self.artifacts.first()
    }

    /// The file a request named.
    pub fn artifact_named(&self, filename: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.filename == filename)
    }

    /// Whether installing the file a request named runs the package's own code.
    /// `filename` that names no file here falls back to the version's answer.
    pub fn runs_install_scripts(&self, filename: Option<&str>) -> bool {
        match filename.and_then(|f| self.artifact_named(f)) {
            Some(artifact) => artifact.runs_install_scripts,
            None => self.has_install_scripts,
        }
    }

    /// This record as it applies to one file, with that file's install-script answer and
    /// attestation. Returns `None` when the record names no `filename`.
    pub fn narrowed_to(&self, filename: &str) -> Option<Self> {
        let artifact = self.artifact_named(filename)?.clone();
        Some(Self {
            has_install_scripts: artifact.runs_install_scripts,
            yanked: artifact.yanked.clone(),
            provenance: Provenance {
                attestation_url: artifact.attestation_url.clone(),
                ..self.provenance.clone()
            },
            artifacts: vec![artifact],
            ..self.clone()
        })
    }

    /// Whether a field being `None` could mean not fetched, rather than not published.
    pub fn may_be_incomplete(&self) -> bool {
        self.detail == DocumentDetail::Abbreviated
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            direct_dependencies: Vec::new(),
            artifacts: vec![Artifact {
                filename: format!("{name}-{version}.tgz"),
                runs_install_scripts: has_scripts,
                yanked: None,
                url: format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                integrity: Some("sha512-AAAA".into()),
                legacy_sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".into()),
                attestation_url: None,
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

    /// Narrowed to one file, the record claims that file's attestation, whatever the
    /// preferred file claimed, and keeps the rest of the version's provenance.
    #[test]
    fn narrowing_takes_the_files_own_attestation() {
        let mut record = abbreviated("x", "1.0.0", false);
        record.provenance.predicate_type = Some("https://slsa.dev/provenance/v1".into());
        record.provenance.attestation_url = Some("https://example/wheel".into());
        let mut sdist = record.artifacts[0].clone();
        sdist.filename = "x-1.0.0.tar.gz".into();
        sdist.attestation_url = None;
        let mut wheel = record.artifacts[0].clone();
        wheel.filename = "x-1.0.0-py3-none-any.whl".into();
        wheel.attestation_url = Some("https://example/wheel".into());
        record.artifacts = vec![wheel, sdist];

        let narrowed = record.narrowed_to("x-1.0.0.tar.gz").expect("names a file");
        assert_eq!(narrowed.provenance.attestation_url, None);
        assert_eq!(
            narrowed.provenance.predicate_type.as_deref(),
            Some("https://slsa.dev/provenance/v1")
        );
        let narrowed = record
            .narrowed_to("x-1.0.0-py3-none-any.whl")
            .expect("names a file");
        assert_eq!(
            narrowed.provenance.attestation_url.as_deref(),
            Some("https://example/wheel")
        );
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
