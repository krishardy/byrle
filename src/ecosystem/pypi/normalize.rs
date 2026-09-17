//! Turning a project index into records the policy engine reads.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::record::{PackageMetadata, SkippedVersion};

use super::error::PypiError;
use super::wire::{File, Kind, Project};

/// One index entry as the common record spells it.
fn artifact(file: &File) -> crate::record::Artifact {
    crate::record::Artifact {
        filename: file.filename.clone(),
        // An sdist runs the package's own build on install; a wheel unpacks and runs
        // nothing.
        runs_install_scripts: file.kind == Kind::Sdist,
        url: file.url.clone(),
        integrity: file.sha256.as_deref().and_then(sri),
        // PyPI's index gives sha256 and nothing weaker.
        legacy_sha1: None,
        file_count: None,
        unpacked_size: None,
    }
}

/// `hashes.sha256` as an SRI string, the shape [`crate::integrity`] verifies.
///
/// PyPI writes a hex digest and npm writes SRI, so one of the two has to convert and the
/// verifier is npm's shape. `None` when the digest is not 64 hex characters, which is not
/// a sha256 whatever it is.
fn sri(hex: &str) -> Option<String> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("checked above"))
        .collect();
    Some(format!("sha256-{}", BASE64.encode(&bytes)))
}

/// One [`PackageRecord`] per version, as the policy engine sees it.
///
/// A record is about a **version**, which is the question the index filter answers: may
/// this version be installed. Several files carry one version and the record names the one
/// a resolver would take, so `artifact` is the wheel where there is one.
///
/// The bytes that actually arrive are checked against the file that was requested, not
/// against this one. [`Project::files`] keeps every file for that, because a pinned fetch
/// names a filename and the proxy must verify what it serves rather than what it would
/// have preferred.
///
/// A yanked file is kept. PEP 592 says a resolver ignores a yanked version unless it is
/// pinned, which makes yanking an upstream signal rather than a decision this proxy makes,
/// and dropping it here would answer "no such version" for a version that exists.
pub fn normalize(project: &Project) -> Result<PackageMetadata, PypiError> {
    use crate::identity::{Ecosystem, PackageKey};
    use crate::record::{Artifact, PackageRecord, PackumentDetail, Provenance};

    let key = PackageKey::from_registry_name(Ecosystem::PyPI, &project.name)
        .map_err(|_| PypiError::UnusableName(project.name.clone()))?;
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for version in project.versions() {
        let package = match key.at_version(version) {
            Ok(package) => package,
            Err(e) => {
                skipped.push(SkippedVersion {
                    version: version.to_owned(),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let Some(file) = project.preferred(version) else {
            continue;
        };
        // Wheels before sdists, so the first is the file a resolver would take. Each
        // keeps its own digest and its own install-scripts answer, because a request
        // names a file and this record is about a version.
        let mut files = project.files_for(version);
        files.sort_by_key(|f| (f.kind, f.filename.as_str()));
        let artifacts: Vec<Artifact> = files.iter().map(|f| artifact(f)).collect();
        out.push(PackageRecord {
            package,
            // The simple index is the only document under `/simple/`, and it carries
            // everything the index has, publish time included. Nothing is withheld the way
            // npm withholds `time` from the abbreviated packument, so a `None` below means
            // the index does not publish it rather than that it was not fetched.
            source: PackumentDetail::Full,
            published_at: file
                .upload_time
                .as_deref()
                .and_then(|t| t.parse::<jiff::Timestamp>().ok()),
            // The simple index carries neither. PyPI publishes them on its legacy JSON API,
            // which a resolver does not fetch and this proxy therefore does not see.
            maintainers: None,
            repository: None,
            // An sdist runs the package's own build on install and a wheel does not, so a
            // version offering a wheel is not an install-script version. This is the PyPI
            // shape of the same question, read from what is on offer rather than from a
            // flag the index does not have.
            has_install_scripts: project.only_sdist(version).unwrap_or(false),
            install_scripts: None,
            provenance: Provenance::default(),
            artifacts,
        });
    }
    if out.is_empty() {
        return Err(PypiError::NothingReadable {
            name: project.name.clone(),
            files: project.files.len(),
        });
    }
    Ok(PackageMetadata {
        key,
        // The simple index has no `dist-tags`. A resolver picks from `versions` itself,
        // and PEP 503 gives it nothing to pick by name.
        latest: None,
        records: out,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::fixture;
    use super::super::wire::parse;

    #[test]
    fn a_version_becomes_a_record_naming_the_file_a_resolver_would_take() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        let records = normalize(&project).expect("records").records;
        assert_eq!(records.len(), 3, "one per version, not one per file");

        let wheel = records
            .iter()
            .find(|r| r.package.version() == "2.34.2")
            .expect("2.34.2");
        assert_eq!(wheel.package.to_string(), "pkg:pypi/requests@2.34.2");
        assert!(
            wheel
                .artifact()
                .expect("one file")
                .url
                .ends_with("-py3-none-any.whl")
        );
        assert!(
            !wheel.has_install_scripts,
            "a wheel installs without running the package's code"
        );

        let sdist = records
            .iter()
            .find(|r| r.package.version() == "0.2.0")
            .expect("0.2.0");
        assert!(sdist.artifact().expect("one file").url.ends_with(".tar.gz"));
        assert!(
            sdist.has_install_scripts,
            "only an sdist is on offer, so installing runs setup.py"
        );
    }

    /// One version, a wheel and an sdist. The version-level answer is about the file a
    /// resolver would take; each artifact carries its own, because the client can ask for
    /// either and only one of them runs `setup.py`.
    #[test]
    fn a_version_offering_both_keeps_each_files_own_install_answer() {
        let document = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://files/x-1.0.tar.gz","hashes":{}},
            {"filename":"x-1.0-py3-none-any.whl","url":"https://files/x-1.0-py3-none-any.whl","hashes":{}}
        ]}"#;
        let project = parse("x", document).expect("the document reads");
        let records = normalize(&project).expect("records").records;
        assert_eq!(records.len(), 1, "one version");
        let record = &records[0];

        assert_eq!(
            record
                .artifacts
                .iter()
                .map(|a| a.filename.as_str())
                .collect::<Vec<_>>(),
            ["x-1.0-py3-none-any.whl", "x-1.0.tar.gz"],
            "wheels first, so the first is the file a resolver would take"
        );
        assert!(
            !record.has_install_scripts,
            "a resolver that can take the wheel will"
        );
        assert!(!record.runs_install_scripts(Some("x-1.0-py3-none-any.whl")));
        assert!(
            record.runs_install_scripts(Some("x-1.0.tar.gz")),
            "asking for the sdist is asking for the bytes that run setup.py"
        );
    }

    /// A pinned fetch names a file. The record it is decided from has to be about that
    /// file, or a version cleared because it offers a wheel serves its sdist unexamined.
    #[test]
    fn narrowing_to_the_sdist_changes_the_install_answer_the_policy_sees() {
        let document = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://files/x-1.0.tar.gz","hashes":{"sha256":"aa"}},
            {"filename":"x-1.0-py3-none-any.whl","url":"https://files/x-1.0-py3-none-any.whl","hashes":{}}
        ]}"#;
        let project = parse("x", document).expect("the document reads");
        let record = &normalize(&project).expect("records").records[0];

        let sdist = record.narrowed_to("x-1.0.tar.gz").expect("the sdist");
        assert!(sdist.has_install_scripts);
        assert_eq!(sdist.artifacts.len(), 1);
        assert_eq!(
            sdist.artifact().expect("one file").url,
            "https://files/x-1.0.tar.gz"
        );

        let wheel = record
            .narrowed_to("x-1.0-py3-none-any.whl")
            .expect("the wheel");
        assert!(!wheel.has_install_scripts);

        assert!(record.narrowed_to("x-1.0-py2-none-any.whl").is_none());
    }

    /// The simple index has no `dist-tags`, so nothing names a default version. A
    /// resolver picks from the versions itself.
    #[test]
    fn a_normalised_index_names_no_latest_version() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        let metadata = normalize(&project).expect("records");
        assert_eq!(metadata.key.to_string(), "pkg:pypi/requests");
        assert_eq!(metadata.latest, None);
        assert_eq!(metadata.records.len(), 3);
        assert!(metadata.skipped.is_empty());
        assert_eq!(
            metadata.version("2.34.2").map(|r| r.package.to_string()),
            Some("pkg:pypi/requests@2.34.2".to_owned())
        );
        assert_eq!(metadata.version("9.9.9"), None);
    }

    /// A version string the identity rules refuse is recorded rather than dropped in
    /// silence, the same as npm's skipped versions.
    #[test]
    fn a_version_that_is_not_an_identity_is_skipped_and_named() {
        // A filename whose version field is blank after the name gives an empty version.
        let document = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://e/a","hashes":{}},
            {"filename":"x- -py3-none-any.whl","url":"https://e/b","hashes":{}}
        ]}"#;
        let project = parse("x", document).expect("the document reads");
        let metadata = normalize(&project).expect("one version is readable");
        assert_eq!(
            metadata
                .records
                .iter()
                .map(|r| r.package.version())
                .collect::<Vec<_>>(),
            ["1.0"]
        );
        assert_eq!(
            metadata
                .skipped
                .iter()
                .map(|s| s.version.as_str())
                .collect::<Vec<_>>(),
            [" "]
        );
        assert!(!metadata.skipped[0].reason.is_empty());
    }

    /// npm withholds `time` from the abbreviated packument, so a record built from one is
    /// `Abbreviated` and its `None` means unfetched. The simple index withholds nothing it
    /// has, so a PyPI record is `Full` and `cooldown_days` is answerable from it.
    #[test]
    fn a_record_carries_the_publish_time_and_is_not_incomplete() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        let records = normalize(&project).expect("records").records;
        let oldest = &records[0];
        assert_eq!(oldest.package.version(), "0.2.0");
        assert!(!oldest.may_be_incomplete());
        assert_eq!(
            oldest
                .published_at
                .expect("the index gives one")
                .to_string(),
            "2011-02-14T08:49:42.64166Z"
        );
        assert!(records.iter().all(|r| r.published_at.is_some()));
    }

    /// The index writes a hex digest and the verifier reads SRI, so one converts. The
    /// digest below is `requests-0.2.0.tar.gz` as PyPI publishes it.
    #[test]
    fn a_hex_sha256_becomes_the_sri_string_the_verifier_reads() {
        let hex = "813202ace4d9301a3c00740c700e012fb9f3f8c73ddcfe02ab558a8df6f175fd";
        let converted = sri(hex).expect("64 hex characters");
        assert_eq!(
            converted,
            "sha256-gTICrOTZMBo8AHQMcA4BL7nz+Mc93P4Cq1WKjfbxdf0="
        );
        // It round-trips through the verifier npm's digests use.
        let parsed = crate::integrity::Sri::parse(&converted).expect("valid SRI");
        assert_eq!(parsed.algorithm(), crate::integrity::Algorithm::Sha256);

        assert!(sri("not hex at all").is_none());
        assert!(sri(&hex[..63]).is_none(), "too short");
        assert!(sri(&format!("{hex}0")).is_none(), "too long");
        assert!(sri(&"g".repeat(64)).is_none(), "not hex digits");
    }

    /// PEP 592: a resolver ignores a yanked version unless it is pinned, so yanking is an
    /// upstream signal rather than a decision this proxy makes. Dropping the record would
    /// answer "no such version" for a version that exists.
    #[test]
    fn a_yanked_version_still_becomes_a_record() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        let records = normalize(&project).expect("records").records;
        assert!(
            records.iter().any(|r| r.package.version() == "2.32.0"),
            "the yanked version is still a version"
        );
        assert!(project.files_for("2.32.0")[0].yanked);
    }

    #[test]
    fn a_project_with_no_readable_version_produces_no_records() {
        let project = Project {
            name: "x".to_owned(),
            files: Vec::new(),
        };
        let error = normalize(&project).expect_err("nothing to record");
        assert!(
            matches!(error, PypiError::NothingReadable { .. }),
            "{error}"
        );
    }
}
