//! A simple index as PyPI serves it, and the cleaned form the normaliser reads. The
//! intermediate [`Project`] exists because an index is file-keyed and
//! [`crate::record::PackageMetadata`] is version-keyed.
//! See docs/engineering_decisions/pypi-simple-index.md.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::error::PypiError;
use super::paths::{filename_parts, normalise};

/// What installing the file runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A built distribution. Installing unpacks it and runs nothing from the package.
    Wheel,
    /// A source distribution. Installing runs the package's own build, `setup.py` included.
    Sdist,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wheel => "wheel",
            Self::Sdist => "sdist",
        }
    }
}

/// One file the index lists, as this build reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub filename: String,
    /// Read from the filename: the index does not attach a version to a file.
    pub version: String,
    pub kind: Kind,
    pub url: String,
    /// Hex SHA-256, when the index gives one. PyPI always does; another index may not.
    pub sha256: Option<String>,
    /// RFC 3339, as the index wrote it. `cooldown_days` reads this.
    pub upload_time: Option<String>,
    /// The reason the publisher gave, empty for a bare `true`. `None` is not yanked.
    pub yanked: Option<String>,
    pub requires_python: Option<String>,
    /// PEP 740: where this file's attestation bundle is, when the index published one.
    pub provenance: Option<String>,
}

/// One project's index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    /// The normalised name, as [`normalise`] gives it.
    pub name: String,
    pub files: Vec<File>,
}

impl Project {
    /// Every version the files name, sorted and once each.
    pub fn versions(&self) -> Vec<&str> {
        let mut seen: Vec<&str> = self.files.iter().map(|f| f.version.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }

    /// The files carrying `version`.
    pub fn files_for(&self, version: &str) -> Vec<&File> {
        self.files.iter().filter(|f| f.version == version).collect()
    }

    /// Whether installing `version` runs the package's own code.
    /// `version` is as the filenames write it.
    /// Returns true when every file for it is an sdist, `None` when it has none.
    pub fn only_sdist(&self, version: &str) -> Option<bool> {
        let files = self.files_for(version);
        if files.is_empty() {
            return None;
        }
        Some(files.iter().all(|f| f.kind == Kind::Sdist))
    }
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    files: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    filename: String,
    url: String,
    #[serde(default)]
    hashes: BTreeMap<String, String>,
    #[serde(default, rename = "upload-time")]
    upload_time: Option<String>,
    /// PEP 592: `true`, or a string giving the reason. `false` or absent is not yanked.
    #[serde(default)]
    yanked: serde_json::Value,
    #[serde(default, rename = "requires-python")]
    requires_python: Option<String>,
    /// PEP 740. `null` on a file published without attestations.
    #[serde(default)]
    provenance: Option<String>,
}

/// One project's index, read. A file whose name gives no version is skipped.
/// `name` is used when the document does not name the project. `bytes` is the PEP 691 JSON.
/// Returns the project, or why the document does not read.
pub fn parse(name: &str, bytes: &[u8]) -> Result<Project, PypiError> {
    let document: Document = serde_json::from_slice(bytes).map_err(PypiError::NotJson)?;
    let listed = document.files.len();
    let files: Vec<File> = document
        .files
        .into_iter()
        .filter_map(|entry| {
            let (_, version, kind) = filename_parts(&entry.filename)?;
            Some(File {
                filename: entry.filename,
                version,
                kind,
                url: entry.url,
                sha256: entry.hashes.get("sha256").cloned(),
                upload_time: entry.upload_time,
                yanked: match entry.yanked {
                    serde_json::Value::String(reason) => Some(reason),
                    serde_json::Value::Bool(true) => Some(String::new()),
                    _ => None,
                },
                requires_python: entry.requires_python,
                provenance: entry.provenance,
            })
        })
        .collect();
    let name = document
        .name
        .map_or_else(|| normalise(name), |n| normalise(&n));
    if files.is_empty() {
        return Err(PypiError::NothingReadable {
            name,
            files: listed,
        });
    }
    Ok(Project { name, files })
}

/// The file a resolver would take for a version: a wheel when there is one.
impl Project {
    pub(super) fn preferred(&self, version: &str) -> Option<&File> {
        let files = self.files_for(version);
        files
            .iter()
            .find(|f| f.kind == Kind::Wheel)
            .or_else(|| files.first())
            .copied()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    use super::super::{MAX_INDEX_BYTES, fixture};

    /// A version offering both is dated by its wheel, so the two upload times differ here.
    /// Taking the sdist's would date the version from the file a resolver will not fetch.
    #[test]
    fn a_version_offering_both_kinds_prefers_its_wheel() {
        let document = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://files/x-1.0.tar.gz","hashes":{},
             "upload-time":"2020-01-01T00:00:00Z"},
            {"filename":"x-1.0-py3-none-any.whl","url":"https://files/x-1.0-py3-none-any.whl",
             "hashes":{},"upload-time":"2021-06-02T03:04:05Z"}
        ]}"#;
        let project = parse("x", document).expect("the document reads");

        let file = project.preferred("1.0").expect("one of the two");
        assert_eq!(file.filename, "x-1.0-py3-none-any.whl");
        assert_eq!(file.upload_time.as_deref(), Some("2021-06-02T03:04:05Z"));
    }

    /// With only an sdist there is nothing to prefer, and the version still has a file.
    #[test]
    fn a_version_offering_only_an_sdist_prefers_it() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert_eq!(
            project.preferred("0.2.0").map(|f| f.filename.as_str()),
            Some("requests-0.2.0.tar.gz")
        );
        assert_eq!(project.preferred("9.9.9").map(|f| &f.filename), None);
    }

    /// npm sends `time` only in the full packument, so `published` is `None` for every
    /// record the proxy holds. PyPI writes it per file in the document a resolver fetches.
    #[test]
    fn the_index_carries_an_upload_time_for_every_file() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert!(
            project.files.iter().all(|f| f.upload_time.is_some()),
            "a cooldown is answerable from the index alone"
        );
        assert_eq!(
            project.files_for("0.2.0")[0].upload_time.as_deref(),
            Some("2011-02-14T08:49:42.641660Z")
        );
    }

    /// `yanked` is a yank when it is a string or `true`, and not otherwise, including
    /// when the key is absent.
    #[test]
    fn a_file_is_yanked_by_a_reason_or_by_true_and_by_nothing_else() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert!(
            project.files_for("2.32.0")[0].yanked.is_some(),
            "a reason string is a yank"
        );
        assert!(
            !project.files_for("2.34.2")[0].yanked.is_some(),
            "`false` is not"
        );

        let index = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://example/x-1.0.tar.gz"},
            {"filename":"x-2.0.tar.gz","url":"https://example/x-2.0.tar.gz","yanked":true}
        ]}"#;
        let project = parse("x", index).expect("the index reads");
        assert!(
            !project.files_for("1.0")[0].yanked.is_some(),
            "an absent key is not"
        );
        assert!(project.files_for("2.0")[0].yanked.is_some(), "`true` is");
    }

    /// The PyPI shape of the `install_scripts` question: a wheel installs without running
    /// the package's own code and an sdist does not.
    #[test]
    fn a_version_offering_only_an_sdist_leaves_a_resolver_no_choice() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert_eq!(project.only_sdist("0.2.0"), Some(true));
        assert_eq!(project.only_sdist("2.34.2"), Some(false));
        assert_eq!(project.only_sdist("9.9.9"), None, "no file for it");
    }

    #[test]
    fn a_filename_that_names_no_version_is_skipped_rather_than_refusing_the_index() {
        let document = br#"{"name": "x", "files": [
            {"filename": "x-1.0.0.tar.gz", "url": "https://h/x-1.0.0.tar.gz", "hashes": {}},
            {"filename": "x-1.0.win32.exe", "url": "https://h/x.exe", "hashes": {}},
            {"filename": "x-1.0-py2.7.egg", "url": "https://h/x.egg", "hashes": {}}
        ]}"#;
        let project = parse("x", document).expect("the sdist is readable");
        assert_eq!(
            project.files.len(),
            1,
            "the egg and the installer are skipped"
        );
        assert_eq!(project.versions(), ["1.0.0"]);
    }

    #[test]
    fn a_wheel_with_a_build_tag_still_gives_its_version() {
        assert_eq!(
            filename_parts("x-1.2.3-1-py3-none-any.whl"),
            Some(("x".to_owned(), "1.2.3".to_owned(), Kind::Wheel))
        );
        assert_eq!(
            filename_parts("zope-interface-5.4.0.tar.gz"),
            Some(("zope-interface".to_owned(), "5.4.0".to_owned(), Kind::Sdist))
        );
        assert_eq!(filename_parts("not-a-distribution.txt"), None);
        assert_eq!(filename_parts("x-py3-none-any.whl"), None, "too few fields");
    }

    /// A filename that gives a version but no project name is skipped, as one with no
    /// version is.
    #[test]
    fn a_file_whose_name_is_only_a_version_is_skipped() {
        assert_eq!(filename_parts("-1.0.tar.gz"), None, "sdist, empty name");
        assert_eq!(
            filename_parts("-1.0-py3-none-any.whl"),
            None,
            "wheel, empty name"
        );
        let document = br#"{"name":"x","files":[
            {"filename":"-1.0.tar.gz","url":"https://e/a","hashes":{}},
            {"filename":"-1.0-py3-none-any.whl","url":"https://e/b","hashes":{}},
            {"filename":"x-1.0.tar.gz","url":"https://e/c","hashes":{}}
        ]}"#;
        let project = parse("x", document).expect("the document reads");
        assert_eq!(
            project
                .files
                .iter()
                .map(|f| f.filename.as_str())
                .collect::<Vec<_>>(),
            ["x-1.0.tar.gz"]
        );
    }

    #[test]
    fn a_document_that_is_not_an_index_or_lists_nothing_readable_is_refused() {
        let error = parse("x", b"not json").expect_err("not a document");
        assert!(matches!(error, PypiError::NotJson(_)), "{error}");
        let error = parse("x", br#"{"name": "x", "files": []}"#).expect_err("no files");
        assert!(
            matches!(error, PypiError::NothingReadable { files: 0, .. }),
            "{error}"
        );
        assert!(!error.to_string().is_empty());
    }
    #[test]
    fn the_ceiling_matches_the_packument_ceiling() {
        assert_eq!(MAX_INDEX_BYTES, crate::env::DEFAULT_MAX_METADATA_BYTES);
        assert_eq!(MAX_INDEX_BYTES, 67_108_864);
        assert_eq!(Kind::Wheel.as_str(), "wheel");
        assert_eq!(Kind::Sdist.as_str(), "sdist");
    }

    /// A JSON index with no `name` is named by the request.
    #[test]
    fn an_index_with_no_name_is_named_by_the_request() {
        let body = br#"{"meta": {"api-version": "1.1"}, "files": [
            {"filename": "Requests-1.0.tar.gz", "url": "https://f/r-1.0.tar.gz", "hashes": {"sha256": "aa"}}]}"#;
        assert_eq!(parse("Requests", body).expect("reads").name, "requests");
    }
}
