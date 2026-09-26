//! A simple index as PyPI serves it, and the cleaned form the normaliser reads.
//!
//! Two shapes rather than npm's one. `Document` and `Entry` are the PEP 691
//! deserialisation targets; [`Project`] is what [`parse`] turns them into. The
//! intermediate exists because a simple index is **file**-keyed and
//! [`crate::record::PackageMetadata`] is version-keyed: `requests` lists 244 files for 160
//! versions, and deciding which file stands for a version is a question npm never asks.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::error::PypiError;
use super::paths::{filename_parts, normalise};

/// What installing the file runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A built distribution. Installing unpacks it and runs nothing from the package.
    Wheel,
    /// A source distribution. Installing runs the package's own build, `setup.py`
    /// included, which is the PyPI shape of the `install_scripts` question.
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
    /// RFC 3339, as the index wrote it. `cooldown_days` reads this, and unlike npm it is
    /// in the document a resolver already fetches.
    pub upload_time: Option<String>,
    /// The reason the publisher gave, empty when the index said only `true`. `None` is not
    /// yanked.
    pub yanked: Option<String>,
    pub requires_python: Option<String>,
    /// PEP 740: where this file's attestation bundle is, when the index published one.
    ///
    /// The index carries the URL and not the bundle, so presence is a claim of provenance
    /// and nothing here is verified: fetching and checking it is Stage 4.
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
    ///
    /// Read from the files rather than the index's own `versions` key, which is PEP 700 and
    /// optional: an index that omits it still answers this.
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
    ///
    /// True when every file for that version is an sdist. A resolver that can take a wheel
    /// will, so a version offering one is not an install-script version; a version offering
    /// only an sdist leaves no choice. `None` when the index lists no file for it.
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
    /// PEP 592: `true`, or a string giving the reason. `false` or absent is not yanked,
    /// and absent is the common case: of 244 `requests` files on 2026-09-20, 4 are yanked
    /// and every one carries a reason string.
    #[serde(default)]
    yanked: serde_json::Value,
    #[serde(default, rename = "requires-python")]
    requires_python: Option<String>,
    /// PEP 740. `null` on a file published without attestations, which is most of them:
    /// counted 2026-09-21, `attrs` publishes 12 of 72 with one and `ruff` none of 7,134.
    #[serde(default)]
    provenance: Option<String>,
}

/// One project's index, read.
///
/// A file whose name gives no version is skipped rather than refusing the document: PyPI
/// lists eggs and `.exe` installers for old projects, and one of those should not hide
/// every wheel beside it.
///
/// Measured over nine projects on 2026-09-16, 12,164 files: 510 skipped, every one of them
/// `.egg` (265), `.exe` (237) or `.src.rpm` (8). pip installs neither eggs nor installers,
/// so nothing a resolver would fetch is among them. `examples/pypi_index.rs` is the run.
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
                    // PEP 592 allows a bare `true`, which is a yank with no reason given.
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

/// The file a resolver would take for a version.
///
/// A wheel wins because a resolver that can take one will. `normalize` reads this for the
/// version's publish time, so a version offering both kinds is dated by its wheel; the
/// install-scripts answer comes from [`Project::only_sdist`] rather than from here.
/// `None` when the index lists no file for that version.
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

    /// PEP 592 writes `false` or a string giving the reason, so `yanked` is a string, or
    /// `true`, and anything else is not a yank. An index that omits the key is the common
    /// case: reading an absent key as a yank refused every file of every project.
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
        // PEP 427 allows a build tag between the version and the python tag.
        assert_eq!(
            filename_parts("x-1.2.3-1-py3-none-any.whl"),
            Some(("x".to_owned(), "1.2.3".to_owned(), Kind::Wheel))
        );
        // An sdist whose project name contains a hyphen: the version is after the last one.
        assert_eq!(
            filename_parts("zope-interface-5.4.0.tar.gz"),
            Some(("zope-interface".to_owned(), "5.4.0".to_owned(), Kind::Sdist))
        );
        assert_eq!(filename_parts("not-a-distribution.txt"), None);
        assert_eq!(filename_parts("x-py3-none-any.whl"), None, "too few fields");
    }

    /// A filename that gives a version but no project name is skipped the same as one that
    /// gives no version. `parse` discards the name, so without this the file would become a
    /// record under the project the index was asked about.
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
}
