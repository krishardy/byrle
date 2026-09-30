//! The published npm tarball against the source its metadata names: the commit in `gitHead`,
//! else a release tag, as GitHub's archive of it. Report only, measured by
//! `examples/source_diff.rs`.
//! See docs/engineering_decisions/source-diff.md.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{MAX_MEMBER_BYTES, NPM_INSTALL_SCRIPTS, ReadError, walk};
use crate::identity::Ecosystem;
use crate::record::PackageRecord;

/// The comparer's version, stored with each result; bumped whenever a result would change.
pub const COMPARER: &str = "source 1";

/// The member sizes one archive may state, together.
pub const MAX_SOURCE_BYTES: usize = 512 << 20;

/// GitHub's archive host, which [`crate::env::SOURCE_ARCHIVES`] replaces.
pub const ARCHIVES: &str = "https://codeload.github.com";

/// What comparing one artifact with its source came to, as the analysis store keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sourced {
    /// Compared with `repository`, `owner/name`, at `reference`.
    Compared {
        repository: String,
        reference: String,
        comparison: Box<Comparison>,
    },
    /// Not compared, and why, such as no repository on GitHub.
    NotCompared(String),
}

/// A repository on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub owner: String,
    pub name: String,
}

impl Repo {
    /// The GitHub repository an npm `repository.url` names, in any form npm accepts.
    /// Returns `None` for another host, or a URL naming no owner and repository.
    pub fn from_url(url: &str) -> Option<Self> {
        let url = url.trim();
        let url = url.strip_prefix("git+").unwrap_or(url);
        let url = url.split('#').next().unwrap_or(url);
        let path = if let Some(path) = url.strip_prefix("github:") {
            path
        } else if let Some((_, after)) = url.split_once("://") {
            let (authority, path) = after.split_once('/')?;
            github_host(authority)?;
            path
        } else if let Some((authority, path)) = url.split_once(':') {
            github_host(authority)?;
            path
        } else if url
            .split_once('/')
            .is_some_and(|(owner, name)| !owner.contains('.') && !name.contains('/'))
        {
            url
        } else {
            return None;
        };
        let mut parts = path.split('/').filter(|part| !part.is_empty());
        let owner = parts.next()?;
        let name = parts.next()?;
        let name = name.strip_suffix(".git").unwrap_or(name);
        (github_name(owner) && github_name(name)).then(|| Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    /// The archive at `base`, GitHub's host or a mirror of it, of this repository at
    /// `reference`, a commit or a tag.
    /// Returns `None` for a reference with a character a tag from metadata should not have.
    pub fn archive_url(&self, base: &str, reference: &str) -> Option<String> {
        let safe = !reference.is_empty()
            && !reference.starts_with('/')
            && !reference.contains("..")
            && !reference.contains("//")
            && reference
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-@/+".contains(c));
        safe.then(|| {
            format!(
                "{}/{}/{}/tar.gz/{reference}",
                base.trim_end_matches('/'),
                self.owner,
                self.name
            )
        })
    }
}

/// Whether `part` can be a GitHub owner or repository name.
fn github_name(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `Some` when `authority`, with any user and port, is GitHub's host.
fn github_host(authority: &str) -> Option<()> {
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    matches!(host, "github.com" | "www.github.com").then_some(())
}

/// The references to fetch `record`'s source at, in order: `gitHead` when it is a commit
/// hash, then the tags a release is usually given, with and without a scope.
pub fn references(record: &PackageRecord) -> Vec<String> {
    let version = record.package.version();
    let key = record.package.key();
    let name = key.registry_name();
    let unscoped = key.namespace().map(|_| format!("{}@{version}", key.name()));
    record
        .provenance
        .git_head
        .iter()
        .filter(|head| head.len() == 40 && head.chars().all(|c| c.is_ascii_hexdigit()))
        .cloned()
        .chain([
            format!("v{version}"),
            version.to_owned(),
            format!("{name}@{version}"),
        ])
        .chain(unscoped)
        .collect()
}

/// An archive's files by path below its first component, as SHA-256 of bytes without `\r`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tree {
    pub files: BTreeMap<String, [u8; 32]>,
    /// Each `package.json` that is JSON, by the directory holding it: `""` for the root.
    pub manifests: BTreeMap<String, serde_json::Value>,
    /// A PyPI artifact's core metadata: an sdist's `PKG-INFO`, a wheel's `METADATA`.
    pub metadata: Option<String>,
}

impl Tree {
    /// The root `package.json`.
    pub fn manifest(&self) -> Option<&serde_json::Value> {
        self.manifests.get("")
    }

    /// The package `name`, rooted at the first directory whose publishable `package.json`, one
    /// with a `version` and not `private`, names it: `directory`, the root, the shallowest.
    /// Returns `None` when no such `package.json` names it.
    pub fn package(&self, name: &str, directory: Option<&str>) -> Option<Tree> {
        let names = |dir: &&str| {
            self.manifests.get(*dir).is_some_and(|manifest| {
                manifest.get("name").and_then(|n| n.as_str()) == Some(name)
                    && manifest.get("version").is_some_and(|v| v.is_string())
                    && manifest.get("private") != Some(&serde_json::Value::Bool(true))
            })
        };
        let given = directory.map(|directory| directory.trim_matches('/'));
        let found = given.into_iter().chain([""]).find(names).or_else(|| {
            self.manifests
                .keys()
                .map(String::as_str)
                .filter(names)
                .min_by_key(|dir| dir.matches('/').count())
        })?;
        Some(self.at(found))
    }

    /// The part of this tree under `directory`, rooted there.
    fn at(&self, directory: &str) -> Tree {
        Tree {
            files: self
                .files
                .iter()
                .filter_map(|(path, digest)| Some((relative(path, directory)?.to_owned(), *digest)))
                .collect(),
            manifests: self
                .manifests
                .iter()
                .filter_map(|(dir, manifest)| {
                    Some((relative(dir, directory)?.to_owned(), manifest.clone()))
                })
                .collect(),
            metadata: None,
        }
    }
}

/// `path` relative to `directory`, `""` for the directory itself, or `None` outside it.
fn relative<'a>(path: &'a str, directory: &str) -> Option<&'a str> {
    if directory.is_empty() {
        return Some(path);
    }
    match path.strip_prefix(directory)? {
        "" => Some(""),
        rest => rest.strip_prefix('/'),
    }
}

/// Read a gzipped tar into a [`Tree`]. The first path component is dropped: `package/` in an
/// npm tarball, `{repo}-{commit}/` in GitHub's archive. `limit` bounds the member sizes the
/// headers state, together.
/// Errors when the bytes are not a gzipped tar, or state more than `limit`.
pub fn tree(archive: &mut dyn Read, limit: usize) -> Result<Tree, ReadError> {
    let mut tree = Tree::default();
    let mut stated = 0u64;
    walk(archive, &mut |path, member| {
        stated += member.size;
        if stated > limit as u64 {
            return Err(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit,
            });
        }
        let path = path.strip_prefix("./").unwrap_or(path);
        let Some((_, path)) = path.split_once('/') else {
            return Ok(false);
        };
        if !member.file || path.is_empty() {
            return Ok(false);
        }
        tree.add(path, member.bytes, path == "PKG-INFO")?;
        Ok(false)
    })?;
    Ok(tree)
}

/// Read a wheel, a zip whose paths are where they install, into a [`Tree`]. `limit` bounds
/// the sizes its entries state, together.
/// Errors when the bytes are not a zip, or state more than `limit`.
pub fn wheel_tree<R: Read + std::io::Seek>(archive: R, limit: usize) -> Result<Tree, ReadError> {
    let not_a_zip = |e: zip::result::ZipError| ReadError::NotAnArchive(e.to_string());
    let mut zip = zip::ZipArchive::new(archive).map_err(not_a_zip)?;
    let mut tree = Tree::default();
    let mut stated = 0u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(not_a_zip)?;
        stated += entry.size();
        if stated > limit as u64 {
            return Err(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit,
            });
        }
        if !entry.is_file() {
            continue;
        }
        let path = entry.name().to_owned();
        let metadata = path
            .split_once('/')
            .is_some_and(|(top, rest)| top.ends_with(".dist-info") && rest == "METADATA");
        tree.add(&path, &mut entry, metadata)?;
    }
    Ok(tree)
}

impl Tree {
    /// Add the file at `path`, hashed as its `bytes` stream, keeping a `package.json` parsed
    /// and, when `metadata`, its text as [`Tree::metadata`].
    /// Errors when the bytes cannot be read.
    fn add(&mut self, path: &str, bytes: &mut dyn Read, metadata: bool) -> Result<(), ReadError> {
        let manifest = match path.rsplit_once('/') {
            Some((directory, "package.json")) => Some(directory),
            None if path == "package.json" => Some(""),
            _ => None,
        };
        let mut hasher = Sha256::new();
        let mut kept = (manifest.is_some() || metadata).then(Vec::new);
        let mut chunk = [0u8; 8192];
        loop {
            let read = bytes
                .read(&mut chunk)
                .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
            if read == 0 {
                break;
            }
            for piece in chunk[..read].split(|&byte| byte == b'\r') {
                hasher.update(piece);
                if let Some(bytes) = kept.as_mut() {
                    bytes.extend_from_slice(piece);
                }
            }
            if kept
                .as_ref()
                .is_some_and(|bytes| bytes.len() > MAX_MEMBER_BYTES)
            {
                kept = None;
            }
        }
        if let Some(bytes) = kept {
            if let Some(directory) = manifest
                && let Ok(manifest) = serde_json::from_slice(&bytes)
            {
                self.manifests.insert(directory.to_owned(), manifest);
            }
            if metadata {
                self.metadata = Some(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        self.files.insert(path.to_owned(), hasher.finalize().into());
        Ok(())
    }
}

/// What the published package holds that its source does not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    /// Whether both trees have a `package.json` to compare. The next three are empty when not.
    pub manifests: bool,
    /// Install lifecycle scripts the published `package.json` adds or changes.
    pub lifecycle_scripts: Vec<String>,
    /// Dependencies the published `package.json` adds, by name.
    pub dependencies: Vec<String>,
    /// Optional dependencies it adds, by name: platform binaries, in the packages measured.
    pub optional_dependencies: Vec<String>,
    /// `(script, file)`: a file a lifecycle script names that the source lacks or differs on.
    pub lifecycle_files: Vec<(String, String)>,
    /// How many files the lifecycle scripts name, which `lifecycle_files` is out of.
    pub lifecycle_targets: usize,
    /// Paths in both whose bytes differ, `package.json` and Markdown aside.
    pub differing: Vec<String>,
    /// Markdown files in both whose bytes differ, which publishing often rewrites.
    pub differing_markdown: Vec<String>,
    /// Paths only the package has.
    pub only_in_package: Vec<String>,
    /// Paths in both with the same bytes.
    pub same: usize,
}

/// `package`, the published tarball's tree, against `source`, the source's.
pub fn compare(package: &Tree, source: &Tree) -> Comparison {
    let mut found = Comparison::default();
    let published = package.manifest();
    if let (Some(published), Some(built)) = (published, source.manifest()) {
        found.manifests = true;
        found.lifecycle_scripts = NPM_INSTALL_SCRIPTS
            .into_iter()
            .filter(|name| {
                let body = script(published, name);
                body.is_some() && body != script(built, name)
            })
            .map(str::to_owned)
            .collect();
        let added = |field| {
            let before = names(built, field);
            names(published, field)
                .into_iter()
                .filter(|name| !before.contains(name))
                .collect()
        };
        found.dependencies = added("dependencies");
        found.optional_dependencies = added("optionalDependencies");
    }
    for name in NPM_INSTALL_SCRIPTS {
        let Some(body) = published.and_then(|manifest| script(manifest, name)) else {
            continue;
        };
        for file in targets(body, package) {
            found.lifecycle_targets += 1;
            if source.files.get(&file) != package.files.get(&file) {
                found.lifecycle_files.push((name.to_owned(), file));
            }
        }
    }
    files(package, source, &mut found, &|path| path == "package.json");
    found
}

/// Sort each file of `package` that `skip` does not name into `found`: in `source` with the
/// same bytes, differing, differing Markdown, or only in the package.
fn files(package: &Tree, source: &Tree, found: &mut Comparison, skip: &dyn Fn(&str) -> bool) {
    for (path, digest) in package.files.iter().filter(|(path, _)| !skip(path)) {
        match source.files.get(path) {
            None => found.only_in_package.push(path.clone()),
            Some(built) if built == digest => found.same += 1,
            Some(_) if path.to_ascii_lowercase().ends_with(".md") => {
                found.differing_markdown.push(path.clone());
            }
            Some(_) => found.differing.push(path.clone()),
        }
    }
}

/// How an artifact's files are laid out, which says how it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A gzipped tar, first component `package/` for npm and `{name}-{version}/` for an sdist.
    Tar,
    /// A wheel: a zip whose paths are where they install.
    Wheel,
}

impl Layout {
    /// The layout of the artifact `filename` in `ecosystem`. `None` for one this does not
    /// read, such as a zip sdist.
    pub fn of(ecosystem: Ecosystem, filename: &str) -> Option<Self> {
        match ecosystem {
            Ecosystem::Npm => Some(Self::Tar),
            Ecosystem::PyPI if filename.ends_with(".whl") => Some(Self::Wheel),
            Ecosystem::PyPI if filename.ends_with(".tar.gz") => Some(Self::Tar),
            Ecosystem::PyPI => None,
        }
    }
}

/// The GitHub repository a PyPI core metadata file names: a `Project-URL` whose label says
/// source, repository or code, then any other `Project-URL`, then `Home-page`.
pub fn pypi_repository(metadata: &str) -> Option<Repo> {
    let headers = metadata.split("\n\n").next().unwrap_or(metadata);
    let (mut labelled, mut others, mut home) = (Vec::new(), Vec::new(), None);
    for line in headers.lines() {
        if let Some(value) = line.strip_prefix("Project-URL:") {
            let (label, url) = value.split_once(',').unwrap_or(("", value));
            let label = label.to_ascii_lowercase();
            if ["source", "repo", "code"].iter().any(|w| label.contains(w)) {
                labelled.push(url.trim());
            } else {
                others.push(url.trim());
            }
        } else if let Some(url) = line.strip_prefix("Home-page:") {
            home = Some(url.trim());
        }
    }
    labelled
        .into_iter()
        .chain(others)
        .chain(home)
        .find_map(Repo::from_url)
}

/// Whether `path` in a PyPI artifact is packaging metadata rather than the project's files:
/// `PKG-INFO`, and anything in a `.dist-info` or `.egg-info` directory.
fn pypi_metadata(path: &str) -> bool {
    path == "PKG-INFO"
        || path
            .split('/')
            .any(|part| part.ends_with(".dist-info") || part.ends_with(".egg-info"))
}

/// `package`, a PyPI artifact read with `layout`, against `source`, its repository's whole
/// tree. The code that runs on install is an sdist's `setup.py` and a wheel's `.pth` files.
/// Returns `None` when none of the package's Python files is in the source.
pub fn compare_pypi(package: &Tree, source: &Tree, layout: Layout) -> Option<Comparison> {
    let built = source.at(&located(package, source)?);
    let mut found = Comparison::default();
    let (runs, when): (fn(&str) -> bool, &str) = match layout {
        Layout::Tar => (|path| path == "setup.py", "build"),
        Layout::Wheel => (
            |path| !path.contains('/') && path.ends_with(".pth"),
            "startup",
        ),
    };
    for file in package.files.keys().filter(|path| runs(path)) {
        found.lifecycle_targets += 1;
        if built.files.get(file) != package.files.get(file) {
            found.lifecycle_files.push((when.to_owned(), file.clone()));
        }
    }
    files(package, &built, &mut found, &pypi_metadata);
    Some(found)
}

/// The directory of `source` the package's files are in: the one holding the most of its
/// Python files, found from the shallowest one the source has. `src/`, a monorepo's
/// subdirectory, or `""` for the root.
/// Returns `None` when none of them is in the source.
fn located(package: &Tree, source: &Tree) -> Option<String> {
    let mut python: Vec<&String> = package
        .files
        .keys()
        .filter(|path| path.ends_with(".py") && !pypi_metadata(path))
        .collect();
    python.sort_by_key(|path| (path.matches('/').count(), path.len()));
    let under = |prefix: &str, path: &str| match prefix {
        "" => path.to_owned(),
        prefix => format!("{prefix}/{path}"),
    };
    python.iter().find_map(|anchor| {
        source
            .files
            .keys()
            .filter_map(|path| match path.strip_suffix(anchor.as_str())? {
                "" => Some(""),
                prefix => prefix.strip_suffix('/'),
            })
            .map(|prefix| {
                let held = python
                    .iter()
                    .filter(|path| source.files.contains_key(&under(prefix, path)))
                    .count();
                (held, std::cmp::Reverse(prefix.matches('/').count()), prefix)
            })
            .max()
            .map(|(_, _, prefix)| prefix.to_owned())
    })
}

/// The body of the script `name` in `manifest`, when it has one.
fn script<'a>(manifest: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    manifest.get("scripts")?.get(name)?.as_str()
}

/// The keys of `manifest`'s map `field`, such as `dependencies`.
fn names(manifest: &serde_json::Value, field: &str) -> BTreeSet<String> {
    manifest
        .get(field)
        .and_then(|names| names.as_object())
        .map(|names| names.keys().cloned().collect())
        .unwrap_or_default()
}

/// The files of `package` that a script's `body` names, as a word or a word without `.js`.
fn targets(body: &str, package: &Tree) -> Vec<String> {
    body.split(|c: char| c.is_whitespace() || ";&|()".contains(c))
        .map(|word| word.trim_matches(['\'', '"']))
        .map(|word| word.strip_prefix("./").unwrap_or(word))
        .filter(|word| !word.is_empty())
        .flat_map(|word| [word.to_owned(), format!("{word}.js")])
        .filter(|file| package.files.contains_key(file))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};
    use crate::util::test_support::tarball;

    fn read(files: &[(&str, &[u8])]) -> Tree {
        tree(&mut &*tarball(files), 1 << 20).expect("a tarball")
    }

    /// Every form of `repository.url` the fixtures and npm's docs use, and hosts that are not
    /// GitHub.
    #[test]
    fn a_repository_url_names_its_github_repository() {
        for (url, expected) in [
            (
                "git+https://github.com/lodash/lodash.git",
                Some("lodash/lodash"),
            ),
            ("https://github.com/o/r", Some("o/r")),
            (
                "https://www.github.com/o/r/tree/main/packages/x",
                Some("o/r"),
            ),
            ("git://github.com/o/r.git", Some("o/r")),
            ("git+ssh://git@github.com/o/r.git", Some("o/r")),
            ("git@github.com:o/r.git", Some("o/r")),
            ("github:o/r", Some("o/r")),
            ("o/r", Some("o/r")),
            ("https://github.com/o/r.git#readme", Some("o/r")),
            ("https://gitlab.com/o/r", None),
            ("https://github.com.evil.test/o/r", None),
            ("https://evil.test/github.com/o/r", None),
            ("git@gitlab.com:o/r.git", None),
            ("gitlab.com/o/r", None),
            ("example.com/r", None),
            ("https://github.com/o", None),
            ("https://github.com/o/.git", None),
            ("https://github.com/o/r%20x", None),
            ("https://github.com/../r", None),
            ("https://github.com/o/..", None),
            ("https://github.com", None),
            ("https://github.com/", None),
            ("github", None),
        ] {
            let repo = Repo::from_url(url).map(|r| format!("{}/{}", r.owner, r.name));
            assert_eq!(repo.as_deref(), expected, "{url}");
        }
        let repo = Repo::from_url("o/r").unwrap();
        for (reference, expected) in [
            ("abc", Some("https://codeload.github.com/o/r/tar.gz/abc")),
            (
                "@s/p@1.0.0+b",
                Some("https://codeload.github.com/o/r/tar.gz/@s/p@1.0.0+b"),
            ),
            ("", None),
            ("/abc", None),
            ("a/../b", None),
            ("a//b", None),
            ("a?b", None),
            ("a b", None),
        ] {
            assert_eq!(
                repo.archive_url(&format!("{ARCHIVES}/"), reference)
                    .as_deref(),
                expected,
                "{reference:?}"
            );
        }
    }

    #[test]
    fn the_published_commit_is_tried_before_the_tags() {
        let mut record = crate::ecosystem::npm::normalized(
            "lodash-4.17.21.full.json",
            crate::record::DocumentDetail::Full,
        )
        .version("4.17.21")
        .unwrap()
        .clone();
        assert_eq!(
            references(&record),
            [
                "c6e281b878b315c7a10d90f9c2af4cdb112d9625",
                "v4.17.21",
                "4.17.21",
                "lodash@4.17.21"
            ]
        );
        record.provenance.git_head = Some("c6e281b".to_owned());
        assert_eq!(references(&record).len(), 3, "a short hash is no commit");
        record.provenance.git_head = Some("z".repeat(40));
        assert_eq!(references(&record).len(), 3, "not hex");
        record.provenance.git_head = Some(String::new());
        assert_eq!(
            references(&record).len(),
            3,
            "an empty gitHead is no commit"
        );
        record.package = PackageKey::from_registry_name(Ecosystem::Npm, "@rolldown/pluginutils")
            .and_then(|key| key.at_version("1.0.1"))
            .unwrap();
        assert_eq!(
            references(&record),
            [
                "v1.0.1",
                "1.0.1",
                "@rolldown/pluginutils@1.0.1",
                "pluginutils@1.0.1"
            ]
        );
    }

    /// The first component is dropped, `\r` does not count, only regular files are kept,
    /// and each `package.json` that is JSON is kept by its directory.
    #[test]
    fn an_archive_reads_as_files_from_the_package_root() {
        let package = read(&[
            ("package/package.json", br#"{"name":"x"}"#),
            ("package/index.js", b"a\r\nb\n"),
            ("./package/lib/x.js", b"x"),
            ("package/lib/package.json", b"not json"),
            ("top-level-file", b"skipped"),
        ]);
        assert_eq!(
            package.files.keys().collect::<Vec<_>>(),
            ["index.js", "lib/package.json", "lib/x.js", "package.json"]
        );
        assert_eq!(package.manifest(), Some(&serde_json::json!({"name": "x"})));
        assert_eq!(package.manifests.len(), 1, "not JSON");
        let oversized = format!(
            r#"{{"name":"x","pad":"{}"}}"#,
            " ".repeat(MAX_MEMBER_BYTES + 1)
        );
        let big = tree(
            &mut &*tarball(&[("package/package.json", oversized.as_bytes())]),
            MAX_SOURCE_BYTES,
        )
        .expect("a tarball");
        assert!(
            big.manifest().is_none(),
            "a manifest over the ceiling is not parsed"
        );
        assert!(
            big.files.contains_key("package.json"),
            "and is still a file"
        );
        let unix = read(&[("package/index.js", b"a\nb\n")]);
        assert_eq!(package.files["index.js"], unix.files["index.js"]);

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/dir/", &[][..])
            .unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &builder.into_inner().unwrap()).unwrap();
        let directories = tree(&mut &*gz.finish().unwrap(), 1 << 20).unwrap();
        assert!(directories.files.is_empty(), "a directory is not a file");
    }

    /// A monorepo package is found by the `package.json` naming it: the directory the metadata
    /// gives, the root, then the shallowest, and rooted there.
    #[test]
    fn a_package_is_found_by_the_manifest_naming_it() {
        let source = read(&[
            (
                "r-abc/package.json",
                br#"{"name":"root","version":"0.0.0"}"#,
            ),
            (
                "r-abc/packages/x/package.json",
                br#"{"name":"x","version":"1"}"#,
            ),
            ("r-abc/packages/x/index.js", b"x"),
            ("r-abc/packages/xy/index.js", b"y"),
            (
                "r-abc/test/fixtures/x/package.json",
                br#"{"name":"x","version":"1"}"#,
            ),
            ("r-abc/unnamed/package.json", b"{}"),
            (
                "r-abc/a/package.json",
                br#"{"name":"x","version":"1","private":true}"#,
            ),
            ("r-abc/b/package.json", br#"{"name":"x","version":1}"#),
            ("r-abc/c/package.json", br#"{"name":"x"}"#),
            (
                "r-abc/d/package.json",
                br#"{"name":"x","version":"1","private":false}"#,
            ),
            (
                "r-abc/d/deeper/package.json",
                br#"{"name":"d","version":"1"}"#,
            ),
        ]);
        let files =
            |tree: Option<Tree>| tree.map(|tree| tree.files.into_keys().collect::<Vec<_>>());
        let x = Some(vec!["index.js".to_owned(), "package.json".to_owned()]);
        assert_eq!(files(source.package("x", Some("/packages/x/"))), x);
        assert_eq!(
            files(source.package("x", None)),
            Some(vec![
                "deeper/package.json".to_owned(),
                "package.json".to_owned()
            ]),
            "the shallowest publishable: private, a version that is no string and no version are not"
        );
        for skipped in ["a", "b", "c"] {
            assert_eq!(
                files(source.package("x", Some(skipped))),
                files(source.package("x", None))
            );
        }
        assert_eq!(
            files(source.package("x", Some("test/fixtures/x"))),
            Some(vec!["package.json".to_owned()]),
            "the directory given comes first"
        );
        assert_eq!(
            source
                .package("root", Some("/"))
                .map(|tree| tree.files.len()),
            Some(11),
            "`/` is the root"
        );
        assert_eq!(source.package("absent", None), None);
        assert_eq!(
            source.package("x", Some("packages/x")).unwrap().manifest(),
            Some(&serde_json::json!({"name": "x", "version": "1"}))
        );
    }

    #[test]
    fn an_archive_over_the_limit_or_not_an_archive_is_refused() {
        let big = tarball(&[("package/a", &[b'a'; 10]), ("package/b", &[b'b'; 10])]);
        assert_eq!(
            tree(&mut &*big, 15),
            Err(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit: 15
            })
        );
        assert_eq!(
            tree(&mut &*big, 20).map(|tree| tree.files.len()),
            Ok(2),
            "at the limit"
        );
        assert!(matches!(
            tree(&mut &b"not gzip"[..], 15),
            Err(ReadError::NotAnArchive(_))
        ));
        let noise: Vec<u8> = (0u32..65536)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let whole = tarball(&[("package/a", &noise)]);
        assert!(matches!(
            tree(&mut &whole[..whole.len() / 2], 1 << 20),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// Each difference, sorted into what it is.
    #[test]
    fn a_package_is_compared_with_its_source() {
        let source = read(
            &[
                (
                    "r-abc/package.json",
                    br#"{"scripts":{"preinstall":"dropped","install":"node-gyp rebuild","test":"x"},"dependencies":{"a":"1"}}"#,
                ),
                ("r-abc/index.js", b"same"),
                ("r-abc/README.md", b"source"),
                ("r-abc/lib.js", b"before"),
                ("r-abc/build.js", b"built"),
                ("r-abc/src/index.ts", b"typescript"),
            ],
        );
        let package = read(
            &[
                (
                    "package/package.json",
                    br#"{"scripts":{"install":"node-gyp rebuild","postinstall":"node ./setup && sh 'build.js' && node \"quoted.js\"","test":"y"},
                        "dependencies":{"a":"2","b":"1"},"optionalDependencies":{"c":"1"}}"#,
                ),
                ("package/index.js", b"same"),
                ("package/README.md", b"published"),
                ("package/lib.js", b"after"),
                ("package/setup.js", b"added"),
                ("package/quoted.js", b"added"),
                ("package/build.js", b"built"),
                ("package/dist/index.js", b"compiled"),
            ],
        );
        assert_eq!(
            compare(&package, &source),
            Comparison {
                manifests: true,
                lifecycle_scripts: vec!["postinstall".to_owned()],
                dependencies: vec!["b".to_owned()],
                optional_dependencies: vec!["c".to_owned()],
                lifecycle_files: vec![
                    ("postinstall".to_owned(), "quoted.js".to_owned()),
                    ("postinstall".to_owned(), "setup.js".to_owned())
                ],
                lifecycle_targets: 3,
                differing: vec!["lib.js".to_owned()],
                differing_markdown: vec!["README.md".to_owned()],
                only_in_package: vec![
                    "dist/index.js".to_owned(),
                    "quoted.js".to_owned(),
                    "setup.js".to_owned()
                ],
                same: 2,
            }
        );
    }

    /// Without a source `package.json` the manifests are not compared, and a lifecycle
    /// script's files still are.
    #[test]
    fn a_source_without_a_manifest_compares_only_files() {
        let package = read(&[
            (
                "package/package.json",
                br#"{"scripts":{"preinstall":"node x.js"},"dependencies":{"a":"1"}}"#,
            ),
            ("package/x.js", b"x"),
        ]);
        let found = compare(&package, &read(&[("r/x.js", b"other")]));
        assert!(!found.manifests);
        assert!(found.lifecycle_scripts.is_empty() && found.dependencies.is_empty());
        assert_eq!(
            found.lifecycle_files,
            [("preinstall".to_owned(), "x.js".to_owned())]
        );
        assert_eq!(found.lifecycle_targets, 1);
        assert_eq!(found.differing, ["x.js"]);

        let unscripted = read(&[("package/package.json", b"{}")]);
        assert!(
            compare(&package, &unscripted).manifests,
            "no `scripts` is no script"
        );

        let bare = compare(&read(&[("package/x.js", b"x")]), &Tree::default());
        assert_eq!(bare.only_in_package, ["x.js"]);
        assert!(bare.lifecycle_files.is_empty());
    }

    fn wheel(files: &[(&str, &[u8])]) -> Tree {
        wheel_tree(
            std::io::Cursor::new(crate::util::test_support::zip_of(files)),
            1 << 20,
        )
        .expect("a wheel")
    }

    /// A wheel's paths are kept as they install, its `METADATA` is kept as text, and a
    /// wheel over the limit or not a zip is refused.
    #[test]
    fn a_wheel_reads_as_files_where_they_install() {
        let installed = wheel(&[
            ("idna/__init__.py", b"a\r\n"),
            ("idna-3.10.dist-info/METADATA", b"Name: idna\r\n"),
            ("idna-3.10.dist-info/RECORD", b"x"),
        ]);
        assert_eq!(
            installed.files.keys().collect::<Vec<_>>(),
            [
                "idna-3.10.dist-info/METADATA",
                "idna-3.10.dist-info/RECORD",
                "idna/__init__.py"
            ]
        );
        assert_eq!(installed.metadata.as_deref(), Some("Name: idna\n"));

        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .add_directory("idna/", zip::write::SimpleFileOptions::default())
            .unwrap();
        let directory = writer.finish().unwrap().into_inner();
        assert!(
            wheel_tree(std::io::Cursor::new(directory), 1 << 20)
                .unwrap()
                .files
                .is_empty()
        );

        let big = crate::util::test_support::zip_of(&[("a", &[0; 10]), ("b", &[0; 10])]);
        assert_eq!(
            wheel_tree(std::io::Cursor::new(big), 15),
            Err(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit: 15
            })
        );
        assert!(matches!(
            wheel_tree(std::io::Cursor::new(b"not a zip".to_vec()), 15),
            Err(ReadError::NotAnArchive(_))
        ));
        let good = crate::util::test_support::zip_of(&[("a", b"hello")]);
        let mut no_header = good.clone();
        no_header[0] = b'X';
        let mut bad_crc = good.clone();
        bad_crc[31] ^= 0xff;
        for broken in [no_header, bad_crc] {
            assert!(matches!(
                wheel_tree(std::io::Cursor::new(broken), 1 << 20),
                Err(ReadError::NotAnArchive(_))
            ));
        }
        let sdist = read(&[("idna-3.10/PKG-INFO", b"Name: idna\n")]);
        assert_eq!(sdist.metadata.as_deref(), Some("Name: idna\n"));
    }

    #[test]
    fn a_layout_follows_the_filename() {
        for (ecosystem, filename, expected) in [
            (Ecosystem::Npm, "x-1.0.0.tgz", Some(Layout::Tar)),
            (
                Ecosystem::PyPI,
                "x-1.0-py3-none-any.whl",
                Some(Layout::Wheel),
            ),
            (Ecosystem::PyPI, "x-1.0.tar.gz", Some(Layout::Tar)),
            (Ecosystem::PyPI, "x-1.0.zip", None),
        ] {
            assert_eq!(Layout::of(ecosystem, filename), expected, "{filename}");
        }
    }

    /// A source-labelled `Project-URL` first, then any other, then `Home-page`, and only a
    /// GitHub repository, from the headers and not the description after them.
    #[test]
    fn pypi_metadata_names_its_repository() {
        let repo = |metadata: &str| {
            pypi_repository(metadata).map(|repo| format!("{}/{}", repo.owner, repo.name))
        };
        assert_eq!(
            repo("Name: x\nProject-URL: Documentation, https://github.com/d/docs\nProject-URL: Source Code, https://github.com/o/r\nHome-page: https://github.com/h/h\n")
                .as_deref(),
            Some("o/r")
        );
        assert_eq!(
            repo("Project-URL: Changelog, https://github.com/c/c/blob/main/CHANGES\nHome-page: https://github.com/h/h\n").as_deref(),
            Some("c/c")
        );
        assert_eq!(
            repo("Home-page: https://github.com/h/h\n").as_deref(),
            Some("h/h")
        );
        assert_eq!(
            repo("Project-URL: https://github.com/n/n\n").as_deref(),
            Some("n/n")
        );
        assert_eq!(repo("Home-page: https://example.test\n"), None);
        assert_eq!(
            repo("Name: x\n\nHome-page: https://github.com/d/d\n"),
            None,
            "the description"
        );
    }

    /// An sdist at the source's root and a wheel from `src/`, past a generated file. `setup.py`
    /// and `.pth` run on install, and packaging metadata is left out.
    #[test]
    fn a_pypi_artifact_is_compared_with_its_source() {
        let source = read(&[
            ("r-v1/setup.py", b"setup()"),
            ("r-v1/setup.cfg", b"[metadata]"),
            ("r-v1/src/pkg/__init__.py", b"init"),
            ("r-v1/src/pkg/core.py", b"core"),
            ("r-v1/tests/pkg/__init__.py", b"other"),
            ("r-v1/src/pkg/core_module.py", b"module"),
            ("r-v1/VERSION", b"1"),
            ("r-v1/z.py", b"z"),
            ("r-v1/vendor/a/deep/x.py", b"x"),
        ]);
        let sdist = read(&[
            ("pkg-1.0/PKG-INFO", b"Name: pkg"),
            ("pkg-1.0/setup.py", b"setup(evil)"),
            ("pkg-1.0/setup.cfg", b"[metadata]\n[egg_info]"),
            ("pkg-1.0/src/pkg/__init__.py", b"init"),
            ("pkg-1.0/src/pkg.egg-info/PKG-INFO", b"Name: pkg"),
        ]);
        let found = compare_pypi(&sdist, &source, Layout::Tar).expect("located");
        assert_eq!(
            found.lifecycle_files,
            [("build".to_owned(), "setup.py".to_owned())]
        );
        let kept = read(&[
            ("pkg-1.0/setup.py", b"setup()"),
            ("pkg-1.0/src/pkg/core.py", b"core"),
        ]);
        let found_kept = compare_pypi(&kept, &source, Layout::Tar).expect("located");
        assert_eq!(
            (
                found_kept.lifecycle_targets,
                found_kept.lifecycle_files.len()
            ),
            (1, 0)
        );
        assert_eq!(found.lifecycle_targets, 1);
        assert_eq!(found.differing, ["setup.cfg", "setup.py"]);
        assert_eq!(found.same, 1);
        assert!(
            found.only_in_package.is_empty(),
            "PKG-INFO and .egg-info are packaging"
        );

        let installed = wheel(&[
            ("pkg/__init__.py", b"init"),
            ("pkg/core.py", b"core"),
            ("pkg/_generated.py", b"x"),
            ("_a.py", b"generated at build"),
            ("pkg-startup.pth", b"import os"),
            ("pkg/data.pth", b"not at the top, so not read at startup"),
            ("VERSION", b"1"),
            ("pkg-1.0.dist-info/METADATA", b"Name: pkg"),
        ]);
        let found = compare_pypi(&installed, &source, Layout::Wheel).expect("located in src");
        assert_eq!(
            found.lifecycle_files,
            [("startup".to_owned(), "pkg-startup.pth".to_owned())]
        );
        assert_eq!(found.same, 2);
        assert_eq!(
            found.only_in_package,
            [
                "VERSION",
                "_a.py",
                "pkg-startup.pth",
                "pkg/_generated.py",
                "pkg/data.pth"
            ],
            "VERSION at the source's root anchors nothing: only Python files do"
        );

        let two = wheel(&[
            ("pkg/__init__.py", b"init"),
            ("pkg/core_module.py", b"module"),
        ]);
        let found = compare_pypi(&two, &source, Layout::Wheel).expect("located");
        assert_eq!(found.same, 2, "src holds two of its files and tests one");

        let deep = wheel(&[("a/deep/x.py", b"x"), ("z.py", b"z")]);
        let found = compare_pypi(&deep, &source, Layout::Wheel).expect("located");
        assert_eq!(
            found.only_in_package,
            ["a/deep/x.py"],
            "the shallowest file anchors first"
        );

        let elsewhere = wheel(&[("other/__init__.py", b"x")]);
        assert_eq!(compare_pypi(&elsewhere, &source, Layout::Wheel), None);
        let no_python = wheel(&[("data.txt", b"x")]);
        assert_eq!(compare_pypi(&no_python, &source, Layout::Wheel), None);
    }
}
