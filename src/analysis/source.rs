//! The published npm tarball against the source its metadata names: the commit in `gitHead`,
//! else a release tag, as GitHub's archive of it. Report only, measured by
//! `examples/source_diff.rs`.
//! See docs/engineering_decisions/source-diff.md.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use sha2::{Digest, Sha256};

use super::{NPM_INSTALL_SCRIPTS, ReadError, walk};
use crate::record::PackageRecord;

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
        (!name.is_empty()).then(|| Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    /// GitHub's archive of this repository at `reference`, a commit or a tag.
    pub fn archive_url(&self, reference: &str) -> String {
        format!(
            "https://codeload.github.com/{}/{}/tar.gz/{reference}",
            self.owner, self.name
        )
    }
}

/// `Some` when `authority`, with any user and port, is GitHub's host.
fn github_host(authority: &str) -> Option<()> {
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    matches!(host, "github.com" | "www.github.com").then_some(())
}

/// The references to fetch `record`'s source at, in order: `gitHead`, then the tags a release
/// is usually given.
pub fn references(record: &PackageRecord) -> Vec<String> {
    let version = record.package.version();
    let name = record.package.key().registry_name();
    record
        .provenance
        .git_head
        .iter()
        .filter(|head| !head.is_empty())
        .cloned()
        .chain([
            format!("v{version}"),
            version.to_owned(),
            format!("{name}@{version}"),
        ])
        .collect()
}

/// An archive's files by path below its first component, as SHA-256 of bytes without `\r`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tree {
    pub files: BTreeMap<String, [u8; 32]>,
    /// Each `package.json` that is JSON, by the directory holding it: `""` for the root.
    pub manifests: BTreeMap<String, serde_json::Value>,
}

impl Tree {
    /// The root `package.json`.
    pub fn manifest(&self) -> Option<&serde_json::Value> {
        self.manifests.get("")
    }

    /// The package `name`, as a tree rooted at the first directory whose `package.json` names
    /// it: `directory`, then the root, then the shallowest other.
    /// Returns `None` when no `package.json` names it.
    pub fn package(&self, name: &str, directory: Option<&str>) -> Option<Tree> {
        let names = |dir: &&str| {
            self.manifests
                .get(*dir)
                .and_then(|manifest| manifest.get("name")?.as_str())
                == Some(name)
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
        let mut bytes = Vec::with_capacity(member.size as usize);
        member
            .bytes
            .read_to_end(&mut bytes)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        bytes.retain(|&byte| byte != b'\r');
        let manifest = match path.rsplit_once('/') {
            Some((directory, "package.json")) => Some(directory),
            None if path == "package.json" => Some(""),
            _ => None,
        };
        if let Some(directory) = manifest
            && let Ok(manifest) = serde_json::from_slice(&bytes)
        {
            tree.manifests.insert(directory.to_owned(), manifest);
        }
        tree.files
            .insert(path.to_owned(), Sha256::digest(&bytes).into());
        Ok(false)
    })?;
    Ok(tree)
}

/// What the published package holds that its source does not.
#[derive(Debug, Default, PartialEq, Eq)]
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
            if source.files.get(&file) != package.files.get(&file) {
                found.lifecycle_files.push((name.to_owned(), file));
            }
        }
    }
    for (path, digest) in package
        .files
        .iter()
        .filter(|(path, _)| *path != "package.json")
    {
        match source.files.get(path) {
            None => found.only_in_package.push(path.clone()),
            Some(built) if built == digest => found.same += 1,
            Some(_) if path.to_ascii_lowercase().ends_with(".md") => {
                found.differing_markdown.push(path.clone());
            }
            Some(_) => found.differing.push(path.clone()),
        }
    }
    found
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
            ("https://github.com", None),
            ("https://github.com/", None),
            ("github", None),
        ] {
            let repo = Repo::from_url(url).map(|r| format!("{}/{}", r.owner, r.name));
            assert_eq!(repo.as_deref(), expected, "{url}");
        }
        assert_eq!(
            Repo::from_url("o/r").unwrap().archive_url("abc"),
            "https://codeload.github.com/o/r/tar.gz/abc"
        );
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
        record.provenance.git_head = Some(String::new());
        assert_eq!(
            references(&record).len(),
            3,
            "an empty gitHead is no commit"
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
            ("r-abc/package.json", br#"{"name":"root"}"#),
            ("r-abc/packages/x/package.json", br#"{"name":"x"}"#),
            ("r-abc/packages/x/index.js", b"x"),
            ("r-abc/packages/xy/index.js", b"y"),
            ("r-abc/test/fixtures/x/package.json", br#"{"name":"x"}"#),
            ("r-abc/unnamed/package.json", b"{}"),
        ]);
        let files =
            |tree: Option<Tree>| tree.map(|tree| tree.files.into_keys().collect::<Vec<_>>());
        let x = Some(vec!["index.js".to_owned(), "package.json".to_owned()]);
        assert_eq!(files(source.package("x", Some("/packages/x/"))), x);
        assert_eq!(files(source.package("x", None)), x, "the shallowest");
        assert_eq!(files(source.package("x", Some("elsewhere"))), x);
        assert_eq!(
            files(source.package("x", Some("test/fixtures/x"))),
            Some(vec!["package.json".to_owned()]),
            "the directory given comes first"
        );
        assert_eq!(
            source
                .package("root", Some("/"))
                .map(|tree| tree.files.len()),
            Some(6),
            "`/` is the root"
        );
        assert_eq!(source.package("absent", None), None);
        assert_eq!(
            source.package("x", None).unwrap().manifest(),
            Some(&serde_json::json!({"name": "x"}))
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
}
