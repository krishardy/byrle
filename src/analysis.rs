//! What an artifact's own bytes say, as opposed to what its metadata claims.
//!
//! See docs/engineering_decisions/install-scripts-from-the-artifact.md and
//! docs/engineering_decisions/artifact-spool.md.

pub mod attestation;
pub mod postgres;
pub mod run;
pub mod source;
pub mod store;

use std::io::Read;

use crate::identity::Ecosystem;
use crate::record::DocumentDetail;

/// The lifecycle scripts an artifact declares, read from the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallScripts {
    /// The script names that run on install, in npm's order, or `setup.py` for an sdist.
    pub names: Vec<String>,
    /// Each name's command, for an operator to read. Empty for an sdist.
    pub bodies: Vec<(String, String)>,
}

impl InstallScripts {
    pub fn runs_on_install(&self) -> bool {
        !self.names.is_empty()
    }
}

/// Why an artifact could not be read, which is never the same as "nothing found".
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The bytes are not the archive the filename says.
    NotAnArchive(String),
    /// The archive holds no file this reads: no `package.json` in an npm tarball.
    NothingToRead,
    /// A member larger than [`MAX_MEMBER_BYTES`], which a decompression bomb is.
    TooLarge { member: String, limit: usize },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArchive(why) => write!(f, "not readable as an archive: {why}"),
            Self::NothingToRead => write!(f, "the archive holds no manifest to read"),
            Self::TooLarge { member, limit } => {
                write!(f, "`{member}` is larger than the {limit}-byte ceiling")
            }
        }
    }
}

/// The largest member this reads into memory, far past any `package.json`.
pub const MAX_MEMBER_BYTES: usize = 4 * 1024 * 1024;

/// The readers' version, stored with each analysis; bumped whenever a reader's answer changes.
pub const READER: &str = "install-scripts 2";

/// Which reader an artifact is read by. A file no reader reads is never analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// An npm tarball, read by [`npm_install_scripts`].
    NpmTarball,
    /// A PyPI sdist, read by [`sdist_install_scripts`].
    Sdist,
}

impl Reader {
    /// The reader for `filename` in `ecosystem`. `None` for a PyPI wheel, which runs
    /// nothing on install, so nothing reads it.
    pub fn for_file(ecosystem: Ecosystem, filename: &str) -> Option<Self> {
        match ecosystem {
            Ecosystem::Npm => Some(Self::NpmTarball),
            Ecosystem::PyPI if filename.ends_with(".whl") => None,
            Ecosystem::PyPI => Some(Self::Sdist),
        }
    }

    pub fn read(self, artifact: &mut dyn Read) -> Result<InstallScripts, ReadError> {
        match self {
            Self::NpmTarball => npm_install_scripts(artifact),
            Self::Sdist => sdist_install_scripts(artifact),
        }
    }
}

/// npm's install lifecycle, in the order npm runs them.
pub const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// The scripts an npm tarball's own `package.json` declares.
///
/// One gzip stream and one JSON object: 0.4ms for `bufferutil` 4.1.0, 163,631 bytes.
pub fn npm_install_scripts(tarball: &mut dyn Read) -> Result<InstallScripts, ReadError> {
    let manifest = member(tarball, &|path| {
        let path = path.strip_prefix("./").unwrap_or(path);
        matches!(path.split_once('/'), Some((top, "package.json")) if !top.is_empty())
    })?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
    let Some(scripts) = manifest.get("scripts").and_then(|s| s.as_object()) else {
        return Ok(InstallScripts::default());
    };
    let mut found = InstallScripts::default();
    for name in NPM_INSTALL_SCRIPTS {
        if let Some(body) = scripts.get(name).and_then(|b| b.as_str()) {
            found.names.push(name.to_owned());
            found.bodies.push((name.to_owned(), body.to_owned()));
        }
    }
    Ok(found)
}

/// Whether a PyPI sdist carries a `setup.py`, which pip runs to build it.
///
/// A wheel runs nothing, so this is asked of an sdist only. `pyproject.toml` alone is not
/// this: a PEP 517 build runs the backend it names, which is its own question.
pub fn sdist_install_scripts(sdist: &mut dyn Read) -> Result<InstallScripts, ReadError> {
    match member(sdist, &|path| {
        path.rsplit('/').next() == Some("setup.py") && path.matches('/').count() <= 1
    }) {
        Ok(_) => Ok(InstallScripts {
            names: vec!["setup.py".to_owned()],
            bodies: Vec::new(),
        }),
        Err(ReadError::NothingToRead) => Ok(InstallScripts::default()),
        Err(e) => Err(e),
    }
}

/// The first member of a gzipped tar whose path `wanted` accepts.
fn member(bytes: &mut dyn Read, wanted: &dyn Fn(&str) -> bool) -> Result<Vec<u8>, ReadError> {
    let mut found = None;
    walk(bytes, &mut |path, member| {
        if !wanted(path) {
            return Ok(false);
        }
        let size = member.size as usize;
        if size > MAX_MEMBER_BYTES {
            return Err(ReadError::TooLarge {
                member: path.to_owned(),
                limit: MAX_MEMBER_BYTES,
            });
        }
        let mut out = Vec::with_capacity(size);
        member
            .bytes
            .take(MAX_MEMBER_BYTES as u64)
            .read_to_end(&mut out)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        found = Some(out);
        Ok(true)
    })?;
    found.ok_or(ReadError::NothingToRead)
}

/// One member of a tar, as [`walk`] hands it over.
struct Member<'a> {
    /// Whether it is a regular file, not a directory or a link.
    file: bool,
    /// The size its header states.
    size: u64,
    bytes: &'a mut dyn Read,
}

/// Each member of a gzipped tar in order, with its path, until `visit` returns `true`.
/// Errors when the bytes are not a gzipped tar, or with what `visit` errors with.
fn walk(
    bytes: &mut dyn Read,
    visit: &mut dyn FnMut(&str, Member<'_>) -> Result<bool, ReadError>,
) -> Result<(), ReadError> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().expect("a new archive is at its start");
    for entry in entries {
        let mut entry = entry.map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        let path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let member = Member {
            file: entry.header().entry_type().is_file(),
            size: entry.size(),
            bytes: &mut entry,
        };
        if visit(&path, member)? {
            break;
        }
    }
    Ok(())
}

/// What the artifact says against what the metadata claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The artifact and the metadata agree.
    Kept,
    /// The artifact runs scripts and the metadata did not say so.
    Undeclared,
    /// The metadata said so and the reader found none. The claim still stands.
    Overstated,
}

impl Claim {
    pub fn of(found: &InstallScripts, claimed: bool, detail: DocumentDetail) -> Self {
        match (found.runs_on_install(), claimed) {
            (true, false) => Self::Undeclared,
            (false, true) if detail == DocumentDetail::Full => Self::Overstated,
            _ => Self::Kept,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kept => "kept",
            Self::Undeclared => "undeclared",
            Self::Overstated => "overstated",
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::util::test_support::tarball;

    /// What each reader finds on a fixed set of archives, one line each.
    fn answers() -> String {
        let npm = |files: &[(&str, &[u8])]| npm_install_scripts(&mut &*tarball(files));
        let sdist = |files: &[(&str, &[u8])]| sdist_install_scripts(&mut &*tarball(files));
        let cases: Vec<(&str, Result<InstallScripts, ReadError>)> = vec![
            (
                "npm, every install lifecycle script and two others",
                npm(&[(
                    "package/package.json",
                    br#"{"scripts":{"preinstall":"a","install":"b","postinstall":"c","test":"d","prepare":"e"}}"#,
                )]),
            ),
            (
                "npm, only scripts that do not run on install",
                npm(&[("package/package.json", br#"{"scripts":{"test":"t","build":"b"}}"#)]),
            ),
            ("npm, no scripts key", npm(&[("package/package.json", b"{}")])),
            (
                "npm, scripts not an object",
                npm(&[("package/package.json", br#"{"scripts":"install"}"#)]),
            ),
            (
                "npm, an install script that is not a string",
                npm(&[("package/package.json", br#"{"scripts":{"install":5}}"#)]),
            ),
            (
                "npm, a nested package.json listed first",
                npm(&[
                    (
                        "package/node_modules/x/package.json",
                        br#"{"scripts":{"postinstall":"nested"}}"#,
                    ),
                    ("package/package.json", br#"{"scripts":{"install":"top"}}"#),
                ]),
            ),
            (
                "npm, top package.json written with a leading ./",
                npm(&[("./package/package.json", br#"{"scripts":{"install":"dot"}}"#)]),
            ),
            (
                "npm, a file whose name only ends in package.json",
                npm(&[("package/notpackage.json", br#"{"scripts":{"install":"no"}}"#)]),
            ),
            ("npm, no package.json", npm(&[("package/index.js", b"")])),
            ("npm, not gzip", npm_install_scripts(&mut &b"plain"[..])),
            ("npm, package.json not JSON", npm(&[("package/package.json", b"{")])),
            ("sdist, setup.py at its root", sdist(&[("x-1.0/setup.py", b"")])),
            ("sdist, setup.py only deeper", sdist(&[("x-1.0/sub/setup.py", b"")])),
            ("sdist, pyproject.toml only", sdist(&[("x-1.0/pyproject.toml", b"")])),
            ("sdist, not gzip", sdist_install_scripts(&mut &b"plain"[..])),
        ];
        cases
            .into_iter()
            .map(|(case, answer)| match answer {
                Ok(found) => format!(
                    "{case}: runs {:?}, bodies {:?}\n",
                    found.names, found.bodies
                ),
                Err(e) => format!("{case}: error: {e}\n"),
            })
            .collect()
    }

    /// The first manifest is the one read, and the walk stops there.
    #[test]
    fn the_first_matching_member_is_read() {
        let archive = tarball(&[
            ("package/package.json", br#"{"scripts":{"install":"x"}}"#),
            ("other/package.json", b"{}"),
        ]);
        let found = npm_install_scripts(&mut &*archive).expect("reads");
        assert_eq!(found.names, ["install"]);
    }

    /// A changed answer with an unchanged [`READER`] fails, even with [`crate::env::BLESS`]
    /// set, because stored analyses under the old version would keep being read back.
    #[test]
    fn a_reader_that_answers_differently_bumps_its_version() {
        let path = format!(
            "{}/tests/fixtures/analysis/readers.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let actual = answers();
        let recorded = std::fs::read_to_string(&path).unwrap_or_default();
        let (reader, answered) = recorded
            .strip_prefix("reader: ")
            .and_then(|rest| rest.split_once("\n\n"))
            .unwrap_or(("", ""));
        if reader == READER {
            assert!(
                answered == actual,
                "a reader answers differently and READER is still `{READER}`: bump \
                 analysis::READER, then rerun with {}=1. The answers now:\n{actual}",
                crate::env::BLESS
            );
            return;
        }
        assert!(
            crate::env::process().bless(),
            "READER is `{READER}` and the golden file records `{reader}`: rerun with {}=1",
            crate::env::BLESS
        );
        std::fs::write(&path, format!("reader: {READER}\n\n{actual}")).expect("writes");
    }

    /// A wheel runs nothing on install, so nothing reads it. Every other file is read.
    #[test]
    fn a_reader_is_chosen_for_every_file_but_a_wheel() {
        assert_eq!(
            Reader::for_file(Ecosystem::Npm, "widget-1.0.0.tgz"),
            Some(Reader::NpmTarball)
        );
        assert_eq!(
            Reader::for_file(Ecosystem::PyPI, "six-1.17.0.tar.gz"),
            Some(Reader::Sdist)
        );
        assert_eq!(
            Reader::for_file(Ecosystem::PyPI, "six-1.17.0-py2.py3-none-any.whl"),
            None
        );
        let sdist = tarball(&[("six-1.17.0/setup.py", b"")]);
        assert_eq!(
            Reader::Sdist.read(&mut &sdist[..]).expect("reads").names,
            ["setup.py"]
        );
    }

    /// `bufferutil` 4.1.0 declares `install: node-gyp-build`, which is what its packument's
    /// `hasInstallScript` reports. Read from the real tarball on 2026-09-21.
    #[test]
    fn an_npm_tarball_reports_the_install_scripts_it_declares() {
        let manifest = br#"{"name":"bufferutil","version":"4.1.0","scripts":{
            "install":"node-gyp-build","prebuild":"prebuildify --napi","test":"mocha"}}"#;
        let found = npm_install_scripts(&mut &*tarball(&[("package/package.json", manifest)]))
            .expect("the tarball reads");
        assert_eq!(
            found.names,
            ["install"],
            "only the install lifecycle counts"
        );
        assert_eq!(
            found.bodies,
            [("install".to_owned(), "node-gyp-build".to_owned())]
        );
        assert!(found.runs_on_install());
    }

    /// Every script npm runs on install, in the order it runs them, and nothing else.
    #[test]
    fn the_install_lifecycle_is_pre_install_and_post() {
        let manifest = br#"{"scripts":{"postinstall":"c","preinstall":"a","install":"b",
            "prepare":"d","test":"e"}}"#;
        let found = npm_install_scripts(&mut &*tarball(&[("package/package.json", manifest)]))
            .expect("the tarball reads");
        assert_eq!(found.names, ["preinstall", "install", "postinstall"]);
    }

    /// A package with no scripts at all, and one with scripts that do not run on install.
    #[test]
    fn a_tarball_that_runs_nothing_on_install_says_so() {
        for manifest in [
            &br#"{"name":"node-gyp-build","version":"4.8.4"}"#[..],
            &br#"{"scripts":{"test":"standard && node test"}}"#[..],
        ] {
            let found = npm_install_scripts(&mut &*tarball(&[("package/package.json", manifest)]))
                .expect("the tarball reads");
            assert!(!found.runs_on_install(), "{found:?}");
        }
    }

    /// An archive with no manifest is not a package that runs nothing: it is one this
    /// cannot answer for.
    #[test]
    fn an_archive_with_no_manifest_is_an_error() {
        let empty = tarball(&[("package/index.js", b"module.exports = 1;")]);
        assert_eq!(
            npm_install_scripts(&mut &*empty),
            Err(ReadError::NothingToRead)
        );
        assert!(matches!(
            npm_install_scripts(&mut &b"not a gzip stream"[..]),
            Err(ReadError::NotAnArchive(_))
        ));
        let manifest = tarball(&[("package/package.json", b"{ not json")]);
        assert!(matches!(
            npm_install_scripts(&mut &*manifest),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// A member past the ceiling is refused rather than read into memory.
    #[test]
    fn a_member_past_the_ceiling_is_refused() {
        let big = vec![b' '; MAX_MEMBER_BYTES + 1];
        let archive = tarball(&[("package/package.json", &big)]);
        assert_eq!(
            npm_install_scripts(&mut &*archive),
            Err(ReadError::TooLarge {
                member: "package/package.json".to_owned(),
                limit: MAX_MEMBER_BYTES,
            })
        );
    }

    /// An sdist's `setup.py` is what pip runs to build it. `six` 1.17.0 has one at the
    /// root of its directory; a wheel-only project has none.
    #[test]
    fn an_sdist_reports_whether_it_has_a_setup_py() {
        let with = tarball(&[
            ("six-1.17.0/PKG-INFO", b"Name: six"),
            ("six-1.17.0/setup.py", b"from setuptools import setup"),
        ]);
        let found = sdist_install_scripts(&mut &*with).expect("the sdist reads");
        assert_eq!(found.names, ["setup.py"]);

        let without = tarball(&[
            ("idna-3.10/PKG-INFO", b"Name: idna"),
            ("idna-3.10/pyproject.toml", b"[build-system]"),
            ("idna-3.10/tests/data/setup.py", b"setup()"),
        ]);
        assert!(
            !sdist_install_scripts(&mut &*without)
                .expect("the sdist reads")
                .runs_on_install()
        );
    }

    /// The ceiling, and the two sides of it. A member of exactly the ceiling is read: it
    /// is the largest thing that is still not a bomb.
    #[test]
    fn a_member_at_the_ceiling_is_read_and_one_past_it_is_not() {
        assert_eq!(MAX_MEMBER_BYTES, 4_194_304, "4 MiB");
        let manifest = br#"{"scripts":{"postinstall":"a"}}"#;
        let padded = {
            let mut bytes = manifest.to_vec();
            bytes.resize(MAX_MEMBER_BYTES, b' ');
            bytes
        };
        let found = npm_install_scripts(&mut &*tarball(&[("package/package.json", &padded)]))
            .expect("a member at the ceiling is read whole");
        assert_eq!(found.names, ["postinstall"]);

        let over = {
            let mut bytes = padded.clone();
            bytes.push(b' ');
            bytes
        };
        assert_eq!(
            npm_install_scripts(&mut &*tarball(&[("package/package.json", &over)])),
            Err(ReadError::TooLarge {
                member: "package/package.json".to_owned(),
                limit: MAX_MEMBER_BYTES,
            })
        );
    }

    /// Each answer a person reads, in the log or in a report.
    #[test]
    fn every_outcome_says_what_it_is() {
        assert_eq!(
            ReadError::NothingToRead.to_string(),
            "the archive holds no manifest to read"
        );
        assert_eq!(
            ReadError::NotAnArchive("bad gzip".to_owned()).to_string(),
            "not readable as an archive: bad gzip"
        );
        assert_eq!(
            ReadError::TooLarge {
                member: "package/package.json".to_owned(),
                limit: 10,
            }
            .to_string(),
            "`package/package.json` is larger than the 10-byte ceiling"
        );
        assert_eq!(
            [Claim::Kept, Claim::Undeclared, Claim::Overstated].map(Claim::as_str),
            ["kept", "undeclared", "overstated"]
        );
    }

    /// The real tarballs, from registry.npmjs.org and pypi.org, have the shapes the
    /// synthetic ones above do. Ignored by default, because it uses the network.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org and files.pythonhosted.org"]
    async fn the_real_artifacts_declare_what_their_metadata_claims() {
        let fetch = |url: &'static str| async move {
            reqwest::get(url)
                .await
                .expect("the host answers")
                .bytes()
                .await
                .expect("the body arrives")
                .to_vec()
        };

        let bufferutil =
            fetch("https://registry.npmjs.org/bufferutil/-/bufferutil-4.1.0.tgz").await;
        let found = npm_install_scripts(&mut &*bufferutil).expect("the tarball reads");
        assert_eq!(found.names, ["install"]);
        assert_eq!(found.bodies[0].1, "node-gyp-build");

        let node_gyp_build =
            fetch("https://registry.npmjs.org/node-gyp-build/-/node-gyp-build-4.8.4.tgz").await;
        assert!(
            !npm_install_scripts(&mut &*node_gyp_build)
                .expect("the tarball reads")
                .runs_on_install()
        );

        let six = fetch(
            "https://files.pythonhosted.org/packages/94/e7/\
             b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz",
        )
        .await;
        assert_eq!(
            sdist_install_scripts(&mut &*six)
                .expect("the sdist reads")
                .names,
            ["setup.py"]
        );
    }

    /// What the artifact says against what the metadata claimed.
    #[test]
    fn a_claim_the_artifact_does_not_keep_is_named() {
        let runs = InstallScripts {
            names: vec!["postinstall".to_owned()],
            bodies: Vec::new(),
        };
        let none = InstallScripts::default();
        for (found, claimed, detail, expected) in [
            (&runs, true, DocumentDetail::Abbreviated, Claim::Kept),
            (&runs, false, DocumentDetail::Abbreviated, Claim::Undeclared),
            (&none, false, DocumentDetail::Abbreviated, Claim::Kept),
            (&none, true, DocumentDetail::Abbreviated, Claim::Kept),
            (&none, true, DocumentDetail::Full, Claim::Overstated),
        ] {
            assert_eq!(Claim::of(found, claimed, detail), expected, "{found:?}");
        }
    }

    /// A member that ends before its declared size is not an archive this can read.
    #[test]
    fn a_member_cut_short_is_not_an_archive() {
        let body: Vec<u8> = (0..65_536u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let whole = crate::util::test_support::tarball(&[("package/package.json", &body)]);
        let cut = &whole[..whole.len() * 3 / 4];
        assert!(matches!(
            member(&mut &cut[..], &|path| path == "package/package.json"),
            Err(ReadError::NotAnArchive(_))
        ));
    }
}
