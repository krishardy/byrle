//! What an artifact's own bytes say, as opposed to what its metadata claims.
//!
//! The record's `has_install_scripts` is the registry's claim: npm's `hasInstallScript` on
//! the abbreviated packument, its `scripts` keys on the full one, and on PyPI whether the
//! version offers only an sdist. The artifact is where the truth is, and the two can
//! disagree: a packument that omits `hasInstallScript` for a tarball whose `package.json`
//! runs `postinstall` is a package that installs code the metadata said nothing about.
//!
//! No request waits for a detector. [`run`] analyses an artifact in the background the
//! first time it is fetched. The request is answered 503 only when the answer depends on
//! the analysis, and the retry is decided on what was stored. See `docs/engineering_decisions/artifact-spool.md`.
//!
//! # Cost tiers
//!
//! Every detector declares what it costs. Since 2026-09-26 the tier no longer decides
//! whether a request waits, because none does.

pub mod attestation;
pub mod postgres;
pub mod run;
pub mod store;

use std::io::Read;

use crate::identity::Ecosystem;
use crate::record::DocumentDetail;

/// What running a detector costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Runs on the bytes in hand, in the time it takes to decompress them. Reading
    /// `package.json` out of a tarball took 0.4ms for `bufferutil` 4.1.0, 163,631 bytes.
    Cheap,
    /// Needs a clone, a sandbox or another service.
    Expensive,
}

/// The lifecycle scripts an artifact declares, read from the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallScripts {
    /// The script names that run on install, in the order npm runs them, or `setup.py`
    /// for an sdist.
    pub names: Vec<String>,
    /// Each name's command, for an operator to read. npm writes them in `package.json`;
    /// an sdist's `setup.py` is a file rather than a command, so this is empty there.
    pub bodies: Vec<(String, String)>,
}

impl InstallScripts {
    pub fn runs_on_install(&self) -> bool {
        !self.names.is_empty()
    }
}

/// Why an artifact could not be read. A detector that cannot answer says so; it never
/// answers "nothing found".
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

/// The largest member this reads into memory. A `package.json` is kilobytes; anything
/// past this is not one, and decompressing it is what a bomb wants.
pub const MAX_MEMBER_BYTES: usize = 4 * 1024 * 1024;

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

    pub fn read(self, artifact: impl Read) -> Result<InstallScripts, ReadError> {
        match self {
            Self::NpmTarball => npm_install_scripts(artifact),
            Self::Sdist => sdist_install_scripts(artifact),
        }
    }
}

/// npm's install lifecycle, in the order npm runs them.
const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// The scripts an npm tarball's own `package.json` declares.
///
/// [`Tier::Cheap`]: one gzip stream and one JSON object.
pub fn npm_install_scripts(tarball: impl Read) -> Result<InstallScripts, ReadError> {
    let manifest = member(tarball, |path| path.ends_with("package.json"))?;
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
pub fn sdist_install_scripts(sdist: impl Read) -> Result<InstallScripts, ReadError> {
    match member(sdist, |path| {
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
fn member(bytes: impl Read, wanted: impl Fn(&str) -> bool) -> Result<Vec<u8>, ReadError> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        if !wanted(&path) {
            continue;
        }
        let size = entry.size() as usize;
        if size > MAX_MEMBER_BYTES {
            return Err(ReadError::TooLarge {
                member: path,
                limit: MAX_MEMBER_BYTES,
            });
        }
        let mut out = Vec::with_capacity(size);
        // Bounded again while reading, because the size above is the archive's own claim.
        entry
            .take(MAX_MEMBER_BYTES as u64)
            .read_to_end(&mut out)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        return Ok(out);
    }
    Err(ReadError::NothingToRead)
}

/// What the artifact says against what the metadata claimed.
///
/// The record's answer comes from the document the client asked for, which on npm is the
/// abbreviated packument, where `hasInstallScript` is present only when true. A tarball
/// that declares one the packument did not is the case worth a line in the log: the
/// decision that was made on the metadata was made on a false claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The artifact and the metadata agree.
    Kept,
    /// The artifact runs scripts and the metadata did not say so.
    Undeclared,
    /// The metadata said so and the reader found none. Not a reason to drop the claim:
    /// npm runs `node-gyp rebuild` for a `binding.gyp` that `package.json` never names,
    /// and an sdist with no `setup.py` still runs its PEP 517 backend.
    Overstated,
}

impl Claim {
    pub fn of(found: &InstallScripts, claimed: bool, detail: DocumentDetail) -> Self {
        match (found.runs_on_install(), claimed) {
            (true, false) => Self::Undeclared,
            // An abbreviated packument omits the key rather than writing `false`, so a
            // version whose record came from one and says nothing is not overstating.
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
mod tests {
    use super::*;
    use crate::util::test_support::tarball;

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
            Reader::Sdist.read(&sdist[..]).expect("reads").names,
            ["setup.py"]
        );
    }

    /// `bufferutil` 4.1.0 declares `install: node-gyp-build`, which is what its packument's
    /// `hasInstallScript` reports. Read from the real tarball on 2026-09-21.
    #[test]
    fn an_npm_tarball_reports_the_install_scripts_it_declares() {
        let manifest = br#"{"name":"bufferutil","version":"4.1.0","scripts":{
            "install":"node-gyp-build","prebuild":"prebuildify --napi","test":"mocha"}}"#;
        let found = npm_install_scripts(&*tarball(&[("package/package.json", manifest)]))
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
        let found = npm_install_scripts(&*tarball(&[("package/package.json", manifest)]))
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
            let found = npm_install_scripts(&*tarball(&[("package/package.json", manifest)]))
                .expect("the tarball reads");
            assert!(!found.runs_on_install(), "{found:?}");
        }
    }

    /// An archive with no manifest is not a package that runs nothing: it is one this
    /// cannot answer for.
    #[test]
    fn an_archive_with_no_manifest_is_an_error() {
        let empty = tarball(&[("package/index.js", b"module.exports = 1;")]);
        assert_eq!(npm_install_scripts(&*empty), Err(ReadError::NothingToRead));
        assert!(matches!(
            npm_install_scripts(&b"not a gzip stream"[..]),
            Err(ReadError::NotAnArchive(_))
        ));
        let manifest = tarball(&[("package/package.json", b"{ not json")]);
        assert!(matches!(
            npm_install_scripts(&*manifest),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// A member past the ceiling is refused rather than read into memory.
    #[test]
    fn a_member_past_the_ceiling_is_refused() {
        let big = vec![b' '; MAX_MEMBER_BYTES + 1];
        let archive = tarball(&[("package/package.json", &big)]);
        assert_eq!(
            npm_install_scripts(&*archive),
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
        let found = sdist_install_scripts(&*with).expect("the sdist reads");
        assert_eq!(found.names, ["setup.py"]);

        let without = tarball(&[
            ("idna-3.10/PKG-INFO", b"Name: idna"),
            ("idna-3.10/pyproject.toml", b"[build-system]"),
            // Not the sdist's own build: a file that happens to be called setup.py deeper
            // in the tree is a test fixture or a vendored package.
            ("idna-3.10/tests/data/setup.py", b"setup()"),
        ]);
        assert!(
            !sdist_install_scripts(&*without)
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
            // Trailing whitespace is still the same JSON document.
            bytes.resize(MAX_MEMBER_BYTES, b' ');
            bytes
        };
        let found = npm_install_scripts(&*tarball(&[("package/package.json", &padded)]))
            .expect("a member at the ceiling is read whole");
        assert_eq!(found.names, ["postinstall"]);

        let over = {
            let mut bytes = padded.clone();
            bytes.push(b' ');
            bytes
        };
        assert_eq!(
            npm_install_scripts(&*tarball(&[("package/package.json", &over)])),
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

    /// The real tarballs, read from registry.npmjs.org and pypi.org. The synthetic
    /// archives above hold the shapes; this holds that the shapes are the ones published.
    ///
    /// Ignored by default, and compiled out of coverage builds: `cargo test` must not
    /// depend on the network.
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

        // `hasInstallScript: true` in its packument, `install: node-gyp-build` inside.
        let bufferutil =
            fetch("https://registry.npmjs.org/bufferutil/-/bufferutil-4.1.0.tgz").await;
        let found = npm_install_scripts(&*bufferutil).expect("the tarball reads");
        assert_eq!(found.names, ["install"]);
        assert_eq!(found.bodies[0].1, "node-gyp-build");

        // No `hasInstallScript` and a `test` script only.
        let node_gyp_build =
            fetch("https://registry.npmjs.org/node-gyp-build/-/node-gyp-build-4.8.4.tgz").await;
        assert!(
            !npm_install_scripts(&*node_gyp_build)
                .expect("the tarball reads")
                .runs_on_install()
        );

        // An sdist with a setup.py at the root of its directory.
        let six = fetch(
            "https://files.pythonhosted.org/packages/94/e7/\
             b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz",
        )
        .await;
        assert_eq!(
            sdist_install_scripts(&*six).expect("the sdist reads").names,
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
            // An abbreviated packument writes `hasInstallScript` only when it is true, so
            // a record from one that claims none is not overstating anything.
            (&none, true, DocumentDetail::Abbreviated, Claim::Kept),
            (&none, true, DocumentDetail::Full, Claim::Overstated),
        ] {
            assert_eq!(Claim::of(found, claimed, detail), expected, "{found:?}");
        }
    }
}
