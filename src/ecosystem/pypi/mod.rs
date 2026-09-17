//! PyPI's simple index, read as PEP 691 JSON.
//!
//! Written concretely and on its own. The adapter interface is an **output** of this
//! stage, extracted from npm and PyPI once both work, so nothing here is shared with
//! `src/npm.rs` yet and nothing here should be made generic before that extraction.
//!
//! # How this differs from a packument, measured against `pypi.org` on 2026-09-16
//!
//! | | npm | PyPI |
//! |---|---|---|
//! | document | version-keyed, one entry per version | **file-keyed**: `requests` has 244 files for 160 versions |
//! | publish time | only in the full packument, 1.7x to 3.6x larger | `upload-time` per file, in the document pip already fetches |
//! | artifact host | `registry.npmjs.org` serves both | `files.pythonhosted.org`, not the index host |
//! | install script | `hasInstallScript` on the version | nothing; an sdist runs `setup.py` and a wheel does not |
//! | name | used as written | PEP 503 normalised, and the index 301s to the normalised form |
//! | per-version document | the packument is the only one | none under `/simple/`; PEP 658 gives per-**file** metadata at `<url>.metadata` |
//!
//! The first row is the one that matters: `PackageMetadata` is version-keyed, and a
//! PyPI project is not. Several files carry one version, and they are not interchangeable:
//! a wheel and an sdist for the same version differ in whether installing runs code.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;

use crate::identity::{Ecosystem, PackageKey};
use crate::record::{PackageMetadata, SkippedVersion};
use crate::route::RequestTarget;

/// What `waharoa` sends to ask for JSON rather than HTML. PEP 691.
pub const SIMPLE_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// The index this build reads.
pub const INDEX: &str = "https://pypi.org/simple";

/// Where PyPI serves the files its index names.
///
/// Not configurable and not derived from [`INDEX`]: the index gives each file's URL in
/// full, and a mirror serving the index still points at this host for files it does not
/// hold. Measured over nine projects on 2026-09-16, every one of 12,164 file URLs was on
/// this host.
pub const FILES: &str = "https://files.pythonhosted.org";

/// Bytes past which an index document is refused. `requests` was 123,104 bytes as JSON on
/// 2026-09-16, the largest of the eight measured; 32 MiB matches the npm packument ceiling.
pub const MAX_INDEX_BYTES: usize = 32 << 20;

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
    pub yanked: bool,
    pub requires_python: Option<String>,
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

#[derive(Debug)]
pub enum PypiError {
    /// The body is not a PEP 691 document.
    NotJson(serde_json::Error),
    /// A name that normalises to nothing, so no index path can be built for it.
    UnusableName(String),
    /// The document lists no file this build can read.
    NothingReadable { name: String, files: usize },
}

impl std::fmt::Display for PypiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(e) => write!(f, "the index is not readable: {e}"),
            Self::UnusableName(name) => write!(f, "`{name}` is not a usable project name"),
            Self::NothingReadable { name, files } => write!(
                f,
                "the index for `{name}` lists {files} files and none is readable"
            ),
        }
    }
}

impl std::error::Error for PypiError {}

/// A project name as PEP 503 normalises it: lowercased, with every run of `-`, `_` and `.`
/// replaced by a single `-`.
///
/// The index redirects to this form rather than serving the name as written: `Flask` 301s to
/// `flask`, `zope.interface` and `ruamel_yaml` to `zope-interface` and `ruamel-yaml`, all
/// measured 2026-09-16. Normalising here means the proxy asks for the name the index would
/// redirect to, so one project is one identity rather than one per spelling.
pub fn normalise(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            in_run = true;
            continue;
        }
        if in_run && !out.is_empty() {
            out.push('-');
        }
        in_run = false;
        out.extend(c.to_lowercase());
    }
    out
}

/// The index URL for `name`, normalised. PEP 503 requires the trailing slash.
pub fn index_url(base: &str, name: &str) -> Result<String, PypiError> {
    let normalised = normalise(name);
    if normalised.is_empty() {
        return Err(PypiError::UnusableName(name.to_owned()));
    }
    Ok(format!("{}/{normalised}/", base.trim_end_matches('/')))
}

/// What a distribution filename says: the project it belongs to, its version, and what
/// kind of file it is.
///
/// A wheel is PEP 427 `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`, so the
/// name and version are the first two of at least five fields. An sdist is
/// `{name}-{version}` with an archive extension, where the name may itself contain `-`, so
/// the version is what follows the last `-`. `None` for anything else, including the eggs
/// and `.exe` installers old projects still list.
///
/// The name comes back as [`normalise`] gives it. A wheel writes `-` in the project name
/// as `_`, so `zope-interface` reaches the filename as `zope_interface`, and the two spell
/// one project.
fn filename_parts(filename: &str) -> Option<(String, String, Kind)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let fields: Vec<&str> = stem.split('-').collect();
        // name, version, then python, abi and platform, with an optional build tag between.
        if fields.len() < 5 {
            return None;
        }
        if fields[0].is_empty() {
            return None;
        }
        return Some((normalise(fields[0]), fields[1].to_owned(), Kind::Wheel));
    }
    for extension in [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"] {
        if let Some(stem) = filename.strip_suffix(extension) {
            let (name, version) = stem.rsplit_once('-')?;
            if version.is_empty() || name.is_empty() {
                return None;
            }
            return Some((normalise(name), version.to_owned(), Kind::Sdist));
        }
    }
    None
}

/// The path prefixes this proxy answers as PyPI.
///
/// PEP 503 puts a project's index under `/simple/`. `/packages/` is where PyPI serves its
/// files, and the proxy keeps that path so a rewritten file URL round-trips: the hash
/// segments the index published are what locate the file upstream.
/// Which metadata document a body with this `Content-Type` is.
///
/// PyPI's row of [`crate::ecosystem::TABLE`] reads media types through this. Only PEP 691
/// JSON is read; an index that answers HTML is forwarded unchanged.
pub fn document_from_content_type(
    content_type: Option<&str>,
) -> Option<crate::route::DocumentKind> {
    (crate::route::media_type(content_type)? == SIMPLE_JSON)
        .then_some(crate::route::DocumentKind::SimpleIndex)
}

pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');

    if let Some(rest) = path.strip_prefix("simple/") {
        let name = rest.trim_end_matches('/');
        // `/simple/` itself is the root index: every project PyPI serves, not one of them.
        if name.is_empty() || name.contains('/') {
            return RequestTarget::Other;
        }
        let normalised = normalise(name);
        if normalised.is_empty() {
            return RequestTarget::Other;
        }
        return match PackageKey::from_registry_name(Ecosystem::PyPI, &normalised) {
            Ok(key) => RequestTarget::Metadata(key),
            Err(_) => RequestTarget::Other,
        };
    }

    let Some(rest) = path.strip_prefix("packages/") else {
        return RequestTarget::Other;
    };
    let Some(filename) = rest.rsplit('/').next().filter(|f| !f.is_empty()) else {
        return RequestTarget::Other;
    };
    let Some((name, version, _)) = filename_parts(filename) else {
        return RequestTarget::Other;
    };
    match PackageKey::from_registry_name(Ecosystem::PyPI, &name) {
        Ok(key) => RequestTarget::Artifact {
            key,
            claimed_version: version,
            filename: filename.to_owned(),
        },
        Err(_) => RequestTarget::Other,
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
    /// PEP 592: `false`, or a string giving the reason. Either way it is yanked when it is
    /// not `false`.
    #[serde(default)]
    yanked: serde_json::Value,
    #[serde(default, rename = "requires-python")]
    requires_python: Option<String>,
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
                yanked: !matches!(entry.yanked, serde_json::Value::Bool(false)),
                requires_python: entry.requires_python,
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

/// The file a resolver would take for a version, and what installing it runs.
///
/// A wheel is preferred because a resolver that can take one will: it installs without
/// running the package's own code. `None` when the index lists no file for that version.
impl Project {
    fn preferred(&self, version: &str) -> Option<&File> {
        let files = self.files_for(version);
        files
            .iter()
            .find(|f| f.kind == Kind::Wheel)
            .or_else(|| files.first())
            .copied()
    }
}

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

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Fetches project indexes from one simple index.
///
/// Deliberately the same shape as `npm::Client` (an `http`, a base, a byte ceiling) and
/// deliberately not sharing code with it. Stage 3 extracts the transport interface from
/// the two once both work, and two concrete implementations side by side are what that
/// extraction reads.
///
/// Where they differ is the useful part:
///
/// | | `npm::Client` | this |
/// |---|---|---|
/// | content negotiation | `Accept` picks abbreviated or full | `Accept` picks JSON over HTML, and an index may refuse |
/// | redirects | the registry serves the name as given | PEP 503 301s to the normalised name, and `normalise` avoids the round trip |
/// | encoding | asks for gzip and decodes it here | the same, for the same reason |
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    index: String,
    max_bytes: usize,
}

#[derive(Debug)]
pub enum FetchError {
    /// The request never completed: DNS, TLS, connection, timeout.
    Transport(reqwest::Error),
    /// The index answered, with something other than success.
    Status(reqwest::StatusCode),
    /// The body arrived and could not be decoded.
    Undecodable(crate::http::DecodeError),
    /// The index served something other than PEP 691 JSON. Its own HTML is the likely
    /// answer, which this build does not read.
    NotJson(Option<String>),
    /// The name or the body was unusable. Carries [`PypiError`] rather than restating it.
    Unreadable(PypiError),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "index request failed: {e}"),
            Self::Status(s) => write!(f, "index answered {s}"),
            Self::Undecodable(e) => write!(f, "index body could not be decoded: {e}"),
            Self::NotJson(got) => write!(
                f,
                "the index served `{}` rather than PEP 691 JSON",
                got.as_deref().unwrap_or("no content type")
            ),
            Self::Unreadable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl Client {
    /// `index` is a base URL such as `https://pypi.org/simple`. A trailing slash is
    /// accepted and trimmed.
    pub fn new(http: reqwest::Client, index: impl Into<String>) -> Self {
        let index = index.into();
        Self {
            http,
            index: index.trim_end_matches('/').to_owned(),
            max_bytes: MAX_INDEX_BYTES,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Fetch one project's index and read it.
    ///
    /// The name is normalised before the request rather than after a redirect: PEP 503
    /// says the index redirects a non-normalised name, so asking for the normalised one
    /// saves the round trip and makes one project one request whatever the client spelled.
    ///
    /// An index that answers with HTML is an error rather than a silent empty project.
    /// PyPI serves JSON when asked; another index may not, and reading its HTML is a
    /// separate piece of work that has not been done.
    pub async fn project(&self, name: &str) -> Result<Project, FetchError> {
        let url = index_url(&self.index, name).map_err(FetchError::Unreadable)?;
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, SIMPLE_JSON)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(FetchError::Transport)?;

        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // PEP 691 names the type exactly. A plain `application/json` is accepted too: an
        // index may serve the right document under the generic type.
        let json = content_type
            .as_deref()
            .is_some_and(|t| t.starts_with(SIMPLE_JSON) || t.starts_with("application/json"));
        if !json {
            return Err(FetchError::NotJson(content_type));
        }
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await.map_err(FetchError::Transport)?;
        let decoded = crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes)
            .map_err(FetchError::Undecodable)?;
        parse(name, &decoded).map_err(FetchError::Unreadable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/pypi/requests.json",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).expect("the fixture is present")
    }

    /// Measured against the live index 2026-09-16: each 301s to the right-hand form.
    #[test]
    fn a_name_normalises_the_way_the_index_redirects_it() {
        for (given, normalised) in [
            ("Flask", "flask"),
            ("zope.interface", "zope-interface"),
            ("ruamel_yaml", "ruamel-yaml"),
            ("ruamel.yaml", "ruamel-yaml"),
            // A run of separators collapses to one.
            ("a---b", "a-b"),
            ("A_-.B", "a-b"),
            ("already-normal", "already-normal"),
        ] {
            assert_eq!(normalise(given), normalised, "{given}");
        }
        // Normalising is idempotent, so asking twice cannot drift.
        for name in ["Flask", "zope.interface", "a---b"] {
            assert_eq!(normalise(&normalise(name)), normalise(name), "{name}");
        }
    }

    #[test]
    fn an_index_url_normalises_its_name_and_keeps_pep_503s_trailing_slash() {
        assert_eq!(
            index_url(INDEX, "Zope.Interface").expect("usable"),
            "https://pypi.org/simple/zope-interface/"
        );
        // A trailing slash on the base does not double up.
        assert_eq!(
            index_url("https://pypi.org/simple/", "flask").expect("usable"),
            "https://pypi.org/simple/flask/"
        );
        // A name of nothing but separators normalises away, so no path can be built.
        let error = index_url(INDEX, "...").expect_err("not a usable name");
        assert!(matches!(error, PypiError::UnusableName(_)), "{error}");
    }

    #[test]
    fn a_wheel_and_an_sdist_give_their_version_and_what_installing_them_runs() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert_eq!(project.name, "requests");
        assert_eq!(project.versions(), ["0.2.0", "2.32.0", "2.34.2"]);

        let sdist = &project.files_for("0.2.0")[0];
        assert_eq!(sdist.kind, Kind::Sdist);
        assert_eq!(
            sdist.sha256.as_deref(),
            Some("813202ace4d9301a3c00740c700e012fb9f3f8c73ddcfe02ab558a8df6f175fd")
        );
        assert_eq!(sdist.requires_python, None);

        let wheel = &project.files_for("2.34.2")[0];
        assert_eq!(wheel.kind, Kind::Wheel);
        assert_eq!(wheel.requires_python.as_deref(), Some(">=3.10"));
        // The artifact is on another host than the index, which a certificate covering only
        // the index host would miss. See enforcement-tiers.md.
        assert!(
            wheel.url.starts_with("https://files.pythonhosted.org/"),
            "{}",
            wheel.url
        );
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

    /// PEP 592 writes `false` or a string giving the reason, so `yanked` is read as "not
    /// `false`" rather than as a boolean.
    #[test]
    fn a_file_yanked_with_a_reason_is_yanked() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        let yanked = &project.files_for("2.32.0")[0];
        assert!(yanked.yanked, "a reason string is a yank");
        assert!(!project.files_for("2.34.2")[0].yanked, "`false` is not");
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

    mod transport {
        use super::*;
        use axum::Router;
        use axum::http::{StatusCode, header};
        use axum::routing::get;

        /// Serve fixed responses on an ephemeral port and return the base URL. The same
        /// shape `npm`'s transport tests use.
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

        fn client(base: &str) -> Client {
            Client::new(reqwest::Client::new(), base)
        }

        /// The whole path: the normalised name in the URL, the `Accept` header, the body,
        /// the records. The handler asserts the header, because an index that is not asked
        /// for JSON answers HTML and the parse would then fail for the wrong reason.
        #[tokio::test]
        async fn asks_for_json_under_the_normalised_name_and_reads_the_index() {
            let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
            let base = serve(Router::new().route(
                // `Zope.Interface` normalises to this before the request is made, so no
                // redirect is involved.
                "/zope-interface/",
                get(|headers: axum::http::HeaderMap| async move {
                    assert_eq!(
                        headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()),
                        Some(SIMPLE_JSON),
                        "an index not asked for JSON answers HTML"
                    );
                    ([(header::CONTENT_TYPE, SIMPLE_JSON)], body)
                }),
            ))
            .await;

            let project = client(&base)
                .project("Zope.Interface")
                .await
                .expect("the index reads");
            // The document names itself `requests`, and the document wins: it is what the
            // index says this project is.
            assert_eq!(project.name, "requests");
            assert_eq!(project.versions().len(), 3);
        }

        /// An index serving its own HTML is an error rather than an empty project. PyPI
        /// serves JSON when asked; another index may not.
        #[tokio::test]
        async fn html_is_refused_rather_than_read_as_no_versions() {
            let base = serve(Router::new().route(
                "/x/",
                get(|| async { ([(header::CONTENT_TYPE, "text/html")], "<html></html>") }),
            ))
            .await;
            let error = client(&base).project("x").await.expect_err("not JSON");
            assert!(
                matches!(&error, FetchError::NotJson(Some(t)) if t.starts_with("text/html")),
                "{error}"
            );
        }

        /// An index may serve the right document under the generic type.
        #[tokio::test]
        async fn a_generic_json_content_type_is_accepted() {
            let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
            let base = serve(Router::new().route(
                "/requests/",
                get(|| async { ([(header::CONTENT_TYPE, "application/json")], body) }),
            ))
            .await;
            assert!(client(&base).project("requests").await.is_ok());
        }

        #[tokio::test]
        async fn a_project_the_index_does_not_have_is_its_status() {
            let base = serve(Router::new().route(
                "/missing/",
                get(|| async { (StatusCode::NOT_FOUND, "no such project") }),
            ))
            .await;
            let error = client(&base).project("missing").await.expect_err("404");
            assert!(
                matches!(error, FetchError::Status(StatusCode::NOT_FOUND)),
                "{error}"
            );
        }

        #[tokio::test]
        async fn a_body_past_the_ceiling_is_refused() {
            let body = String::from_utf8(fixture()).expect("the fixture is utf-8");
            let base = serve(Router::new().route(
                "/requests/",
                get(|| async { ([(header::CONTENT_TYPE, SIMPLE_JSON)], body) }),
            ))
            .await;
            let error = client(&base)
                .with_max_bytes(16)
                .project("requests")
                .await
                .expect_err("over the ceiling");
            assert!(matches!(error, FetchError::Undecodable(_)), "{error}");
        }

        #[tokio::test]
        async fn an_index_that_is_not_there_is_a_transport_error() {
            // Bound and dropped, so the port refuses rather than answering.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds");
            let addr = listener.local_addr().expect("has an address");
            drop(listener);
            let error = client(&format!("http://{addr}"))
                .project("x")
                .await
                .expect_err("nothing is listening");
            assert!(matches!(error, FetchError::Transport(_)), "{error}");
        }

        #[tokio::test]
        async fn a_name_that_normalises_to_nothing_never_reaches_the_network() {
            let error = client("http://127.0.0.1:1")
                .project("...")
                .await
                .expect_err("not a usable name");
            assert!(
                matches!(error, FetchError::Unreadable(PypiError::UnusableName(_))),
                "{error}"
            );
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn the_ceiling_matches_the_packument_ceiling() {
        assert_eq!(MAX_INDEX_BYTES, 33_554_432);
        assert_eq!(Kind::Wheel.as_str(), "wheel");
        assert_eq!(Kind::Sdist.as_str(), "sdist");
    }

    mod paths {
        use super::*;

        fn key(name: &str) -> PackageKey {
            PackageKey::from_registry_name(Ecosystem::PyPI, name).expect("valid name")
        }

        #[test]
        fn a_simple_index_path_is_the_projects_metadata() {
            assert_eq!(
                classify_path("/simple/requests/"),
                RequestTarget::Metadata(key("requests"))
            );
            assert_eq!(
                classify_path("/simple/requests"),
                RequestTarget::Metadata(key("requests")),
                "pip sends the trailing slash; a client that omits it names the same page"
            );
        }

        /// PEP 503 asks for the normalised name, and pip sends whichever spelling the
        /// requirement used. `Zope.Interface`, `zope_interface` and `zope-interface` are
        /// one project, so they are one key.
        #[test]
        fn the_index_name_is_normalised_into_the_key() {
            for spelling in ["Zope.Interface", "zope_interface", "ZOPE--INTERFACE"] {
                assert_eq!(
                    classify_path(&format!("/simple/{spelling}/")),
                    RequestTarget::Metadata(key("zope-interface")),
                    "{spelling}"
                );
            }
        }

        #[test]
        fn a_packages_path_is_the_file_it_names() {
            assert_eq!(
                classify_path(
                    "/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfe6f7/\
                     requests-2.32.3-py3-none-any.whl"
                ),
                RequestTarget::Artifact {
                    key: key("requests"),
                    claimed_version: "2.32.3".into(),
                    filename: "requests-2.32.3-py3-none-any.whl".into(),
                }
            );
            assert_eq!(
                classify_path("/packages/source/z/zope-interface/zope.interface-5.4.0.tar.gz"),
                RequestTarget::Artifact {
                    key: key("zope-interface"),
                    claimed_version: "5.4.0".into(),
                    filename: "zope.interface-5.4.0.tar.gz".into(),
                }
            );
        }

        /// One version lists several files, each with its own digest, so the filename is
        /// what separates them. npm has no path that does this.
        #[test]
        fn two_files_of_one_version_differ_only_in_the_filename() {
            let wheel = classify_path("/packages/a/b/c/requests-2.32.3-py3-none-any.whl");
            let sdist = classify_path("/packages/a/b/c/requests-2.32.3.tar.gz");
            assert_ne!(wheel, sdist);
            let (
                RequestTarget::Artifact {
                    key: w,
                    claimed_version: wv,
                    ..
                },
                RequestTarget::Artifact {
                    key: s,
                    claimed_version: sv,
                    ..
                },
            ) = (&wheel, &sdist)
            else {
                panic!("both are artifacts");
            };
            assert_eq!(w, s);
            assert_eq!(wv, sv);
        }

        #[test]
        fn a_query_string_is_not_part_of_the_path() {
            assert_eq!(
                classify_path("/simple/requests/?foo=1"),
                RequestTarget::Metadata(key("requests"))
            );
        }

        #[test]
        fn anything_that_names_no_project_is_other() {
            for path in [
                "",
                "/",
                "/simple/",
                "/simple",
                "/simple/a/b/",
                "/simple/./",
                "/packages/",
                "/packages/a/b/c/",
                "/packages/a/b/c/notadistribution.txt",
                "/packages/a/b/c/x-py3-none-any.whl",
                "/packages/a/b/c/-1.0.tar.gz",
                "/pypi/requests/json",
            ] {
                assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
            }
        }
    }
}
