//! What an artifact's own bytes say, as opposed to what its metadata claims.
//!
//! See docs/engineering_decisions/0062-install-scripts-from-the-artifact.md and
//! docs/engineering_decisions/0064-artifact-spool.md.

pub mod attestation;
pub mod decision;
pub mod detector;
pub mod postgres;
pub mod run;
pub mod source;
pub mod store;
pub mod virustotal;

use std::io::Read;

use crate::identity::Ecosystem;
use crate::record::DocumentDetail;

/// The lifecycle scripts an artifact declares, read from the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallScripts {
    /// What runs on install: npm's scripts, an sdist's `setup.py`, a jar's processor file.
    pub names: Vec<String>,
    /// Each name's command, or a jar's processor classes. Empty for an sdist.
    pub bodies: Vec<(String, String)>,
    /// What in a tarball's shape no packer writes, in the order it was found.
    pub anomalies: Vec<Anomaly>,
}

impl InstallScripts {
    pub fn runs_on_install(&self) -> bool {
        !self.names.is_empty()
    }
}

/// A tarball shape no packer writes and extractors read differently: see decision 0122.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// This many gzip members. npm and pip decode every one; cargo, the first.
    GzipMembers(u32),
    /// Bytes after the last gzip member that do not start another.
    AfterGzip,
    /// Entries or bytes after a zero block, which node-tar reads past and `tarfile` does not.
    AfterEnd,
    /// A second entry at this path as npm extracts it, which keeps the last.
    Duplicate(String),
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GzipMembers(count) => write!(f, "{count} gzip members"),
            Self::AfterGzip => f.write_str("bytes after the last gzip member"),
            Self::AfterEnd => f.write_str("entries or bytes after the end-of-archive block"),
            Self::Duplicate(path) => write!(f, "two entries extract to `{path}`"),
        }
    }
}

impl Anomaly {
    /// The form a store keeps it in, which [`Anomaly::parse`] reads back.
    pub fn code(&self) -> String {
        match self {
            Self::GzipMembers(count) => format!("gzip_members:{count}"),
            Self::AfterGzip => "after_gzip".to_owned(),
            Self::AfterEnd => "after_end".to_owned(),
            Self::Duplicate(path) => format!("duplicate:{path}"),
        }
    }

    /// The anomaly [`Anomaly::code`] wrote, `None` for text it does not write.
    pub fn parse(code: &str) -> Option<Self> {
        match code.split_once(':') {
            None if code == "after_gzip" => Some(Self::AfterGzip),
            None if code == "after_end" => Some(Self::AfterEnd),
            Some(("gzip_members", count)) => count.parse().ok().map(Self::GzipMembers),
            Some(("duplicate", path)) => Some(Self::Duplicate(path.to_owned())),
            _ => None,
        }
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
    /// An archive of more members than `limit`.
    TooMany { limit: usize },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArchive(why) => write!(f, "not readable as an archive: {why}"),
            Self::NothingToRead => write!(f, "the archive holds no manifest to read"),
            Self::TooLarge { member, limit } => {
                write!(f, "`{member}` is larger than the {limit}-byte ceiling")
            }
            Self::TooMany { limit } => write!(f, "the archive holds more than {limit} members"),
        }
    }
}

/// The largest member this reads into memory, far past any `package.json`.
pub const MAX_MEMBER_BYTES: usize = 4 * 1024 * 1024;

/// The most a tarball may decompress to before it is refused as a bomb.
pub const MAX_UNPACKED_BYTES: usize = 4 << 30;

/// The readers' version, stored with each analysis; bumped whenever a reader's answer changes.
pub const READER: &str = "install-scripts 7";

/// What reads an artifact for the code it runs on install, such as [`npm_install_scripts`].
pub type Reader = fn(&mut dyn crate::ecosystem::Source) -> Result<InstallScripts, ReadError>;

/// The services file naming the annotation processors javac runs from a jar it is given.
pub const PROCESSOR_SERVICES: &str = "META-INF/services/javax.annotation.processing.Processor";

/// The annotation processors a jar declares: javac runs each one it finds on the class or
/// processor path while it compiles. Read from the central directory, which javac's
/// `ZipFile` reads, so an entry a stream reader would not see is found. The services file at
/// the root, or a multi-release jar's under `META-INF/versions/`, is read.
pub fn jar_annotation_processors(
    jar: &mut dyn crate::ecosystem::Source,
) -> Result<InstallScripts, ReadError> {
    let mut archive =
        zip::ZipArchive::new(jar).map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
    let mut found = InstallScripts::default();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        let path = crate::util::zip_name(&entry);
        let versioned = path
            .strip_prefix("META-INF/versions/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(_, rest)| rest == PROCESSOR_SERVICES);
        if path != PROCESSOR_SERVICES && !versioned {
            continue;
        }
        if entry.size() as usize > MAX_MEMBER_BYTES {
            return Err(ReadError::TooLarge {
                member: path,
                limit: MAX_MEMBER_BYTES,
            });
        }
        let mut text = Vec::new();
        entry
            .read_to_end(&mut text)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
        let classes: Vec<&str> = std::str::from_utf8(&text)
            .map_err(|e| ReadError::NotAnArchive(e.to_string()))?
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().trim())
            .filter(|class| !class.is_empty())
            .collect();
        if !classes.is_empty() {
            found.bodies.push((path.clone(), classes.join(" ")));
            found.names.push(path);
        }
    }
    Ok(found)
}

/// The reader for `filename` in `ecosystem`, from its row's [`crate::ecosystem::Registry::reader`].
pub fn reader(ecosystem: Ecosystem, filename: &str) -> Option<Reader> {
    (crate::ecosystem::of(ecosystem).reader)(filename)
}

/// npm's install lifecycle, in the order npm runs them.
pub const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// The scripts an npm tarball's `package.json` declares, and `install: node-gyp rebuild`
/// where npm adds it. A tarball with two `package.json`, which an extractor would keep the
/// last of, declares the scripts of both.
///
/// One gzip stream and one JSON object: 0.4ms for `bufferutil` 4.1.0, 163,631 bytes.
pub fn npm_install_scripts(tarball: &mut dyn Read) -> Result<InstallScripts, ReadError> {
    let (mut found, mut binding_gyp, mut gyp) = (None::<InstallScripts>, false, false);
    let anomalies = walk(tarball, &mut |path, member| {
        match installed(path).as_deref() {
            Some(NODE_GYP_FILE) => binding_gyp |= !member.directory,
            Some("package.json") => {
                let manifest: serde_json::Value =
                    serde_json::from_slice(&read_member(path, member)?)
                        .map_err(|e| ReadError::NotAnArchive(e.to_string()))?;
                gyp |= npm_runs_node_gyp(&manifest);
                let found = found.get_or_insert_default();
                let Some(scripts) = manifest.get("scripts").and_then(|s| s.as_object()) else {
                    return Ok(());
                };
                for name in NPM_INSTALL_SCRIPTS {
                    if let Some(body) = scripts.get(name).and_then(|b| b.as_str())
                        && !found.names.iter().any(|known| known == name)
                    {
                        found.names.push(name.to_owned());
                        found.bodies.push((name.to_owned(), body.to_owned()));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    let mut found = found.ok_or(ReadError::NothingToRead)?;
    if binding_gyp && gyp && !found.names.iter().any(|name| name == "install") {
        found.names.push("install".to_owned());
        found
            .bodies
            .push(("install".to_owned(), NODE_GYP_INSTALL.to_owned()));
    }
    let lifecycle = |name: &String| NPM_INSTALL_SCRIPTS.iter().position(|step| step == name);
    found.names.sort_by_key(lifecycle);
    found.bodies.sort_by_key(|(name, _)| lifecycle(name));
    found.anomalies = anomalies;
    Ok(found)
}

/// The file at a package's root that makes npm build it with node-gyp.
pub const NODE_GYP_FILE: &str = "binding.gyp";

/// The `install` script npm runs for a package with a [`NODE_GYP_FILE`] and none of its own.
pub const NODE_GYP_INSTALL: &str = "node-gyp rebuild";

/// Whether npm runs [`NODE_GYP_INSTALL`] for `manifest`, given a [`NODE_GYP_FILE`]: its
/// `scripts` have no `install` or `preinstall` npm reads as true, and `gypfile` is not `false`.
fn npm_runs_node_gyp(manifest: &serde_json::Value) -> bool {
    let truthy = |value: Option<&serde_json::Value>| match value {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(set)) => *set,
        Some(serde_json::Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(serde_json::Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    };
    let scripts = manifest.get("scripts");
    let script = |name: &str| truthy(scripts.and_then(|s| s.get(name)));
    !script("install")
        && !script("preinstall")
        && manifest.get("gypfile") != Some(&serde_json::Value::Bool(false))
}

/// Whether a PyPI sdist carries a `setup.py`, which pip runs to build it.
///
/// A wheel runs nothing, so this is asked of an sdist only. `pyproject.toml` alone is not
/// this: a PEP 517 build runs the backend it names, which is its own question.
pub fn sdist_install_scripts(sdist: &mut dyn Read) -> Result<InstallScripts, ReadError> {
    let mut setup_py = false;
    let anomalies = walk(sdist, &mut |path, _| {
        let parts = components(path);
        setup_py |= parts.len() <= 2 && parts.last() == Some(&"setup.py");
        Ok(())
    })?;
    Ok(InstallScripts {
        names: setup_py
            .then(|| "setup.py".to_owned())
            .into_iter()
            .collect(),
        bodies: Vec::new(),
        anomalies,
    })
}

/// What one `Cargo.toml` says of a build script.
enum Build {
    /// `build = "path"`.
    Named(String),
    /// `build = false`.
    Off,
    /// `build = true`, or no `build`: `build.rs`, if it exists.
    Default,
}

/// The code a `.crate` runs when it is built: its build script and its proc-macro, read
/// from `<top>/Cargo.toml`. One naming no `build`, as libc 0.2.0's, has one if
/// `<top>/build.rs` exists. A crate with two `Cargo.toml` runs what either names.
pub fn crate_build_scripts(archive: &mut dyn Read) -> Result<InstallScripts, ReadError> {
    let (mut manifests, mut build_rs) = (Vec::new(), false);
    let anomalies = walk(archive, &mut |path, member| {
        match installed(path).as_deref() {
            Some("build.rs") => build_rs = true,
            Some("Cargo.toml") => {
                let manifest: toml::Table = std::str::from_utf8(&read_member(path, member)?)
                    .map_err(|e| ReadError::NotAnArchive(e.to_string()))?
                    .parse()
                    .map_err(|e: toml::de::Error| ReadError::NotAnArchive(e.to_string()))?;
                let build = match manifest.get("package").and_then(|p| p.get("build")) {
                    Some(toml::Value::String(script)) => Build::Named(script.clone()),
                    Some(toml::Value::Boolean(true)) | None => Build::Default,
                    _ => Build::Off,
                };
                let lib = manifest.get("lib");
                let lib_key = |key: &&str| lib.and_then(|l| l.get(*key));
                let proc_macro = ["proc-macro", "proc_macro"]
                    .iter()
                    .any(|key| lib_key(key).and_then(toml::Value::as_bool) == Some(true))
                    || ["crate-type", "crate_type"].iter().any(|key| {
                        lib_key(key)
                            .and_then(toml::Value::as_array)
                            .is_some_and(|types| {
                                types.iter().any(|t| t.as_str() == Some("proc-macro"))
                            })
                    });
                manifests.push((build, proc_macro));
            }
            _ => {}
        }
        Ok(())
    })?;
    if manifests.is_empty() {
        return Err(ReadError::NothingToRead);
    }
    let mut found = InstallScripts {
        anomalies,
        ..InstallScripts::default()
    };
    let mut add = |name: &str| {
        if !found.names.iter().any(|known| known == name) {
            found.names.push(name.to_owned());
        }
    };
    for (build, _) in &manifests {
        match build {
            Build::Named(script) => add(script),
            Build::Default if build_rs => add("build.rs"),
            _ => {}
        }
    }
    if manifests.iter().any(|(_, proc_macro)| *proc_macro) {
        add("proc-macro");
    }
    Ok(found)
}

/// `member`'s bytes, refused past [`MAX_MEMBER_BYTES`]. `path` names it in the error.
fn read_member(path: &str, member: Member<'_>) -> Result<Vec<u8>, ReadError> {
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
    Ok(out)
}

/// `path`'s components, with the empty and `.` ones an extractor skips dropped.
fn components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

/// Where npm extracts `path`: its components after the first, as `strip: 1` drops it.
/// `package/./package.json`, `package//package.json` and `other/package.json` are each
/// `package.json`. `None` for a path with no component after the first.
pub fn installed(path: &str) -> Option<String> {
    match components(path).split_first() {
        Some((_, rest)) if !rest.is_empty() => Some(rest.join("/")),
        _ => None,
    }
}

/// One member of a tar, as [`walk`] hands it over.
struct Member<'a> {
    /// Whether it is a regular file, not a directory or a link.
    file: bool,
    directory: bool,
    /// The size its header states.
    size: u64,
    bytes: &'a mut dyn Read,
}

/// Each member of a gzipped tar in order, with its path, as the extractor that reads the
/// most would read them: every gzip member, and entries past a single zero block.
/// Returns what in its shape no packer writes.
/// Errors when the bytes are not a gzipped tar, decompress past [`MAX_UNPACKED_BYTES`], or
/// with what `visit` errors with.
fn walk(
    bytes: &mut dyn Read,
    visit: &mut dyn FnMut(&str, Member<'_>) -> Result<(), ReadError>,
) -> Result<Vec<Anomaly>, ReadError> {
    walk_within(bytes, MAX_UNPACKED_BYTES, visit)
}

/// [`walk`], refusing a tarball that decompresses past `limit` bytes.
fn walk_within(
    bytes: &mut dyn Read,
    limit: usize,
    visit: &mut dyn FnMut(&str, Member<'_>) -> Result<(), ReadError>,
) -> Result<Vec<Anomaly>, ReadError> {
    let mut unpacked = Unpacked::new(bytes, limit);
    let mut paths = Paths::default();
    let mut archive = tar::Archive::new(&mut unpacked);
    let read = each_entry(&mut archive, visit, &mut paths);
    let unpacked = archive.into_inner();
    let failed = |unpacked: &mut Unpacked<'_>, e| unpacked.failed.take().unwrap_or(e);
    match read {
        Err(e) => return Err(failed(unpacked, e)),
        Ok((_, Some(e))) => return Err(failed(unpacked, ReadError::NotAnArchive(e.to_string()))),
        Ok((_, None)) => {}
    }
    let mut rest = tar::Archive::new(&mut *unpacked);
    rest.set_ignore_zeros(true);
    let read = each_entry(&mut rest, visit, &mut paths);
    if let Some(e) = unpacked.failed.take() {
        return Err(e);
    }
    let (after, stopped) = read?;
    let mut anomalies = Vec::new();
    if unpacked.members > 1 {
        anomalies.push(Anomaly::GzipMembers(unpacked.members));
    }
    if unpacked.after {
        anomalies.push(Anomaly::AfterGzip);
    }
    if after > 0 || stopped.is_some() {
        anomalies.push(Anomaly::AfterEnd);
    }
    anomalies.extend(paths.duplicates);
    Ok(anomalies)
}

/// The paths a walk has seen, as [`installed`] writes them, kept as hashes to bound memory.
#[derive(Default)]
struct Paths {
    hasher: std::hash::RandomState,
    seen: std::collections::HashSet<u64>,
    /// Each path seen twice, once, up to [`MAX_DUPLICATES_NAMED`].
    duplicates: Vec<Anomaly>,
}

/// The most [`Anomaly::Duplicate`] one walk reports.
const MAX_DUPLICATES_NAMED: usize = 8;

impl Paths {
    /// Note an entry at `path`, a [`Anomaly::Duplicate`] the second time it extracts there.
    fn note(&mut self, path: &str) {
        use std::hash::BuildHasher;
        let Some(installed) = installed(path) else {
            return;
        };
        if self.seen.insert(self.hasher.hash_one(&installed))
            || self.duplicates.len() >= MAX_DUPLICATES_NAMED
        {
            return;
        }
        let duplicate = Anomaly::Duplicate(installed);
        if !self.duplicates.contains(&duplicate) {
            self.duplicates.push(duplicate);
        }
    }
}

/// Hand each entry `archive` holds to `visit`, noting its path in `paths`, until the archive
/// ends or a header does not parse. Returns how many entries there were, and the error that
/// stopped it, if one did.
/// Errors with what `visit` errors with.
fn each_entry<R: Read>(
    archive: &mut tar::Archive<R>,
    visit: &mut dyn FnMut(&str, Member<'_>) -> Result<(), ReadError>,
    paths: &mut Paths,
) -> Result<(usize, Option<std::io::Error>), ReadError> {
    let mut count = 0;
    let entries = archive.entries().expect("a new archive is at its start");
    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(e) => return Ok((count, Some(e))),
        };
        count += 1;
        let path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let kind = entry.header().entry_type();
        if !kind.is_dir() {
            paths.note(&path);
        }
        let member = Member {
            file: kind.is_file(),
            directory: kind.is_dir(),
            size: entry.size(),
            bytes: &mut entry,
        };
        visit(&path, member)?;
    }
    Ok((count, None))
}

/// Every gzip member's bytes in turn, as npm and pip decode them, up to `limit` bytes.
struct Unpacked<'a> {
    /// The member being read, `None` once the last has ended.
    member: Option<flate2::bufread::GzDecoder<std::io::BufReader<&'a mut dyn Read>>>,
    members: u32,
    /// Whether bytes that do not start a member followed the last.
    after: bool,
    read: usize,
    limit: usize,
    /// Why a read failed, which the tar reading it reports only as text.
    failed: Option<ReadError>,
}

impl<'a> Unpacked<'a> {
    fn new(bytes: &'a mut dyn Read, limit: usize) -> Self {
        Self {
            member: Some(flate2::bufread::GzDecoder::new(std::io::BufReader::new(
                bytes,
            ))),
            members: 1,
            after: false,
            read: 0,
            limit,
            failed: None,
        }
    }

    /// The next bytes, or `Ok(0)` after the last member.
    fn next(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(member) = self.member.as_mut() else {
                return Ok(0);
            };
            let read = member.read(buf)?;
            if read > 0 || buf.is_empty() {
                return Ok(read);
            }
            let mut rest = self.member.take().expect("a member is open").into_inner();
            match std::io::BufRead::fill_buf(&mut rest)?.first() {
                None => return Ok(0),
                Some(0x1f) => {
                    self.members += 1;
                    self.member = Some(flate2::bufread::GzDecoder::new(rest));
                }
                Some(_) => {
                    self.after = true;
                    return Ok(0);
                }
            }
        }
    }
}

impl Read for Unpacked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.next(buf).inspect_err(|e| {
            self.failed = Some(ReadError::NotAnArchive(e.to_string()));
        })?;
        self.read += read;
        if self.read > self.limit {
            self.failed = Some(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit: self.limit,
            });
            return Err(std::io::Error::other("decompressed past the ceiling"));
        }
        Ok(read)
    }
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
        let krate = |files: &[(&str, &[u8])]| crate_build_scripts(&mut &*tarball(files));
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
            (
                "crate, build named",
                krate(&[("x-1/Cargo.toml", b"[package]\nbuild = \"src/gen.rs\"\n")]),
            ),
            (
                "crate, build.rs and no build key",
                krate(&[("x-1/Cargo.toml", b"[package]\n"), ("x-1/build.rs", b"")]),
            ),
            (
                "crate, build = true and build.rs",
                krate(&[("x-1/Cargo.toml", b"[package]\nbuild = true\n"), ("x-1/build.rs", b"")]),
            ),
            (
                "crate, build = false and build.rs",
                krate(&[("x-1/Cargo.toml", b"[package]\nbuild = false\n"), ("x-1/build.rs", b"")]),
            ),
            (
                "crate, build.rs only deeper",
                krate(&[("x-1/Cargo.toml", b"[package]\n"), ("x-1/src/build.rs", b"")]),
            ),
            (
                "crate, proc-macro",
                krate(&[("x-1/Cargo.toml", b"[package]\nbuild = false\n[lib]\nproc-macro = true\n")]),
            ),
            (
                "crate, proc_macro, the old spelling",
                krate(&[("x-1/Cargo.toml", b"[lib]\nproc_macro = true\n")]),
            ),
            (
                "crate, crate-type proc-macro",
                krate(&[("x-1/Cargo.toml", b"[lib]\ncrate-type = [\"proc-macro\"]\n")]),
            ),
            (
                "crate, neither",
                krate(&[("x-1/Cargo.toml", b"[package]\nbuild = false\n[lib]\n")]),
            ),
            ("crate, no Cargo.toml", krate(&[("x-1/src/lib.rs", b"")])),
            ("crate, Cargo.toml at the root", krate(&[("Cargo.toml", b"[package]\n")])),
            ("crate, Cargo.toml not UTF-8", krate(&[("x-1/Cargo.toml", b"\xff")])),
            ("crate, Cargo.toml not TOML", krate(&[("x-1/Cargo.toml", b"[package")])),
            ("crate, not gzip", crate_build_scripts(&mut &b"plain"[..])),
            (
                "sdist, setup.py in a second gzip member",
                sdist_install_scripts(
                    &mut &*[
                        crate::http::gzip(&crate::util::test_support::tar(&[("x-1.0/PKG-INFO", b"")], false)),
                        tarball(&[("x-1.0/setup.py", b"")]),
                    ]
                    .concat(),
                ),
            ),
            (
                "npm, binding.gyp and no install script",
                npm(&[("package/package.json", b"{}"), ("package/binding.gyp", b"{}")]),
            ),
            (
                "npm, binding.gyp with gypfile false",
                npm(&[
                    ("package/package.json", br#"{"gypfile":false}"#),
                    ("package/binding.gyp", b"{}"),
                ]),
            ),
            (
                "npm, two package.json",
                npm(&[
                    ("package/package.json", b"{}"),
                    ("package/./package.json", br#"{"scripts":{"install":"b"}}"#),
                ]),
            ),
        ];
        cases
            .into_iter()
            .map(|(case, answer)| match answer {
                Ok(found) if found.anomalies.is_empty() => format!(
                    "{case}: runs {:?}, bodies {:?}\n",
                    found.names, found.bodies
                ),
                Ok(found) => format!(
                    "{case}: runs {:?}, bodies {:?}, anomalies {:?}\n",
                    found.names, found.bodies, found.anomalies
                ),
                Err(e) => format!("{case}: error: {e}\n"),
            })
            .collect()
    }

    /// npm extracts every `<top>/package.json` to one path and keeps the last, so the
    /// scripts of every copy count, in lifecycle order, and the copy is an anomaly.
    #[test]
    fn every_package_json_npm_extracts_to_one_path_is_read() {
        for second in [
            "other/package.json",
            "package/./package.json",
            "package//package.json",
        ] {
            let archive = tarball(&[
                (
                    "package/package.json",
                    br#"{"scripts":{"postinstall":"x"}}"#,
                ),
                (
                    second,
                    br#"{"scripts":{"preinstall":"y","postinstall":"z"}}"#,
                ),
                ("package/package.json", b"{}"),
            ]);
            let found = npm_install_scripts(&mut &*archive).expect("reads");
            assert_eq!(found.names, ["preinstall", "postinstall"], "{second}");
            assert_eq!(
                found.bodies,
                [
                    ("preinstall".to_owned(), "y".to_owned()),
                    ("postinstall".to_owned(), "x".to_owned())
                ],
                "{second}"
            );
            assert_eq!(
                found.anomalies,
                [Anomaly::Duplicate("package.json".to_owned())],
                "{second}"
            );
        }
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
        let npm = reader(Ecosystem::Npm, "widget-1.0.0.tgz").expect("a tarball is read");
        let package = tarball(&[(
            "package/package.json",
            br#"{"scripts":{"postinstall":"x"}}"#,
        )]);
        assert_eq!(
            npm(&mut std::io::Cursor::new(&package[..]))
                .expect("reads")
                .names,
            ["postinstall"]
        );
        let sdist = reader(Ecosystem::PyPI, "six-1.17.0.tar.gz").expect("an sdist is read");
        let built = tarball(&[("six-1.17.0/setup.py", b"")]);
        assert_eq!(
            sdist(&mut std::io::Cursor::new(&built[..]))
                .expect("reads")
                .names,
            ["setup.py"]
        );
        assert!(reader(Ecosystem::PyPI, "six-1.17.0-py2.py3-none-any.whl").is_none());
        let krate = reader(Ecosystem::Cargo, "serde-1.0.229.crate").expect("a .crate is read");
        let built = tarball(&[(
            "serde-1.0.229/Cargo.toml",
            b"[package]\nbuild = \"build.rs\"\n",
        )]);
        assert_eq!(
            krate(&mut std::io::Cursor::new(&built[..]))
                .expect("reads")
                .names,
            ["build.rs"]
        );
        assert!(reader(Ecosystem::Cargo, "serde-1.0.229.tar.gz").is_none());
        let jar = reader(Ecosystem::Maven, "lombok-1.18.42.jar").expect("a jar is read");
        let built =
            crate::util::test_support::zip_of(&[(PROCESSOR_SERVICES, b"lombok.Processor\n")]);
        assert_eq!(
            jar(&mut std::io::Cursor::new(&built[..]))
                .expect("reads")
                .names,
            [PROCESSOR_SERVICES]
        );
        assert!(reader(Ecosystem::Maven, "lombok-1.18.42.pom").is_none());
    }

    fn processors(jar: &[u8]) -> Result<InstallScripts, ReadError> {
        jar_annotation_processors(&mut std::io::Cursor::new(jar))
    }

    /// Each class the services file names, comments and blank lines dropped, at the root
    /// or under a multi-release version; a file naming none, or elsewhere, runs nothing.
    #[test]
    fn a_jar_declaring_an_annotation_processor_has_install_scripts() {
        let found = processors(&crate::util::test_support::zip_of(&[
            ("lombok/Lombok.class", b"\xca\xfe"),
            (
                PROCESSOR_SERVICES,
                b"# processors\nlombok.launch.AnnotationProcessorHider$AnnotationProcessor\n\n\
                  lombok.launch.AnnotationProcessorHider$ClaimingProcessor # claims\n",
            ),
        ]))
        .unwrap();
        assert!(found.runs_on_install());
        assert_eq!(
            found.bodies,
            [(
                PROCESSOR_SERVICES.to_owned(),
                "lombok.launch.AnnotationProcessorHider$AnnotationProcessor \
                 lombok.launch.AnnotationProcessorHider$ClaimingProcessor"
                    .to_owned()
            )]
        );
        let versioned = format!("META-INF/versions/11/{PROCESSOR_SERVICES}");
        let found =
            processors(&crate::util::test_support::zip_of(&[(&versioned, b"a.B")])).unwrap();
        assert_eq!(found.names, [versioned]);
        for quiet in [
            crate::util::test_support::zip_of(&[(PROCESSOR_SERVICES, b"# none\n\n")]),
            crate::util::test_support::zip_of(&[(
                &format!("BOOT-INF/classes/{PROCESSOR_SERVICES}"),
                b"a.B",
            )]),
            crate::util::test_support::zip_of(&[("META-INF/versions/11", b"")]),
            crate::util::test_support::zip_of(&[("META-INF/services/java.sql.Driver", b"a.B")]),
            crate::util::test_support::zip_of(&[]),
        ] {
            assert_eq!(processors(&quiet).unwrap(), InstallScripts::default());
        }
    }

    /// Bytes before the first local header stop a reader walking local headers from the
    /// start; the central directory, which javac's `ZipFile` reads, still lists the entry.
    #[test]
    fn a_jar_is_read_from_its_central_directory() {
        let mut prefixed = b"#!/bin/sh\nexec java -jar \"$0\"\n".to_vec();
        prefixed.extend(crate::util::test_support::zip_of(&[(
            PROCESSOR_SERVICES,
            b"evil.Processor",
        )]));
        let mut stream = std::io::Cursor::new(&prefixed[..]);
        assert!(!matches!(
            zip::read::read_zipfile_from_stream(&mut stream),
            Ok(Some(_))
        ));
        assert_eq!(processors(&prefixed).unwrap().names, [PROCESSOR_SERVICES]);
    }

    /// An entry in a compression this build cannot read, whose bytes do not match its CRC,
    /// or whose local header is missing, is an error, as an archive that does not read is.
    #[test]
    fn a_jar_entry_that_cannot_be_read_is_an_error() {
        let built = crate::util::test_support::zip_of(&[(PROCESSOR_SERVICES, b"evil.Processor")]);
        let central = built
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("a central directory");
        let mut unsupported = built.clone();
        unsupported[central + 10..central + 12].copy_from_slice(&12u16.to_le_bytes());
        assert!(matches!(
            processors(&unsupported),
            Err(ReadError::NotAnArchive(_))
        ));
        let mut corrupt = built.clone();
        let at = corrupt
            .windows(4)
            .position(|w| w == b"evil")
            .expect("the entry's bytes");
        corrupt[at] = b'E';
        assert!(matches!(
            processors(&corrupt),
            Err(ReadError::NotAnArchive(_))
        ));
        let mut no_local_header = built.clone();
        no_local_header[3] = 0x05;
        assert!(matches!(
            processors(&no_local_header),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// Bytes that are not a zip, a services file over the ceiling or not UTF-8, are errors.
    #[test]
    fn a_jar_that_cannot_be_read_is_an_error() {
        assert!(matches!(
            processors(b"not a zip"),
            Err(ReadError::NotAnArchive(_))
        ));
        let at_ceiling = vec![b'a'; MAX_MEMBER_BYTES];
        assert!(
            processors(&crate::util::test_support::zip_of(&[(
                PROCESSOR_SERVICES,
                &at_ceiling
            )]))
            .is_ok()
        );
        let over = vec![b'a'; MAX_MEMBER_BYTES + 1];
        assert!(matches!(
            processors(&crate::util::test_support::zip_of(&[(
                PROCESSOR_SERVICES,
                &over
            )])),
            Err(ReadError::TooLarge { .. })
        ));
        assert!(matches!(
            processors(&crate::util::test_support::zip_of(&[(
                PROCESSOR_SERVICES,
                b"\xff\xfe"
            )])),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// Read from the published `.crate` files on 2026-10-14. libc 0.2.0's manifest names no
    /// `build`, and it has no `build.rs`.
    #[tokio::test]
    #[ignore = "downloads from static.crates.io"]
    async fn real_crates_declare_their_build_scripts_and_proc_macros() {
        for (name, version, expected) in [
            ("serde", "1.0.229", &["build.rs"][..]),
            ("serde_derive", "1.0.229", &["proc-macro"][..]),
            ("itoa", "1.0.18", &[][..]),
            ("libc", "0.2.0", &[][..]),
        ] {
            let url = format!("https://static.crates.io/crates/{name}/{version}/download");
            let bytes = reqwest::get(url).await.unwrap().bytes().await.unwrap();
            let found = crate_build_scripts(&mut &bytes[..]).expect("reads");
            assert_eq!(found.names, expected, "{name} {version}");
        }
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

    /// cargo 1.99.1 builds a proc-macro from either flag or either spelling of `crate-type`
    /// naming `proc-macro`, even beside `proc-macro = false`. rustc refuses another spelling.
    #[test]
    fn every_way_cargo_reads_a_proc_macro_is_one() {
        for (lib, proc_macro) in [
            ("proc-macro = true", true),
            ("proc_macro = true", true),
            ("crate-type = [\"proc-macro\"]", true),
            ("crate_type = [\"proc-macro\"]", true),
            ("proc-macro = false\ncrate-type = [\"proc-macro\"]", true),
            ("crate-type = [\"rlib\", \"proc-macro\"]", true),
            ("proc-macro = false", false),
            ("crate-type = [\"rlib\"]", false),
            ("crate-type = [\"proc_macro\"]", false),
            ("crate-type = \"proc-macro\"", false),
            ("crate-type = [1]", false),
        ] {
            let manifest = format!("[package]\nbuild = false\n[lib]\n{lib}\n");
            let found =
                crate_build_scripts(&mut &*tarball(&[("x-1/Cargo.toml", manifest.as_bytes())]))
                    .expect("reads");
            assert_eq!(found.names == ["proc-macro"], proc_macro, "{lib}");
        }
    }

    /// npm runs `node-gyp rebuild` on install for a package with a `binding.gyp` at its root
    /// and no `install` or `preinstall` it reads as true, unless `gypfile` is `false`.
    #[test]
    fn a_binding_gyp_is_npm_s_install_script() {
        let gyp = |manifest: &[u8], at: &str| {
            let found = npm_install_scripts(&mut &*tarball(&[
                ("package/package.json", manifest),
                (at, b"{}"),
            ]))
            .expect("reads");
            found
                .bodies
                .iter()
                .map(|(name, body)| format!("{name}: {body}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let root = "package/binding.gyp";
        for (manifest, at, expected) in [
            (&br#"{}"#[..], root, "install: node-gyp rebuild"),
            (br#"{"gypfile":false}"#, root, ""),
            (br#"{"gypfile":"false"}"#, root, "install: node-gyp rebuild"),
            (br#"{"scripts":{"install":"own"}}"#, root, "install: own"),
            (
                br#"{"scripts":{"preinstall":"pre"}}"#,
                root,
                "preinstall: pre",
            ),
            (
                br#"{"scripts":{"postinstall":"post"}}"#,
                root,
                "install: node-gyp rebuild, postinstall: post",
            ),
            (br#"{"scripts":{"install":""}}"#, root, "install: "),
            (
                br#"{"scripts":{"install":0}}"#,
                root,
                "install: node-gyp rebuild",
            ),
            (
                br#"{"scripts":{"install":null}}"#,
                root,
                "install: node-gyp rebuild",
            ),
            (
                br#"{"scripts":{"install":false}}"#,
                root,
                "install: node-gyp rebuild",
            ),
            (br#"{"scripts":{"install":1}}"#, root, ""),
            (br#"{"scripts":{"install":true}}"#, root, ""),
            (br#"{"scripts":{"install":{}}}"#, root, ""),
            (
                br#"{"scripts":"install"}"#,
                root,
                "install: node-gyp rebuild",
            ),
            (
                br#"{}"#,
                "package/./binding.gyp",
                "install: node-gyp rebuild",
            ),
            (br#"{}"#, "package/src/binding.gyp", ""),
        ] {
            let manifest = String::from_utf8_lossy(manifest);
            assert_eq!(
                gyp(manifest.as_bytes(), at),
                expected,
                "{manifest} with {at}"
            );
        }

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/binding.gyp/", &[][..])
            .expect("appends");
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &b"{}"[..])
            .expect("appends");
        let directory = gzip(&builder.into_inner().expect("builds"));
        assert!(
            !npm_install_scripts(&mut &*directory)
                .expect("reads")
                .runs_on_install()
        );

        for copies in [
            [&br#"{"gypfile":false}"#[..], b"{}"],
            [b"{}", br#"{"gypfile":false}"#],
        ] {
            let either = tarball(&[
                ("package/package.json", copies[0]),
                ("package/package.json", copies[1]),
                ("package/binding.gyp", b"{}"),
            ]);
            assert_eq!(
                npm_install_scripts(&mut &*either).expect("reads").names,
                ["install"],
                "a copy that does not turn it off, in either order"
            );
        }
        let hidden = [
            gzip(&tar(&[("package/package.json", b"{}")], false)),
            tarball(&[("package/binding.gyp", b"{}")]),
        ]
        .concat();
        assert_eq!(
            npm_install_scripts(&mut &*hidden).expect("reads").names,
            ["install"],
            "in a second gzip member"
        );
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

    /// A crate with two `Cargo.toml` runs what either names, and neither hides the other.
    #[test]
    fn every_cargo_toml_is_read() {
        let archive = tarball(&[
            ("x-1/Cargo.toml", b"[package]\nbuild = \"gen.rs\"\n"),
            (
                "x-1/./Cargo.toml",
                b"[package]\nbuild = false\n[lib]\nproc-macro = true\n",
            ),
            ("x-1/build.rs", b""),
            ("y/Cargo.toml", b"[package]\n"),
            ("y/Cargo.toml", b"[package]\nbuild = \"gen.rs\"\n"),
        ]);
        let found = crate_build_scripts(&mut &*archive).expect("reads");
        assert_eq!(found.names, ["gen.rs", "build.rs", "proc-macro"]);
        assert_eq!(
            found.anomalies,
            [Anomaly::Duplicate("Cargo.toml".to_owned())]
        );
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
        let manifest = tarball(&[("x-1/Cargo.toml", &big)]);
        assert_eq!(
            crate_build_scripts(&mut &*manifest),
            Err(ReadError::TooLarge {
                member: "x-1/Cargo.toml".to_owned(),
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
            anomalies: Vec::new(),
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
            npm_install_scripts(&mut &cut[..]),
            Err(ReadError::NotAnArchive(_))
        ));
        assert!(matches!(
            sdist_install_scripts(&mut &cut[..]),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    use crate::http::gzip;
    use crate::util::test_support::tar;

    /// What each reader finds in `archive`, and the anomalies, which every reader finds alike.
    fn shape(archive: &[u8]) -> ([Vec<String>; 3], Vec<Anomaly>) {
        let found = [
            npm_install_scripts(&mut &*archive),
            sdist_install_scripts(&mut &*archive),
            crate_build_scripts(&mut &*archive),
        ]
        .map(|found| found.expect("reads"));
        assert!(found.iter().all(|f| f.anomalies == found[0].anomalies));
        let anomalies = found[0].anomalies.clone();
        (found.map(|f| f.names), anomalies)
    }

    /// Something every reader reads past.
    const QUIET: [(&str, &[u8]); 1] = [("x-1/README", b"")];

    /// What runs, for every reader.
    const LOUD: [(&str, &[u8]); 4] = [
        ("x-1/package.json", br#"{"scripts":{"install":"x"}}"#),
        ("x-1/setup.py", b""),
        ("x-1/Cargo.toml", b"[package]\n"),
        ("x-1/build.rs", b""),
    ];

    /// The names each reader finds in [`LOUD`].
    fn loud() -> [Vec<String>; 3] {
        [
            vec!["install".to_owned()],
            vec!["setup.py".to_owned()],
            vec!["build.rs".to_owned()],
        ]
    }

    /// A tar that runs on into a second gzip member is one tar to npm and pip, so pip runs
    /// a `setup.py` only the second member holds. Each reader sees it.
    #[test]
    fn a_tar_continued_in_a_second_gzip_member_is_read_whole() {
        let archive = [gzip(&tar(&QUIET, false)), gzip(&tar(&LOUD, true))].concat();
        assert_eq!(shape(&archive), (loud(), vec![Anomaly::GzipMembers(2)]));
        let tree = crate::analysis::source::tree(&mut &*archive, crate::analysis::source::CEILING)
            .expect("reads");
        assert!(
            tree.files.contains_key("setup.py"),
            "{:?}",
            tree.files.keys()
        );
    }

    /// node-tar reads on past a single zero block, to the next entry.
    #[test]
    fn entries_past_a_single_zero_block_are_read() {
        let one_block = [tar(&QUIET, false), vec![0; 512], tar(&LOUD, true)].concat();
        assert_eq!(shape(&gzip(&one_block)), (loud(), vec![Anomaly::AfterEnd]));
    }

    /// A whole second tar, in the same member or another, is read and flagged.
    #[test]
    fn a_second_whole_tar_is_read() {
        let members = [gzip(&tar(&QUIET, true)), gzip(&tar(&LOUD, true))].concat();
        assert_eq!(
            shape(&members),
            (loud(), vec![Anomaly::GzipMembers(2), Anomaly::AfterEnd])
        );
        let one = gzip(&[tar(&QUIET, true), tar(&LOUD, true)].concat());
        assert_eq!(shape(&one), (loud(), vec![Anomaly::AfterEnd]));
    }

    /// Bytes after the archive that are not a tar, or after the gzip stream that are not a
    /// member, are flagged; what came before is read as usual.
    #[test]
    fn bytes_after_the_end_are_flagged_and_the_rest_is_read() {
        let mut junk = tar(&LOUD, true);
        junk.extend([b'j'; 512]);
        assert_eq!(shape(&gzip(&junk)), (loud(), vec![Anomaly::AfterEnd]));

        let mut after = gzip(&tar(&LOUD, true));
        after.extend(b"garbage");
        assert_eq!(shape(&after), (loud(), vec![Anomaly::AfterGzip]));

        assert_eq!(shape(&gzip(&tar(&LOUD, true))), (loud(), Vec::new()));
    }

    /// What decodes as neither gzip nor tar, wherever it is, is not an archive.
    #[test]
    fn an_archive_that_does_not_decode_is_an_error() {
        let mut corrupt = gzip(&tar(&LOUD, true));
        corrupt.extend([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, b'x', b'y']);
        assert!(matches!(
            sdist_install_scripts(&mut &*corrupt),
            Err(ReadError::NotAnArchive(_))
        ));
        assert!(matches!(
            sdist_install_scripts(&mut &*gzip(&[b'j'; 512])),
            Err(ReadError::NotAnArchive(_))
        ));
        let hidden_unparsable = [
            tar(&QUIET, false),
            vec![0; 512],
            tar(&[("x-1/package.json", b"{")], true),
        ]
        .concat();
        assert!(matches!(
            npm_install_scripts(&mut &*gzip(&hidden_unparsable)),
            Err(ReadError::NotAnArchive(_))
        ));
    }

    /// A tarball decompressing past the ceiling is refused, whether a reader reads the
    /// member that passes it or skips it.
    #[test]
    fn a_tarball_decompressing_past_the_ceiling_is_refused() {
        let archive = tarball(&[("x-1/package.json", &[b' '; 4096])]);
        let too_large = Err(ReadError::TooLarge {
            member: "the archive".to_owned(),
            limit: 1024,
        });
        let read = walk_within(&mut &*archive, 1024, &mut |path, member| {
            read_member(path, member).map(drop)
        });
        assert_eq!(read, too_large);
        let skipped = walk_within(&mut &*archive, 1024, &mut |_, _| Ok(()));
        assert_eq!(skipped, too_large);
        let hidden = [tar(&QUIET, true), tar(&[("x-1/a", &[b' '; 4096])], true)].concat();
        let skipped = walk_within(&mut &*gzip(&hidden), 4096, &mut |_, _| Ok(()));
        assert_eq!(
            skipped,
            Err(ReadError::TooLarge {
                member: "the archive".to_owned(),
                limit: 4096,
            })
        );
        assert_eq!(MAX_UNPACKED_BYTES, 4 << 30, "4 GiB");
    }

    /// An empty read returns 0. A read after the last member returns 0. A source that
    /// fails between members fails the read.
    #[test]
    fn an_empty_read_ends_no_member() {
        let archive = [gzip(b"a"), gzip(b"b")].concat();
        let mut source = &archive[..];
        let mut unpacked = Unpacked::new(&mut source, 16);
        assert_eq!(unpacked.read(&mut []).expect("reads"), 0);
        let mut all = String::new();
        unpacked.read_to_string(&mut all).expect("reads");
        assert_eq!((all.as_str(), unpacked.members), ("ab", 2));
        assert_eq!(
            unpacked.read(&mut [0; 8]).expect("reads"),
            0,
            "after the last"
        );

        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("the source failed"))
            }
        }
        let first = gzip(b"a");
        let mut source = (&first[..]).chain(Failing);
        let mut failing = Unpacked::new(&mut source, 16);
        assert!(failing.read_to_end(&mut Vec::new()).is_err());
        assert_eq!(
            failing.failed,
            Some(ReadError::NotAnArchive("the source failed".to_owned()))
        );
    }

    /// A directory is no duplicate; a path seen three times is named once; at most
    /// [`MAX_DUPLICATES_NAMED`] are named.
    #[test]
    fn duplicates_are_named_once_and_only_so_many() {
        let mut builder = tar::Builder::new(Vec::new());
        for _ in 0..2 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "x-1/lib/", &[][..])
                .expect("appends");
        }
        let dirs = gzip(&builder.into_inner().expect("builds"));
        assert_eq!(walk(&mut &*dirs, &mut |_, _| Ok(())), Ok(Vec::new()));

        let thrice = tarball(&[("x-1/a", b""), ("x-1/a", b""), ("y/a", b"")]);
        assert_eq!(
            walk(&mut &*thrice, &mut |_, _| Ok(())),
            Ok(vec![Anomaly::Duplicate("a".to_owned())])
        );

        let paths: Vec<String> = (0..10).map(|i| format!("x-1/{i}")).collect();
        let files: Vec<(&str, &[u8])> = paths
            .iter()
            .chain(&paths)
            .map(|path| (path.as_str(), &b""[..]))
            .collect();
        let found = walk(&mut &*tarball(&files), &mut |_, _| Ok(())).expect("reads");
        assert_eq!(found.len(), MAX_DUPLICATES_NAMED);
    }

    /// Each anomaly reads as what it is, and back from the form a store keeps it in.
    #[test]
    fn every_anomaly_says_what_it_is_and_reads_back() {
        for (anomaly, said, code) in [
            (Anomaly::GzipMembers(3), "3 gzip members", "gzip_members:3"),
            (
                Anomaly::AfterGzip,
                "bytes after the last gzip member",
                "after_gzip",
            ),
            (
                Anomaly::AfterEnd,
                "entries or bytes after the end-of-archive block",
                "after_end",
            ),
            (
                Anomaly::Duplicate("a:b".to_owned()),
                "two entries extract to `a:b`",
                "duplicate:a:b",
            ),
        ] {
            assert_eq!(anomaly.to_string(), said);
            assert_eq!(anomaly.code(), code);
            assert_eq!(Anomaly::parse(code), Some(anomaly));
        }
        for unknown in ["", "gzip_members:x", "after", "other:1"] {
            assert_eq!(Anomaly::parse(unknown), None, "{unknown}");
        }
    }

    /// Where npm extracts each path.
    #[test]
    fn a_path_is_installed_without_its_first_directory() {
        for (path, expected) in [
            ("package/package.json", Some("package.json")),
            ("./package/./a//b", Some("a/b")),
            ("/package/a", Some("a")),
            ("package/", None),
            ("package.json", None),
        ] {
            assert_eq!(installed(path).as_deref(), expected, "{path}");
        }
    }
}
