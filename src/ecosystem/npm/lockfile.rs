//! Lockfiles npm, yarn 1, pnpm and bun write, read for `waharoa policy diff`.
//!
//! See docs/engineering_decisions/policy-diff-lockfiles.md.

use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, BTreeSet};

use crate::identity::Ecosystem;
use crate::lockfile::{Locked, LockedArtifact, Lockfile, Pins, Platform, Unread, own_source};

const REINSTALL: &str =
    "delete the lockfile and node_modules, then install again through the proxy";

/// How npm and yarn record the absolute artifact URL.
const RESOLVED: Pins = Pins {
    key: "resolved",
    when_absent: "records no artifact URLs",
    absent_is_off_proxy: false,
    reinstall: REINSTALL,
};

/// Each lockfile name, the reader it chooses, and how it records artifact URLs.
pub const LOCKFILES: &[Lockfile] = &[
    Lockfile {
        name: "package-lock.json",
        read: npm,
        artifacts: Some(npm_artifacts),
        urls: Some(npm_urls),
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "npm-shrinkwrap.json",
        read: npm,
        artifacts: Some(npm_artifacts),
        urls: Some(npm_urls),
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "yarn.lock",
        read: yarn,
        artifacts: Some(yarn_artifacts),
        urls: Some(yarn_urls),
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "pnpm-lock.yaml",
        read: pnpm,
        artifacts: Some(pnpm_artifacts),
        urls: Some(pnpm_urls),
        pins: Some(Pins {
            key: "tarball",
            when_absent: "records no artifact URLs, which is normal: pnpm derives them from \
                          the configured registry, so the lockfile is portable and is not \
                          evidence either way",
            absent_is_off_proxy: false,
            reinstall: REINSTALL,
        }),
    },
    Lockfile {
        name: "bun.lock",
        read: bun,
        artifacts: Some(bun_artifacts),
        urls: Some(bun_urls),
        pins: Some(Pins {
            key: "\": [",
            when_absent: "records no artifact URLs: bun writes one for every registry but \
                          registry.npmjs.org, so these packages were resolved there, not \
                          through the proxy",
            absent_is_off_proxy: true,
            reinstall: REINSTALL,
        }),
    },
];

/// bun's older lockfile, which is binary.
pub const UNREAD: &[Unread] = &[Unread {
    name: "bun.lockb",
    reason: "bun.lockb is binary; `bun install --save-text-lockfile` writes bun.lock",
}];

/// The packages `artifacts` lock, for `policy diff`.
fn locked_set(artifacts: Vec<LockedArtifact>) -> BTreeSet<Locked> {
    artifacts.into_iter().map(|a| a.locked).collect()
}

/// One registry artifact: fetched from `resolved`'s path when it is an HTTP URL, otherwise
/// from the registry's own path for the package.
fn artifact(
    name: &str,
    version: &str,
    resolved: Option<&str>,
    platform: Platform,
) -> LockedArtifact {
    let path = resolved
        .and_then(|r| reqwest::Url::parse(r).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.path().to_owned())
        .unwrap_or_else(|| {
            let file = name.rsplit('/').next().unwrap_or(name);
            format!("/{name}/-/{file}-{version}.tgz")
        });
    LockedArtifact {
        locked: locked(name, version),
        path,
        platform,
        url: resolved.filter(|r| !r.is_empty()).map(str::to_owned),
    }
}

/// A lockfile's `os`, `cpu` or `libc`: a list, or one value.
#[derive(Deserialize, Default, Clone)]
#[serde(untagged)]
enum Values {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Values {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

/// The platform fields npm, pnpm and bun write on a package.
#[derive(Deserialize, Default, Clone)]
struct Platforms {
    #[serde(default)]
    os: Values,
    #[serde(default)]
    cpu: Values,
    #[serde(default)]
    libc: Values,
}

impl Platforms {
    fn platform(self) -> Platform {
        Platform {
            os: self.os.into_vec(),
            cpu: self.cpu.into_vec(),
            libc: self.libc.into_vec(),
        }
    }
}

fn locked(name: &str, version: &str) -> Locked {
    (
        Ecosystem::Npm.as_str().to_owned(),
        name.to_owned(),
        version.to_owned(),
    )
}

/// `name@version` or `@scope/name@version`, split at the `@` before the version.
fn split(spec: &str) -> Option<(&str, &str)> {
    let at = spec.get(1..)?.find('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

/// Whether `version` came from a registry: a version number, resolved from nowhere recorded
/// or from an HTTP URL.
fn registry(version: &str, resolved: Option<&str>) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && resolved.is_none_or(|r| r.starts_with("https://") || r.starts_with("http://"))
}

/// Whether a yarn descriptor's `range` asks a registry: a semver range, a tag or an `npm:`
/// alias. yarn 1 resolves `github:o/r` to an HTTP URL and its `package.json` version, which
/// [`registry`] alone takes for a registry's.
fn registry_range(range: &str) -> bool {
    range.starts_with("npm:") || !range.contains([':', '/'])
}

#[derive(Deserialize)]
struct NpmLock {
    #[serde(rename = "lockfileVersion")]
    version: u32,
    packages: Option<BTreeMap<String, NpmEntry>>,
}

#[derive(Deserialize)]
struct NpmEntry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    #[serde(default)]
    link: bool,
    #[serde(flatten)]
    platforms: Platforms,
}

fn npm(text: &str) -> Result<BTreeSet<Locked>, String> {
    npm_artifacts(text).map(locked_set)
}

fn npm_artifacts(text: &str) -> Result<Vec<LockedArtifact>, String> {
    npm_read(text, false)
}

/// The registry artifacts, and each package installed from git or a path outside the project.
fn npm_urls(text: &str) -> Result<Vec<LockedArtifact>, String> {
    npm_read(text, true)
}

/// Each registry artifact, and with `unregistered` each package installed from elsewhere: a
/// `resolved` that is not an HTTP URL, or a link outside the project, named by its target.
fn npm_read(text: &str, unregistered: bool) -> Result<Vec<LockedArtifact>, String> {
    let lock: NpmLock = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if !matches!(lock.version, 2 | 3) {
        return Err(format!(
            "lockfileVersion {} is not read; npm 7 and later write 2 or 3",
            lock.version
        ));
    }
    let packages = lock.packages.ok_or("`packages` is missing")?;
    let mut out = Vec::new();
    for (key, entry) in &packages {
        let Some((_, installed)) = key.rsplit_once("node_modules/") else {
            continue;
        };
        let name = entry.name.as_deref().unwrap_or(installed);
        let resolved = entry.resolved.as_deref();
        if entry.link {
            if let Some(target) = resolved.filter(|r| unregistered && !own_source(r)) {
                let version = packages.get(target).and_then(|t| t.version.as_deref());
                out.push(LockedArtifact::unregistered(
                    locked(name, version.unwrap_or(target)),
                    target,
                ));
            }
            continue;
        }
        let Some(version) = entry.version.as_deref() else {
            continue;
        };
        if registry(version, resolved) {
            let platform = entry.platforms.clone().platform();
            out.push(artifact(name, version, resolved, platform));
        } else if let Some(spec) = resolved.filter(|r| unregistered && !own_source(r)) {
            out.push(LockedArtifact::unregistered(locked(name, version), spec));
        }
    }
    Ok(out)
}

/// A yarn 1 entry as it is read.
struct YarnEntry<'a> {
    line: usize,
    name: &'a str,
    /// The first descriptor's range: a registry's, or else a spec such as a local path.
    range: &'a str,
    version: Option<&'a str>,
    resolved: Option<&'a str>,
}

fn yarn(text: &str) -> Result<BTreeSet<Locked>, String> {
    yarn_artifacts(text).map(locked_set)
}

fn yarn_artifacts(text: &str) -> Result<Vec<LockedArtifact>, String> {
    yarn_read(text, false)
}

/// The registry artifacts, and each package installed from git or a path outside the project.
fn yarn_urls(text: &str) -> Result<Vec<LockedArtifact>, String> {
    yarn_read(text, true)
}

/// yarn 1 records no platform, so every entry allows every platform. With `unregistered`,
/// each entry from elsewhere too: its `resolved`, or without one its range.
fn yarn_read(text: &str, unregistered: bool) -> Result<Vec<LockedArtifact>, String> {
    if !text.lines().any(|line| line == "# yarn lockfile v1") {
        return Err("not a yarn 1 lockfile: `# yarn lockfile v1` is missing".to_owned());
    }
    let mut out = Vec::new();
    let mut entry: Option<YarnEntry> = None;
    for (i, line) in (1..).zip(text.lines()) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(field) = line.strip_prefix("  ") {
            let entry = entry
                .as_mut()
                .ok_or_else(|| format!("line {i}: indented before any entry"))?;
            if let Some(version) = field.strip_prefix("version ") {
                entry.version = Some(unquote(version));
            } else if let Some(resolved) = field.strip_prefix("resolved ") {
                entry.resolved = Some(unquote(resolved));
            }
            continue;
        }
        yarn_entry(&mut out, entry.take(), unregistered)?;
        let descriptors = line
            .strip_suffix(':')
            .ok_or_else(|| format!("line {i}: `{line}` is neither an entry nor a field"))?;
        let first = unquote(descriptors.split(", ").next().unwrap_or_default());
        let (name, range) =
            split(first).ok_or_else(|| format!("line {i}: `{first}` is not `name@range`"))?;
        let name = match range.strip_prefix("npm:") {
            Some(package) => split(package).map_or(package, |(name, _)| name),
            None => name,
        };
        entry = Some(YarnEntry {
            line: i,
            name,
            range,
            version: None,
            resolved: None,
        });
    }
    yarn_entry(&mut out, entry, unregistered)?;
    Ok(out)
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

fn yarn_entry(
    out: &mut Vec<LockedArtifact>,
    entry: Option<YarnEntry>,
    unregistered: bool,
) -> Result<(), String> {
    let Some(entry) = entry else {
        return Ok(());
    };
    let version = entry
        .version
        .ok_or_else(|| format!("line {}: the entry has no version", entry.line))?;
    if registry_range(entry.range) && registry(version, Some(entry.resolved.unwrap_or_default())) {
        out.push(artifact(
            entry.name,
            version,
            entry.resolved,
            Platform::default(),
        ));
    } else {
        let spec = entry.resolved.unwrap_or(entry.range);
        if unregistered && !own_source(spec) {
            out.push(LockedArtifact::unregistered(
                locked(entry.name, version),
                spec,
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct PnpmLock {
    #[serde(rename = "lockfileVersion")]
    version: String,
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackage>,
}

#[derive(Deserialize)]
struct PnpmPackage {
    #[serde(flatten)]
    platforms: Platforms,
    /// `tarball` is written only when the URL is not the configured registry's.
    #[serde(default)]
    resolution: Option<PnpmResolution>,
    /// The version a package not from a registry has, whose key records its spec instead.
    #[serde(default)]
    version: Option<String>,
    #[serde(flatten)]
    _rest: BTreeMap<String, IgnoredAny>,
}

#[derive(Deserialize)]
struct PnpmResolution {
    #[serde(default)]
    tarball: Option<String>,
}

fn pnpm(text: &str) -> Result<BTreeSet<Locked>, String> {
    pnpm_artifacts(text).map(locked_set)
}

fn pnpm_artifacts(text: &str) -> Result<Vec<LockedArtifact>, String> {
    pnpm_read(text, false)
}

/// The registry artifacts, and each package installed from git or a path outside the project.
fn pnpm_urls(text: &str) -> Result<Vec<LockedArtifact>, String> {
    pnpm_read(text, true)
}

/// pnpm omits the tarball URL for the configured registry, so each path is that URL's or,
/// without one, the registry's own for the package. With `unregistered`, each package from
/// elsewhere too, named by the spec its key records in place of a version.
fn pnpm_read(text: &str, unregistered: bool) -> Result<Vec<LockedArtifact>, String> {
    let lock: PnpmLock = serde_saphyr::from_str(text).map_err(|e| e.to_string())?;
    if lock.version.split('.').next() != Some("9") {
        return Err(format!(
            "lockfileVersion {} is not read; pnpm 9 and later write 9.0",
            lock.version
        ));
    }
    Ok(lock
        .packages
        .into_iter()
        .filter_map(|(key, package)| {
            let (name, version) = split(&key)?;
            let tarball = package.resolution.and_then(|r| r.tarball);
            if registry(version, tarball.as_deref()) {
                return Some(artifact(
                    name,
                    version,
                    tarball.as_deref(),
                    package.platforms.platform(),
                ));
            }
            let label = package.version.as_deref().unwrap_or(version);
            (unregistered && !own_source(version))
                .then(|| LockedArtifact::unregistered(locked(name, label), version))
        })
        .collect())
}

#[derive(Deserialize)]
struct BunLock {
    #[serde(rename = "lockfileVersion")]
    version: u32,
    #[serde(default)]
    packages: BTreeMap<String, Vec<serde_json::Value>>,
}

fn bun(text: &str) -> Result<BTreeSet<Locked>, String> {
    bun_artifacts(text).map(locked_set)
}

fn bun_artifacts(text: &str) -> Result<Vec<LockedArtifact>, String> {
    bun_read(text, false)
}

/// The registry artifacts, and each package installed from git or a path outside the project.
fn bun_urls(text: &str) -> Result<Vec<LockedArtifact>, String> {
    bun_read(text, true)
}

/// bun records an empty URL for registry.npmjs.org, and the artifact's for any other: the
/// entry's second element. The platform is in its third. With `unregistered`, each package
/// from elsewhere too, named by the spec after its name: `github:o/r#abc`, `../x.tgz`.
fn bun_read(text: &str, unregistered: bool) -> Result<Vec<LockedArtifact>, String> {
    let lock: BunLock = serde_saphyr::from_str(text).map_err(|e| e.to_string())?;
    if lock.version > 3 {
        return Err(format!(
            "lockfileVersion {} is not read; bun writes 0 to 3",
            lock.version
        ));
    }
    let mut out = Vec::new();
    for (key, entry) in &lock.packages {
        let (name, version) = entry
            .first()
            .and_then(serde_json::Value::as_str)
            .and_then(split)
            .ok_or_else(|| format!("packages.{key}: the first element is not `name@version`"))?;
        if registry(version, None) {
            let platform = entry
                .get(2)
                .and_then(|meta| Platforms::deserialize(meta).ok())
                .unwrap_or_default()
                .platform();
            let url = entry.get(1).and_then(serde_json::Value::as_str);
            out.push(artifact(name, version, url, platform));
        } else if unregistered && !own_source(version) {
            out.push(LockedArtifact::unregistered(locked(name, version), version));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Each format's artifacts: the recorded path where there is one, the registry's own
    /// path otherwise, and the platform where the format writes it.
    #[test]
    fn each_format_gives_each_artifact_its_path_and_platform() {
        let npm = npm_artifacts(
            r#"{"lockfileVersion": 3, "packages": {"": {},
                "node_modules/@s/b": {"version": "1.0.0",
                    "resolved": "http://127.0.0.1:8080/@s/b/-/b-1.0.0.tgz"},
                "node_modules/c": {"version": "2.0.0", "os": ["darwin"], "cpu": ["arm64"]}}}"#,
        )
        .unwrap();
        assert_eq!(npm[0].path, "/@s/b/-/b-1.0.0.tgz");
        assert_eq!(npm[1].path, "/c/-/c-2.0.0.tgz");
        assert_eq!(npm[1].platform.os, ["darwin"]);
        assert_eq!(npm[1].platform.cpu, ["arm64"]);

        let yarn = yarn_artifacts(
            "# yarn lockfile v1\n\nms@^2.1.3:\n  version \"2.1.3\"\n  resolved \
             \"https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#abc\"\n",
        )
        .unwrap();
        assert_eq!(yarn[0].path, "/ms/-/ms-2.1.3.tgz");
        assert_eq!(yarn[0].platform, Platform::default());

        let pnpm = pnpm_artifacts(
            "lockfileVersion: '9.0'\npackages:\n  '@esbuild/linux-x64@0.25.0':\n    \
             resolution: {integrity: sha512-x}\n    os: [linux]\n    cpu: [x64]\n  \
             ms@2.1.3:\n    resolution: {integrity: sha512-y}\n",
        )
        .unwrap();
        assert_eq!(pnpm[0].path, "/@esbuild/linux-x64/-/linux-x64-0.25.0.tgz");
        assert_eq!(pnpm[0].platform.os, ["linux"]);
        assert_eq!(pnpm[1].platform, Platform::default());

        let bun = bun_artifacts(
            r#"{"lockfileVersion": 1, "packages": {
                "@esbuild/darwin-arm64": ["@esbuild/darwin-arm64@0.25.0", "",
                    {"os": "darwin", "cpu": "arm64"}, "sha512-x"],
                "ms": ["ms@2.1.3", "", {}, "sha512-y"]}}"#,
        )
        .unwrap();
        assert_eq!(
            bun[0].path,
            "/@esbuild/darwin-arm64/-/darwin-arm64-0.25.0.tgz"
        );
        assert_eq!(bun[0].platform.os, ["darwin"]);
        assert_eq!(bun[0].platform.cpu, ["arm64"]);
        assert_eq!(bun[1].platform, Platform::default());
    }

    fn set(packages: &[(&str, &str)]) -> BTreeSet<Locked> {
        packages
            .iter()
            .map(|(name, version)| locked(name, version))
            .collect()
    }

    /// Each format names a package from elsewhere by its spec, and not a path inside the
    /// project. npm names a link by its target, with the target's version where recorded.
    #[test]
    fn each_format_names_a_package_from_elsewhere_and_not_the_projects_own() {
        let named = |artifacts: Vec<LockedArtifact>| -> Vec<(String, Option<String>)> {
            artifacts
                .into_iter()
                .map(|a| (format!("{}@{}", a.locked.1, a.locked.2), a.url))
                .collect()
        };
        let pair = |label: &str, spec: &str| (label.to_owned(), Some(spec.to_owned()));
        let npm = r#"{"lockfileVersion": 3, "packages": {
            "../out": {"version": "1.0.0"},
            "node_modules/out": {"resolved": "../out", "link": true},
            "node_modules/bare": {"resolved": "../bare", "link": true},
            "node_modules/nowhere": {"link": true},
            "node_modules/unversioned": {"resolved": "../unversioned"},
            "node_modules/ws": {"resolved": "packages/ws", "link": true},
            "node_modules/vendored": {"version": "2.0.0", "resolved": "file:vendor/v.tgz"},
            "node_modules/tag": {"version": "latest"}
        }}"#;
        assert_eq!(
            named(npm_urls(npm).unwrap()),
            [pair("bare@../bare", "../bare"), pair("out@1.0.0", "../out")]
        );
        assert_eq!(npm_artifacts(npm), Ok(Vec::new()));

        let yarn = "# yarn lockfile v1\n\n\
            \"gh@github:o/gh\":\n  version \"1.0.0\"\n  resolved \"https://codeload.github.com/o/gh/tar.gz/abc\"\n\n\
            short@o/short:\n  version \"4.0.0\"\n  resolved \"https://codeload.github.com/o/short/tar.gz/abc\"\n\n\
            \"vendored@file:vendor/v.tgz\":\n  version \"2.0.0\"\n  resolved \"file:vendor/v.tgz#abc\"\n\n\
            \"inside@file:packages/inside\":\n  version \"3.0.0\"\n";
        assert_eq!(
            named(yarn_urls(yarn).unwrap()),
            [
                pair("gh@1.0.0", "https://codeload.github.com/o/gh/tar.gz/abc"),
                pair(
                    "short@4.0.0",
                    "https://codeload.github.com/o/short/tar.gz/abc"
                )
            ],
            "a github range is not a registry's, whatever its URL"
        );
        assert_eq!(yarn_artifacts(yarn), Ok(Vec::new()));

        let pnpm = "lockfileVersion: '9.0'
packages:
              git@git+https://example.test/o/git.git#abc:
                resolution: {type: git, repo: 'https://example.test/o/git.git', commit: abc}
              inside@file:packages/inside:
                resolution: {directory: packages/inside, type: directory}
              vendored@file:vendor/v.tgz:
                resolution: {tarball: 'file:vendor/v.tgz'}
                version: 2.0.0
";
        assert_eq!(
            named(pnpm_urls(pnpm).unwrap()),
            [pair(
                "git@git+https://example.test/o/git.git#abc",
                "git+https://example.test/o/git.git#abc"
            )]
        );
        assert_eq!(pnpm_artifacts(pnpm), Ok(Vec::new()));

        let bun = r#"{"lockfileVersion": 1, "packages": {
            "inside": ["inside@file:packages/inside", {}],
            "vendored": ["vendored@vendor/v.tgz", {}, "sha512-x"],
            "url": ["url@https://example.test/u.tgz", {}, "sha512-y"]
        }}"#;
        assert_eq!(
            named(bun_urls(bun).unwrap()),
            [pair(
                "url@https://example.test/u.tgz",
                "https://example.test/u.tgz"
            )]
        );
        assert_eq!(bun_artifacts(bun), Ok(Vec::new()));
    }

    #[test]
    fn npm_keeps_only_registry_versions_under_node_modules() {
        let text = r#"{"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "packages/ws": {"name": "ws", "version": "2.0.0"},
            "node_modules/ws": {"resolved": "packages/ws", "link": true},
            "node_modules/linked": {"version": "2.1.0", "link": true},
            "node_modules/a/node_modules/@s/b": {"version": "1.0.0",
                "resolved": "https://registry.npmjs.org/@s/b/-/b-1.0.0.tgz"},
            "node_modules/insecure": {"version": "1.5.0",
                "resolved": "http://registry.example/insecure-1.5.0.tgz"},
            "node_modules/from-git": {"version": "3.0.0",
                "resolved": "git+ssh://git@github.com/o/from-git.git#abc"},
            "node_modules/from-file": {"version": "4.0.0", "resolved": "file:../from-file"},
            "node_modules/bundled": {"version": "5.0.0", "inBundle": true},
            "node_modules/tag": {"version": "latest"}
        }}"#;
        assert_eq!(
            npm(text),
            Ok(set(&[
                ("@s/b", "1.0.0"),
                ("bundled", "5.0.0"),
                ("insecure", "1.5.0")
            ]))
        );
    }

    #[test]
    fn npm_other_than_lockfile_version_2_or_3_and_json_that_does_not_parse_are_refused() {
        for (version, text) in [
            (1, r#"{"lockfileVersion": 1, "dependencies": {}}"#),
            (4, r#"{"lockfileVersion": 4, "packages": {}}"#),
        ] {
            assert_eq!(
                npm(text),
                Err(format!(
                    "lockfileVersion {version} is not read; npm 7 and later write 2 or 3"
                ))
            );
        }
        assert_eq!(
            npm(r#"{"lockfileVersion": 3}"#),
            Err("`packages` is missing".to_owned())
        );
        assert!(npm("{").is_err());
    }

    #[test]
    fn yarn_reads_the_first_descriptor_and_keeps_only_registry_entries() {
        let text = "# yarn lockfile v1\n\n\n\
            \"@s/a@^1.0.0\", \"@s/a@^1.1.0\":\n\
            \x20 version \"1.2.0\"\n\
            \x20 resolved \"https://registry.yarnpkg.com/@s/a/-/a-1.2.0.tgz#x\"\n\
            \x20 dependencies:\n\
            \x20   version \"9.9.9\"\n\n\
            \"from-git@git+https://github.com/o/r.git\":\n\
            \x20 version \"2.0.0\"\n\
            \x20 resolved \"git+https://github.com/o/r.git#abc\"\n\n\
            \"local@file:../local\":\n\
            \x20 version \"3.0.0\"\n\n\
            \"alias@npm:@s/real@^4\":\n\
            \x20 version \"4.1.0\"\n\
            \x20 resolved \"https://registry.yarnpkg.com/@s/real/-/real-4.1.0.tgz\"\n\n\
            bare@npm:plain:\n\
            \x20 version \"5.0.0\"\n\
            \x20 resolved \"https://registry.yarnpkg.com/plain/-/plain-5.0.0.tgz\"\n";
        assert_eq!(
            yarn(text),
            Ok(set(&[
                ("@s/a", "1.2.0"),
                ("@s/real", "4.1.0"),
                ("plain", "5.0.0")
            ]))
        );
    }

    #[test]
    fn a_yarn_file_that_is_not_a_yarn_1_lockfile_is_refused_with_the_line() {
        for (text, reason) in [
            (
                "__metadata:\n  version: 6\n",
                "not a yarn 1 lockfile: `# yarn lockfile v1` is missing",
            ),
            (
                "# yarn lockfile v1\n  version \"1.0.0\"\n",
                "line 2: indented before any entry",
            ),
            (
                "# yarn lockfile v1\na@^1\n",
                "line 2: `a@^1` is neither an entry nor a field",
            ),
            (
                "# yarn lockfile v1\nnoversion:\n  version \"1.0.0\"\n",
                "line 2: `noversion` is not `name@range`",
            ),
            (
                "# yarn lockfile v1\n\"a@^1\":\n  resolved \"https://x\"\nb@^1:\n  version \"1\"\n",
                "line 2: the entry has no version",
            ),
            (
                "# yarn lockfile v1\nb@^1:\n  version \"1.0.0\"\na@^1:\n",
                "line 4: the entry has no version",
            ),
        ] {
            assert_eq!(yarn(text), Err(reason.to_owned()), "{text:?}");
        }
    }

    #[test]
    fn pnpm_keeps_only_registry_package_keys() {
        let text = "lockfileVersion: '9.0'\n\
            packages:\n\
            \x20 a@1.0.0:\n\
            \x20   resolution: {integrity: sha512-x}\n\
            \x20 b@file:../b:\n\
            \x20   resolution: {directory: ../b, type: directory}\n\
            \x20 c@https://codeload.github.com/o/c/tar.gz/abc:\n\
            \x20   resolution: {tarball: 'https://codeload.github.com/o/c/tar.gz/abc'}\n\
            \x20 '@s/d@2.0.0': {}\n";
        assert_eq!(pnpm(text), Ok(set(&[("@s/d", "2.0.0"), ("a", "1.0.0")])));
        assert_eq!(pnpm("lockfileVersion: '9.0'\n"), Ok(BTreeSet::new()));
    }

    #[test]
    fn pnpm_before_lockfile_version_9_is_refused() {
        assert_eq!(
            pnpm("lockfileVersion: '6.0'\npackages: {}\n"),
            Err("lockfileVersion 6.0 is not read; pnpm 9 and later write 9.0".to_owned())
        );
        assert!(pnpm("packages: [").is_err());
    }

    #[test]
    fn bun_keeps_only_registry_entries_and_refuses_what_it_cannot_read() {
        let text = r#"{
            "lockfileVersion": 1,
            "packages": {
                "ws": ["ws@workspace:packages/ws"],
                "g": ["g@github:o/g#abc", {}, "o-g-abc"],
                "my-a": ["a@1.0.0", "", {}, "sha512-x"],
            },
        }"#;
        assert_eq!(bun(text), Ok(set(&[("a", "1.0.0")])));

        assert_eq!(
            bun(r#"{"lockfileVersion": 4, "packages": {}}"#),
            Err("lockfileVersion 4 is not read; bun writes 0 to 3".to_owned())
        );
        for entry in ["[{}]", "[]", r#"["no-version"]"#] {
            assert_eq!(
                bun(&format!(
                    r#"{{"lockfileVersion": 0, "packages": {{"a": {entry}}}}}"#
                )),
                Err("packages.a: the first element is not `name@version`".to_owned()),
                "{entry}"
            );
        }
    }

    /// A spec with no version after its name is not split, and its entry is not read.
    #[test]
    fn a_spec_with_no_version_is_not_split() {
        assert_eq!(split("@s/b@1.0.0"), Some(("@s/b", "1.0.0")));
        assert_eq!(split("lodash"), None);
        assert_eq!(split(""), None);
        let locked = pnpm("lockfileVersion: '9.0'\npackages:\n  lodash: {}\n  a@1.0.0: {}\n")
            .expect("reads");
        assert_eq!(
            locked
                .into_iter()
                .map(|(_, name, _)| name)
                .collect::<Vec<_>>(),
            ["a"]
        );
    }

    #[test]
    fn a_bun_lockfile_that_is_not_json_is_an_error() {
        assert!(bun("{ not json").is_err());
    }
}
