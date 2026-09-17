//! Lockfiles npm, yarn 1, pnpm and bun write, read for `waharoa policy diff`.
//!
//! npm's row of [`crate::ecosystem::TABLE`] lists these:
//!
//! | File | Format | Where the package and version are |
//! |---|---|---|
//! | `package-lock.json`, `npm-shrinkwrap.json` | JSON, `lockfileVersion` 2 or 3 | an entry's `name`, else its key after the last `node_modules/`, and `version` |
//! | `yarn.lock` | yarn 1's own text | the first descriptor, or the package after `npm:` in an alias, and `version` |
//! | `pnpm-lock.yaml` | YAML, `lockfileVersion` 9 | each `packages` key, `name@version` |
//! | `bun.lock` | JSON with trailing commas, read as YAML | the first element of each `packages` value, `name@version` |
//!
//! In npm, yarn and bun an entry's key can be an alias, such as `my-lodash` for
//! `lodash@4.17.21`. The package is read from the entry, so an alias is judged as the package
//! it installs.
//!
//! Only versions from a registry are kept. A path, a git reference or a URL in the version is
//! not one, and neither is an npm entry resolved from somewhere other than an HTTP URL. yarn 1
//! writes `resolved` for every registry entry, so a yarn entry without one is not kept either.
//! See docs/engineering_decisions/policy-diff-lockfiles.md.

use serde::Deserialize;
use serde::de::IgnoredAny;
use std::collections::{BTreeMap, BTreeSet};

use crate::identity::Ecosystem;
use crate::lockfile::{Locked, Lockfile, Pins, Unread};

const REINSTALL: &str =
    "delete the lockfile and node_modules, then install again through the proxy";

/// npm and yarn record the absolute artifact URL, so a lockfile written through the proxy
/// contains its address.
const RESOLVED: Pins = Pins {
    key: "resolved",
    when_absent: "records no artifact URLs",
    reinstall: REINSTALL,
};

/// Each lockfile name, the reader it chooses, and how it records artifact URLs.
///
/// bun's `bun.lock` is not checked by `doctor`: it records an empty string for an artifact
/// from the configured registry.
pub const LOCKFILES: &[Lockfile] = &[
    Lockfile {
        name: "package-lock.json",
        read: npm,
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "npm-shrinkwrap.json",
        read: npm,
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "yarn.lock",
        read: yarn,
        pins: Some(RESOLVED),
    },
    Lockfile {
        name: "pnpm-lock.yaml",
        read: pnpm,
        // pnpm omits `resolution.tarball` when the URL matches the configured registry and
        // derives it at install time.
        pins: Some(Pins {
            key: "tarball",
            when_absent: "records no artifact URLs, which is normal: pnpm derives them from \
                          the configured registry, so the lockfile is portable and is not \
                          evidence either way",
            reinstall: REINSTALL,
        }),
    },
    Lockfile {
        name: "bun.lock",
        read: bun,
        pins: None,
    },
];

/// bun's older lockfile, which is binary.
pub const UNREAD: &[Unread] = &[Unread {
    name: "bun.lockb",
    reason: "bun.lockb is binary; `bun install --save-text-lockfile` writes bun.lock",
}];

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
}

fn npm(text: &str) -> Result<BTreeSet<Locked>, String> {
    let lock: NpmLock = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if !matches!(lock.version, 2 | 3) {
        return Err(format!(
            "lockfileVersion {} is not read; npm 7 and later write 2 or 3",
            lock.version
        ));
    }
    let packages = lock.packages.ok_or("`packages` is missing")?;
    let mut out = BTreeSet::new();
    for (key, entry) in packages {
        // The project and its workspaces sit outside `node_modules`, and a link points at one.
        let (Some((_, installed)), Some(version)) =
            (key.rsplit_once("node_modules/"), entry.version)
        else {
            continue;
        };
        if !entry.link && registry(&version, entry.resolved.as_deref()) {
            out.insert(locked(entry.name.as_deref().unwrap_or(installed), &version));
        }
    }
    Ok(out)
}

/// A yarn 1 entry as it is read.
struct YarnEntry<'a> {
    line: usize,
    name: &'a str,
    version: Option<&'a str>,
    resolved: Option<&'a str>,
}

fn yarn(text: &str) -> Result<BTreeSet<Locked>, String> {
    if !text.lines().any(|line| line == "# yarn lockfile v1") {
        return Err("not a yarn 1 lockfile: `# yarn lockfile v1` is missing".to_owned());
    }
    let mut out = BTreeSet::new();
    let mut entry: Option<YarnEntry> = None;
    for (i, line) in (1..).zip(text.lines()) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(field) = line.strip_prefix("  ") {
            let entry = entry
                .as_mut()
                .ok_or_else(|| format!("line {i}: indented before any entry"))?;
            // A field of the entry. Deeper lines are under `dependencies` and the like.
            if let Some(version) = field.strip_prefix("version ") {
                entry.version = Some(unquote(version));
            } else if let Some(resolved) = field.strip_prefix("resolved ") {
                entry.resolved = Some(unquote(resolved));
            }
            continue;
        }
        yarn_entry(&mut out, entry.take())?;
        let descriptors = line
            .strip_suffix(':')
            .ok_or_else(|| format!("line {i}: `{line}` is neither an entry nor a field"))?;
        let first = unquote(descriptors.split(", ").next().unwrap_or_default());
        let (name, range) =
            split(first).ok_or_else(|| format!("line {i}: `{first}` is not `name@range`"))?;
        // An alias is followed by the package it installs.
        let name = match range.strip_prefix("npm:") {
            Some(package) => split(package).map_or(package, |(name, _)| name),
            None => name,
        };
        entry = Some(YarnEntry {
            line: i,
            name,
            version: None,
            resolved: None,
        });
    }
    yarn_entry(&mut out, entry)?;
    Ok(out)
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

fn yarn_entry(out: &mut BTreeSet<Locked>, entry: Option<YarnEntry>) -> Result<(), String> {
    let Some(entry) = entry else {
        return Ok(());
    };
    let version = entry
        .version
        .ok_or_else(|| format!("line {}: the entry has no version", entry.line))?;
    if registry(version, Some(entry.resolved.unwrap_or_default())) {
        out.insert(locked(entry.name, version));
    }
    Ok(())
}

#[derive(Deserialize)]
struct PnpmLock {
    #[serde(rename = "lockfileVersion")]
    version: String,
    #[serde(default)]
    packages: BTreeMap<String, IgnoredAny>,
}

fn pnpm(text: &str) -> Result<BTreeSet<Locked>, String> {
    let lock: PnpmLock = serde_saphyr::from_str(text).map_err(|e| e.to_string())?;
    if lock.version.split('.').next() != Some("9") {
        return Err(format!(
            "lockfileVersion {} is not read; pnpm 9 and later write 9.0",
            lock.version
        ));
    }
    Ok(lock
        .packages
        .keys()
        .filter_map(|key| split(key))
        .filter(|(_, version)| registry(version, None))
        .map(|(name, version)| locked(name, version))
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
    let lock: BunLock = serde_saphyr::from_str(text).map_err(|e| e.to_string())?;
    if lock.version > 1 {
        return Err(format!(
            "lockfileVersion {} is not read; bun writes 0 or 1",
            lock.version
        ));
    }
    let mut out = BTreeSet::new();
    for (key, entry) in &lock.packages {
        let (name, version) = entry
            .first()
            .and_then(serde_json::Value::as_str)
            .and_then(split)
            .ok_or_else(|| format!("packages.{key}: the first element is not `name@version`"))?;
        if registry(version, None) {
            out.insert(locked(name, version));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(packages: &[(&str, &str)]) -> BTreeSet<Locked> {
        packages
            .iter()
            .map(|(name, version)| locked(name, version))
            .collect()
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
            bun(r#"{"lockfileVersion": 2, "packages": {}}"#),
            Err("lockfileVersion 2 is not read; bun writes 0 or 1".to_owned())
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
}
