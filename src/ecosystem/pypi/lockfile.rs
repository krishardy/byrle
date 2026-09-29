//! Lockfiles uv, poetry, pip and pipenv write, read for `waharoa policy diff`.
//!
//! See docs/engineering_decisions/policy-diff-lockfiles.md.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::identity::Ecosystem;
use crate::lockfile::{Locked, Lockfile, Pins, Unread};

/// Each lockfile name, the reader it chooses, and how it records artifact URLs.
pub const LOCKFILES: &[Lockfile] = &[
    Lockfile {
        name: "uv.lock",
        read: uv,
        artifacts: None,
        pins: Some(Pins {
            key: "url",
            when_absent: "records no artifact URLs",
            reinstall: "delete uv.lock and the environment, then `uv lock` through the proxy",
        }),
    },
    Lockfile {
        name: "poetry.lock",
        read: poetry,
        artifacts: None,
        pins: None,
    },
    Lockfile {
        name: "requirements.txt",
        read: requirements,
        artifacts: None,
        pins: None,
    },
    Lockfile {
        name: "Pipfile.lock",
        read: pipenv,
        artifacts: None,
        pins: None,
    },
];

/// File names a Python client writes that no reader here takes.
pub const UNREAD: &[Unread] = &[];

fn locked(name: &str, version: &str) -> Locked {
    (
        Ecosystem::PyPI.as_str().to_owned(),
        super::paths::normalise(name),
        version.trim().to_owned(),
    )
}

#[derive(Deserialize)]
struct TomlLock {
    #[serde(default)]
    package: Vec<TomlPackage>,
}

#[derive(Deserialize)]
struct TomlPackage {
    name: String,
    version: String,
    /// Where the package came from. poetry omits it for its default index.
    #[serde(default)]
    source: Option<toml::Value>,
}

/// uv's lockfile. A package is kept when its source is a registry.
fn uv(text: &str) -> Result<BTreeSet<Locked>, String> {
    let lock: TomlLock = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(lock
        .package
        .iter()
        .filter(|package| {
            package
                .source
                .as_ref()
                .and_then(|source| source.as_table())
                .is_some_and(|source| source.contains_key("registry"))
        })
        .map(|package| locked(&package.name, &package.version))
        .collect())
}

/// poetry's lockfile. A package with no `[package.source]` came from the default index; one
/// with `type = "legacy"` came from another index, which is a registry too.
fn poetry(text: &str) -> Result<BTreeSet<Locked>, String> {
    let lock: TomlLock = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(lock
        .package
        .iter()
        .filter(|package| match &package.source {
            None => true,
            Some(source) => source.get("type").and_then(toml::Value::as_str) == Some("legacy"),
        })
        .map(|package| locked(&package.name, &package.version))
        .collect())
}

/// pipenv's lockfile: `default` and `develop`, each a map of name to entry.
/// An entry with an `==` `version` is kept. `text` is the file's contents.
/// Returns the packages locked, or why the file does not read.
fn pipenv(text: &str) -> Result<BTreeSet<Locked>, String> {
    #[derive(Deserialize)]
    struct Lock {
        #[serde(default)]
        default: std::collections::BTreeMap<String, Entry>,
        #[serde(default)]
        develop: std::collections::BTreeMap<String, Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        #[serde(default)]
        version: Option<String>,
    }
    let lock: Lock = serde_json::from_str(text).map_err(|e| e.to_string())?;
    Ok(lock
        .default
        .iter()
        .chain(&lock.develop)
        .filter_map(|(name, entry)| {
            let version = entry.version.as_deref()?.strip_prefix("==")?;
            Some(locked(name, version))
        })
        .collect())
}

/// pip's requirement lines, of which only an `==` pin is a locked version.
///
/// A file with no pin at all is refused rather than read as no packages: `policy diff`
/// compares the packages it is given, and an empty answer from a file full of ranges reads
/// as a project with no dependencies.
fn requirements(text: &str) -> Result<BTreeSet<Locked>, String> {
    let mut out = BTreeSet::new();
    let mut lines = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        lines += 1;
        let requirement = line
            .split(';')
            .next()
            .unwrap_or(line)
            .trim_end_matches('\\')
            .trim();
        let Some((name, version)) = requirement.split_once("==") else {
            continue;
        };
        if name.contains('@') || version.contains([',', '*']) {
            continue;
        }
        let name = name.split('[').next().unwrap_or(name).trim();
        out.insert(locked(name, version));
    }
    if out.is_empty() && lines > 0 {
        return Err("no requirement is pinned with `==`, so this is not a lockfile".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lockfiles/pypi/"
        );
        std::fs::read_to_string(format!("{dir}{name}")).expect("fixture is missing")
    }

    fn names(locked: &BTreeSet<Locked>) -> Vec<String> {
        locked
            .iter()
            .map(|(_, name, version)| format!("{name}@{version}"))
            .collect()
    }

    /// uv 0.12.5, with a git dependency and the project itself in the file.
    #[test]
    fn uv_keeps_the_packages_a_registry_published() {
        let locked = uv(&fixture("uv.lock")).expect("the lockfile reads");
        assert_eq!(
            names(&locked),
            ["idna@3.10"],
            "the git package and the project itself are not from a registry"
        );
        assert_eq!(locked.iter().next().expect("one").0, "pypi");
    }

    /// poetry 2.2.1. Its git package carries `[package.source] type = "git"`.
    #[test]
    fn poetry_keeps_the_packages_an_index_published() {
        let locked = poetry(&fixture("poetry.lock")).expect("the lockfile reads");
        assert_eq!(names(&locked), ["idna@3.10"]);
    }

    /// Another index is still an index: poetry writes `type = "legacy"` for one.
    #[test]
    fn poetry_keeps_a_package_from_another_index() {
        let text = r#"
[[package]]
name = "torch"
version = "2.4.0"

[package.source]
type = "legacy"
url = "https://download.pytorch.org/whl/cpu"
reference = "pytorch"

[[package]]
name = "local"
version = "1.0.0"

[package.source]
type = "directory"
url = "../local"
"#;
        let locked = poetry(text).expect("the lockfile reads");
        assert_eq!(names(&locked), ["torch@2.4.0"]);
    }

    /// pipenv 2024.4.1, with a git dependency in `default` and dev dependencies beside it.
    #[test]
    fn pipenv_keeps_the_pinned_packages_of_both_sections() {
        let locked = pipenv(&fixture("Pipfile.lock")).expect("the lockfile reads");
        assert_eq!(
            names(&locked),
            [
                "certifi@2026.7.22",
                "charset-normalizer@3.5.1",
                "idna@3.10",
                "requests@2.32.3",
                "urllib3@2.8.0"
            ],
            "the git package has no version, and dev dependencies are kept"
        );
    }

    /// An entry with no `==` version is not a locked version, whatever else it says.
    #[test]
    fn pipenv_keeps_only_an_exact_pin() {
        let text = r#"{"default": {
            "from-git": {"git": "https://github.com/o/r.git", "ref": "abc"},
            "local": {"path": "."},
            "ranged": {"version": ">=2.0"},
            "pinned": {"version": "==1.0", "index": "internal"}
        }}"#;
        let locked = pipenv(text).expect("the lockfile reads");
        assert_eq!(
            names(&locked),
            ["pinned@1.0"],
            "another index is still an index"
        );
    }

    /// `uv export`'s requirements.txt, which pins `urllib3` once per marker.
    /// Both pins are locked.
    #[test]
    fn requirements_keeps_every_pinned_line() {
        let locked = requirements(&fixture("requirements.txt")).expect("the file reads");
        assert_eq!(
            names(&locked),
            [
                "certifi@2026.7.22",
                "charset-normalizer@3.5.1",
                "idna@3.10",
                "requests@2.32.3",
                "urllib3@2.6.3",
                "urllib3@2.8.0"
            ]
        );
    }

    /// What a requirement line has to be to count as a locked version.
    #[test]
    fn only_an_exact_pin_is_a_locked_version() {
        let text = "idna==3.10\n\
                    requests[socks]==2.32.3 ; python_version < \"3.11\"\n\
                    urllib3>=2.0\n\
                    packaging @ git+https://github.com/pypa/packaging@23.2\n\
                    other @ https://example.test/other-1.0.tar.gz\n\
                    flask==2.*\n\
                    -e .\n\
                    --index-url https://pypi.org/simple\n\
                    # a comment\n";
        let locked = requirements(text).expect("some lines are pins");
        assert_eq!(names(&locked), ["idna@3.10", "requests@2.32.3"]);
    }

    /// A file of ranges is not a lockfile, and reading it as no packages would say this
    /// project depends on nothing.
    #[test]
    fn a_file_with_no_pin_is_refused() {
        let error = requirements("requests>=2\nidna\n").expect_err("nothing is pinned");
        assert!(error.contains("not a lockfile"), "{error}");
        assert_eq!(
            requirements("# nothing here\n"),
            Ok(BTreeSet::new()),
            "an empty file locks nothing, and is not unreadable"
        );
    }

    /// A name is normalised as PyPI normalises one, so `Charset_Normalizer` and
    /// `charset-normalizer` are the same package.
    #[test]
    fn a_name_is_normalised() {
        let locked = requirements("Charset_Normalizer==3.5.1\n").expect("a pin");
        assert_eq!(names(&locked), ["charset-normalizer@3.5.1"]);
    }

    /// A file that is not what its name says says so, rather than reading as no packages.
    #[test]
    fn a_lockfile_that_does_not_parse_is_an_error() {
        assert!(uv("{not toml").is_err());
        assert!(poetry("{not toml").is_err());
        assert!(pipenv("not json").is_err());
    }
}
