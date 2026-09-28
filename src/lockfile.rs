//! Package versions from a lockfile, for `waharoa policy diff`.
//!
//! The file name chooses the reader. Each row of [`crate::ecosystem::TABLE`] lists the
//! lockfile names its ecosystem's clients write, in `lockfiles`, and the reader for each.
//! A name no row lists is refused, naming every name that is read.
//!
//! See docs/engineering_decisions/policy-diff-lockfiles.md.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::ecosystem::TABLE;

/// Ecosystem, name and version, as `audit::packages` gives them.
pub type Locked = (String, String, String);

/// One locked version: its purl, the package it names, and the version.
pub type Reference = (String, crate::identity::PackageRef, String);

/// `listed`, each version once, with its purl. A name that makes no purl is left out.
pub fn references(listed: impl IntoIterator<Item = Locked>) -> Vec<Reference> {
    let mut seen = std::collections::HashSet::new();
    listed
        .into_iter()
        .filter(|package| seen.insert(package.clone()))
        .filter_map(|(ecosystem, name, version)| {
            let purl = format!("pkg:{ecosystem}/{name}@{version}");
            let reference = purl.parse::<crate::identity::PackageRef>().ok()?;
            Some((purl, reference, version))
        })
        .collect()
}

/// Every registry package version one lockfile's text locks, or why it cannot be read.
pub type Reader = fn(&str) -> Result<BTreeSet<Locked>, String>;

/// One lockfile a client writes: its file name and the reader for it.
pub struct Lockfile {
    pub name: &'static str,
    pub read: Reader,
    /// How the file records artifact URLs, for `waharoa doctor`. `None` for a file doctor
    /// does not check.
    pub pins: Option<Pins>,
}

/// How a lockfile records the absolute artifact URLs it pins.
pub struct Pins {
    /// The key written before each URL on its line, as `<key>: <url>` or `<key> "<url>"`.
    pub key: &'static str,
    /// What `doctor` reports for a file that records no URL.
    pub when_absent: &'static str,
    /// How to write the file again through the proxy.
    pub reinstall: &'static str,
}

/// A file name no reader takes, with why and what to write instead.
pub struct Unread {
    pub name: &'static str,
    pub reason: &'static str,
}

/// Why a lockfile gave no packages.
#[derive(Debug)]
pub enum LockfileError {
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    /// A file name that chooses no reader.
    Unknown(PathBuf),
    Invalid {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for LockfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Unknown(path) => match unread(path) {
                Some(unread) => write!(f, "{}: {}", path.display(), unread.reason),
                None => {
                    let names: Vec<&str> = lockfiles().map(|lockfile| lockfile.name).collect();
                    write!(
                        f,
                        "{}: a lockfile is read only under one of these names: {}",
                        path.display(),
                        names.join(", ")
                    )
                }
            },
            Self::Invalid { path, reason } => write!(f, "{}: {reason}", path.display()),
        }
    }
}

impl std::error::Error for LockfileError {}

/// Every lockfile any ecosystem reads, in table order.
fn lockfiles() -> impl Iterator<Item = &'static Lockfile> {
    TABLE.iter().flat_map(|registry| registry.lockfiles)
}

/// Every lockfile that records artifact URLs, with how it records them.
pub fn pinning() -> impl Iterator<Item = (&'static Lockfile, &'static Pins)> {
    lockfiles().filter_map(|lockfile| Some((lockfile, lockfile.pins.as_ref()?)))
}

/// What a row says about a file name it does not read, if any row does.
fn unread(path: &Path) -> Option<&'static Unread> {
    let name = path.file_name()?;
    TABLE
        .iter()
        .flat_map(|registry| registry.unread_lockfiles)
        .find(|unread| name == unread.name)
}

/// Every registry package version the lockfile at `path` locks, each once, sorted.
pub fn read(path: &Path) -> Result<Vec<Locked>, LockfileError> {
    let name = path.file_name().and_then(|n| n.to_str());
    let Some(lockfile) = lockfiles().find(|lockfile| Some(lockfile.name) == name) else {
        return Err(LockfileError::Unknown(path.to_owned()));
    };
    let text = std::fs::read_to_string(path).map_err(|error| LockfileError::Io {
        path: path.to_owned(),
        error,
    })?;
    (lockfile.read)(&text)
        .map(|locked| locked.into_iter().collect())
        .map_err(|reason| LockfileError::Invalid {
            path: path.to_owned(),
            reason,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_support::tempdir;

    fn npm(name: &str, version: &str) -> Locked {
        ("npm".to_owned(), name.to_owned(), version.to_owned())
    }

    #[test]
    fn each_manager_locking_the_same_project_gives_the_same_packages() {
        let expected: Vec<Locked> = [
            ("@babel/code-frame", "7.22.13"),
            ("@babel/helper-validator-identifier", "7.29.7"),
            ("@babel/highlight", "7.25.9"),
            ("ansi-styles", "3.2.1"),
            ("chalk", "2.4.2"),
            ("color-convert", "1.9.3"),
            ("color-name", "1.1.3"),
            ("escape-string-regexp", "1.0.5"),
            ("has-flag", "3.0.0"),
            ("js-tokens", "4.0.0"),
            ("lodash", "4.17.20"),
            ("lodash", "4.17.21"),
            ("minimist", "1.2.5"),
            ("picocolors", "1.1.1"),
            ("supports-color", "5.5.0"),
        ]
        .into_iter()
        .map(|(name, version)| npm(name, version))
        .collect();
        for (dir, name) in [
            ("npm", "package-lock.json"),
            ("yarn", "yarn.lock"),
            ("pnpm", "pnpm-lock.yaml"),
            ("bun", "bun.lock"),
            ("bun-1.1", "bun.lock"),
        ] {
            let path = PathBuf::from(format!(
                "{}/tests/fixtures/lockfiles/{dir}/{name}",
                env!("CARGO_MANIFEST_DIR")
            ));
            assert_eq!(read(&path).expect(name), expected, "{name}");
        }
    }

    #[test]
    fn a_file_is_refused_by_its_name_and_by_what_it_contains() {
        let dir = tempdir("lockfile-read");
        let unknown = read(&dir.join("deps.txt")).expect_err("no reader");
        assert!(matches!(unknown, LockfileError::Unknown(_)));
        assert_eq!(
            unknown.to_string(),
            format!(
                "{}: a lockfile is read only under one of these names: package-lock.json, \
                 npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, uv.lock, \
                 poetry.lock, requirements.txt, Pipfile.lock",
                dir.join("deps.txt").display()
            )
        );
        assert_eq!(
            read(&dir.join("bun.lockb"))
                .expect_err("binary")
                .to_string(),
            format!(
                "{}: bun.lockb is binary; `bun install --save-text-lockfile` writes bun.lock",
                dir.join("bun.lockb").display()
            )
        );

        let absent = read(&dir.join("yarn.lock")).expect_err("not written");
        assert!(matches!(absent, LockfileError::Io { .. }), "{absent:?}");

        let path = dir.join("npm-shrinkwrap.json");
        std::fs::write(&path, r#"{"lockfileVersion": 1}"#).expect("writes");
        assert_eq!(
            read(&path).expect_err("version 1").to_string(),
            format!(
                "{}: lockfileVersion 1 is not read; npm 7 and later write 2 or 3",
                path.display()
            )
        );
    }
}
