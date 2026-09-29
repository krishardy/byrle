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

/// Every registry artifact one lockfile's text locks, with where each is fetched and the
/// platforms it installs on, or why it cannot be read.
pub type ArtifactReader = fn(&str) -> Result<Vec<LockedArtifact>, String>;

/// One artifact a lockfile locks, for `waharoa warm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedArtifact {
    pub locked: Locked,
    /// The artifact's path on a registry, which the proxy serves at the same path.
    pub path: String,
    pub platform: Platform,
}

/// The platforms a locked package installs on, as npm records them. An empty list allows
/// every value; a value starting `!` excludes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Platform {
    pub os: Vec<String>,
    pub cpu: Vec<String>,
    pub libc: Vec<String>,
}

/// One platform an install runs on, in npm's names: `linux`, `x64`, `glibc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub os: String,
    pub cpu: String,
    /// `None` off Linux, where npm does not check it.
    pub libc: Option<String>,
}

impl Platform {
    /// Whether a package with this platform installs on `target`.
    pub fn allows(&self, target: &Target) -> bool {
        let allows = |values: &[String], value: &str| {
            let excluded = values.iter().any(|v| v.strip_prefix('!') == Some(value));
            let listed: Vec<&String> = values.iter().filter(|v| !v.starts_with('!')).collect();
            !excluded && (listed.is_empty() || listed.iter().any(|v| *v == value))
        };
        allows(&self.os, &target.os)
            && allows(&self.cpu, &target.cpu)
            && target
                .libc
                .as_deref()
                .is_none_or(|libc| allows(&self.libc, libc))
    }
}

impl Target {
    /// The platform this build runs on.
    pub fn this_machine() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            "windows" => "win32",
            other => other,
        };
        let cpu = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            "x86" => "ia32",
            other => other,
        };
        let libc = if cfg!(target_env = "musl") {
            "musl"
        } else {
            "glibc"
        };
        let libc = (os == "linux").then_some(libc);
        Self {
            os: os.to_owned(),
            cpu: cpu.to_owned(),
            libc: libc.map(str::to_owned),
        }
    }

    /// `<os>-<cpu>` or `<os>-<cpu>-<libc>`, such as `linux-x64-musl`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let parts: Vec<&str> = value.split('-').collect();
        let (os, cpu, libc) = match parts.as_slice() {
            [os, cpu] => (*os, *cpu, None),
            [os, cpu, libc] => (*os, *cpu, Some(*libc)),
            _ => return Err(format!("`{value}` is not <os>-<cpu> or <os>-<cpu>-<libc>")),
        };
        let libc = libc
            .map(str::to_owned)
            .or_else(|| (os == "linux").then(|| "glibc".to_owned()));
        Ok(Self {
            os: os.to_owned(),
            cpu: cpu.to_owned(),
            libc,
        })
    }
}

/// One lockfile a client writes: its file name and the reader for it.
pub struct Lockfile {
    pub name: &'static str,
    pub read: Reader,
    /// Where each locked artifact is fetched and the platforms it installs on. `None` for
    /// a format that records neither.
    pub artifacts: Option<ArtifactReader>,
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
/// The artifacts the lockfile at `path` locks. `None` for a format with no artifact
/// reader.
pub fn artifacts(path: &Path) -> Result<Option<Vec<LockedArtifact>>, LockfileError> {
    let lockfile = lockfile_for(path)?;
    let Some(artifacts) = lockfile.artifacts else {
        return Ok(None);
    };
    artifacts(&text_of(path)?)
        .map(Some)
        .map_err(|reason| LockfileError::Invalid {
            path: path.to_owned(),
            reason,
        })
}

fn lockfile_for(path: &Path) -> Result<&'static Lockfile, LockfileError> {
    let name = path.file_name().and_then(|n| n.to_str());
    lockfiles()
        .find(|lockfile| Some(lockfile.name) == name)
        .ok_or_else(|| LockfileError::Unknown(path.to_owned()))
}

fn text_of(path: &Path) -> Result<String, LockfileError> {
    std::fs::read_to_string(path).map_err(|error| LockfileError::Io {
        path: path.to_owned(),
        error,
    })
}

pub fn read(path: &Path) -> Result<Vec<Locked>, LockfileError> {
    let lockfile = lockfile_for(path)?;
    let text = text_of(path)?;
    (lockfile.read)(&text)
        .map(|locked| locked.into_iter().collect())
        .map_err(|reason| LockfileError::Invalid {
            path: path.to_owned(),
            reason,
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::util::test_support::tempdir;

    fn platform(os: &[&str], cpu: &[&str], libc: &[&str]) -> Platform {
        let owned = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect();
        Platform {
            os: owned(os),
            cpu: owned(cpu),
            libc: owned(libc),
        }
    }

    /// npm's rules: an empty list allows all, a listed value is required, `!` excludes, and
    /// libc is read only on Linux.
    #[test]
    fn a_platform_allows_a_target_as_npm_does() {
        let linux = Target::parse("linux-x64").unwrap();
        let musl = Target::parse("linux-x64-musl").unwrap();
        let mac = Target::parse("darwin-arm64").unwrap();

        assert!(Platform::default().allows(&linux));
        assert!(platform(&["linux"], &["x64"], &[]).allows(&linux));
        assert!(!platform(&["darwin"], &[], &[]).allows(&linux));
        assert!(!platform(&[], &["arm64"], &[]).allows(&linux));
        assert!(platform(&["!win32"], &[], &[]).allows(&linux));
        assert!(!platform(&["!linux"], &[], &[]).allows(&linux));
        assert!(!platform(&["linux"], &[], &["musl"]).allows(&linux));
        assert!(platform(&["linux"], &[], &["musl"]).allows(&musl));
        assert!(
            platform(&[], &[], &["glibc"]).allows(&mac),
            "libc is Linux's only"
        );
    }

    #[test]
    fn a_target_is_os_cpu_and_on_linux_libc() {
        assert_eq!(
            Target::parse("linux-x64").unwrap(),
            Target {
                os: "linux".to_owned(),
                cpu: "x64".to_owned(),
                libc: Some("glibc".to_owned()),
            }
        );
        assert_eq!(Target::parse("darwin-arm64").unwrap().libc, None);
        assert_eq!(
            Target::parse("linux-arm64-musl").unwrap().libc.as_deref(),
            Some("musl")
        );
        assert!(Target::parse("linux").is_err());
        assert!(Target::parse("a-b-c-d").is_err());
        let here = Target::this_machine();
        assert_eq!(here.libc.is_some(), here.os == "linux");
        assert!(!here.os.is_empty() && !here.cpu.is_empty());
    }

    /// A format with no artifact reader answers `None`, and an unknown one an error.
    #[test]
    fn artifacts_are_read_only_where_a_format_records_them() {
        let dir = tempdir("lockfile-artifacts");
        let requirements = dir.join("requirements.txt");
        std::fs::write(&requirements, "six==1.17.0\n").unwrap();
        assert_eq!(artifacts(&requirements).unwrap(), None);
        assert!(matches!(
            artifacts(&dir.join("Gemfile.lock")),
            Err(LockfileError::Unknown(_))
        ));
        let broken = dir.join("package-lock.json");
        std::fs::write(&broken, "{").unwrap();
        assert!(matches!(
            artifacts(&broken),
            Err(LockfileError::Invalid { .. })
        ));
        assert!(matches!(
            artifacts(&dir.join("missing").join("package-lock.json")),
            Err(LockfileError::Io { .. })
        ));
    }

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
