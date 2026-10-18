//! `./mvnw`, as `byrle doctor` checks it, from `.mvn/wrapper/maven-wrapper.properties`.
//! mvnw downloads mvn from a Central path the proxy's `/maven/` serves, so it is checked as
//! a client of that path. Measured with Maven Wrapper 3.3.4 in docs/maven-plan.md, step 7.

use std::path::{Path, PathBuf};

use crate::doctor::{
    CacheBypass, CacheLocation, Client, Finding, Indexes, Machine, RegistrySource, Severity,
};
use crate::env::EnvError;

pub const MVNW: Client = Client {
    name: "mvnw",
    version_args: &[],
    registry: Some(RegistrySource::Read {
        read: mvnw_indexes,
        set_index: point_at,
        drop_extra: || {
            format!(
                "set wrapperUrl to the proxy's /maven/, or {}",
                crate::env::MVNW_BASE
            )
        },
    }),
    set_registry: "",
    cache: CacheLocation::Read(distributions),
    bypass: CacheBypass::Complete,
    clear_cache: "remove wrapper/dists in the Maven user home",
    settings: Some(mvnw_settings),
    found: Some(|machine| properties_path(machine.dir).is_some()),
};

/// The wrapper's properties, relative to the project.
const PROPERTIES: &str = ".mvn/wrapper/maven-wrapper.properties";

/// Where in a download URL mvnw puts [`crate::env::MVNW_BASE`] in place of what precedes it.
const SPLICE: &str = "/org/apache/maven/";

/// The fix for a wrapper not pointed at the proxy's `url`.
fn point_at(url: &str) -> String {
    format!(
        "set {}={url}, or the start of distributionUrl in {PROPERTIES} to {url}",
        crate::env::MVNW_BASE
    )
}

/// Java properties as `key=value`, `key: value` or `key value`, with `#` and `!` comments
/// and `\` escapes. A line ending in `\` is not joined to the next.
pub fn properties(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim_start)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', '!']))
        .map(|line| {
            let mut key = String::new();
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => key.extend(chars.next()),
                    '=' | ':' => break,
                    c if c.is_whitespace() => break,
                    c => key.push(c),
                }
            }
            let rest = chars.as_str().trim_start();
            let rest = rest.strip_prefix(['=', ':']).unwrap_or(rest).trim_start();
            (key, unescape(rest))
        })
        .collect()
}

fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// The value of `key` in `properties`, the last one set.
pub fn value<'a>(properties: &'a [(String, String)], key: &str) -> Option<&'a str> {
    properties
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// The nearest `.mvn/wrapper/maven-wrapper.properties` at or above `dir`.
fn properties_path(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .map(|dir| dir.join(PROPERTIES))
        .find(|path| path.is_file())
}

/// The base mvnw downloads `url` from: `base` in place of what precedes `/org/apache/maven/`,
/// as mvnw splices it, else `url` up to it.
pub fn download_base(url: &str, base: Option<&str>) -> String {
    let before = url.find(SPLICE).map_or(url, |at| &url[..at]);
    base.unwrap_or(before).trim_end_matches('/').to_owned()
}

/// What doctor reads of the wrapper: its properties and the environment's base.
struct Wrapper {
    properties: Vec<(String, String)>,
    base: Option<String>,
}

fn read(machine: &Machine) -> Result<Option<Wrapper>, EnvError> {
    let base = machine.environment.mvnw_repository()?;
    Ok(properties_path(machine.dir)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| Wrapper {
            properties: properties(&text),
            base,
        }))
}

fn mvnw_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    Ok(read(machine)?.map(|wrapper| indexes(&wrapper.properties, wrapper.base.as_deref())))
}

/// Where the distribution is downloaded from, and the wrapper's jar when one is.
pub fn indexes(properties: &[(String, String)], base: Option<&str>) -> Indexes {
    let at = |key: &str| value(properties, key).map(|url| download_base(url, base));
    Indexes {
        index: at("distributionUrl").unwrap_or_default(),
        extra: at("wrapperUrl").into_iter().collect(),
    }
}

/// `wrapper/dists` in the Maven user home, read as `~/.m2`.
fn distributions(machine: &Machine) -> Result<Option<PathBuf>, EnvError> {
    Ok(machine
        .environment
        .home()?
        .map(|home| home.join(".m2/wrapper/dists")))
}

fn mvnw_settings(machine: &Machine, tokens: Option<bool>) -> Vec<Finding> {
    let environment = machine.environment;
    match (read(machine), environment.mvnw_credentials()) {
        (Ok(Some(wrapper)), Ok(credentials)) => {
            settings(&wrapper.properties, tokens == Some(true) && !credentials)
        }
        _ => Vec::new(),
    }
}

/// Whether the distribution's sha256 is pinned, and whether mvnw lacks the credentials a
/// proxy requiring tokens asks for.
pub fn settings(properties: &[(String, String)], uncredentialed: bool) -> Vec<Finding> {
    let pinned = value(properties, "distributionSha256Sum").is_some_and(|sum| !sum.is_empty());
    let mut findings = vec![if pinned {
        Finding::new(
            Severity::Ok,
            "mvnw checksum",
            "distributionSha256Sum is set, so mvnw checks the distribution it downloads",
        )
    } else {
        Finding::new(
            Severity::Warn,
            "mvnw checksum",
            "no distributionSha256Sum, so nothing outside byrle checks the distribution",
        )
        .with_fix(format!(
            "set distributionSha256Sum in {PROPERTIES} to the sha256 of the .zip, or of the \
             .tar.gz when unzip is not installed, which mvnw downloads in its place"
        ))
    }];
    if uncredentialed {
        findings.push(
            Finding::new(
                Severity::Problem,
                "mvnw credentials",
                format!(
                    "{} and {} are not both set, so the proxy answers mvnw 401",
                    crate::env::MVNW_USER,
                    crate::env::MVNW_SECRET
                ),
            )
            .with_fix(format!(
                "set {} to the account and {} to the token",
                crate::env::MVNW_USER,
                crate::env::MVNW_SECRET
            )),
        );
    }
    findings
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::{HOME_DIR, MVNW_BASE, MVNW_SECRET, MVNW_USER};

    /// What `mvn -N wrapper:wrapper` wrote through the stub's mirror on 2026-10-18.
    const GENERATED: &str = "wrapperVersion=3.3.4
distributionType=only-script
distributionUrl=http://127.0.0.1:18891/maven2/org/apache/maven/apache-maven/3.10.0/apache-maven-3.10.0-bin.zip
";

    fn pairs(listed: &[(&str, &str)]) -> Vec<(String, String)> {
        listed
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn properties_are_read_with_their_escapes() {
        let read = properties(GENERATED);
        assert_eq!(value(&read, "distributionType"), Some("only-script"));
        assert_eq!(
            properties(
                "# a comment\n! another\n\ndistributionUrl=https\\://services.gradle.org/x.zip\n\
                 key: value\n  spaced  value \na\\=b=c\nempty=\nbare\nk=1\nk=2\n"
            ),
            pairs(&[
                ("distributionUrl", "https://services.gradle.org/x.zip"),
                ("key", "value"),
                ("spaced", "value "),
                ("a=b", "c"),
                ("empty", ""),
                ("bare", ""),
                ("k", "1"),
                ("k", "2"),
            ])
        );
        assert_eq!(value(&properties("k=1\nk=2\n"), "k"), Some("2"));
        assert_eq!(value(&read, "absent"), None);
        assert_eq!(unescape("a\\"), "a", "a trailing backslash escapes nothing");
    }

    /// mvnw puts its base in place of what precedes `/org/apache/maven/`.
    #[test]
    fn the_download_base_is_the_url_before_central_s_path() {
        let url = value(&properties(GENERATED), "distributionUrl")
            .unwrap()
            .to_owned();
        assert_eq!(download_base(&url, None), "http://127.0.0.1:18891/maven2");
        assert_eq!(
            download_base(&url, Some("https://byrle.example/maven/")),
            "https://byrle.example/maven"
        );
        assert_eq!(
            download_base("https://x.example/a.zip", None),
            "https://x.example/a.zip"
        );
        assert_eq!(
            indexes(&properties(GENERATED), None),
            Indexes {
                index: "http://127.0.0.1:18891/maven2".to_owned(),
                extra: Vec::new(),
            }
        );
        let jarred = pairs(&[
            ("distributionUrl", &url),
            (
                "wrapperUrl",
                "https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.4/maven-wrapper-3.3.4.jar",
            ),
        ]);
        assert_eq!(
            indexes(&jarred, None).extra,
            ["https://repo.maven.apache.org/maven2"]
        );
        assert_eq!(indexes(&[], None).index, "");
    }

    #[test]
    fn a_wrapper_off_the_proxy_is_told_both_ways_to_point_it_there() {
        let proxy = "http://127.0.0.1:8080";
        let found = indexes(&properties(GENERATED), None);
        let registry = crate::doctor::check_registry(&MVNW, Some(&found.index), proxy);
        assert_eq!(registry.severity, Severity::Problem);
        assert_eq!(
            registry.fix,
            Some(format!(
                "set {MVNW_BASE}=http://127.0.0.1:8080/maven, or the start of distributionUrl \
                 in .mvn/wrapper/maven-wrapper.properties to http://127.0.0.1:8080/maven"
            ))
        );
        let at_proxy = indexes(&properties(GENERATED), Some("http://127.0.0.1:8080/maven"));
        assert_eq!(
            crate::doctor::check_registry(&MVNW, Some(&at_proxy.index), proxy).severity,
            Severity::Ok
        );
        let RegistrySource::Read { drop_extra, .. } = MVNW.registry.as_ref().unwrap() else {
            panic!("read from files");
        };
        assert_eq!(
            drop_extra(),
            format!("set wrapperUrl to the proxy's /maven/, or {MVNW_BASE}")
        );
    }

    #[test]
    fn a_pinned_sha256_and_credentials_are_reported() {
        let shown = |properties: &[(String, String)], uncredentialed| -> Vec<(Severity, String)> {
            settings(properties, uncredentialed)
                .into_iter()
                .map(|finding| (finding.severity, finding.detail))
                .collect()
        };
        assert_eq!(
            shown(&properties(GENERATED), true),
            [
                (
                    Severity::Warn,
                    "no distributionSha256Sum, so nothing outside byrle checks the distribution"
                        .to_owned()
                ),
                (
                    Severity::Problem,
                    format!(
                        "{MVNW_USER} and {MVNW_SECRET} are not both set, so the proxy answers \
                         mvnw 401"
                    )
                ),
            ]
        );
        let pinned = pairs(&[("distributionSha256Sum", "a46cc51b")]);
        assert_eq!(
            shown(&pinned, false),
            [(
                Severity::Ok,
                "distributionSha256Sum is set, so mvnw checks the distribution it downloads"
                    .to_owned()
            )]
        );
        let empty = pairs(&[("distributionSha256Sum", "")]);
        assert_eq!(shown(&empty, false)[0].0, Severity::Warn);
        let fixes: Vec<Option<String>> = settings(&properties(GENERATED), true)
            .into_iter()
            .map(|finding| finding.fix)
            .collect();
        assert_eq!(
            fixes,
            [
                Some(
                    "set distributionSha256Sum in .mvn/wrapper/maven-wrapper.properties to the \
                     sha256 of the .zip, or of the .tar.gz when unzip is not installed, which \
                     mvnw downloads in its place"
                        .to_owned()
                ),
                Some(format!(
                    "set {MVNW_USER} to the account and {MVNW_SECRET} to the token"
                )),
            ]
        );
    }

    /// The wrapper is the nearest one at or above the directory, with the environment's base.
    #[test]
    fn the_nearest_wrapper_is_read_with_the_environment() {
        let root = crate::util::test_support::tempdir("mvnw");
        let project = root.join("work/project");
        std::fs::create_dir_all(&project).unwrap();
        let environment = crate::env::testing::empty();
        let machine = Machine {
            environment: &environment,
            dir: &project,
            run: &|_, _| None,
        };
        assert!(!(MVNW.found.unwrap())(&machine));
        assert_eq!(mvnw_indexes(&machine), Ok(None));
        assert!(mvnw_settings(&machine, Some(true)).is_empty());
        std::fs::create_dir_all(root.join("work/.mvn/wrapper")).unwrap();
        std::fs::write(root.join("work").join(PROPERTIES), GENERATED).unwrap();
        assert!((MVNW.found.unwrap())(&machine));
        assert_eq!(
            mvnw_indexes(&machine).unwrap().unwrap().index,
            "http://127.0.0.1:18891/maven2"
        );
        assert_eq!(mvnw_settings(&machine, Some(true)).len(), 2);
        assert_eq!(mvnw_settings(&machine, Some(false)).len(), 1);
        let set = crate::env::testing::with(&[
            (MVNW_BASE, "https://byrle.example/maven"),
            (MVNW_USER, "alice"),
            (MVNW_SECRET, "t0k"),
            (HOME_DIR, "/home/u"),
        ]);
        let configured = Machine {
            environment: &set,
            ..machine
        };
        assert_eq!(
            mvnw_indexes(&configured).unwrap().unwrap().index,
            "https://byrle.example/maven"
        );
        assert_eq!(mvnw_settings(&configured, Some(true)).len(), 1);
        assert_eq!(
            distributions(&configured).unwrap(),
            Some(PathBuf::from("/home/u/.m2/wrapper/dists"))
        );
        for unreadable in [MVNW_BASE, MVNW_USER, MVNW_SECRET] {
            let environment = crate::env::testing::with_unreadable(&[(MVNW_USER, "a")], unreadable);
            let broken = Machine {
                environment: &environment,
                ..machine
            };
            assert!(
                mvnw_settings(&broken, Some(true)).is_empty(),
                "{}",
                unreadable.name
            );
        }
        let environment = crate::env::testing::with_unreadable(&[], MVNW_BASE);
        let broken = Machine {
            environment: &environment,
            ..machine
        };
        assert!(mvnw_indexes(&broken).is_err());
        let environment = crate::env::testing::with_unreadable(&[], HOME_DIR);
        let broken = Machine {
            environment: &environment,
            ..machine
        };
        assert!(distributions(&broken).is_err());
    }
}
