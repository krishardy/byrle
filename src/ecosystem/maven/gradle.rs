//! Gradle, as `byrle doctor` checks it, from the text of the init scripts in its user home.
//! Gradle does not read `settings.xml`, and its repositories are code; doctor reads each
//! `http://` and `https://` URL an init script writes whole. See docs/maven-plan.md, step 7.

use std::path::{Path, PathBuf};

use crate::doctor::{
    CacheBypass, CacheLocation, Client, Finding, Indexes, Machine, RegistrySource, Severity,
};
use crate::env::EnvError;

use super::PORTAL;

pub const GRADLE: Client = Client {
    name: "gradle",
    version_args: &["--version"],
    registry: Some(RegistrySource::Read {
        read: gradle_indexes,
        set_index: init_script,
        drop_extra: || {
            "replace the plugin portal with the proxy's /gradle-plugins/ in the init script"
                .to_owned()
        },
    }),
    set_registry: "",
    cache: CacheLocation::Read(modules),
    bypass: CacheBypass::Complete,
    clear_cache: "remove caches/modules-2 in the Gradle user home, or build with \
                  --refresh-dependencies",
    settings: Some(gradle_settings),
    found: Some(found),
};

/// Where `mavenCentral()` asks.
const CENTRAL_URL: &str = "https://repo.maven.apache.org/maven2";

/// The wrapper's properties, relative to the root project.
const WRAPPER: &str = "gradle/wrapper/gradle-wrapper.properties";

/// The fix for a build not pointed at the proxy: `url` is its `/maven` repository.
fn init_script(url: &str) -> String {
    let base = url.strip_suffix("/maven").unwrap_or(url);
    format!(
        "add an init script to init.d/ in the Gradle user home that replaces every \
         repository with {base}/maven/ and the plugin portal with {base}/gradle-plugins/"
    )
}

/// Whether a project at `dir` or above it has a Gradle wrapper, or `gradle` runs.
fn found(machine: &Machine) -> bool {
    machine
        .dir
        .ancestors()
        .any(|dir| dir.join(WRAPPER).is_file())
        || (machine.run)(GRADLE.name, GRADLE.version_args).is_some()
}

/// [`crate::env::GRADLE_DIR`], else `~/.gradle`.
fn user_home(machine: &Machine) -> Result<Option<PathBuf>, EnvError> {
    let environment = machine.environment;
    Ok(match environment.gradle_user_home()? {
        Some(home) => Some(home),
        None => environment.home()?.map(|home| home.join(".gradle")),
    })
}

/// The init scripts Gradle runs from `home`: `init.gradle` or `init.gradle.kts`, then each
/// `.gradle` or `.gradle.kts` file in `init.d/`, by name.
pub fn init_scripts(home: &Path) -> Vec<PathBuf> {
    let is_script = |path: &Path| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        path.is_file() && (name.ends_with(".gradle") || name.ends_with(".gradle.kts"))
    };
    let mut listed: Vec<PathBuf> = std::fs::read_dir(home.join("init.d"))
        .map(|entries| entries.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    listed.sort();
    ["init.gradle", "init.gradle.kts"]
        .iter()
        .map(|name| home.join(name))
        .chain(listed)
        .filter(|path| is_script(path))
        .collect()
}

/// Each `http://` and `https://` URL `text` writes, up to a quote, a space or a bracket.
pub fn urls(text: &str) -> Vec<String> {
    text.match_indices("http")
        .map(|(start, _)| {
            text[start..]
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ')' | '}' | ','))
                .collect::<String>()
        })
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .collect()
}

/// The first of `urls` whose path is `path`, with or without a trailing slash.
fn at_path<'a>(urls: &'a [String], path: &str) -> Option<&'a String> {
    urls.iter().find(|url| {
        reqwest::Url::parse(url).is_ok_and(|parsed| parsed.path().trim_end_matches('/') == path)
    })
}

/// The URL the scripts give Central's place, and the one they give the portal's. Central's
/// and the portal's own when no script names a `/maven` or `/gradle-plugins` URL.
pub fn indexes(urls: &[String]) -> Indexes {
    let named = |path: &str, otherwise: &str| {
        at_path(urls, path).map_or_else(|| otherwise.to_owned(), Clone::clone)
    };
    Indexes {
        index: named("/maven", CENTRAL_URL),
        extra: vec![named("/gradle-plugins", PORTAL)],
    }
}

/// What doctor reads of Gradle's init scripts: each one's path and text.
fn read(machine: &Machine) -> Result<Option<Vec<(PathBuf, String)>>, EnvError> {
    if !found(machine) {
        return Ok(None);
    }
    let scripts = user_home(machine)?.map_or_else(Vec::new, |home| init_scripts(&home));
    Ok(Some(
        scripts
            .into_iter()
            .filter_map(|path| Some((path.clone(), std::fs::read_to_string(path).ok()?)))
            .collect(),
    ))
}

fn gradle_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    Ok(read(machine)?.map(|scripts| {
        let urls: Vec<String> = scripts.iter().flat_map(|(_, text)| urls(text)).collect();
        indexes(&urls)
    }))
}

/// `caches/modules-2` in the Gradle user home.
fn modules(machine: &Machine) -> Result<Option<PathBuf>, EnvError> {
    Ok(user_home(machine)?.map(|home| home.join("caches/modules-2")))
}

fn gradle_settings(machine: &Machine, tokens: Option<bool>) -> Vec<Finding> {
    match read(machine) {
        Ok(Some(scripts)) => settings(&scripts, tokens),
        _ => Vec::new(),
    }
}

/// Which init scripts were read, and when the proxy requires tokens, whether one sets
/// `credentials`.
pub fn settings(scripts: &[(PathBuf, String)], tokens: Option<bool>) -> Vec<Finding> {
    let title = "gradle init scripts";
    let mut findings = vec![if scripts.is_empty() {
        Finding::new(
            Severity::Ok,
            title,
            "none, so builds ask the repositories they declare",
        )
    } else {
        let read: Vec<String> = scripts
            .iter()
            .map(|(path, _)| path.display().to_string())
            .collect();
        Finding::new(Severity::Ok, title, format!("read {}", read.join(", ")))
    }];
    let credentials = scripts.iter().any(|(_, text)| text.contains("credentials"));
    if tokens == Some(true) && !scripts.is_empty() && !credentials {
        findings.push(
            Finding::new(
                Severity::Problem,
                "gradle credentials",
                "no init script sets `credentials`, so the proxy answers Gradle 401",
            )
            .with_fix(
                "add `credentials { username = ACCOUNT; password = TOKEN }` to each repository \
                 the init script adds",
            ),
        );
    }
    findings
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::{GRADLE_DIR, HOME_DIR};

    /// The init script the portal's live run used on 2026-10-17, from docs/maven-plan.md.
    const PORTAL_RUN: &str = "\
// Every repository and the plugin portal replaced with the mirror.
def central = 'http://127.0.0.1:18893/maven'
def portal = 'http://127.0.0.1:18893/gradle-plugins'
def only = { RepositoryHandler repos, String mirror ->
    repos.all { ArtifactRepository repo ->
        if (!(repo instanceof MavenArtifactRepository) || !repo.url.toString().startsWith(mirror)) {
            repos.remove(repo)
        }
    }
    repos.maven { url = mirror; allowInsecureProtocol = true }
}
beforeSettings { settings ->
    settings.pluginManagement.repositories { only(delegate, portal) }
}
allprojects {
    buildscript { only(repositories, portal) }
    only(repositories, central)
}
";

    #[test]
    fn the_init_script_s_urls_are_central_s_and_the_portal_s_places() {
        let found = urls(PORTAL_RUN);
        assert_eq!(
            found,
            [
                "http://127.0.0.1:18893/maven",
                "http://127.0.0.1:18893/gradle-plugins"
            ]
        );
        assert_eq!(
            indexes(&found),
            Indexes {
                index: "http://127.0.0.1:18893/maven".to_owned(),
                extra: vec!["http://127.0.0.1:18893/gradle-plugins".to_owned()],
            }
        );
        assert_eq!(
            indexes(&[]),
            Indexes {
                index: CENTRAL_URL.to_owned(),
                extra: vec![PORTAL.to_owned()],
            }
        );
    }

    #[test]
    fn a_url_ends_at_a_quote_a_space_or_a_bracket() {
        let text = "url = uri(\"https://a.example/maven/\")\nhttp\nurl 'http://b.example/gradle-plugins/',\
                    https://c.example/x}\n{https://d.example/y,";
        assert_eq!(
            urls(text),
            [
                "https://a.example/maven/",
                "http://b.example/gradle-plugins/",
                "https://c.example/x",
                "https://d.example/y",
            ]
        );
        let found = urls(text);
        assert_eq!(indexes(&found).index, "https://a.example/maven/");
        assert_eq!(indexes(&found).extra, ["http://b.example/gradle-plugins/"]);
        assert_eq!(at_path(&["not a url".to_owned()], "/maven"), None);
    }

    #[test]
    fn init_scripts_are_the_home_s_then_init_d_s_by_name() {
        let home = crate::util::test_support::tempdir("gradle-init");
        std::fs::create_dir_all(home.join("init.d/dir.gradle")).unwrap();
        for name in [
            "init.gradle.kts",
            "init.d/b.gradle",
            "init.d/a.gradle.kts",
            "init.d/notes.txt",
        ] {
            std::fs::write(home.join(name), "").unwrap();
        }
        assert_eq!(
            init_scripts(&home),
            [
                home.join("init.gradle.kts"),
                home.join("init.d/a.gradle.kts"),
                home.join("init.d/b.gradle"),
            ]
        );
        assert!(init_scripts(&home.join("absent")).is_empty());
    }

    #[test]
    fn the_fix_names_both_of_the_proxy_s_paths() {
        assert_eq!(
            init_script("https://byrle.example/maven"),
            "add an init script to init.d/ in the Gradle user home that replaces every \
             repository with https://byrle.example/maven/ and the plugin portal with \
             https://byrle.example/gradle-plugins/"
        );
        assert!(init_script("https://byrle.example").contains("https://byrle.example/maven/"));
        let RegistrySource::Read { drop_extra, .. } = GRADLE.registry.as_ref().unwrap() else {
            panic!("read from files");
        };
        assert_eq!(
            drop_extra(),
            "replace the plugin portal with the proxy's /gradle-plugins/ in the init script"
        );
    }

    fn scripts(text: &str) -> Vec<(PathBuf, String)> {
        vec![(PathBuf::from("/g/init.d/byrle.gradle"), text.to_owned())]
    }

    #[test]
    fn credentials_are_asked_for_only_when_the_proxy_requires_tokens() {
        let details = |scripts: &[(PathBuf, String)], tokens| -> Vec<(Severity, String)> {
            settings(scripts, tokens)
                .into_iter()
                .map(|finding| (finding.severity, finding.detail))
                .collect()
        };
        assert_eq!(
            details(&scripts(PORTAL_RUN), Some(true)),
            [
                (Severity::Ok, "read /g/init.d/byrle.gradle".to_owned()),
                (
                    Severity::Problem,
                    "no init script sets `credentials`, so the proxy answers Gradle 401".to_owned()
                ),
            ]
        );
        assert_eq!(details(&scripts(PORTAL_RUN), Some(false)).len(), 1);
        assert_eq!(details(&scripts(PORTAL_RUN), None).len(), 1);
        let with = scripts("credentials { username = 'a'; password = 't' }");
        assert_eq!(details(&with, Some(true)).len(), 1);
        assert_eq!(
            details(&[], Some(true)),
            [(
                Severity::Ok,
                "none, so builds ask the repositories they declare".to_owned()
            )]
        );
    }

    /// A project at `root/work/project`, `gradle` not on the path.
    fn project(label: &str) -> (PathBuf, PathBuf) {
        let root = crate::util::test_support::tempdir(label);
        let project = root.join("work/project");
        std::fs::create_dir_all(&project).unwrap();
        (root, project)
    }

    #[test]
    fn gradle_is_found_by_a_wrapper_above_the_directory_or_by_running() {
        let (root, project) = project("gradle-found");
        let environment = crate::env::testing::empty();
        let absent = Machine {
            environment: &environment,
            dir: &project,
            run: &|_, _| None,
        };
        assert!(!found(&absent));
        assert_eq!(gradle_indexes(&absent), Ok(None));
        assert!(gradle_settings(&absent, Some(true)).is_empty());
        let runs = Machine {
            run: &|program, args| (program == "gradle" && args == ["--version"]).then(String::new),
            ..absent
        };
        assert!(found(&runs));
        std::fs::create_dir_all(root.join("work/gradle/wrapper")).unwrap();
        std::fs::write(root.join("work").join(WRAPPER), "").unwrap();
        let wrapped = Machine {
            run: &|_, _| None,
            ..absent
        };
        assert!(found(&wrapped));
        assert_eq!(
            gradle_indexes(&wrapped).unwrap().map(|i| i.index),
            Some(CENTRAL_URL.to_owned()),
            "no home, so no script"
        );
    }

    /// [`GRADLE_DIR`] holds the scripts and the cache, else `~/.gradle` does.
    #[test]
    fn the_user_home_holds_the_scripts_and_the_cache() {
        let (root, project) = project("gradle-home");
        let run = |_: &str, _: &[&str]| Some("Gradle 9.8.1".to_owned());
        let gradle_home = root.join("gradle");
        let user = root.join("user");
        for home in [gradle_home.clone(), user.join(".gradle")] {
            std::fs::create_dir_all(home.join("init.d")).unwrap();
            std::fs::write(home.join("init.d/byrle.gradle"), PORTAL_RUN).unwrap();
        }
        std::fs::write(user.join(".gradle/init.d/unread.gradle"), [0xff]).unwrap();
        for (vars, home) in [
            (
                vec![(GRADLE_DIR, gradle_home.to_str().unwrap())],
                gradle_home.clone(),
            ),
            (
                vec![(HOME_DIR, user.to_str().unwrap())],
                user.join(".gradle"),
            ),
        ] {
            let environment = crate::env::testing::with(&vars);
            let machine = Machine {
                environment: &environment,
                dir: &project,
                run: &run,
            };
            assert_eq!(
                gradle_indexes(&machine).unwrap().unwrap().index,
                "http://127.0.0.1:18893/maven"
            );
            assert_eq!(
                modules(&machine).unwrap(),
                Some(home.join("caches/modules-2"))
            );
            let read = gradle_settings(&machine, None);
            assert_eq!(
                read[0].detail,
                format!("read {}", home.join("init.d/byrle.gradle").display()),
                "a script that is not UTF-8 is not read"
            );
        }
    }

    #[test]
    fn an_unreadable_home_is_an_error() {
        let (_, project) = project("gradle-unreadable");
        let run = |_: &str, _: &[&str]| Some("Gradle 9.8.1".to_owned());
        for unreadable in [GRADLE_DIR, HOME_DIR] {
            let environment = crate::env::testing::with_unreadable(&[], unreadable);
            let machine = Machine {
                environment: &environment,
                dir: &project,
                run: &run,
            };
            assert!(gradle_indexes(&machine).is_err(), "{}", unreadable.name);
            assert!(modules(&machine).is_err(), "{}", unreadable.name);
            assert!(gradle_settings(&machine, Some(true)).is_empty());
        }
    }

    /// What doctor prints for Gradle with no init script.
    #[test]
    fn gradle_without_an_init_script_is_reported_off_the_proxy() {
        let proxy = "http://127.0.0.1:8080";
        let found = indexes(&[]);
        let registry = crate::doctor::check_registry(&GRADLE, Some(&found.index), proxy);
        assert_eq!(
            registry.detail,
            "points at https://repo.maven.apache.org/maven2, not the proxy at \
             http://127.0.0.1:8080/maven"
        );
        assert_eq!(
            registry.fix.as_deref(),
            Some(
                "add an init script to init.d/ in the Gradle user home that replaces every \
                 repository with http://127.0.0.1:8080/maven/ and the plugin portal with \
                 http://127.0.0.1:8080/gradle-plugins/"
            )
        );
        let extra = crate::doctor::check_extra_indexes(&GRADLE, &found.extra, "fix", proxy);
        assert_eq!(
            extra.detail,
            "also asks https://plugins.gradle.org/m2, whose files never reach the proxy"
        );
    }
}
