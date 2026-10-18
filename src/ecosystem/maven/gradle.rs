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
    let Ok(Some(scripts)) = read(machine) else {
        return Vec::new();
    };
    let mut findings = settings(&scripts, tokens);
    if let Some(root) = project_root(machine.dir) {
        let text = std::fs::read_to_string(root.join(VERIFICATION)).ok();
        findings.push(verification(text.as_deref().map(verifies_signatures)));
    }
    findings
}

/// Where a build commits what Gradle checks each file against, relative to the root project.
const VERIFICATION: &str = "gradle/verification-metadata.xml";

/// The root project at `dir` or above it: the nearest holding a wrapper or a settings script.
fn project_root(dir: &Path) -> Option<&Path> {
    dir.ancestors().find(|dir| {
        [WRAPPER, "settings.gradle", "settings.gradle.kts"]
            .iter()
            .any(|name| dir.join(name).is_file())
    })
}

/// Whether a `verification-metadata.xml` sets `<verify-signatures>` true. Errors when it is
/// not well-formed XML.
pub fn verifies_signatures(text: &str) -> Result<bool, String> {
    let mut reader = quick_xml::Reader::from_str(text);
    let mut path: Vec<String> = Vec::new();
    let mut verifies = false;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            quick_xml::events::Event::Start(start) => {
                path.push(start.local_name().as_ref().to_owned());
            }
            quick_xml::events::Event::Text(t) if path == SIGNATURES => {
                verifies = t.xml10_content().trim() == "true";
            }
            quick_xml::events::Event::End(_) => {
                path.pop();
            }
            quick_xml::events::Event::Eof => return Ok(verifies),
            _ => {}
        }
    }
}

/// Where `<verify-signatures>` is in a `verification-metadata.xml`.
const SIGNATURES: &[&str] = &[
    "verification-metadata",
    "configuration",
    "verify-signatures",
];

/// Whether files byrle serves are checked against something recorded outside it: PGP
/// signatures with keys from key servers. `read` is `None` when the file is absent.
pub fn verification(read: Option<Result<bool, String>>) -> Finding {
    let title = "gradle verification";
    let fix = format!(
        "run `./gradlew --write-verification-metadata pgp,sha256 help` with keys.openpgp.org \
         and keyserver.ubuntu.com in <key-servers>, and commit {VERIFICATION}"
    );
    match read {
        Some(Ok(true)) => Finding::new(
            Severity::Ok,
            title,
            format!("{VERIFICATION} verifies PGP signatures, with keys from key servers"),
        ),
        Some(Ok(false)) => Finding::new(
            Severity::Warn,
            title,
            format!(
                "{VERIFICATION} checks digests only, which record what was served when they \
                 were written"
            ),
        )
        .with_fix(fix),
        Some(Err(error)) => Finding::new(
            Severity::Problem,
            title,
            format!("{VERIFICATION} is not well-formed XML: {error}"),
        ),
        None => Finding::new(
            Severity::Warn,
            title,
            format!("no {VERIFICATION}, so nothing outside byrle checks the files it serves"),
        )
        .with_fix(fix),
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

/// The Gradle releases services.gradle.org lists, for the wrapper's checks.
pub const VERSIONS: &str = "https://services.gradle.org/versions/all";

/// The wrapper's jar, beside its properties.
const WRAPPER_JAR: &str = "gradle/wrapper/gradle-wrapper.jar";

/// One release in [`VERSIONS`]. 149 of 532 had no `wrapperChecksum` on 2026-10-18.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub version: String,
    /// When it was built, as `yyyyMMddHHmmss+0000`.
    pub build_time: String,
    pub download_url: String,
    /// The `-bin` zip's sha256.
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub wrapper_checksum: Option<String>,
    #[serde(default)]
    pub nightly: bool,
    #[serde(default)]
    pub snapshot: bool,
}

/// What doctor reads of a project's Gradle wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapper {
    /// The file name `distributionUrl` ends with, such as `gradle-9.8.1-bin.zip`.
    pub distribution: String,
    pub sha256: Option<String>,
    /// The jar's sha256, `None` when there is no jar.
    pub jar: Option<String>,
}

/// The wrapper of the root project at or above `dir`, when it has one.
pub fn wrapper(dir: &Path) -> Option<Wrapper> {
    let root = project_root(dir)?;
    let text = std::fs::read_to_string(root.join(WRAPPER)).ok()?;
    let properties = super::wrapper::properties(&text);
    let value = |key| super::wrapper::value(&properties, key).filter(|v| !v.is_empty());
    let url = value("distributionUrl")?;
    let jar = std::fs::read(root.join(WRAPPER_JAR)).ok().map(|bytes| {
        use sha2::Digest as _;
        crate::util::hex(&sha2::Sha256::digest(bytes))
    });
    Some(Wrapper {
        distribution: url.rsplit('/').next().unwrap_or(url).to_owned(),
        sha256: value("distributionSha256Sum").map(str::to_owned),
        jar,
    })
}

/// The release whose `-bin` zip is `distribution`'s, `-all` read as `-bin`.
pub fn release_of<'a>(releases: &'a [Release], distribution: &str) -> Option<&'a Release> {
    let bin = distribution.replace("-all.zip", "-bin.zip");
    releases
        .iter()
        .find(|release| release.download_url.rsplit('/').next() == Some(bin.as_str()))
}

/// Where an `-all` distribution's sha256 is: only at its `.sha256` URL.
pub fn all_checksum_url(release: &Release) -> String {
    format!(
        "{}.sha256",
        release.download_url.replace("-bin.zip", "-all.zip")
    )
}

/// What a wrapper is checked against.
pub struct Known<'a> {
    /// The releases, or why they were not fetched.
    pub releases: Result<&'a [Release], &'a str>,
    /// An `-all` distribution's sha256, when it was fetched.
    pub all_sha256: Option<&'a str>,
    pub today: jiff::civil::Date,
    pub cooldown_days: u32,
}

/// Q9's four checks: the jar is a release's, the distribution's sha256 is pinned and is
/// the release's, and the release was built outside the cooldown.
pub fn check_wrapper(wrapper: &Wrapper, known: &Known) -> Vec<Finding> {
    let releases = match known.releases {
        Ok(releases) => releases,
        Err(why) => {
            return vec![Finding::new(
                Severity::Warn,
                "gradle wrapper",
                format!("not checked: {VERSIONS} {why}"),
            )];
        }
    };
    let own = release_of(releases, &wrapper.distribution);
    let mut findings = vec![jar_finding(wrapper.jar.as_deref(), releases, own)];
    let Some(release) = own else {
        findings.push(Finding::new(
            Severity::Warn,
            "gradle distribution",
            format!("{} is no release {VERSIONS} lists", wrapper.distribution),
        ));
        return findings;
    };
    let expected = if wrapper.distribution.ends_with("-all.zip") {
        known.all_sha256
    } else {
        release.checksum.as_deref()
    };
    findings.push(sum_finding(wrapper, expected));
    findings.extend(cooldown_finding(release, known.today, known.cooldown_days));
    findings
}

/// Whether the jar `./gradlew` runs is one Gradle released. Gradle 9.8.1 wrote its own jar
/// for `--gradle-version 8.14.3`, so any release's `wrapperChecksum` matches: `own`'s
/// first, then a release that is not a nightly or snapshot, which share their jars.
fn jar_finding(jar: Option<&str>, releases: &[Release], own: Option<&Release>) -> Finding {
    let title = "gradle wrapper jar";
    let Some(jar) = jar else {
        return Finding::new(Severity::Problem, title, format!("no {WRAPPER_JAR}"));
    };
    let matching = |release: &&Release| release.wrapper_checksum.as_deref() == Some(jar);
    let released = |release: &&Release| !(release.nightly || release.snapshot);
    match own
        .filter(matching)
        .or_else(|| releases.iter().filter(released).find(matching))
        .or_else(|| releases.iter().find(matching))
    {
        Some(release) => Finding::new(
            Severity::Ok,
            title,
            format!("Gradle {}'s, by its sha256", release.version),
        ),
        None => Finding::new(
            Severity::Problem,
            title,
            format!("its sha256, {jar}, is no release's wrapperChecksum in {VERSIONS}"),
        )
        .with_fix("run `gradle wrapper` with a Gradle installed and checked by its sha256"),
    }
}

/// Whether `distributionSha256Sum` pins the distribution, as `expected` says it is.
fn sum_finding(wrapper: &Wrapper, expected: Option<&str>) -> Finding {
    let title = "gradle distribution";
    let name = &wrapper.distribution;
    let fix = |sum: Option<&str>| {
        format!(
            "set distributionSha256Sum in {WRAPPER} to {}",
            sum.unwrap_or("the sha256 at the distribution's .sha256 URL")
        )
    };
    match (wrapper.sha256.as_deref(), expected) {
        (None, _) => Finding::new(
            Severity::Warn,
            title,
            format!("no distributionSha256Sum, so ./gradlew does not check {name}"),
        )
        .with_fix(fix(expected)),
        (Some(_), None) => Finding::new(
            Severity::Warn,
            title,
            format!("distributionSha256Sum is set, and {name}'s sha256 was not fetched"),
        ),
        (Some(sum), Some(expected)) if sum.eq_ignore_ascii_case(expected) => Finding::new(
            Severity::Ok,
            title,
            format!("distributionSha256Sum is {name}'s"),
        ),
        (Some(sum), Some(expected)) => Finding::new(
            Severity::Problem,
            title,
            format!("distributionSha256Sum is {sum}, and {name}'s is {expected}"),
        )
        .with_fix(fix(Some(expected))),
    }
}

/// The distribution is not served by the proxy, so its cooldown is reported here.
fn cooldown_finding(release: &Release, today: jiff::civil::Date, days: u32) -> Option<Finding> {
    let built = jiff::civil::Date::strptime("%Y%m%d", release.build_time.get(..8)?).ok()?;
    let age = (today - built).get_days();
    (days > 0 && age < i32::try_from(days).unwrap_or(i32::MAX)).then(|| {
        Finding::new(
            Severity::Warn,
            "gradle cooldown",
            format!(
                "Gradle {} was built {built}, inside the policy's {days}-day cooldown, which \
                 the proxy does not apply to a distribution it does not serve",
                release.version
            ),
        )
    })
}

/// `./gradlew` downloads its distribution itself, not through the proxy, so it is checked
/// against `versions`, Gradle's list of releases, fetched only when a wrapper is there. A
/// policy that cannot be read is no cooldown here: doctor reports it before this runs.
pub async fn wrapper_findings(machine: &Machine<'_>, versions: &str) -> Vec<Finding> {
    let Some(wrapper) = wrapper(machine.dir) else {
        return Vec::new();
    };
    let cooldown_days = match machine.environment.policy().ok().flatten() {
        Some(path) => crate::policy::Policy::load(&path).map_or(0, |policy| policy.cooldown_days),
        None => 0,
    };
    let releases = crate::doctor::probe::text(versions).await.and_then(|body| {
        serde_json::from_str::<Vec<Release>>(&body)
            .map_err(|e| format!("answered what is not a list of releases: {e}"))
    });
    let mut all_sha256 = None;
    if let Ok(releases) = &releases
        && wrapper.distribution.ends_with("-all.zip")
        && let Some(release) = release_of(releases, &wrapper.distribution)
    {
        all_sha256 = crate::doctor::probe::text(&all_checksum_url(release))
            .await
            .ok()
            .map(|sum| sum.trim().to_owned());
    }
    let known = Known {
        releases: releases.as_deref().map_err(String::as_str),
        all_sha256: all_sha256.as_deref(),
        today: crate::policy::today(),
        cooldown_days,
    };
    check_wrapper(&wrapper, &known)
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

    /// What `--write-verification-metadata sha256` wrote on 2026-10-17, its components cut.
    const DIGESTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://schema.gradle.org/dependency-verification https://schema.gradle.org/dependency-verification/dependency-verification-1.4.xsd">
   <configuration>
      <verify-metadata>true</verify-metadata>
      <verify-signatures>false</verify-signatures>
   </configuration>
   <components>
      <component group="org.apache.commons" name="commons-lang3" version="3.17.0">
         <artifact name="commons-lang3-3.17.0.jar">
            <sha256 value="6ee731df5c8e5a2976a1ca023b6bb320ea8d3539fbe64c8a1d5cb765127c33b4" origin="Generated by Gradle"/>
         </artifact>
      </component>
   </components>
</verification-metadata>
"#;

    #[test]
    fn verify_signatures_is_read_from_the_configuration() {
        assert_eq!(verifies_signatures(DIGESTS), Ok(false));
        let signed = DIGESTS.replace("<verify-signatures>false<", "<verify-signatures> true <");
        assert_eq!(verifies_signatures(&signed), Ok(true));
        let elsewhere = "<verification-metadata><verify-signatures>true</verify-signatures>\
                         </verification-metadata>";
        assert_eq!(
            verifies_signatures(elsewhere),
            Ok(false),
            "not in <configuration>"
        );
        assert!(verifies_signatures("<verification-metadata></configuration>").is_err());
    }

    #[test]
    fn signatures_are_the_check_from_outside_byrle() {
        let shown = |read| {
            let finding = verification(read);
            (finding.severity, finding.detail, finding.fix.is_some())
        };
        assert_eq!(
            shown(Some(Ok(true))),
            (
                Severity::Ok,
                "gradle/verification-metadata.xml verifies PGP signatures, with keys from key \
                 servers"
                    .to_owned(),
                false
            )
        );
        assert_eq!(
            shown(Some(Ok(false))),
            (
                Severity::Warn,
                "gradle/verification-metadata.xml checks digests only, which record what was \
                 served when they were written"
                    .to_owned(),
                true
            )
        );
        assert_eq!(
            shown(Some(Err("bad".to_owned()))),
            (
                Severity::Problem,
                "gradle/verification-metadata.xml is not well-formed XML: bad".to_owned(),
                false
            )
        );
        let absent = verification(None);
        assert_eq!(
            absent.detail,
            "no gradle/verification-metadata.xml, so nothing outside byrle checks the files it \
             serves"
        );
        assert_eq!(
            absent.fix.as_deref(),
            Some(
                "run `./gradlew --write-verification-metadata pgp,sha256 help` with \
                 keys.openpgp.org and keyserver.ubuntu.com in <key-servers>, and commit \
                 gradle/verification-metadata.xml"
            )
        );
    }

    /// The file is read from the root project, the nearest directory with a settings script.
    #[test]
    fn the_root_project_s_verification_file_is_read() {
        let (root, project) = project("gradle-verification");
        let environment = crate::env::testing::empty();
        let run = |_: &str, _: &[&str]| Some("Gradle 9.8.1".to_owned());
        let machine = Machine {
            environment: &environment,
            dir: &project,
            run: &run,
        };
        assert_eq!(gradle_settings(&machine, None).len(), 1, "no root project");
        for settings in ["settings.gradle", "settings.gradle.kts"] {
            let dir = root.join(settings);
            std::fs::write(&dir, "").unwrap();
            assert_eq!(project_root(&project), Some(root.as_path()), "{settings}");
            std::fs::remove_file(dir).unwrap();
        }
        std::fs::write(root.join("work/settings.gradle"), "").unwrap();
        assert_eq!(gradle_settings(&machine, None)[1].severity, Severity::Warn);
        std::fs::create_dir_all(root.join("work/gradle")).unwrap();
        std::fs::write(
            root.join("work").join(VERIFICATION),
            DIGESTS.replace("<verify-signatures>false<", "<verify-signatures>true<"),
        )
        .unwrap();
        let found = gradle_settings(&machine, None);
        assert_eq!(found[1].severity, Severity::Ok);
        assert_eq!(project_root(&root), None);
    }

    fn releases() -> Vec<Release> {
        serde_json::from_slice(&super::super::fixture("gradle-versions.json")).expect("parses")
    }

    /// 9.8.1's jar, which its own `wrapper --gradle-version 8.14.3` wrote.
    const JAR_981: &str = "3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98";

    const BIN_981: &str = "dce76f55f8e251a3a1f130eb120f30b3d271de2b76c9b0729d316b5a1b6dc01f";

    fn wrapped(distribution: &str, sha256: Option<&str>, jar: Option<&str>) -> Wrapper {
        Wrapper {
            distribution: distribution.to_owned(),
            sha256: sha256.map(str::to_owned),
            jar: jar.map(str::to_owned),
        }
    }

    fn date(text: &str) -> jiff::civil::Date {
        text.parse().unwrap()
    }

    fn checked(
        wrapper: &Wrapper,
        all: Option<&str>,
        today: &str,
        days: u32,
    ) -> Vec<(Severity, String)> {
        let releases = releases();
        let known = Known {
            releases: Ok(&releases),
            all_sha256: all,
            today: date(today),
            cooldown_days: days,
        };
        check_wrapper(wrapper, &known)
            .into_iter()
            .map(|finding| (finding.severity, finding.detail))
            .collect()
    }

    #[test]
    fn a_release_is_found_by_its_bin_zip_s_name() {
        let releases = releases();
        assert_eq!(releases.len(), 4);
        let version = |name| release_of(&releases, name).map(|r| r.version.as_str());
        assert_eq!(version("gradle-9.8.1-bin.zip"), Some("9.8.1"));
        assert_eq!(version("gradle-9.8.1-all.zip"), Some("9.8.1"));
        assert_eq!(version("gradle-9.8.0-rc-3-bin.zip"), Some("9.8.0-rc-3"));
        assert_eq!(version("gradle-1.0-bin.zip"), None);
        let rc5 = release_of(&releases, "gradle-5.0-rc-5-bin.zip").unwrap();
        assert_eq!(rc5.wrapper_checksum, None);
        assert_eq!(
            all_checksum_url(release_of(&releases, "gradle-9.8.1-bin.zip").unwrap()),
            "https://services.gradle.org/distributions/gradle-9.8.1-all.zip.sha256"
        );
    }

    #[test]
    fn a_pinned_jar_and_distribution_of_a_release_are_ok() {
        let wrapper = wrapped("gradle-9.8.1-bin.zip", Some(BIN_981), Some(JAR_981));
        assert_eq!(
            checked(&wrapper, None, "2026-10-18", 0),
            [
                (Severity::Ok, "Gradle 9.8.1's, by its sha256".to_owned()),
                (
                    Severity::Ok,
                    "distributionSha256Sum is gradle-9.8.1-bin.zip's".to_owned()
                ),
            ]
        );
        let upper = wrapped(
            "gradle-9.8.1-bin.zip",
            Some(&BIN_981.to_uppercase()),
            Some(JAR_981),
        );
        assert_eq!(checked(&upper, None, "2026-10-18", 0)[1].0, Severity::Ok);
    }

    /// A nightly shares its jar with the release before it, as 9.9.0's did with 9.8.1's.
    #[test]
    fn a_jar_is_named_by_its_own_release_then_a_final_one() {
        let mut releases = releases();
        let nightly = Release {
            version: "9.9.0-20261018002219+0000".to_owned(),
            download_url: "https://services.gradle.org/distributions-snapshots/n-bin.zip"
                .to_owned(),
            nightly: true,
            ..releases[0].clone()
        };
        releases.insert(0, nightly.clone());
        let named = |own: Option<&Release>, releases: &[Release]| {
            jar_finding(Some(JAR_981), releases, own).detail
        };
        assert_eq!(named(None, &releases), "Gradle 9.8.1's, by its sha256");
        assert_eq!(
            named(Some(&releases[2]), &releases),
            "Gradle 9.8.1's, by its sha256",
            "8.14.3's own jar is another"
        );
        assert_eq!(
            named(Some(&nightly), &releases),
            "Gradle 9.9.0-20261018002219+0000's, by its sha256"
        );
        let snapshot = Release {
            nightly: false,
            snapshot: true,
            ..nightly.clone()
        };
        assert_eq!(
            named(None, &[nightly.clone(), snapshot]),
            "Gradle 9.9.0-20261018002219+0000's, by its sha256",
            "only unreleased ones match"
        );
    }

    /// 9.8.1's jar beside 8.14.3's distribution is what `wrapper --gradle-version` writes.
    #[test]
    fn a_jar_is_any_release_s() {
        let wrapper = wrapped("gradle-8.14.3-bin.zip", None, Some(JAR_981));
        let found = checked(&wrapper, None, "2026-10-18", 0);
        assert_eq!(
            found[0],
            (Severity::Ok, "Gradle 9.8.1's, by its sha256".to_owned())
        );
        assert_eq!(
            found[1],
            (
                Severity::Warn,
                "no distributionSha256Sum, so ./gradlew does not check gradle-8.14.3-bin.zip"
                    .to_owned()
            )
        );
        let releases = releases();
        let known = Known {
            releases: Ok(&releases),
            all_sha256: None,
            today: date("2026-10-18"),
            cooldown_days: 0,
        };
        assert_eq!(
            check_wrapper(&wrapper, &known)[1].fix.as_deref(),
            Some(
                "set distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties to \
                 bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531"
            )
        );
    }

    #[test]
    fn a_jar_or_sum_no_release_has_is_a_problem() {
        let wrapper = wrapped("gradle-9.8.1-bin.zip", Some("00"), Some("ab"));
        assert_eq!(
            checked(&wrapper, None, "2026-10-18", 0),
            [
                (
                    Severity::Problem,
                    "its sha256, ab, is no release's wrapperChecksum in \
                     https://services.gradle.org/versions/all"
                        .to_owned()
                ),
                (
                    Severity::Problem,
                    format!("distributionSha256Sum is 00, and gradle-9.8.1-bin.zip's is {BIN_981}")
                ),
            ]
        );
        let jarless = wrapped("gradle-1.0-bin.zip", None, None);
        assert_eq!(
            checked(&jarless, None, "2026-10-18", 0),
            [
                (
                    Severity::Problem,
                    "no gradle/wrapper/gradle-wrapper.jar".to_owned()
                ),
                (
                    Severity::Warn,
                    "gradle-1.0-bin.zip is no release https://services.gradle.org/versions/all \
                     lists"
                        .to_owned()
                ),
            ]
        );
    }

    /// An `-all` zip's sha256 is only at its `.sha256` URL, not in the list.
    #[test]
    fn an_all_distribution_is_checked_against_its_fetched_sum() {
        let pinned = wrapped("gradle-9.8.1-all.zip", Some("a11"), Some(JAR_981));
        assert_eq!(
            checked(&pinned, Some("a11"), "2026-10-18", 0)[1],
            (
                Severity::Ok,
                "distributionSha256Sum is gradle-9.8.1-all.zip's".to_owned()
            )
        );
        assert_eq!(
            checked(&pinned, None, "2026-10-18", 0)[1],
            (
                Severity::Warn,
                "distributionSha256Sum is set, and gradle-9.8.1-all.zip's sha256 was not fetched"
                    .to_owned()
            )
        );
        let unpinned = wrapped("gradle-9.8.1-all.zip", None, Some(JAR_981));
        let releases = releases();
        let known = Known {
            releases: Ok(&releases),
            all_sha256: None,
            today: date("2026-10-18"),
            cooldown_days: 0,
        };
        assert_eq!(
            check_wrapper(&unpinned, &known)[1].fix.as_deref(),
            Some(
                "set distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties to the \
                 sha256 at the distribution's .sha256 URL"
            )
        );
    }

    /// 9.8.1 was built 2026-10-07.
    #[test]
    fn a_release_built_inside_the_cooldown_is_a_warning() {
        let wrapper = wrapped("gradle-9.8.1-bin.zip", Some(BIN_981), Some(JAR_981));
        let inside = checked(&wrapper, None, "2026-10-18", 14);
        assert_eq!(
            inside[2],
            (
                Severity::Warn,
                "Gradle 9.8.1 was built 2026-10-07, inside the policy's 14-day cooldown, which \
                 the proxy does not apply to a distribution it does not serve"
                    .to_owned()
            )
        );
        assert_eq!(
            checked(&wrapper, None, "2026-10-21", 14).len(),
            2,
            "14 days on"
        );
        assert_eq!(
            checked(&wrapper, None, "2026-10-20", 14).len(),
            3,
            "13 days on"
        );
        assert_eq!(
            checked(&wrapper, None, "2026-10-08", 0).len(),
            2,
            "no cooldown"
        );
        let bad = Release {
            build_time: "2026".to_owned(),
            ..releases()[0].clone()
        };
        assert_eq!(cooldown_finding(&bad, date("2026-10-18"), 14), None);
        let unparsed = Release {
            build_time: "2026xx07165746+0000".to_owned(),
            ..releases()[0].clone()
        };
        assert_eq!(cooldown_finding(&unparsed, date("2026-10-18"), 14), None);
    }

    #[test]
    fn a_list_not_fetched_is_a_warning() {
        let wrapper = wrapped("gradle-9.8.1-bin.zip", None, None);
        let known = Known {
            releases: Err("answered 503 Service Unavailable"),
            all_sha256: None,
            today: date("2026-10-18"),
            cooldown_days: 0,
        };
        let found = check_wrapper(&wrapper, &known);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Warn);
        assert_eq!(
            found[0].detail,
            "not checked: https://services.gradle.org/versions/all answered 503 Service \
             Unavailable"
        );
    }

    /// Gradle writes `https\://`, and the jar's sha256 is read from the file.
    #[test]
    fn the_wrapper_is_read_from_the_root_project() {
        let (root, project) = project("gradle-wrapper");
        assert_eq!(wrapper(&project), None, "no root project");
        std::fs::write(root.join("work/settings.gradle"), "").unwrap();
        assert_eq!(wrapper(&project), None, "a root project with no wrapper");
        let dir = root.join("work/gradle/wrapper");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gradle-wrapper.properties"), "distributionUrl=\n").unwrap();
        assert_eq!(wrapper(&project), None, "no distribution");
        std::fs::write(
            dir.join("gradle-wrapper.properties"),
            "distributionBase=PROJECT\n\
             distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.1-bin.zip\n\
             distributionSha256Sum=\n",
        )
        .unwrap();
        assert_eq!(
            wrapper(&project),
            Some(wrapped("gradle-9.8.1-bin.zip", None, None))
        );
        std::fs::write(dir.join("gradle-wrapper.jar"), b"").unwrap();
        std::fs::write(
            dir.join("gradle-wrapper.properties"),
            format!("distributionUrl=gradle.zip\ndistributionSha256Sum={BIN_981}\n"),
        )
        .unwrap();
        assert_eq!(
            wrapper(&project),
            Some(wrapped(
                "gradle.zip",
                Some(BIN_981),
                Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            ))
        );
    }

    /// The list and an `-all` zip's sha256 are fetched only for a project with a wrapper.
    #[tokio::test]
    async fn a_gradle_wrapper_is_checked_against_the_releases_fetched() {
        use axum::Router;
        use axum::routing::get;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port should bind");
        let url = format!("http://{}", listener.local_addr().expect("bound"));
        let built = crate::policy::today()
            .strftime("%Y%m%d120000+0000")
            .to_string();
        let list = format!(
            r#"[{{"version": "9.8.1", "buildTime": "{built}",
                 "downloadUrl": "{url}/gradle-9.8.1-bin.zip", "checksum": "b1",
                 "wrapperChecksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}]"#
        );
        let router = Router::new()
            .route("/versions", get(move || async move { list }))
            .route("/gradle-9.8.1-all.zip.sha256", get(|| async { "a11\n" }))
            .route("/broken", get(|| async { "[" }));
        tokio::spawn(axum::serve(listener, router).into_future());

        let dir = crate::util::test_support::tempdir("doctor-gradle-wrapper");
        let policy = dir.join("policy.yaml");
        std::fs::write(&policy, "version: 1\ncooldown_days: 7\n").expect("writes");
        let environment =
            crate::env::testing::with(&[(crate::env::POLICY, policy.to_str().unwrap())]);
        let machine = Machine {
            environment: &environment,
            dir: &dir,
            run: &|_, _| None,
        };
        let versions = format!("{url}/versions");
        assert!(wrapper_findings(&machine, &versions).await.is_empty());

        std::fs::create_dir_all(dir.join("gradle/wrapper")).expect("creates");
        std::fs::write(dir.join("gradle/wrapper/gradle-wrapper.jar"), b"").expect("writes");
        std::fs::write(
            dir.join("gradle/wrapper/gradle-wrapper.properties"),
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.1-all.zip\n\
             distributionSha256Sum=a11\n",
        )
        .expect("writes");
        let severities = |findings: Vec<Finding>| -> Vec<(Severity, String)> {
            findings
                .into_iter()
                .map(|f| (f.severity, f.title))
                .collect()
        };
        assert_eq!(
            severities(wrapper_findings(&machine, &versions).await),
            [
                (Severity::Ok, "gradle wrapper jar".to_owned()),
                (Severity::Ok, "gradle distribution".to_owned()),
                (Severity::Warn, "gradle cooldown".to_owned()),
            ]
        );
        let unset = crate::env::testing::empty();
        let without = Machine {
            environment: &unset,
            ..machine
        };
        assert_eq!(
            wrapper_findings(&without, &versions).await.len(),
            2,
            "no policy, no cooldown"
        );
        for (at, why) in [
            ("/broken", "answered what is not a list of releases"),
            ("/absent", "404 Not Found"),
        ] {
            let found = wrapper_findings(&machine, &format!("{url}{at}")).await;
            assert_eq!(found.len(), 1);
            assert!(found[0].detail.contains(why), "{}", found[0].detail);
        }
        let silent = crate::util::test_support::closing_server().await;
        let found = wrapper_findings(&machine, &format!("http://{silent}/versions")).await;
        assert!(
            found[0].detail.contains("was not fetched"),
            "{}",
            found[0].detail
        );
        let unreadable = crate::env::testing::with_unreadable(&[], crate::env::POLICY);
        let broken = Machine {
            environment: &unreadable,
            ..machine
        };
        assert_eq!(wrapper_findings(&broken, &versions).await.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
