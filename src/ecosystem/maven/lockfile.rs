//! The lockfiles Gradle writes, read for `byrle policy diff`, `explain`, `warm` and
//! `lockfile verify`. mvn writes none. A line locks `<group>:<artifact>:<version>` and
//! names the configurations it is in; it records no classifier, packaging, repository,
//! URL or digest.

use std::collections::BTreeSet;

use super::paths::{canonical_name, directory, filename};
use super::{PLUGINS, PLUGINS_PREFIX, PREFIX};
use crate::ecosystem::Repository;
use crate::identity::{Ecosystem, PackageKey};
use crate::lockfile::{Locked, LockedArtifact, Lockfile, Platform, Unread};

/// A project's lockfile, and its build and settings scripts', whose plugins are the portal's.
pub const LOCKFILES: &[Lockfile] = &[
    locks("gradle.lockfile", on_central, None),
    locks("buildscript-gradle.lockfile", on_portal, Some(PLUGINS)),
    locks("settings-gradle.lockfile", on_portal, Some(PLUGINS)),
];

/// Gradle's lockfile named `name`, its artifacts read by `artifacts` and its versions from
/// `repository`.
const fn locks(
    name: &'static str,
    artifacts: crate::lockfile::ArtifactReader,
    repository: Option<Repository>,
) -> Lockfile {
    Lockfile {
        name,
        read: packages,
        artifacts: Some(artifacts),
        urls: Some(artifacts),
        pins: None,
        repository,
    }
}

/// File names mvn and Gradle write that no reader here takes.
pub const UNREAD: &[Unread] = &[Unread {
    name: "pom.xml",
    reason: "mvn writes no lockfile, and a pom.xml's versions are resolved by mvn",
}];

/// What a line names when its configurations lock nothing.
const EMPTY: &str = "empty=";

/// What a plugin marker's artifact name is: its group, then this.
const MARKER: &str = ".gradle.plugin";

/// Each `<group>:<artifact>:<version>` the text locks, in file order, or the first line
/// that is not a lockfile line.
fn lines(text: &str) -> Result<Vec<(&str, &str, &str)>, String> {
    let mut found = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(EMPTY) {
            continue;
        }
        let coordinates = line.split_once('=').map(|(coordinates, _)| coordinates);
        let parts: Vec<&str> = coordinates.unwrap_or_default().split(':').collect();
        let [group, artifact, version] = parts.as_slice() else {
            return Err(format!(
                "line {}: `{line}` is not `<group>:<artifact>:<version>=<configurations>`",
                at + 1
            ));
        };
        if [group, artifact, version]
            .iter()
            .any(|part| part.is_empty())
        {
            return Err(format!("line {}: `{line}` has an empty coordinate", at + 1));
        }
        found.push((*group, *artifact, *version));
    }
    Ok(found)
}

fn locked(group: &str, artifact: &str, version: &str) -> Locked {
    (
        Ecosystem::Maven.as_str().to_owned(),
        canonical_name(&format!("{group}:{artifact}")),
        version.to_owned(),
    )
}

/// Every version the file locks, plugin markers among them.
fn packages(text: &str) -> Result<BTreeSet<Locked>, String> {
    Ok(lines(text)?
        .into_iter()
        .map(|(group, artifact, version)| locked(group, artifact, version))
        .collect())
}

/// For `byrle warm` and `byrle lockfile verify`: each jar at its path under `/maven/`.
fn on_central(text: &str) -> Result<Vec<LockedArtifact>, String> {
    jars(text, PREFIX)
}

/// As [`on_central`], under `/gradle-plugins/`, which answers for Central's files too.
fn on_portal(text: &str) -> Result<Vec<LockedArtifact>, String> {
    jars(text, PLUGINS_PREFIX)
}

/// Each locked version's jar under `prefix`. A plugin marker publishes only a `.pom`, so
/// it is left out. No URL is recorded; the build's repositories say where it was fetched.
fn jars(text: &str, prefix: &str) -> Result<Vec<LockedArtifact>, String> {
    Ok(lines(text)?
        .into_iter()
        .filter(|(group, artifact, _)| artifact.strip_suffix(MARKER) != Some(group))
        .filter_map(|(group, artifact, version)| {
            let locked = locked(group, artifact, version);
            let key = PackageKey::from_registry_name(Ecosystem::Maven, &locked.1).ok()?;
            let path = format!(
                "{prefix}{}/{version}/{}",
                directory(&key),
                filename(&key, version)
            );
            Some(LockedArtifact {
                locked,
                path,
                platform: Platform::default(),
                url: None,
            })
        })
        .collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Part of what Gradle 9.8.1's `dependencies --write-locks` wrote on 2026-10-17.
    const PROJECT: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
# To regenerate this file, run: ./gradlew :dependencies --write-locks
com.google.guava:guava:33.4.0-jre=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
io.netty:netty-transport-native-epoll:4.1.127.Final=runtimeClasspath,testRuntimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
org.apache.commons:commons-lang3:3.17.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
org.projectlombok:lombok:1.18.42=annotationProcessor
org.springframework.boot:spring-boot-dependencies:3.5.6=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath
empty=testAnnotationProcessor
";

    /// The same run's `buildscript-gradle.lockfile`, from `plugins { id ... version ... }`.
    const BUILDSCRIPT: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.github.ben-manes.versions:com.github.ben-manes.versions.gradle.plugin:0.52.0=classpath
com.github.ben-manes:gradle-versions-plugin:0.52.0=classpath
org.jetbrains.kotlin:kotlin-stdlib:2.0.21=classpath
empty=
";

    #[test]
    fn every_locked_version_is_read_with_its_purl() {
        let locked: Vec<Locked> = packages(PROJECT).expect("reads").into_iter().collect();
        assert_eq!(locked.len(), 7);
        assert!(locked.iter().all(|(ecosystem, _, _)| ecosystem == "maven"));
        let references = crate::lockfile::references(locked.into_iter().map(|l| (None, l)));
        let (purl, guava, version, at) = &references[0];
        assert_eq!(
            *at,
            Repository::of(Ecosystem::Maven),
            "Central, when no row says"
        );
        assert_eq!(purl, "pkg:maven/com.google.guava/guava@33.4.0-jre");
        assert_eq!(guava.key().namespace(), Some("com.google.guava"));
        assert_eq!(version, "33.4.0-jre");
        assert_eq!(references.len(), 7, "every name makes a purl");
    }

    /// A marker is a version `policy diff` reads, with no jar to warm.
    #[test]
    fn a_plugin_marker_is_locked_but_has_no_jar() {
        let locked = packages(BUILDSCRIPT).expect("reads");
        assert!(locked.contains(&locked_of(
            "com.github.ben-manes.versions/com.github.ben-manes.versions.gradle.plugin",
            "0.52.0"
        )));
        let paths: Vec<String> = on_portal(BUILDSCRIPT)
            .expect("reads")
            .into_iter()
            .map(|artifact| artifact.path)
            .collect();
        assert_eq!(
            paths,
            [
                "/gradle-plugins/com/github/ben-manes/gradle-versions-plugin/0.52.0/gradle-versions-plugin-0.52.0.jar",
                "/gradle-plugins/org/jetbrains/kotlin/kotlin-stdlib/2.0.21/kotlin-stdlib-2.0.21.jar",
            ]
        );
    }

    fn locked_of(name: &str, version: &str) -> Locked {
        ("maven".to_owned(), name.to_owned(), version.to_owned())
    }

    /// A project's jars are Central's. None records a URL.
    #[test]
    fn a_project_s_jars_are_asked_for_under_the_maven_prefix() {
        let found = on_central(PROJECT).expect("reads");
        assert_eq!(found.len(), 7);
        assert_eq!(
            found[4].path,
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar"
        );
        assert!(found.iter().all(|artifact| artifact.url.is_none()));
    }

    #[test]
    fn a_line_that_is_not_a_lockfile_line_is_an_error() {
        for (text, expected) in [
            (
                "# header\ncom.google.guava:guava=compileClasspath\n",
                "line 2: `com.google.guava:guava=compileClasspath` is not \
                 `<group>:<artifact>:<version>=<configurations>`",
            ),
            (
                "com.google.guava:guava:33.4.0-jre\n",
                "line 1: `com.google.guava:guava:33.4.0-jre` is not \
                 `<group>:<artifact>:<version>=<configurations>`",
            ),
            (
                "com.google.guava::33.4.0-jre=classpath\n",
                "line 1: `com.google.guava::33.4.0-jre=classpath` has an empty coordinate",
            ),
        ] {
            assert_eq!(packages(text).unwrap_err(), expected);
            assert_eq!(on_central(text).unwrap_err(), expected);
        }
    }

    /// A coordinate no key takes makes no path.
    #[test]
    fn a_name_that_makes_no_key_is_left_out_of_warm() {
        let found = on_central("com.google guava:guava:1=classpath\n").expect("reads");
        assert!(found.is_empty());
    }

    /// A build script's versions are the portal's, and a project's Central's.
    #[test]
    fn a_script_s_lockfile_is_read_from_the_portal() {
        let dir = crate::util::test_support::tempdir("gradle-lockfiles");
        for (name, text, expected) in [
            ("gradle.lockfile", PROJECT, None),
            ("buildscript-gradle.lockfile", BUILDSCRIPT, Some(PLUGINS)),
            ("settings-gradle.lockfile", BUILDSCRIPT, Some(PLUGINS)),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, text).expect("writes");
            let listed = crate::lockfile::listed(&path).expect("reads");
            assert!(!listed.is_empty());
            assert!(listed.iter().all(|(at, _)| *at == expected), "{name}");
        }
        assert_eq!(PLUGINS.prefix(), PLUGINS_PREFIX);
        let built = locks(
            "buildscript-gradle.lockfile",
            on_portal,
            Some(Repository::also_of(Ecosystem::Maven, 0)),
        );
        assert_eq!(built.repository, Some(PLUGINS));
        assert_eq!((built.read)(BUILDSCRIPT), packages(BUILDSCRIPT));
        for read in [built.artifacts, built.urls] {
            assert_eq!(read.expect("set")(BUILDSCRIPT), on_portal(BUILDSCRIPT));
        }
        assert!(built.pins.is_none());
    }
}
