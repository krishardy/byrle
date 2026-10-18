//! A Maven repository under [`PREFIX`], as mvn and Gradle read one: `maven-metadata.xml`
//! filtered by policy, and each version's files fetched at the proxy. See
//! docs/maven-plan.md.

pub mod clients;
pub mod digest;
pub mod gradle;
pub mod inspect;
pub mod keys;
pub mod lockfile;
pub mod paths;
pub mod signature;
pub mod signer;
pub mod signing;
pub mod transport;
pub mod wire;

pub use paths::{classify_path, document_from_content_type, upstream_url};
pub use transport::Client;

use crate::ecosystem::{Also, PublishTimeSource, Registry, Setup, UncoveredMetadata};
use crate::identity::Ecosystem;
use crate::intel::providers::osv::bundle;
use crate::intel::range::VersionOrder;
use crate::intel::stream;
use crate::policy::merge::Rule;

/// OSV's bundle for this ecosystem.
pub const OSV: stream::Stream = stream::osv(bundle::MAVEN_STREAM, bundle::MAVEN_BUNDLE, |bytes| {
    stream::osv_bundle(Ecosystem::Maven, bytes)
});

/// This ecosystem's row of [`crate::ecosystem::TABLE`].
pub const REGISTRY: Registry = Registry {
    ecosystem: Ecosystem::Maven,
    prefix: PREFIX,
    always_reachable: &[ORIGIN],
    classify_path,
    read_media_type: document_from_content_type,
    documents: &["text/xml", "application/xml"],
    other_is_probe: false,
    publish_times: PublishTimeSource {
        said: "each version's `.pom` `Last-Modified`; `maven-metadata.xml` carries none",
        full_accept: None,
        cost: Some(
            "a `HEAD` of each version's `.pom` in a `maven-metadata.xml`, every version, \
             each time kept",
        ),
    },
    streams: &[&OSV],
    lockfiles: lockfile::LOCKFILES,
    unread_lockfiles: lockfile::UNREAD,
    clients: clients::CLIENTS,
    setup: Setup {
        client: "mvn",
        command: setup_line,
        path: "/maven",
    },
    uncovered_metadata: UncoveredMetadata::FilterWithoutIntel,
    versions: VersionOrder::Maven,
    split_name: paths::split_name,
    canonical_name: paths::canonical_name,
    upstream: crate::env::UPSTREAM_MAVEN,
    upstream_url,
    read: inspect::read,
    reader: |filename| {
        filename
            .ends_with(".jar")
            .then_some(crate::analysis::jar_annotation_processors as crate::analysis::Reader)
    },
    layout: |_| None,
    source: |_| None,
    compare_source: |_, _, _| None,
    unfound_source: "maven-metadata.xml names no repository",
    upstream_check: None,
    keep_for_platforms: |_, _| {},
    provenance_bundle: |_| {
        Err("Maven Central serves PGP signatures, not Sigstore attestations".to_owned())
    },
    osv_name: "Maven",
    advisory_package: |name| Some(name.to_owned()),
    metadata_names_repository: |_| false,
    client: |http, upstream, max_bytes| std::sync::Arc::new(Client::new(http, upstream, max_bytes)),
    write: |_| None,
    meaningless: &[Rule::Deprecated, Rule::Yanked],
    install_scripts_unread: Some(
        "maven-metadata.xml does not say; the .jar is read for annotation processors when it is downloaded",
    ),
    publishers: Some(signing::made),
    decides_head: true,
    signatures: Some(signature::VERIFIER),
    sidecar: paths::metadata_sidecar,
    also: &[Also {
        prefix: PLUGINS_PREFIX,
        upstream: crate::env::UPSTREAM_GRADLE_PLUGINS,
        client: |http, upstream, max_bytes| {
            std::sync::Arc::new(Client::new(http, upstream, max_bytes).claiming_from_redirects())
        },
        own_at: &CENTRAL,
    }],
};

/// What points mvn at `url`: a mirror of every repository in `~/.m2/settings.xml`.
fn setup_line(url: &str) -> String {
    format!(
        "in ~/.m2/settings.xml: <mirror><id>byrle</id><mirrorOf>*</mirrorOf><url>{url}</url>\
         </mirror>, and a <server><id>byrle</id> with the account and token"
    )
}

/// The path the proxy serves Maven repositories under.
pub const PREFIX: &str = "/maven/";

/// The path the proxy serves the Gradle plugin portal under, a second Maven repository.
pub const PLUGINS_PREFIX: &str = "/gradle-plugins/";

/// The plugin portal, the Maven row's first [`Also`].
pub const PLUGINS: crate::ecosystem::Repository =
    crate::ecosystem::Repository::also_of(Ecosystem::Maven, 0);

/// The Gradle plugin portal's Maven repository.
pub const PORTAL: &str = "https://plugins.gradle.org/m2";

/// Maven Central, the repository this build reads.
pub const REPOSITORY: &str = "https://repo1.maven.org/maven2";

/// Central as the portal redirects to it. The configured upstream is Central too.
pub const CENTRAL: [&str; 1] = ["https://repo.maven.apache.org/maven2/"];

/// The origin of [`REPOSITORY`].
pub const ORIGIN: &str = "https://repo1.maven.org";

/// A file from `tests/fixtures/maven/`.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/maven/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("the fixture is present")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Maven Central serves PGP signatures, which step 4.5 reads, and a jar is the same on
    /// every platform.
    #[test]
    fn one_jar_per_version_and_no_attestations() {
        let key = crate::identity::PackageKey::from_registry_name(
            Ecosystem::Maven,
            "org.apache.commons:commons-lang3",
        )
        .unwrap();
        let read = wire::parse(&fixture("commons-lang3.xml")).unwrap();
        let metadata = read.records(&key, "https://r.example/");
        let mut files: Vec<_> = metadata.records[0].artifacts.iter().collect();
        (REGISTRY.keep_for_platforms)(&mut files, &[]);
        assert_eq!(files.len(), 1);
        assert!((REGISTRY.provenance_bundle)(b"{}").is_err());
        assert!((REGISTRY.reader)("x.jar").is_some());
        assert!((REGISTRY.reader)("x.pom").is_none());
        assert!((REGISTRY.layout)("x.jar").is_none());
        assert!((REGISTRY.source)(&metadata.records[0]).is_none());
        assert!(!(REGISTRY.metadata_names_repository)(&metadata.records[0]));
        assert!(
            (REGISTRY.write)(&crate::ecosystem::Writing {
                path: "/maven/a/b/maven-metadata.xml",
                base: None,
                tokens_required: true,
            })
            .is_none()
        );
        assert_eq!(
            (REGISTRY.advisory_package)("org.apache.commons:commons-lang3").as_deref(),
            Some("org.apache.commons:commons-lang3")
        );
        assert_eq!(
            REGISTRY.setup.command_line("https://h"),
            "in ~/.m2/settings.xml: <mirror><id>byrle</id><mirrorOf>*</mirrorOf>\
             <url>https://h/maven</url></mirror>, and a <server><id>byrle</id> with the \
             account and token"
        );
    }
}
