//! Turning a packument into records the policy engine reads.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::identity::{Ecosystem, PackageKey};
use crate::record::{
    Artifact, DirectDependency, DocumentDetail, Maintainer, PackageMetadata, PackageRecord,
    Provenance, RegistrySignature, SkippedVersion, TrustedPublisher,
};

use super::error::NormalizeError;
use super::paths::tarball_filename;
use super::wire::{WireDist, WireMaintainer, WirePackument, WireVersion};

/// Turn a packument body into records.
/// `detail` says which document this is, from the `Accept` sent or the `Content-Type`
/// returned, never inferred from the content, because it qualifies every absent field.
pub fn normalize_packument(
    body: &[u8],
    detail: DocumentDetail,
) -> Result<PackageMetadata, NormalizeError> {
    let wire: WirePackument = serde_json::from_slice(body).map_err(NormalizeError::Json)?;
    normalize_wire(wire, detail)
}

fn normalize_wire(
    wire: WirePackument,
    detail: DocumentDetail,
) -> Result<PackageMetadata, NormalizeError> {
    let key =
        PackageKey::from_registry_name(Ecosystem::Npm, &wire.name).map_err(NormalizeError::Name)?;

    let mut records = Vec::with_capacity(wire.versions.len());
    let mut skipped = Vec::new();

    for (version, entry) in &wire.versions {
        match version_record(&key, version, entry, &wire, detail) {
            Ok(record) => records.push(record),
            Err(reason) => skipped.push(SkippedVersion {
                version: version.clone(),
                reason,
            }),
        }
    }

    Ok(PackageMetadata {
        key,
        latest: wire.dist_tags.get("latest").cloned(),
        records,
        skipped,
    })
}

/// Build one record, or say why not. The error is a plain string because it is
/// reported, not matched on.
fn version_record(
    key: &PackageKey,
    version: &str,
    entry: &WireVersion,
    wire: &WirePackument,
    detail: DocumentDetail,
) -> Result<PackageRecord, String> {
    let package = key.at_version(version).map_err(|e| format!("{e}"))?;

    let dist = entry.dist.as_ref().ok_or("version has no `dist` object")?;
    let url = dist
        .tarball
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or("version has no `dist.tarball`")?
        .to_owned();

    let published_at = wire
        .time
        .get(version)
        .and_then(|raw| raw.parse::<jiff::Timestamp>().ok());

    let maintainers = entry
        .maintainers
        .as_ref()
        .or(wire.maintainers.as_ref())
        .map(|list| list.iter().map(maintainer).collect());

    let repository = entry.repository.clone().or_else(|| wire.repository.clone());

    let scripts = has_install_scripts(entry);
    Ok(PackageRecord {
        package,
        detail,
        published_at,
        maintainers,
        repository,
        deprecated: entry
            .deprecated
            .clone()
            .filter(|message| !message.trim().is_empty()),
        has_install_scripts: scripts,
        yanked: None,
        install_scripts: entry.scripts.as_ref().map(install_scripts),
        provenance: provenance(entry, dist),
        direct_dependencies: [
            &entry.dependencies,
            &entry.optional_dependencies,
            &entry.peer_dependencies,
        ]
        .into_iter()
        .flat_map(|specs| &specs.0)
        .map(|(name, spec)| DirectDependency {
            name: name.clone(),
            spec: spec.clone(),
        })
        .collect(),
        artifacts: vec![Artifact {
            filename: tarball_filename(&url),
            runs_install_scripts: scripts,
            yanked: None,
            url,
            integrity: dist.integrity.clone(),
            legacy_sha1: dist.shasum.clone(),
            attestation_url: dist.attestations.as_ref().and_then(|a| a.url.clone()),
            file_count: dist.file_count,
            unpacked_size: dist.unpacked_size,
        }],
    })
}

/// The three lifecycle scripts npm runs when installing a registry tarball.
const INSTALL_SCRIPT_NAMES: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Whether installing runs a script: `hasInstallScript` in the abbreviated document,
/// `scripts` in the full one. `entry` is one version of either.
fn has_install_scripts(entry: &WireVersion) -> bool {
    if let Some(flag) = entry.has_install_script {
        return flag;
    }
    entry.scripts.as_ref().is_some_and(|scripts| {
        INSTALL_SCRIPT_NAMES
            .iter()
            .any(|name| scripts.contains_key(*name))
    })
}

/// Keep only the scripts that run on install. The rest of `scripts` is build and test
/// tooling that a `npm install` of a published tarball never executes.
fn install_scripts(scripts: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    INSTALL_SCRIPT_NAMES
        .iter()
        .filter_map(|name| {
            scripts
                .get_key_value(*name)
                .map(|(k, v)| (k.clone(), v.clone()))
        })
        .collect()
}

fn maintainer(wire: &WireMaintainer) -> Maintainer {
    Maintainer {
        name: wire.name.clone().unwrap_or_default(),
        email: wire.email.clone(),
    }
}

fn provenance(entry: &WireVersion, dist: &WireDist) -> Provenance {
    Provenance {
        attestation_url: dist.attestations.as_ref().and_then(|a| a.url.clone()),
        predicate_type: dist
            .attestations
            .as_ref()
            .and_then(|a| a.provenance.as_ref())
            .and_then(|p| p.predicate_type.clone()),
        registry_signatures: dist
            .signatures
            .as_ref()
            .map(|sigs| {
                sigs.iter()
                    .map(|s| RegistrySignature {
                        key_id: s.keyid.clone(),
                        signature: s.sig.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        trusted_publisher: entry
            .npm_user
            .as_ref()
            .and_then(|u| u.trusted_publisher.as_ref())
            .map(|t| TrustedPublisher { id: t.id.clone() }),
        publisher: entry.npm_user.as_ref().and_then(|u| u.name.clone()),
    }
}

/// Only the `time` map, out of a full packument, without building its records.
#[derive(Deserialize)]
struct WireTimes {
    #[serde(default)]
    time: BTreeMap<String, String>,
}

/// When each version was published, keyed by version.
///
/// `created` and `modified` share the map and describe the package rather than a version,
/// so they are dropped: npm's own semver parsing rejects both as version names.
pub fn parse_publish_times(
    json: &[u8],
) -> Result<BTreeMap<String, jiff::Timestamp>, NormalizeError> {
    let wire: WireTimes = serde_json::from_slice(json).map_err(NormalizeError::Json)?;
    Ok(wire
        .time
        .into_iter()
        .filter(|(key, _)| key != "created" && key != "modified")
        .filter_map(|(version, raw)| Some((version, raw.parse::<jiff::Timestamp>().ok()?)))
        .collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::{fixture, normalized};
    use super::*;
    use crate::record::Repository;

    /// The specifier forms npm-package-arg treats as fetched from where they point, and
    /// the near-misses it resolves through the registry.
    #[test]
    fn a_specifier_naming_where_to_fetch_is_direct() {
        use super::super::wire::is_direct;
        for direct in [
            "git+https://github.com/o/r.git",
            "git://github.com/o/r.git",
            "github:o/r#v1",
            "gitlab:o/r",
            "bitbucket:o/r",
            "gist:abc123",
            "https://host/x.tgz",
            "http://host/x.tgz",
            "file:../x",
            "./x",
            "../x",
            "/abs/x",
            "~/x",
            "o/r",
            "o/r#v1.0.0",
            " o/r ",
        ] {
            assert!(is_direct(direct), "{direct}");
        }
        for registry in [
            "^1.0.0",
            "1.x",
            "latest",
            "*",
            "",
            ">=1 <2",
            "npm:other@1",
            "npm:@s/p@1",
            "@scope/pkg",
            "o/r/extra",
            "a /b",
        ] {
            assert!(!is_direct(registry), "{registry}");
        }
    }

    /// Kept from the three maps a client installs from, and nothing else: a dependency's
    /// `devDependencies` are never installed.
    #[test]
    fn only_installed_dependency_maps_are_read_for_direct_specifiers() {
        let doc = br#"{"name":"x","versions":{"1.0.0":{"version":"1.0.0",
            "dist":{"tarball":"https://registry.npmjs.org/x/-/x-1.0.0.tgz"},
            "dependencies":{"a":"^1.0.0","b":"github:o/r#v1","c":"npm:d@1","e":"file:../x"},
            "optionalDependencies":{"f":"https://host/f.tgz","n":7},
            "peerDependencies":{"g":"o/r"},
            "devDependencies":{"h":"git+https://host/h.git"}},
          "2.0.0":{"version":"2.0.0",
            "dist":{"tarball":"https://registry.npmjs.org/x/-/x-2.0.0.tgz"},
            "dependencies":["legacy"],"peerDependencies":null,"optionalDependencies":5}}}"#;
        let metadata = normalize_packument(doc, DocumentDetail::Abbreviated).expect("reads");
        let named: Vec<(String, String)> = metadata
            .version("1.0.0")
            .expect("listed")
            .direct_dependencies
            .iter()
            .map(|d| (d.name.clone(), d.spec.clone()))
            .collect();
        assert_eq!(
            named,
            [
                ("b".to_owned(), "github:o/r#v1".to_owned()),
                ("e".to_owned(), "file:../x".to_owned()),
                ("f".to_owned(), "https://host/f.tgz".to_owned()),
                ("g".to_owned(), "o/r".to_owned()),
            ]
        );
        assert!(
            metadata
                .version("2.0.0")
                .expect("listed")
                .direct_dependencies
                .is_empty()
        );
    }

    #[cfg(not(coverage))]
    use super::super::{DEFAULT_REGISTRY, classify_path};
    #[cfg(not(coverage))]
    use crate::origin::{ReachableOrigins, bypassing_origin, rewrite_artifact_origins};
    #[cfg(not(coverage))]
    use crate::route::RequestTarget;

    #[test]
    fn publish_times_are_read_without_normalising() {
        let times = parse_publish_times(&fixture("lodash-4.17.21.full.json"))
            .expect("the full fixture carries a time map");

        assert_eq!(
            times.get("4.17.21").map(|t| t.to_string()),
            Some("2021-02-20T15:42:16.891Z".to_owned())
        );
    }

    /// `created` and `modified` sit in the `time` map and are not versions.
    #[test]
    fn the_package_level_timestamps_are_not_versions() {
        let times = parse_publish_times(
            br#"{"time":{"created":"2011-01-01T00:00:00.000Z",
                 "modified":"2021-01-01T00:00:00.000Z","1.0.0":"2012-06-01T00:00:00.000Z"}}"#,
        )
        .expect("should parse");

        assert_eq!(times.keys().collect::<Vec<_>>(), ["1.0.0"]);
    }

    /// The abbreviated document has no `time` map at all, which is why the full one has
    /// to be fetched.
    #[test]
    fn the_abbreviated_document_yields_no_times() {
        let times =
            parse_publish_times(&fixture("lodash-4.17.21.abbrev.json")).expect("should parse");

        assert!(times.is_empty());
    }

    #[test]
    fn an_unparseable_timestamp_drops_that_version_rather_than_the_document() {
        let times = parse_publish_times(
            br#"{"time":{"1.0.0":"not a timestamp","1.0.1":"2012-06-01T00:00:00.000Z"}}"#,
        )
        .expect("should parse");

        assert_eq!(times.keys().collect::<Vec<_>>(), ["1.0.1"]);
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error() {
        assert!(parse_publish_times(b"<html>").is_err());
    }

    /// Nothing may be dropped quietly. A version the normaliser cannot read has to be
    /// visible, because a version that disappears is a version no policy gates.
    fn assert_nothing_skipped(p: &PackageMetadata) {
        assert!(
            p.skipped.is_empty(),
            "unexpectedly skipped: {:?}",
            p.skipped
        );
    }

    #[test]
    fn abbreviated_carries_artifact_and_provenance_but_no_publish_time() {
        let p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
        assert_nothing_skipped(&p);
        assert_eq!(p.key.registry_name(), "lodash");

        let r = p.version("4.17.21").expect("version 4.17.21");
        assert_eq!(
            r.artifact().expect("one file").url,
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        assert!(
            r.artifact()
                .expect("one file")
                .integrity
                .as_deref()
                .unwrap()
                .starts_with("sha512-")
        );
        assert_eq!(
            r.artifact().expect("one file").legacy_sha1.as_deref(),
            Some("679591c564c3bffaae8454cf0b3df370c3d6911c")
        );
        assert!(!r.has_install_scripts);

        assert!(r.published_at.is_none(), "abbreviated has no `time` map");
        assert!(r.maintainers.is_none());
        assert!(r.repository.is_none());
        assert!(r.may_be_incomplete());
    }

    /// The fields the full document adds, and the reason the proxy would ever fetch it.
    #[test]
    fn full_adds_publish_time_maintainers_and_repository() {
        let p = normalized("lodash-4.17.21.full.json", DocumentDetail::Full);
        assert_nothing_skipped(&p);

        let r = p.version("4.17.21").expect("version 4.17.21");
        assert_eq!(
            r.published_at.map(|t| t.to_string()).as_deref(),
            Some("2021-02-20T15:42:16.891Z")
        );
        let maintainers = r.maintainers.as_ref().expect("full carries maintainers");
        assert!(maintainers.iter().any(|m| m.name == "jdalton"));
        let repo = r.repository.as_ref().expect("full carries repository");
        assert_eq!(repo.url, "git+https://github.com/lodash/lodash.git");
        assert_eq!(repo.kind.as_deref(), Some("git"));
        assert!(!r.may_be_incomplete());
    }

    /// `dist-tags.latest` is kept as a string: the lodash fixture tags 4.18.1 as latest
    /// while carrying only 4.17.21.
    #[test]
    fn dist_tag_latest_may_name_a_version_the_document_does_not_carry() {
        let p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
        assert_eq!(p.latest.as_deref(), Some("4.18.1"));
        assert!(p.version("4.18.1").is_none());
        assert_eq!(p.records.len(), 1);
    }

    /// `created` and `modified` in the `time` map do not become versions.
    #[test]
    fn time_map_metadata_keys_do_not_become_versions() {
        let p = normalized("lodash-4.17.21.full.json", DocumentDetail::Full);
        assert_eq!(p.records.len(), 1);
        assert!(p.version("created").is_none());
        assert!(p.version("modified").is_none());
    }

    /// The same package read from both documents agrees on install scripts.
    #[test]
    fn install_script_detection_agrees_across_both_documents() {
        for (abbrev, full, expected) in [
            (
                "lodash-4.17.21.abbrev.json",
                "lodash-4.17.21.full.json",
                false,
            ),
            (
                "esbuild-0.28.2.abbrev.json",
                "esbuild-0.28.2.full.json",
                true,
            ),
            (
                "@babel_traverse-8.0.5.abbrev.json",
                "@babel_traverse-8.0.5.full.json",
                false,
            ),
            (
                "sigstore-5.0.0.abbrev.json",
                "sigstore-5.0.0.full.json",
                false,
            ),
        ] {
            let a = normalized(abbrev, DocumentDetail::Abbreviated);
            let f = normalized(full, DocumentDetail::Full);
            for (x, name) in [(&a, abbrev), (&f, full)] {
                let r = x.records.first().expect("one version per fixture");
                assert_eq!(
                    r.has_install_scripts, expected,
                    "{name} disagreed on has_install_scripts"
                );
            }
        }
    }

    /// The flag is answerable from either document; the bodies are full-only.
    #[test]
    fn script_bodies_are_full_only_and_limited_to_install_hooks() {
        let abbrev = normalized("esbuild-0.28.2.abbrev.json", DocumentDetail::Abbreviated);
        let r = abbrev.version("0.28.2").unwrap();
        assert!(r.has_install_scripts);
        assert!(r.install_scripts.is_none());

        let full = normalized("esbuild-0.28.2.full.json", DocumentDetail::Full);
        let r = full.version("0.28.2").unwrap();
        let scripts = r.install_scripts.as_ref().expect("full carries bodies");
        assert_eq!(
            scripts.get("postinstall").map(String::as_str),
            Some("node install.js")
        );
        assert!(
            !scripts.contains_key("build"),
            "only install hooks belong here; the rest never run on install"
        );
    }

    /// A scoped name from the document's `name` survives the trip into a purl.
    #[test]
    fn scoped_name_round_trips_from_document_to_purl() {
        let p = normalized(
            "@babel_traverse-8.0.5.abbrev.json",
            DocumentDetail::Abbreviated,
        );
        assert_eq!(p.key.registry_name(), "@babel/traverse");
        assert_eq!(p.key.namespace(), Some("@babel"));
        assert_eq!(p.key.name(), "traverse");

        let r = p.version("8.0.5").expect("version 8.0.5");
        assert_eq!(r.package.to_string(), "pkg:npm/%40babel/traverse@8.0.5");
    }

    /// Both documents carry attestations and signatures, so provenance does not depend
    /// on fetching the full packument.
    #[test]
    fn provenance_is_present_in_both_documents() {
        for (name, detail) in [
            ("sigstore-5.0.0.abbrev.json", DocumentDetail::Abbreviated),
            ("sigstore-5.0.0.full.json", DocumentDetail::Full),
        ] {
            let p = normalized(name, detail);
            let r = p.version("5.0.0").expect("version 5.0.0");
            assert_eq!(
                r.provenance.attestation_url.as_deref(),
                Some("https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0"),
                "{name}"
            );
            assert_eq!(
                r.provenance.predicate_type.as_deref(),
                Some("https://slsa.dev/provenance/v1"),
                "{name}"
            );
            assert_eq!(r.provenance.registry_signatures.len(), 1, "{name}");
            assert!(
                r.provenance.registry_signatures[0]
                    .key_id
                    .starts_with("SHA256:"),
                "{name}"
            );
        }
    }

    /// `trustedPublisher` says a CI identity published the version rather than a
    /// long-lived user token. It is in `_npmUser`, which the abbreviated document omits.
    #[test]
    fn trusted_publisher_is_full_only() {
        let abbrev = normalized("sigstore-5.0.0.abbrev.json", DocumentDetail::Abbreviated);
        assert!(
            abbrev
                .version("5.0.0")
                .unwrap()
                .provenance
                .trusted_publisher
                .is_none()
        );

        let full = normalized("sigstore-5.0.0.full.json", DocumentDetail::Full);
        let publisher = full
            .version("5.0.0")
            .unwrap()
            .provenance
            .trusted_publisher
            .as_ref()
            .expect("full carries _npmUser.trustedPublisher");
        assert_eq!(publisher.id, "github");
    }

    /// A monorepo package points at a subdirectory of its repository. Without it, source
    /// diffing compares the wrong tree.
    #[test]
    fn repository_directory_is_kept_for_monorepo_packages() {
        let p = normalized("@babel_traverse-8.0.5.full.json", DocumentDetail::Full);
        let repo = p.version("8.0.5").unwrap().repository.clone().unwrap();
        assert_eq!(repo.url, "https://github.com/babel/babel.git");
        assert_eq!(repo.directory.as_deref(), Some("packages/babel-traverse"));
    }

    /// npm accepts the shorthand string form. The object form is what registries
    /// normally serve, and both have to land in the same type.
    #[test]
    fn repository_parses_both_string_and_object_forms() {
        let object: Repository =
            serde_json::from_str(r#"{"type":"git","url":"git+https://x/y.git","extra":1}"#)
                .unwrap();
        assert_eq!(object.url, "git+https://x/y.git");
        assert_eq!(object.kind.as_deref(), Some("git"));

        let shorthand: Repository = serde_json::from_str(r#""github:user/repo""#).unwrap();
        assert_eq!(shorthand.url, "github:user/repo");
        assert_eq!(shorthand.kind, None);

        let no_url = serde_json::from_str::<Repository>(r#"{"type":"git"}"#);
        assert!(
            no_url.is_err(),
            "an object without a url is not a repository"
        );
    }

    /// A registry adding a field must not break an install passing through the proxy.
    /// This is the opposite of the policy loader, which rejects unknown keys.
    #[test]
    fn unknown_fields_are_ignored_rather_than_fatal() {
        let body = br#"{
            "name": "widget",
            "dist-tags": {"latest": "1.0.0"},
            "somethingNpmAddedLater": {"nested": true},
            "versions": {
                "1.0.0": {
                    "name": "widget",
                    "version": "1.0.0",
                    "brandNewField": 42,
                    "dist": {
                        "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz",
                        "integrity": "sha512-AAAA",
                        "futureDigest": "blake3-zzz"
                    }
                }
            }
        }"#;
        let p = normalize_packument(body, DocumentDetail::Abbreviated).expect("should parse");
        assert_nothing_skipped(&p);
        assert_eq!(p.records.len(), 1);
    }

    /// A version with no artifact cannot be fetched, hashed or gated, so it produces no
    /// record. It has to be reported rather than dropped.
    #[test]
    fn a_version_without_a_tarball_is_skipped_and_reported() {
        let body = br#"{
            "name": "widget",
            "versions": {
                "1.0.0": {"version": "1.0.0", "dist": {"integrity": "sha512-AAAA"}},
                "1.0.1": {"version": "1.0.1"},
                "1.0.2": {"version": "1.0.2", "dist": {
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.2.tgz"
                }}
            }
        }"#;
        let p = normalize_packument(body, DocumentDetail::Abbreviated).expect("should parse");
        assert_eq!(p.records.len(), 1);
        assert_eq!(
            p.version("1.0.2")
                .map(|r| r.artifact().expect("one file").url.as_str())
                .unwrap(),
            "https://registry.npmjs.org/widget/-/widget-1.0.2.tgz"
        );
        assert_eq!(
            p.skipped,
            vec![
                SkippedVersion {
                    version: "1.0.0".into(),
                    reason: "version has no `dist.tarball`".into(),
                },
                SkippedVersion {
                    version: "1.0.1".into(),
                    reason: "version has no `dist` object".into(),
                },
            ]
        );
    }

    /// A body the normaliser cannot read is a normalise error, not a fetch error, so the
    /// proxy never answers 502 for it.
    #[test]
    fn malformed_bodies_are_a_normalize_error_not_a_fetch_error() {
        assert!(matches!(
            normalize_packument(b"not json", DocumentDetail::Abbreviated),
            Err(NormalizeError::Json(_))
        ));
        assert!(matches!(
            normalize_packument(br#"{"versions":{}}"#, DocumentDetail::Abbreviated),
            Err(NormalizeError::Json(_)),
        ));
    }
    /// Whole real packuments normalise without a skipped version. Ignored by default; see
    /// docs/engineering_decisions/npm-packument-shapes.md for the corpus it needs.
    #[cfg(not(coverage))]
    #[test]
    #[ignore = "needs a corpus directory of packuments; see the doc comment"]
    fn real_packuments_normalise_without_skipping_anything() {
        use crate::env;
        let environment = env::process();
        let corpora: Vec<(String, DocumentDetail)> = [
            (environment.npm_corpus(), DocumentDetail::Abbreviated),
            (environment.npm_corpus_full(), DocumentDetail::Full),
        ]
        .into_iter()
        .filter_map(|(dir, detail)| {
            let dir = dir.unwrap_or_else(|e| panic!("{e}"))?;
            Some((dir.to_string_lossy().into_owned(), detail))
        })
        .collect();
        assert!(
            !corpora.is_empty(),
            "set {} and/or {} to corpus directories",
            env::NPM_CORPUS,
            env::NPM_CORPUS_FULL
        );

        for (dir, detail) in &corpora {
            check_corpus(dir, *detail);
        }

        if corpora.len() == 2 {
            cross_check_install_scripts(&corpora[0].0, &corpora[1].0);
        }
    }

    #[cfg(not(coverage))]
    fn cross_check_install_scripts(abbrev_dir: &str, full_dir: &str) {
        let load = |dir: &str, file: &std::path::Path, detail| {
            let body = std::fs::read(std::path::Path::new(dir).join(file)).ok()?;
            normalize_packument(&body, detail).ok()
        };

        let mut pairs = 0usize;
        let mut disagreements = Vec::new();

        for entry in std::fs::read_dir(abbrev_dir).expect("abbreviated corpus") {
            let name = entry.expect("readable entry").file_name();
            let file = std::path::Path::new(&name);
            if file.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let (Some(a), Some(f)) = (
                load(abbrev_dir, file, DocumentDetail::Abbreviated),
                load(full_dir, file, DocumentDetail::Full),
            ) else {
                continue;
            };

            for record in &a.records {
                let Some(other) = f.version(record.package.version()) else {
                    continue;
                };
                pairs += 1;
                if record.has_install_scripts != other.has_install_scripts {
                    disagreements.push(format!(
                        "{}: abbreviated={} full={}",
                        record.package, record.has_install_scripts, other.has_install_scripts
                    ));
                }
            }
        }

        println!("compared has_install_scripts across {pairs} version pairs");
        assert!(pairs > 0, "no packages appeared in both corpora");
        assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    }

    #[cfg(not(coverage))]
    fn check_corpus(dir: &str, detail: DocumentDetail) {
        let mut packages = 0usize;
        let mut versions = 0usize;
        let mut rewrote = 0usize;
        let mut failures = Vec::new();

        for entry in std::fs::read_dir(dir).expect("corpus directory should be readable") {
            let path = entry.expect("readable entry").path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let body = std::fs::read(&path).expect("readable packument");
            match normalize_packument(&body, detail) {
                Ok(p) => {
                    packages += 1;
                    versions += p.records.len();
                    for skip in &p.skipped {
                        failures.push(format!(
                            "{}: {} skipped: {}",
                            path.display(),
                            skip.version,
                            skip.reason
                        ));
                    }
                    for record in &p.records {
                        assert_eq!(
                            record.package.key(),
                            &p.key,
                            "{}: version key drifted from the document name",
                            path.display()
                        );

                        let url_path = record
                            .artifact()
                            .expect("one file")
                            .url
                            .split_once("://")
                            .and_then(|(_, rest)| rest.split_once('/'))
                            .map(|(_, p)| format!("/{p}"))
                            .unwrap_or_default();
                        assert_eq!(
                            bypassing_origin(
                                &record.artifact().expect("one file").url,
                                &default_origins()
                            ),
                            None,
                            "{}: artifact published off the registry",
                            record.artifact().expect("one file").url
                        );
                        match classify_path(&url_path) {
                            RequestTarget::Artifact { key, .. } => assert_eq!(
                                key, p.key,
                                "{url_path}: classified as a different package"
                            ),
                            other => failures
                                .push(format!("{url_path}: expected a tarball, got {other:?}")),
                        }
                    }
                }
                Err(e) => failures.push(format!("{}: {e}", path.display())),
            }

            if let Ok(p) = normalize_packument(&body, detail) {
                let artifacts: Vec<String> = p
                    .records
                    .iter()
                    .map(|r| r.artifact().expect("one file").url.clone())
                    .collect();
                match rewrite_artifact_origins(
                    &body,
                    artifacts.iter().map(String::as_str),
                    &default_origins(),
                    DEFAULT_REGISTRY,
                ) {
                    Ok(out) => {
                        rewrote += 1;
                        assert_eq!(
                            out.rewritten,
                            artifacts.len(),
                            "{}: not every artifact URL was found",
                            path.display()
                        );
                        assert_eq!(
                            out.body,
                            body,
                            "{}: the rewrite changed something other than a URL",
                            path.display()
                        );
                    }
                    Err(e) => failures.push(format!("{}: rewrite failed: {e}", path.display())),
                }
            }
        }

        println!("{dir}: normalised {versions} versions across {packages} packages ({detail:?})");
        println!("{dir}: rewrote and restored {rewrote} documents byte for byte");
        assert!(packages > 0, "corpus at {dir} held no .json files");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// `event-stream@0.9.1`, from 2012, carries only `dist.shasum` and no `integrity`.
    #[test]
    fn a_pre_sri_version_has_a_sha1_and_no_integrity() {
        let p = normalized(
            "event-stream-0.9.1.abbrev.json",
            DocumentDetail::Abbreviated,
        );
        assert_nothing_skipped(&p);

        let r = p.version("0.9.1").expect("version 0.9.1");
        assert_eq!(r.artifact().expect("one file").integrity, None);
        assert_eq!(
            r.artifact().expect("one file").legacy_sha1.as_deref(),
            Some("d13bd543138154f503146878ba500c005eb9d5cb")
        );
        assert_eq!(r.artifact().expect("one file").file_count, None);
        assert_eq!(r.artifact().expect("one file").unpacked_size, None);
    }

    /// npm's `deprecated`, carried in both documents, is read with its message.
    #[test]
    fn a_deprecated_version_carries_the_message_its_publisher_left() {
        for (name, detail) in [
            ("rimraf-1.0.0.abbrev.json", DocumentDetail::Abbreviated),
            ("rimraf-1.0.0.full.json", DocumentDetail::Full),
        ] {
            let p = normalized(name, detail);
            assert_eq!(
                p.records[0].deprecated.as_deref(),
                Some("Rimraf versions prior to v4 are no longer supported"),
                "{name}"
            );
        }
        let lodash = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
        assert_eq!(lodash.records[0].deprecated, None, "no key is no message");

        let undeprecated = br#"{"name":"x","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{
            "name":"x","version":"1.0.0","deprecated":"","dist":{
            "tarball":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-AAAA"}}}}"#;
        let p = normalize_packument(undeprecated, DocumentDetail::Abbreviated).expect("reads");
        assert_eq!(p.records[0].deprecated, None, "an empty message is not one");
    }

    /// `rimraf@1.0.0`'s own shorthand `repository` wins over the package-level object.
    #[test]
    fn version_repository_overrides_the_package_level_one() {
        let p = normalized("rimraf-1.0.0.full.json", DocumentDetail::Full);
        let repo = p
            .version("1.0.0")
            .expect("version 1.0.0")
            .repository
            .clone()
            .expect("full carries repository");

        assert_eq!(repo.url, "git://github.com/isaacs/rimraf.git");
        assert_eq!(repo.kind, None, "the shorthand form states no type");
        assert_ne!(
            repo.url, "git+ssh://git@github.com/isaacs/rimraf.git",
            "the package-level object must not shadow the version's own value"
        );
    }

    /// `test`, `prepare` and `prepublish` do not set the install-scripts flag.
    #[test]
    fn non_install_lifecycle_scripts_do_not_set_the_flag() {
        let p = normalized("rimraf-1.0.0.full.json", DocumentDetail::Full);
        let r = p.version("1.0.0").expect("version 1.0.0");
        assert!(!r.has_install_scripts);
        assert_eq!(
            r.install_scripts.as_ref().map(BTreeMap::len),
            Some(0),
            "the document had scripts, none of which run on install"
        );

        let body = br#"{"name":"widget","versions":{"1.0.0":{"version":"1.0.0",
            "scripts":{"prepare":"tsc","prepublish":"tsc","test":"jest"},
            "dist":{"tarball":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}}"#;
        let p = normalize_packument(body, DocumentDetail::Full).unwrap();
        assert!(!p.version("1.0.0").unwrap().has_install_scripts);
    }
    /// The origins a default deployment fronts.
    #[cfg(not(coverage))]
    fn default_origins() -> ReachableOrigins {
        ReachableOrigins::new([DEFAULT_REGISTRY], std::iter::empty()).expect("valid origins")
    }

    /// A document name's casing is preserved end to end, as `pkg:npm/AdultJS` needs.
    #[test]
    fn document_name_casing_is_preserved() {
        let body = br#"{"name":"AdultJS","versions":{"1.0.0":{"version":"1.0.0","dist":{
            "tarball":"https://registry.npmjs.org/AdultJS/-/AdultJS-1.0.0.tgz"}}}}"#;
        let p = normalize_packument(body, DocumentDetail::Abbreviated).unwrap();
        assert_eq!(p.key.registry_name(), "AdultJS");
        assert_eq!(
            p.version("1.0.0").unwrap().package.to_string(),
            "pkg:npm/AdultJS@1.0.0"
        );
    }

    /// A version key that is empty is skipped with the reason, and the rest are read.
    #[test]
    fn an_empty_version_key_is_skipped() {
        let body =
            br#"{"name": "a", "versions": {" ": {"dist": {"tarball": "https://r/a/-/a-1.0.0.tgz"}},
            "1.0.0": {"dist": {"tarball": "https://r/a/-/a-1.0.0.tgz"}}}}"#;
        let metadata = normalize_packument(body, DocumentDetail::Abbreviated).expect("reads");
        assert_eq!(metadata.records.len(), 1);
        assert_eq!(metadata.skipped.len(), 1);
        assert_eq!(metadata.skipped[0].version, " ");
        assert!(
            metadata.skipped[0].reason.contains("empty version"),
            "{:?}",
            metadata.skipped
        );
    }
}
