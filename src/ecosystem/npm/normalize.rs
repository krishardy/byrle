//! Turning a packument into records the policy engine reads.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::identity::{Ecosystem, PackageKey};
use crate::record::{
    Artifact, DocumentDetail, Maintainer, PackageMetadata, PackageRecord, Provenance,
    RegistrySignature, SkippedVersion, TrustedPublisher,
};

use super::error::NormalizeError;
use super::paths::tarball_filename;
use super::wire::{WireDist, WireMaintainer, WirePackument, WireVersion};

/// Turn a packument body into records.
///
/// `detail` says which document this is, and comes from what was asked for: the
/// `Accept` header sent, or the `Content-Type` returned. It is not inferred from the
/// content, because it qualifies every absent field in the result. Labelling an
/// abbreviated document `Full` would report "npm publishes no timestamp for this
/// version" when the truth is that nobody asked for one, and [`PackageRecord`]'s whole
/// `source` field exists to keep those apart.
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

    // Publish time comes from the document-level `time` map keyed by version. `created`
    // and `modified` live in the same map and describe the package, not a version; a
    // version literally named "created" would collide, and npm's own semver parsing
    // rejects that name, so the lookup is safe as written.
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
        has_install_scripts: scripts,
        // npm has no yank. A version is published or unpublished, and an unpublished one
        // is not in the packument at all.
        yanked: false,
        install_scripts: entry.scripts.as_ref().map(install_scripts),
        provenance: provenance(entry, dist),
        // One file. An npm version resolves to one tarball, so the version-level
        // install-scripts answer and the file's own are the same answer.
        artifacts: vec![Artifact {
            filename: tarball_filename(&url),
            runs_install_scripts: scripts,
            yanked: false,
            url,
            // Absent on two versions in the measured corpus, both from 2012. A record
            // with no `integrity` has only a SHA-1 digest behind it, which the policy
            // engine has to be able to see rather than have papered over here.
            integrity: dist.integrity.clone(),
            legacy_sha1: dist.shasum.clone(),
            file_count: dist.file_count,
            unpacked_size: dist.unpacked_size,
        }],
    })
}

/// The three lifecycle scripts npm runs on install. `prepare` and `prepublish` are
/// deliberately absent: they run when building from a git dependency or publishing, not
/// when installing a registry tarball.
const INSTALL_SCRIPT_NAMES: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Answer the same question from either document.
///
/// The abbreviated packument states it outright. The full packument never carries
/// `hasInstallScript` and has to be read from `scripts`. Checked equivalent across
/// 24,852 version pairs with no disagreement; see
/// `record::PackageRecord::has_install_scripts`.
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
        // No maintainer entry in the measured corpus lacked a name, but `name` is not
        // guaranteed by any schema. An entry missing one keeps an empty name rather
        // than being dropped, because the number of maintainers is itself a signal the
        // heuristics read.
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
    }
}

/// Only the `time` map, out of a full packument.
///
/// npm publishes version timestamps in the full document and nowhere else. The
/// abbreviated document that `npm install` asks for has no `time` map at all, and the
/// registry serves no projection of one: `?fields=time` returns the whole document
/// unchanged and `/<package>/time` is a 404, both checked against registry.npmjs.org.
///
/// So reading a publish date means fetching the full document, which is 1.7x to 3.6x the
/// abbreviated one on eight packages measured, and 15.7 MB for typescript. This parses
/// only the map rather than normalising, because building 3,823 records to read one field
/// per version is the part worth not doing.
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
mod tests {
    use super::super::{fixture, normalized};
    use super::*;
    use crate::record::Repository;

    // The corpus run below is the only caller, and it is compiled out under `cfg(coverage)`.
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

    /// `created` and `modified` sit in the same map and describe the package. A version
    /// named either would be rejected by npm's own semver parsing, so dropping them
    /// cannot lose a real version.
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

    /// `dist-tags.latest` is kept as a string and never resolved into a record here.
    /// The lodash fixture is the case: it tags 4.18.1 as latest while carrying only
    /// 4.17.21 in `versions`, and a resolver that assumed the tag names a present
    /// version would panic or invent one.
    #[test]
    fn dist_tag_latest_may_name_a_version_the_document_does_not_carry() {
        let p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
        assert_eq!(p.latest.as_deref(), Some("4.18.1"));
        assert!(p.version("4.18.1").is_none());
        assert_eq!(p.records.len(), 1);
    }

    /// `created` and `modified` share the `time` map with real versions and are package
    /// metadata. Reading either as a publish time would date every version to the same
    /// instant.
    #[test]
    fn time_map_metadata_keys_do_not_become_versions() {
        let p = normalized("lodash-4.17.21.full.json", DocumentDetail::Full);
        assert_eq!(p.records.len(), 1);
        assert!(p.version("created").is_none());
        assert!(p.version("modified").is_none());
    }

    /// The pairing is the point of the fixtures: the same package read both ways must
    /// agree on the install-script question, which each document answers by a different
    /// route.
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

    /// Identity comes from the document's `name`, and a scoped name has to survive the
    /// trip into a purl. This is the case most likely to regress, because npm and OSV
    /// each write scopes differently.
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

    /// A body the normaliser cannot read is our gap, not an upstream outage. The error
    /// type keeps it separate from a transport failure so the proxy never answers 502
    /// for it.
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
    /// Fixtures are curated, so they only prove the normaliser handles what was chosen
    /// for it. This runs it over whole real packuments instead.
    ///
    /// Compiled out under `cfg(coverage)`, which `make coverage` sets, along with the
    /// two live tests below. None of them run in a coverage build, and counting the
    /// body of a test that cannot run reports a gap in the test suite that is not one.
    ///
    /// Ignored by default because it needs a corpus on disk. Populate one per document
    /// kind and point the two environment variables at them:
    ///
    /// ```text
    /// curl -H "Accept: application/vnd.npm.install-v1+json" \
    ///     https://registry.npmjs.org/typescript > abbrev/typescript.json
    /// curl -H "Accept: application/json" \
    ///     https://registry.npmjs.org/typescript > full/typescript.json
    /// cargo test --lib -- --ignored --nocapture
    /// ```
    ///
    /// with [`crate::env::NPM_CORPUS`] set to `abbrev` and [`crate::env::NPM_CORPUS_FULL`]
    /// to `full`.
    ///
    /// It fails on any skipped version. A registry shape the normaliser cannot read is
    /// exactly what fixtures will not surface.
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

        // With both corpora present, the pairing is checkable at corpus scale: the same
        // version read two ways must agree on whether installing it runs a script, a
        // question each document answers by a different route.
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

                        // Every real tarball URL has to classify, and has to classify
                        // to the same package the document names.
                        let url_path = record
                            .artifact()
                            .expect("one file")
                            .url
                            .split_once("://")
                            .and_then(|(_, rest)| rest.split_once('/'))
                            .map(|(_, p)| format!("/{p}"))
                            .unwrap_or_default();
                        // Every artifact a real registry publishes has to be one the
                        // proxy will see, or verification never gets a chance.
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

            // Every real document has to survive the rewrite, and putting the URLs back
            // has to give the original bytes. That is the property re-serialising into a
            // JSON value could not offer.
            if let Ok(p) = normalize_packument(&body, detail) {
                let artifacts: Vec<String> = p
                    .records
                    .iter()
                    .map(|r| r.artifact().expect("one file").url.clone())
                    .collect();
                // Rewriting to the origin the URLs already name: every artifact is
                // found and replaced, and the result has to be the original bytes. That
                // exercises the whole copy path and checks that nothing but a URL moves.
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

    /// npm did not always publish SRI digests. `event-stream@0.9.1` (2012) carries only
    /// `dist.shasum`, so a record can exist with no `integrity` at all, and the policy
    /// engine has to be able to tell that apart from a strong digest it simply did not
    /// read.
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

    /// `rimraf@1.0.0` is the shorthand string form in the wild, and its document also
    /// gives the package-level `repository` as an object. The version's own value is
    /// what was true at publish time, so it has to win.
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

    /// A version whose only lifecycle entry is `test` runs nothing on install. `prepare`
    /// and `prepublish` are likewise excluded: they run when building from git or
    /// publishing, not when installing a registry tarball.
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

    /// Casing is preserved end to end. `pkg:npm/AdultJS` is a malicious-package advisory
    /// and `pkg:npm/adultjs` matches nothing, so lowercasing anywhere on this path loses
    /// the match (see `identity`).
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
}
