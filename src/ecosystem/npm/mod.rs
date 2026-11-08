//! npm: fetching packuments and normalising them into [`crate::record::PackageRecord`].
//!
//! Wire types accept keys they do not model, and a version that cannot be normalised is kept
//! in `skipped`: see docs/engineering_decisions/0079-npm-packument-shapes.md.

pub mod attestation;
pub mod clients;
pub mod error;
pub mod inspect;
pub mod lockfile;
pub mod normalize;
pub mod paths;
pub mod rewrite;
pub mod transport;
pub mod wire;

pub use error::{FetchError, NormalizeError};
pub use inspect::{PackumentOutcome, inspect_decoded, inspect_packument, read_packument};
pub use normalize::{normalize_packument, parse_publish_times};
pub use paths::{
    classify_path, detail_from_content_type, document_from_content_type, upstream_url,
};

#[cfg(test)]
use crate::record::DocumentDetail;
pub use rewrite::{Filtered, Rewrite, filter_unservable_versions, rewrite_packument};
pub use transport::{Client, fetched};

use crate::ecosystem::{PublishTimeSource, Registry, Setup, UncoveredMetadata};
use crate::identity::Ecosystem;
use crate::intel::providers::osv::bundle;
use crate::intel::providers::{datadog, github};
use crate::intel::range::VersionOrder;
use crate::intel::stream;

/// OSV's bundle for this ecosystem.
pub const OSV: stream::Stream = stream::osv(bundle::NPM_STREAM, bundle::NPM_BUNDLE, |bytes| {
    stream::osv_bundle(Ecosystem::Npm, bytes)
});

/// Datadog's manifest for this ecosystem.
pub const DATADOG: stream::Stream =
    stream::datadog(datadog::NPM_STREAM, datadog::NPM_MANIFEST, |bytes| {
        stream::datadog_manifest(Ecosystem::Npm, bytes)
    });

/// GitHub's advisories for this ecosystem.
pub const GITHUB: stream::Stream = stream::github(github::NPM_STREAM, github::NPM_QUERY, |bytes| {
    stream::github_advisories(Ecosystem::Npm, bytes)
});

/// The path the proxy serves npm's registry under.
pub const PREFIX: &str = "/npm/";

/// This ecosystem's row of [`crate::ecosystem::TABLE`].
pub const REGISTRY: Registry = Registry {
    ecosystem: Ecosystem::Npm,
    prefix: PREFIX,
    always_reachable: &[DEFAULT_REGISTRY],
    classify_path,
    read_media_type: document_from_content_type,
    documents: &[ABBREVIATED_ACCEPT, FULL_ACCEPT],
    other_is_probe: false,
    publish_times: PublishTimeSource {
        said: "the full packument, fetched under a cooldown",
        full_accept: Some(FULL_ACCEPT),
        cost: Some(
            "a full-packument fetch per package that the client never asked for. npm \
             publishes version timestamps only in the full document, measured at 1.7x to \
             3.6x the abbreviated one",
        ),
    },
    streams: &[&OSV, &DATADOG, &GITHUB],
    lockfiles: lockfile::LOCKFILES,
    unread_lockfiles: lockfile::UNREAD,
    clients: clients::CLIENTS,
    fetched_check: None,
    setup: Setup {
        client: clients::NPM.name,
        command: |url| format!("{} {url}", clients::NPM.set_registry),
        path: PREFIX,
    },
    uncovered_metadata: UncoveredMetadata::Refuse,
    versions: VersionOrder::SemVer,
    split_name: paths::split_name,
    canonical_name: paths::canonical_name,
    intel_alias: |_| None,
    filename_projects: |_| Vec::new(),
    published_name: Some(paths::published_name),
    upstream: crate::env::UPSTREAM_NPM,
    upstream_url: paths::upstream_url,
    read: |reading| {
        let crate::route::DocumentKind::Packument(detail) = reading.kind else {
            return Ok(None);
        };
        let packument = read_packument(
            reading.decoded,
            detail,
            reading.store,
            reading.origins,
            reading.encoded_bytes,
            reading.parse_started,
            reading.path,
        )?;
        Ok(Some(Box::new(Packument(packument))))
    },
    reader: |_| Some(|file| crate::analysis::npm_install_scripts(file)),
    layout: |_| Some(crate::analysis::source::Layout::Tar),
    source: |record| {
        let repository = record.repository.as_ref()?;
        Some((
            Some(crate::analysis::source::Repo::from_url(&repository.url)?),
            repository.directory.clone(),
        ))
    },
    compare_source: |package, built, job| {
        built
            .package(&job.name, job.directory.as_deref())
            .map(|built| crate::analysis::source::compare(package, &built))
    },
    unfound_source: "no package.json in the source names the package",
    upstream_check: None,
    keep_for_platforms: |_, _| {},
    provenance_bundle: attestation::provenance_bundle,
    osv_name: "npm",
    advisory_package: crate::ecosystem::as_named,
    metadata_names_repository: |record| record.detail == crate::record::DocumentDetail::Full,
    client: |http, upstream, max_bytes| {
        std::sync::Arc::new(Client::new(http, upstream).with_max_bytes(max_bytes))
    },
    write: |_| None,
    meaningless: &[crate::policy::merge::Rule::Yanked],
    install_scripts_unread: None,
    publishers: None,
    decides_head: false,
    signatures: None,
    sidecar: |_| None,
    also: &[],
};

/// npm's abbreviated packument media type, which is what `npm install` asks for.
pub const ABBREVIATED_ACCEPT: &str = "application/vnd.npm.install-v1+json";
/// The full packument, which the proxy asks for itself for publish times.
pub const FULL_ACCEPT: &str = "application/json";

/// The default registry, and the upstream the proxy points at unless configured.
pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// A packument from `tests/fixtures/npm/`.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
    std::fs::read(format!("{path}{name}")).expect("fixture is missing")
}

/// That packument, normalised. Every caller wants the records, not the bytes.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn normalized(name: &str, detail: DocumentDetail) -> crate::record::PackageMetadata {
    normalize_packument(&fixture(name), detail).expect("fixture should normalise")
}

/// A packument read on its way to the client.
struct Packument(Box<crate::record::PackageMetadata>);

impl crate::ecosystem::Document for Packument {
    fn metadata(&self) -> Option<&crate::record::PackageMetadata> {
        Some(&self.0)
    }

    fn rewrite(&self, r: &crate::ecosystem::Rewriting<'_>) -> Result<Option<Vec<u8>>, String> {
        rewrite_packument(Rewrite {
            decoded: r.decoded,
            packument: &self.0,
            base: r.base,
            origins: r.origins,
            refused_by_policy: r.refused_by_policy,
            refuse_unservable: r.refuse_unservable,
            path: r.path,
        })
    }
}
