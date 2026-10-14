//! PyPI's simple index, as PEP 691 JSON or a PEP 503 page. An index is keyed by file, not
//! by version, and serves its files from another host: see
//! docs/engineering_decisions/pypi-simple-index.md.

pub mod attestation;
pub mod clients;
pub mod error;
pub mod html;
pub mod inspect;
pub mod lockfile;
pub mod normalize;
pub mod paths;
pub mod rewrite;
pub mod transport;
pub mod wheel;
pub mod wire;

pub use error::PypiError;
pub use inspect::{Index, read_index};
pub use normalize::normalize;
pub use paths::{classify_path, document_from_content_type, index_url, normalise, upstream_url};
pub use transport::{Client, FetchError};
pub use wire::{File, Kind, Project, parse};

use crate::ecosystem::{PublishTimeSource, Registry, Setup, UncoveredMetadata};
use crate::identity::Ecosystem;
use crate::intel::providers::osv::bundle;
use crate::intel::providers::{datadog, github};
use crate::intel::range::VersionOrder;
use crate::intel::stream;

/// OSV's bundle for this ecosystem.
pub const OSV: stream::Stream = stream::osv(bundle::PYPI_STREAM, bundle::PYPI_BUNDLE, |bytes| {
    stream::osv_bundle(Ecosystem::PyPI, bytes)
});

/// Datadog's manifest for this ecosystem.
pub const DATADOG: stream::Stream =
    stream::datadog(datadog::PYPI_STREAM, datadog::PYPI_MANIFEST, |bytes| {
        stream::datadog_manifest(Ecosystem::PyPI, bytes)
    });

/// GitHub's advisories for this ecosystem.
pub const GITHUB: stream::Stream =
    stream::github(github::PYPI_STREAM, github::PYPI_QUERY, |bytes| {
        stream::github_advisories(Ecosystem::PyPI, bytes)
    });

/// This ecosystem's row of [`crate::ecosystem::TABLE`].
pub const REGISTRY: Registry = Registry {
    ecosystem: Ecosystem::PyPI,
    prefixes: &[SIMPLE, "/packages/"],
    always_reachable: &[INDEX, FILES],
    classify_path,
    read_media_type: document_from_content_type,
    documents: &[SIMPLE_JSON, SIMPLE_HTML, "text/html"],
    other_is_probe: true,
    publish_times: PublishTimeSource {
        said: "in the document",
        full_accept: None,
        cost: None,
    },
    streams: &[&OSV, &DATADOG, &GITHUB],
    lockfiles: lockfile::LOCKFILES,
    unread_lockfiles: lockfile::UNREAD,
    clients: clients::CLIENTS,
    setup: Setup {
        client: "pip",
        command: clients::pip_set_index,
        path: SIMPLE,
    },
    uncovered_metadata: UncoveredMetadata::FilterWithoutIntel,
    versions: VersionOrder::Pep440,
    split_name: paths::split_name,
    canonical_name: paths::canonical_name,
    upstream: crate::env::UPSTREAM_PYPI,
    upstream_url: paths::upstream_url,
    read: |reading| {
        let crate::route::DocumentKind::SimpleIndex(format) = reading.kind else {
            return None;
        };
        let index = read_index(
            reading.decoded,
            format,
            reading.page,
            reading.store,
            reading.path,
        )?;
        Some(Box::new(index))
    },
    reader: |filename| {
        (!filename.ends_with(".whl"))
            .then_some(crate::analysis::sdist_install_scripts as crate::analysis::Reader)
    },
    layout: |filename| {
        use crate::analysis::source::Layout;
        if filename.ends_with(".whl") {
            Some(Layout::Wheel)
        } else {
            filename.ends_with(".tar.gz").then_some(Layout::Tar)
        }
    },
    source: |_| Some((None, None)),
    compare_source: |package, built, job| {
        crate::analysis::source::compare_pypi(package, built, job.layout)
    },
    unfound_source: "none of the package's Python files is in the source",
    upstream_check: Some(crate::ecosystem::UpstreamCheck {
        accept: SIMPLE_JSON,
        check: clients::check_index_format,
    }),
    keep_for_platforms: wheel::keep_for_platforms,
    provenance_bundle: attestation::provenance_bundle,
    osv_name: "PyPI",
    metadata_names_repository: |_| false,
    client: |http, upstream, max_bytes| {
        std::sync::Arc::new(Client::new(http, upstream).with_max_bytes(max_bytes))
    },
};

/// What `byrle` sends to ask for JSON rather than HTML. PEP 691.
pub const SIMPLE_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// PEP 691's name for the HTML form, read as `text/html` is.
pub const SIMPLE_HTML: &str = "application/vnd.pypi.simple.v1+html";

/// The path prefix PEP 503 puts a project's index under.
pub const SIMPLE: &str = "/simple/";

/// The index this build reads.
pub const INDEX: &str = "https://pypi.org/simple";

/// Where PyPI serves the files its index names, whichever index names them.
pub const FILES: &str = "https://files.pythonhosted.org";

/// Bytes past which an index is refused: the packument ceiling, so one number bounds both.
pub const MAX_INDEX_BYTES: usize = crate::env::DEFAULT_MAX_METADATA_BYTES;

/// The `requests` index from `tests/fixtures/pypi/`.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/pypi/requests.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("the fixture is present")
}

impl crate::ecosystem::Document for Index {
    fn metadata(&self) -> Option<&crate::record::PackageMetadata> {
        self.metadata.as_deref()
    }

    fn rewrite(&self, r: &crate::ecosystem::Rewriting<'_>) -> Option<Vec<u8>> {
        rewrite::rewrite_index(rewrite::Rewrite {
            decoded: r.decoded,
            format: self.format,
            project: &self.project,
            reachable: r.origins.reachable(),
            base: r.base,
            refused_by_policy: r.refused_by_policy,
            path: r.path,
        })
    }
}
