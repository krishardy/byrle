//! The Go module proxy protocol under [`PREFIX`]: `@v/list` and `@latest` filtered by policy,
//! zips fetched at the proxy, and sum.golang.org relayed. See docs/go-plan.md.

pub mod dirhash;
pub mod inspect;
pub mod note;
pub mod paths;
pub mod sumdb;
pub mod tlog;
pub mod transport;
pub mod wire;

pub use paths::{classify_path, document_from_content_type, upstream_url};
pub use transport::Client;

use crate::ecosystem::{PublishTimeSource, Registry, Setup, UncoveredMetadata, Writing, Written};
use crate::identity::Ecosystem;
use crate::intel::providers::osv::bundle;
use crate::intel::range::VersionOrder;
use crate::intel::stream;
use crate::policy::merge::Rule;

/// OSV's bundle for this ecosystem.
pub const OSV: stream::Stream = stream::osv(bundle::GO_STREAM, bundle::GO_BUNDLE, |bytes| {
    stream::osv_bundle(Ecosystem::Go, bytes)
});

/// This ecosystem's row of [`crate::ecosystem::TABLE`].
pub const REGISTRY: Registry = Registry {
    ecosystem: Ecosystem::Go,
    prefix: PREFIX,
    always_reachable: &[PROXY],
    classify_path,
    read_media_type: document_from_content_type,
    documents: &["text/plain", "application/json"],
    other_is_probe: false,
    publish_times: PublishTimeSource {
        said: "`Time` in each version's `.info`, and in `@latest`",
        full_accept: None,
        cost: Some(
            "an `.info` fetch per version of a `@v/list`, newest first, until one is older \
             than the cooldown",
        ),
    },
    streams: &[&OSV],
    lockfiles: &[],
    unread_lockfiles: &[],
    clients: &[],
    setup: Setup {
        client: "go",
        command: |url| format!("go env -w GOPROXY={url}"),
        path: "/go",
    },
    uncovered_metadata: UncoveredMetadata::FilterWithoutIntel,
    versions: VersionOrder::Go,
    split_name: paths::split_name,
    canonical_name: paths::canonical_name,
    upstream: crate::env::UPSTREAM_GO,
    upstream_url,
    read: inspect::read,
    reader: |_| None,
    layout: |_| None,
    source: |_| None,
    compare_source: |_, _, _| None,
    unfound_source: "the module proxy's documents name no repository",
    upstream_check: None,
    keep_for_platforms: |_, _| {},
    provenance_bundle: |_| Err("the Go module proxy serves no attestations".to_owned()),
    osv_name: "Go",
    advisory_package,
    metadata_names_repository: |_| false,
    client: |http, upstream, max_bytes| std::sync::Arc::new(Client::new(http, upstream, max_bytes)),
    write,
    meaningless: &[Rule::Deprecated, Rule::Yanked, Rule::InstallScripts],
    install_scripts_unread: None,
    publishers: None,
};

/// The module an OSV record's name stands for: `toolchain` is `golang.org/toolchain`, the
/// module go downloads a Go release as, and `stdlib` is in every Go release and no module.
fn advisory_package(name: &str) -> Option<String> {
    match name {
        "stdlib" => None,
        "toolchain" => Some(TOOLCHAIN.to_owned()),
        module => Some(module.to_owned()),
    }
}

/// The module a Go release is downloaded as when `go.mod` asks for a newer go.
pub const TOOLCHAIN: &str = "golang.org/toolchain";

/// The path the proxy serves Go modules under.
pub const PREFIX: &str = "/go/";

/// The module proxy this build reads.
pub const PROXY: &str = "https://proxy.golang.org";

/// sum.golang.org's `supported`, which the proxy answers itself: proxy.golang.org and
/// sum.golang.org both answer 404, which sends go to sum.golang.org directly.
fn write(writing: &Writing<'_>) -> Option<Result<Written, String>> {
    let path = writing.path.split('?').next().unwrap_or(writing.path);
    let supported = format!("{PREFIX}{}supported", paths::SUMDB);
    (path == supported).then(|| {
        Ok(Written {
            content_type: "text/plain",
            body: Vec::new(),
        })
    })
}

/// A file from `tests/fixtures/go/`.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/go/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("the fixture is present")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn written(path: &str) -> Option<Result<Written, String>> {
        write(&Writing {
            path,
            base: None,
            tokens_required: true,
        })
    }

    /// go asks `<GOPROXY>/sumdb/sum.golang.org/supported` before it asks sum.golang.org itself.
    #[test]
    fn the_proxy_says_it_relays_sum_golang_org() {
        let supported = written("/go/sumdb/sum.golang.org/supported")
            .expect("written")
            .expect("ok");
        assert!(supported.body.is_empty());
        for other in [
            "/go/sumdb/sum.golang.org/latest",
            "/go/sumdb/other.example/supported",
            "/sumdb/sum.golang.org/supported",
        ] {
            assert!(written(other).is_none(), "{other}");
        }
    }

    /// The Go module proxy serves no attestations, and a module's zip is the same on every
    /// platform.
    #[test]
    fn one_zip_per_version_and_no_attestations() {
        let key =
            crate::identity::PackageKey::from_registry_name(Ecosystem::Go, "golang.org/x/text")
                .unwrap();
        let metadata = wire::list(&key, b"v1.0.0\n", "https://p.example/x/@v/");
        let mut files: Vec<_> = metadata.records[0].artifacts.iter().collect();
        (REGISTRY.keep_for_platforms)(&mut files, &[]);
        assert_eq!(files.len(), 1);
        assert!((REGISTRY.provenance_bundle)(b"{}").is_err());
        assert!((REGISTRY.reader)("v1.0.0.zip").is_none());
        assert!((REGISTRY.layout)("v1.0.0.zip").is_none());
        assert!((REGISTRY.source)(&metadata.records[0]).is_none());
        assert!(!(REGISTRY.metadata_names_repository)(&metadata.records[0]));
        assert_eq!(
            REGISTRY.setup.command_line("https://h"),
            "go env -w GOPROXY=https://h/go"
        );
    }
}
