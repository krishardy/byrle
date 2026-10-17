//! cargo's sparse registry protocol: `config.json`, written by the proxy, index files of one
//! JSON line per version, and `.crate` downloads checked against each line's `cksum`. See
//! docs/cargo-plan.md.

pub mod clients;
pub mod inspect;
pub mod lockfile;
pub mod paths;
pub mod transport;
pub mod trustpub;
pub mod wire;

pub use inspect::{IndexFile, read_index};
pub use paths::{classify_path, document_from_content_type, upstream_url};
pub use transport::Client;

use crate::ecosystem::{PublishTimeSource, Registry, Setup, UncoveredMetadata, Writing, Written};
use crate::identity::Ecosystem;
use crate::intel::providers::osv::bundle;
use crate::intel::range::VersionOrder;
use crate::intel::stream;

/// OSV's bundle for this ecosystem.
pub const OSV: stream::Stream = stream::osv(bundle::CARGO_STREAM, bundle::CARGO_BUNDLE, |bytes| {
    stream::osv_bundle(Ecosystem::Cargo, bytes)
});

/// This ecosystem's row of [`crate::ecosystem::TABLE`].
pub const REGISTRY: Registry = Registry {
    ecosystem: Ecosystem::Cargo,
    prefix: PREFIX,
    always_reachable: &[INDEX, FILES],
    classify_path,
    read_media_type: document_from_content_type,
    documents: &["text/plain"],
    other_is_probe: false,
    publish_times: PublishTimeSource {
        said: "`pubtime` on each line of the index file",
        full_accept: None,
        cost: None,
    },
    streams: &[&OSV],
    lockfiles: lockfile::LOCKFILES,
    unread_lockfiles: lockfile::UNREAD,
    clients: clients::CLIENTS,
    setup: Setup {
        client: "cargo",
        command: config_line,
        path: PREFIX,
    },
    uncovered_metadata: UncoveredMetadata::FilterWithoutIntel,
    versions: VersionOrder::SemVer,
    split_name: paths::split_name,
    canonical_name: paths::canonical_name,
    upstream: crate::env::UPSTREAM_CARGO,
    upstream_url,
    read: |reading| {
        let crate::route::DocumentKind::IndexLines = reading.kind else {
            return None;
        };
        Some(Box::new(read_index(
            reading.decoded,
            reading.store,
            reading.path,
        )))
    },
    reader: |filename| {
        filename.ends_with(".crate").then_some(
            (|file| crate::analysis::crate_build_scripts(file)) as crate::analysis::Reader,
        )
    },
    layout: |_| None,
    source: |_| None,
    compare_source: |_, _, _| None,
    unfound_source: "crates.io's index names no repository",
    upstream_check: None,
    keep_for_platforms: |_, _| {},
    provenance_bundle: |_| Err("crates.io serves no attestations".to_owned()),
    osv_name: "crates.io",
    advisory_package: crate::ecosystem::as_named,
    metadata_names_repository: |_| false,
    client: |http, upstream, max_bytes| std::sync::Arc::new(Client::new(http, upstream, max_bytes)),
    write,
    meaningless: &[crate::policy::merge::Rule::Deprecated],
    install_scripts_unread: Some(
        "crates.io's index does not say; the .crate is read when it is downloaded",
    ),
    publishers: Some(trustpub::made),
    decides_head: false,
    signatures: None,
    sidecar: |_| None,
    also: &[],
};

/// What points cargo at `url`, the proxy's cargo registry, with or without a trailing `/`.
pub fn config_line(url: &str) -> String {
    format!(
        "in ~/.cargo/config.toml: [registries.byrle] index = \"sparse+{}/\" and \
         credential-provider = \"cargo:token\", [source.crates-io] replace-with = \"byrle\", \
         and [net] retry = {NET_RETRY}",
        url.trim_end_matches('/')
    )
}

/// cargo's retries, at most 10 s each: about 300 crates' lookups at one a second.
pub const NET_RETRY: u32 = 30;

/// The path the proxy serves cargo's registry under.
pub const PREFIX: &str = "/cargo/";

/// The sparse index this build reads.
pub const INDEX: &str = "https://index.crates.io";

/// Where crates.io serves `.crate` files, whichever index lists them.
pub const FILES: &str = "https://static.crates.io";

/// cargo's first request, which says where downloads are.
const CONFIG: &str = "config.json";

/// `config.json`, with `dl` at the proxy so each download is checked, and `auth-required`
/// when the proxy asks for a token: without it cargo sends none with a download.
fn write(writing: &Writing<'_>) -> Option<Result<Written, String>> {
    let path = writing.path.split('?').next().unwrap_or(writing.path);
    if path.strip_prefix(PREFIX) != Some(CONFIG) {
        return None;
    }
    let Some(base) = writing.base else {
        return Some(Err(
            "the request named no Host, so config.json has no address for downloads".to_owned(),
        ));
    };
    let config = serde_json::json!({
        "dl": format!("{base}{PREFIX}{}", paths::CRATES),
        "auth-required": writing.tokens_required,
    });
    Some(Ok(Written {
        content_type: "application/json",
        body: config.to_string().into_bytes(),
    }))
}

/// itoa's index file from `tests/fixtures/cargo/`.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn fixture() -> Vec<u8> {
    let path = format!("{}/tests/fixtures/cargo/itoa", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("the fixture is present")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn written(
        path: &str,
        base: Option<&str>,
        tokens_required: bool,
    ) -> Option<Result<String, String>> {
        write(&Writing {
            path,
            base,
            tokens_required,
        })
        .map(|w| {
            w.map(|w| {
                assert_eq!(w.content_type, "application/json");
                String::from_utf8(w.body).unwrap()
            })
        })
    }

    /// cargo 1.99.0 sent no token with a download unless `auth-required` was set.
    #[test]
    fn config_json_points_downloads_at_the_proxy_and_asks_for_a_token_when_one_is_required() {
        assert_eq!(
            written("/cargo/config.json", Some("https://h/registry"), true),
            Some(Ok(
                r#"{"auth-required":true,"dl":"https://h/registry/cargo/crates"}"#.to_owned()
            ))
        );
        assert_eq!(
            written("/cargo/config.json?x", Some("http://h"), false),
            Some(Ok(
                r#"{"auth-required":false,"dl":"http://h/cargo/crates"}"#.to_owned()
            ))
        );
        assert!(written("/cargo/config.json", None, true).is_some_and(|w| w.is_err()));
        for other in ["/cargo/se/rd/serde", "/config.json", "/cargo/x/config.json"] {
            assert_eq!(written(other, Some("http://h"), true), None, "{other}");
        }
    }

    /// crates.io lists one file per version and serves no attestations.
    #[test]
    fn one_file_per_version_and_no_attestations() {
        let metadata = wire::normalize(&fixture()).unwrap();
        let mut files: Vec<_> = metadata.records[0].artifacts.iter().collect();
        (REGISTRY.keep_for_platforms)(&mut files, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(
            (REGISTRY.provenance_bundle)(b"{}").unwrap_err(),
            "crates.io serves no attestations"
        );
    }

    /// The line names every setting cargo 1.99.0 needed against a stub registry.
    #[test]
    fn the_setup_line_names_the_index_the_credential_provider_and_the_replacement() {
        let line = REGISTRY.setup.command_line("http://127.0.0.1:8080");
        for needed in [
            "index = \"sparse+http://127.0.0.1:8080/cargo/\"",
            "credential-provider = \"cargo:token\"",
            "replace-with = \"byrle\"",
            "[net] retry = 30",
        ] {
            assert!(line.contains(needed), "{line}");
        }
    }
}
