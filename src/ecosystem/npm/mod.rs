//! npm: fetching packuments and normalising them into [`crate::record::PackageRecord`].
//!
//! Wire types accept keys they do not model, and a version that cannot be normalised is kept
//! in `skipped`: see docs/engineering_decisions/npm-packument-shapes.md.

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
