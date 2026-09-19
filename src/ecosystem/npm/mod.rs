//! npm: fetching packuments and normalising them into [`crate::record::PackageRecord`].
//!
//! Written concretely against npm alone. What this shares with PyPI is what
//! [`crate::ecosystem::Registry`] names and nothing else; there is no `Registry` trait,
//! and `docs/engineering_decisions/adapter-interface.md` says why.
//!
//! # Unknown fields are accepted here, and rejected in the config loader
//!
//! The wire types below ignore keys they do not model. npm adds fields to packuments
//! without notice, and a registry doing that must never break an install passing
//! through the proxy. The policy loader takes the opposite position, rejecting unknown
//! keys, because a typo in an operator's policy must fail loudly rather than disable a
//! rule (see `docs/engineering_decisions/config-format-yaml-serde-saphyr.md`). Both
//! are deliberate; neither is a default to "fix".
//!
//! # What is measured rather than assumed
//!
//! Against 24,852 versions across 47 packages, each fetched as both documents (Sept
//! 2026). The set mixes current packages with ones published in 2011 and 2012, because
//! npm's oldest metadata is where the shapes stop being uniform.
//!
//! - Every version carried `dist.tarball`, and every version carried `dist.shasum`. A
//!   version without a tarball URL is therefore treated as a document defect and
//!   skipped, rather than modelled as an optional URL: with no artifact to fetch there
//!   is nothing to hash or gate.
//! - `dist.integrity` was **not** universal. Two versions lacked it, both published in
//!   2012 (`event-stream@0.9.1`, `vue@0.8.6`), leaving SHA-1 as the only digest npm
//!   offers for them. Hence `Artifact::integrity` is `Option`.
//! - The `versions` map key and the version object's own `version` field never
//!   disagreed. The key is used as the authority anyway, because that is what npm
//!   resolves a range against.
//! - `hasInstallScript` appeared as `true` on 901 versions and was absent on the rest.
//!   It was never present and `false`, so absence is read as "no install script".
//! - `repository` was an object 24,477 times and a bare string 5 times
//!   (`bower@1.8.11` through `1.8.14`, `rimraf@1.0.0`). The string form is rare and
//!   real, which is why the polymorphism is hand-written below.
//! - The abbreviated and full documents agreed on `has_install_scripts` for all 24,852
//!   version pairs, by their two different routes.
//!
//! `real_packuments_normalise_without_skipping_anything` in the tests re-runs all of
//! this against a corpus on disk.
//!
//! # Skipping is visible
//!
//! A version that cannot be normalised lands in [`crate::record::PackageMetadata::skipped`]
//! instead of being dropped. A package version that vanishes between the registry and
//! the policy engine is a version nothing gates, which is the shape of a bypass rather
//! than a parse detail.
//!
//! # Layout
//!
//! | File | Holds |
//! |---|---|
//! | `paths.rs` | what a request path refers to, and which document a response is |
//! | `wire.rs` | the packument as npm serves it |
//! | `normalize.rs` | wire types to [`crate::record::PackageMetadata`] |
//! | `inspect.rs` | decoding and normalising a packument body the proxy forwarded |
//! | `lockfile.rs` | the lockfiles npm, yarn 1, pnpm and bun write |
//! | `clients.rs` | npm, pnpm, yarn and bun, as `waharoa doctor` checks them |
//! | `rewrite.rs` | removing versions from a packument and repointing the rest |
//! | `transport.rs` | fetching a packument on the proxy's own behalf |
//! | `error.rs` | what can go wrong reading one, and fetching one |
//!
//! `crate::ecosystem::pypi` has the same files, minus `rewrite.rs`, `inspect.rs`, `lockfile.rs` and `clients.rs`.

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
/// The full document. Nothing in a normal install requests this; the proxy has to ask
/// for it on its own behalf to get publish times, maintainers and repository.
pub const FULL_ACCEPT: &str = "application/json";

/// The default registry, and the upstream the proxy points at unless configured.
pub const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";

/// A packument from `tests/fixtures/npm/`.
#[cfg(test)]
pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
    std::fs::read(format!("{path}{name}")).expect("fixture is missing")
}

/// That packument, normalised. Every caller wants the records, not the bytes.
#[cfg(test)]
pub(crate) fn normalized(name: &str, detail: DocumentDetail) -> crate::record::PackageMetadata {
    normalize_packument(&fixture(name), detail).expect("fixture should normalise")
}
