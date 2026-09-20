//! PyPI's simple index, read as PEP 691 JSON.
//!
//! Written concretely and on its own. What this shares with npm is what
//! [`crate::ecosystem::Registry`] names and nothing else; the rest of the two modules is
//! deliberately separate, because the adapter interface was extracted from both once both
//! worked rather than designed first.
//!
//! # How this differs from a packument, measured against `pypi.org` on 2026-09-16
//!
//! | | npm | PyPI |
//! |---|---|---|
//! | document | version-keyed, one entry per version | **file-keyed**: `requests` has 244 files for 160 versions |
//! | publish time | only in the full packument, 1.7x to 3.6x larger | `upload-time` per file, in the document pip already fetches |
//! | artifact host | `registry.npmjs.org` serves both | `files.pythonhosted.org`, not the index host |
//! | install script | `hasInstallScript` on the version | nothing; an sdist runs `setup.py` and a wheel does not |
//! | name | used as written | PEP 503 normalised, and the index 301s to the normalised form |
//! | per-version document | the packument is the only one | none under `/simple/`; PEP 658 gives per-**file** metadata at `<url>.metadata` |
//!
//! The first row is the one that matters: `PackageMetadata` is version-keyed, and a
//! PyPI project is not. Several files carry one version, and they are not interchangeable:
//! a wheel and an sdist for the same version differ in whether installing runs code.
//!
//! # Layout
//!
//! | File | Holds |
//! |---|---|
//! | `paths.rs` | what a request path refers to, PEP 503 names, PEP 427 filenames |
//! | `wire.rs` | the index as PyPI serves it, and the cleaned form |
//! | `normalize.rs` | the cleaned form to [`crate::record::PackageMetadata`] |
//! | `clients.rs` | pip and uv, as `waharoa doctor` checks them |
//! | `inspect.rs` | reading a forwarded index and keeping its records |
//! | `version.rs` | PEP 440 versions and their order |
//! | `rewrite.rs` | removing refused versions from an index and pointing its files at the proxy |
//! | `transport.rs` | fetching an index on the proxy's own behalf |
//! | `error.rs` | what can go wrong reading one, and fetching one |
//!
//! `crate::ecosystem::npm` has the same files plus `lockfile.rs` and `clients.rs`.

pub mod clients;
pub mod error;
pub mod html;
pub mod inspect;
pub mod lockfile;
pub mod normalize;
pub mod paths;
pub mod rewrite;
pub mod transport;
pub mod version;
pub mod wire;

pub use error::PypiError;
pub use inspect::{Index, read_index};
pub use normalize::normalize;
pub use paths::{classify_path, document_from_content_type, index_url, normalise, upstream_url};
pub use transport::{Client, FetchError};
pub use wire::{File, Kind, Project, parse};

/// What `waharoa` sends to ask for JSON rather than HTML. PEP 691.
pub const SIMPLE_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// PEP 691's name for the HTML form. An index that predates PEP 691 answers `text/html`,
/// which is read the same way.
pub const SIMPLE_HTML: &str = "application/vnd.pypi.simple.v1+html";

/// The path prefix PEP 503 puts a project's index under.
pub const SIMPLE: &str = "/simple/";

/// The index this build reads.
pub const INDEX: &str = "https://pypi.org/simple";

/// Where PyPI serves the files its index names.
///
/// Not configurable and not derived from [`INDEX`]: the index gives each file's URL in
/// full, and a mirror serving the index still points at this host for files it does not
/// hold. Measured over nine projects on 2026-09-16, every one of 12,164 file URLs was on
/// this host.
pub const FILES: &str = "https://files.pythonhosted.org";

/// Bytes past which an index document is refused. `requests` was 123,104 bytes as JSON on
/// 2026-09-16, the largest of the eight measured; 32 MiB matches the npm packument ceiling.
pub const MAX_INDEX_BYTES: usize = 32 << 20;

/// The `requests` index from `tests/fixtures/pypi/`.
#[cfg(test)]
pub(crate) fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/pypi/requests.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("the fixture is present")
}
