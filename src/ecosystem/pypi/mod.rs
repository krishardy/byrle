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
pub mod version;
pub mod wheel;
pub mod wire;

pub use error::PypiError;
pub use inspect::{Index, read_index};
pub use normalize::normalize;
pub use paths::{classify_path, document_from_content_type, index_url, normalise, upstream_url};
pub use transport::{Client, FetchError};
pub use wire::{File, Kind, Project, parse};

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
