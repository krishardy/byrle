//! What a request path refers to and what a response body is, in terms every ecosystem
//! answers. Each ecosystem's `classify_path` produces these and `proxy::handle` reads them.

use crate::identity::{Ecosystem, PackageKey};
use crate::record::DocumentDetail;

/// What a request path refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    /// The document listing a package's versions: npm's packument, PyPI's index page.
    Metadata(PackageKey),
    /// One installable file.
    Artifact {
        key: PackageKey,
        /// The version as the filename spells it, which may differ from the metadata's.
        claimed_version: String,
        /// The filename as the path spells it.
        filename: String,
    },
    /// Anything else the registry serves: npm's `/-/v1/search`, PyPI's `/simple/`.
    Other,
}

/// Which metadata document a response body is, read from its `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    /// An npm packument, abbreviated or full.
    Packument(DocumentDetail),
    /// A simple index, in the form the index served it.
    SimpleIndex(IndexFormat),
}

/// Which of the two simple-index forms a body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFormat {
    /// PEP 691 JSON.
    Json,
    /// PEP 503 HTML: a list of anchors.
    Html,
}

/// The media type out of a `Content-Type`, lowercased, with parameters dropped.
///
/// `application/json; charset=UTF-8` and `Application/JSON` both give `application/json`.
/// Every ecosystem's reader compares against a constant, so they all start here.
pub fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type.map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    })
}

/// Which ecosystem answers this request path, and what the path refers to.
/// A path under an ecosystem's prefix is that ecosystem's. npm has the rest.
/// Returns the ecosystem and the target.
pub fn classify(path: &str) -> (Ecosystem, RequestTarget) {
    let registry = crate::ecosystem::serving(path);
    (registry.ecosystem, registry.classify(path))
}
