//! What a request path refers to and what a response body is, in terms every ecosystem
//! answers. Each ecosystem's `classify_path` produces these and `proxy::handle` reads them.

use crate::identity::PackageKey;
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
    /// A version's manifest, served once checked against its claim, never refused: `go.mod`.
    Manifest {
        key: PackageKey,
        version: String,
        /// The file the path names, which a claim may be asked of.
        filename: String,
    },
    /// A path of a shape the adapter lists and forwards: npm's `/-/v1/search`, PyPI's `/simple/`.
    Other,
    /// A path under the prefix of no shape the adapter lists: refused, or forwarded in observe.
    Unrecognised,
}

/// Which metadata document a response body is, read from its `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    /// An npm packument, abbreviated or full.
    Packument(DocumentDetail),
    /// A simple index, in the form the index served it.
    SimpleIndex(IndexFormat),
    /// A cargo index file: one JSON line per version.
    IndexLines,
    /// A Go module's `@v/list`: one version per line.
    VersionList,
    /// A Go module's `@latest`: one version's JSON.
    Latest,
    /// A Maven artifact's `maven-metadata.xml`.
    MavenMetadata,
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

/// Which repository answers this request path, and what the path refers to. `None` for a
/// path under no repository's prefix.
pub fn classify(path: &str) -> Option<(crate::ecosystem::Repository, RequestTarget)> {
    let repository = crate::ecosystem::serving(path)?;
    Some((repository, repository.registry().classify(path)))
}

/// Whether a request path, its query left out, has a segment the upstream URL's parser
/// would remove: `.` or `..`, with `%2e` in any case, split on `/` or `\`. The fetched path
/// would then differ from the one classified.
pub fn rewritten_by_url_parser(path: &str) -> bool {
    let path = crate::http::url_path(path);
    path.split(['/', '\\']).any(|segment| {
        let dots = segment.to_ascii_lowercase().replace("%2e", ".");
        dots == "." || dots == ".."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_the_url_parser_removes_is_found() {
        for path in [
            "/npm/-/npm/v1/attestations/../../evil/-/evil-6.6.6.tgz",
            "/npm/-/npm/v1/attestations/%2e%2e/%2E%2e/evil",
            "/npm/-/npm/v1/attestations/.%2E/evil",
            "/npm/-/npm/v1/attestations/%2e/evil",
            "/npm/./lodash",
            "/npm/-/npm/v1/attestations\\..\\evil",
        ] {
            assert!(rewritten_by_url_parser(path), "{path}");
        }
    }

    #[test]
    fn a_path_the_url_parser_keeps_is_not() {
        for path in [
            "/npm/-/v1/search?text=../..",
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "/npm/-/npm/v1/attestations/..%5cevil",
            "/npm/-/npm/v1/attestations/..%2fevil",
            "/npm/-/npm/v1/attestations/...",
            "/pypi/simple/a.b/",
        ] {
            assert!(!rewritten_by_url_parser(path), "{path}");
        }
    }
}
