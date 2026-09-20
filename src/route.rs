//! What a request path refers to and what a response body is, in terms every ecosystem
//! answers.
//!
//! The proxy serves more than one registry, and each spells its paths differently:
//! npm's `/lodash` and `/lodash/-/lodash-4.17.21.tgz`, PyPI's `/simple/requests/` and
//! `/packages/<hash>/<hash>/<hash>/requests-2.32.3-py3-none-any.whl`. Every registry
//! serves the same two kinds of thing behind those paths, so `proxy::handle` reads this
//! and each ecosystem's `classify_path` produces it.

use crate::identity::{Ecosystem, PackageKey};
use crate::record::DocumentDetail;

/// What a request path refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    /// The document listing a package's versions: npm's packument, PyPI's simple index
    /// page.
    Metadata(PackageKey),
    /// One installable file.
    Artifact {
        key: PackageKey,
        /// The version as the **filename** spells it, which is not always the version
        /// the metadata uses. Of 24,852 npm tarball URLs measured, 38 differ: every
        /// prerelease of `express` before 3.0.0 and of `grunt` before 0.4.0 drops the
        /// hyphen, so `express@3.0.0-rc1` is served at `express-3.0.0rc1.tgz`.
        ///
        /// Nothing may treat this as an identity. Resolving it means matching the
        /// artifact against a record from the metadata, which is the fetch-path work
        /// in plan §5.
        claimed_version: String,
        /// The filename as the path spells it. npm serves one file per version, so there
        /// the version reaches the file; PyPI serves several, each with its own digest,
        /// so there it does not. This is what both can name.
        filename: String,
    },
    /// Anything else the registry serves: npm's `/-/v1/search`, PyPI's `/simple/`.
    Other,
}

/// Which metadata document a response body is.
///
/// Read from the response's `Content-Type`, not the request: npm asks for both packument
/// kinds in one `Accept` header and settles nothing, and an index may answer HTML where
/// PEP 691 JSON was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    /// An npm packument, abbreviated or full.
    Packument(DocumentDetail),
    /// A simple index, in the form the index served it.
    SimpleIndex(IndexFormat),
}

/// Which of the two simple-index forms a body is.
///
/// PEP 691 added the JSON form and PyPI serves it. An index that predates it, or has not
/// added it, serves the PEP 503 page: `download.pytorch.org`, `pypi.nvidia.com`,
/// `www.piwheels.org` and `data.pyg.org` all did on 2026-09-21, whatever `Accept` asked
/// for.
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
    Some(content_type?.split(';').next()?.trim().to_ascii_lowercase())
}

/// Which ecosystem answers this request path, and what the path refers to.
///
/// The proxy serves npm at the root, because that is where a client configured with
/// `registry=http://proxy/` looks, and PyPI under the prefixes its
/// [`crate::ecosystem::Registry`] entry reserves. A path under one of those is PyPI's
/// whatever it turns out to be, including when it names no project: sending pip's other
/// requests to an npm registry answers them with npm's 404 rather than PyPI's.
pub fn classify(path: &str) -> (Ecosystem, RequestTarget) {
    let registry = crate::ecosystem::serving(path);
    (registry.ecosystem, registry.classify(path))
}
