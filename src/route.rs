//! What a request path refers to, in terms every ecosystem answers.
//!
//! The proxy serves more than one registry, and each spells its paths differently:
//! npm's `/lodash` and `/lodash/-/lodash-4.17.21.tgz`, PyPI's `/simple/requests/` and
//! `/packages/<hash>/<hash>/<hash>/requests-2.32.3-py3-none-any.whl`. Every registry
//! serves the same two kinds of thing behind those paths, so `proxy::handle` reads this
//! and each ecosystem's `classify_path` produces it.

use crate::identity::PackageKey;

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
