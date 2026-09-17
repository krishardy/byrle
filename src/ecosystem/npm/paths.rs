//! What an npm request path refers to, and which document a response body is.
//!
//! npm serves packuments at the root and tarballs under `/<name>/-/<file>.tgz`, so the
//! path alone answers both questions this module is asked.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::record::PackumentDetail;
use crate::route::{DocumentKind, RequestTarget};

use super::{ABBREVIATED_ACCEPT, FULL_ACCEPT};

/// Build an npm key from a registry-reported name.
///
/// An npm name carries a `/` only when it is scoped, and a scope always starts with `@`.
/// `PackageKey::from_registry_name` splits on the `/` without asking, because it is shared
/// with PyPI, so `foo/bar` would reach a purl of `pkg:npm/foo/bar`, a package npm cannot
/// have. The proxy serves npm at the root and PyPI under `/simple/`, and a request for
/// `/simple/requests` is the shape that made this matter.
pub(super) fn key_from_name(name: &str) -> Result<PackageKey, IdentityError> {
    let trimmed = name.trim();
    if trimmed.contains('/') && !trimmed.starts_with('@') {
        return Err(IdentityError::Malformed(format!(
            "`{name}` is not a valid npm package name: a `/` needs an `@` scope"
        )));
    }
    PackageKey::from_registry_name(Ecosystem::Npm, trimmed)
}

/// Classify a request path.
///
/// Paths that do not resolve to a package, including names this crate cannot turn into
/// an identity, come back as [`RequestTarget::Other`]. A path the proxy cannot classify
/// is still forwarded; it is not an error.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return RequestTarget::Other;
    }

    // Registry endpoints live under `/-/`. A package name cannot start with `-`, so a
    // leading segment of `-` is never a package.
    if path == "-" || path.starts_with("-/") {
        return RequestTarget::Other;
    }

    let (name, artifact) = match path.split_once("/-/") {
        Some((name, artifact)) => (name, Some(artifact)),
        None => (path, None),
    };

    // npm percent-encodes the scope separator on packument requests and leaves it bare
    // on tarball paths. Both spell the same package.
    let name = name.replace("%2f", "/").replace("%2F", "/");
    let Ok(key) = key_from_name(&name) else {
        return RequestTarget::Other;
    };

    let Some(artifact) = artifact else {
        return RequestTarget::Metadata(key);
    };

    // `<unscoped name>-<version>.tgz`, with the scope absent from the filename.
    let Some(stem) = artifact.strip_suffix(".tgz") else {
        return RequestTarget::Other;
    };
    let Some(version) = stem
        .strip_prefix(key.name())
        .and_then(|rest| rest.strip_prefix('-'))
        .filter(|v| !v.is_empty())
    else {
        return RequestTarget::Other;
    };

    RequestTarget::Artifact {
        key,
        claimed_version: version.to_owned(),
        filename: artifact.to_owned(),
    }
}

/// Which document a response body is, read from its `Content-Type`.
///
/// The response is authoritative and the request is not: npm asks with
/// `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*`, which
/// names both documents and settles nothing.
///
/// Across 18 responses from registry.npmjs.org (6 packages, scoped and unscoped, each
/// of the three Accept headers above), the value was exactly one of the two media types
/// with no `charset` parameter. Parameters and casing are handled anyway, since a mirror
/// or a CDN in front of one may add them. Anything else returns `None`, and the proxy
/// forwards that response without reading it.
pub fn detail_from_content_type(content_type: Option<&str>) -> Option<PackumentDetail> {
    match crate::route::media_type(content_type)?.as_str() {
        ABBREVIATED_ACCEPT => Some(PackumentDetail::Abbreviated),
        FULL_ACCEPT => Some(PackumentDetail::Full),
        _ => None,
    }
}

/// Where a request goes upstream: the configured registry with the client's path appended.
///
/// A private mirror publishes `registry.npmjs.org` artifact URLs while being the whole
/// reason the proxy was pointed at it, so the URL in the document is deliberately not what
/// decides.
pub fn upstream_url(registry: &str, path_and_query: &str) -> String {
    format!("{registry}{path_and_query}")
}

/// npm's row of [`crate::ecosystem::TABLE`] reads media types through this.
///
/// Both npm packument kinds are the same document to everything outside npm, so which one
/// arrived rides along in [`DocumentKind::Packument`].
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    detail_from_content_type(content_type).map(DocumentKind::Packument)
}

/// The last path segment of a tarball URL, which is the filename a request names.
///
/// Query and fragment are dropped: `classify_path` reads the path alone, so a URL
/// carrying either would otherwise never match the request that fetches it.
pub(super) fn tarball_filename(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ecosystem::npm::{NormalizeError, normalize_packument, normalized};

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
    }

    #[test]
    fn packument_paths_resolve_to_a_key() {
        assert_eq!(
            classify_path("/lodash"),
            RequestTarget::Metadata(key("lodash"))
        );
        assert_eq!(
            classify_path("/@babel%2fcore"),
            RequestTarget::Metadata(key("@babel/core")),
            "npm percent-encodes the scope separator"
        );
        assert_eq!(
            classify_path("/@babel%2Fcore"),
            RequestTarget::Metadata(key("@babel/core"))
        );
        assert_eq!(
            classify_path("/@babel/core"),
            RequestTarget::Metadata(key("@babel/core")),
            "the bare form resolves too"
        );
        assert_eq!(
            classify_path("/lodash?write=true"),
            RequestTarget::Metadata(key("lodash")),
            "a query string is not part of the name"
        );
    }

    #[test]
    fn tarball_paths_carry_the_filename_version() {
        assert_eq!(
            classify_path("/lodash/-/lodash-4.17.21.tgz"),
            RequestTarget::Artifact {
                key: key("lodash"),
                claimed_version: "4.17.21".into(),
                filename: "lodash-4.17.21.tgz".into()
            }
        );
        assert_eq!(
            classify_path("/@babel/core/-/core-7.0.0.tgz"),
            RequestTarget::Artifact {
                key: key("@babel/core"),
                claimed_version: "7.0.0".into(),
                filename: "core-7.0.0.tgz".into()
            },
            "the scope is absent from the filename"
        );
    }

    /// A prerelease version contains hyphens, and the filename is split on the last
    /// hyphen of the package name, not the first hyphen in the string.
    #[test]
    fn prerelease_versions_survive_the_filename_split() {
        assert_eq!(
            classify_path("/react/-/react-18.3.0-canary-a1b2c3.tgz"),
            RequestTarget::Artifact {
                key: key("react"),
                claimed_version: "18.3.0-canary-a1b2c3".into(),
                filename: "react-18.3.0-canary-a1b2c3.tgz".into()
            }
        );
        assert_eq!(
            classify_path("/is-odd/-/is-odd-3.0.1.tgz"),
            RequestTarget::Artifact {
                key: key("is-odd"),
                claimed_version: "3.0.1".into(),
                filename: "is-odd-3.0.1.tgz".into()
            },
            "hyphens in the package name are not version separators"
        );
    }

    /// 38 of 24,852 tarball URLs spell the version differently from the packument:
    /// every `express` prerelease before 3.0.0 and every `grunt` prerelease before
    /// 0.4.0 drops the hyphen. The path says `3.0.0rc1`, the packument says
    /// `3.0.0-rc1`.
    #[test]
    fn the_filename_version_is_what_the_filename_says() {
        let RequestTarget::Artifact {
            claimed_version, ..
        } = classify_path("/express/-/express-3.0.0rc1.tgz")
        else {
            panic!("should classify as a tarball");
        };
        assert_eq!(claimed_version, "3.0.0rc1");
        assert_ne!(
            claimed_version, "3.0.0-rc1",
            "the packument spells this version with a hyphen; the path does not"
        );
    }

    #[test]
    fn registry_endpoints_and_junk_are_not_packages() {
        for path in [
            "/",
            "",
            "/-/v1/search?text=lodash",
            "/-/whoami",
            "/-/npm/v1/attestations/sigstore@5.0.0",
            "/-",
            "/lodash/-/lodash-4.17.21.tar.gz",
            "/lodash/-/something-else.tgz",
            "/lodash/-/lodash-.tgz",
            "/@scope/",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
        }
    }

    /// An npm scope starts with `@`. `PackageKey::from_registry_name` splits on the
    /// `/` without asking, so without the check `/foo/bar` classified as
    /// `pkg:npm/foo/bar`, and `/simple/requests` as `pkg:npm/simple/requests`.
    #[test]
    fn a_slash_without_an_at_is_not_a_scoped_package() {
        for path in [
            "/foo/bar",
            "/simple/requests",
            "/packages/x",
            "/foo/bar/-/bar-1.0.0.tgz",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
        }
        assert_eq!(
            classify_path("/@foo/bar"),
            RequestTarget::Metadata(key("@foo/bar")),
            "the scoped spelling is still a package"
        );
    }

    /// The artifact a request names is the last segment of the URL the packument
    /// published, so a record can be looked up by the filename the path carries.
    #[test]
    fn a_record_names_its_tarball_by_the_filename_the_path_uses() {
        let p = normalized("lodash-4.17.21.abbrev.json", PackumentDetail::Abbreviated);
        let record = p.version("4.17.21").expect("4.17.21");
        let artifact = record.artifact().expect("one file");
        assert_eq!(artifact.filename, "lodash-4.17.21.tgz");
        assert_eq!(
            classify_path("/lodash/-/lodash-4.17.21.tgz"),
            RequestTarget::Artifact {
                key: key("lodash"),
                claimed_version: "4.17.21".into(),
                filename: artifact.filename.clone(),
            },
            "the path and the record name the same file"
        );
        assert_eq!(record.artifacts.len(), 1, "a version is one tarball");
        assert_eq!(artifact.runs_install_scripts, record.has_install_scripts);
    }

    #[test]
    fn a_tarball_url_with_a_query_still_names_its_file() {
        assert_eq!(
            tarball_filename("https://r/a/-/a-1.0.tgz?x=1#y"),
            "a-1.0.tgz"
        );
        assert_eq!(tarball_filename("a-1.0.tgz"), "a-1.0.tgz");
    }

    /// A packument claiming an unscoped name with a `/` is refused rather than
    /// normalised into a purl npm cannot have.
    #[test]
    fn a_packument_naming_an_unscoped_slash_does_not_normalize() {
        let body = br#"{"name":"foo/bar","versions":{}}"#;
        let error = normalize_packument(body, PackumentDetail::Full).expect_err("not a name");
        assert!(matches!(error, NormalizeError::Name(_)), "{error:?}");
    }

    /// npm asks for both documents in one Accept header, so the response is the only
    /// thing that says which arrived.
    #[test]
    fn detail_comes_from_the_response_content_type() {
        assert_eq!(
            detail_from_content_type(Some("application/vnd.npm.install-v1+json; charset=utf-8")),
            Some(PackumentDetail::Abbreviated)
        );
        assert_eq!(
            detail_from_content_type(Some("application/json")),
            Some(PackumentDetail::Full)
        );
        assert_eq!(
            detail_from_content_type(Some("Application/JSON; charset=UTF-8")),
            Some(PackumentDetail::Full)
        );
        assert_eq!(
            detail_from_content_type(Some("application/octet-stream")),
            None
        );
        assert_eq!(detail_from_content_type(Some("text/html")), None);
        assert_eq!(detail_from_content_type(None), None);
    }
}
