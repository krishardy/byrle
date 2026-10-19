//! What an npm request path refers to, and which document a response body is.
//!
//! npm serves packuments at the root and tarballs under `/<name>/-/<file>.tgz`, so the
//! path alone answers both questions this module is asked.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::record::DocumentDetail;
use crate::route::{DocumentKind, RequestTarget};

use super::{ABBREVIATED_ACCEPT, FULL_ACCEPT};

/// A name in a policy selector, as written. npm does not fold case: names with capitals,
/// such as `JSONStream`, were published before new names had to be lowercase.
pub fn canonical_name(name: &str) -> String {
    name.to_owned()
}

/// Split an npm name into its scope and its name: `@babel/core` is `@babel` and `core`.
/// `name` must be scoped when it contains a `/`.
pub fn split_name(name: &str) -> Result<(Option<String>, String), IdentityError> {
    let Some((scope, rest)) = name.split_once('/') else {
        return Ok((None, name.to_owned()));
    };
    if !scope.starts_with('@') {
        return Err(IdentityError::Malformed(format!(
            "`{name}` is not a valid npm package name: a `/` needs an `@` scope"
        )));
    }
    if rest.is_empty() || rest.contains('/') {
        return Err(IdentityError::Malformed(format!(
            "`{name}` is not a valid npm package name"
        )));
    }
    Ok((Some(scope.to_owned()), rest.to_owned()))
}

/// Whether npm could publish `name`: the scope and the name in characters
/// `encodeURIComponent` leaves alone, and an unscoped name not starting with `.` or `_`.
pub fn published_name(name: &str) -> bool {
    match name
        .strip_prefix('@')
        .and_then(|scoped| scoped.split_once('/'))
    {
        Some((scope, bare)) => url_safe(scope) && url_safe(bare),
        None => url_safe(name) && !name.starts_with(['.', '_']),
    }
}

/// Whether `part` is non-empty and every character is one a URL carries unescaped.
fn url_safe(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b))
}

/// Classify a request path.
/// `path` is the request path, with or without a query.
/// Returns [`RequestTarget::Other`] for an endpoint `is_endpoint` lists, and
/// [`RequestTarget::Unrecognised`] for any other path that names no package.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let Some(path) = crate::ecosystem::within(super::PREFIX, path) else {
        return RequestTarget::Unrecognised;
    };
    let path = path.trim_start_matches('/');
    if path == "-" {
        return RequestTarget::Unrecognised;
    }
    if let Some(endpoint) = path.strip_prefix("-/") {
        return if is_endpoint(endpoint) {
            RequestTarget::Other
        } else {
            RequestTarget::Unrecognised
        };
    }

    let (name, artifact) = match path.split_once("/-/") {
        Some((name, artifact)) => (name, Some(artifact)),
        None => (path, None),
    };

    let name = name.replace("%2f", "/").replace("%2F", "/");
    let Ok(key) = PackageKey::from_registry_name(Ecosystem::Npm, &name) else {
        return RequestTarget::Unrecognised;
    };

    let Some(artifact) = artifact else {
        return RequestTarget::Metadata(key);
    };

    let Some(stem) = artifact.strip_suffix(".tgz") else {
        return RequestTarget::Unrecognised;
    };
    let Some(version) = stem
        .strip_prefix(key.name())
        .and_then(|rest| rest.strip_prefix('-'))
        .filter(|v| !v.is_empty())
    else {
        return RequestTarget::Unrecognised;
    };

    RequestTarget::Artifact {
        key,
        claimed_version: version.to_owned(),
        filename: artifact.to_owned(),
    }
}

/// Whether `endpoint`, the path after `/-/`, is a registry endpoint a client asks that serves
/// no package file: ping, whoami, search, the audit and signing endpoints, a version's
/// attestations, and a package's dist-tags.
fn is_endpoint(endpoint: &str) -> bool {
    const ENDPOINTS: [&str; 6] = [
        "ping",
        "whoami",
        "v1/search",
        "npm/v1/security/advisories/bulk",
        "npm/v1/security/audits/quick",
        "npm/v1/keys",
    ];
    ENDPOINTS.contains(&endpoint)
        || endpoint.starts_with("npm/v1/attestations/")
        || endpoint
            .strip_prefix("package/")
            .and_then(|rest| rest.strip_suffix("/dist-tags"))
            .is_some_and(|name| {
                PackageKey::from_registry_name(
                    Ecosystem::Npm,
                    &name.replace("%2f", "/").replace("%2F", "/"),
                )
                .is_ok()
            })
}

/// Which document a response body is, read from its `Content-Type`.
/// Returns `None` for anything but the two packument media types.
pub fn detail_from_content_type(content_type: Option<&str>) -> Option<DocumentDetail> {
    match crate::route::media_type(content_type)?.as_str() {
        ABBREVIATED_ACCEPT => Some(DocumentDetail::Abbreviated),
        FULL_ACCEPT => Some(DocumentDetail::Full),
        _ => None,
    }
}

/// Where a request goes upstream: the configured registry with the client's path appended.
///
/// A private mirror publishes `registry.npmjs.org` artifact URLs while being the whole
/// reason the proxy was pointed at it, so the URL in the document is deliberately not what
/// decides.
pub fn upstream_url(registry: &str, path_and_query: &str) -> String {
    let path = crate::ecosystem::within(super::PREFIX, path_and_query).unwrap_or(path_and_query);
    format!("{registry}{path}")
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    use crate::ecosystem::npm::{NormalizeError, normalize_packument, normalized};

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, name).unwrap()
    }

    /// A path outside `/npm/`, such as the root npm was served at before, names nothing.
    #[test]
    fn a_path_outside_the_prefix_names_no_package() {
        for path in [
            "/lodash",
            "/lodash/-/lodash-4.17.21.tgz",
            "/npmx/lodash",
            "/npm/",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Unrecognised, "{path}");
        }
    }

    /// The registry endpoints clients ask are forwarded; any other path naming no package
    /// is unrecognised, a tarball that does not parse among them.
    #[test]
    fn registry_endpoints_are_forwarded_and_junk_is_unrecognised() {
        for path in [
            "/npm/-/ping",
            "/npm/-/v1/search?text=lodash",
            "/npm/-/whoami",
            "/npm/-/npm/v1/security/advisories/bulk",
            "/npm/-/npm/v1/security/audits/quick",
            "/npm/-/npm/v1/keys",
            "/npm/-/npm/v1/attestations/sigstore@5.0.0",
            "/npm/-/package/lodash/dist-tags",
            "/npm/-/package/@babel%2fcore/dist-tags",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
        }
        for path in [
            "/",
            "",
            "/npm/-",
            "/npm/-/",
            "/npm/-/v1/login",
            "/npm/-/package/foo/bar/dist-tags",
            "/npm/-/package/lodash/access",
            "/npm/lodash/-/lodash-4.17.21.tar.gz",
            "/npm/lodash/-/something-else.tgz",
            "/npm/lodash/-/lodash-.tgz",
            "/npm/@scope/",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Unrecognised, "{path}");
        }
    }

    /// validate-npm-package-name's rules, with the capitals and `~!*'()` legacy names have.
    #[test]
    fn a_published_name_is_url_safe_and_an_unscoped_one_starts_with_neither_dot_nor_underscore() {
        for (name, published) in [
            ("lodash", true),
            ("JSONStream", true),
            ("@babel/core", true),
            ("@scope/_private", true),
            ("cheerio!(beta)~*'", true),
            ("", false),
            (".hidden", false),
            ("_private", false),
            ("lo?dash", false),
            ("lo#dash", false),
            ("lo%2edash", false),
            ("lo dash", false),
            ("@foo", false),
            ("@/core", false),
            ("@sc?pe/core", false),
            ("@scope/co?re", false),
        ] {
            assert_eq!(published_name(name), published, "{name}");
        }
    }

    /// An npm scope starts with `@`. Without the check in `split_name`, `/foo/bar`
    /// classified as `pkg:npm/foo/bar`, and `/simple/requests` as `pkg:npm/simple/requests`.
    #[test]
    fn a_slash_without_an_at_is_not_a_scoped_package() {
        for path in [
            "/npm/foo/bar",
            "/pypi/simple/requests",
            "/pypi/packages/x",
            "/npm/foo/bar/-/bar-1.0.0.tgz",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Unrecognised, "{path}");
        }
        assert_eq!(
            classify_path("/npm/@foo/bar"),
            RequestTarget::Metadata(key("@foo/bar")),
            "the scoped spelling is still a package"
        );
    }

    /// The artifact a request names is the last segment of the URL the packument
    /// published, so a record can be looked up by the filename the path carries.
    #[test]
    fn a_record_names_its_tarball_by_the_filename_the_path_uses() {
        let p = normalized("lodash-4.17.21.abbrev.json", DocumentDetail::Abbreviated);
        let record = p.version("4.17.21").expect("4.17.21");
        let artifact = record.artifact().expect("one file");
        assert_eq!(artifact.filename, "lodash-4.17.21.tgz");
        assert_eq!(
            classify_path("/npm/lodash/-/lodash-4.17.21.tgz"),
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
        let error = normalize_packument(body, DocumentDetail::Full).expect_err("not a name");
        assert!(matches!(error, NormalizeError::Name(_)), "{error:?}");
    }

    /// npm asks for both documents in one Accept header, so the response is the only
    /// thing that says which arrived.
    #[test]
    fn detail_comes_from_the_response_content_type() {
        assert_eq!(
            detail_from_content_type(Some("application/vnd.npm.install-v1+json; charset=utf-8")),
            Some(DocumentDetail::Abbreviated)
        );
        assert_eq!(
            detail_from_content_type(Some("application/json")),
            Some(DocumentDetail::Full)
        );
        assert_eq!(
            detail_from_content_type(Some("Application/JSON; charset=UTF-8")),
            Some(DocumentDetail::Full)
        );
        assert_eq!(
            detail_from_content_type(Some("application/octet-stream")),
            None
        );
        assert_eq!(detail_from_content_type(Some("text/html")), None);
        assert_eq!(detail_from_content_type(None), None);
    }
}
