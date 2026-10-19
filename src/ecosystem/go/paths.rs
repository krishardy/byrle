//! What a Go request path refers to, and where it goes upstream. go asks under [`PREFIX`]
//! for `<module>/@v/list`, `<module>/@latest` and `<module>/@v/<version>.info`, `.mod` and
//! `.zip`, each escaped, and for the checksum database under [`SUMDB`].

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::route::{DocumentKind, RequestTarget};

use super::PREFIX;

/// Where go asks a proxy for sum.golang.org, after [`PREFIX`].
pub const SUMDB: &str = "sumdb/sum.golang.org/";

/// What follows a module path to name its version list.
pub const LIST: &str = "/@v/list";

/// What follows a module path to name its newest version.
pub const LATEST: &str = "/@latest";

/// What follows a module path before a version's file.
const FILES: &str = "/@v/";

/// A path element as the module proxy and the checksum database spell it: each upper-case
/// letter as `!` and its lower case, since some file systems ignore case.
pub fn escape(element: &str) -> String {
    let mut out = String::with_capacity(element.len());
    for c in element.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// [`escape`] undone. `None` for an upper-case letter, or a `!` before anything but a
/// lower-case one, which go never writes.
pub fn unescape(escaped: &str) -> Option<String> {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '!' => out.push(
                chars
                    .next()
                    .filter(char::is_ascii_lowercase)?
                    .to_ascii_uppercase(),
            ),
            c if c.is_ascii_uppercase() => return None,
            c => out.push(c),
        }
    }
    Some(out)
}

/// Split a module path for its purl: the elements before the last as the namespace and the
/// last as the name, case kept. A path `is_module_path` refuses is not one.
pub fn split_name(path: &str) -> Result<(Option<String>, String), IdentityError> {
    if !is_module_path(path) {
        return Err(IdentityError::Malformed(format!(
            "`{path}` is not a valid Go module path"
        )));
    }
    Ok(match path.rsplit_once('/') {
        Some((namespace, name)) => (Some(namespace.to_owned()), name.to_owned()),
        None => (None, path.to_owned()),
    })
}

/// Whether `path` is a module path as `golang.org/x/mod/module.CheckPath` reads one: ASCII
/// letters, digits and `-._~` in elements neither empty nor starting or ending with `.`,
/// the first in lower case, holding a dot and not starting with `-`.
fn is_module_path(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or_default();
    let host = first.contains('.')
        && !first.starts_with('-')
        && first
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    host && path.split('/').all(|element| {
        !element.is_empty()
            && !element.starts_with('.')
            && !element.ends_with('.')
            && element
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    })
}

/// A module path in a policy selector, compared as written: Go's are case-sensitive.
pub fn canonical_name(name: &str) -> String {
    name.to_owned()
}

/// The file name the proxy gives a version's zip.
pub fn filename(version: &str) -> String {
    format!("{version}.zip")
}

/// The key of an escaped module path, `None` when it is not one.
fn key(escaped: &str) -> Option<PackageKey> {
    PackageKey::from_registry_name(Ecosystem::Go, &unescape(escaped)?).ok()
}

/// `@v/list` and `@latest` are a module's metadata, a `.zip` its artifact and a `.mod` its
/// manifest. A version's `.info` and the checksum database's `sumdb/<db>/` paths are none of
/// those, and any other path under [`PREFIX`] is unrecognised.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let Some(rest) = path.strip_prefix(PREFIX) else {
        return RequestTarget::Unrecognised;
    };
    if is_checksum_database(rest) {
        return RequestTarget::Other;
    }
    if let Some(module) = rest.strip_suffix(LATEST).or(rest.strip_suffix(LIST)) {
        return key(module).map_or(RequestTarget::Unrecognised, RequestTarget::Metadata);
    }
    let Some((module, file)) = rest.split_once(FILES) else {
        return RequestTarget::Unrecognised;
    };
    let (Some(key), Some((version, kind))) = (key(module), file.rsplit_once('.')) else {
        return RequestTarget::Unrecognised;
    };
    match (unescape(version), kind) {
        (Some(version), "zip") if is_version(&version) => RequestTarget::Artifact {
            filename: filename(&version),
            claimed_version: version,
            key,
        },
        (Some(version), "mod") if is_version(&version) => RequestTarget::Manifest {
            filename: format!("{version}.mod"),
            key,
            version,
        },
        (Some(version), "info") if is_version(&version) => RequestTarget::Other,
        _ => RequestTarget::Unrecognised,
    }
}

/// Whether `rest` is a checksum database path go asks a proxy for: `sumdb/<db>/supported`,
/// `latest`, `lookup/...` or `tile/...`.
fn is_checksum_database(rest: &str) -> bool {
    let Some((_, asked)) = rest
        .strip_prefix("sumdb/")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    matches!(asked, "supported" | "latest")
        || asked.starts_with("lookup/")
        || asked.starts_with("tile/")
}

/// Whether a path's version can be one: not empty, and no path of its own.
fn is_version(version: &str) -> bool {
    !version.is_empty() && !version.contains('/')
}

/// The checksum database's path goes to sum.golang.org, which go asks through the proxy
/// when the proxy says it can. The rest goes to `proxy`.
pub fn upstream_url(proxy: &str, path_and_query: &str) -> String {
    let rest = crate::ecosystem::within(PREFIX, path_and_query).unwrap_or(path_and_query);
    match rest.strip_prefix('/').and_then(|r| r.strip_prefix(SUMDB)) {
        Some(sumdb) => format!("{}/{sumdb}", super::sumdb::DEFAULT),
        None => format!("{proxy}{rest}"),
    }
}

/// The URL a module's version files are under, from the upstream URL of its `@v/list` or
/// `@latest`. `None` for any other.
pub fn files_url(page: &str) -> Option<String> {
    let page = page.split('?').next().unwrap_or(page);
    let module = page.strip_suffix(LIST).or(page.strip_suffix(LATEST))?;
    Some(format!("{module}{FILES}"))
}

/// A version list is `text/plain`; `@latest` is `application/json`.
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    match crate::route::media_type(content_type)?.as_str() {
        "text/plain" => Some(DocumentKind::VersionList),
        "application/json" => Some(DocumentKind::Latest),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn key(path: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Go, path).expect("a module path")
    }

    #[test]
    fn a_path_is_escaped_and_unescaped_as_the_go_command_spells_it() {
        assert_eq!(
            escape("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(
            unescape("github.com/!burnt!sushi/toml").as_deref(),
            Some("github.com/BurntSushi/toml")
        );
        for refused in ["github.com/BurntSushi", "a!", "a!B", "a!1"] {
            assert_eq!(unescape(refused), None, "{refused}");
        }
    }

    /// The purl keeps the case: `pkg:golang/github.com/BurntSushi/toml`.
    #[test]
    fn a_module_path_splits_at_its_last_element() {
        assert_eq!(
            key("github.com/BurntSushi/toml").to_string(),
            "pkg:golang/github.com/BurntSushi/toml"
        );
        assert_eq!(split_name("gopkg.in"), Ok((None, "gopkg.in".to_owned())));
        assert_eq!(canonical_name("github.com/A/b"), "github.com/A/b");
        for refused in [
            "",
            "sumdb/sum.golang.org",
            "Github.com/a",
            "-x.com/a",
            "x.com//a",
            "x.com/.a",
            "x.com/a.",
            "x.com/a b",
            "x.com/caf\u{e9}",
        ] {
            assert!(split_name(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn each_path_is_metadata_an_artifact_or_neither() {
        assert_eq!(
            classify_path("/go/golang.org/x/text/@v/list"),
            RequestTarget::Metadata(key("golang.org/x/text"))
        );
        assert_eq!(
            classify_path("/go/golang.org/@v/list"),
            RequestTarget::Metadata(key("golang.org")),
            "go asks each prefix of a path, and the proxy answers 404 for one that is no module"
        );
        assert_eq!(
            classify_path("/go/github.com/!burnt!sushi/toml/@latest?x"),
            RequestTarget::Metadata(key("github.com/BurntSushi/toml"))
        );
        assert_eq!(
            classify_path("/go/golang.org/x/text/@v/v0.20.0-!r!c1.zip"),
            RequestTarget::Artifact {
                key: key("golang.org/x/text"),
                claimed_version: "v0.20.0-RC1".into(),
                filename: "v0.20.0-RC1.zip".into(),
            }
        );
        assert_eq!(
            classify_path("/go/golang.org/x/text/@v/v0.20.0.mod"),
            RequestTarget::Manifest {
                key: key("golang.org/x/text"),
                version: "v0.20.0".into(),
                filename: "v0.20.0.mod".into(),
            }
        );
        for other in [
            "/go/golang.org/x/text/@v/v0.20.0.info",
            "/go/sumdb/sum.golang.org/supported",
            "/go/sumdb/sum.golang.org/latest",
            "/go/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.20.0",
            "/go/sumdb/sum.golang.org/tile/8/0/x123/456",
        ] {
            assert_eq!(classify_path(other), RequestTarget::Other, "{other}");
        }
        for unrecognised in [
            "/go/golang.org/x/text/@v/.mod",
            "/go/golang.org/x/text/@v/.info",
            "/go/golang.org/x/text/@v/v1",
            "/go/golang.org/x/text/@v/v0.20.0.ziphash",
            "/go/sumdb/sum.golang.org",
            "/go/sumdb/sum.golang.org/other",
            "/go/golang.org/x/text/@v/.zip",
            "/go/golang.org/x/text/@v/a/b.zip",
            "/go/golang.org/x/text/@v/V1.zip",
            "/go/Golang.org/x/text/@v/v1.0.0.zip",
            "/go/Golang.org/x/text/@latest",
            "/go/golang.org/x/text",
            "/golang.org/x/text/@v/list",
        ] {
            assert_eq!(
                classify_path(unrecognised),
                RequestTarget::Unrecognised,
                "{unrecognised}"
            );
        }
    }

    #[test]
    fn the_checksum_database_goes_to_sum_golang_org_and_the_rest_to_the_proxy() {
        let proxy = "https://proxy.golang.org";
        assert_eq!(
            upstream_url(proxy, "/go/sumdb/sum.golang.org/lookup/rsc.io/quote@v1.5.2"),
            "https://sum.golang.org/lookup/rsc.io/quote@v1.5.2"
        );
        assert_eq!(
            upstream_url(proxy, "/go/golang.org/x/text/@v/list"),
            "https://proxy.golang.org/golang.org/x/text/@v/list"
        );
        assert_eq!(
            upstream_url(proxy, "/go/sumdb/other.example/latest"),
            "https://proxy.golang.org/sumdb/other.example/latest"
        );
        assert_eq!(
            upstream_url(proxy, "/elsewhere"),
            "https://proxy.golang.org/elsewhere"
        );
    }

    #[test]
    fn a_module_s_files_are_under_its_list_or_latest() {
        for page in [
            "https://p.example/golang.org/x/text/@v/list",
            "https://p.example/golang.org/x/text/@latest?x",
        ] {
            assert_eq!(
                files_url(page).as_deref(),
                Some("https://p.example/golang.org/x/text/@v/"),
                "{page}"
            );
        }
        assert_eq!(files_url("https://p.example/x/@v/v1.0.0.info"), None);
    }

    #[test]
    fn a_list_is_plain_text_and_latest_is_json() {
        assert_eq!(
            document_from_content_type(Some("text/plain; charset=UTF-8")),
            Some(DocumentKind::VersionList)
        );
        assert_eq!(
            document_from_content_type(Some("application/json")),
            Some(DocumentKind::Latest)
        );
        assert_eq!(document_from_content_type(Some("text/html")), None);
        assert_eq!(document_from_content_type(None), None);
    }
}
