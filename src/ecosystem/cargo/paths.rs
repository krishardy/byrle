//! What a cargo request path refers to, and where it goes upstream. cargo asks for the
//! registry under [`PREFIX`]: `config.json`, an index file such as `se/rd/serde`, and a
//! download at `crates/{name}/{version}/download`, the `dl` the proxy writes.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::route::{DocumentKind, RequestTarget};

use super::{FILES, PREFIX};

/// Where downloads are asked for under [`PREFIX`] and under [`FILES`].
pub const CRATES: &str = "crates";

/// Split a crate name for its purl: no namespace, lowercased, since crates.io refuses a
/// name differing from another only in case. A name of other than ASCII letters, digits,
/// `-` and `_` is not one.
pub fn split_name(name: &str) -> Result<(Option<String>, String), IdentityError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(IdentityError::Malformed(format!(
            "`{name}` is not a valid crate name"
        )));
    }
    Ok((None, name.to_ascii_lowercase()))
}

/// A name in a policy selector, lowercased as [`split_name`] lowercases it.
pub fn canonical_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// The index file of a crate already lowercased: `1/a`, `2/ab`, `3/a/abc`, `se/rd/serde`.
pub fn index_path(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// The file name the proxy gives a download, from the key's name and the version.
pub fn filename(key: &PackageKey, version: &str) -> String {
    format!("{}-{version}.crate", key.name())
}

/// An index file is a crate's metadata, a download its artifact, and anything else under
/// [`PREFIX`], such as `config.json`, neither.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let Some(rest) = path.strip_prefix(PREFIX) else {
        return RequestTarget::Other;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    if let [CRATES, name, version, "download"] = segments[..] {
        return match PackageKey::from_registry_name(Ecosystem::Cargo, name) {
            Ok(key) if !version.is_empty() => RequestTarget::Artifact {
                filename: filename(&key, version),
                claimed_version: version.to_owned(),
                key,
            },
            _ => RequestTarget::Other,
        };
    }
    let name = segments.last().copied().unwrap_or_default();
    match PackageKey::from_registry_name(Ecosystem::Cargo, name) {
        Ok(key) if index_path(key.name()) == rest => RequestTarget::Metadata(key),
        _ => RequestTarget::Other,
    }
}

/// A download goes to [`FILES`] with the name spelled as the path spells it, since
/// static.crates.io answers `Inflector` and refuses `inflector`. The rest goes to `index`.
pub fn upstream_url(index: &str, path_and_query: &str) -> String {
    let downloads = format!("{PREFIX}{CRATES}/");
    if let Some(rest) = path_and_query.strip_prefix(&downloads) {
        return format!("{FILES}/{CRATES}/{rest}");
    }
    let rest = path_and_query
        .strip_prefix(PREFIX.trim_end_matches('/'))
        .unwrap_or(path_and_query);
    format!("{index}{rest}")
}

/// An index file is `text/plain`, one JSON line per version.
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    (crate::route::media_type(content_type)? == "text/plain").then_some(DocumentKind::IndexLines)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Cargo, name).expect("a crate name")
    }

    /// cargo's index layout, by name length.
    #[test]
    fn each_name_length_has_its_index_path() {
        for (name, path) in [
            ("a", "1/a"),
            ("ab", "2/ab"),
            ("abc", "3/a/abc"),
            ("itoa", "it/oa/itoa"),
            ("serde", "se/rd/serde"),
        ] {
            assert_eq!(index_path(name), path);
        }
    }

    #[test]
    fn a_crate_name_is_lowercased_and_checked() {
        assert_eq!(split_name("Inflector"), Ok((None, "inflector".to_owned())));
        assert_eq!(
            split_name("proc-macro2_x"),
            Ok((None, "proc-macro2_x".into()))
        );
        for bad in ["", "a/b", "caf\u{e9}", "a b", "a.b"] {
            assert!(split_name(bad).is_err(), "{bad}");
        }
        assert_eq!(canonical_name("Serde_"), "serde_");
    }

    #[test]
    fn each_path_is_metadata_an_artifact_or_neither() {
        assert_eq!(
            classify_path("/cargo/se/rd/serde"),
            RequestTarget::Metadata(key("serde"))
        );
        assert_eq!(
            classify_path("/cargo/3/a/abc?x=1"),
            RequestTarget::Metadata(key("abc"))
        );
        assert_eq!(
            classify_path("/cargo/crates/Inflector/0.11.4/download"),
            RequestTarget::Artifact {
                key: key("inflector"),
                claimed_version: "0.11.4".into(),
                filename: "inflector-0.11.4.crate".into(),
            }
        );
        for other in [
            "/cargo/config.json",
            "/cargo/se/rd/itoa",
            "/cargo/crates/serde/1.0.0/other",
            "/cargo/crates/serde//download",
            "/cargo/crates/a.b/1.0.0/download",
            "/cargo/",
            "/serde",
        ] {
            assert_eq!(classify_path(other), RequestTarget::Other, "{other}");
        }
    }

    #[test]
    fn a_download_goes_to_static_crates_io_and_the_rest_to_the_index() {
        let index = "https://index.crates.io";
        assert_eq!(
            upstream_url(index, "/cargo/crates/Inflector/0.11.4/download"),
            "https://static.crates.io/crates/Inflector/0.11.4/download"
        );
        assert_eq!(
            upstream_url(index, "/cargo/se/rd/serde"),
            "https://index.crates.io/se/rd/serde"
        );
        assert_eq!(
            upstream_url(index, "/elsewhere"),
            "https://index.crates.io/elsewhere"
        );
    }

    #[test]
    fn only_plain_text_is_an_index_file() {
        assert_eq!(
            document_from_content_type(Some("text/plain; charset=utf-8")),
            Some(DocumentKind::IndexLines)
        );
        assert_eq!(document_from_content_type(Some("application/json")), None);
        assert_eq!(document_from_content_type(None), None);
    }
}
