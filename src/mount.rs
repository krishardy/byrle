//! The path the proxy answers at and the path the console answers at, each read from its
//! URL. They may share a host and port, and are never at the same path.

use std::fmt;

/// A path a part of byrle answers under: `/registry` for `https://h/registry/`; empty for `/`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mount {
    path: String,
}

impl Mount {
    /// The whole of a listener's paths.
    pub const ROOT: Mount = Mount {
        path: String::new(),
    };

    /// The path of `url`, which has to be an `http` or `https` URL with no credentials,
    /// query or fragment. The parser refuses either scheme without a host.
    pub fn from_url(url: &str) -> Result<Mount, String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("is not a URL: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("is not an http or https URL".to_owned());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("carries credentials".to_owned());
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(
                "carries a query or fragment; give the scheme, host, port and path".to_owned(),
            );
        }
        Ok(Mount {
            path: parsed.path().trim_end_matches('/').to_owned(),
        })
    }

    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    /// `path_and_query` as seen from this mount: `/registry/lodash?x` is `/lodash?x` under
    /// `/registry`. `None` for a path outside it, including `/registryx`.
    pub fn strip(&self, path_and_query: &str) -> Option<String> {
        let rest = path_and_query.strip_prefix(self.path.as_str())?;
        match rest.chars().next() {
            Some('/') => Some(rest.to_owned()),
            None | Some('?') => Some(format!("/{rest}")),
            Some(_) => None,
        }
    }

    /// Whether every path under `other` is also under this mount, segment by segment.
    pub fn contains(&self, other: &Mount) -> bool {
        self.strip(&other.path).is_some()
    }
}

impl fmt::Display for Mount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/", self.path)
    }
}

/// Why the proxy's and the console's paths cannot be used together. `None` when they can.
///
/// They are never the same path. On one listener, neither may contain the other either:
/// with the proxy at `/` and the console at `/admin/`, npm's package `admin` would be
/// answered by the console.
pub fn conflict(proxy: &Mount, console: &Mount, shared_listener: bool) -> Option<String> {
    if proxy == console {
        return Some(format!("is the proxy's path too, {proxy}"));
    }
    if !shared_listener {
        return None;
    }
    if proxy.contains(console) {
        return Some(format!(
            "is inside the proxy's path {proxy}, on the same listener, so packages under it \
             would reach the console. Give the proxy a path of its own, or the console a \
             listener of its own"
        ));
    }
    if console.contains(proxy) {
        return Some(format!(
            "contains the proxy's path {proxy}, on the same listener. Give each a path the \
             other does not contain, or the console a listener of its own"
        ));
    }
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn mount(url: &str) -> Mount {
        Mount::from_url(url).expect("a usable URL")
    }

    #[test]
    fn the_path_is_read_from_the_url_without_its_trailing_slash() {
        assert_eq!(mount("https://proxy.example"), Mount::ROOT);
        assert_eq!(mount("https://proxy.example/"), Mount::ROOT);
        assert!(mount("http://proxy.example:8080/").is_root());
        let registry = mount("https://proxy.example/registry/");
        assert_eq!(registry, mount("https://proxy.example/registry"));
        assert!(!registry.is_root());
        assert_eq!(registry.to_string(), "/registry/");
        assert_eq!(Mount::ROOT.to_string(), "/");
    }

    #[test]
    fn a_url_that_cannot_name_a_mount_is_refused_with_the_reason() {
        for (url, reason) in [
            ("proxy.example/registry", "is not a URL"),
            ("http://", "is not a URL"),
            ("ftp://proxy.example/", "is not an http or https URL"),
            ("https://user:secret@proxy.example/", "carries credentials"),
            ("https://user@proxy.example/", "carries credentials"),
            ("https://proxy.example/?x=1", "carries a query or fragment"),
            ("https://proxy.example/#top", "carries a query or fragment"),
        ] {
            let refused = Mount::from_url(url).expect_err(url);
            assert!(refused.starts_with(reason), "{url}: {refused}");
        }
    }

    #[test]
    fn a_path_is_stripped_only_at_a_segment_boundary() {
        let registry = mount("https://proxy.example/registry/");
        assert_eq!(
            registry.strip("/registry/lodash").as_deref(),
            Some("/lodash")
        );
        assert_eq!(
            registry
                .strip("/registry/lodash/-/lodash-4.17.21.tgz?x=1")
                .as_deref(),
            Some("/lodash/-/lodash-4.17.21.tgz?x=1")
        );
        assert_eq!(registry.strip("/registry").as_deref(), Some("/"));
        assert_eq!(registry.strip("/registry?x").as_deref(), Some("/?x"));
        assert_eq!(registry.strip("/registryx/lodash"), None);
        assert_eq!(registry.strip("/lodash"), None);
        assert_eq!(Mount::ROOT.strip("/lodash").as_deref(), Some("/lodash"));
        assert_eq!(Mount::ROOT.strip("?x").as_deref(), Some("/?x"));
    }

    #[test]
    fn the_root_contains_every_path_and_a_path_contains_only_those_under_it() {
        let registry = mount("https://h/registry/");
        let deeper = mount("https://h/registry/admin/");
        let sibling = mount("https://h/registry-admin/");
        assert!(Mount::ROOT.contains(&registry));
        assert!(registry.contains(&deeper));
        assert!(registry.contains(&registry));
        assert!(!deeper.contains(&registry));
        assert!(!registry.contains(&sibling));
        assert!(!registry.contains(&Mount::ROOT));
    }

    /// Apart, nesting is harmless. Together, the npm package `admin`'s
    /// `/admin/-/admin-1.0.0.tgz` would be under a console at `/admin/`.
    #[test]
    fn the_two_paths_never_match_and_on_one_listener_never_nest() {
        let root = Mount::ROOT;
        let registry = mount("https://h/registry/");
        let admin = mount("https://h/admin/");
        let registry_admin = mount("https://h/registry/admin/");

        let same = conflict(&registry, &registry, false).expect("refused");
        assert!(same.contains("/registry/"), "{same}");
        assert!(conflict(&admin, &admin, true).is_some());

        assert_eq!(conflict(&root, &admin, false), None);
        assert_eq!(conflict(&registry, &registry_admin, false), None);

        let inside = conflict(&root, &admin, true).expect("refused");
        assert!(inside.contains("packages under it"), "{inside}");
        assert!(conflict(&registry, &registry_admin, true).is_some());
        let around = conflict(&registry_admin, &registry, true).expect("refused");
        assert!(
            around.contains("contains the proxy's path /registry/admin/"),
            "{around}"
        );

        assert_eq!(conflict(&registry, &admin, true), None);
        assert_eq!(
            conflict(&registry, &mount("https://h/registry-admin/"), true),
            None
        );
    }
}
