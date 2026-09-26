//! What a PyPI request path refers to, and which document a response body is.
//!
//! Also the two name questions the paths turn on: PEP 503 normalisation, which decides
//! what the proxy asks the index for, and PEP 427 filename parsing, which is the only
//! place a file's version is written.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::route::{DocumentKind, IndexFormat, RequestTarget};

use super::error::PypiError;
use super::wire::Kind;
use super::{FILES, SIMPLE_HTML, SIMPLE_JSON};

/// Split a project name for its purl: no namespace, and the name [`normalise`]d, so one
/// project is one key however it is spelled. A PyPI project has no namespace, so a name with
/// a `/` is not one, and neither is one with nothing but separators.
pub fn split_name(name: &str) -> Result<(Option<String>, String), IdentityError> {
    let normalised = normalise(name);
    if name.contains('/') || normalised.is_empty() {
        return Err(IdentityError::Malformed(format!(
            "`{name}` is not a valid PyPI project name"
        )));
    }
    Ok((None, normalised))
}

/// A name in a policy selector, [`normalise`]d. A trailing separator is kept as `-`, so the
/// prefix `zope.` in `zope.*` covers `zope-interface` and not `zopefoo`.
pub fn canonical_name(name: &str) -> String {
    let mut normalised = normalise(name);
    if name.ends_with(['-', '_', '.']) {
        normalised.push('-');
    }
    normalised
}

/// A project name as PEP 503 normalises it: lowercased, with every run of `-`, `_` and `.`
/// replaced by a single `-`.
///
/// The index redirects to this form rather than serving the name as written: `Flask` 301s to
/// `flask`, `zope.interface` and `ruamel_yaml` to `zope-interface` and `ruamel-yaml`, all
/// measured 2026-09-16. Normalising here means the proxy asks for the name the index would
/// redirect to, so one project is one identity rather than one per spelling.
pub fn normalise(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            in_run = true;
            continue;
        }
        if in_run && !out.is_empty() {
            out.push('-');
        }
        in_run = false;
        out.extend(c.to_lowercase());
    }
    out
}

/// The index URL for `name`, normalised. PEP 503 requires the trailing slash.
pub fn index_url(base: &str, name: &str) -> Result<String, PypiError> {
    let normalised = normalise(name);
    if normalised.is_empty() {
        return Err(PypiError::UnusableName(name.to_owned()));
    }
    Ok(format!("{}/{normalised}/", base.trim_end_matches('/')))
}

/// What a distribution filename says: the project it belongs to, its version, and what
/// kind of file it is.
///
/// A wheel is PEP 427 `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`, so the
/// name and version are the first two of at least five fields. An sdist is
/// `{name}-{version}` with an archive extension, where the name may itself contain `-`, so
/// the version is what follows the last `-`. `None` for anything else, including the eggs
/// and `.exe` installers old projects still list.
///
/// The name comes back as [`normalise`] gives it. A wheel writes `-` in the project name
/// as `_`, so `zope-interface` reaches the filename as `zope_interface`, and the two spell
/// one project.
pub(super) fn filename_parts(filename: &str) -> Option<(String, String, Kind)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let fields: Vec<&str> = stem.split('-').collect();
        // name, version, then python, abi and platform, with an optional build tag between.
        if fields.len() < 5 {
            return None;
        }
        if fields[0].is_empty() {
            return None;
        }
        return Some((normalise(fields[0]), fields[1].to_owned(), Kind::Wheel));
    }
    for extension in [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"] {
        if let Some(stem) = filename.strip_suffix(extension) {
            let (name, version) = stem.rsplit_once('-')?;
            if version.is_empty() || name.is_empty() {
                return None;
            }
            return Some((normalise(name), version.to_owned(), Kind::Sdist));
        }
    }
    None
}

/// Where a request under PyPI's prefixes goes upstream.
///
/// The index answers `/simple/<name>/` and the files come from [`FILES`], which the index
/// gives in full and which the proxy reaches by keeping the path: the hash segments in
/// `/packages/ab/cd/ef.../name-1.0.whl` are what locate the file, and they arrive in the
/// request because the client followed the URL the index published.
///
/// `index` already ends in the index path, `https://pypi.org/simple`, so the proxy's own
/// `/simple` prefix comes off before the rest is appended. A path under a PyPI prefix that
/// names no project still goes to PyPI: `/simple/` is the root index, and answering pip
/// with an npm registry's 404 says nothing useful.
///
/// `/integrity/`, PEP 740's attestations, is served by the index's host beside `/simple`:
/// `https://pypi.org/integrity/attrs/26.1.0/attrs-26.1.0.tar.gz/provenance`.
pub fn upstream_url(index: &str, path_and_query: &str) -> String {
    if path_and_query.starts_with("/integrity/") {
        let host = index.strip_suffix("/simple").unwrap_or(index);
        return format!("{host}{path_and_query}");
    }
    match path_and_query.strip_prefix("/simple") {
        Some(rest) => format!("{index}{rest}"),
        None => format!("{FILES}{path_and_query}"),
    }
}

/// Which metadata document a body with this `Content-Type` is.
///
/// PyPI's row of [`crate::ecosystem::TABLE`] reads media types through this. Both simple
/// index forms are read: PEP 691 JSON, and the PEP 503 page an index that has not
/// implemented PEP 691 serves.
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    match crate::route::media_type(content_type)?.as_str() {
        SIMPLE_JSON | "application/json" => Some(DocumentKind::SimpleIndex(IndexFormat::Json)),
        SIMPLE_HTML | "text/html" => Some(DocumentKind::SimpleIndex(IndexFormat::Html)),
        _ => None,
    }
}

pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');

    if let Some(rest) = path.strip_prefix("simple/") {
        let name = rest.trim_end_matches('/');
        // `/simple/` itself is the root index: every project PyPI serves, not one of them.
        if name.is_empty() {
            return RequestTarget::Other;
        }
        // A file served from under the index rather than from a file host.
        // `www.piwheels.org` writes `/simple/idna/idna-3.20-py3-none-any.whl`, and the
        // request that follows the rewrite carries that path.
        if name.contains('/') {
            return artifact(name.rsplit('/').next().unwrap_or_default());
        }
        let normalised = normalise(name);
        if normalised.is_empty() {
            return RequestTarget::Other;
        }
        return match PackageKey::from_registry_name(Ecosystem::PyPI, &normalised) {
            Ok(key) => RequestTarget::Metadata(key),
            Err(_) => RequestTarget::Other,
        };
    }

    let Some(rest) = path.strip_prefix("packages/") else {
        return RequestTarget::Other;
    };
    artifact(rest.rsplit('/').next().unwrap_or_default())
}

/// The request for one file, named by a filename this build can read a version out of.
fn artifact(filename: &str) -> RequestTarget {
    let Some((name, version, _)) = filename_parts(filename) else {
        return RequestTarget::Other;
    };
    match PackageKey::from_registry_name(Ecosystem::PyPI, &name) {
        Ok(key) => RequestTarget::Artifact {
            key,
            claimed_version: version,
            filename: filename.to_owned(),
        },
        Err(_) => RequestTarget::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::wire::parse;
    use super::super::{INDEX, fixture};

    /// Measured against the live index 2026-09-16: each 301s to the right-hand form.
    #[test]
    fn a_name_normalises_the_way_the_index_redirects_it() {
        for (given, normalised) in [
            ("Flask", "flask"),
            ("zope.interface", "zope-interface"),
            ("ruamel_yaml", "ruamel-yaml"),
            ("ruamel.yaml", "ruamel-yaml"),
            // A run of separators collapses to one.
            ("a---b", "a-b"),
            ("A_-.B", "a-b"),
            ("already-normal", "already-normal"),
        ] {
            assert_eq!(normalise(given), normalised, "{given}");
        }
        // Normalising is idempotent, so asking twice cannot drift.
        for name in ["Flask", "zope.interface", "a---b"] {
            assert_eq!(normalise(&normalise(name)), normalise(name), "{name}");
        }
    }

    #[test]
    fn an_index_url_normalises_its_name_and_keeps_pep_503s_trailing_slash() {
        assert_eq!(
            index_url(INDEX, "Zope.Interface").expect("usable"),
            "https://pypi.org/simple/zope-interface/"
        );
        // A trailing slash on the base does not double up.
        assert_eq!(
            index_url("https://pypi.org/simple/", "flask").expect("usable"),
            "https://pypi.org/simple/flask/"
        );
        // A name of nothing but separators normalises away, so no path can be built.
        let error = index_url(INDEX, "...").expect_err("not a usable name");
        assert!(matches!(error, PypiError::UnusableName(_)), "{error}");
    }

    #[test]
    fn a_wheel_and_an_sdist_give_their_version_and_what_installing_them_runs() {
        let project = parse("requests", &fixture()).expect("the fixture reads");
        assert_eq!(project.name, "requests");
        assert_eq!(project.versions(), ["0.2.0", "2.32.0", "2.34.2"]);

        let sdist = &project.files_for("0.2.0")[0];
        assert_eq!(sdist.kind, Kind::Sdist);
        assert_eq!(
            sdist.sha256.as_deref(),
            Some("813202ace4d9301a3c00740c700e012fb9f3f8c73ddcfe02ab558a8df6f175fd")
        );
        assert_eq!(sdist.requires_python, None);

        let wheel = &project.files_for("2.34.2")[0];
        assert_eq!(wheel.kind, Kind::Wheel);
        assert_eq!(wheel.requires_python.as_deref(), Some(">=3.10"));
        // The artifact is on another host than the index, which a certificate covering only
        // the index host would miss. See enforcement-tiers.md.
        assert!(
            wheel.url.starts_with("https://files.pythonhosted.org/"),
            "{}",
            wheel.url
        );
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::PyPI, name).expect("valid name")
    }

    #[test]
    fn a_simple_index_path_is_the_projects_metadata() {
        assert_eq!(
            classify_path("/simple/requests/"),
            RequestTarget::Metadata(key("requests"))
        );
        assert_eq!(
            classify_path("/simple/requests"),
            RequestTarget::Metadata(key("requests")),
            "pip sends the trailing slash; a client that omits it names the same page"
        );
    }

    /// PEP 503 asks for the normalised name, and pip sends whichever spelling the
    /// requirement used. `Zope.Interface`, `zope_interface` and `zope-interface` are
    /// one project, so they are one key.
    #[test]
    fn the_index_name_is_normalised_into_the_key() {
        for spelling in ["Zope.Interface", "zope_interface", "ZOPE--INTERFACE"] {
            assert_eq!(
                classify_path(&format!("/simple/{spelling}/")),
                RequestTarget::Metadata(key("zope-interface")),
                "{spelling}"
            );
        }
    }

    #[test]
    fn a_packages_path_is_the_file_it_names() {
        assert_eq!(
            classify_path(
                "/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfe6f7/\
                 requests-2.32.3-py3-none-any.whl"
            ),
            RequestTarget::Artifact {
                key: key("requests"),
                claimed_version: "2.32.3".into(),
                filename: "requests-2.32.3-py3-none-any.whl".into(),
            }
        );
        assert_eq!(
            classify_path("/packages/source/z/zope-interface/zope.interface-5.4.0.tar.gz"),
            RequestTarget::Artifact {
                key: key("zope-interface"),
                claimed_version: "5.4.0".into(),
                filename: "zope.interface-5.4.0.tar.gz".into(),
            }
        );
    }

    /// One version lists several files, each with its own digest, so the filename is
    /// what separates them. npm has no path that does this.
    #[test]
    fn two_files_of_one_version_differ_only_in_the_filename() {
        let wheel = classify_path("/packages/a/b/c/requests-2.32.3-py3-none-any.whl");
        let sdist = classify_path("/packages/a/b/c/requests-2.32.3.tar.gz");
        assert_ne!(wheel, sdist);
        let (
            RequestTarget::Artifact {
                key: w,
                claimed_version: wv,
                ..
            },
            RequestTarget::Artifact {
                key: s,
                claimed_version: sv,
                ..
            },
        ) = (&wheel, &sdist)
        else {
            panic!("both are artifacts");
        };
        assert_eq!(w, s);
        assert_eq!(wv, sv);
    }

    #[test]
    fn a_query_string_is_not_part_of_the_path() {
        assert_eq!(
            classify_path("/simple/requests/?foo=1"),
            RequestTarget::Metadata(key("requests"))
        );
    }

    #[test]
    fn anything_that_names_no_project_is_other() {
        for path in [
            "",
            "/",
            "/simple/",
            "/simple",
            "/simple/a/b/",
            "/simple/./",
            "/packages/",
            "/packages/a/b/c/",
            "/packages/a/b/c/notadistribution.txt",
            "/packages/a/b/c/x-py3-none-any.whl",
            "/packages/a/b/c/-1.0.tar.gz",
            "/pypi/requests/json",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
        }
    }
}
