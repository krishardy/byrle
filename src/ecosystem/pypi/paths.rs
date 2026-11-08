//! What a PyPI request path refers to, which document a response body is, and the PEP 503
//! and PEP 427 name rules the paths turn on.

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

/// Whether PyPI could publish the [`normalise`]d `name`. PEP 508 allows ASCII letters,
/// digits and `-_.`, which normalising leaves as ASCII letters, digits and `-`.
pub fn published_name(name: &str) -> bool {
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
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
/// Returns the name the index would redirect to.
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

/// What a distribution filename says, a wheel's by PEP 427 and an sdist's by its last `-`.
/// Eggs and installers give `None`. An sdist's split is a guess when its name or version
/// holds a `-`: [`version_in`] reads it for a known project.
/// Returns the [`normalise`]d project name, the version and the kind of file.
pub(super) fn filename_parts(filename: &str) -> Option<(String, String, Kind)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let fields: Vec<&str> = stem.split('-').collect();
        if fields.len() < 5 {
            return None;
        }
        if fields[0].is_empty() {
            return None;
        }
        return Some((normalise(fields[0]), fields[1].to_owned(), Kind::Wheel));
    }
    let (name, version) = sdist_stem(filename)?.rsplit_once('-')?;
    if version.is_empty() || name.is_empty() {
        return None;
    }
    Some((normalise(name), version.to_owned(), Kind::Sdist))
}

/// The version and kind of a file in `project`'s index. A wheel's is [`filename_parts`]'s.
/// An sdist's follows the first `-` before which the name [`normalise`]s to `project`, as
/// pip's `_find_name_version_sep` finds it: `foo-1.0-1.tar.gz` is `foo` at `1.0-1`.
/// Returns `None` for an sdist of another project, which pip skips.
pub(super) fn version_in(project: &str, filename: &str) -> Option<(String, Kind)> {
    if filename.ends_with(".whl") {
        return filename_parts(filename).map(|(_, version, kind)| (version, kind));
    }
    let stem = sdist_stem(filename)?;
    let project = normalise(project);
    let (at, _) = stem
        .match_indices('-')
        .find(|&(at, _)| at > 0 && normalise(&stem[..at]) == project)?;
    let version = &stem[at + 1..];
    (!version.is_empty()).then(|| (version.to_owned(), Kind::Sdist))
}

/// An sdist's filename without its archive extension.
fn sdist_stem(filename: &str) -> Option<&str> {
    [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"]
        .into_iter()
        .find_map(|extension| filename.strip_suffix(extension))
}

/// Where a request under PyPI's prefixes goes upstream: `/simple/` to the index, `/packages/`
/// to [`FILES`] with its path kept, and `/integrity/` to the index's host.
/// `index` ends in the index path, such as `https://pypi.org/simple`, whose prefix the path
/// loses.
pub fn upstream_url(index: &str, path_and_query: &str) -> String {
    let path_and_query =
        crate::ecosystem::within(super::PREFIX, path_and_query).unwrap_or(path_and_query);
    if path_and_query.starts_with("/integrity/") {
        let host = index.strip_suffix("/simple").unwrap_or(index);
        return format!("{host}{path_and_query}");
    }
    match path_and_query.strip_prefix("/simple") {
        Some(rest) => format!("{index}{rest}"),
        None => format!("{FILES}{path_and_query}"),
    }
}

/// Which simple-index form, PEP 691 JSON or a PEP 503 page, a body is.
/// Returns `None` for any other media type.
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    match crate::route::media_type(content_type)?.as_str() {
        SIMPLE_JSON | "application/json" => Some(DocumentKind::SimpleIndex(IndexFormat::Json)),
        SIMPLE_HTML | "text/html" => Some(DocumentKind::SimpleIndex(IndexFormat::Html)),
        _ => None,
    }
}

/// What a request path refers to. The project list and a PEP 658 `.metadata` file are
/// [`RequestTarget::Other`]; any other path naming no project or file is unrecognised.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let Some(path) = crate::ecosystem::within(super::PREFIX, path) else {
        return RequestTarget::Unrecognised;
    };
    let path = path.trim_start_matches('/');

    if let Some(rest) = path.strip_prefix("simple/") {
        let name = rest.trim_end_matches('/');
        if name.is_empty() {
            return RequestTarget::Other;
        }
        if name.contains('/') {
            return artifact(name.rsplit('/').next().unwrap_or_default());
        }
        return PackageKey::from_registry_name(Ecosystem::PyPI, name)
            .map_or(RequestTarget::Unrecognised, RequestTarget::Metadata);
    }
    if path == "simple" {
        return RequestTarget::Other;
    }

    let Some(rest) = path.strip_prefix("packages/") else {
        return RequestTarget::Unrecognised;
    };
    artifact(rest.rsplit('/').next().unwrap_or_default())
}

/// The request for one file, named by a filename this build can read a version out of. A
/// PEP 658 `<file>.metadata` is forwarded; any other filename is unrecognised.
fn artifact(filename: &str) -> RequestTarget {
    if filename
        .strip_suffix(".metadata")
        .is_some_and(|file| filename_parts(file).is_some())
    {
        return RequestTarget::Other;
    }
    filename_parts(filename)
        .and_then(|(name, version, _)| {
            PackageKey::from_registry_name(Ecosystem::PyPI, &name)
                .ok()
                .map(|key| RequestTarget::Artifact {
                    key,
                    claimed_version: version,
                    filename: filename.to_owned(),
                })
        })
        .unwrap_or(RequestTarget::Unrecognised)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            ("a---b", "a-b"),
            ("A_-.B", "a-b"),
            ("already-normal", "already-normal"),
        ] {
            assert_eq!(normalise(given), normalised, "{given}");
        }
        for name in ["Flask", "zope.interface", "a---b"] {
            assert_eq!(
                normalise(&normalise(name)),
                normalise(name),
                "normalising {name} twice gives the same name"
            );
        }
    }

    /// PEP 508 names, read after normalising: `?`, `#`, `%` and non-ASCII letters are not.
    #[test]
    fn a_published_name_is_ascii_letters_digits_and_hyphens() {
        for (name, published) in [
            ("zope-interface", true),
            ("pip2", true),
            ("lo?dash", false),
            ("lo#dash", false),
            ("lo%2edash", false),
            ("caf\u{e9}", false),
        ] {
            assert_eq!(published_name(name), published, "{name}");
        }
    }

    #[test]
    fn an_index_url_normalises_its_name_and_keeps_pep_503s_trailing_slash() {
        assert_eq!(
            index_url(INDEX, "Zope.Interface").expect("usable"),
            "https://pypi.org/simple/zope-interface/"
        );
        assert_eq!(
            index_url("https://pypi.org/simple/", "flask").expect("usable"),
            "https://pypi.org/simple/flask/"
        );
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
            classify_path("/pypi/simple/requests/"),
            RequestTarget::Metadata(key("requests"))
        );
        assert_eq!(
            classify_path("/pypi/simple/requests"),
            RequestTarget::Metadata(key("requests")),
            "pip sends the trailing slash; a client that omits it names the same page"
        );
    }

    /// `Zope.Interface`, `zope_interface` and `zope-interface`, as pip may send them, are
    /// one key.
    #[test]
    fn the_index_name_is_normalised_into_the_key() {
        for spelling in ["Zope.Interface", "zope_interface", "ZOPE--INTERFACE"] {
            assert_eq!(
                classify_path(&format!("/pypi/simple/{spelling}/")),
                RequestTarget::Metadata(key("zope-interface")),
                "{spelling}"
            );
        }
    }

    #[test]
    fn a_packages_path_is_the_file_it_names() {
        assert_eq!(
            classify_path(
                "/pypi/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfe6f7/\
                 requests-2.32.3-py3-none-any.whl"
            ),
            RequestTarget::Artifact {
                key: key("requests"),
                claimed_version: "2.32.3".into(),
                filename: "requests-2.32.3-py3-none-any.whl".into(),
            }
        );
        assert_eq!(
            classify_path("/pypi/packages/source/z/zope-interface/zope.interface-5.4.0.tar.gz"),
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
        let wheel = classify_path("/pypi/packages/a/b/c/requests-2.32.3-py3-none-any.whl");
        let sdist = classify_path("/pypi/packages/a/b/c/requests-2.32.3.tar.gz");
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
            classify_path("/pypi/simple/requests/?foo=1"),
            RequestTarget::Metadata(key("requests"))
        );
    }

    /// The project list and a PEP 658 `.metadata` file are forwarded. Any other path naming no
    /// project or file `filename_parts` reads, such as a `.tgz` sdist pip installs, is not.
    #[test]
    fn anything_that_names_no_project_is_other_or_unrecognised() {
        for path in [
            "/pypi/simple/",
            "/pypi/simple",
            "/pypi/simple/requests/requests-2.32.3-py3-none-any.whl.metadata",
            "/pypi/packages/a/b/c/requests-2.32.3.tar.gz.metadata",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Other, "{path}");
        }
        for path in [
            "",
            "/",
            "/pypi/simple/a/b/",
            "/pypi/simple/./",
            "/pypi/packages/",
            "/pypi/packages/a/b/c/",
            "/pypi/packages/a/b/c/notadistribution.txt",
            "/pypi/packages/a/b/c/notadistribution.txt.metadata",
            "/pypi/packages/a/b/c/x-py3-none-any.whl",
            "/pypi/packages/a/b/c/-1.0.tar.gz",
            "/pypi/packages/a/b/c/requests-2.32.3.tgz",
            "/pypi/packages/a/b/c/requests-2.32.3.tar",
            "/pypi/requests/json",
        ] {
            assert_eq!(classify_path(path), RequestTarget::Unrecognised, "{path}");
        }
    }

    /// In a known project's index an sdist's version follows the first `-` after the project
    /// name, as pip reads it. The same filename gives another version in another project.
    #[test]
    fn an_sdist_in_a_known_project_is_split_after_its_name() {
        for (project, filename, version) in [
            ("foo", "foo-1.0-1.tar.gz", Some("1.0-1")),
            ("foo-1-0", "foo-1.0-1.tar.gz", Some("1")),
            ("Zope.Interface", "zope.interface-5.4.0.zip", Some("5.4.0")),
            ("foo-bar", "foo_bar-2.0.tar.bz2", Some("2.0")),
            ("foo", "foo--1.0.tar.gz", Some("-1.0")),
            ("foo", "foo--1.0.tar.gz", Some("-1.0")),
            ("foo", "bar-1.0.tar.gz", None),
            ("foo", "foobar-1.0.tar.xz", None),
            ("foo", "foo.tar.gz", None),
            ("foo", "foo-.tar.gz", None),
            ("", "-1.0.tar.gz", None),
            ("foo", "foo-1.0.txt", None),
        ] {
            assert_eq!(
                version_in(project, filename),
                version.map(|v| (v.to_owned(), Kind::Sdist)),
                "{project} {filename}"
            );
        }
        assert_eq!(
            version_in("foo", "foo-1.0.post1-1-py3-none-any.whl"),
            Some(("1.0.post1".to_owned(), Kind::Wheel)),
            "a wheel's version is its second field"
        );
        assert_eq!(version_in("foo", "foo-py3-none-any.whl"), None);
    }

    /// An sdist name with no `-` names no version.
    #[test]
    fn an_sdist_with_no_version_is_not_read() {
        assert_eq!(filename_parts("requests.tar.gz"), None);
        assert_eq!(
            classify_path("/pypi/packages/ab/requests.tar.gz"),
            RequestTarget::Unrecognised
        );
    }
}
