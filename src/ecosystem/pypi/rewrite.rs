//! Removing refused versions from a simple index, and pointing the rest at the proxy. A
//! version is removed with every file that carries it: see
//! docs/engineering_decisions/pypi-index-filtering.md.

use std::collections::HashSet;

use serde_json::Value;
use tracing::{info, warn};

use crate::origin::{ReachableOrigins, rewrite_artifact_origins};
use crate::route::IndexFormat;

use super::wire::Project;

/// What [`rewrite_index`] reads.
pub struct Rewrite<'a> {
    /// The index as it arrived, decoded.
    pub decoded: &'a [u8],
    /// Which form it is, because a file is removed from each differently.
    pub format: IndexFormat,
    /// The same index, parsed.
    pub project: &'a Project,
    pub reachable: &'a ReachableOrigins,
    /// The proxy's own address, or `None` when files are left on their own host.
    pub base: Option<&'a str>,
    /// Versions the policy refuses, which are removed.
    pub refused_by_policy: &'a HashSet<String>,
    pub path: &'a str,
}

/// Remove refused versions and point the remaining files at the proxy, keeping each path.
/// `r`: the index, its project, and what is refused.
/// Returns `None` to forward the body as it came, which is logged: see pypi-simple-index.md.
pub fn rewrite_index(r: Rewrite<'_>) -> Option<Vec<u8>> {
    let kept: Vec<&str> = r
        .project
        .files
        .iter()
        .filter(|file| !r.refused_by_policy.contains(&file.version))
        .map(|file| file.url.as_str())
        .collect();
    let filtered = if r.refused_by_policy.is_empty() {
        None
    } else {
        Some(filtered(&r, kept.len())?)
    };
    let Some(base) = r.base else {
        warn!(
            url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path),
            waharoa.package.files = kept.len(),
            "UNINSPECTED: the simple index is forwarded as written, so its files are \
             fetched from the index's own host rather than through the proxy"
        );
        return filtered;
    };
    repointed(&r, filtered, kept, base)
}

/// The index with the files of the versions the policy refuses removed, `kept` files left.
/// Returns `None` when it cannot be filtered.
fn filtered(r: &Rewrite<'_>, kept: usize) -> Option<Vec<u8>> {
    match remove_versions(r.decoded, r.format, r.project, r.refused_by_policy) {
        Ok(body) => {
            warn!(
                url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path),
                waharoa.package.removed_files = r.project.files.len() - kept,
                waharoa.package.kept_files = kept,
                waharoa.package.removed_by_policy = r.refused_by_policy.len(),
                "REFUSED versions removed from the document so the resolver picks \
                 another"
            );
            Some(body)
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path), error.message = %e, "UNINSPECTED: simple index could not be filtered");
            None
        }
    }
}

/// `filtered`, or the index as it came, with the `kept` files pointed at `base`.
/// Returns `filtered` when no file was repointed or the rewrite failed.
fn repointed(
    r: &Rewrite<'_>,
    filtered: Option<Vec<u8>>,
    kept: Vec<&str>,
    base: &str,
) -> Option<Vec<u8>> {
    let body = filtered.as_deref().unwrap_or(r.decoded);
    let files = kept.len();
    match rewrite_artifact_origins(body, kept, r.reachable, base) {
        Ok(out) => {
            info!(
                url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path),
                waharoa.package.files = files,
                waharoa.package.rewritten_files = out.rewritten,
                waharoa.package.left_alone_files = out.left_alone,
                "simple index rewritten"
            );
            if out.rewritten > 0 {
                Some(out.body)
            } else {
                filtered
            }
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(r.path), url.query = crate::http::url_query(r.path), error.message = %e, "UNINSPECTED: simple index could not be rewritten");
            filtered
        }
    }
}

/// The index without the files that carry a version in `refused`, and without those
/// versions in the PEP 700 `versions` key when it has one.
///
/// The version of a file is the one [`super::wire::parse`] read from its filename, so the
/// files are matched by `filename` against `project`.
fn remove_versions(
    decoded: &[u8],
    format: IndexFormat,
    project: &Project,
    refused: &HashSet<String>,
) -> Result<Vec<u8>, RemoveError> {
    let removed: HashSet<&str> = project
        .files
        .iter()
        .filter(|file| refused.contains(&file.version))
        .map(|file| file.filename.as_str())
        .collect();
    match format {
        IndexFormat::Json => remove_from_json(decoded, &removed, refused),
        IndexFormat::Html => remove_from_html(decoded, &removed),
    }
}

/// Why a document could not have a file taken out of it.
#[derive(Debug)]
pub enum RemoveError {
    Json(serde_json::Error),
    /// A page that parsed as anchors and then did not.
    Html(&'static str),
}

impl std::fmt::Display for RemoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{e}"),
            Self::Html(why) => write!(f, "{why}"),
        }
    }
}

/// The PEP 503 page without the anchors naming a removed file.
///
/// The anchor is cut out whole and nothing else is touched: the page is the index's own
/// document, and reserialising it would change bytes nobody asked us to change.
fn remove_from_html(decoded: &[u8], removed: &HashSet<&str>) -> Result<Vec<u8>, RemoveError> {
    let text = std::str::from_utf8(decoded).map_err(|_| RemoveError::Html("not UTF-8"))?;
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for anchor in super::html::anchor_spans(text).map_err(|_| RemoveError::Html("unreadable"))? {
        if !removed.contains(anchor.filename.as_str()) {
            continue;
        }
        out.push_str(&text[cursor..anchor.start]);
        cursor = anchor.end;
    }
    out.push_str(&text[cursor..]);
    Ok(out.into_bytes())
}

/// The PEP 691 document without the removed files, and without those versions in the
/// PEP 700 `versions` key when it has one.
fn remove_from_json(
    decoded: &[u8],
    removed: &HashSet<&str>,
    refused: &HashSet<String>,
) -> Result<Vec<u8>, RemoveError> {
    let mut document: Value = serde_json::from_slice(decoded).map_err(RemoveError::Json)?;
    if let Some(files) = document.get_mut("files").and_then(Value::as_array_mut) {
        files.retain(|file| {
            !file
                .get("filename")
                .and_then(Value::as_str)
                .is_some_and(|name| removed.contains(name))
        });
    }
    if let Some(versions) = document.get_mut("versions").and_then(Value::as_array_mut) {
        versions.retain(|version| !version.as_str().is_some_and(|v| refused.contains(v)));
    }
    serde_json::to_vec(&document).map_err(RemoveError::Json)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;
    use crate::route::RequestTarget;

    /// The origins every row reaches, which include PyPI's two hosts.
    fn reachable() -> ReachableOrigins {
        ReachableOrigins::new(std::iter::empty(), std::iter::empty())
            .expect("the table's own origins are valid")
    }

    fn rewrite(decoded: &[u8], base: Option<&str>, refused: &[&str]) -> Option<Vec<u8>> {
        let project = super::super::parse("", decoded).expect("the index parses");
        rewrite_parsed(decoded, &project, base, refused)
    }

    fn rewrite_parsed(
        decoded: &[u8],
        project: &Project,
        base: Option<&str>,
        refused: &[&str],
    ) -> Option<Vec<u8>> {
        let refused: HashSet<String> = refused.iter().map(|v| (*v).to_owned()).collect();
        rewrite_index(Rewrite {
            decoded,
            format: IndexFormat::Json,
            project,
            reachable: &reachable(),
            base,
            refused_by_policy: &refused,
            path: "/simple/x/",
        })
    }

    /// The log line says why a document could not have a file taken out of it.
    #[test]
    fn a_document_that_cannot_be_filtered_says_why() {
        let json = remove_from_json(b"not json", &HashSet::new(), &HashSet::new())
            .expect_err("not a document");
        assert!(json.to_string().contains("expected ident"), "{json}");
        let html = remove_from_html(&[0xff], &HashSet::new()).expect_err("not text");
        assert_eq!(html.to_string(), "not UTF-8");
    }

    /// A PEP 503 page: the refused version's anchor is cut out whole, and every other byte
    /// is left as the index wrote it.
    #[test]
    fn a_refused_version_is_cut_out_of_a_pep_503_page() {
        const PAGE: &str = "<!DOCTYPE html>\n<html><body>\n\
            <a href=\"https://files.pythonhosted.org/packages/ab/x-1.0.tar.gz#sha256=aa\">x-1.0.tar.gz</a><br/>\n\
            <a href=\"https://files.pythonhosted.org/packages/cd/x-2.0.tar.gz#sha256=bb\">x-2.0.tar.gz</a><br/>\n\
            </body></html>\n";
        let project =
            super::super::html::parse("x", "https://example.test/simple/x/", PAGE.as_bytes())
                .expect("the page reads");
        let refused: HashSet<String> = ["1.0".to_owned()].into_iter().collect();
        let out = rewrite_index(Rewrite {
            decoded: PAGE.as_bytes(),
            format: IndexFormat::Html,
            project: &project,
            reachable: &reachable(),
            base: Some("http://127.0.0.1:8080"),
            refused_by_policy: &refused,
            path: "/simple/x/",
        })
        .expect("a version was refused, so the body changes");
        let out = String::from_utf8(out).expect("utf-8");
        assert!(
            !out.contains("x-1.0.tar.gz"),
            "the refused version is gone: {out}"
        );
        assert!(
            out.contains("<a href=\"http://127.0.0.1:8080/packages/cd/x-2.0.tar.gz#sha256=bb\">x-2.0.tar.gz</a>"),
            "the kept file points at the proxy, digest and all: {out}"
        );
        assert!(out.starts_with("<!DOCTYPE html>"), "{out}");
    }

    fn json(body: &[u8]) -> Value {
        serde_json::from_slice(body).expect("json")
    }

    fn filenames(document: &Value) -> Vec<&str> {
        document["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|f| f["filename"].as_str().expect("a filename"))
            .collect()
    }

    const INDEX: &[u8] = br#"{"name":"x","files":[
        {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl","hashes":{}},
        {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/x-1.0.tar.gz","hashes":{}}
    ]}"#;

    /// Two versions, the PEP 700 `versions` key, and a key this build does not read.
    const TWO_VERSIONS: &[u8] = br#"{"name":"x","meta":{"api-version":"1.1"},"versions":["1.0","2.0"],"files":[
        {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl","hashes":{}},
        {"filename":"x-2.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/ce/x-2.0-py3-none-any.whl","hashes":{}},
        {"filename":"x-2.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/02/x-2.0.tar.gz","hashes":{}}
    ]}"#;

    /// pip uses each file's url as written, so without this every file is fetched
    /// from the index's own host and nothing about those bytes is observed.
    #[test]
    fn a_rewritten_index_points_its_files_at_the_proxy() {
        let out = rewrite(INDEX, Some("http://127.0.0.1:8080"), &[]).expect("two files rewritten");
        let text = String::from_utf8(out).expect("still utf-8");
        assert!(
            text.contains("\"http://127.0.0.1:8080/packages/ab/cd/x-1.0-py3-none-any.whl\""),
            "{text}"
        );
        assert!(
            text.contains("\"http://127.0.0.1:8080/packages/ef/01/x-1.0.tar.gz\""),
            "{text}"
        );
        assert!(!text.contains("files.pythonhosted.org"), "{text}");
    }

    /// The path is kept, so the request that comes back is one `classify_path`
    /// understands and `upstream_url` sends to the host it came from.
    #[test]
    fn a_rewritten_url_round_trips_to_where_it_came_from() {
        let out = rewrite(INDEX, Some("http://127.0.0.1:8080"), &[]).expect("rewritten");
        let document = json(&out);
        let url = document["files"][0]["url"].as_str().expect("a url");
        let path = url.strip_prefix("http://127.0.0.1:8080").expect("our base");

        let (ecosystem, target) = crate::route::classify(path);
        assert_eq!(ecosystem, Ecosystem::PyPI);
        assert!(
            matches!(target, RequestTarget::Artifact { .. }),
            "{target:?}"
        );
        assert_eq!(
            super::super::upstream_url(super::super::INDEX, path),
            "https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl"
        );
    }

    /// With nothing refused, nothing to point at and nothing to rewrite each leave the
    /// body exactly as it arrived.
    #[test]
    fn an_index_with_nothing_to_change_is_forwarded_untouched() {
        assert_eq!(rewrite(INDEX, None, &[]), None);
        let offsite = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://cdn.example/x-1.0.tar.gz","hashes":{}}
        ]}"#;
        assert_eq!(
            rewrite(offsite, Some("http://p"), &[]),
            None,
            "an origin the proxy does not front is left where it is"
        );
    }

    /// Every file of a refused version goes, and so does the version in `versions`. The
    /// other files and the keys this build does not read stay.
    #[test]
    fn a_refused_version_is_removed_with_every_file_that_carries_it() {
        let out = rewrite(TWO_VERSIONS, Some("http://p"), &["2.0"]).expect("filtered");
        let document = json(&out);
        assert_eq!(filenames(&document), ["x-1.0-py3-none-any.whl"]);
        assert_eq!(document["versions"], serde_json::json!(["1.0"]));
        assert_eq!(document["meta"]["api-version"], "1.1");
        assert_eq!(
            document["files"][0]["url"],
            "http://p/packages/ab/cd/x-1.0-py3-none-any.whl"
        );
    }

    /// Filtering is a policy question and pointing files at the proxy a transport one, so
    /// a refused version is removed with rewriting off too.
    #[test]
    fn a_refused_version_is_removed_whether_or_not_files_are_repointed() {
        let out = rewrite(TWO_VERSIONS, None, &["2.0"]).expect("filtered");
        let document = json(&out);
        assert_eq!(filenames(&document), ["x-1.0-py3-none-any.whl"]);
        assert_eq!(
            document["files"][0]["url"],
            "https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl"
        );
    }

    /// Forwarding the original here would put the refused version back.
    #[test]
    fn the_filtered_body_is_sent_when_no_file_could_be_repointed() {
        let offsite = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://cdn.example/x-1.0.tar.gz","hashes":{}},
            {"filename":"x-2.0.tar.gz","url":"https://cdn.example/x-2.0.tar.gz","hashes":{}}
        ]}"#;
        let out = rewrite(offsite, Some("http://p"), &["2.0"]).expect("filtered");
        assert_eq!(filenames(&json(&out)), ["x-1.0.tar.gz"]);
    }

    /// An index that escapes its slashes does not contain its URLs as written, so the
    /// rewrite refuses it rather than repointing some files and not others.
    #[test]
    fn an_index_whose_urls_cannot_be_found_is_forwarded_untouched() {
        let escaped = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https:\/\/files.pythonhosted.org\/packages\/ef\/01\/x-1.0.tar.gz","hashes":{}}
        ]}"#;
        assert_eq!(rewrite(escaped, Some("http://p"), &[]), None);
    }

    /// Every version refused leaves an index with no files, which pip reports as no
    /// matching distribution.
    #[test]
    fn refusing_every_version_leaves_no_files() {
        let out = rewrite(TWO_VERSIONS, Some("http://p"), &["1.0", "2.0"]).expect("filtered");
        let document = json(&out);
        assert!(filenames(&document).is_empty());
        assert_eq!(document["versions"], serde_json::json!([]));
    }

    /// A body that is not the JSON the project was parsed from is forwarded as it came,
    /// with the refusal left to the artifact request.
    #[test]
    fn a_body_that_is_not_json_is_forwarded_untouched() {
        let project = super::super::parse("", TWO_VERSIONS).expect("parses");
        assert_eq!(
            rewrite_parsed(b"not json", &project, Some("http://p"), &["2.0"]),
            None
        );
    }

    /// A page that cannot be read is not cut, and a JSON index with no `versions` key has
    /// only its files filtered.
    #[test]
    fn an_unreadable_page_is_an_error_and_versions_are_optional() {
        let removed: HashSet<&str> = ["x-1.0.tar.gz"].into();
        assert!(matches!(
            remove_from_html(b"<a href=\"x\">", &removed),
            Err(RemoveError::Html("unreadable"))
        ));
        let json =
            br#"{"name":"x","files":[{"filename":"x-1.0.tar.gz"},{"filename":"x-2.0.tar.gz"}]}"#;
        let out = remove_from_json(json, &removed, &HashSet::new()).expect("filters");
        let out: Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(out["files"].as_array().map(Vec::len), Some(1));
        assert!(out.get("versions").is_none());
        let no_files = remove_from_json(br#"{"name":"x"}"#, &removed, &HashSet::new())
            .expect("nothing to filter");
        assert_eq!(no_files, br#"{"name":"x"}"#);
    }
}
