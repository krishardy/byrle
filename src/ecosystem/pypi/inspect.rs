//! Reading a simple index the proxy forwarded: parse it, keep its records, and point its
//! files at the proxy.

use std::sync::Mutex;

use tracing::{info, warn};

use crate::origin::{ReachableOrigins, rewrite_artifact_origins};
use crate::store::RecordStore;

use super::normalize::normalize;
use super::wire::parse;

/// Point a simple index's files at the proxy.
///
/// pip uses each file's `url` as written, so without this every file is fetched from
/// `files.pythonhosted.org` and nothing about those bytes is observed. The path is kept,
/// which is what makes the request that comes back one [`super::classify_path`] understands
/// and [`super::upstream_url`] sends back to the same place.
///
/// `None` leaves the body exactly as it arrived: the index did not parse, there is no
/// address to point at, or the operator turned rewriting off. Each says so in the log,
/// because a forwarded index means that project's files go around the proxy.
pub fn read_index(
    decoded: &[u8],
    store: &Mutex<RecordStore>,
    reachable: &ReachableOrigins,
    base: Option<&str>,
    path: &str,
) -> Option<Vec<u8>> {
    // The project name is not read from here: `pypi::parse` takes one as the fallback for
    // an index that does not name itself, and every message below says `path`, which
    // identifies the project already.
    let project = match parse("", decoded) {
        Ok(project) => project,
        Err(e) => {
            warn!(path = %path, error = %e, "UNINSPECTED: simple index did not parse");
            return None;
        }
    };
    let files = project.files.len();

    // Stored before the rewrite, and built from the bytes that arrived. Records built
    // from the rewritten document would name the proxy's own origin as every artifact's
    // upstream, which is the wrong thing to hold as the index's claim.
    match normalize(&project) {
        Ok(metadata) => {
            let versions = metadata.records.len();
            let skipped = metadata.skipped.len();
            let artifacts: usize = metadata.records.iter().map(|r| r.artifacts.len()).sum();
            let sdist_only = metadata
                .records
                .iter()
                .filter(|r| r.has_install_scripts)
                .count();
            let (held_packages, held_records) = {
                let mut store = store.lock().expect("record store lock");
                store.insert(metadata);
                (store.len(), store.records())
            };
            info!(
                path = %path,
                files,
                versions,
                artifacts,
                skipped,
                sdist_only_versions_listed = sdist_only,
                held_packages,
                held_records,
                "simple index normalized"
            );
        }
        Err(e) => warn!(path = %path, error = %e, "UNINSPECTED: simple index did not normalize"),
    }

    let Some(base) = base else {
        warn!(
            path = %path,
            files,
            "UNINSPECTED: the simple index is forwarded as written, so its files are \
             fetched from the index's own host rather than through the proxy"
        );
        return None;
    };
    let urls: Vec<&str> = project.files.iter().map(|f| f.url.as_str()).collect();
    match rewrite_artifact_origins(decoded, urls, reachable, base) {
        Ok(out) => {
            info!(
                path = %path,
                files,
                rewritten = out.rewritten,
                left_alone = out.left_alone,
                "simple index rewritten"
            );
            (out.rewritten > 0).then_some(out.body)
        }
        Err(e) => {
            warn!(path = %path, error = %e, "UNINSPECTED: simple index could not be rewritten");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};
    use crate::route::RequestTarget;
    use crate::store::Lookup;

    fn store() -> Mutex<RecordStore> {
        Mutex::new(RecordStore::new(1000))
    }

    /// The origins every row reaches, which include PyPI's two hosts.
    fn reachable() -> ReachableOrigins {
        ReachableOrigins::new(std::iter::empty(), std::iter::empty())
            .expect("the table's own origins are valid")
    }

    fn read(store: &Mutex<RecordStore>, decoded: &[u8], base: Option<&str>) -> Option<Vec<u8>> {
        read_index(decoded, store, &reachable(), base, "/simple/x/")
    }

    /// Reading the index is what gives the artifact request that follows it a digest.
    /// Without the records the bytes are forwarded and said to be unverified.
    #[test]
    fn reading_an_index_leaves_its_records_for_the_file_request() {
        let store = store();
        let index = br#"{"name":"x","files":[
            {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl","hashes":{"sha256":"aa3f5e4a4b1a8b2b4e0a9a6e4e0f4d0b6a3d2c1f0e9d8c7b6a5f4e3d2c1b0a9f"}},
            {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/x-1.0.tar.gz","hashes":{}}
        ]}"#;

        assert_eq!(store.lock().unwrap().records(), 0);
        read(&store, index, Some("http://127.0.0.1:8080"));

        let key = PackageKey::from_registry_name(Ecosystem::PyPI, "x").unwrap();
        let mut store = store.lock().unwrap();
        assert_eq!(store.records(), 1, "one version, two files");
        let Lookup::Found(record) = store.lookup(&key, "1.0") else {
            panic!("the index named 1.0");
        };
        assert_eq!(
            record
                .artifact_named("x-1.0-py3-none-any.whl")
                .and_then(|a| a.integrity.as_deref()),
            Some("sha256-qj9eSksaiytOCppuTg9NC2o9LB8OnYx7al9OPSwbCp8=")
        );
        assert!(
            record
                .artifact_named("x-1.0.tar.gz")
                .expect("the sdist")
                .integrity
                .is_none(),
            "the index gave no digest for it"
        );
        assert!(!record.has_install_scripts, "a wheel is on offer");
        assert!(
            record.runs_install_scripts(Some("x-1.0.tar.gz")),
            "asking for the sdist is asking for the bytes that run setup.py"
        );
    }

    /// An index the proxy cannot read stores nothing rather than storing a partial
    /// record: an artifact request then says it saw no metadata, which is true.
    #[test]
    fn an_index_that_does_not_normalize_stores_nothing() {
        let store = store();
        read(&store, b"not json", Some("http://p"));
        read(
            &store,
            br#"{"name":"x","files":[{"filename":"notadistribution.txt","url":"https://e/a","hashes":{}}]}"#,
            Some("http://p"),
        );
        assert_eq!(store.lock().unwrap().records(), 0);
    }

    const INDEX: &[u8] = br#"{"name":"x","files":[
        {"filename":"x-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/packages/ab/cd/x-1.0-py3-none-any.whl","hashes":{}},
        {"filename":"x-1.0.tar.gz","url":"https://files.pythonhosted.org/packages/ef/01/x-1.0.tar.gz","hashes":{}}
    ]}"#;

    /// pip uses each file's url as written, so without this every file is fetched
    /// from the index's own host and nothing about those bytes is observed.
    #[test]
    fn a_rewritten_index_points_its_files_at_the_proxy() {
        let out =
            read(&store(), INDEX, Some("http://127.0.0.1:8080")).expect("two files rewritten");
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
        let out = read(&store(), INDEX, Some("http://127.0.0.1:8080")).expect("rewritten");
        let document: serde_json::Value = serde_json::from_slice(&out).expect("json");
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

    /// Nothing to point at, nothing that parses, and nothing to rewrite each leave
    /// the body exactly as it arrived.
    #[test]
    fn an_index_that_cannot_be_rewritten_is_forwarded_untouched() {
        assert_eq!(read(&store(), INDEX, None), None);
        assert_eq!(read(&store(), b"not json", Some("http://p")), None);
        let offsite = br#"{"name":"x","files":[
            {"filename":"x-1.0.tar.gz","url":"https://cdn.example/x-1.0.tar.gz","hashes":{}}
        ]}"#;
        assert_eq!(
            read(&store(), offsite, Some("http://p")),
            None,
            "an origin the proxy does not front is left where it is"
        );
    }
}
