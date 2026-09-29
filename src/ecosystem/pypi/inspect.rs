//! Reading a simple index the proxy forwarded: parse it and keep its records.

use std::sync::Mutex;

use tracing::{info, warn};

use crate::record::PackageMetadata;
use crate::store::RecordStore;

use crate::route::IndexFormat;

use super::normalize::normalize;
use super::wire::{Project, parse};

/// A simple index as read.
pub struct Index {
    pub project: Project,
    /// The form the index was served in, which the rewrite has to remove files from.
    pub format: IndexFormat,
    /// Its records, when it normalised.
    pub metadata: Option<Box<PackageMetadata>>,
}

/// No project name for the parsers: every message here names the project by its path.
const UNNAMED: &str = "";

/// Parse a forwarded simple index and keep its records.
///
/// `None` when it did not parse: the body is then forwarded as it arrived.
pub fn read_index(
    decoded: &[u8],
    format: IndexFormat,
    page: &str,
    store: &Mutex<RecordStore>,
    path: &str,
) -> Option<Index> {
    let read = match format {
        IndexFormat::Json => parse(UNNAMED, decoded),
        IndexFormat::Html => super::html::parse(UNNAMED, page, decoded),
    };
    let project = match read {
        Ok(project) => project,
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "UNINSPECTED: simple index did not parse");
            return None;
        }
    };

    let metadata = match normalize(&project) {
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
                store.insert(metadata.clone());
                (store.len(), store.records())
            };
            info!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                waharoa.package.files = project.files.len(),
                waharoa.package.versions = versions,
                waharoa.package.artifacts = artifacts,
                waharoa.package.skipped_versions = skipped,
                waharoa.package.sdist_only_versions = sdist_only,
                provenance_files_listed = project
                    .files
                    .iter()
                    .filter(|file| file.provenance.is_some())
                    .count(),
                waharoa.store.packages = held_packages,
                waharoa.store.records = held_records,
                "simple index normalized"
            );
            Some(Box::new(metadata))
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "UNINSPECTED: simple index did not normalize");
            None
        }
    };
    Some(Index {
        project,
        format,
        metadata,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};
    use crate::store::Lookup;

    fn store() -> Mutex<RecordStore> {
        Mutex::new(RecordStore::new(1000))
    }

    fn read(store: &Mutex<RecordStore>, decoded: &[u8]) -> Option<Index> {
        read_index(
            decoded,
            IndexFormat::Json,
            "https://pypi.org/simple/x/",
            store,
            "/simple/x/",
        )
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
        read(&store, index).expect("it parses");

        let key = PackageKey::from_registry_name(Ecosystem::PyPI, "x").unwrap();
        let mut store = store.lock().unwrap();
        assert_eq!(store.records(), 1, "one version, two files");
        let Lookup::Found(record) = store.lookup(&key, "1.0", "x-1.0-py3-none-any.whl") else {
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
        assert!(read(&store, b"not json").is_none());
        assert!(
            read(
                &store,
                br#"{"name":"x","files":[{"filename":"notadistribution.txt","url":"https://e/a","hashes":{}}]}"#,
            )
            .is_none()
        );
        let unreadable = read(
            &store,
            br#"{"name":"a/b/c","files":[{"filename":"x-1.0.tar.gz","url":"https://e/a","hashes":{}}]}"#,
        )
        .expect("it parses");
        assert!(unreadable.metadata.is_none());
        assert_eq!(store.lock().unwrap().records(), 0);
    }

    /// A PEP 503 page is read against the URL it came from.
    #[test]
    fn a_pep_503_page_is_read() {
        let store = store();
        let page = b"<a href=\"/packages/x-1.0.tar.gz\">x-1.0.tar.gz</a>";
        read_index(
            page,
            IndexFormat::Html,
            "https://pypi.org/simple/x/",
            &store,
            "/simple/x/",
        )
        .expect("it parses");
        assert_eq!(store.lock().unwrap().records(), 1);
    }
}
