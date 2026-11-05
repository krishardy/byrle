//! Reading a simple index the proxy forwarded: parse it and keep its records.

use tracing::{info, warn};

use crate::record::PackageMetadata;
use crate::store::Keeping;

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
/// `Err` says why it did not parse.
pub fn read_index(
    decoded: &[u8],
    format: IndexFormat,
    page: &str,
    store: Keeping<'_>,
    path: &str,
) -> Result<Index, String> {
    let read = match format {
        IndexFormat::Json => parse(UNNAMED, decoded),
        IndexFormat::Html => super::html::parse(UNNAMED, page, decoded),
    };
    let project = match read {
        Ok(project) => project,
        Err(e) => return Err(format!("the simple index did not parse: {e}")),
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
            let (held_packages, held_records) = store.keep(metadata.clone());
            info!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                byrle.package.files = project.files.len(),
                byrle.package.versions = versions,
                byrle.package.artifacts = artifacts,
                byrle.package.skipped_versions = skipped,
                byrle.package.sdist_only_versions = sdist_only,
                provenance_files_listed = project
                    .files
                    .iter()
                    .filter(|file| file.provenance.is_some())
                    .count(),
                byrle.store.packages = held_packages,
                byrle.store.records = held_records,
                "simple index normalized"
            );
            Some(Box::new(metadata))
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "UNINSPECTED: simple index did not normalize");
            None
        }
    };
    Ok(Index {
        project,
        format,
        metadata,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const AT: crate::ecosystem::Repository =
        crate::ecosystem::Repository::of(crate::identity::Ecosystem::PyPI);
    use crate::identity::{Ecosystem, PackageKey};
    use crate::store::Lookup;

    fn store() -> std::sync::Mutex<crate::store::RecordStore> {
        std::sync::Mutex::new(crate::store::RecordStore::new(1000))
    }

    fn read(
        store: &std::sync::Mutex<crate::store::RecordStore>,
        decoded: &[u8],
    ) -> Result<Index, String> {
        read_index(
            decoded,
            IndexFormat::Json,
            "https://pypi.org/simple/x/",
            Keeping { store, at: AT },
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
        let Lookup::Found(record) = store.lookup(AT, &key, "1.0", "x-1.0-py3-none-any.whl") else {
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
        let unparsed = read(&store, b"not json").err().unwrap_or_default();
        assert!(unparsed.contains("did not parse"), "{unparsed}");
        assert!(
            read(
                &store,
                br#"{"name":"x","files":[{"filename":"notadistribution.txt","url":"https://e/a","hashes":{}}]}"#,
            )
            .is_err()
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
            Keeping {
                store: &store,
                at: AT,
            },
            "/simple/x/",
        )
        .expect("it parses");
        assert_eq!(store.lock().unwrap().records(), 1);
    }

    /// Real simple indexes parse, normalise and are served without an `Err`, which answers 502.
    /// Ignored; see docs/engineering_decisions/0046-pypi-simple-index.md for the corpus.
    #[cfg(not(coverage))]
    #[test]
    #[ignore = "needs a corpus directory of simple indexes; see the doc comment"]
    fn real_indexes_are_served_without_skipping_anything() {
        let dir = crate::env::process()
            .pypi_corpus()
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("set {} to a corpus directory", crate::env::PYPI_CORPUS));
        let origins = crate::origin::OriginPolicy::new(
            crate::origin::ReachableOrigins::new(std::iter::empty(), std::iter::empty())
                .expect("the table's own origins are valid"),
            std::iter::empty(),
        )
        .expect("valid origins");
        let (mut indexes, mut versions, mut files) = (0usize, 0usize, 0usize);
        let mut failures = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("corpus directory should be readable") {
            let path = entry.expect("readable entry").path();
            let format = match path.extension().and_then(|e| e.to_str()) {
                Some("json") => IndexFormat::Json,
                Some("html") => IndexFormat::Html,
                _ => continue,
            };
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            let body = std::fs::read(&path).expect("readable index");
            let store = store();
            let index = match read_index(
                &body,
                format,
                &format!("https://pypi.org/simple/{stem}/"),
                Keeping {
                    store: &store,
                    at: AT,
                },
                &format!("/pypi/simple/{stem}/"),
            ) {
                Ok(index) => index,
                Err(why) => {
                    failures.push(format!("{}: would answer 502: {why}", path.display()));
                    continue;
                }
            };
            indexes += 1;
            let Some(metadata) = &index.metadata else {
                failures.push(format!("{}: did not normalize", path.display()));
                continue;
            };
            versions += metadata.records.len();
            files += index.project.files.len();
            for skip in &metadata.skipped {
                let (version, reason) = (&skip.version, &skip.reason);
                failures.push(format!("{}: {version} skipped: {reason}", path.display()));
            }
            let latest = metadata
                .records
                .last()
                .map(|r| r.package.version().to_owned());
            let refusals: [std::collections::HashSet<String>; 2] = [
                std::collections::HashSet::new(),
                latest.into_iter().collect(),
            ];
            for refused_by_policy in refusals {
                let served = super::super::rewrite::rewrite_index(super::super::rewrite::Rewrite {
                    decoded: &body,
                    format,
                    project: &index.project,
                    origins: &origins,
                    base: Some("http://127.0.0.1:8080/pypi"),
                    refused_by_policy: &refused_by_policy,
                    refused_files: &[],
                    refuse_unservable: true,
                    path: "/pypi/simple/corpus/",
                });
                match served {
                    Err(why) => {
                        failures.push(format!("{}: would answer 502: {why}", path.display()));
                    }
                    Ok(Some(out)) => {
                        let on_origin = |body: &[u8]| {
                            String::from_utf8_lossy(body)
                                .matches(super::super::FILES)
                                .count()
                        };
                        let read = index.project.files.iter();
                        let read = read.filter(|file| file.url.starts_with(super::super::FILES));
                        let unread = on_origin(&body) - read.count();
                        let left = on_origin(&out).saturating_sub(unread);
                        if left > 0 {
                            let at = path.display();
                            failures.push(format!("{at}: {left} file URLs left on the origin"));
                        }
                    }
                    Ok(_) => {}
                }
            }
        }
        println!(
            "{}: served {indexes} indexes, {versions} versions, {files} files",
            dir.display()
        );
        assert!(indexes > 0, "corpus at {} held no indexes", dir.display());
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
