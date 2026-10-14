//! Reading an index file the proxy forwarded, keeping its records, and removing the lines of
//! the versions the policy refuses.

use std::sync::Mutex;

use tracing::{info, warn};

use crate::ecosystem::{Document, Rewriting};
use crate::record::PackageMetadata;
use crate::store::RecordStore;

use super::wire::{Version, lines, normalize};

/// An index file as read: its records, when it normalised.
pub struct IndexFile(pub Option<Box<PackageMetadata>>);

/// Read a forwarded index file and keep its records. A file that does not normalise is
/// forwarded as it came, and logged.
pub fn read_index(decoded: &[u8], store: &Mutex<RecordStore>, path: &str) -> IndexFile {
    match normalize(decoded) {
        Ok(metadata) => {
            let (held_packages, held_records) = {
                let mut store = store.lock().expect("record store lock");
                store.insert(metadata.clone());
                (store.len(), store.records())
            };
            info!(
                url.path = %crate::http::url_path(path),
                byrle.package.versions = metadata.records.len(),
                byrle.package.skipped_versions = metadata.skipped.len(),
                byrle.store.packages = held_packages,
                byrle.store.records = held_records,
                "index file normalized"
            );
            IndexFile(Some(Box::new(metadata)))
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), error.message = %e, "UNINSPECTED: index file did not normalize");
            IndexFile(None)
        }
    }
}

/// `decoded` without the lines whose version is in `refused`. A line that does not parse is
/// kept, as cargo is the one to refuse it.
fn without_versions(decoded: &[u8], refused: &std::collections::HashSet<String>) -> Vec<u8> {
    let mut kept = Vec::with_capacity(decoded.len());
    for (_, line) in lines(decoded) {
        let named = serde_json::from_slice::<Version>(line).ok();
        if named.is_some_and(|v| refused.contains(&v.vers)) {
            continue;
        }
        kept.extend_from_slice(line);
        kept.push(b'\n');
    }
    kept
}

impl Document for IndexFile {
    fn metadata(&self) -> Option<&PackageMetadata> {
        self.0.as_deref()
    }

    /// Downloads already come to the proxy through `config.json`'s `dl`, so only refused
    /// lines are removed. `None` when none is.
    fn rewrite(&self, r: &Rewriting<'_>) -> Option<Vec<u8>> {
        if r.refused_by_policy.is_empty() {
            return None;
        }
        let body = without_versions(r.decoded, r.refused_by_policy);
        warn!(
            url.path = %crate::http::url_path(r.path),
            byrle.package.removed_by_policy = r.refused_by_policy.len(),
            "REFUSED versions removed from the document so the resolver picks another"
        );
        Some(body)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};
    use std::collections::HashSet;

    fn store() -> Mutex<RecordStore> {
        Mutex::new(RecordStore::new(1000))
    }

    /// Reading the file is what gives the download that follows it a digest.
    #[test]
    fn reading_an_index_file_leaves_its_records_for_the_download() {
        let store = store();
        let read = read_index(&super::super::fixture(), &store, "/cargo/it/oa/itoa");
        assert_eq!(read.metadata().expect("normalised").records.len(), 37);
        let key = PackageKey::from_registry_name(Ecosystem::Cargo, "itoa").unwrap();
        assert!(matches!(
            store
                .lock()
                .unwrap()
                .lookup(&key, "1.0.18", "itoa-1.0.18.crate"),
            crate::store::Lookup::Found(_)
        ));
        assert!(
            read_index(b"not json", &store, "/cargo/it/oa/itoa")
                .metadata()
                .is_none()
        );
    }

    /// Each kept line is the line as it came, so cargo reads what crates.io wrote.
    #[test]
    fn a_refused_version_s_line_is_removed_and_the_rest_kept_as_they_came() {
        let body = b"{\"name\":\"a\",\"vers\":\"1.0.0\"}\nnot json\n\n{\"name\":\"a\", \"vers\":\"2.0.0\"}";
        let refused: HashSet<String> = ["2.0.0".to_owned()].into();
        assert_eq!(
            without_versions(body, &refused),
            b"{\"name\":\"a\",\"vers\":\"1.0.0\"}\nnot json\n"
        );
        let fixture = super::super::fixture();
        assert_eq!(without_versions(&fixture, &HashSet::new()), fixture);
    }

    #[test]
    fn nothing_refused_forwards_the_file_as_it_came() {
        let reachable = crate::origin::ReachableOrigins::new([], []).unwrap();
        let origins = crate::origin::OriginPolicy::new(reachable, std::iter::empty()).unwrap();
        let fixture = super::super::fixture();
        let file = IndexFile(None);
        let mut rewriting = Rewriting {
            decoded: &fixture,
            base: None,
            origins: &origins,
            refused_by_policy: &HashSet::new(),
            refuse_unservable: true,
            path: "/cargo/it/oa/itoa",
        };
        assert_eq!(file.rewrite(&rewriting), None);
        let refused: HashSet<String> = ["1.0.18".to_owned()].into();
        rewriting.refused_by_policy = &refused;
        let body = file.rewrite(&rewriting).expect("filtered");
        assert_eq!(lines(&body).count(), 36);
    }
}
