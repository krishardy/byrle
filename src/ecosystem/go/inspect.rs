//! Reading a module's `@v/list` or `@latest` the proxy forwarded: the list's records are kept
//! and its refused versions' lines removed, and `@latest` naming a refused version is 404.

use std::collections::HashSet;

use tracing::{info, warn};

use crate::ecosystem::{Document, Reading, Rewriting};
use crate::record::PackageMetadata;
use crate::route::{DocumentKind, RequestTarget};

use super::paths::{LATEST, LIST, classify_path, files_url};
use super::wire::{latest, list, listed};

/// A `@v/list` as read, its records kept for the zips that follow it.
pub struct VersionList(PackageMetadata);

/// A `@latest` as read: one version, never kept, so the list's records stay whole.
pub struct Latest(PackageMetadata);

/// Read a forwarded `@v/list` or `@latest`. `None` to forward it unread: a body of the other
/// kind, or a `@latest` that does not read, which is logged.
pub fn read(reading: Reading<'_>) -> Option<Box<dyn Document>> {
    let RequestTarget::Metadata(key) = classify_path(reading.path) else {
        return None;
    };
    let files = files_url(reading.page)?;
    let path = reading.path.split('?').next().unwrap_or(reading.path);
    match reading.kind {
        DocumentKind::VersionList if path.ends_with(LIST) => {
            let metadata = list(&key, reading.decoded, &files);
            reading.store.keep(metadata.clone());
            info!(
                url.path = %crate::http::url_path(reading.path),
                byrle.package.versions = metadata.records.len(),
                byrle.package.skipped_versions = metadata.skipped.len(),
                "version list normalized"
            );
            Some(Box::new(VersionList(metadata)))
        }
        DocumentKind::Latest if path.ends_with(LATEST) => {
            match latest(&key, reading.decoded, &files) {
                Ok(metadata) => Some(Box::new(Latest(metadata))),
                Err(e) => {
                    warn!(url.path = %crate::http::url_path(reading.path), error.message = %e, "UNINSPECTED: @latest did not normalize");
                    None
                }
            }
        }
        _ => None,
    }
}

impl Document for VersionList {
    fn metadata(&self) -> Option<&PackageMetadata> {
        Some(&self.0)
    }

    /// Zips are fetched at the proxy, which the go command asks for every file, so only
    /// refused versions' lines are removed. `None` when none is.
    fn rewrite(&self, r: &Rewriting<'_>) -> Option<Vec<u8>> {
        if r.refused_by_policy.is_empty() {
            return None;
        }
        let mut kept = Vec::with_capacity(r.decoded.len());
        for line in r.decoded.split_inclusive(|b| *b == b'\n') {
            if listed(line).is_some_and(|version| r.refused_by_policy.contains(version)) {
                continue;
            }
            kept.extend_from_slice(line);
        }
        warn!(
            url.path = %crate::http::url_path(r.path),
            byrle.package.removed_by_policy = r.refused_by_policy.len(),
            "REFUSED versions removed from the document so the resolver picks another"
        );
        Some(kept)
    }
}

impl Document for Latest {
    fn metadata(&self) -> Option<&PackageMetadata> {
        Some(&self.0)
    }

    fn rewrite(&self, _: &Rewriting<'_>) -> Option<Vec<u8>> {
        None
    }

    fn names_none(&self, refused: &HashSet<String>) -> bool {
        !self.0.records.is_empty()
            && self
                .0
                .records
                .iter()
                .all(|record| refused.contains(record.package.version()))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const AT: crate::ecosystem::Repository =
        crate::ecosystem::Repository::of(crate::identity::Ecosystem::Go);
    use crate::identity::{Ecosystem, PackageKey};
    use crate::store::{Lookup, RecordStore};
    use std::sync::Mutex;

    const PROXY: &str = "https://proxy.golang.org";

    fn origins() -> crate::origin::OriginPolicy {
        crate::origin::OriginPolicy::new(
            crate::origin::ReachableOrigins::new([PROXY], std::iter::empty()).unwrap(),
            std::iter::empty(),
        )
        .unwrap()
    }

    fn reading<'a>(
        path: &'a str,
        page: &'a str,
        kind: DocumentKind,
        body: &'a [u8],
        store: &'a Mutex<RecordStore>,
        origins: &'a crate::origin::OriginPolicy,
    ) -> Reading<'a> {
        Reading {
            decoded: body,
            kind,
            page,
            store: crate::store::Keeping { store, at: AT },
            origins,
            encoded_bytes: body.len(),
            parse_started: std::time::Instant::now(),
            path,
        }
    }

    fn rewriting<'a>(
        body: &'a [u8],
        refused: &'a HashSet<String>,
        origins: &'a crate::origin::OriginPolicy,
    ) -> Rewriting<'a> {
        Rewriting {
            decoded: body,
            base: Some("http://h/go"),
            origins,
            refused_by_policy: refused,
            refuse_unservable: true,
            path: "/go/golang.org/x/text/@v/list",
        }
    }

    /// Reading the list is what gives the zip that follows it a record.
    #[test]
    fn a_list_s_records_are_kept_and_its_refused_lines_removed() {
        let (store, origins) = (Mutex::new(RecordStore::new(10)), origins());
        let body = super::super::fixture("text.list");
        let read = read(reading(
            "/go/golang.org/x/text/@v/list",
            "https://proxy.golang.org/golang.org/x/text/@v/list",
            DocumentKind::VersionList,
            &body,
            &store,
            &origins,
        ))
        .expect("read");
        assert_eq!(read.metadata().expect("records").records.len(), 51);
        let key = PackageKey::from_registry_name(Ecosystem::Go, "golang.org/x/text").unwrap();
        assert!(matches!(
            store
                .lock()
                .unwrap()
                .lookup(AT, &key, "v0.20.0", "v0.20.0.zip"),
            Lookup::Found(_)
        ));
        let none = HashSet::new();
        assert_eq!(read.rewrite(&rewriting(&body, &none, &origins)), None);
        assert!(!read.names_none(&none));
        let refused: HashSet<String> = ["v0.43.0".to_owned()].into();
        let kept = read
            .rewrite(&rewriting(b"v0.42.0\nv0.43.0\nv0.41.0", &refused, &origins))
            .expect("rewritten");
        assert_eq!(kept, b"v0.42.0\nv0.41.0");
    }

    /// `@latest` is read for its one version and leaves the list's records alone.
    #[test]
    fn latest_naming_a_refused_version_names_none() {
        let (store, origins) = (Mutex::new(RecordStore::new(10)), origins());
        let body = super::super::fixture("text.latest");
        let read = read(reading(
            "/go/golang.org/x/text/@latest",
            "https://proxy.golang.org/golang.org/x/text/@latest",
            DocumentKind::Latest,
            &body,
            &store,
            &origins,
        ))
        .expect("read");
        assert_eq!(store.lock().unwrap().len(), 0);
        let refused: HashSet<String> = ["v0.43.0".to_owned()].into();
        assert_eq!(read.rewrite(&rewriting(&body, &refused, &origins)), None);
        assert!(read.names_none(&refused));
        assert!(!read.names_none(&HashSet::new()));
    }

    /// A `@latest` with no version is not one naming a refused version: removing nothing
    /// from nothing leaves it as it came.
    #[test]
    fn latest_with_no_version_never_names_none() {
        let key = PackageKey::from_registry_name(Ecosystem::Go, "golang.org/x/text").unwrap();
        let empty = Latest(PackageMetadata {
            key,
            latest: None,
            records: Vec::new(),
            skipped: Vec::new(),
        });
        assert!(!empty.names_none(&HashSet::new()));
        assert!(!empty.names_none(&["v0.43.0".to_owned()].into()));
    }

    /// Anything else is forwarded as it came.
    #[test]
    fn a_body_of_the_other_kind_or_unread_is_forwarded() {
        let (store, origins) = (Mutex::new(RecordStore::new(10)), origins());
        for (path, page, kind, body) in [
            (
                "/go/golang.org/x/text/@latest",
                "https://proxy.golang.org/golang.org/x/text/@latest",
                DocumentKind::VersionList,
                &b"v1.0.0\n"[..],
            ),
            (
                "/go/golang.org/x/text/@v/list",
                "https://proxy.golang.org/golang.org/x/text/@v/list",
                DocumentKind::Latest,
                br#"{"Version":"v1.0.0"}"#,
            ),
            (
                "/go/golang.org/x/text/@latest",
                "https://proxy.golang.org/golang.org/x/text/@latest",
                DocumentKind::Latest,
                b"not json",
            ),
            (
                "/go/golang.org/x/text/@v/v1.0.0.info",
                "https://proxy.golang.org/golang.org/x/text/@v/v1.0.0.info",
                DocumentKind::Latest,
                b"{}",
            ),
            (
                "/go/golang.org/x/text/@v/list",
                "https://elsewhere.example/text",
                DocumentKind::VersionList,
                b"v1.0.0\n",
            ),
            (
                "/go/golang.org/x/text/@v/list",
                "",
                DocumentKind::IndexLines,
                b"v1.0.0\n",
            ),
        ] {
            assert!(
                read(reading(path, page, kind, body, &store, &origins)).is_none(),
                "{path} {page} {kind:?}"
            );
        }
    }
}
