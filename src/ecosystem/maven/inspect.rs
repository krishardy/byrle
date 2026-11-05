//! Reading a `maven-metadata.xml` the proxy forwarded: an artifact's versions are kept as
//! records, and the policy's refused versions removed from the body.

use tracing::{info, warn};

use crate::ecosystem::{Document, Reading, Rewriting};
use crate::record::PackageMetadata;
use crate::route::{DocumentKind, RequestTarget};

use super::paths::{classify_path, versions_url};
use super::wire::{Metadata, parse};

/// An artifact's `maven-metadata.xml` as read, its records kept for the files that follow.
pub struct ArtifactMetadata {
    read: Metadata,
    records: PackageMetadata,
}

/// Read a forwarded `maven-metadata.xml`. `None` to forward it unread: one that does not
/// parse, which is logged, or one that is not the artifact's, as a group's is not.
pub fn read(reading: Reading<'_>) -> Option<Box<dyn Document>> {
    let RequestTarget::Metadata(key) = classify_path(reading.path) else {
        return None;
    };
    if reading.kind != DocumentKind::MavenMetadata {
        return None;
    }
    let versions = versions_url(reading.page)?;
    let read = match parse(reading.decoded) {
        Ok(read) if read.is_of(&key) => read,
        Ok(_) => {
            info!(url.path = %crate::http::url_path(reading.path), "maven-metadata.xml names no versions of this artifact; forwarded unread");
            return None;
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(reading.path), error.message = %e, "UNINSPECTED: maven-metadata.xml did not normalize");
            return None;
        }
    };
    let records = read.records(&key, &versions);
    reading.store.keep(records.clone());
    info!(
        url.path = %crate::http::url_path(reading.path),
        byrle.package.versions = records.records.len(),
        "maven-metadata.xml normalized"
    );
    Some(Box::new(ArtifactMetadata { read, records }))
}

impl Document for ArtifactMetadata {
    fn metadata(&self) -> Option<&PackageMetadata> {
        Some(&self.records)
    }

    /// Files are fetched at the proxy, which mvn and Gradle ask for every file, so only
    /// refused versions are removed. `None` when none is.
    fn rewrite(&self, r: &Rewriting<'_>) -> Result<Option<Vec<u8>>, String> {
        if r.refused_by_policy.is_empty() {
            return Ok(None);
        }
        warn!(
            url.path = %crate::http::url_path(r.path),
            byrle.package.removed_by_policy = r.refused_by_policy.len(),
            "REFUSED versions removed from the document so the resolver picks another"
        );
        Ok(Some(self.read.without(r.decoded, r.refused_by_policy)))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const AT: crate::ecosystem::Repository =
        crate::ecosystem::Repository::of(crate::identity::Ecosystem::Maven);
    use crate::identity::{Ecosystem, PackageKey};
    use crate::store::{Lookup, RecordStore};
    use std::collections::HashSet;
    use std::sync::Mutex;

    const PAGE: &str =
        "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml";
    const PATH: &str = "/maven/org/apache/commons/commons-lang3/maven-metadata.xml";

    fn origins() -> crate::origin::OriginPolicy {
        crate::origin::OriginPolicy::new(
            crate::origin::ReachableOrigins::new([super::super::ORIGIN], std::iter::empty())
                .unwrap(),
            std::iter::empty(),
        )
        .unwrap()
    }

    fn read_at(
        path: &str,
        page: &str,
        kind: DocumentKind,
        body: &[u8],
        store: &Mutex<RecordStore>,
    ) -> Option<Box<dyn Document>> {
        let origins = origins();
        read(Reading {
            decoded: body,
            kind,
            page,
            store: crate::store::Keeping { store, at: AT },
            origins: &origins,
            encoded_bytes: body.len(),
            parse_started: std::time::Instant::now(),
            path,
        })
    }

    fn lang3() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Maven, "org.apache.commons:commons-lang3")
            .unwrap()
    }

    /// Reading the file is what gives a jar fetched after it its record.
    #[test]
    fn an_artifact_s_metadata_leaves_its_records_for_the_jars() {
        let store = Mutex::new(RecordStore::new(1000));
        let fixture = super::super::fixture("commons-lang3.xml");
        let document =
            read_at(PATH, PAGE, DocumentKind::MavenMetadata, &fixture, &store).expect("read");
        assert_eq!(document.metadata().unwrap().records.len(), 27);
        assert!(matches!(
            store
                .lock()
                .unwrap()
                .lookup(AT, &lang3(), "3.17.0", "commons-lang3-3.17.0.jar"),
            Lookup::Found(_)
        ));
        let origins = origins();
        let mut rewriting = Rewriting {
            decoded: &fixture,
            base: None,
            origins: &origins,
            refused_by_policy: &HashSet::new(),
            refused_files: &[],
            refuse_unservable: true,
            path: PATH,
        };
        assert_eq!(document.rewrite(&rewriting), Ok(None));
        let refused: HashSet<String> = ["3.21.0".to_owned()].into();
        rewriting.refused_by_policy = &refused;
        let body = String::from_utf8(document.rewrite(&rewriting).unwrap().unwrap()).unwrap();
        assert!(!body.contains("<version>3.21.0</version>"), "{body}");
        assert!(body.contains("<release>3.20.0</release>"), "{body}");
    }

    #[test]
    fn what_is_not_the_artifact_s_metadata_is_forwarded_unread() {
        let store = Mutex::new(RecordStore::new(1000));
        let fixture = super::super::fixture("commons-lang3.xml");
        let plugins = super::super::fixture("plugins.xml");
        for (path, page, kind, body) in [
            (
                "/maven/org/apache/maven/plugins/maven-metadata.xml",
                PAGE,
                DocumentKind::MavenMetadata,
                &plugins[..],
            ),
            (PATH, PAGE, DocumentKind::MavenMetadata, b"<metadata>"),
            (PATH, PAGE, DocumentKind::VersionList, &fixture[..]),
            (
                "/maven/org/apache/commons/commons-lang3/3.0/commons-lang3-3.0.jar",
                PAGE,
                DocumentKind::MavenMetadata,
                &fixture[..],
            ),
            (
                PATH,
                "https://r.example/x.pom",
                DocumentKind::MavenMetadata,
                &fixture[..],
            ),
        ] {
            assert!(
                read_at(path, page, kind, body, &store).is_none(),
                "{path} {page}"
            );
        }
        assert!(matches!(
            store
                .lock()
                .unwrap()
                .lookup(AT, &lang3(), "3.0", "commons-lang3-3.0.jar"),
            Lookup::Unknown
        ));
    }
}
