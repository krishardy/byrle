//! Reading a packument body the proxy forwarded: decode it, then normalise it.

use std::sync::Mutex;
use std::time::Instant;

use tracing::{info, warn};

use crate::http::{DecodeError, decode_for_parsing};
use crate::origin::OriginPolicy;
use crate::record::{DocumentDetail, PackageMetadata};
use crate::store::RecordStore;

use super::error::NormalizeError;
use super::normalize::normalize_packument;

/// What reading a packument body produced.
#[derive(Debug)]
pub enum PackumentOutcome {
    Normalized(Box<PackageMetadata>),
    /// The body could not be decoded, or decoded past the limit.
    Undecodable(DecodeError),
    /// The body decoded but is not a shape we model. Our gap, not an upstream outage.
    Unreadable(NormalizeError),
}

/// Decode a packument body and normalise it.
///
/// Separate from the proxy's handler because it is the part worth testing directly: the
/// handler around it only decides what to forward.
pub fn inspect_packument(
    body: &[u8],
    content_encoding: Option<&str>,
    detail: DocumentDetail,
    limit: usize,
) -> PackumentOutcome {
    match decode_for_parsing(body, content_encoding, limit) {
        Ok(decoded) => inspect_decoded(&decoded, detail),
        Err(e) => PackumentOutcome::Undecodable(e),
    }
}

/// Read a packument the proxy forwarded: normalise it, keep its records, and say what it
/// holds. `None` when it did not normalise, which is logged as UNINSPECTED.
///
/// The records are built from the bytes that arrived, not the rewritten document, which
/// would name the proxy's own origin as every artifact's upstream.
pub fn read_packument(
    decoded: &[u8],
    detail: DocumentDetail,
    store: &Mutex<RecordStore>,
    origins: &OriginPolicy,
    encoded_bytes: usize,
    parse_started: Instant,
    path: &str,
) -> Option<Box<PackageMetadata>> {
    match normalize_packument(decoded, detail) {
        Ok(p) => {
            let p = Box::new(p);
            let (allowed_direct, refused) = p.unserved_origins(origins);
            let (held_packages, held_records) = {
                let mut store = store.lock().expect("record store lock");
                store.insert((*p).clone());
                (store.len(), store.records())
            };
            info!(
                url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path),
                waharoa.package.purl = %p.key,
                waharoa.package.detail = ?detail,
                waharoa.package.versions = p.records.len(),
                waharoa.package.skipped_versions = p.skipped.len(),
                install_script_versions_listed =
                    p.records.iter().filter(|r| r.has_install_scripts).count(),
                waharoa.package.deprecated_versions = p.records.iter().filter(|r| r.deprecated.is_some()).count(),
                waharoa.package.latest = %p.latest.as_deref().unwrap_or("-"),
                waharoa.metadata.bytes = encoded_bytes,
                waharoa.metadata.parse_ms = parse_started.elapsed().as_millis() as u64,
                waharoa.package.offsite_versions = refused.values().sum::<usize>() + allowed_direct.values().sum::<usize>(),
                waharoa.store.packages = held_packages,
                waharoa.store.records = held_records,
                "packument normalized"
            );
            Some(p)
        }
        Err(e) => {
            warn!(url.path = %crate::http::url_path(path), url.query = crate::http::url_query(path), error.message = %e, "UNINSPECTED: packument did not normalize");
            None
        }
    }
}

/// Normalise an already decoded body.
pub fn inspect_decoded(decoded: &[u8], detail: DocumentDetail) -> PackumentOutcome {
    match normalize_packument(decoded, detail) {
        Ok(p) => PackumentOutcome::Normalized(Box::new(p)),
        Err(e) => PackumentOutcome::Unreadable(e),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::fixture;
    use super::*;
    use crate::env::DEFAULT_MAX_METADATA_BYTES;
    use crate::http::gzip;

    fn gzipped(data: &[u8]) -> Vec<u8> {
        gzip(data)
    }

    #[test]
    fn identity_and_gzip_bodies_normalise_alike() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        for (encoding, bytes) in [(None, body.clone()), (Some("gzip"), gzipped(&body))] {
            let outcome = inspect_packument(
                &bytes,
                encoding,
                DocumentDetail::Abbreviated,
                DEFAULT_MAX_METADATA_BYTES,
            );
            let PackumentOutcome::Normalized(p) = outcome else {
                panic!("{encoding:?} should normalise, got {outcome:?}");
            };
            assert_eq!(p.key.to_string(), "pkg:npm/lodash");
            assert_eq!(p.records.len(), 1);
        }
    }

    /// The three failure modes stay apart: a body we cannot decode, a body we cannot
    /// model, and a body past the limit are different problems with different fixes.
    #[test]
    fn the_failure_modes_stay_apart() {
        assert!(matches!(
            inspect_packument(b"{}", Some("br"), DocumentDetail::Full, 1024),
            PackumentOutcome::Undecodable(DecodeError::UnsupportedEncoding(_))
        ));
        assert!(matches!(
            inspect_packument(b"<html>", None, DocumentDetail::Full, 1024),
            PackumentOutcome::Unreadable(_)
        ));
        assert!(matches!(
            inspect_packument(
                &gzipped(&vec![b'A'; 5000]),
                Some("gzip"),
                DocumentDetail::Full,
                100
            ),
            PackumentOutcome::Undecodable(DecodeError::TooLarge(100))
        ));
    }
}
