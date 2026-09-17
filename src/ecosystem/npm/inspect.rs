//! Reading a packument body the proxy forwarded: decode it, then normalise it.

use crate::http::{DecodeError, decode_for_parsing};
use crate::record::{PackageMetadata, PackumentDetail};

use super::error::NormalizeError;
use super::normalize::normalize_packument;

/// What reading a packument body produced.
#[derive(Debug)]
pub enum PackumentOutcome {
    Normalized(Box<PackageMetadata>),
    /// The body could not be decoded: an encoding we do not handle, a corrupt stream, or
    /// output past the limit.
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
    detail: PackumentDetail,
    limit: usize,
) -> PackumentOutcome {
    match decode_for_parsing(body, content_encoding, limit) {
        Ok(decoded) => inspect_decoded(&decoded, detail),
        Err(e) => PackumentOutcome::Undecodable(e),
    }
}

/// Normalise an already decoded body.
pub fn inspect_decoded(decoded: &[u8], detail: PackumentDetail) -> PackumentOutcome {
    match normalize_packument(decoded, detail) {
        Ok(p) => PackumentOutcome::Normalized(Box::new(p)),
        Err(e) => PackumentOutcome::Unreadable(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixture;
    use super::*;
    use crate::env::DEFAULT_MAX_PACKUMENT_BYTES;
    use crate::http::gzip;

    fn gzipped(data: &[u8]) -> Vec<u8> {
        gzip(data).expect("gzip into memory")
    }

    #[test]
    fn identity_and_gzip_bodies_normalise_alike() {
        let body = fixture("lodash-4.17.21.abbrev.json");
        for (encoding, bytes) in [(None, body.clone()), (Some("gzip"), gzipped(&body))] {
            let outcome = inspect_packument(
                &bytes,
                encoding,
                PackumentDetail::Abbreviated,
                DEFAULT_MAX_PACKUMENT_BYTES,
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
            inspect_packument(b"{}", Some("br"), PackumentDetail::Full, 1024),
            PackumentOutcome::Undecodable(DecodeError::UnsupportedEncoding(_))
        ));
        assert!(matches!(
            inspect_packument(b"<html>", None, PackumentDetail::Full, 1024),
            PackumentOutcome::Unreadable(_)
        ));
        assert!(matches!(
            inspect_packument(
                &gzipped(&vec![b'A'; 5000]),
                Some("gzip"),
                PackumentDetail::Full,
                100
            ),
            PackumentOutcome::Undecodable(DecodeError::TooLarge(100))
        ));
    }
}
