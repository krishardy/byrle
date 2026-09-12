//! Subresource Integrity: parsing what a registry claims, and checking what arrives.
//!
//! npm publishes `dist.integrity` as an SRI string, in practice `sha512-<base64>`. Of
//! 24,852 versions measured, 24,850 carry one and every one of those is sha512; the two
//! without are from 2012 and offer only SHA-1.
//!
//! Plan §5: the registry's digest is a **cache key, not a trust anchor**. It says whether
//! this exact artifact has been analysed before. Checking it proves the bytes are the
//! ones the packument described, which is not the same as proving they are honest. A
//! mismatch is a finding, not a cache error.
//!
//! SHA-1 is deliberately not verifiable through this module. It is collision-broken, and
//! a passing SHA-1 check reported beside a passing SHA-512 check invites treating them as
//! the same evidence.

use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;

/// Hash algorithms SRI names that are worth checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    // Ordered weakest to strongest: `Ord` is how the strongest is picked when an
    // integrity string names several.
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One integrity claim: an algorithm and the digest it expects.
///
/// `Hash`, because it is the key plan §5 branches the fetch path on: see
/// [`crate::verified`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sri {
    algorithm: Algorithm,
    digest: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SriError {
    /// No entry in the string named an algorithm this checks.
    NoSupportedAlgorithm(String),
    /// The algorithm is supported but its digest does not decode, or is the wrong length.
    MalformedDigest(String),
}

impl fmt::Display for SriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSupportedAlgorithm(s) => {
                write!(f, "no supported hash in integrity string `{s}`")
            }
            Self::MalformedDigest(s) => write!(f, "integrity digest is malformed: {s}"),
        }
    }
}

impl std::error::Error for SriError {}

impl Sri {
    /// Parse an SRI metadata string.
    ///
    /// The format allows whitespace-separated entries and a `?options` suffix on each.
    /// Neither appears in any of the 24,852 npm versions measured, so neither would ever
    /// be exercised by a fixture; both are handled because a registry can start emitting
    /// them without notice. When several supported algorithms appear, the strongest wins.
    pub fn parse(integrity: &str) -> Result<Self, SriError> {
        let mut best: Option<Sri> = None;
        let mut malformed: Option<String> = None;

        for entry in integrity.split_whitespace() {
            // `sha512-<base64>?foo=bar`: options are advisory and not part of the digest.
            let entry = entry.split('?').next().unwrap_or(entry);
            let Some((name, encoded)) = entry.split_once('-') else {
                continue;
            };
            let Some(algorithm) = Algorithm::parse(&name.to_ascii_lowercase()) else {
                continue;
            };
            if best.as_ref().is_some_and(|b| b.algorithm >= algorithm) {
                continue;
            }

            match decode_digest(algorithm, encoded) {
                Ok(digest) => best = Some(Sri { algorithm, digest }),
                Err(e) => malformed = Some(e),
            }
        }

        match (best, malformed) {
            (Some(sri), _) => Ok(sri),
            (None, Some(e)) => Err(SriError::MalformedDigest(e)),
            (None, None) => Err(SriError::NoSupportedAlgorithm(integrity.to_owned())),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Start checking a byte stream against this claim.
    pub fn verifier(&self) -> Verifier {
        Verifier {
            expected: self.clone(),
            hasher: Hasher::new(self.algorithm),
        }
    }
}

fn decode_digest(algorithm: Algorithm, encoded: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let digest = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("`{encoded}` is not base64: {e}"))?;
    if digest.len() != algorithm.digest_len() {
        return Err(format!(
            "{algorithm} needs {} bytes, got {}",
            algorithm.digest_len(),
            digest.len()
        ));
    }
    Ok(digest)
}

impl fmt::Display for Sri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine as _;
        write!(
            f,
            "{}-{}",
            self.algorithm,
            base64::engine::general_purpose::STANDARD.encode(&self.digest)
        )
    }
}

enum Hasher {
    Sha256(Box<Sha256>),
    Sha384(Box<Sha384>),
    Sha512(Box<Sha512>),
}

impl Hasher {
    fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha256 => Self::Sha256(Box::default()),
            Algorithm::Sha384 => Self::Sha384(Box::default()),
            Algorithm::Sha512 => Self::Sha512(Box::default()),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(chunk),
            Self::Sha384(h) => h.update(chunk),
            Self::Sha512(h) => h.update(chunk),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// A digest being computed over bytes as they go past.
pub struct Verifier {
    expected: Sri,
    hasher: Hasher,
}

/// What actually arrived did not match what the packument claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub expected: String,
    pub actual: String,
    pub bytes: u64,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "artifact digest mismatch over {} bytes: packument claimed {}, received {}",
            self.bytes, self.expected, self.actual
        )
    }
}

impl std::error::Error for Mismatch {}

impl Verifier {
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// Compare what was hashed against the claim.
    ///
    /// `bytes` is carried into the error only for the report; it is what the caller
    /// counted, not something this can know.
    pub fn finish(self, bytes: u64) -> Result<(), Mismatch> {
        use base64::Engine as _;
        let actual = self.hasher.finish();
        if actual == self.expected.digest {
            return Ok(());
        }
        let algorithm = self.expected.algorithm;
        Err(Mismatch {
            expected: self.expected.to_string(),
            actual: format!(
                "{algorithm}-{}",
                base64::engine::general_purpose::STANDARD.encode(&actual)
            ),
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim npm publishes for lodash 4.17.21, and the digest of the tarball the
    /// registry actually serves for it.
    pub(super) const LODASH_SRI: &str = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==";

    fn sri_of(algorithm: Algorithm, data: &[u8]) -> String {
        use base64::Engine as _;
        let digest = match algorithm {
            Algorithm::Sha256 => Sha256::digest(data).to_vec(),
            Algorithm::Sha384 => Sha384::digest(data).to_vec(),
            Algorithm::Sha512 => Sha512::digest(data).to_vec(),
        };
        format!(
            "{algorithm}-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    }

    #[test]
    fn a_real_npm_integrity_string_parses() {
        let sri = Sri::parse(LODASH_SRI).expect("npm publishes this exact string");
        assert_eq!(sri.algorithm(), Algorithm::Sha512);
        assert_eq!(sri.to_string(), LODASH_SRI, "parsing has to round trip");
    }

    #[test]
    fn every_supported_algorithm_verifies_its_own_digest() {
        for algorithm in [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512] {
            let data = b"the bytes that arrived";
            let sri = Sri::parse(&sri_of(algorithm, data)).unwrap();
            assert_eq!(sri.algorithm(), algorithm);

            let mut verifier = sri.verifier();
            verifier.update(data);
            assert_eq!(verifier.finish(data.len() as u64), Ok(()), "{algorithm}");
        }
    }

    /// The bytes are hashed as they go past, in whatever chunks the network produced, so
    /// chunking must not change the answer.
    #[test]
    fn chunking_does_not_change_the_digest() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let sri = Sri::parse(&sri_of(Algorithm::Sha512, &data)).unwrap();

        let mut verifier = sri.verifier();
        for chunk in data.chunks(997) {
            verifier.update(chunk);
        }
        assert_eq!(verifier.finish(data.len() as u64), Ok(()));
    }

    /// A mismatch has to name both digests and the size, because it is a finding someone
    /// will have to investigate.
    #[test]
    fn a_mismatch_reports_what_was_claimed_and_what_arrived() {
        let sri = Sri::parse(&sri_of(Algorithm::Sha512, b"the honest bytes")).unwrap();
        let mut verifier = sri.verifier();
        verifier.update(b"something else entirely");

        let Err(mismatch) = verifier.finish(23) else {
            panic!("different bytes must not verify");
        };
        assert_eq!(mismatch.expected, sri.to_string());
        assert_ne!(mismatch.actual, mismatch.expected);
        assert!(mismatch.actual.starts_with("sha512-"));
        assert_eq!(mismatch.bytes, 23);
        assert!(
            mismatch
                .to_string()
                .contains("digest mismatch over 23 bytes")
        );
    }

    /// A single flipped byte has to fail. Otherwise the check is decoration.
    #[test]
    fn one_changed_byte_fails_the_check() {
        let mut data = vec![7u8; 4096];
        let sri = Sri::parse(&sri_of(Algorithm::Sha512, &data)).unwrap();
        data[2048] = 8;

        let mut verifier = sri.verifier();
        verifier.update(&data);
        assert!(verifier.finish(data.len() as u64).is_err());
    }

    /// The spec allows several hashes in one string. npm publishes one, so no fixture
    /// will ever cover this. The strongest has to win, whatever the order.
    #[test]
    fn the_strongest_algorithm_wins_when_several_are_offered() {
        let data = b"payload";
        let weak = sri_of(Algorithm::Sha256, data);
        let strong = sri_of(Algorithm::Sha512, data);

        for combined in [
            format!("{weak} {strong}"),
            format!("{strong} {weak}"),
            format!("{weak}  {}  {strong}", sri_of(Algorithm::Sha384, data)),
        ] {
            let sri = Sri::parse(&combined).expect("should parse");
            assert_eq!(sri.algorithm(), Algorithm::Sha512, "{combined}");
        }
    }

    /// `?options` is advisory and is not part of the digest.
    #[test]
    fn options_after_the_digest_are_ignored() {
        let sri = Sri::parse(&format!("{LODASH_SRI}?foo=bar")).expect("should parse");
        assert_eq!(sri.to_string(), LODASH_SRI);
    }

    /// An unknown algorithm is skipped rather than failing the string, so a registry
    /// adding one alongside sha512 does not break verification.
    #[test]
    fn an_unknown_algorithm_alongside_a_known_one_is_skipped() {
        let data = b"payload";
        let sri = Sri::parse(&format!(
            "blake3-Ynl0ZXM= {}",
            sri_of(Algorithm::Sha512, data)
        ))
        .expect("the sha512 entry is still usable");
        assert_eq!(sri.algorithm(), Algorithm::Sha512);
    }

    #[test]
    fn unusable_integrity_strings_say_why() {
        assert_eq!(
            Sri::parse("sha1-2KoFEwbCVDvbCxC5dXgvFkSlpwc="),
            Err(SriError::NoSupportedAlgorithm(
                "sha1-2KoFEwbCVDvbCxC5dXgvFkSlpwc=".into()
            )),
            "SHA-1 is collision-broken and is not verifiable here"
        );
        assert!(matches!(
            Sri::parse("sha512-not base64!"),
            Err(SriError::NoSupportedAlgorithm(_)) | Err(SriError::MalformedDigest(_))
        ));
        assert!(
            matches!(Sri::parse("sha512-YWJj"), Err(SriError::MalformedDigest(_))),
            "a three-byte digest is not a sha512"
        );
        assert!(matches!(
            Sri::parse(""),
            Err(SriError::NoSupportedAlgorithm(_))
        ));
        assert!(
            matches!(
                Sri::parse("nonsense"),
                Err(SriError::NoSupportedAlgorithm(_))
            ),
            "an entry with no `-` names no algorithm"
        );
        assert!(
            SriError::MalformedDigest("x".into())
                .to_string()
                .contains("malformed")
        );
        assert!(
            SriError::NoSupportedAlgorithm("x".into())
                .to_string()
                .contains("no supported hash")
        );
    }

    #[test]
    fn algorithms_order_weakest_to_strongest() {
        assert!(Algorithm::Sha256 < Algorithm::Sha384);
        assert!(Algorithm::Sha384 < Algorithm::Sha512);
        assert_eq!(Algorithm::Sha512.to_string(), "sha512");
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Against the real artifact, not a synthetic one. Fetches
    /// lodash 4.17.21 and checks it against the `dist.integrity` npm publishes for it.
    ///
    /// Ignored by default, and compiled out of coverage builds: `cargo test` must not
    /// depend on the network.
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "hits registry.npmjs.org"]
    async fn the_real_lodash_tarball_matches_its_published_digest() {
        let claimed = super::tests::LODASH_SRI;
        let sri = Sri::parse(claimed).unwrap();

        let body = reqwest::get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
            .await
            .expect("registry should answer")
            .bytes()
            .await
            .expect("body should arrive");

        let mut verifier = sri.verifier();
        for chunk in body.chunks(8192) {
            verifier.update(chunk);
        }
        assert_eq!(
            verifier.finish(body.len() as u64),
            Ok(()),
            "the tarball the registry serves does not match what its packument claims"
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    const ALL: [Algorithm; 3] = [Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512];

    fn any_algorithm() -> Algorithm {
        let i: usize = kani::any();
        kani::assume(i < ALL.len());
        ALL[i]
    }

    /// `Ord` on `Algorithm` is how `Sri::parse` picks the strongest when an integrity
    /// string names several, and the enum's ordering is the only thing that makes that
    /// correct. Reordering the variants would silently make the parser prefer the weakest
    /// hash on offer, which every test using a single-algorithm fixture would still pass.
    ///
    /// Digest length is the independent statement of strength: 32, 48, 64 bytes.
    #[kani::proof]
    fn ordering_is_by_strength() {
        let a = any_algorithm();
        let b = any_algorithm();
        assert_eq!(a < b, a.digest_len() < b.digest_len());
        assert_eq!(a == b, a.digest_len() == b.digest_len());
    }

    /// The two directions of the name mapping agree, so an algorithm this can parse is one
    /// it can also print. `Display` is used in the mismatch message a digest failure
    /// reports, which is the one place an operator reads it.
    #[kani::proof]
    fn parsing_a_name_this_prints_gives_it_back() {
        let a = any_algorithm();
        assert!(Algorithm::parse(a.as_str()) == Some(a));
    }

    /// Every algorithm names a length, and it is one SRI actually uses. A zero here would
    /// make `decode_digest` accept an empty digest.
    #[kani::proof]
    fn every_algorithm_has_a_real_digest_length() {
        let a = any_algorithm();
        let len = a.digest_len();
        assert!(len == 32 || len == 48 || len == 64);
    }
}
