//! npm's attestations document, as served at `dist.attestations.url`.
//!
//! `{"attestations": [{"predicateType": ..., "bundle": {...}}]}`, one entry per attestation.
//! A version published with provenance carries two: npm's publish attestation, signed with
//! a registry key, and the SLSA provenance the build signed. Only the second names who
//! built the artifact, so it is the one verified. See
//! `docs/engineering_decisions/provenance-check.md`.

use sigstore_verify::types::Bundle;

/// The predicate type prefix of SLSA provenance, v0.2 and v1.
const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/";

/// The SLSA provenance bundle in an attestations document, or why there is none.
pub fn provenance_bundle(document: &[u8]) -> Result<Bundle, String> {
    let document: serde_json::Value =
        serde_json::from_slice(document).map_err(|e| format!("not JSON: {e}"))?;
    let bundle = document["attestations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| {
            a["predicateType"]
                .as_str()
                .is_some_and(|t| t.starts_with(SLSA_PROVENANCE))
        })
        .map(|a| &a["bundle"])
        .ok_or("no SLSA provenance attestation")?;
    Bundle::from_json(&bundle.to_string()).map_err(|e| format!("not a Sigstore bundle: {e}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn the_slsa_bundle_is_taken_and_the_publish_attestation_left() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/attestations/sigstore-5.0.0.json"
        );
        let bundle = provenance_bundle(&std::fs::read(path).expect("fixture")).expect("parses");
        // The build's attestation carries a Fulcio certificate. npm's publish attestation
        // carries the registry's public key.
        assert!(!matches!(
            bundle.verification_material.content,
            sigstore_verify::types::bundle::VerificationMaterialContent::PublicKey { .. }
        ));
    }

    #[test]
    fn a_document_it_cannot_read_says_why() {
        let why = |document: &[u8]| provenance_bundle(document).expect_err("unreadable");
        assert!(why(b"<html>").starts_with("not JSON"));
        assert_eq!(
            why(br#"{"attestations":[]}"#),
            "no SLSA provenance attestation"
        );
        assert!(
            why(br#"{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1","bundle":{}}]}"#)
                .starts_with("not a Sigstore bundle")
        );
    }
}
