//! PyPI's PEP 740 provenance object, rebuilt as a Sigstore bundle to be verified.
//!
//! Its certificate and log entries become the bundle's verification material, and its
//! statement and signature a DSSE envelope: see docs/engineering_decisions/provenance-check.md.

use sigstore_verify::types::Bundle;

/// The first attestation in a provenance object, as a Sigstore bundle, or why there is
/// none. PyPI's own publish attestation is the one a trusted publisher writes for every
/// file, and it is first.
pub fn provenance_bundle(document: &[u8]) -> Result<Bundle, String> {
    let document: serde_json::Value =
        serde_json::from_slice(document).map_err(|e| format!("not JSON: {e}"))?;
    let attestation = document["attestation_bundles"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|b| b["attestations"].as_array().into_iter().flatten())
        .next()
        .ok_or("no attestation in the provenance object")?;
    let material = &attestation["verification_material"];
    let bundle = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": material["certificate"]},
            "tlogEntries": material["transparency_entries"],
        },
        "dsseEnvelope": {
            "payload": attestation["envelope"]["statement"],
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": attestation["envelope"]["signature"]}],
        },
    });
    Bundle::from_json(&bundle.to_string()).map_err(|e| format!("not a Sigstore bundle: {e}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::attestation::{Attested, verify};
    use crate::integrity::Sri;

    /// The sha256 PyPI's index publishes for each file, as SRI.
    fn sri(hex: &str) -> Sri {
        use base64::Engine as _;
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect();
        Sri::parse(&format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ))
        .expect("parses")
    }

    fn fixture(file: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pypi/attestations/{file}.provenance.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture is missing")
    }

    const SDIST: &str = "d03ceb89cb322a8fd706d4fb91940737b6642aa36998fe130a9bc96c985eff32";
    const WHEEL: &str = "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309";
    const ATTRS: &str = "github.com/python-attrs/attrs/.github/workflows/pypi-package.yml";

    /// `attrs` 26.1.0's sdist and wheel, as PyPI served their provenance on 2026-09-26.
    /// Both files of the release name the same workflow.
    #[test]
    fn each_file_verifies_against_its_own_digest() {
        for (file, digest) in [
            ("attrs-26.1.0.tar.gz", SDIST),
            ("attrs-26.1.0-py3-none-any.whl", WHEEL),
        ] {
            let bundle = provenance_bundle(&fixture(file)).expect("reads");
            assert_eq!(
                verify(&bundle, &sri(digest)),
                Attested::Verified {
                    identity: ATTRS.to_owned()
                },
                "{file}"
            );
        }
        let bundle = provenance_bundle(&fixture("attrs-26.1.0.tar.gz")).expect("reads");
        assert!(matches!(
            verify(&bundle, &sri(WHEEL)),
            Attested::Failed { .. }
        ));
    }

    #[test]
    fn a_document_it_cannot_read_says_why() {
        let why = |document: &[u8]| provenance_bundle(document).expect_err("unreadable");
        assert!(why(b"<html>").starts_with("not JSON"));
        assert_eq!(
            why(br#"{"attestation_bundles":[{"attestations":[]}]}"#),
            "no attestation in the provenance object"
        );
        assert!(
            why(br#"{"attestation_bundles":[{"attestations":[{}]}]}"#)
                .starts_with("not a Sigstore bundle")
        );
    }
}
