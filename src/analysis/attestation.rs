//! What a version's attestations say, verified, and what that makes of the version.
//!
//! The `provenance` check compares a version with the version published before it. This
//! module answers the two questions that takes: whose attestation is this, verified against
//! the digest it names ([`verify`]), and which version came before ([`previous`]).
//! [`provenance`] puts them together as the fact the policy engine decides on. See
//! `docs/engineering_decisions/provenance-check.md`.
//!
//! Nothing here is specific to an ecosystem. Where each registry serves its attestations and
//! how they are laid out is its adapter's: `crate::ecosystem::npm::attestation` turns npm's
//! document into the Sigstore bundle this verifies.
//!
//! Verification is offline, against Sigstore's production root as `sigstore-verify` embeds
//! it. See `docs/engineering_decisions/sigstore-verifier.md`.

use std::sync::OnceLock;

use sigstore_verify::trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot};
use sigstore_verify::types::{Artifact, ArtifactDigest, Bundle, HashAlgorithm};
use sigstore_verify::{VerificationPolicy, Verifier};

use crate::integrity::{Algorithm, Sri};
use crate::policy::decide::Provenance;
use crate::policy::facts::PublishTimes;
use crate::record::PackageRecord;

/// What verifying one artifact's attestations found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attested {
    /// The attestation verified, and names this identity: the repository and workflow
    /// file, without the ref.
    Verified { identity: String },
    /// It did not verify, or could not be read, and why. A registry that could not be
    /// reached is not this: nothing is recorded for it.
    Failed { why: String },
}

/// Verify a Sigstore bundle against the digest the metadata published for the artifact.
///
/// The digest rather than the bytes, so the version before this one is verified without
/// fetching its artifact. The digest is what the bytes are checked against when they are
/// fetched, so the two bind the same artifact.
pub fn verify(bundle: &Bundle, digest: &Sri) -> Attested {
    match verified_identity(bundle, digest) {
        Ok(identity) => Attested::Verified { identity },
        Err(why) => Attested::Failed { why },
    }
}

fn verified_identity(bundle: &Bundle, digest: &Sri) -> Result<String, String> {
    let algorithm = match digest.algorithm() {
        Algorithm::Sha256 => HashAlgorithm::Sha2256,
        Algorithm::Sha384 => HashAlgorithm::Sha2384,
        Algorithm::Sha512 => HashAlgorithm::Sha2512,
    };
    let digest = ArtifactDigest::new(algorithm, digest.digest()).map_err(|e| e.to_string())?;
    let result = verifier()?
        .verify(
            Artifact::from_digest(digest),
            bundle,
            &VerificationPolicy::any_identity(),
        )
        .map_err(|e| e.to_string())?;
    result
        .identity()
        .map(identity)
        .ok_or_else(|| "the certificate names no identity".to_owned())
}

/// The `sigstore-verify` version `Cargo.toml` pins. Checked against it by a test.
const SIGSTORE_VERIFY: &str = "0.13.0";

/// What verified a stored result: the crate version and a digest of the root it embeds.
/// A result is read back only by the verifier that wrote it, so an upgrade that fixes a
/// verification failure verifies again rather than keep the refusal.
pub fn verifier_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let root = Sha256::digest(SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes());
        let prefix: String = root.iter().take(8).map(|b| format!("{b:02x}")).collect();
        format!("sigstore-verify {SIGSTORE_VERIFY}; root sha256:{prefix}")
    })
}

/// The verifier for Sigstore's production root, built once.
fn verifier() -> Result<&'static Verifier, String> {
    static VERIFIER: OnceLock<Result<Verifier, String>> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
                .map_err(|e| format!("the embedded trusted root: {e}"))?;
            Verifier::new(&root).map_err(|e| format!("the embedded trusted root: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// The repository and workflow file a certificate's identity names, without the scheme
/// or the ref: `https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1` is
/// `github.com/o/r/.github/workflows/release.yml`.
///
/// Cut at the first `@refs/`, not the last `@`: a monorepo tags releases
/// `@scope/pkg@1.2.3`, and the ref would otherwise be half kept. GitHub and GitLab both
/// write the ref this way. An identity with no `@refs/` is kept whole.
fn identity(san: &str) -> String {
    let without_scheme = san.split_once("://").map_or(san, |(_, rest)| rest);
    without_scheme
        .split_once("@refs/")
        .map_or(without_scheme, |(path, _)| path)
        .to_owned()
}

/// The version published before another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Previous {
    /// The version has no publish time, so nothing can be said to come before it.
    Unknown,
    /// Nothing was published before it.
    First,
    /// The version with the latest publish time earlier than it.
    Version(Prior),
}

/// What the check reads of the version published before: which one it is, where its
/// attestations are, and the digest they bind.
///
/// The version as a whole. It claims attestations when any of its files does, and its
/// identity is read from its attested sdist, or from its first attested file when it has
/// no sdist. On PyPI no release was found attesting only some of its files, in 10 projects
/// measured on 2026-09-26, so which file does not change the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub version: String,
    pub attestation_url: Option<String>,
    pub integrity: Option<String>,
}

impl Prior {
    fn of(record: &PackageRecord) -> Self {
        let attested = || {
            record
                .artifacts
                .iter()
                .filter(|a| a.attestation_url.is_some())
        };
        let file = attested()
            .find(|a| !a.filename.ends_with(".whl"))
            .or_else(|| attested().next());
        Self {
            version: record.package.version().to_owned(),
            attestation_url: file.and_then(|a| a.attestation_url.clone()),
            integrity: file.and_then(|a| a.integrity.clone()),
        }
    }
}

/// When a record was published: from `times` when given, the full packument's `time` map,
/// and otherwise from the record.
fn published(record: &PackageRecord, times: Option<&PublishTimes>) -> Option<jiff::Timestamp> {
    times
        .and_then(|t| t.get(record.package.version()).copied())
        .or(record.published_at)
}

/// The version of `records` published before `version`. A record with no time is not a
/// candidate.
pub fn previous(
    records: &[PackageRecord],
    version: &str,
    times: Option<&PublishTimes>,
) -> Previous {
    let Some(index) = records.iter().position(|r| r.package.version() == version) else {
        return Previous::Unknown;
    };
    predecessors(records, times).swap_remove(index)
}

/// The version published before each of `records`, in their order. One sort, rather than a
/// scan per version, for a document that lists thousands.
///
/// Versions published at the same instant are not before one another. Among several
/// published at the latest earlier instant, the one listed last is taken.
pub fn predecessors(records: &[PackageRecord], times: Option<&PublishTimes>) -> Vec<Previous> {
    let mut dated: Vec<(jiff::Timestamp, usize)> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| published(r, times).map(|t| (t, i)))
        .collect();
    dated.sort();
    let mut out = vec![Previous::Unknown; records.len()];
    let mut before: Option<usize> = None;
    for group in dated.chunk_by(|a, b| a.0 == b.0) {
        for &(_, i) in group {
            out[i] = before.map_or(Previous::First, |p| {
                Previous::Version(Prior::of(&records[p]))
            });
        }
        before = group.last().map(|&(_, i)| i);
    }
    out
}

/// The fact as metadata alone answers it, with nothing verified: dropped provenance, or a
/// version and its predecessor that both publish none. Anything that needs a verification
/// is [`Provenance::NOT_VERIFIED`]. What the resolution path, `explain` and `policy diff`
/// decide on.
pub fn from_metadata(this: &PackageRecord, previous: &Previous) -> Provenance {
    match provenance(this, previous, None, None) {
        Answer::Known(fact) => fact,
        Answer::Needs { .. } => Provenance::NOT_VERIFIED,
    }
}

/// The provenance fact, or which attestations still have to be verified to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Known(Provenance),
    /// Verification results that are missing. The fact is [`Provenance::NOT_VERIFIED`]
    /// until they are stored.
    Needs {
        this: bool,
        previous: bool,
    },
}

/// What the version's attestations say against the version published before it.
///
/// `this_result` and `previous_result` are what verifying each one's attestations found,
/// `None` when nothing has. A version that claims no attestation needs no result.
pub fn provenance(
    this: &PackageRecord,
    previous: &Previous,
    this_result: Option<&Attested>,
    previous_result: Option<&Attested>,
) -> Answer {
    let prior = match previous {
        Previous::Unknown => {
            return Answer::Known(Provenance::Unknown(
                "it has no publish time, so the version before it is not known",
            ));
        }
        Previous::First => None,
        Previous::Version(prior) => Some(prior),
    };
    let prior_claims = prior.is_some_and(|p| p.attestation_url.is_some());
    if this.provenance.attestation_url.is_none() {
        return Answer::Known(match prior {
            Some(prior) if prior_claims => Provenance::Dropped {
                previous: prior.version.clone(),
            },
            _ => Provenance::Consistent,
        });
    }
    let needs_previous = prior_claims && previous_result.is_none();
    let identity = match this_result {
        None => {
            return Answer::Needs {
                this: true,
                previous: needs_previous,
            };
        }
        Some(Attested::Failed { why }) => {
            return Answer::Known(Provenance::Unverified { why: why.clone() });
        }
        Some(Attested::Verified { identity }) => identity,
    };
    let Some(prior) = prior.filter(|_| prior_claims) else {
        return Answer::Known(Provenance::Consistent);
    };
    match previous_result {
        None => Answer::Needs {
            this: false,
            previous: true,
        },
        Some(Attested::Failed { .. }) => Answer::Known(Provenance::Unknown(
            "the attestation of the version before it does not verify",
        )),
        Some(Attested::Verified { identity: before }) if before == identity => {
            Answer::Known(Provenance::Consistent)
        }
        Some(Attested::Verified { identity: before }) => {
            Answer::Known(Provenance::IdentityChanged {
                previous: prior.version.clone(),
                from: before.clone(),
                to: identity.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystem::npm::normalize_packument;
    use crate::record::DocumentDetail;

    const SIGSTORE_5_0_0: &str = "sha512-hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==";
    const SIGSTORE_4_1_1: &str = "sha512-endqECJkfhozrXMK5ngu/UAA0xVcVEFdnHJCElGaExypjW+HK5i6zu3NteLoaX/iFbRUbC3+DjttQs0GARr+5w==";
    const SIGSTORE_JS: &str = "github.com/sigstore/sigstore-js/.github/workflows/release.yml";

    fn bundle(version: &str) -> Bundle {
        let path = format!(
            "{}/tests/fixtures/npm/attestations/sigstore-{version}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        crate::ecosystem::npm::attestation::provenance_bundle(
            &std::fs::read(path).expect("fixture is missing"),
        )
        .expect("the fixture carries SLSA provenance")
    }

    fn sri(integrity: &str) -> Sri {
        Sri::parse(integrity).expect("parses")
    }

    /// `sigstore` 5.0.0 and 4.1.1 as npm serves their attestations, fetched 2026-09-26.
    /// Both built by the same workflow.
    #[test]
    fn a_real_attestation_verifies_against_the_digest_it_names() {
        for (version, integrity) in [("5.0.0", SIGSTORE_5_0_0), ("4.1.1", SIGSTORE_4_1_1)] {
            assert_eq!(
                verify(&bundle(version), &sri(integrity)),
                Attested::Verified {
                    identity: SIGSTORE_JS.to_owned()
                },
                "{version}"
            );
        }
    }

    #[test]
    fn an_attestation_against_another_artifact_fails() {
        let Attested::Failed { why } = verify(&bundle("5.0.0"), &sri(SIGSTORE_4_1_1)) else {
            panic!("4.1.1's digest is not 5.0.0's subject");
        };
        assert!(why.contains("does not match any subject"), "{why}");
    }

    /// A digest of a length its algorithm does not have is refused before verification.
    #[test]
    fn a_sha256_digest_is_passed_through_as_sha256() {
        use base64::Engine as _;
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let Attested::Failed { why } = verify(&bundle("5.0.0"), &sri(&format!("sha256-{short}")))
        else {
            panic!("the subject is sha512");
        };
        assert!(!why.is_empty());
        let middle = base64::engine::general_purpose::STANDARD.encode([7u8; 48]);
        assert!(matches!(
            verify(&bundle("5.0.0"), &sri(&format!("sha384-{middle}"))),
            Attested::Failed { .. }
        ));
    }

    #[test]
    fn the_verifier_names_the_pinned_version_and_the_root() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains(&format!(
                "sigstore-verify = {{ version = \"={SIGSTORE_VERIFY}\""
            )),
            "SIGSTORE_VERIFY must match the pin in Cargo.toml"
        );
        let id = verifier_id();
        assert!(
            id.starts_with("sigstore-verify 0.13.0; root sha256:"),
            "{id}"
        );
        assert_eq!(id.len(), "sigstore-verify 0.13.0; root sha256:".len() + 16);
    }

    #[test]
    fn an_identity_is_the_repository_and_workflow_without_the_ref() {
        assert_eq!(
            identity("https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1"),
            "github.com/o/r/.github/workflows/release.yml"
        );
        assert_eq!(identity("github.com/o/r/x.yml"), "github.com/o/r/x.yml");
        assert_eq!(
            identity(
                "https://github.com/o/r/.github/workflows/release.yml@refs/tags/@scope/pkg@1.2.3"
            ),
            "github.com/o/r/.github/workflows/release.yml"
        );
        assert_eq!(
            identity("https://gitlab.com/g/p//.gitlab-ci.yml@refs/heads/main"),
            "gitlab.com/g/p//.gitlab-ci.yml"
        );
    }

    /// Four versions, published in the order 1.0.0, 2.0.0, 1.0.1, 3.0.0: a backport
    /// between two majors.
    fn records(attested: &[&str]) -> Vec<PackageRecord> {
        let versions = ["1.0.0", "2.0.0", "1.0.1", "3.0.0"];
        let mut doc = serde_json::json!({"name": "pkg", "versions": {}, "time": {}});
        for (i, version) in versions.iter().enumerate() {
            let mut dist = serde_json::json!({
                "tarball": format!("https://registry.npmjs.org/pkg/-/pkg-{version}.tgz"),
                "integrity": SIGSTORE_5_0_0,
            });
            if attested.contains(version) {
                dist["attestations"] = serde_json::json!({
                    "url": format!("https://registry.npmjs.org/-/npm/v1/attestations/pkg@{version}"),
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
                });
            }
            doc["versions"][version] =
                serde_json::json!({"name": "pkg", "version": version, "dist": dist});
            doc["time"][version] = serde_json::json!(format!("2026-0{}-01T00:00:00.000Z", i + 1));
        }
        normalize_packument(doc.to_string().as_bytes(), DocumentDetail::Full)
            .expect("normalises")
            .records
    }

    fn version(previous: Previous) -> Option<String> {
        match previous {
            Previous::Version(prior) => Some(prior.version),
            _ => None,
        }
    }

    #[test]
    fn the_previous_version_is_the_latest_published_before_it() {
        let records = records(&[]);
        assert_eq!(
            version(previous(&records, "1.0.1", None)).as_deref(),
            Some("2.0.0")
        );
        assert_eq!(
            version(previous(&records, "3.0.0", None)).as_deref(),
            Some("1.0.1")
        );
        assert_eq!(previous(&records, "1.0.0", None), Previous::First);
        assert_eq!(previous(&records, "9.9.9", None), Previous::Unknown);
    }

    /// Times fetched separately answer for records that carry none, as the abbreviated
    /// packument's do not.
    #[test]
    fn separately_fetched_times_order_undated_records() {
        let mut records = records(&[]);
        for record in &mut records {
            record.published_at = None;
        }
        assert_eq!(previous(&records, "2.0.0", None), Previous::Unknown);
        let times: PublishTimes = [
            ("1.0.0", "2026-05-01T00:00:00Z"),
            ("2.0.0", "2026-06-01T00:00:00Z"),
        ]
        .into_iter()
        .map(|(v, t)| (v.to_owned(), t.parse().expect("a timestamp")))
        .collect();
        assert_eq!(
            version(previous(&records, "2.0.0", Some(&times))).as_deref(),
            Some("1.0.0")
        );
    }

    fn verified(identity: &str) -> Attested {
        Attested::Verified {
            identity: identity.to_owned(),
        }
    }

    fn failed() -> Attested {
        Attested::Failed {
            why: "bad".to_owned(),
        }
    }

    /// Every state `docs/engineering_decisions/provenance-check.md` names, with
    /// 2.0.0 compared against 1.0.0.
    #[test]
    fn each_state_is_decided_against_the_version_before_it() {
        let find = |records: &[PackageRecord], v: &str| {
            records
                .iter()
                .find(|r| r.package.version() == v)
                .expect("a record")
                .clone()
        };
        let neither = records(&[]);
        let both = records(&["1.0.0", "2.0.0"]);
        let only_before = records(&["1.0.0"]);
        let only_this = records(&["2.0.0"]);
        let ask = |records: &[PackageRecord], this: Option<&Attested>, prior: Option<&Attested>| {
            let this_record = find(records, "2.0.0");
            provenance(&this_record, &previous(records, "2.0.0", None), this, prior)
        };
        let known = Answer::Known;

        assert_eq!(ask(&neither, None, None), known(Provenance::Consistent));
        assert_eq!(
            ask(&only_before, None, None),
            known(Provenance::Dropped {
                previous: "1.0.0".to_owned()
            })
        );
        assert_eq!(
            ask(&only_this, Some(&failed()), None),
            known(Provenance::Unverified {
                why: "bad".to_owned()
            })
        );
        assert_eq!(
            ask(&only_this, Some(&verified("a")), None),
            known(Provenance::Consistent)
        );
        assert_eq!(
            ask(&both, Some(&verified("a")), Some(&verified("a"))),
            known(Provenance::Consistent)
        );
        assert_eq!(
            ask(&both, Some(&verified("b")), Some(&verified("a"))),
            known(Provenance::IdentityChanged {
                previous: "1.0.0".to_owned(),
                from: "a".to_owned(),
                to: "b".to_owned(),
            })
        );
        assert_eq!(
            ask(&both, Some(&verified("a")), Some(&failed())),
            known(Provenance::Unknown(
                "the attestation of the version before it does not verify"
            ))
        );

        // What is still to be verified.
        assert_eq!(
            ask(&both, None, None),
            Answer::Needs {
                this: true,
                previous: true
            }
        );
        assert_eq!(
            ask(&both, None, Some(&verified("a"))),
            Answer::Needs {
                this: true,
                previous: false
            }
        );
        assert_eq!(
            ask(&only_this, None, None),
            Answer::Needs {
                this: true,
                previous: false
            }
        );
        assert_eq!(
            ask(&both, Some(&verified("a")), None),
            Answer::Needs {
                this: false,
                previous: true
            }
        );

        // The first version has nothing before it, and a version with no time has no
        // known predecessor.
        let first = find(&only_this, "1.0.0");
        assert_eq!(
            provenance(&first, &Previous::First, None, None),
            known(Provenance::Consistent)
        );
        assert!(matches!(
            provenance(&first, &Previous::Unknown, None, None),
            Answer::Known(Provenance::Unknown(_))
        ));
    }
}
