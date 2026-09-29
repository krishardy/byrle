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

/// The versions a version is compared against: the one published just before it, every
/// version published in the window before it, and the most recent attested version,
/// however old. The window catches a burst: Nx published 19 malicious versions in two
/// hours, each after another. The attested version catches a burst long after the last
/// attested release: eslint-config-prettier's came 70 days after 10.1.5. See
/// `docs/engineering_decisions/incident-benchmark.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Previous {
    /// The version has no publish time, so nothing can be said to come before it.
    Unknown,
    /// Those of them that claim attestations, most recent first. Empty when none does, or
    /// nothing was published before it.
    Known(Vec<Prior>),
}

/// What the check reads of a version published before: which one it is, where its
/// attestations are, and the digest they bind.
///
/// The version as a whole. It claims attestations when any of its files does, and its
/// identity is read from its attested sdist, or from its first attested file when it has
/// no sdist. On PyPI no release was found attesting only some of its files, in 10 projects
/// measured on 2026-09-26, so which file does not change the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub version: String,
    pub attestation_url: String,
    pub integrity: Option<String>,
}

impl Prior {
    /// `None` for a version that claims no attestation.
    fn of(record: &PackageRecord) -> Option<Self> {
        let attested = || {
            record
                .artifacts
                .iter()
                .filter(|a| a.attestation_url.is_some())
        };
        let file = attested()
            .find(|a| !a.filename.ends_with(".whl"))
            .or_else(|| attested().next())?;
        Some(Self {
            version: record.package.version().to_owned(),
            attestation_url: file.attestation_url.clone()?,
            integrity: file.integrity.clone(),
        })
    }
}

/// When a record was published: from `times` when given, the full packument's `time` map,
/// and otherwise from the record.
fn published(record: &PackageRecord, times: Option<&PublishTimes>) -> Option<jiff::Timestamp> {
    times
        .and_then(|t| t.get(record.package.version()).copied())
        .or(record.published_at)
}

/// The versions `version` is compared against. A record with no time is not a candidate.
pub fn previous(
    records: &[PackageRecord],
    version: &str,
    times: Option<&PublishTimes>,
    window: jiff::SignedDuration,
) -> Previous {
    let Some(index) = records.iter().position(|r| r.package.version() == version) else {
        return Previous::Unknown;
    };
    predecessors(records, times, window).swap_remove(index)
}

/// [`previous`] for each of `records`, in their order: one sort, then a walk of each
/// version's window, for a document that lists thousands.
///
/// Versions published at the same instant are not before one another. Among several
/// published at the latest earlier instant, the one listed last is the one just before.
pub fn predecessors(
    records: &[PackageRecord],
    times: Option<&PublishTimes>,
    window: jiff::SignedDuration,
) -> Vec<Previous> {
    let mut dated: Vec<(jiff::Timestamp, usize)> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| published(r, times).map(|t| (t, i)))
        .collect();
    dated.sort();
    let mut out = vec![Previous::Unknown; records.len()];
    let mut start = 0;
    let mut anchor: Option<Prior> = None;
    for (group_start, group) in dated.chunk_by(|a, b| a.0 == b.0).scan(0, |at, group| {
        let here = *at;
        *at += group.len();
        Some((here, group))
    }) {
        let at = group[0].0;
        let opens = at.checked_sub(window).unwrap_or(at);
        while dated[start].0 < opens {
            start += 1;
        }
        // The window, and the version just before it when that falls outside the window.
        let from = start.min(group_start.saturating_sub(1));
        let mut priors: Vec<Prior> = dated[from..group_start]
            .iter()
            .rev()
            .filter_map(|&(_, i)| Prior::of(&records[i]))
            .collect();
        // And the most recent attested version, however old, when neither of those is it.
        if let Some(anchor) = &anchor
            && !priors.iter().any(|p| p.version == anchor.version)
        {
            priors.push(anchor.clone());
        }
        for &(_, i) in group {
            out[i] = Previous::Known(priors.clone());
        }
        if let Some(latest) = group
            .iter()
            .rev()
            .find_map(|&(_, i)| Prior::of(&records[i]))
        {
            anchor = Some(latest);
        }
    }
    out
}

/// The fact as metadata alone answers it, with nothing verified: dropped provenance, or a
/// version that publishes none after versions that published none. Anything that needs a
/// verification is [`Provenance::NOT_VERIFIED`]. What the resolution path, `explain` and
/// `policy diff` decide on.
pub fn from_metadata(this: &PackageRecord, previous: &Previous) -> Provenance {
    let unverified = match previous {
        Previous::Known(priors) => vec![None; priors.len()],
        Previous::Unknown => Vec::new(),
    };
    match provenance(this, previous, None, &unverified) {
        Answer::Known(fact) => fact,
        Answer::Needs { .. } => Provenance::NOT_VERIFIED,
    }
}

/// The provenance fact, or which attestations still have to be verified to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Known(Provenance),
    /// Verification results that are missing: this version's, and the priors' at these
    /// positions of [`Previous::Known`]. The fact is [`Provenance::NOT_VERIFIED`] until
    /// they are stored.
    Needs {
        this: bool,
        priors: Vec<usize>,
    },
}

/// What the version's attestations say against the versions before it.
///
/// `this_result` is what verifying its attestations found, and `prior_results` each
/// prior's, in the order of [`Previous::Known`], `None` where nothing has.
///
/// A version claiming no attestation after one that claimed some has dropped them. One
/// claiming attestations is refused when they do not verify, or when their identity
/// differs from that of any prior whose attestations verified. A prior whose attestations
/// do not verify is left out of the comparison; when every prior's fails, the check is
/// unknown.
pub fn provenance(
    this: &PackageRecord,
    previous: &Previous,
    this_result: Option<&Attested>,
    prior_results: &[Option<&Attested>],
) -> Answer {
    let priors = match previous {
        Previous::Unknown => {
            return Answer::Known(Provenance::Unknown(
                "it has no publish time, so the versions before it are not known",
            ));
        }
        Previous::Known(priors) => priors,
    };
    if this.provenance.attestation_url.is_none() {
        return Answer::Known(match priors.first() {
            Some(prior) => Provenance::Dropped {
                previous: prior.version.clone(),
            },
            None => Provenance::Consistent,
        });
    }
    let missing: Vec<usize> = (0..priors.len())
        .filter(|&i| prior_results.get(i).copied().flatten().is_none())
        .collect();
    let identity = match this_result {
        None => {
            return Answer::Needs {
                this: true,
                priors: missing,
            };
        }
        Some(Attested::Failed { why }) => {
            return Answer::Known(Provenance::Unverified { why: why.clone() });
        }
        Some(Attested::Verified { identity }) => identity,
    };
    if !missing.is_empty() {
        return Answer::Needs {
            this: false,
            priors: missing,
        };
    }
    let verified: Vec<(&Prior, &String)> = priors
        .iter()
        .zip(prior_results)
        .filter_map(|(prior, result)| match result {
            Some(Attested::Verified { identity }) => Some((prior, identity)),
            _ => None,
        })
        .collect();
    if verified.is_empty() && !priors.is_empty() {
        return Answer::Known(Provenance::Unknown(
            "the attestations of the versions before it do not verify",
        ));
    }
    match verified.iter().find(|(_, before)| *before != identity) {
        Some((prior, before)) => Answer::Known(Provenance::IdentityChanged {
            previous: prior.version.clone(),
            from: (*before).clone(),
            to: identity.clone(),
        }),
        None => Answer::Known(Provenance::Consistent),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// `pkg` with each version published on the day given, attested when listed in
    /// `attested`.
    fn records(schedule: &[(&str, &str)], attested: &[&str]) -> Vec<PackageRecord> {
        let mut doc = serde_json::json!({"name": "pkg", "versions": {}, "time": {}});
        for (version, day) in schedule {
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
            doc["time"][version] = serde_json::json!(format!("{day}T00:00:00.000Z"));
        }
        normalize_packument(doc.to_string().as_bytes(), DocumentDetail::Full)
            .expect("normalises")
            .records
    }

    /// 1.0.0 and 2.0.0 a month apart, the 1.0.1 backport a month later, then 3.0.0, 3.0.1
    /// and 3.0.2 on consecutive days.
    const SCHEDULE: &[(&str, &str)] = &[
        ("1.0.0", "2026-01-01"),
        ("2.0.0", "2026-02-01"),
        ("1.0.1", "2026-03-01"),
        ("3.0.0", "2026-04-01"),
        ("3.0.1", "2026-04-02"),
        ("3.0.2", "2026-04-03"),
    ];
    const ALL: &[&str] = &["1.0.0", "2.0.0", "1.0.1", "3.0.0", "3.0.1", "3.0.2"];
    const WEEK: jiff::SignedDuration = jiff::SignedDuration::from_hours(168);

    fn versions(previous: Previous) -> Option<Vec<String>> {
        match previous {
            Previous::Known(priors) => Some(priors.into_iter().map(|p| p.version).collect()),
            Previous::Unknown => None,
        }
    }

    /// The version just before, however old, and every version in the window, most recent
    /// first.
    #[test]
    fn the_versions_before_are_the_one_just_before_and_the_window() {
        let records = records(SCHEDULE, ALL);
        let before = |v: &str, window| versions(previous(&records, v, None, window));
        assert_eq!(
            before("3.0.2", WEEK),
            Some(vec!["3.0.1".into(), "3.0.0".into()])
        );
        assert_eq!(before("1.0.1", WEEK), Some(vec!["2.0.0".into()]));
        assert_eq!(
            before("3.0.2", jiff::SignedDuration::ZERO),
            Some(vec!["3.0.1".into()])
        );
        assert_eq!(before("1.0.0", WEEK), Some(vec![]));
        assert_eq!(before("9.9.9", WEEK), None);
    }

    /// Only versions claiming attestations are compared against.
    #[test]
    fn only_attested_versions_are_kept() {
        let records = records(SCHEDULE, &["3.0.0", "3.0.2"]);
        assert_eq!(
            versions(previous(&records, "3.0.2", None, WEEK)),
            Some(vec!["3.0.0".into()])
        );
    }

    /// Versions published at the same instant are not before one another.
    #[test]
    fn versions_published_together_are_not_before_one_another() {
        let records = records(
            &[
                ("1.0.0", "2026-01-01"),
                ("2.0.0", "2026-01-02"),
                ("2.0.1", "2026-01-02"),
            ],
            &["1.0.0", "2.0.0", "2.0.1"],
        );
        for version in ["2.0.0", "2.0.1"] {
            assert_eq!(
                versions(previous(&records, version, None, WEEK)),
                Some(vec!["1.0.0".into()])
            );
        }
    }

    /// Times fetched separately answer for records that carry none, as the abbreviated
    /// packument's do not.
    #[test]
    fn separately_fetched_times_order_undated_records() {
        let mut records = records(SCHEDULE, ALL);
        for record in &mut records {
            record.published_at = None;
        }
        assert_eq!(previous(&records, "2.0.0", None, WEEK), Previous::Unknown);
        let times: PublishTimes = [
            ("1.0.0", "2026-05-01T00:00:00Z"),
            ("2.0.0", "2026-06-01T00:00:00Z"),
        ]
        .into_iter()
        .map(|(v, t)| (v.to_owned(), t.parse().expect("a timestamp")))
        .collect();
        assert_eq!(
            versions(previous(&records, "2.0.0", Some(&times), WEEK)),
            Some(vec!["1.0.0".into()])
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

    fn find(records: &[PackageRecord], version: &str) -> PackageRecord {
        records
            .iter()
            .find(|r| r.package.version() == version)
            .expect("a record")
            .clone()
    }

    /// Nx's burst: an attested release, then unattested ones a day apart. Each is compared
    /// with the attested one, not only with the unattested one just before it.
    #[test]
    fn a_burst_after_an_attested_release_has_dropped_provenance() {
        let records = records(SCHEDULE, &["1.0.0", "2.0.0", "1.0.1", "3.0.0"]);
        for version in ["3.0.1", "3.0.2"] {
            let previous = previous(&records, version, None, WEEK);
            assert_eq!(
                from_metadata(&find(&records, version), &previous),
                Provenance::Dropped {
                    previous: "3.0.0".to_owned()
                },
                "{version}"
            );
        }
        // With no window, 3.0.2 is still compared with 3.0.0, the most recent attested.
        let previous = previous(&records, "3.0.2", None, jiff::SignedDuration::ZERO);
        assert_eq!(
            from_metadata(&find(&records, "3.0.2"), &previous),
            Provenance::Dropped {
                previous: "3.0.0".to_owned()
            }
        );
    }

    /// eslint-config-prettier's burst came 70 days after its last attested release, far
    /// outside the window, and each version after the first followed another malicious one.
    /// The most recent attested version is compared with however old it is.
    #[test]
    fn a_burst_long_after_the_last_attested_release_is_compared_with_it() {
        let burst = records(SCHEDULE, &["2.0.0"]);
        for version in ["1.0.1", "3.0.0", "3.0.1", "3.0.2"] {
            let previous = previous(&burst, version, None, WEEK);
            assert_eq!(
                from_metadata(&find(&burst, version), &previous),
                Provenance::Dropped {
                    previous: "2.0.0".to_owned()
                },
                "{version}"
            );
        }
        // Listed after the window's versions, and only once when it is also in the window.
        let attested = records(SCHEDULE, &["2.0.0", "3.0.1"]);
        assert_eq!(
            versions(previous(&attested, "3.0.2", None, WEEK)),
            Some(vec!["3.0.1".into()])
        );
        let older = records(SCHEDULE, &["2.0.0", "3.0.0"]);
        assert_eq!(
            versions(previous(&older, "1.0.1", None, WEEK)),
            Some(vec!["2.0.0".into()])
        );
        let both = records(SCHEDULE, &["1.0.0", "3.0.1"]);
        assert_eq!(
            versions(previous(&both, "3.0.2", None, jiff::SignedDuration::ZERO)),
            Some(vec!["3.0.1".into()])
        );
        let far = records(SCHEDULE, &["1.0.0", "3.0.0"]);
        assert_eq!(
            versions(previous(&far, "2.0.0", None, WEEK)),
            Some(vec!["1.0.0".into()])
        );
    }

    /// Every state `docs/engineering_decisions/provenance-check.md` names, with 3.0.2
    /// compared against 3.0.1 and 3.0.0.
    #[test]
    fn each_state_is_decided_against_the_versions_before_it() {
        let both = records(SCHEDULE, ALL);
        let this = find(&both, "3.0.2");
        let before = previous(&both, "3.0.2", None, WEEK);
        let ask = |this_result: Option<&Attested>, priors: &[Option<&Attested>]| {
            provenance(&this, &before, this_result, priors)
        };
        let known = Answer::Known;
        let (a, b) = (verified("a"), verified("b"));

        assert_eq!(
            ask(Some(&a), &[Some(&a), Some(&a)]),
            known(Provenance::Consistent)
        );
        assert_eq!(
            ask(Some(&failed()), &[None, None]),
            known(Provenance::Unverified {
                why: "bad".to_owned()
            })
        );
        // A change against any prior, named by the one that differs.
        assert_eq!(
            ask(Some(&a), &[Some(&a), Some(&b)]),
            known(Provenance::IdentityChanged {
                previous: "3.0.0".to_owned(),
                from: "b".to_owned(),
                to: "a".to_owned(),
            })
        );
        // A prior that does not verify is left out; when all fail, it is unknown.
        assert_eq!(
            ask(Some(&a), &[Some(&failed()), Some(&a)]),
            known(Provenance::Consistent)
        );
        assert!(matches!(
            ask(Some(&a), &[Some(&failed()), Some(&failed())]),
            Answer::Known(Provenance::Unknown(_))
        ));

        // What is still to be verified.
        assert_eq!(
            ask(None, &[None, Some(&a)]),
            Answer::Needs {
                this: true,
                priors: vec![0]
            }
        );
        assert_eq!(
            ask(Some(&a), &[Some(&a), None]),
            Answer::Needs {
                this: false,
                priors: vec![1]
            }
        );

        // Nothing attested before: its own attestation decides.
        let alone = records(SCHEDULE, &["3.0.2"]);
        let before = previous(&alone, "3.0.2", None, WEEK);
        assert_eq!(
            provenance(&find(&alone, "3.0.2"), &before, Some(&a), &[]),
            known(Provenance::Consistent)
        );
        assert_eq!(
            from_metadata(&find(&alone, "3.0.2"), &before),
            Provenance::NOT_VERIFIED
        );
        let none = records(SCHEDULE, &[]);
        assert_eq!(
            from_metadata(&find(&none, "3.0.2"), &previous(&none, "3.0.2", None, WEEK)),
            Provenance::Consistent
        );
        assert!(matches!(
            provenance(&this, &Previous::Unknown, None, &[]),
            Answer::Known(Provenance::Unknown(_))
        ));
    }
}
