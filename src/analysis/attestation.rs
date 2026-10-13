//! What a version's attestations say, verified offline, and what that makes of the version
//! against the versions before it. Nothing here is specific to an ecosystem.
//! See docs/engineering_decisions/provenance-check.md and
//! docs/engineering_decisions/sigstore-verifier.md.

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
    /// The attestation verified, naming this repository and workflow file, without the ref.
    Verified { identity: String },
    /// It did not verify, or could not be read, and why.
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
    let digest = ArtifactDigest::new(algorithm, digest.digest())
        .expect("an Sri's digest is its algorithm's length");
    let result = verifier()
        .verify(
            Artifact::from_digest(digest),
            bundle,
            &VerificationPolicy::any_identity(),
        )
        .map_err(|e| e.to_string())?;
    result
        .identity()
        .map(|san| identity(san.as_str()))
        .ok_or("the certificate names no identity".to_owned())
}

/// The `sigstore-verify` version `Cargo.toml` pins. Checked against it by a test.
const SIGSTORE_VERIFY: &str = "0.14.0";

/// What verified a stored result: the crate version and a digest of the root it embeds.
/// A result is read back only by the verifier that wrote it, so an upgrade that fixes a
/// verification failure verifies again rather than keep the refusal.
pub fn verifier_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let root = Sha256::digest(SIGSTORE_PRODUCTION_TRUSTED_ROOT.as_bytes());
        let prefix = crate::util::hex(&root[..8]);
        format!("sigstore-verify {SIGSTORE_VERIFY}; root sha256:{prefix}")
    })
}

/// The verifier for Sigstore's production root, built once. The root is compiled in, and
/// the tests verify real attestations with it.
fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
            .expect("the embedded trusted root parses");
        Verifier::new(&root).expect("the embedded trusted root makes a verifier")
    })
}

/// The repository and workflow file a certificate's identity names, without the scheme,
/// cut at the first `@refs/`. `san` is the identity, such as
/// `https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1`.
/// Returns `github.com/o/r/.github/workflows/release.yml`.
fn identity(san: &str) -> String {
    let without_scheme = san.split_once("://").map_or(san, |(_, rest)| rest);
    without_scheme
        .split_once("@refs/")
        .map_or(without_scheme, |(path, _)| path)
        .to_owned()
}

/// The attested versions a version is compared against: the window's, then established ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Previous {
    /// The version has no publish time, so nothing can be said to come before it.
    Unknown,
    /// Most recent first: those in the window, then the established ones.
    Known(Vec<Prior>),
}

/// A version published before, as a whole: which it is, its attestations, and their digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub version: String,
    pub attestation_url: String,
    pub integrity: Option<String>,
    /// Published before the window opened, so its identity is established.
    pub established: bool,
}

impl Prior {
    /// `None` for a version that claims no attestation.
    fn of(record: &PackageRecord) -> Option<Self> {
        let attested = || {
            record
                .artifacts
                .iter()
                .filter_map(|a| Some((a, a.attestation_url.as_ref()?)))
        };
        let (file, url) = attested()
            .find(|(a, _)| !a.filename.ends_with(".whl"))
            .or_else(|| attested().next())?;
        Some(Self {
            version: record.package.version().to_owned(),
            attestation_url: url.clone(),
            integrity: file.integrity.clone(),
            established: false,
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

/// Established versions compared by default: [`crate::env::PROVENANCE_HISTORY`].
pub const DEFAULT_HISTORY: usize = 64;

/// The history [`from_metadata`] needs: it reads only the most recent attested version.
pub const METADATA_HISTORY: usize = 1;

/// The versions `version` is compared against, with at most `history` established ones.
/// A record with no time is not a candidate.
pub fn previous(
    records: &[PackageRecord],
    version: &str,
    times: Option<&PublishTimes>,
    (window, history): (jiff::SignedDuration, usize),
) -> Previous {
    let Some(at) = records
        .iter()
        .find(|r| r.package.version() == version)
        .and_then(|r| published(r, times))
    else {
        return Previous::Unknown;
    };
    let mut before: Vec<(jiff::Timestamp, Prior)> = records
        .iter()
        .filter_map(|r| Some((published(r, times).filter(|t| *t < at)?, Prior::of(r)?)))
        .collect();
    before.sort_by_key(|(t, _)| *t);
    Previous::Known(chosen(&before, at, window, history))
}

/// [`previous`] for each of `records`, in their order: one sort, then a walk, for a
/// document that lists thousands.
///
/// Versions published at the same instant are not before one another.
pub fn predecessors(
    records: &[PackageRecord],
    times: Option<&PublishTimes>,
    (window, history): (jiff::SignedDuration, usize),
) -> Vec<Previous> {
    let mut dated: Vec<(jiff::Timestamp, usize)> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| published(r, times).map(|t| (t, i)))
        .collect();
    dated.sort();
    let mut out = vec![Previous::Unknown; records.len()];
    let mut before: Vec<(jiff::Timestamp, Prior)> = Vec::new();
    for group in dated.chunk_by(|a, b| a.0 == b.0) {
        let priors = chosen(&before, group[0].0, window, history);
        for &(_, i) in group {
            out[i] = Previous::Known(priors.clone());
        }
        before.extend(
            group
                .iter()
                .filter_map(|&(t, i)| Some((t, Prior::of(&records[i])?))),
        );
    }
    out
}

/// From `before`, the attested versions published before `at`, oldest first: those in the
/// window, then `history` established ones, each most recent first.
fn chosen(
    before: &[(jiff::Timestamp, Prior)],
    at: jiff::Timestamp,
    window: jiff::SignedDuration,
    history: usize,
) -> Vec<Prior> {
    let opens = at.checked_sub(window).unwrap_or(at);
    let split = before.partition_point(|(t, _)| *t <= opens);
    let recent = before[split..].iter().rev().map(|(_, p)| p.clone());
    let established = before[..split]
        .iter()
        .rev()
        .take(history)
        .map(|(_, p)| Prior {
            established: true,
            ..p.clone()
        });
    recent.chain(established).collect()
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
    /// Verification results still missing: this version's, and the priors' at these positions.
    Needs {
        this: bool,
        priors: Vec<usize>,
    },
}

/// What the version's attestations say against the versions before it. Its identity passes
/// when an established version names it, or, with none, when every version in the window does.
/// `this_result` is what verifying its attestations found, `None` where nothing has.
/// `prior_results` is each prior's, in the order of [`Previous::Known`].
/// Returns the fact, or the verification results still needed.
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
    let established = priors.iter().any(|p| p.established);
    let compared = priors
        .iter()
        .filter(|p| p.established == established)
        .count();
    let missing: Vec<usize> = (0..priors.len())
        .filter(|&i| priors[i].established == established)
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
    let matched = priors.iter().zip(prior_results).any(|(prior, result)| {
        prior.established
            && matches!(result, Some(Attested::Verified { identity: before }) if before == identity)
    });
    if matched {
        return Answer::Known(Provenance::Consistent);
    }
    if !missing.is_empty() {
        return Answer::Needs {
            this: false,
            priors: missing,
        };
    }
    let verified: Vec<(&Prior, &String)> = priors
        .iter()
        .zip(prior_results)
        .filter(|(prior, _)| prior.established == established)
        .filter_map(|(prior, result)| match result {
            Some(Attested::Verified { identity }) => Some((prior, identity)),
            _ => None,
        })
        .collect();
    if verified.is_empty() && compared > 0 {
        return Answer::Known(Provenance::Unknown(
            "the attestations of the versions before it do not verify",
        ));
    }
    if let (true, Some((prior, before))) = (established, verified.first()) {
        return Answer::Known(Provenance::IdentityChanged {
            previous: prior.version.clone(),
            from: (*before).clone(),
            to: identity.clone(),
        });
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
            id.starts_with("sigstore-verify 0.14.0; root sha256:"),
            "{id}"
        );
        assert_eq!(id.len(), "sigstore-verify 0.14.0; root sha256:".len() + 16);
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

    /// 1.0.0 and 2.0.0 a month apart, a 1.0.1 backport, then 3.0.x on consecutive days.
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

    const COMPARED: (jiff::SignedDuration, usize) = (WEEK, DEFAULT_HISTORY);

    /// The versions in the window, then the established ones, each most recent first.
    fn versions(previous: Previous) -> Option<(Vec<String>, Vec<String>)> {
        match previous {
            Previous::Known(priors) => {
                let (old, recent): (Vec<_>, Vec<_>) =
                    priors.into_iter().partition(|p| p.established);
                let names = |priors: Vec<Prior>| priors.into_iter().map(|p| p.version).collect();
                Some((names(recent), names(old)))
            }
            Previous::Unknown => None,
        }
    }

    fn named(versions: &[&str]) -> Vec<String> {
        versions.iter().map(|v| (*v).to_owned()).collect()
    }

    /// Every attested version in the window, then up to `history` from before it.
    #[test]
    fn the_window_then_the_established_versions_most_recent_first() {
        let records = records(SCHEDULE, ALL);
        let before = |v: &str, compared| versions(previous(&records, v, None, compared));
        assert_eq!(
            before("3.0.2", COMPARED),
            Some((
                named(&["3.0.1", "3.0.0"]),
                named(&["1.0.1", "2.0.0", "1.0.0"])
            ))
        );
        assert_eq!(
            before("3.0.2", (WEEK, 2)),
            Some((named(&["3.0.1", "3.0.0"]), named(&["1.0.1", "2.0.0"])))
        );
        assert_eq!(
            before("1.0.1", COMPARED),
            Some((vec![], named(&["2.0.0", "1.0.0"])))
        );
        assert_eq!(
            before("3.0.2", (jiff::SignedDuration::ZERO, 1)),
            Some((vec![], named(&["3.0.1"])))
        );
        assert_eq!(before("1.0.0", COMPARED), Some((vec![], vec![])));
        assert_eq!(before("9.9.9", COMPARED), None);
    }

    /// [`predecessors`] answers for every version what [`previous`] answers for one.
    #[test]
    fn predecessors_agree_with_previous_for_each_version() {
        let mut records = records(SCHEDULE, &["1.0.0", "2.0.0", "3.0.1"]);
        records[1].published_at = None;
        let each = predecessors(&records, None, (WEEK, 2));
        for (record, previous_of) in records.iter().zip(each) {
            let version = record.package.version();
            assert_eq!(
                previous_of,
                previous(&records, version, None, (WEEK, 2)),
                "{version}"
            );
        }
    }

    /// Only versions claiming attestations are compared against.
    #[test]
    fn only_attested_versions_are_kept() {
        let records = records(SCHEDULE, &["3.0.0", "3.0.2"]);
        assert_eq!(
            versions(previous(&records, "3.0.2", None, COMPARED)),
            Some((named(&["3.0.0"]), vec![]))
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
                versions(previous(&records, version, None, COMPARED)),
                Some((named(&["1.0.0"]), vec![]))
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
        assert_eq!(
            previous(&records, "2.0.0", None, COMPARED),
            Previous::Unknown
        );
        let times: PublishTimes = [
            ("1.0.0", "2026-05-01T00:00:00Z"),
            ("2.0.0", "2026-06-01T00:00:00Z"),
        ]
        .into_iter()
        .map(|(v, t)| (v.to_owned(), t.parse().expect("a timestamp")))
        .collect();
        assert_eq!(
            versions(previous(&records, "2.0.0", Some(&times), COMPARED)),
            Some((vec![], named(&["1.0.0"])))
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
        for (version, compared) in [
            ("3.0.1", COMPARED),
            ("3.0.2", COMPARED),
            ("3.0.2", (jiff::SignedDuration::ZERO, METADATA_HISTORY)),
        ] {
            let previous = previous(&records, version, None, compared);
            assert_eq!(
                from_metadata(&find(&records, version), &previous),
                Provenance::Dropped {
                    previous: "3.0.0".to_owned()
                },
                "{version}"
            );
        }
    }

    /// A burst long after the last attested release, as eslint-config-prettier's was, is
    /// compared with that release, however old.
    #[test]
    fn a_burst_long_after_the_last_attested_release_is_compared_with_it() {
        let burst = records(SCHEDULE, &["2.0.0"]);
        for version in ["1.0.1", "3.0.0", "3.0.1", "3.0.2"] {
            let previous = previous(&burst, version, None, (WEEK, METADATA_HISTORY));
            assert_eq!(
                from_metadata(&find(&burst, version), &previous),
                Provenance::Dropped {
                    previous: "2.0.0".to_owned()
                },
                "{version}"
            );
        }
    }

    /// Every state `docs/engineering_decisions/provenance-check.md` names. 3.0.2 is
    /// compared with 3.0.1 and 3.0.0 in the window, and 1.0.1, 2.0.0 and 1.0.0 before it.
    #[test]
    fn an_identity_is_decided_against_the_established_versions() {
        let all = records(SCHEDULE, ALL);
        let this = find(&all, "3.0.2");
        let before = previous(&all, "3.0.2", None, COMPARED);
        let ask = |this_result: Option<&Attested>, priors: &[Option<&Attested>]| {
            provenance(&this, &before, this_result, priors)
        };
        let known = Answer::Known;
        let (a, b, bad) = (verified("a"), verified("b"), failed());

        assert_eq!(
            ask(Some(&a), &[None, None, Some(&a), Some(&b), Some(&b)]),
            known(Provenance::Consistent),
            "a canary in the window does not matter once the identity is established"
        );
        assert_eq!(
            ask(Some(&a), &[Some(&b), Some(&b), Some(&b), Some(&a), None]),
            known(Provenance::Consistent),
            "an older match is enough, with others still unverified"
        );
        assert_eq!(
            ask(
                Some(&a),
                &[Some(&a), Some(&a), Some(&b), Some(&bad), Some(&b)]
            ),
            known(Provenance::IdentityChanged {
                previous: "1.0.1".to_owned(),
                from: "b".to_owned(),
                to: "a".to_owned(),
            }),
            "agreeing with the window is not enough"
        );
        assert_eq!(
            ask(Some(&a), &[None, None, Some(&b), None, None]),
            Answer::Needs {
                this: false,
                priors: vec![3, 4]
            }
        );
        assert_eq!(
            ask(None, &[None, None, None, None, None]),
            Answer::Needs {
                this: true,
                priors: vec![2, 3, 4]
            }
        );
        assert!(matches!(
            ask(
                Some(&a),
                &[Some(&a), Some(&a), Some(&bad), Some(&bad), Some(&bad)]
            ),
            Answer::Known(Provenance::Unknown(_))
        ));
        assert_eq!(
            ask(Some(&bad), &[None, None, None, None, None]),
            known(Provenance::Unverified {
                why: "bad".to_owned()
            })
        );
    }

    /// With no version older than the window, every one in it has to agree.
    #[test]
    fn without_an_established_version_the_window_has_to_agree() {
        let recent = records(SCHEDULE, &["3.0.0", "3.0.1", "3.0.2"]);
        let this = find(&recent, "3.0.2");
        let before = previous(&recent, "3.0.2", None, COMPARED);
        let ask =
            |priors: &[Option<&Attested>]| provenance(&this, &before, Some(&verified("a")), priors);
        let (a, b, bad) = (verified("a"), verified("b"), failed());
        assert_eq!(
            ask(&[Some(&a), Some(&a)]),
            Answer::Known(Provenance::Consistent)
        );
        assert_eq!(
            ask(&[Some(&a), Some(&b)]),
            Answer::Known(Provenance::IdentityChanged {
                previous: "3.0.0".to_owned(),
                from: "b".to_owned(),
                to: "a".to_owned(),
            })
        );
        assert_eq!(
            ask(&[Some(&bad), Some(&a)]),
            Answer::Known(Provenance::Consistent)
        );
        assert!(matches!(
            ask(&[Some(&bad), Some(&bad)]),
            Answer::Known(Provenance::Unknown(_))
        ));
        assert_eq!(
            ask(&[Some(&a), None]),
            Answer::Needs {
                this: false,
                priors: vec![1]
            }
        );

        let alone = records(SCHEDULE, &["3.0.2"]);
        let before = previous(&alone, "3.0.2", None, COMPARED);
        assert_eq!(
            provenance(&find(&alone, "3.0.2"), &before, Some(&a), &[]),
            Answer::Known(Provenance::Consistent)
        );
        assert_eq!(
            from_metadata(&find(&alone, "3.0.2"), &before),
            Provenance::NOT_VERIFIED
        );
        let none = records(SCHEDULE, &[]);
        assert_eq!(
            from_metadata(
                &find(&none, "3.0.2"),
                &previous(&none, "3.0.2", None, COMPARED)
            ),
            Provenance::Consistent
        );
        assert!(matches!(
            provenance(&this, &Previous::Unknown, None, &[]),
            Answer::Known(Provenance::Unknown(_))
        ));
    }

    /// A new workflow's burst is refused until a version from it is a window old. A release
    /// channel older than the window passes beside another.
    #[test]
    fn a_new_identity_is_refused_until_it_is_a_window_old() {
        let schedule = &[
            ("1.0.0", "2026-01-01"),
            ("1.0.1-canary", "2026-01-02"),
            ("1.1.0", "2026-02-01"),
            ("1.1.1-canary", "2026-02-01"),
            ("9.0.0", "2026-03-01"),
            ("9.0.1", "2026-03-02"),
            ("9.0.2", "2026-03-20"),
        ];
        let versions: Vec<&str> = schedule.iter().map(|(v, _)| *v).collect();
        let all = records(schedule, &versions);
        let identity = |version: &str| match version {
            v if v.ends_with("-canary") => verified("canary"),
            v if v.starts_with("9.") => verified("evil"),
            _ => verified("release"),
        };
        let decided = |version: &str| {
            let Previous::Known(priors) = previous(&all, version, None, COMPARED) else {
                panic!("{version} has a publish time");
            };
            let results: Vec<Attested> = priors.iter().map(|p| identity(&p.version)).collect();
            let results: Vec<Option<&Attested>> = results.iter().map(Some).collect();
            match provenance(
                &find(&all, version),
                &Previous::Known(priors),
                Some(&identity(version)),
                &results,
            ) {
                Answer::Known(fact) => fact,
                needs => panic!("{version}: {needs:?}"),
            }
        };
        assert_eq!(decided("1.1.0"), Provenance::Consistent);
        assert_eq!(decided("1.1.1-canary"), Provenance::Consistent);
        for version in ["9.0.0", "9.0.1"] {
            assert!(
                matches!(decided(version), Provenance::IdentityChanged { .. }),
                "{version}"
            );
        }
        assert_eq!(decided("9.0.2"), Provenance::Consistent);
    }
}
