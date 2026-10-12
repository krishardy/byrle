//! Each pinned decision on an artifact, kept with the features it was decided on and its
//! disposition, so they can be looked up and exported without reading the audit log.
//!
//! See docs/engineering_decisions/artifact-decisions.md.

pub mod command;

use serde::{Deserialize, Serialize};

use crate::analysis::detector::Detection;
use crate::analysis::virustotal::{Scanned, Verdict};
use crate::audit::{self, Answered, RecordedFacts};

/// One pinned decision on an artifact, as the store keeps it and `byrle artifact` prints it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decided {
    /// RFC 3339, UTC: the audit line's `at`.
    pub at: String,
    /// The SRI string the metadata published. `None` without a strong digest: see the doc.
    pub digest: Option<String>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// The account whose token the request carried.
    pub account: Option<String>,
    pub features: Features,
    pub disposition: Disposition,
}

/// What the decision was made on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Features {
    /// What the policy read: the audit line's `inputs.facts`.
    pub facts: RecordedFacts,
    /// Each detector result held when the decision was made. One absent had not run.
    pub detectors: Vec<DetectorRun>,
    /// What VirusTotal said. `None` when it had not been asked about the artifact.
    pub virustotal: Option<Scan>,
}

/// One detector's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorRun {
    pub detector: String,
    #[serde(flatten)]
    pub detection: Detection,
}

/// VirusTotal's answer, with the counts when it knew the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scan {
    /// `known`, `unknown`, or `queued` for an upload whose analysis had not finished.
    pub state: String,
    pub malicious: Option<u32>,
    pub suspicious: Option<u32>,
    pub engines: Option<u32>,
}

impl Scan {
    pub fn of(scanned: &Scanned) -> Self {
        let (state, counts) = match &scanned.verdict {
            Verdict::Known(counts) => ("known", Some(counts)),
            Verdict::Unknown => ("unknown", None),
            Verdict::Queued(_) => ("queued", None),
        };
        Self {
            state: state.to_owned(),
            malicious: counts.map(|c| c.malicious),
            suspicious: counts.map(|c| c.suspicious),
            engines: counts.map(|c| c.engines),
        }
    }
}

/// What was decided, and what it was decided under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disposition {
    /// `allow`, `quarantine` or `block`.
    pub action: String,
    /// What the request was answered.
    pub answered: Answered,
    /// `enforce` or `observe`. In observe mode a refused version is served.
    pub mode: String,
    /// The checks that decided against the artifact, strongest first.
    pub checks: Vec<String>,
    /// Checks that could not be answered.
    pub unenforceable: Vec<String>,
    /// Indices of the `packages` entries that did work.
    pub exceptions_used: Vec<usize>,
    /// The signals' sum under the policy's `signal_weights`. `None` with no signal.
    pub risk_score: Option<u32>,
    /// The upstream's status, with [`Answered::UpstreamStatus`].
    pub upstream_status: Option<u16>,
    pub policy_digest: String,
    /// The intel snapshot the facts were read from. `None` when no intel store was asked.
    pub intel_snapshot: Option<String>,
    /// The day decided as of, `YYYY-MM-DD`, UTC.
    pub as_of: String,
    /// The build, reader and verifier versions, as the audit line's `inputs` gives them.
    pub build: String,
    pub reader: String,
    pub verifier: String,
}

/// What a decision row carries that its audit line does not.
#[derive(Debug, Clone, PartialEq)]
pub struct Basis {
    pub digest: Option<String>,
    /// [`crate::refusal::Mode::as_str`].
    pub mode: &'static str,
    pub detectors: Vec<DetectorRun>,
    pub virustotal: Option<Scan>,
}

impl Basis {
    /// `detections`, by detector name, and `scanned`, for the artifact with `digest`.
    pub fn of(
        digest: Option<String>,
        mode: crate::refusal::Mode,
        detections: &[(String, Detection)],
        scanned: Option<&Scanned>,
    ) -> Self {
        Self {
            digest,
            mode: mode.as_str(),
            detectors: detections
                .iter()
                .map(|(detector, detection)| DetectorRun {
                    detector: detector.clone(),
                    detection: detection.clone(),
                })
                .collect(),
            virustotal: scanned.map(Scan::of),
        }
    }
}

impl Decided {
    /// The row for `line`, a pinned audit line, with `basis`. `None` for a line that
    /// decided nothing: one with no version, no `inputs` or no `answered`.
    pub fn of(line: &audit::Event, basis: &Basis) -> Option<Self> {
        let inputs = line.inputs.as_ref()?;
        Some(Self {
            at: line.at.clone(),
            digest: basis.digest.clone(),
            ecosystem: line.ecosystem.clone(),
            name: line.name.clone(),
            version: line.version.clone()?,
            account: line.account.clone(),
            features: Features {
                facts: inputs.facts.clone(),
                detectors: basis.detectors.clone(),
                virustotal: basis.virustotal.clone(),
            },
            disposition: Disposition {
                action: line.action.clone(),
                answered: line.answered?,
                mode: basis.mode.to_owned(),
                checks: line.checks.clone(),
                unenforceable: line.unenforceable.clone(),
                exceptions_used: line.exceptions_used.clone(),
                risk_score: line.risk_score,
                upstream_status: line.upstream_status,
                policy_digest: inputs.policy_digest.clone(),
                intel_snapshot: line.intel_snapshot.clone(),
                as_of: inputs.as_of.clone(),
                build: inputs.build.clone(),
                reader: inputs.reader.clone(),
                verifier: inputs.verifier.clone(),
            },
        })
    }

    /// One line of JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a decision serialises")
    }

    /// What [`Self::to_json`] wrote. `None` for anything else.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }

    /// The day it was decided, `YYYY-MM-DD`.
    pub fn day(&self) -> &str {
        self.at.get(..10).unwrap_or(&self.at)
    }
}

/// Which artifacts `byrle artifact show` asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Artifact {
    /// The one with this Subresource Integrity string.
    Digest(String),
    /// Each artifact of this version: a PyPI version has one per wheel and sdist.
    Version {
        ecosystem: String,
        name: String,
        version: String,
    },
}

impl Artifact {
    /// A digest, `sha512-...` or `sha256-...`, or a purl naming one version.
    pub fn parse(argument: &str) -> Result<Self, String> {
        if let Ok(sri) = crate::integrity::Sri::parse(argument) {
            return Ok(Self::Digest(sri.to_string()));
        }
        let package: crate::identity::PackageRef = argument.parse().map_err(|_| {
            format!(
                "{argument} is neither a digest nor a purl with a version, such as pkg:npm/ms@2.1.3"
            )
        })?;
        let key = package.key();
        Ok(Self::Version {
            ecosystem: key.ecosystem().as_str().to_owned(),
            name: key.registry_name(),
            version: package.version().to_owned(),
        })
    }

    /// Whether `decided` is about this artifact.
    pub fn matches(&self, decided: &Decided) -> bool {
        match self {
            Self::Digest(digest) => decided.digest.as_deref() == Some(digest.as_str()),
            Self::Version {
                ecosystem,
                name,
                version,
            } => {
                decided.digest.is_some()
                    && &decided.ecosystem == ecosystem
                    && &decided.name == name
                    && &decided.version == version
            }
        }
    }
}

/// `argument` when it is a day, `YYYY-MM-DD`.
pub fn day(argument: &str) -> Result<String, String> {
    argument
        .parse::<jiff::civil::Date>()
        .map(|day| day.to_string())
        .map_err(|_| format!("{argument} is not a day, YYYY-MM-DD"))
}

/// One page of `byrle artifact export`: the decisions after row `after`, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The row id the last page ended at; 0 for the first.
    pub after: i64,
    /// The first day, `YYYY-MM-DD`, UTC. `None` from the first decision.
    pub since: Option<String>,
    /// The last day, included. `None` to the last decision.
    pub until: Option<String>,
    pub limit: usize,
}

impl Page {
    /// Whether `decided` falls between `since` and `until`.
    pub fn includes(&self, decided: &Decided) -> bool {
        let day = decided.day();
        self.since.as_deref().is_none_or(|since| day >= since)
            && self.until.as_deref().is_none_or(|until| day <= until)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::analysis::detector::Finding;
    use crate::analysis::virustotal::Counts;
    use crate::refusal::Mode;

    /// A served pinned line for `name`@1.0.0 as the proxy writes it, decided under the
    /// default policy.
    pub(crate) fn served_line(name: &str) -> audit::Event {
        let policy = crate::policy::Policy::parse("version: 1\n").unwrap();
        let facts = crate::policy::decide::Facts {
            ecosystem: "npm".into(),
            name: name.into(),
            version: "1.0.0".into(),
            published: None,
            known_malware: false,
            advisories: Vec::new(),
            intel: crate::policy::decide::Intel::NotConsulted,
            has_install_scripts: false,
            yanked: None,
            deprecated: None,
            provenance: crate::policy::decide::Provenance::NOT_VERIFIED,
        };
        let today = jiff::civil::date(2026, 10, 12);
        audit::Event::pinned(
            "npm",
            name,
            "1.0.0",
            &crate::policy::decide::decide(&policy, &facts, today),
            &[],
        )
        .answered(Answered::Served)
        .with_inputs(audit::Inputs::of(&policy, &facts, today))
        .with_account(Some("alice"))
    }

    pub(crate) fn basis(digest: &str) -> Basis {
        let found = Detection {
            findings: vec![Finding {
                rule: "typosquat".into(),
                detail: "near express".into(),
            }],
            errors: Vec::new(),
        };
        let scanned = Scanned {
            sha256: "ab".repeat(32),
            verdict: Verdict::Known(Counts {
                malicious: 2,
                suspicious: 1,
                engines: 70,
            }),
            asked: 0,
        };
        Basis::of(
            Some(digest.to_owned()),
            Mode::Observe,
            &[
                ("metadata".to_owned(), found),
                ("guarddog".to_owned(), Detection::default()),
            ],
            Some(&scanned),
        )
    }

    pub(crate) fn decided(name: &str, digest: &str) -> Decided {
        Decided::of(&served_line(name), &basis(digest)).unwrap()
    }

    #[test]
    fn a_decision_carries_the_lines_disposition_and_the_basis_features() {
        let line = served_line("ms");
        let decided = Decided::of(&line, &basis("sha512-x")).unwrap();
        assert_eq!(decided.at, line.at);
        assert_eq!(decided.digest.as_deref(), Some("sha512-x"));
        assert_eq!(
            (decided.ecosystem.as_str(), decided.name.as_str()),
            ("npm", "ms")
        );
        assert_eq!(decided.version, "1.0.0");
        assert_eq!(decided.account.as_deref(), Some("alice"));
        let inputs = line.inputs.as_ref().unwrap();
        assert_eq!(decided.features.facts, inputs.facts);
        assert_eq!(decided.features.detectors.len(), 2);
        assert_eq!(decided.features.detectors[0].detector, "metadata");
        assert_eq!(
            decided.features.detectors[1].detection,
            Detection::default()
        );
        let disposition = &decided.disposition;
        assert_eq!(disposition.action, line.action);
        assert_eq!(disposition.answered, Answered::Served);
        assert_eq!(disposition.mode, "observe");
        assert_eq!(disposition.checks, line.checks);
        assert_eq!(disposition.policy_digest, inputs.policy_digest);
        assert_eq!(disposition.as_of, "2026-10-12");
        assert_eq!(disposition.build, inputs.build);
        assert_eq!(disposition.reader, inputs.reader);
        assert_eq!(disposition.verifier, inputs.verifier);
    }

    #[test]
    fn the_lines_other_fields_are_carried_as_written() {
        let mut line = served_line("ms")
            .answered(Answered::UpstreamStatus)
            .with_upstream_status(404)
            .with_intel_snapshot(Some("sha256:snap"));
        line.unenforceable = vec!["kev".into()];
        line.exceptions_used = vec![2];
        line.risk_score = Some(3);
        let decided = Decided::of(&line, &basis("sha512-x")).unwrap();
        let disposition = &decided.disposition;
        assert_eq!(disposition.answered, Answered::UpstreamStatus);
        assert_eq!(disposition.upstream_status, Some(404));
        assert_eq!(disposition.intel_snapshot.as_deref(), Some("sha256:snap"));
        assert_eq!(disposition.unenforceable, ["kev"]);
        assert_eq!(disposition.exceptions_used, [2]);
        assert_eq!(disposition.risk_score, Some(3));
    }

    #[test]
    fn a_line_that_decided_nothing_is_no_decision() {
        let basis = basis("sha512-x");
        let undecided = audit::Event::undecided("npm", "ms", Some("1.0.0"), Answered::CutShort);
        assert_eq!(Decided::of(&undecided, &basis), None);
        let mut unversioned = served_line("ms");
        unversioned.version = None;
        assert_eq!(Decided::of(&unversioned, &basis), None);
        let mut unanswered = served_line("ms");
        unanswered.answered = None;
        assert_eq!(Decided::of(&unanswered, &basis), None);
    }

    #[test]
    fn virustotal_is_stored_by_state_with_counts_only_when_known() {
        let scan = |verdict| {
            Scan::of(&Scanned {
                sha256: String::new(),
                verdict,
                asked: 0,
            })
        };
        let known = scan(Verdict::Known(Counts {
            malicious: 2,
            suspicious: 1,
            engines: 70,
        }));
        assert_eq!(
            known,
            Scan {
                state: "known".into(),
                malicious: Some(2),
                suspicious: Some(1),
                engines: Some(70),
            }
        );
        for (verdict, state) in [
            (Verdict::Unknown, "unknown"),
            (Verdict::Queued("id".into()), "queued"),
        ] {
            assert_eq!(
                scan(verdict),
                Scan {
                    state: state.into(),
                    malicious: None,
                    suspicious: None,
                    engines: None,
                }
            );
        }
        let none = Basis::of(None, Mode::Enforce, &[], None);
        assert_eq!(none.virustotal, None);
        assert_eq!(none.mode, "enforce");
    }

    #[test]
    fn a_decision_reads_back_from_its_json() {
        let decided = decided("ms", "sha512-x");
        let json = decided.to_json();
        assert!(!json.contains('\n'));
        assert!(json.contains(r#""features":{"facts":"#), "{json}");
        assert!(
            json.contains(r#"{"detector":"metadata","findings":[{"rule":"typosquat""#),
            "{json}"
        );
        assert!(json.contains(r#""answered":"served""#), "{json}");
        assert_eq!(Decided::from_json(&json), Some(decided));
        assert_eq!(Decided::from_json("{}"), None);
    }

    #[test]
    fn a_decision_is_dated_by_its_day() {
        let mut decided = decided("ms", "sha512-x");
        decided.at = "2026-10-12T01:02:03Z".into();
        assert_eq!(decided.day(), "2026-10-12");
        decided.at = "short".into();
        assert_eq!(decided.day(), "short");
    }

    #[test]
    fn an_artifact_is_a_digest_or_a_versioned_purl() {
        let digest = format!("sha512-{}", "A".repeat(86) + "==");
        assert_eq!(Artifact::parse(&digest), Ok(Artifact::Digest(digest)));
        assert_eq!(
            Artifact::parse("pkg:npm/%40scope/a@1.0.0"),
            Ok(Artifact::Version {
                ecosystem: "npm".into(),
                name: "@scope/a".into(),
                version: "1.0.0".into(),
            })
        );
        assert_eq!(
            Artifact::parse("pkg:pypi/Foo_Bar@2.0"),
            Ok(Artifact::Version {
                ecosystem: "pypi".into(),
                name: "foo-bar".into(),
                version: "2.0".into(),
            })
        );
        for refused in ["pkg:npm/ms", "ms", "sha512-"] {
            let e = Artifact::parse(refused).unwrap_err();
            assert!(e.starts_with(refused), "{e}");
            assert!(e.contains("pkg:npm/ms@2.1.3"), "{e}");
        }
    }

    #[test]
    fn an_artifact_matches_decisions_by_digest_or_by_version_with_a_digest() {
        let decided = decided("ms", "sha512-x");
        assert!(Artifact::Digest("sha512-x".into()).matches(&decided));
        assert!(!Artifact::Digest("sha512-y".into()).matches(&decided));
        let version = |ecosystem: &str, name: &str, version: &str| Artifact::Version {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: version.into(),
        };
        assert!(version("npm", "ms", "1.0.0").matches(&decided));
        assert!(!version("pypi", "ms", "1.0.0").matches(&decided));
        assert!(!version("npm", "other", "1.0.0").matches(&decided));
        assert!(!version("npm", "ms", "2.0.0").matches(&decided));
        let undigested = Decided {
            digest: None,
            ..decided
        };
        assert!(!version("npm", "ms", "1.0.0").matches(&undigested));
    }

    #[test]
    fn a_day_is_yyyy_mm_dd() {
        assert_eq!(day("2026-10-01"), Ok("2026-10-01".to_owned()));
        assert_eq!(
            day("2026-13-01"),
            Err("2026-13-01 is not a day, YYYY-MM-DD".to_owned())
        );
    }

    #[test]
    fn a_page_includes_the_days_from_since_to_until() {
        let mut decided = decided("ms", "sha512-x");
        decided.at = "2026-10-12T23:59:59Z".into();
        let page = |since: Option<&str>, until: Option<&str>| Page {
            after: 0,
            since: since.map(str::to_owned),
            until: until.map(str::to_owned),
            limit: 10,
        };
        assert!(page(None, None).includes(&decided));
        assert!(page(Some("2026-10-12"), Some("2026-10-12")).includes(&decided));
        assert!(!page(Some("2026-10-13"), None).includes(&decided));
        assert!(!page(None, Some("2026-10-11")).includes(&decided));
    }
}
