//! What an advisory stream may say, and what it may not.
//!
//! §3 gives each stream a capability per ecosystem: `match`, `enrich` or `malware`. The
//! distinction that matters is between the first two:
//!
//! - a **`match`** stream answers "what is wrong with this package", and so originates
//!   findings;
//! - an **`enrich`** stream answers "what more is known about this advisory", and so can
//!   only add to a finding something else already made.
//!
//! NVD is the case that forced this: it is keyed by CPE, not by package, so it cannot be
//! asked about npm at all. CISA's KEV catalogue is the same shape, measured: a KEV entry
//! carries a `cveID` and no package identifier of any kind. Neither can be allowed to
//! produce a finding on its own, because neither knows what a package is.
//!
//! # The enforcement is the types, not a check
//!
//! [`Finding`] and [`Enrichment`] are different types. There is no `From<Enrichment> for
//! Finding`, no constructor on `Finding` that takes one, and [`EnrichStream`] cannot
//! return one because its return type says so. A capability field on a shared type would
//! be a runtime check wearing a type's clothes.
//!
//! ```compile_fail
//! use waharoa::intel::{Enrichment, Finding};
//! // An enrichment knows an advisory id and a score, which looks like enough to make a
//! // finding out of. It is not, and this does not compile.
//! let enrichment = Enrichment::new("CVE-2024-1234");
//! let finding: Finding = enrichment.into();
//! ```
//!
//! # What this is worth today
//!
//! Almost nothing, and it is still cheaper to build now than after three streams exist.
//! Measured over OSV's npm bundle, 96.8% of npm advisories are malware records, and the
//! `enrich` capability this machinery exists to constrain has no implemented producer at
//! all. See `docs/engineering_decisions/advisory-stream-licences.md`.

use std::collections::{BTreeMap, BTreeSet};

/// What a stream is trusted to say about one ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Answers "what is wrong with this package". Originates findings.
    Match,
    /// Answers "what more is known about this advisory". Adds to findings, never makes
    /// one.
    Enrich,
    /// Answers "is this package malware". Separate from `Match` and a higher bar,
    /// because known malware always blocks and has no exception: a stream holding this
    /// can trigger the one check an operator cannot write their way past.
    Malware,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Enrich => "enrich",
            Self::Malware => "malware",
        }
    }
}

/// A score, and which stream said so.
///
/// The source is kept for `explain`, not for the arithmetic: the merge rule below does
/// not consult it, so two streams reporting the same advisory cannot produce different
/// answers depending on which was read first.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub cvss: f64,
    pub source: String,
}

/// Something wrong with a package. Only a `match` stream can make one.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub advisory_id: String,
    pub score: Option<Score>,
    /// Which stream originated this.
    pub source: String,
    /// Whether the advisory is known to be exploited.
    ///
    /// Always `false` as originated: exploitation is what `enrich` streams know, and a
    /// `match` stream saying so would be claiming a capability it was not granted.
    exploited: bool,
}

impl Finding {
    pub fn new(source: &str, advisory_id: &str) -> Self {
        Self {
            advisory_id: advisory_id.to_owned(),
            score: None,
            source: source.to_owned(),
            exploited: false,
        }
    }

    pub fn with_score(mut self, cvss: f64) -> Self {
        self.score = Some(Score {
            cvss,
            source: self.source.clone(),
        });
        self
    }

    pub fn exploited(&self) -> bool {
        self.exploited
    }

    /// Apply everything known about this advisory from `enrich` streams.
    ///
    /// **Escalation only.** An enrichment may raise a score and may mark an advisory as
    /// exploited; it can do neither in reverse. That makes the result independent of the
    /// order enrichments arrive in, which is what the plan means by requiring the
    /// behaviour to be explicit rather than emergent: without it, two streams disagreeing
    /// would resolve to whichever was read last.
    pub fn enriched_by(mut self, enrichments: &[Enrichment]) -> Self {
        for e in enrichments.iter().filter(|e| e.advisory_id == self.advisory_id) {
            if let Some(score) = &e.score
                && self.score.as_ref().is_none_or(|held| score.cvss > held.cvss)
            {
                self.score = Some(score.clone());
            }
            if e.exploited {
                self.exploited = true;
            }
        }
        self
    }
}

/// What more is known about an advisory. Carries no package, and cannot become a
/// [`Finding`].
#[derive(Debug, Clone, PartialEq)]
pub struct Enrichment {
    pub advisory_id: String,
    pub score: Option<Score>,
    pub exploited: bool,
}

impl Enrichment {
    pub fn new(advisory_id: &str) -> Self {
        Self {
            advisory_id: advisory_id.to_owned(),
            score: None,
            exploited: false,
        }
    }

    pub fn with_score(mut self, source: &str, cvss: f64) -> Self {
        self.score = Some(Score {
            cvss,
            source: source.to_owned(),
        });
        self
    }

    /// What a KEV catalogue contributes: this advisory is being exploited.
    pub fn exploited(mut self) -> Self {
        self.exploited = true;
        self
    }
}

/// A stream that can say what is wrong with a package.
pub trait MatchStream {
    fn name(&self) -> &str;
    fn findings(&self, ecosystem: &str, name: &str, version: &str) -> Vec<Finding>;
}

/// A stream that can only add to what another stream found.
///
/// It is asked about an advisory, never about a package, so there is no package argument
/// to give it even if the return type allowed a finding.
pub trait EnrichStream {
    fn name(&self) -> &str;
    fn enrichments(&self, advisory_ids: &[String]) -> Vec<Enrichment>;
}

/// A stream that can say a package is malware.
///
/// Separate from [`MatchStream`] because the check it feeds has no exception. A stream
/// granted this can stop an install outright with nothing an operator can write to
/// override it.
pub trait MalwareStream {
    fn name(&self) -> &str;
    fn is_malware(&self, ecosystem: &str, name: &str, version: &str) -> bool;
}

/// What each stream is trusted to say, per ecosystem.
#[derive(Debug, Default)]
pub struct Capabilities {
    by_stream: BTreeMap<String, BTreeMap<String, BTreeSet<Capability>>>,
}

impl Capabilities {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(mut self, stream: &str, ecosystem: &str, granted: &[Capability]) -> Self {
        self.by_stream
            .entry(stream.to_owned())
            .or_default()
            .entry(ecosystem.to_owned())
            .or_default()
            .extend(granted.iter().copied());
        self
    }

    pub fn has(&self, stream: &str, ecosystem: &str, capability: Capability) -> bool {
        self.by_stream
            .get(stream)
            .and_then(|by_eco| by_eco.get(ecosystem))
            .is_some_and(|c| c.contains(&capability))
    }

    /// Streams granted a capability for an ecosystem.
    pub fn providers(&self, ecosystem: &str, capability: Capability) -> Vec<&str> {
        self.by_stream
            .iter()
            .filter(|(_, by_eco)| {
                by_eco
                    .get(ecosystem)
                    .is_some_and(|c| c.contains(&capability))
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Ecosystems this build serves with nothing able to originate a finding for them.
    ///
    /// An ecosystem proxied with no `match`-capable stream is a firewall that
    /// structurally cannot block anything. It is a startup warning and a `doctor` check
    /// rather than a startup failure, because a proxy that still verifies digests and
    /// records what went past is worth more than one that refuses to run.
    pub fn gaps(&self, enabled: &[&str]) -> Vec<Gap> {
        enabled
            .iter()
            .filter_map(|&ecosystem| {
                let missing: Vec<Capability> = [Capability::Match, Capability::Malware]
                    .into_iter()
                    .filter(|&c| self.providers(ecosystem, c).is_empty())
                    .collect();
                (!missing.is_empty()).then(|| Gap {
                    ecosystem: ecosystem.to_owned(),
                    missing,
                })
            })
            .collect()
    }
}

/// An ecosystem served with no stream able to say something about it.
#[derive(Debug, PartialEq)]
pub struct Gap {
    pub ecosystem: String,
    pub missing: Vec<Capability>,
}

impl std::fmt::Display for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let missing: Vec<&str> = self.missing.iter().map(|c| c.as_str()).collect();
        write!(
            f,
            "`{}` is served with no stream providing {}. Nothing can {}",
            self.ecosystem,
            missing.join(" or "),
            if self.missing.contains(&Capability::Match) {
                "originate a finding for it"
            } else {
                "report malware for it"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standing in for NVD or KEV: knows advisory ids, knows nothing about packages.
    struct Catalogue;

    impl EnrichStream for Catalogue {
        fn name(&self) -> &str {
            "kev"
        }

        fn enrichments(&self, advisory_ids: &[String]) -> Vec<Enrichment> {
            advisory_ids
                .iter()
                .filter(|id| id.as_str() == "CVE-2021-44228")
                .map(|id| Enrichment::new(id).exploited())
                .collect()
        }
    }

    #[test]
    fn an_enrich_stream_is_asked_about_advisories_and_never_about_a_package() {
        let ids = vec!["CVE-2021-44228".to_owned(), "CVE-2020-0001".to_owned()];
        let enrichments = Catalogue.enrichments(&ids);

        // The one thing it can say is about an advisory it was handed. There is no
        // package argument to give it, and no `Finding` in the return type.
        assert_eq!(enrichments.len(), 1);
        assert_eq!(enrichments[0].advisory_id, "CVE-2021-44228");
        assert!(enrichments[0].exploited);
        assert_eq!(Catalogue.name(), "kev");
    }

    #[test]
    fn a_finding_is_not_exploited_until_something_that_knows_says_so() {
        let finding = Finding::new("osv", "CVE-2021-44228");
        assert!(!finding.exploited());

        let enriched = finding.enriched_by(&Catalogue.enrichments(&["CVE-2021-44228".to_owned()]));
        assert!(enriched.exploited());
    }

    #[test]
    fn an_enrichment_raises_a_score_and_never_lowers_one() {
        let finding = Finding::new("osv", "CVE-1").with_score(5.0);

        let raised = finding
            .clone()
            .enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 9.8)]);
        assert_eq!(raised.score.as_ref().unwrap().cvss, 9.8);
        assert_eq!(raised.score.as_ref().unwrap().source, "nvd");

        let lowered = finding.enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 1.0)]);
        assert_eq!(lowered.score.as_ref().unwrap().cvss, 5.0);
        assert_eq!(lowered.score.as_ref().unwrap().source, "osv");
    }

    #[test]
    fn an_enrichment_supplies_a_score_the_matching_stream_did_not_have() {
        let finding =
            Finding::new("osv", "CVE-1").enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 4.2)]);

        assert_eq!(finding.score.as_ref().unwrap().cvss, 4.2);
        assert_eq!(finding.score.as_ref().unwrap().source, "nvd");
    }

    #[test]
    fn two_streams_disagreeing_settle_the_same_way_whichever_is_read_first() {
        let low = Enrichment::new("CVE-1").with_score("a", 3.0);
        let high = Enrichment::new("CVE-1").with_score("b", 9.0);

        let one_way = Finding::new("osv", "CVE-1").enriched_by(&[low.clone(), high.clone()]);
        let other_way = Finding::new("osv", "CVE-1").enriched_by(&[high, low]);

        assert_eq!(one_way, other_way);
        assert_eq!(one_way.score.unwrap().source, "b");
    }

    #[test]
    fn an_enrichment_for_a_different_advisory_is_not_applied() {
        let finding = Finding::new("osv", "CVE-1")
            .with_score(2.0)
            .enriched_by(&[Enrichment::new("CVE-2").with_score("nvd", 9.8).exploited()]);

        assert_eq!(finding.score.unwrap().cvss, 2.0);
        assert!(!finding.exploited);
    }

    #[test]
    fn an_ecosystem_a_stream_can_only_enrich_is_still_a_gap() {
        // NVD declared for npm, which it can only enrich. Nothing can originate a
        // finding, so the ecosystem is uncovered despite having a stream.
        let caps = Capabilities::new().grant("nvd", "npm", &[Capability::Enrich]);

        let gaps = caps.gaps(&["npm"]);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing, vec![Capability::Match, Capability::Malware]);
        assert!(caps.providers("npm", Capability::Match).is_empty());
        assert_eq!(caps.providers("npm", Capability::Enrich), vec!["nvd"]);
    }

    #[test]
    fn holding_a_capability_for_one_ecosystem_does_not_grant_it_for_another() {
        let caps = Capabilities::new().grant("nvd", "maven", &[Capability::Match, Capability::Enrich]);

        assert!(caps.has("nvd", "maven", Capability::Match));
        assert!(!caps.has("nvd", "npm", Capability::Match));
        assert!(!caps.has("osv", "maven", Capability::Match));
        assert_eq!(caps.gaps(&["maven"])[0].missing, vec![Capability::Malware]);
    }

    #[test]
    fn saying_what_is_wrong_with_a_package_does_not_carry_the_right_to_call_it_malware() {
        let caps = Capabilities::new().grant("ghsa", "npm", &[Capability::Match]);

        assert!(caps.has("ghsa", "npm", Capability::Match));
        assert!(!caps.has("ghsa", "npm", Capability::Malware));
        assert_eq!(caps.gaps(&["npm"])[0].missing, vec![Capability::Malware]);
    }

    #[test]
    fn an_ecosystem_with_both_a_matcher_and_a_malware_stream_has_no_gap() {
        let caps = Capabilities::new()
            .grant("osv", "npm", &[Capability::Match, Capability::Malware])
            .grant("nvd", "npm", &[Capability::Enrich]);

        assert!(caps.gaps(&["npm"]).is_empty());
    }

    #[test]
    fn an_ecosystem_served_with_no_stream_at_all_is_a_gap() {
        let caps = Capabilities::new().grant("osv", "npm", &[Capability::Match, Capability::Malware]);

        let gaps = caps.gaps(&["npm", "pypi"]);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].ecosystem, "pypi");
        assert_eq!(
            gaps[0].to_string(),
            "`pypi` is served with no stream providing match or malware. \
             Nothing can originate a finding for it"
        );
    }

    #[test]
    fn a_gap_in_malware_alone_says_so() {
        let caps = Capabilities::new().grant("ghsa", "npm", &[Capability::Match]);

        assert_eq!(
            caps.gaps(&["npm"])[0].to_string(),
            "`npm` is served with no stream providing malware. Nothing can report malware for it"
        );
    }

    #[test]
    fn granting_the_same_stream_twice_adds_rather_than_replaces() {
        let caps = Capabilities::new()
            .grant("osv", "npm", &[Capability::Match])
            .grant("osv", "npm", &[Capability::Malware]);

        assert!(caps.has("osv", "npm", Capability::Match));
        assert!(caps.has("osv", "npm", Capability::Malware));
    }

    #[test]
    fn every_capability_has_the_name_the_plan_gives_it() {
        assert_eq!(Capability::Match.as_str(), "match");
        assert_eq!(Capability::Enrich.as_str(), "enrich");
        assert_eq!(Capability::Malware.as_str(), "malware");
    }

    #[test]
    fn a_matcher_reports_what_it_found_and_says_who_it_was() {
        struct Osv;

        impl MatchStream for Osv {
            fn name(&self) -> &str {
                "osv"
            }

            fn findings(&self, ecosystem: &str, name: &str, _version: &str) -> Vec<Finding> {
                if ecosystem == "npm" && name == "left-pad" {
                    vec![Finding::new(self.name(), "GHSA-xxxx").with_score(7.5)]
                } else {
                    Vec::new()
                }
            }
        }

        assert_eq!(Osv.name(), "osv");
        assert!(Osv.findings("npm", "right-pad", "1.0.0").is_empty());

        let found = Osv.findings("npm", "left-pad", "1.0.0");
        assert_eq!(found[0].source, "osv");
        assert_eq!(found[0].score.as_ref().unwrap().source, "osv");
        assert!(!found[0].exploited());
    }

    #[test]
    fn a_malware_stream_answers_only_yes_or_no() {
        struct Mal;

        impl MalwareStream for Mal {
            fn name(&self) -> &str {
                "osv-malware"
            }

            fn is_malware(&self, ecosystem: &str, name: &str, _version: &str) -> bool {
                ecosystem == "npm" && name == "evil-pkg"
            }
        }

        assert_eq!(Mal.name(), "osv-malware");
        assert!(Mal.is_malware("npm", "evil-pkg", "1.0.0"));
        assert!(!Mal.is_malware("npm", "left-pad", "1.0.0"));
    }
}
