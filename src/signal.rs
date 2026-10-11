//! Signals about a package version: each rule a detector fired, reported in the log, the
//! audit line and `explain`, and never refused on. Their weights sum to the risk score.
//!
//! See docs/engineering_decisions/detectors.md.

use crate::analysis::detector::{self, Detection};
use crate::policy::SignalWeights;

/// One rule a detector fired on a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub detector: String,
    pub rule: String,
    /// What the rule found, which a detector built in prints and another does not.
    pub detail: String,
}

impl Signal {
    /// The name `signal_weights` weighs it under: see [`detector::key`].
    pub fn key(&self) -> String {
        detector::key(&self.detector, &self.rule)
    }

    /// What it weighs under `weights`.
    pub fn weight(&self, weights: &SignalWeights) -> u32 {
        weights.of(&self.key())
    }
}

/// A version's risk score: the weight `weights` gives each rule present, summed, each rule
/// once however often it fires.
pub fn score(signals: &[Signal], weights: &SignalWeights) -> u32 {
    let mut seen = std::collections::BTreeSet::new();
    signals
        .iter()
        .filter(|signal| seen.insert(signal.key()))
        .map(|signal| signal.weight(weights))
        .sum()
}

/// The signals `detections`, each a detector's name and what it found, give: one per rule
/// that fired, in their order.
pub fn of_detections(detections: &[(String, Detection)]) -> Vec<Signal> {
    detections
        .iter()
        .flat_map(|(detector, detection)| {
            detection.findings.iter().map(|finding| Signal {
                detector: detector.clone(),
                rule: finding.rule.clone(),
                detail: finding.detail.clone(),
            })
        })
        .collect()
}

/// A rule built in as `rule in words: detail`, another detector's as `detector: rule`.
impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if detector::BUILT_IN.contains(&self.detector.as_str()) {
            write!(f, "{}: {}", self.rule.replace('_', " "), self.detail)
        } else {
            write!(f, "{}: {}", self.detector, self.rule)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::detector::Finding;

    fn signal(detector: &str, rule: &str, detail: &str) -> Signal {
        Signal {
            detector: detector.to_owned(),
            rule: rule.to_owned(),
            detail: detail.to_owned(),
        }
    }

    #[test]
    fn each_signal_says_what_it_found() {
        for (signal, text) in [
            (
                signal("metadata", "new_package", "first published 2 days ago"),
                "new package: first published 2 days ago",
            ),
            (
                signal("source", "source_dependencies", "o/r@v1 lacks: a"),
                "source dependencies: o/r@v1 lacks: a",
            ),
            (
                signal("guarddog", "bundled_binary", "a long message"),
                "guarddog: bundled_binary",
            ),
        ] {
            assert_eq!(signal.to_string(), text);
        }
    }

    /// A rule counts once however often it fires, and each rule adds its own weight.
    #[test]
    fn the_risk_score_sums_the_weight_of_each_rule_present() {
        let weights = SignalWeights::of_pairs(&[("near_name", 4), ("source_differing", 2)]);
        let near = |served: &str| signal("metadata", "near_name", served);
        let differing = signal("source", "source_differing", "2 files");
        let none = signal("metadata", "no_repository", "the metadata names none");
        assert_eq!(score(&[], &weights), 0);
        assert_eq!(score(&[near("a"), near("b")], &weights), 4);
        assert_eq!(score(&[near("a"), differing, none], &weights), 7);
    }

    /// Each rule a detector fired is a signal, weighed by its own `detector.rule` weight,
    /// once however many detections repeat it.
    #[test]
    fn a_detector_rule_is_a_signal_with_its_own_weight() {
        let fired = |rules: &[&str]| Detection {
            findings: rules
                .iter()
                .map(|rule| Finding {
                    rule: (*rule).to_owned(),
                    detail: String::new(),
                })
                .collect(),
            errors: vec![Finding {
                rule: "e".to_owned(),
                detail: "no dns".to_owned(),
            }],
        };
        let detected = [
            (
                "guarddog".to_owned(),
                fired(&["threat-process-hooks", "bundled_binary"]),
            ),
            ("guarddog".to_owned(), fired(&["bundled_binary"])),
            ("metadata".to_owned(), fired(&["no_repository"])),
        ];
        let signals = of_detections(&detected);
        assert_eq!(
            signals.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "guarddog: threat-process-hooks",
                "guarddog: bundled_binary",
                "guarddog: bundled_binary",
                "no repository: ",
            ]
        );
        assert_eq!(signals[0].key(), "guarddog.threat-process-hooks");
        assert_eq!(signals[3].key(), "no_repository");
        let weights = SignalWeights::of_pairs(&[("guarddog.threat-process-hooks", 4)]);
        assert_eq!(signals[0].weight(&weights), 4);
        assert_eq!(
            score(&signals, &weights),
            6,
            "4, then bundled_binary and no_repository once each at 1"
        );
    }
}
