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

/// Where advisory signals come from: the intel store, named in `signal_weights` without it.
pub const ADVISORY: &str = "advisory";

/// One rule per kind of advisory, each with its default weight, most severe first.
pub const ADVISORY_WEIGHTS: [(&str, u32); 5] = [
    ("advisory_malware", 8),
    ("advisory_vulnerability", 4),
    ("advisory_unsound", 3),
    ("advisory_unmaintained", 2),
    ("advisory_notice", 1),
];

/// The rules of [`ADVISORY_WEIGHTS`], as `detector::KNOWN` lists rules.
pub const ADVISORY_RULES: [&str; 5] = {
    let mut out = [""; 5];
    let mut i = 0;
    while i < 5 {
        out[i] = ADVISORY_WEIGHTS[i].0;
        i += 1;
    }
    out
};

/// The weight a rule has when the policy does not set one.
pub fn default_weight(key: &str) -> u32 {
    ADVISORY_WEIGHTS
        .iter()
        .find(|(rule, _)| *rule == key)
        .map_or(crate::policy::DEFAULT_SIGNAL_WEIGHT, |(_, weight)| *weight)
}

/// The rule an advisory is a signal under: malware, a vulnerability, or RustSec's kind for
/// one that is neither. A kind RustSec adds is a notice.
fn advisory_rule(record: &crate::intel::store::Record) -> &'static str {
    let rule = match (record.malware, record.informational.as_deref()) {
        (true, _) => "advisory_malware",
        (false, None) => "advisory_vulnerability",
        (false, Some("unsound")) => "advisory_unsound",
        (false, Some("unmaintained")) => "advisory_unmaintained",
        (false, Some(_)) => "advisory_notice",
    };
    debug_assert!(ADVISORY_RULES.contains(&rule));
    rule
}

/// One signal per kind of advisory against the version, naming its advisories, in the
/// order of [`ADVISORY_WEIGHTS`].
pub fn of_advisories(records: &[&crate::intel::store::Record]) -> Vec<Signal> {
    ADVISORY_RULES
        .iter()
        .filter_map(|rule| {
            let mut ids: Vec<&str> = records
                .iter()
                .filter(|record| advisory_rule(record) == *rule)
                .map(|record| record.advisory_id.as_str())
                .collect();
            ids.sort_unstable();
            ids.dedup();
            (!ids.is_empty()).then(|| Signal {
                detector: ADVISORY.to_owned(),
                rule: (*rule).to_owned(),
                detail: ids.join(", "),
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

    fn advisory(
        id: &str,
        malware: bool,
        informational: Option<&str>,
    ) -> crate::intel::store::Record {
        crate::intel::store::Record {
            advisory_id: id.to_owned(),
            aliases: Vec::new(),
            source: "osv/cargo".to_owned(),
            cvss: None,
            cvss_source: None,
            band: None,
            exploited: false,
            malware,
            informational: informational.map(str::to_owned),
            cached: None,
        }
    }

    /// One signal per kind, naming each advisory once, most severe kind first.
    #[test]
    fn each_kind_of_advisory_is_a_signal_of_its_own() {
        let records = [
            advisory("RUSTSEC-3", false, Some("unmaintained")),
            advisory("GHSA-1", false, None),
            advisory("RUSTSEC-1", false, None),
            advisory("GHSA-1", false, None),
            advisory("MAL-1", true, None),
            advisory("RUSTSEC-4", false, Some("unsound")),
            advisory("RUSTSEC-5", false, Some("notice")),
            advisory("RUSTSEC-6", false, Some("a kind not yet written")),
        ];
        let found: Vec<String> = of_advisories(&records.iter().collect::<Vec<_>>())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            found,
            [
                "advisory malware: MAL-1",
                "advisory vulnerability: GHSA-1, RUSTSEC-1",
                "advisory unsound: RUSTSEC-4",
                "advisory unmaintained: RUSTSEC-3",
                "advisory notice: RUSTSEC-5, RUSTSEC-6",
            ]
        );
        assert!(of_advisories(&[]).is_empty());
    }

    /// The user asked for each kind to weigh differently; a policy can still set one.
    #[test]
    fn each_kind_has_its_own_default_weight_and_a_policy_can_set_it() {
        let defaults = SignalWeights::default();
        let weights: Vec<u32> = ADVISORY_RULES
            .iter()
            .map(|rule| defaults.of(rule))
            .collect();
        assert_eq!(weights, [8, 4, 3, 2, 1]);
        assert_eq!(
            defaults.of("new_package"),
            crate::policy::DEFAULT_SIGNAL_WEIGHT
        );
        let set = SignalWeights::of_pairs(&[("advisory_unmaintained", 0)]);
        assert_eq!(set.of("advisory_unmaintained"), 0);
        let records = [
            advisory("RUSTSEC-3", false, Some("unmaintained")),
            advisory("MAL-1", true, None),
        ];
        assert_eq!(
            score(
                &of_advisories(&records.iter().collect::<Vec<_>>()),
                &defaults
            ),
            10
        );
    }
}
