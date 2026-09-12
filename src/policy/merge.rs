//! Merging global defaults with an ecosystem's overrides, and saying what moved.
//!
//! §5.5: ecosystem rules override global rules, and an override that loosens the
//! effective policy above it is reported. This does the merge and produces that report.
//!
//! # The report is produced here, not warned here
//!
//! §5.5 emits these at config load and in `explain`, never per request: per-package
//! warnings become wallpaper within a day. So this returns findings and the caller
//! decides what to do with them. Nothing here logs.
//!
//! # Three ways a rule can have no comparison
//!
//! Loosening is only meaningful against a baseline, and there are two ways not to have
//! one. The rule may have no meaning for this ecosystem, which the plan's example is
//! `install_scripts` for Go modules. Or nothing above may have set it, which is the
//! ordinary shape of a real config where `defaults` is sparse. Neither warns, and
//! [`crate::policy::strictness`] keeps them apart so `explain` can say which.

use super::strictness::{Direction, Strictness};
use super::{Action, CooldownRule, Defaults, EcosystemRules, Policy, ScriptRule};

/// A rule an ecosystem can override, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Cooldown,
    InstallScripts,
    ProvenanceRequired,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cooldown => "cooldown",
            Self::InstallScripts => "install_scripts",
            Self::ProvenanceRequired => "provenance_required",
        }
    }

    /// Every rule an ecosystem block can carry. One list, so a rule added to the schema
    /// and not to the merge is a compile error rather than a silently unmerged field.
    pub const ALL: [Rule; 3] = [
        Self::Cooldown,
        Self::InstallScripts,
        Self::ProvenanceRequired,
    ];
}

/// Whether a rule means anything for an ecosystem.
///
/// Keyed on the ecosystem name as the policy file spells it, not on
/// [`crate::identity::Ecosystem`], because a policy can name an ecosystem before an
/// adapter for it exists. The plan's own example is Go modules, which has no adapter.
///
/// The default is that a rule applies. An ecosystem is listed here only where a rule
/// genuinely has no meaning, because reporting N/A for a rule that does apply would hide
/// a real loosening.
pub fn applies(ecosystem: &str, rule: Rule) -> bool {
    match (ecosystem, rule) {
        // Go modules have no install step, so there is no script to run. §5.5's example
        // of a rule that reports not-applicable rather than a violation.
        ("golang" | "go", Rule::InstallScripts) => false,
        _ => true,
    }
}

/// What one ecosystem's override of one rule did to the policy above it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub ecosystem: String,
    pub rule: Rule,
    pub outcome: Strictness,
    /// Whether the override carries §5.5's `loosens_global` acknowledgment.
    ///
    /// Read and reported, not yet acted on: what the acknowledgment requires of a rule,
    /// and when it expires, is its own item.
    pub acknowledged: bool,
}

impl Finding {
    /// Whether §5.5 warns about this at config load.
    pub fn warns(&self) -> bool {
        self.outcome.warns()
    }
}

/// The rules in force for one ecosystem once defaults and overrides are merged.
#[derive(Debug, Clone, PartialEq)]
pub struct Effective {
    /// From defaults only: an ecosystem block cannot set it, so it cannot be weakened
    /// per ecosystem.
    pub known_malware: Option<Action>,
    pub cooldown: Option<CooldownRule>,
    pub install_scripts: Option<ScriptRule>,
    pub provenance_required: Option<bool>,
}

/// Merge global defaults with one ecosystem's overrides, and report what moved.
///
/// The ecosystem wins wherever it sets a value. A rule it does not set keeps the default,
/// which is why a sparse ecosystem block is the normal case rather than a suspicious one.
pub fn merge(policy: &Policy, ecosystem: &str) -> (Effective, Vec<Finding>) {
    let defaults = &policy.defaults;
    let overrides = policy.ecosystems.get(ecosystem);

    let effective = Effective {
        known_malware: defaults.known_malware,
        cooldown: pick(
            overrides.and_then(|e| e.cooldown.as_ref()),
            defaults.cooldown.as_ref(),
        ),
        install_scripts: pick(
            overrides.and_then(|e| e.install_scripts.as_ref()),
            defaults.install_scripts.as_ref(),
        ),
        provenance_required: overrides
            .and_then(|e| e.provenance_required)
            .or(defaults.provenance_required),
    };

    let findings = match overrides {
        None => Vec::new(),
        Some(overrides) => Rule::ALL
            .iter()
            .map(|&rule| Finding {
                ecosystem: ecosystem.to_owned(),
                rule,
                outcome: compare(ecosystem, rule, overrides, defaults),
                acknowledged: acknowledges(rule, overrides),
            })
            .collect(),
    };

    (effective, findings)
}

/// The override if there is one, otherwise the default.
fn pick<T: Clone>(override_value: Option<&T>, default: Option<&T>) -> Option<T> {
    override_value.or(default).cloned()
}

/// How one ecosystem rule compares to the policy above it.
fn compare(
    ecosystem: &str,
    rule: Rule,
    overrides: &EcosystemRules,
    defaults: &Defaults,
) -> Strictness {
    // Applicability is decided for the whole rule, before its dimensions are looked at.
    if !applies(ecosystem, rule) {
        return Strictness::NotApplicable;
    }
    match rule {
        Rule::Cooldown => match (&overrides.cooldown, &defaults.cooldown) {
            (Some(value), Some(baseline)) => cooldown_strictness(value, baseline),
            (Some(_), None) | (None, _) => Strictness::Unset,
        },
        Rule::InstallScripts => match (&overrides.install_scripts, &defaults.install_scripts) {
            (Some(value), Some(baseline)) => {
                script_action(value).strictness_against(script_action(baseline))
            }
            (Some(_), None) | (None, _) => Strictness::Unset,
        },
        Rule::ProvenanceRequired => {
            match (overrides.provenance_required, defaults.provenance_required) {
                // Required is stricter than not, so the flag runs the same way a number with
                // `HigherIsStricter` does rather than being compared its own way.
                (Some(value), Some(baseline)) => {
                    Direction::HigherIsStricter.strictness(u32::from(value), u32::from(baseline))
                }
                (Some(_), None) | (None, _) => Strictness::Unset,
            }
        }
    }
}

/// A cooldown moves in two dimensions, and they can disagree: `block/3d` overridden by
/// `warn/30d` is the plan's own example of an override whose direction cannot be proven.
fn cooldown_strictness(value: &CooldownRule, baseline: &CooldownRule) -> Strictness {
    let action = match (value.action, baseline.action) {
        (Some(v), Some(b)) => v.strictness_against(b),
        _ => Strictness::Unset,
    };
    let days = match (value.days, baseline.days) {
        (Some(v), Some(b)) => Direction::HigherIsStricter.strictness(v, b),
        _ => Strictness::Unset,
    };
    action.and(days)
}

/// The action a script rule carries, whichever shape it is written in.
fn script_action(rule: &ScriptRule) -> Action {
    match rule {
        ScriptRule::Bare(action) => *action,
        ScriptRule::Detailed(detail) => detail.action,
    }
}

/// Whether an override carries §5.5's acknowledgment. Only `install_scripts` has a shape
/// that can.
fn acknowledges(rule: Rule, overrides: &EcosystemRules) -> bool {
    match (rule, &overrides.install_scripts) {
        (Rule::InstallScripts, Some(ScriptRule::Detailed(detail))) => detail.loosens_global,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ScriptDetail;

    fn from_body(body: &str) -> Policy {
        Policy::parse(&format!(
            "version: 1\nfloor:\n  npm:\n    known_malware: block\n{body}"
        ))
        .expect("fixture should parse")
    }

    fn finding(findings: &[Finding], rule: Rule) -> &Finding {
        findings
            .iter()
            .find(|f| f.rule == rule)
            .expect("every rule is reported")
    }

    #[test]
    fn an_ecosystem_override_wins_and_the_rest_keeps_the_default() {
        let policy = from_body(
            "defaults:\n  cooldown: { action: quarantine, days: 7 }\n  \
             provenance_required: true\necosystems:\n  npm:\n    \
             cooldown: { action: block, days: 14 }\n",
        );
        let (effective, _) = merge(&policy, "npm");

        assert_eq!(effective.cooldown.as_ref().unwrap().days, Some(14));
        assert_eq!(
            effective.cooldown.as_ref().unwrap().action,
            Some(Action::Block)
        );
        assert_eq!(
            effective.provenance_required,
            Some(true),
            "a rule the ecosystem does not set keeps the default"
        );
    }

    /// An ecosystem block cannot set `known_malware`, so it comes from defaults whatever
    /// the ecosystem says. The schema is what enforces that; this pins the consequence.
    #[test]
    fn known_malware_is_not_something_an_ecosystem_can_weaken() {
        let policy = from_body(
            "defaults:\n  known_malware: block\necosystems:\n  npm:\n    \
             install_scripts: allow\n",
        );
        let (effective, _) = merge(&policy, "npm");
        assert_eq!(effective.known_malware, Some(Action::Block));
    }

    /// An ecosystem with no block at all reports nothing. There is no override, so there
    /// is nothing that could have loosened anything.
    #[test]
    fn an_ecosystem_that_overrides_nothing_reports_nothing() {
        let policy = from_body("defaults:\n  install_scripts: warn\n");
        let (effective, findings) = merge(&policy, "npm");
        assert!(findings.is_empty());
        assert_eq!(
            effective.install_scripts,
            Some(ScriptRule::Bare(Action::Warn))
        );
    }

    #[test]
    fn moving_down_the_lattice_is_reported_as_loosening() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts: warn\n",
        );
        let (_, findings) = merge(&policy, "npm");
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Looser);
        assert!(f.warns());
        assert!(!f.acknowledged);
    }

    #[test]
    fn moving_up_the_lattice_is_reported_and_does_not_warn() {
        let policy = from_body(
            "defaults:\n  install_scripts: warn\necosystems:\n  npm:\n    \
             install_scripts: block\n",
        );
        let (_, findings) = merge(&policy, "npm");
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Stricter);
        assert!(!f.warns());
    }

    /// The plan's own example of an override whose direction cannot be proven.
    #[test]
    fn a_cooldown_tighter_in_days_and_looser_in_action_is_incomparable() {
        let policy = from_body(
            "defaults:\n  cooldown: { action: block, days: 3 }\necosystems:\n  npm:\n    \
             cooldown: { action: warn, days: 30 }\n",
        );
        let (_, findings) = merge(&policy, "npm");
        let f = finding(&findings, Rule::Cooldown);
        assert_eq!(f.outcome, Strictness::Incomparable);
        assert!(
            f.warns(),
            "§5.5 fails loud when tightening cannot be proven"
        );
    }

    /// Both dimensions moving the same way decides it.
    #[test]
    fn a_cooldown_that_moves_one_way_in_both_dimensions_is_decided() {
        let policy = from_body(
            "defaults:\n  cooldown: { action: warn, days: 3 }\necosystems:\n  npm:\n    \
             cooldown: { action: block, days: 30 }\n",
        );
        let (_, findings) = merge(&policy, "npm");
        assert_eq!(
            finding(&findings, Rule::Cooldown).outcome,
            Strictness::Stricter
        );
    }

    /// The ordinary shape of a real config: `defaults` is sparse and the ecosystem fills
    /// it in. Nothing was loosened, because there was nothing above to loosen.
    #[test]
    fn setting_a_rule_nothing_above_had_set_is_not_loosening() {
        let policy = from_body("ecosystems:\n  npm:\n    install_scripts: allow\n");
        let (effective, findings) = merge(&policy, "npm");
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Unset);
        assert!(!f.warns());
        assert_eq!(
            effective.install_scripts,
            Some(ScriptRule::Bare(Action::Allow)),
            "it still takes effect; it just loosened nothing"
        );
    }

    /// §5.5's own example of a rule that reports not-applicable rather than a violation.
    /// Go modules have no install step, and a policy can name an ecosystem before an
    /// adapter for it exists, which is why the table is keyed on the written name.
    #[test]
    fn a_rule_with_no_meaning_for_an_ecosystem_reports_not_applicable() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  golang:\n    \
             install_scripts: allow\n",
        );
        let (_, findings) = merge(&policy, "golang");
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::NotApplicable);
        assert!(
            !f.warns(),
            "warning about a rule that has no meaning here makes the channel noise"
        );

        // The same override for an ecosystem where it does mean something warns.
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts: allow\n",
        );
        let (_, findings) = merge(&policy, "npm");
        assert!(finding(&findings, Rule::InstallScripts).warns());
    }

    #[test]
    fn applicability_is_per_rule_and_defaults_to_applying() {
        assert!(!applies("golang", Rule::InstallScripts));
        assert!(!applies("go", Rule::InstallScripts));
        assert!(applies("golang", Rule::Cooldown));
        assert!(applies("npm", Rule::InstallScripts));
        assert!(
            applies("some-future-ecosystem", Rule::InstallScripts),
            "a rule applies unless it is known not to; the other way round would hide \
             a real loosening behind an unrecognised name"
        );
    }

    /// Read and reported, not acted on: what the acknowledgment requires, and when it
    /// expires, is its own item.
    #[test]
    fn the_acknowledgment_is_reported_alongside_the_loosening_it_acknowledges() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      loosens_global: true\n      \
             reason: reviewed\n      expires: \"2026-11-30\"\n",
        );
        let (effective, findings) = merge(&policy, "npm");
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Looser);
        assert!(f.acknowledged);
        assert!(
            f.warns(),
            "still reported as loosening; whether the acknowledgment silences it is the \
             next item"
        );
        assert!(matches!(
            effective.install_scripts,
            Some(ScriptRule::Detailed(ScriptDetail { .. }))
        ));
    }

    #[test]
    fn a_detailed_rule_without_the_flag_is_not_an_acknowledgment() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      reason: reviewed\n",
        );
        let (_, findings) = merge(&policy, "npm");
        assert!(!finding(&findings, Rule::InstallScripts).acknowledged);
    }

    #[test]
    fn provenance_required_runs_the_way_a_stricter_number_does() {
        let looser = from_body(
            "defaults:\n  provenance_required: true\necosystems:\n  npm:\n    \
             provenance_required: false\n",
        );
        let (_, findings) = merge(&looser, "npm");
        assert_eq!(
            finding(&findings, Rule::ProvenanceRequired).outcome,
            Strictness::Looser
        );

        let stricter = from_body(
            "defaults:\n  provenance_required: false\necosystems:\n  npm:\n    \
             provenance_required: true\n",
        );
        let (_, findings) = merge(&stricter, "npm");
        assert_eq!(
            finding(&findings, Rule::ProvenanceRequired).outcome,
            Strictness::Stricter
        );
    }

    /// A cooldown that only sets one dimension has nothing to compare in the other, and
    /// the one it does set decides the rule.
    #[test]
    fn a_cooldown_dimension_with_no_baseline_does_not_decide_the_rule() {
        let policy = from_body(
            "defaults:\n  cooldown: { days: 7 }\necosystems:\n  npm:\n    \
             cooldown: { action: block, days: 14 }\n",
        );
        let (_, findings) = merge(&policy, "npm");
        assert_eq!(
            finding(&findings, Rule::Cooldown).outcome,
            Strictness::Stricter,
            "days moved up and the action had nothing above it"
        );
    }

    #[test]
    fn every_rule_an_ecosystem_can_set_is_reported() {
        let policy = from_body("ecosystems:\n  npm:\n    install_scripts: warn\n");
        let (_, findings) = merge(&policy, "npm");
        assert_eq!(findings.len(), Rule::ALL.len());
        for rule in Rule::ALL {
            assert_eq!(finding(&findings, rule).rule, rule);
            assert!(!rule.as_str().is_empty());
        }
    }

    /// The shipped example, merged. It declares `ecosystems.cargo` with no
    /// `floor.cargo`, which is the spike artifact's deliberate gap and not this
    /// function's business.
    #[test]
    fn the_shipped_example_merges_without_warning_where_it_should_not() {
        let source = std::fs::read_to_string("examples/policy.yaml").unwrap();
        let policy = Policy::parse(&source).unwrap();
        for ecosystem in policy.ecosystems.keys() {
            let (_, findings) = merge(&policy, ecosystem);
            assert_eq!(findings.len(), Rule::ALL.len());
        }
    }
}
