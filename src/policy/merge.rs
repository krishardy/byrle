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
use super::{Action, CooldownRule, Defaults, EcosystemRules, ExpiryDate, Policy, ScriptRule};
use jiff::civil::Date;

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

/// Someone answered for a loosening, and said when the answer runs out.
///
/// The reason and the expiry are required by the schema, so an acknowledgment that
/// records neither cannot be loaded: see `Policy::check_acknowledgments`.
#[derive(Debug, Clone, PartialEq)]
pub struct Acknowledgment {
    pub reason: String,
    pub expires: ExpiryDate,
    /// Whether it has run out by the date the policy was read against.
    ///
    /// An expired acknowledgment warns again. §5.5 gives it an expiry precisely so that
    /// the exemption has to be looked at again rather than becoming permanent by being
    /// forgotten.
    pub expired: bool,
}

/// What one ecosystem's override of one rule did to the policy above it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub ecosystem: String,
    pub rule: Rule,
    pub outcome: Strictness,
    /// §5.5's `loosens_global` acknowledgment, when the override carries one.
    pub acknowledgment: Option<Acknowledgment>,
}

impl Finding {
    /// Whether §5.5 warns about this at config load.
    ///
    /// A loosening someone has answered for and not yet let lapse does not warn; it goes
    /// to the audit trail and passes `--strict`. Everything else that loosened, or whose
    /// direction could not be proven, warns.
    pub fn warns(&self) -> bool {
        if !self.outcome.warns() {
            return false;
        }
        match &self.acknowledgment {
            Some(ack) => ack.expired,
            None => true,
        }
    }

    /// Whether this belongs in the audit trail: a loosening that was acknowledged rather
    /// than warned about is exactly what there has to be a record of.
    pub fn audited(&self) -> bool {
        self.outcome.warns() && self.acknowledgment.is_some()
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
/// `as_of` is the date acknowledgments are judged against, taken as an argument rather
/// than read from the clock. `policy diff --as-of` needs to ask what a policy says on
/// another day, and a function that called `now()` could not answer.
pub fn merge(policy: &Policy, ecosystem: &str, as_of: Date) -> (Effective, Vec<Finding>) {
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
                acknowledgment: acknowledgment(rule, overrides, as_of),
            })
            .collect(),
    };

    (effective, findings)
}

/// The override if there is one, otherwise the default.
///
/// Whole values, never combined. §5.5 requires that a list-valued rule **replaces**
/// rather than unions, and taking one side or the other is what makes that true by
/// construction rather than by remembering. No rule in the schema is list-valued yet, so
/// there is nothing here that could union; when one is added it gets this for free, and
/// writing a merge that unions would mean not using this function.
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

/// §5.5's acknowledgment, when an override carries one. Only `install_scripts` has a
/// shape that can.
///
/// The reason and expiry are unwrapped rather than matched: a `loosens_global` without
/// both is refused at load, so an acknowledgment that reached here has them.
fn acknowledgment(rule: Rule, overrides: &EcosystemRules, as_of: Date) -> Option<Acknowledgment> {
    let (Rule::InstallScripts, Some(ScriptRule::Detailed(detail))) =
        (rule, &overrides.install_scripts)
    else {
        return None;
    };
    if !detail.loosens_global {
        return None;
    }
    let reason = detail
        .reason
        .clone()
        .expect("an acknowledgment without a reason is refused at load");
    let expires = detail
        .expires
        .expect("an acknowledgment without an expiry is refused at load");
    Some(Acknowledgment {
        reason,
        expires,
        expired: expires.has_passed(as_of),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ScriptDetail;
    use jiff::civil::date;

    /// A fixed day, so nothing here depends on when it is run.
    const TODAY: Date = date(2026, 9, 12);

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
        let (effective, _) = merge(&policy, "npm", TODAY);

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
        let (effective, _) = merge(&policy, "npm", TODAY);
        assert_eq!(effective.known_malware, Some(Action::Block));
    }

    /// An ecosystem with no block at all reports nothing. There is no override, so there
    /// is nothing that could have loosened anything.
    #[test]
    fn an_ecosystem_that_overrides_nothing_reports_nothing() {
        let policy = from_body("defaults:\n  install_scripts: warn\n");
        let (effective, findings) = merge(&policy, "npm", TODAY);
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
        let (_, findings) = merge(&policy, "npm", TODAY);
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Looser);
        assert!(f.warns());
        assert!(f.acknowledgment.is_none());
    }

    #[test]
    fn moving_up_the_lattice_is_reported_and_does_not_warn() {
        let policy = from_body(
            "defaults:\n  install_scripts: warn\necosystems:\n  npm:\n    \
             install_scripts: block\n",
        );
        let (_, findings) = merge(&policy, "npm", TODAY);
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
        let (_, findings) = merge(&policy, "npm", TODAY);
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
        let (_, findings) = merge(&policy, "npm", TODAY);
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
        let (effective, findings) = merge(&policy, "npm", TODAY);
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
        let (_, findings) = merge(&policy, "golang", TODAY);
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
        let (_, findings) = merge(&policy, "npm", TODAY);
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

    /// §5.5: an acknowledged loosening logs to the audit trail and passes `--strict`.
    /// Someone answered for it and said when the answer runs out.
    #[test]
    fn a_loosening_someone_answered_for_does_not_warn() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      loosens_global: true\n      \
             reason: reviewed\n      expires: \"2026-11-30\"\n",
        );
        let (effective, findings) = merge(&policy, "npm", TODAY);
        let f = finding(&findings, Rule::InstallScripts);

        assert_eq!(f.outcome, Strictness::Looser, "it is still a loosening");
        assert!(!f.warns(), "answered for, so it does not warn");
        assert!(
            f.audited(),
            "and that is exactly what there has to be a record of"
        );

        let ack = f.acknowledgment.as_ref().unwrap();
        assert_eq!(ack.reason, "reviewed");
        assert!(!ack.expired);
        assert!(matches!(
            effective.install_scripts,
            Some(ScriptRule::Detailed(ScriptDetail { .. }))
        ));
    }

    /// §5.5 gives an acknowledgment an expiry precisely so the exemption has to be looked
    /// at again rather than becoming permanent by being forgotten.
    #[test]
    fn an_acknowledgment_that_has_run_out_warns_again() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      loosens_global: true\n      \
             reason: reviewed\n      expires: \"2026-08-01\"\n",
        );
        let (_, findings) = merge(&policy, "npm", TODAY);
        let f = finding(&findings, Rule::InstallScripts);

        assert!(f.acknowledgment.as_ref().unwrap().expired);
        assert!(f.warns());
        assert!(f.audited(), "an expired exemption is still worth a record");
    }

    /// The expiry date is the last day it is in force, so a policy does not lapse on the
    /// morning of the day an operator wrote down.
    #[test]
    fn an_acknowledgment_is_in_force_on_the_day_it_names() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      loosens_global: true\n      \
             reason: reviewed\n      expires: \"2026-09-12\"\n",
        );
        let (_, today) = merge(&policy, "npm", TODAY);
        assert!(!finding(&today, Rule::InstallScripts).warns());

        let (_, tomorrow) = merge(&policy, "npm", date(2026, 9, 13));
        assert!(finding(&tomorrow, Rule::InstallScripts).warns());
    }

    /// The date is an argument, not the clock, because `policy diff --as-of` has to be
    /// able to ask what a policy says on another day.
    #[test]
    fn the_same_policy_reads_differently_on_different_days() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      loosens_global: true\n      \
             reason: reviewed\n      expires: \"2026-10-15\"\n",
        );
        for (day, expected) in [
            (date(2026, 1, 1), false),
            (date(2026, 10, 15), false),
            (date(2026, 10, 16), true),
            (date(2030, 1, 1), true),
        ] {
            let (_, findings) = merge(&policy, "npm", day);
            assert_eq!(
                finding(&findings, Rule::InstallScripts).warns(),
                expected,
                "on {day}"
            );
        }
    }

    /// An acknowledgment on something that did not loosen anything is not a warning
    /// waiting to happen, so it is not audited either.
    #[test]
    fn an_acknowledgment_on_a_tightening_has_nothing_to_record() {
        let policy = from_body(
            "defaults:\n  install_scripts: warn\necosystems:\n  npm:\n    \
             install_scripts:\n      action: block\n      loosens_global: true\n      \
             reason: belt and braces\n      expires: \"2026-11-30\"\n",
        );
        let (_, findings) = merge(&policy, "npm", TODAY);
        let f = finding(&findings, Rule::InstallScripts);
        assert_eq!(f.outcome, Strictness::Stricter);
        assert!(!f.warns());
        assert!(!f.audited());
    }

    #[test]
    fn a_detailed_rule_without_the_flag_is_not_an_acknowledgment() {
        let policy = from_body(
            "defaults:\n  install_scripts: block\necosystems:\n  npm:\n    \
             install_scripts:\n      action: allow\n      reason: reviewed\n",
        );
        let (_, findings) = merge(&policy, "npm", TODAY);
        assert!(
            finding(&findings, Rule::InstallScripts)
                .acknowledgment
                .is_none()
        );
    }

    #[test]
    fn provenance_required_runs_the_way_a_stricter_number_does() {
        let looser = from_body(
            "defaults:\n  provenance_required: true\necosystems:\n  npm:\n    \
             provenance_required: false\n",
        );
        let (_, findings) = merge(&looser, "npm", TODAY);
        assert_eq!(
            finding(&findings, Rule::ProvenanceRequired).outcome,
            Strictness::Looser
        );

        let stricter = from_body(
            "defaults:\n  provenance_required: false\necosystems:\n  npm:\n    \
             provenance_required: true\n",
        );
        let (_, findings) = merge(&stricter, "npm", TODAY);
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
        let (_, findings) = merge(&policy, "npm", TODAY);
        assert_eq!(
            finding(&findings, Rule::Cooldown).outcome,
            Strictness::Stricter,
            "days moved up and the action had nothing above it"
        );
    }

    #[test]
    fn every_rule_an_ecosystem_can_set_is_reported() {
        let policy = from_body("ecosystems:\n  npm:\n    install_scripts: warn\n");
        let (_, findings) = merge(&policy, "npm", TODAY);
        assert_eq!(findings.len(), Rule::ALL.len());
        for rule in Rule::ALL {
            assert_eq!(finding(&findings, rule).rule, rule);
            assert!(!rule.as_str().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Golden files. See tests/fixtures/policy/README.md.
    // -----------------------------------------------------------------------

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/policy"
        ))
    }

    /// Render a whole merge as text: what is in force, and what every override did.
    ///
    /// Written out rather than derived, because the file is read by a person reviewing a
    /// diff. A `{:?}` dump would change shape whenever a field is added and tell them
    /// nothing about what moved.
    fn render(policy: &Policy) -> String {
        let mut out = String::new();
        // npm is always rendered, declared or not, so a file that never mentions it
        // still shows what an ecosystem nobody customised ends up with. That is the
        // common case in a real deployment and it would otherwise appear in no golden
        // file at all.
        let mut names: Vec<&str> = policy.ecosystems.keys().map(String::as_str).collect();
        if !names.contains(&"npm") {
            names.push("npm");
            names.sort_unstable();
        }
        for ecosystem in names {
            let (effective, findings) = merge(policy, ecosystem, TODAY);
            out.push_str(&format!("== {ecosystem}\n"));
            out.push_str("-- in force\n");
            out.push_str(&format!(
                "   known_malware       {}\n",
                show_action(effective.known_malware)
            ));
            out.push_str(&format!(
                "   cooldown            {}\n",
                show_cooldown(effective.cooldown.as_ref())
            ));
            out.push_str(&format!(
                "   install_scripts     {}\n",
                show_script(effective.install_scripts.as_ref())
            ));
            out.push_str(&format!(
                "   provenance_required {}\n",
                effective
                    .provenance_required
                    .map_or_else(|| "-".to_owned(), |v| v.to_string())
            ));
            if findings.is_empty() {
                out.push_str("-- overrides\n   (none: this ecosystem has no block)\n");
            } else {
                out.push_str("-- overrides\n");
                for f in &findings {
                    let line = format!(
                        "   {:<19} {:<13} {:<6} {:<7} {}",
                        f.rule.as_str(),
                        format!("{:?}", f.outcome),
                        if f.warns() { "warns" } else { "-" },
                        if f.audited() { "audited" } else { "-" },
                        show_ack(f.acknowledgment.as_ref()),
                    );
                    // Trimmed: these files are read in a diff, and trailing spaces show
                    // up there as changes nobody made.
                    out.push_str(line.trim_end());
                    out.push('\n');
                }
            }
            out.push('\n');
        }
        out
    }

    fn show_action(action: Option<Action>) -> String {
        action.map_or_else(|| "-".to_owned(), |a| format!("{a:?}").to_lowercase())
    }

    fn show_cooldown(rule: Option<&CooldownRule>) -> String {
        rule.map_or_else(
            || "-".to_owned(),
            |c| {
                format!(
                    "action={} days={}",
                    show_action(c.action),
                    c.days.map_or_else(|| "-".to_owned(), |d| d.to_string())
                )
            },
        )
    }

    fn show_script(rule: Option<&ScriptRule>) -> String {
        match rule {
            None => "-".to_owned(),
            Some(ScriptRule::Bare(a)) => show_action(Some(*a)),
            Some(ScriptRule::Detailed(d)) => {
                format!("{} (table)", show_action(Some(d.action)))
            }
        }
    }

    fn show_ack(ack: Option<&Acknowledgment>) -> String {
        match ack {
            None => String::new(),
            Some(a) => format!(
                "ack until {}{}: {}",
                a.expires,
                if a.expired { " (expired)" } else { "" },
                a.reason
            ),
        }
    }

    /// Every policy in `tests/fixtures/policy` merges to the report beside it.
    ///
    /// `WAHAROA_BLESS=1` rewrites them. Read the diff: the point of the file is that a
    /// change to the report has to be looked at.
    #[test]
    fn merging_every_golden_policy_gives_what_is_recorded_beside_it() {
        let dir = fixture_dir();
        let bless = std::env::var("WAHAROA_BLESS").is_ok_and(|v| v == "1");
        let mut checked = 0;

        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("the fixture directory is missing")
            .map(|e| e.expect("readable entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
            .collect();
        entries.sort();

        for input in entries {
            let source = std::fs::read_to_string(&input).unwrap();
            let policy =
                Policy::parse(&source).unwrap_or_else(|e| panic!("{}: {e}", input.display()));
            let rendered = render(&policy);
            let expected_path = input.with_extension("merged");

            if bless {
                std::fs::write(&expected_path, &rendered).unwrap();
                checked += 1;
                continue;
            }
            let expected = std::fs::read_to_string(&expected_path).unwrap_or_else(|_| {
                panic!(
                    "{} has no .merged beside it. Run WAHAROA_BLESS=1 cargo test --lib merge",
                    input.display()
                )
            });
            assert_eq!(
                rendered,
                expected,
                "\n{} changed. If the new output is right, \
                 WAHAROA_BLESS=1 cargo test --lib merge\n",
                input.display()
            );
            checked += 1;
        }
        assert!(checked >= 7, "only {checked} golden policies were read");
    }

    /// The shipped example, merged. It declares `ecosystems.cargo` with no
    /// `floor.cargo`, which is the spike artifact's deliberate gap and not this
    /// function's business.
    #[test]
    fn the_shipped_example_merges_without_warning_where_it_should_not() {
        let source = std::fs::read_to_string("examples/policy.yaml").unwrap();
        let policy = Policy::parse(&source).unwrap();
        for ecosystem in policy.ecosystems.keys() {
            let (_, findings) = merge(&policy, ecosystem, TODAY);
            assert_eq!(findings.len(), Rule::ALL.len());
        }
    }
}
