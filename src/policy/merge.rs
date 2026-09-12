//! Comparing one set of settings against another, and whether a check applies at all.
//!
//! What remains of the global-to-ecosystem merge this module used to be. There are no
//! per-ecosystem settings, so nothing is merged; what survives is the part the `packages`
//! tier needs, which is deciding whether an exception loosens the settings above it.

use super::strictness::{Direction, Strictness};
use super::{Action, Policy, SetBlock};

/// A setting an exception can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    CooldownDays,
    Kev,
    InstallScripts,
    CveIds,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CooldownDays => "cooldown_days",
            Self::Kev => "kev",
            Self::InstallScripts => "install_scripts",
            Self::CveIds => "cve_ids",
        }
    }

    /// Every setting an exception can carry. One list, so a setting added to the schema
    /// and not here is a compile error rather than a silently unchecked field.
    pub const ALL: [Rule; 4] = [
        Self::CooldownDays,
        Self::Kev,
        Self::InstallScripts,
        Self::CveIds,
    ];
}

/// Whether a check means anything for an ecosystem.
///
/// Keyed on the ecosystem name as the policy file spells it, not on
/// [`crate::identity::Ecosystem`], because a policy can name an ecosystem before an
/// adapter for it exists. Go modules are the case that matters and have no adapter.
///
/// The default is that a check applies. An ecosystem is listed here only where a check
/// genuinely has no meaning, because reporting not-applicable for one that does apply
/// would hide a real loosening.
pub fn applies(ecosystem: &str, rule: Rule) -> bool {
    match (ecosystem, rule) {
        // Go modules have no install step, so there is no script to run. The check
        // reports not-applicable rather than a violation.
        ("golang" | "go", Rule::InstallScripts) => false,
        _ => true,
    }
}

/// The settings an exception may change, borrowed from whichever side they come from.
///
/// One shape, so the global settings and an exception's `set` block are compared by the
/// same code.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleValues<'a> {
    pub cooldown_days: Option<u32>,
    pub kev: Option<Action>,
    pub install_scripts: Option<Action>,
    pub cve_ids: Option<&'a [String]>,
}

impl<'a> From<&'a SetBlock> for RuleValues<'a> {
    fn from(s: &'a SetBlock) -> Self {
        Self {
            cooldown_days: s.cooldown_days,
            kev: s.kev,
            install_scripts: s.install_scripts,
            // An empty list is not an exception, so it reads as unset rather than as an
            // exception that ignores nothing.
            cve_ids: (!s.cve_ids.is_empty()).then_some(s.cve_ids.as_slice()),
        }
    }
}

impl From<&Policy> for RuleValues<'_> {
    fn from(p: &Policy) -> Self {
        Self {
            cooldown_days: Some(p.cooldown_days),
            kev: Some(p.kev),
            install_scripts: Some(p.install_scripts),
            // There is no global list of advisories to ignore. An exception naming one has
            // nothing above it to be compared against, and ignoring an advisory can only
            // ever loosen, which `compare` reports directly.
            cve_ids: None,
        }
    }
}

/// How one setting in an exception compares to the same setting above it.
pub fn compare(
    ecosystem: &str,
    rule: Rule,
    value: RuleValues<'_>,
    baseline: RuleValues<'_>,
) -> Strictness {
    // Applicability is decided for the whole check, before its values are looked at.
    if !applies(ecosystem, rule) {
        return Strictness::NotApplicable;
    }
    match rule {
        // Higher is stricter: a longer wait is a stricter policy.
        Rule::CooldownDays => match (value.cooldown_days, baseline.cooldown_days) {
            (Some(value), Some(baseline)) => {
                Direction::HigherIsStricter.strictness(value, baseline)
            }
            (Some(_), None) | (None, _) => Strictness::Unset,
        },
        Rule::Kev => action_strictness(value.kev, baseline.kev),
        Rule::InstallScripts => action_strictness(value.install_scripts, baseline.install_scripts),
        // Ignoring an advisory can only loosen. There is nothing above to compare it to,
        // so naming any is a loosening and naming none is no change at all.
        Rule::CveIds => match value.cve_ids {
            Some(ids) if !ids.is_empty() => Strictness::Looser,
            _ => Strictness::Unset,
        },
    }
}

fn action_strictness(value: Option<Action>, baseline: Option<Action>) -> Strictness {
    match (value, baseline) {
        (Some(value), Some(baseline)) => value.strictness_against(baseline),
        (Some(_), None) | (None, _) => Strictness::Unset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(body: &str) -> Policy {
        Policy::parse(&format!("version: 1\n{body}")).expect("fixture should parse")
    }

    fn set(body: &str) -> Policy {
        policy(&format!(
            "packages:\n  - match: {{ ecosystem: npm, name: x }}\n    set: {{ {body} }}\n    \
             reason: r\n    permanent: true\n"
        ))
    }

    fn outcome(p: &Policy, rule: Rule) -> Strictness {
        compare("npm", rule, (&p.packages[0].set).into(), p.into())
    }

    #[test]
    fn a_shorter_wait_is_looser_and_a_longer_one_is_stricter() {
        assert_eq!(
            outcome(&set("cooldown_days: 0"), Rule::CooldownDays),
            Strictness::Looser
        );
        assert_eq!(
            outcome(&set("cooldown_days: 30"), Rule::CooldownDays),
            Strictness::Stricter
        );
        assert_eq!(
            outcome(&set("cooldown_days: 7"), Rule::CooldownDays),
            Strictness::Same,
            "the shipped default"
        );
    }

    #[test]
    fn turning_a_check_off_is_looser() {
        assert_eq!(outcome(&set("kev: allow"), Rule::Kev), Strictness::Looser);
        assert_eq!(
            outcome(&set("install_scripts: allow"), Rule::InstallScripts),
            Strictness::Looser
        );
    }

    /// Ignoring a named advisory has nothing above it to be compared against, and can
    /// only ever loosen.
    #[test]
    fn naming_an_advisory_to_ignore_is_always_a_loosening() {
        assert_eq!(
            outcome(&set("cve_ids: [\"CVE-2024-1234\"]"), Rule::CveIds),
            Strictness::Looser
        );
    }

    /// An empty list is not an exception. Written out, it would otherwise read as an
    /// exception that ignores nothing and still count as a loosening.
    #[test]
    fn an_empty_advisory_list_is_not_an_exception() {
        assert_eq!(
            outcome(&set("cve_ids: []"), Rule::CveIds),
            Strictness::Unset
        );
    }

    /// A setting the exception does not mention has not moved.
    #[test]
    fn a_setting_an_exception_does_not_mention_is_unset() {
        let p = set("cooldown_days: 0");
        assert_eq!(outcome(&p, Rule::Kev), Strictness::Unset);
        assert_eq!(outcome(&p, Rule::InstallScripts), Strictness::Unset);
    }

    /// Go has no install step, so the check reports not-applicable rather than the
    /// loosening it would be anywhere else.
    #[test]
    fn a_check_with_no_meaning_for_an_ecosystem_reports_not_applicable() {
        let p = set("install_scripts: allow");
        let values = (&p.packages[0].set).into();
        assert_eq!(
            compare("golang", Rule::InstallScripts, values, (&p).into()),
            Strictness::NotApplicable
        );
        assert_eq!(
            compare("npm", Rule::InstallScripts, values, (&p).into()),
            Strictness::Looser,
            "the same exception, for an ecosystem where it means something"
        );
    }

    #[test]
    fn applicability_defaults_to_applying() {
        assert!(!applies("golang", Rule::InstallScripts));
        assert!(!applies("go", Rule::InstallScripts));
        assert!(applies("golang", Rule::CooldownDays));
        assert!(applies("npm", Rule::InstallScripts));
        assert!(
            applies("some-future-ecosystem", Rule::InstallScripts),
            "a check applies unless it is known not to; the other way round would hide a \
             real loosening behind an unrecognised name"
        );
    }

    #[test]
    fn every_setting_an_exception_can_carry_has_a_name() {
        for rule in Rule::ALL {
            assert!(!rule.as_str().is_empty());
        }
        assert_eq!(Rule::ALL.len(), 4);
    }
}
