//! Comparing an exception's settings against the ones above it, and whether a check applies
//! to an ecosystem at all.

use super::strictness::{Direction, Strictness};
use super::{Action, Policy, SetBlock};

/// A setting an exception can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    CooldownDays,
    Kev,
    InstallScripts,
    IgnoredVulnAdvisoryIds,
    Yanked,
    Deprecated,
    Provenance,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CooldownDays => "cooldown_days",
            Self::Kev => "kev",
            Self::InstallScripts => "install_scripts",
            Self::IgnoredVulnAdvisoryIds => "ignored_vuln_advisory_ids",
            Self::Yanked => "yanked",
            Self::Deprecated => "deprecated",
            Self::Provenance => "provenance",
        }
    }

    /// Every setting an exception can carry.
    pub const ALL: [Rule; 7] = [
        Self::CooldownDays,
        Self::Kev,
        Self::InstallScripts,
        Self::IgnoredVulnAdvisoryIds,
        Self::Yanked,
        Self::Deprecated,
        Self::Provenance,
    ];
}

/// Whether a check means anything for an ecosystem: its row's [`crate::ecosystem::Registry::
/// meaningless`] says, and one with no row has every check but Go's install scripts.
/// See docs/engineering_decisions/0023-policy-tier-resolution.md.
pub fn applies(ecosystem: &str, rule: Rule) -> bool {
    match ecosystem.parse::<crate::identity::Ecosystem>() {
        Ok(served) => !crate::ecosystem::of(served).meaningless.contains(&rule),
        Err(_) => !matches!((ecosystem, rule), ("golang" | "go", Rule::InstallScripts)),
    }
}

/// The settings an exception may change, borrowed from the global settings or a `set` block.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleValues<'a> {
    pub cooldown_days: Option<u32>,
    pub kev: Option<Action>,
    pub install_scripts: Option<Action>,
    pub ignored_vuln_advisory_ids: Option<&'a [String]>,
    pub yanked: Option<Action>,
    pub deprecated: Option<Action>,
    pub provenance: Option<Action>,
}

impl RuleValues<'_> {
    /// Whether these values set `rule`.
    pub fn sets(&self, rule: Rule) -> bool {
        match rule {
            Rule::CooldownDays => self.cooldown_days.is_some(),
            Rule::Kev => self.kev.is_some(),
            Rule::InstallScripts => self.install_scripts.is_some(),
            Rule::IgnoredVulnAdvisoryIds => self.ignored_vuln_advisory_ids.is_some(),
            Rule::Yanked => self.yanked.is_some(),
            Rule::Deprecated => self.deprecated.is_some(),
            Rule::Provenance => self.provenance.is_some(),
        }
    }
}

impl<'a> From<&'a SetBlock> for RuleValues<'a> {
    fn from(s: &'a SetBlock) -> Self {
        Self {
            cooldown_days: s.cooldown_days,
            kev: s.kev,
            install_scripts: s.install_scripts,
            ignored_vuln_advisory_ids: (!s.ignored_vuln_advisory_ids.is_empty())
                .then_some(s.ignored_vuln_advisory_ids.as_slice()),
            yanked: s.yanked,
            deprecated: s.deprecated,
            provenance: s.provenance,
        }
    }
}

impl From<&Policy> for RuleValues<'_> {
    fn from(p: &Policy) -> Self {
        Self {
            cooldown_days: Some(p.cooldown_days),
            kev: Some(p.kev),
            install_scripts: Some(p.install_scripts),
            ignored_vuln_advisory_ids: None,
            yanked: Some(p.yanked),
            deprecated: Some(p.deprecated),
            provenance: Some(p.provenance),
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
    if !applies(ecosystem, rule) {
        return Strictness::NotApplicable;
    }
    match rule {
        Rule::CooldownDays => match (value.cooldown_days, baseline.cooldown_days) {
            (Some(value), Some(baseline)) => {
                Direction::HigherIsStricter.strictness(value, baseline)
            }
            (Some(_), None) | (None, _) => Strictness::Unset,
        },
        Rule::Kev => action_strictness(value.kev, baseline.kev),
        Rule::InstallScripts => action_strictness(value.install_scripts, baseline.install_scripts),
        Rule::Yanked => action_strictness(value.yanked, baseline.yanked),
        Rule::Deprecated => action_strictness(value.deprecated, baseline.deprecated),
        Rule::Provenance => action_strictness(value.provenance, baseline.provenance),
        Rule::IgnoredVulnAdvisoryIds => match value.ignored_vuln_advisory_ids {
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
            outcome(
                &set("ignored_vuln_advisory_ids: [\"CVE-2024-1234\"]"),
                Rule::IgnoredVulnAdvisoryIds
            ),
            Strictness::Looser
        );
    }

    /// An empty list is not an exception. Written out, it would otherwise read as an
    /// exception that ignores nothing and still count as a loosening.
    #[test]
    fn an_empty_advisory_list_is_not_an_exception() {
        assert_eq!(
            outcome(
                &set("ignored_vuln_advisory_ids: []"),
                Rule::IgnoredVulnAdvisoryIds
            ),
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
        assert_eq!(
            Rule::ALL.map(Rule::as_str),
            [
                "cooldown_days",
                "kev",
                "install_scripts",
                "ignored_vuln_advisory_ids",
                "yanked",
                "deprecated",
                "provenance",
            ],
            "a name here is the key in the policy file"
        );
    }
}
