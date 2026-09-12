//! The `packages` tier: what each entry does to the policy it overrides, and what §5.5
//! requires of an entry that loosens it.
//!
//! # Loosening here is the point, so it does not warn
//!
//! At the ecosystem tier a loosening is unexpected and warns. Here it is the tier's
//! purpose, and a warning per entry would become noise that hides the ecosystem-tier
//! warnings that matter. §5.5 asks for a required field instead, because a required field
//! cannot be ignored the way a warning can. So an unjustified loosening is refused at
//! load and nothing here warns about anything.
//!
//! # Measured against the effective policy above the rule
//!
//! Not against the global default. An entry is compared to what would apply in its
//! absence, which is the ecosystem merge for its own ecosystem, so a rule that loosens
//! relative to its ecosystem but happens to match global does not slip through
//! unjustified.
//!
//! # Why an expiry at all
//!
//! §5.5: a justification is true when written and silently stops being true later.
//! Reviewed versions get superseded, internal packages change owners, the blocker gets
//! fixed and nobody deletes the entry. An expiry inverts the default so an unexamined
//! entry dies rather than persisting, which makes deletion the outcome of inattention.

use super::merge::{self, Rule, RuleValues};
use super::strictness::Strictness;
use super::{PackageRule, Policy};
use jiff::civil::Date;

/// §5.5's ceiling on how far ahead a package entry may be dated.
///
/// Long enough to cover a review cycle, short enough that an entry nobody looked at
/// again lapses within a quarter.
pub const DEFAULT_EXPIRY_CEILING_DAYS: i64 = 90;

/// What one package entry does to one rule of the policy above it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// Index into `policy.packages`, which is how an entry is named in an error: the
    /// selector may not be unique and the file has no other handle on it.
    pub index: usize,
    pub ecosystem: String,
    pub rule: Rule,
    pub outcome: Strictness,
}

/// How every package entry compares to the policy that would apply without it.
pub fn findings(policy: &Policy, as_of: Date) -> Vec<Finding> {
    let mut out = Vec::new();
    for (index, entry) in policy.packages.iter().enumerate() {
        let ecosystem = &entry.selector.ecosystem;
        // What applies without this entry: the ecosystem merge for its own ecosystem.
        let (effective, _) = merge::merge(policy, ecosystem, as_of);
        let baseline = RuleValues::from(&effective);
        let value = RuleValues::from(&entry.set);

        for rule in Rule::ALL {
            out.push(Finding {
                index,
                ecosystem: ecosystem.clone(),
                rule,
                outcome: merge::compare(ecosystem, rule, value, baseline),
            });
        }
    }
    out
}

/// Whether an entry loosens anything at all.
///
/// Any one rule getting looser, or moving in a direction that cannot be proven, makes
/// the entry a loosening that has to be answered for. An entry is not excused by having
/// tightened something else in the same breath.
pub fn loosens(findings: &[Finding], index: usize) -> bool {
    findings
        .iter()
        .filter(|f| f.index == index)
        .any(|f| f.outcome.warns())
}

/// Why a package entry was refused.
#[derive(Debug, PartialEq)]
pub enum PackageError {
    /// It loosens the policy above it and says neither when it stops nor that it does
    /// not stop.
    Unjustified { at: String, rule: Rule },
    /// It is dated further ahead than the ceiling allows.
    TooFarAhead {
        at: String,
        expires: String,
        latest: String,
        ceiling_days: i64,
    },
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unjustified { at, rule } => write!(
                f,
                "{at} loosens `{}` and carries neither `expires` nor `permanent: true`. \
                 A loosening at this tier is expected, which is why it is not warned \
                 about; saying when it stops being true is what is required instead",
                rule.as_str()
            ),
            Self::TooFarAhead {
                at,
                expires,
                latest,
                ceiling_days,
            } => write!(
                f,
                "{at} expires {expires}, past the {ceiling_days}-day ceiling. The latest \
                 it may be dated is {latest}. Use `permanent: true` if it genuinely does \
                 not stop being true"
            ),
        }
    }
}

impl std::error::Error for PackageError {}

/// Check every package entry against §5.5's requirements.
///
/// `as_of` and the ceiling are arguments rather than a clock and a constant, so
/// `policy check --as-of` can ask what a policy would be judged as on another day.
pub fn check(policy: &Policy, as_of: Date, ceiling_days: i64) -> Result<(), PackageError> {
    let findings = findings(policy, as_of);
    let latest = as_of
        .checked_add(jiff::Span::new().days(ceiling_days))
        .unwrap_or(Date::MAX);

    for (index, entry) in policy.packages.iter().enumerate() {
        let at = format!("packages[{index}]");

        if let Some(expires) = entry.expires
            && expires.0 > latest
        {
            return Err(PackageError::TooFarAhead {
                at,
                expires: expires.to_string(),
                latest: latest.to_string(),
                ceiling_days,
            });
        }

        // Tightening entries need no justification: nothing was given away, so there is
        // nothing to answer for and nothing to revisit.
        if !loosens(&findings, index) || justified(entry) {
            continue;
        }
        let rule = findings
            .iter()
            .find(|f| f.index == index && f.outcome.warns())
            .map(|f| f.rule)
            .expect("loosens() is true only when some rule warns");
        return Err(PackageError::Unjustified { at, rule });
    }
    Ok(())
}

/// An entry says either when it stops being true, or that it does not.
///
/// `reason` is not checked here because the schema already requires it on every entry,
/// tightening ones included.
fn justified(entry: &PackageRule) -> bool {
    entry.expires.is_some() || entry.permanent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyError;
    use jiff::civil::date;

    const TODAY: Date = date(2026, 9, 12);

    fn parse(body: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!(
            "version: 1\nfloor:\n  npm:\n    known_malware: block\n{body}"
        ))
    }

    fn policy(body: &str) -> Policy {
        parse(body).expect("fixture should parse")
    }

    fn checked(body: &str) -> Result<(), PackageError> {
        check(&policy(body), TODAY, DEFAULT_EXPIRY_CEILING_DAYS)
    }

    #[test]
    fn a_loosening_entry_with_an_expiry_is_accepted() {
        assert!(
            checked(
                "defaults:\n  install_scripts: block\npackages:\n  \
                 - match: { ecosystem: npm, name: x }\n    set: { install_scripts: allow }\n    \
                 reason: reviewed\n    expires: \"2026-10-15\"\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_loosening_entry_with_neither_an_expiry_nor_permanence_is_refused() {
        let error = checked(
            "defaults:\n  install_scripts: block\npackages:\n  \
             - match: { ecosystem: npm, name: x }\n    set: { install_scripts: allow }\n    \
             reason: reviewed\n",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PackageError::Unjustified {
                rule: Rule::InstallScripts,
                ..
            }
        ));
        assert!(error.to_string().contains("packages[0]"));
    }

    /// §5.5's explicit alternative, for genuine invariants like an internal namespace.
    #[test]
    fn a_loosening_entry_may_say_it_does_not_stop_being_true() {
        assert!(
            checked(
                "defaults:\n  install_scripts: block\npackages:\n  \
                 - match: { ecosystem: npm, name: \"@mycompany/*\" }\n    \
                 set: { install_scripts: allow }\n    reason: \"published by our CI\"\n    \
                 permanent: true\n"
            )
            .is_ok()
        );
    }

    /// Tightening entries need no justification: nothing was given away.
    #[test]
    fn a_tightening_entry_needs_nothing() {
        assert!(
            checked(
                "defaults:\n  install_scripts: warn\npackages:\n  \
                 - match: { ecosystem: npm, name: x }\n    set: { install_scripts: block }\n    \
                 reason: \"we distrust this one\"\n"
            )
            .is_ok()
        );
    }

    /// An entry that tightens one rule and loosens another is still a loosening. It is
    /// not excused by what it gave in the other direction.
    #[test]
    fn tightening_one_rule_does_not_excuse_loosening_another() {
        let error = checked(
            "defaults:\n  install_scripts: block\n  provenance_required: false\npackages:\n  \
             - match: { ecosystem: npm, name: x }\n    \
             set: { install_scripts: allow, provenance_required: true }\n    reason: r\n",
        )
        .unwrap_err();
        assert!(matches!(error, PackageError::Unjustified { .. }));
    }

    /// §5.5: measured against the effective policy above the rule, not the global
    /// default. Global says `warn`; the ecosystem tightened to `block`; the entry's
    /// `warn` matches global exactly and is still a loosening of what actually applies.
    #[test]
    fn loosening_is_measured_against_the_ecosystem_not_the_global_default() {
        let body = "defaults:\n  install_scripts: warn\necosystems:\n  npm:\n    \
                    install_scripts: block\npackages:\n  \
                    - match: { ecosystem: npm, name: x }\n    set: { install_scripts: warn }\n    \
                    reason: r\n";
        let found = findings(&policy(body), TODAY);
        let scripts = found
            .iter()
            .find(|f| f.rule == Rule::InstallScripts)
            .unwrap();
        assert_eq!(
            scripts.outcome,
            Strictness::Looser,
            "matching the global default does not make it not a loosening"
        );
        assert!(matches!(
            check(&policy(body), TODAY, DEFAULT_EXPIRY_CEILING_DAYS).unwrap_err(),
            PackageError::Unjustified { .. }
        ));
    }

    /// An entry for an ecosystem whose merge says nothing has no baseline, so it loosened
    /// nothing and needs no justification.
    #[test]
    fn an_entry_with_nothing_above_it_has_loosened_nothing() {
        assert!(
            checked(
                "packages:\n  - match: { ecosystem: npm, name: x }\n    \
                 set: { install_scripts: allow }\n    reason: r\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn an_expiry_inside_the_ceiling_is_accepted_and_one_past_it_is_not() {
        let body = |date: &str| {
            format!(
                "defaults:\n  install_scripts: block\npackages:\n  \
                 - match: {{ ecosystem: npm, name: x }}\n    set: {{ install_scripts: allow }}\n    \
                 reason: r\n    expires: \"{date}\"\n"
            )
        };
        // 90 days from 2026-09-12 is 2026-12-11.
        assert!(
            checked(&body("2026-12-11")).is_ok(),
            "the ceiling day itself"
        );
        let error = checked(&body("2026-12-12")).unwrap_err();
        assert!(matches!(error, PackageError::TooFarAhead { .. }));
        let text = error.to_string();
        assert!(
            text.contains("2026-12-12") && text.contains("2026-12-11") && text.contains("90"),
            "the refusal has to say what it found, what is allowed, and the ceiling: {text}"
        );
    }

    /// The ceiling is an argument, so an operator who needs a different one is not
    /// editing the source.
    #[test]
    fn the_ceiling_is_configurable() {
        let source = policy(
            "defaults:\n  install_scripts: block\npackages:\n  \
             - match: { ecosystem: npm, name: x }\n    set: { install_scripts: allow }\n    \
             reason: r\n    expires: \"2027-09-12\"\n",
        );
        assert!(check(&source, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_err());
        assert!(check(&source, TODAY, 365).is_ok());
    }

    /// The date is an argument too, so the same policy is judged differently as the
    /// ceiling moves with the day.
    #[test]
    fn the_same_entry_passes_today_and_fails_when_today_moves_back() {
        let source = policy(
            "defaults:\n  install_scripts: block\npackages:\n  \
             - match: { ecosystem: npm, name: x }\n    set: { install_scripts: allow }\n    \
             reason: r\n    expires: \"2026-12-01\"\n",
        );
        assert!(check(&source, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_ok());
        assert!(
            check(&source, date(2026, 1, 1), DEFAULT_EXPIRY_CEILING_DAYS).is_err(),
            "dated eleven months ahead of a January reading"
        );
    }

    /// A tightening entry is not exempt from the ceiling. An entry that expires is making
    /// a claim about time whichever direction it moves the policy in.
    #[test]
    fn the_ceiling_applies_to_tightening_entries_too() {
        assert!(matches!(
            checked(
                "defaults:\n  install_scripts: warn\npackages:\n  \
                 - match: { ecosystem: npm, name: x }\n    set: { install_scripts: block }\n    \
                 reason: r\n    expires: \"2030-01-01\"\n"
            )
            .unwrap_err(),
            PackageError::TooFarAhead { .. }
        ));
    }

    #[test]
    fn a_policy_with_no_package_entries_has_nothing_to_check() {
        assert!(checked("defaults:\n  install_scripts: block\n").is_ok());
        assert!(findings(&policy(""), TODAY).is_empty());
    }

    #[test]
    fn every_rule_is_reported_for_every_entry() {
        let found = findings(
            &policy(
                "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: r\n  \
                 - match: { ecosystem: npm, name: y }\n    set: {}\n    reason: r\n",
            ),
            TODAY,
        );
        assert_eq!(found.len(), 2 * Rule::ALL.len());
        assert!(found.iter().all(|f| f.ecosystem == "npm"));
        assert!(!loosens(&found, 0));
    }

    /// The shipped example is a real §5.5 policy and has to pass its own rules, read on a
    /// day its entries are still dated ahead of.
    #[test]
    fn the_shipped_example_satisfies_the_package_rules() {
        let source = std::fs::read_to_string("examples/policy.yaml").unwrap();
        let policy = Policy::parse(&source).unwrap();
        check(&policy, date(2026, 9, 1), DEFAULT_EXPIRY_CEILING_DAYS)
            .expect("the shipped example should satisfy the rules it documents");
    }
}
