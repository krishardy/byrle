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
//! # It may only loosen
//!
//! An entry that would tighten is a load-time error. Tightening one package is not what
//! this tier is for, and admitting it would reopen questions about what outranks what
//! that the design settled by not having them.
//!
//! # Why an expiry at all
//!
//! §5.5: a justification is true when written and silently stops being true later.
//! Reviewed versions get superseded, internal packages change owners, the blocker gets
//! fixed and nobody deletes the entry. An expiry inverts the default so an unexamined
//! entry dies rather than persisting, which makes deletion the outcome of inattention.

use super::merge::{self, Rule, RuleValues};
use super::strictness::Strictness;
use super::{AdvisoryScore, ExpiryDate, PackageRule, Policy};
use jiff::civil::Date;

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

/// How every package entry compares to the settings it overrides.
pub fn findings(policy: &Policy) -> Vec<Finding> {
    let mut out = Vec::new();
    let baseline = RuleValues::from(policy);
    for (index, entry) in policy.packages.iter().enumerate() {
        let ecosystem = &entry.selector.ecosystem;
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

/// How an entry is named in messages: by index, because its selector may not be unique.
pub fn label(index: usize) -> String {
    format!("packages[{index}]")
}

/// Whether an entry loosens anything at all.
///
/// Any one setting getting looser, or moving in a direction that cannot be proven, makes
/// the entry a loosening that has to be answered for.
pub fn loosens(findings: &[Finding], index: usize) -> bool {
    findings
        .iter()
        .filter(|f| f.index == index)
        .any(|f| f.outcome.warns())
}

/// Whether an entry tightens anything, which this tier does not allow.
pub fn tightens(findings: &[Finding], index: usize) -> bool {
    findings
        .iter()
        .filter(|f| f.index == index)
        .any(|f| f.outcome == Strictness::Stricter)
}

/// Whether an entry changes anything at all.
///
/// An entry that changes nothing is valid, and almost always a selector that no longer
/// matches what it was written for. It warns rather than refusing, because a policy that
/// will not load is a worse outcome than one carrying a line that does nothing.
pub fn changes_nothing(findings: &[Finding], index: usize) -> bool {
    findings
        .iter()
        .filter(|f| f.index == index)
        .all(|f| !f.outcome.compared() || f.outcome == Strictness::Same)
}

/// Why a package entry was refused.
#[derive(Debug, PartialEq)]
pub enum PackageError {
    /// It loosens the settings above it and says neither when it stops nor that it does
    /// not stop.
    Unjustified { at: String, rule: Rule },
    /// It tightens, which this tier does not allow.
    Tightens { at: String, rule: Rule },
    /// It, or an `advisory_scores` entry, is dated further ahead than the ceiling allows.
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
            Self::Tightens { at, rule } => write!(
                f,
                "{at} tightens `{}`. This tier is for exceptions, which may only loosen: \
                 a setting that should be stricter for everyone belongs in the global \
                 settings, and one that should be stricter for a single package belongs \
                 in `denials`",
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

/// Check every package entry against §5.5's requirements, and every `advisory_scores` entry
/// against the expiry ceiling.
///
/// `as_of` and the ceiling are arguments rather than a clock and a constant, so
/// `policy check --as-of` can ask what a policy would be judged as on another day.
pub fn check(policy: &Policy, as_of: Date, ceiling_days: i64) -> Result<(), PackageError> {
    let findings = findings(policy);
    let latest = as_of
        .checked_add(jiff::Span::new().days(ceiling_days))
        .unwrap_or(Date::MAX);

    let within_ceiling = |at: String, expires: Option<ExpiryDate>| match expires {
        Some(expires) if expires.0 > latest => Err(PackageError::TooFarAhead {
            at,
            expires: expires.to_string(),
            latest: latest.to_string(),
            ceiling_days,
        }),
        _ => Ok(()),
    };

    for (index, score) in policy.advisory_scores.iter().enumerate() {
        within_ceiling(AdvisoryScore::label(index), score.expires)?;
    }

    for (index, entry) in policy.packages.iter().enumerate() {
        let at = label(index);
        within_ceiling(at.clone(), entry.expires)?;

        if tightens(&findings, index) {
            let rule = findings
                .iter()
                .find(|f| f.index == index && f.outcome == Strictness::Stricter)
                .map(|f| f.rule)
                .expect("tightens() is true only when some setting is stricter");
            return Err(PackageError::Tightens { at, rule });
        }

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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::DEFAULT_EXPIRY_CEILING_DAYS;
    use crate::policy::PolicyError;
    use jiff::civil::date;

    const TODAY: Date = date(2026, 9, 12);

    fn parse(body: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!("version: 1\n{body}"))
    }

    fn policy(body: &str) -> Policy {
        parse(body).expect("fixture should parse")
    }

    /// One entry, with whatever `set` and trailing fields the case needs.
    fn entry(set: &str, tail: &str) -> String {
        format!(
            "packages:\n  - match: {{ ecosystem: npm, name: x }}\n    set: {{ {set} }}\n    \
             reason: reviewed\n{tail}"
        )
    }

    fn checked(set: &str, tail: &str) -> Result<(), PackageError> {
        check(
            &policy(&entry(set, tail)),
            TODAY,
            DEFAULT_EXPIRY_CEILING_DAYS,
        )
    }

    #[test]
    fn a_loosening_entry_with_an_expiry_is_accepted() {
        assert!(checked("cooldown_days: 0", "    expires: \"2026-10-15\"\n").is_ok());
    }

    #[test]
    fn a_loosening_entry_with_neither_an_expiry_nor_permanence_is_refused() {
        let error = checked("cooldown_days: 0", "").unwrap_err();
        assert!(matches!(
            error,
            PackageError::Unjustified {
                rule: Rule::CooldownDays,
                ..
            }
        ));
        assert!(error.to_string().contains("packages[0]"));
    }

    /// The explicit alternative, for a genuine invariant like an internal namespace.
    #[test]
    fn a_loosening_entry_may_say_it_does_not_stop_being_true() {
        assert!(checked("install_scripts: allow", "    permanent: true\n").is_ok());
    }

    /// The tier is for exceptions, and an exception loosens. A setting that should be
    /// stricter for everyone belongs in the global settings.
    #[test]
    fn a_tightening_entry_is_refused() {
        let error = checked("cooldown_days: 30", "    permanent: true\n").unwrap_err();
        assert!(matches!(
            error,
            PackageError::Tightens {
                rule: Rule::CooldownDays,
                ..
            }
        ));
        assert!(
            error.to_string().contains("denials"),
            "the refusal has to say where a stricter rule does belong: {error}"
        );
    }

    /// An entry that loosens one setting and tightens another is refused for tightening.
    /// It cannot buy the loosening with the tightening.
    #[test]
    fn tightening_alongside_a_loosening_is_still_refused() {
        let error = checked(
            "install_scripts: allow, cooldown_days: 30",
            "    permanent: true\n",
        )
        .unwrap_err();
        assert!(matches!(error, PackageError::Tightens { .. }));
    }

    /// Every exception is measured against the global settings, which is the only
    /// baseline there is.
    #[test]
    fn loosening_is_measured_against_the_global_settings() {
        let p = policy(&format!(
            "cooldown_days: 14\n{}",
            entry("cooldown_days: 7", "    permanent: true\n")
        ));
        let found = findings(&p);
        let cooldown = found.iter().find(|f| f.rule == Rule::CooldownDays).unwrap();
        assert_eq!(
            cooldown.outcome,
            Strictness::Looser,
            "7 is the shipped default and still a loosening of a policy that says 14"
        );
    }

    /// An entry that changes nothing is valid. It is almost always a selector that no
    /// longer matches what it was written for, which is worth saying and not worth
    /// refusing a policy over.
    #[test]
    fn an_entry_that_changes_nothing_loads_and_is_detectable() {
        let p = policy(&entry("", "    permanent: true\n"));
        let found = findings(&p);
        assert!(changes_nothing(&found, 0));
        assert!(!loosens(&found, 0));
        assert!(!tightens(&found, 0));
        assert!(check(&p, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_ok());
    }

    /// Setting a value to what it already is changes nothing either.
    #[test]
    fn restating_the_global_setting_changes_nothing() {
        let p = policy(&entry("cooldown_days: 7", "    permanent: true\n"));
        assert!(changes_nothing(&findings(&p), 0));
    }

    #[test]
    fn an_expiry_inside_the_ceiling_is_accepted_and_one_past_it_is_not() {
        // 90 days from 2026-09-12 is 2026-12-11.
        assert!(
            checked("cooldown_days: 0", "    expires: \"2026-12-11\"\n").is_ok(),
            "the ceiling day itself"
        );
        let error = checked("cooldown_days: 0", "    expires: \"2026-12-12\"\n").unwrap_err();
        assert!(matches!(error, PackageError::TooFarAhead { .. }));
        let text = error.to_string();
        assert!(
            text.contains("2026-12-12") && text.contains("2026-12-11") && text.contains("90"),
            "the refusal has to say what it found, what is allowed, and the ceiling: {text}"
        );
    }

    #[test]
    fn an_advisory_score_is_held_to_the_expiry_ceiling() {
        let scored = |expires: &str| {
            policy(&format!(
                "advisory_scores:\n  - {{ advisory_id: GHSA-x, cvss: 5.0, reason: r, \
                 expires: \"{expires}\" }}\n"
            ))
        };
        assert!(check(&scored("2026-12-11"), TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_ok());
        let error = check(&scored("2026-12-12"), TODAY, DEFAULT_EXPIRY_CEILING_DAYS).unwrap_err();
        assert!(
            matches!(&error, PackageError::TooFarAhead { at, .. } if at == "advisory_scores[0]"),
            "{error}"
        );
    }

    /// The ceiling is an argument, so an operator who needs a different one is not
    /// editing the source.
    #[test]
    fn the_ceiling_is_configurable() {
        let p = policy(&entry("cooldown_days: 0", "    expires: \"2027-09-12\"\n"));
        assert!(check(&p, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_err());
        assert!(check(&p, TODAY, 365).is_ok());
    }

    /// The date is an argument too, so `policy check --as-of` can ask what a policy would
    /// be judged as on another day.
    #[test]
    fn the_same_entry_passes_today_and_fails_when_today_moves_back() {
        let p = policy(&entry("cooldown_days: 0", "    expires: \"2026-12-01\"\n"));
        assert!(check(&p, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_ok());
        assert!(
            check(&p, date(2026, 1, 1), DEFAULT_EXPIRY_CEILING_DAYS).is_err(),
            "dated eleven months ahead of a January reading"
        );
    }

    #[test]
    fn a_policy_with_no_entries_has_nothing_to_check() {
        let p = policy("cooldown_days: 7\n");
        assert!(findings(&p).is_empty());
        assert!(check(&p, TODAY, DEFAULT_EXPIRY_CEILING_DAYS).is_ok());
    }

    #[test]
    fn every_setting_is_reported_for_every_entry() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: r\n    \
             permanent: true\n  - match: { ecosystem: npm, name: y }\n    set: {}\n    \
             reason: r\n    permanent: true\n",
        );
        let found = findings(&p);
        assert_eq!(found.len(), 2 * Rule::ALL.len());
        assert!(found.iter().all(|f| f.ecosystem == "npm"));
    }

    /// Ignoring a named advisory is a loosening like any other and has to be answered for.
    #[test]
    fn ignoring_an_advisory_needs_a_justification() {
        assert!(matches!(
            checked("vuln_advisory_ids: [\"CVE-2024-1234\"]", "").unwrap_err(),
            PackageError::Unjustified {
                rule: Rule::VulnAdvisoryIds,
                ..
            }
        ));
        assert!(
            checked(
                "vuln_advisory_ids: [\"CVE-2024-1234\"]",
                "    permanent: true\n"
            )
            .is_ok()
        );
    }

    /// The shipped example is a real policy and has to pass its own rules, read on a day
    /// its entries are still dated ahead of.
    #[test]
    fn the_shipped_example_satisfies_the_package_rules() {
        let source = std::fs::read_to_string("examples/policy.yaml").unwrap();
        let policy = Policy::parse(&source).unwrap();
        check(&policy, date(2026, 9, 1), DEFAULT_EXPIRY_CEILING_DAYS)
            .expect("the shipped example should satisfy the rules it documents");
    }
}
