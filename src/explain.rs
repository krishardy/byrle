//! `waharoa explain`: the whole decision vector, not just the verdict.
//!
//! The point of a vector is that every check answers. A refusal that named only the
//! strongest reason would hide that two others also fired, and hide that a third was never
//! asked. So every check is printed with its own outcome, and the verdict is shown as what
//! it is: the strongest answer in the list.
//!
//! Five states can appear against a check, and they are deliberately not collapsed:
//!
//! | state | means |
//! |---|---|
//! | `pass` | the check ran and found nothing |
//! | `FAIL` | the check ran and found something |
//! | `excepted` | it found something and a `packages` entry excused it |
//! | `n/a` | the check has no meaning for this ecosystem |
//! | `unenforced` | the fact it needs is not available in this build |
//!
//! `n/a` and `unenforced` both mean the check did not decide, for different reasons, and
//! neither is `pass`. Reporting either as a pass would claim a check ran that never could.

use crate::policy::decide::{Check, Decision, Facts, Outcome};
use crate::policy::enforce::Unenforceable;
use crate::policy::{Action, Policy};

/// One line per check, then the verdict.
pub fn decision(facts: &Facts, decision: &Decision, unenforceable: &[Unenforceable]) -> String {
    let mut out = format!(
        "pkg:{}/{}@{}\n\n",
        facts.ecosystem, facts.name, facts.version
    );

    let width = Check::ALL
        .iter()
        .map(|c| c.as_str().len())
        .max()
        .unwrap_or(0);

    for result in &decision.results {
        let unenforced = unenforceable.iter().find(|u| u.check == result.check);
        let (state, detail) = match (unenforced, &result.outcome) {
            (Some(u), _) => ("unenforced".to_owned(), u.why.to_owned()),
            (None, Outcome::Passed) => ("pass".to_owned(), String::new()),
            (None, Outcome::NotApplicable) => (
                "n/a".to_owned(),
                format!("no meaning for {}", facts.ecosystem),
            ),
            (None, Outcome::Failed(action)) => (
                format!("FAIL {}", action.as_str()),
                why(result.check, facts),
            ),
            (None, Outcome::Excepted { entry, action }) => (
                "excepted".to_owned(),
                format!(
                    "would have been {}; packages[{entry}] excused it",
                    action.as_str()
                ),
            ),
        };
        out.push_str(&format!(
            "  {:width$}  {:16}  {detail}\n",
            result.check.as_str(),
            state
        ));
    }

    // The verdict is the strongest answer above, not a separate judgement.
    out.push_str(&format!(
        "\n  verdict: {}\n",
        decision.action().as_str()
    ));
    if decision.action() == Action::Quarantine {
        out.push_str("  quarantine lapses on its own; block does not\n");
    }
    out
}

/// What a failing check found, in the terms the operator wrote.
fn why(check: Check, facts: &Facts) -> String {
    match check {
        Check::Denials => "this exact version is denied".to_owned(),
        Check::KnownMalware => "reported as malware; this has no exception".to_owned(),
        Check::CooldownDays => match facts.published {
            Some(published) => format!("published {published}"),
            None => "no publish date, which is not the same as old enough".to_owned(),
        },
        Check::Kev => facts
            .advisories
            .iter()
            .filter(|a| a.kev)
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Check::MaxCvss => facts
            .advisories
            .iter()
            .map(|a| format!("{} {:.1}", a.id, a.cvss))
            .collect::<Vec<_>>()
            .join(", "),
        Check::InstallScripts => "declares an install script".to_owned(),
    }
}

/// The policy as loaded, and which of its checks can actually fire.
///
/// Separate from the settings themselves because a configured check with no fact source is
/// not the same as one that is off, and reading the file cannot tell them apart.
pub fn policy(policy: &Policy, has_advisory_stream: bool) -> String {
    let mut out = String::from("settings\n");
    out.push_str(&format!("  cooldown_days    {}\n", policy.cooldown_days));
    out.push_str(&format!("  max_cvss         {}\n", policy.max_cvss));
    out.push_str(&format!(
        "  install_scripts  {}\n",
        policy.install_scripts.as_str()
    ));
    out.push_str(&format!("  kev              {}\n", policy.kev.as_str()));
    out.push_str(&format!("  denials          {}\n", policy.denials.len()));
    out.push_str(&format!("  packages         {}\n", policy.packages.len()));

    out.push_str("\nchecks\n");
    for check in Check::ALL {
        let state = match check {
            Check::MaxCvss | Check::Kev | Check::KnownMalware if !has_advisory_stream => {
                "unenforced, no advisory stream"
            }
            Check::CooldownDays if !policy.uses_cooldown() => "off",
            _ => "enforced",
        };
        out.push_str(&format!("  {:16}  {state}\n", check.as_str()));
    }

    for (index, entry) in policy.packages.iter().enumerate() {
        out.push_str(&format!("\npackages[{index}]  {}\n", entry.reason));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::decide::{Advisory, Intel, decide};

    const TODAY: jiff::civil::Date = jiff::civil::date(2026, 9, 13);

    fn facts() -> Facts {
        Facts {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
            published: Some(jiff::civil::date(2021, 2, 20)),
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: false,
            intel: Intel::NotConsulted,
        }
    }

    fn loaded(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    fn rendered(yaml: &str, facts: &Facts, unenforceable: &[Unenforceable]) -> String {
        let policy = loaded(yaml);
        decision(facts, &decide(&policy, facts, TODAY), unenforceable)
    }

    /// The whole point: every check answers, not just the one that decided.
    #[test]
    fn every_check_gets_a_line() {
        let out = rendered("version: 1", &facts(), &[]);

        for check in Check::ALL {
            assert!(
                out.contains(check.as_str()),
                "{} is missing from:\n{out}",
                check.as_str()
            );
        }
    }

    #[test]
    fn a_clean_package_is_allowed_and_says_so() {
        let out = rendered("version: 1", &facts(), &[]);

        assert!(out.contains("verdict: allow"), "{out}");
        assert!(!out.contains("FAIL"), "{out}");
    }

    #[test]
    fn a_failing_check_names_the_action_it_contributes() {
        let out = rendered(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
            &[],
        );

        assert!(out.contains("denials"), "{out}");
        assert!(out.contains("FAIL block"), "{out}");
        assert!(out.contains("this exact version is denied"), "{out}");
        assert!(out.contains("verdict: block"), "{out}");
    }

    /// A refusal that named only the strongest reason would hide the rest.
    #[test]
    fn two_failing_checks_are_both_shown_under_one_verdict() {
        let out = rendered(
            "version: 1\ncooldown_days: 3650\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
            &[],
        );

        assert!(out.contains("FAIL block"), "{out}");
        assert!(out.contains("FAIL quarantine"), "{out}");
        assert!(out.contains("published 2021-02-20"), "{out}");
        assert!(out.contains("verdict: block"), "{out}");
    }

    /// Quarantine lapses and block does not, so the difference is stated.
    #[test]
    fn a_quarantine_verdict_says_it_lapses() {
        let out = rendered("version: 1\ncooldown_days: 3650", &facts(), &[]);

        assert!(out.contains("verdict: quarantine"), "{out}");
        assert!(out.contains("lapses on its own"), "{out}");
    }

    #[test]
    fn an_excepted_check_names_the_entry_that_excused_it() {
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..facts()
        };
        let out = rendered(
            "version: 1\ncooldown_days: 0\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    permanent: true\n",
            &facts,
            &[],
        );

        assert!(out.contains("excepted"), "{out}");
        assert!(out.contains("packages[0] excused it"), "{out}");
        assert!(out.contains("would have been block"), "{out}");
        assert!(out.contains("verdict: allow"), "{out}");
    }

    /// `unenforced` is not `pass`. Reporting it as one would claim a check ran.
    #[test]
    fn a_check_with_no_fact_source_reads_as_unenforced_not_passed() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "the abbreviated packument carries no publish times",
        }];
        let facts = Facts {
            published: None,
            ..facts()
        };
        let out = rendered("version: 1\ncooldown_days: 30", &facts, &unenforceable);

        assert!(out.contains("unenforced"), "{out}");
        assert!(out.contains("carries no publish times"), "{out}");
        // The check failed inside the engine, and that is not what is shown.
        assert!(!out.contains("FAIL quarantine"), "{out}");
    }

    /// `n/a` is not `pass` either, and says which ecosystem it is not applicable to.
    #[test]
    fn a_check_with_no_meaning_for_the_ecosystem_reads_as_not_applicable() {
        let facts = Facts {
            ecosystem: "go".to_owned(),
            ..facts()
        };
        let out = rendered("version: 1", &facts, &[]);

        assert!(out.contains("n/a"), "{out}");
        assert!(out.contains("no meaning for go"), "{out}");
    }

    #[test]
    fn an_advisory_that_fired_is_named_by_id() {
        let facts = Facts {
            advisories: vec![Advisory {
                id: "CVE-2024-1234".to_owned(),
                cvss: 9.8,
                kev: true,
            }],
            ..facts()
        };
        let out = rendered("version: 1\nmax_cvss: 7.0", &facts, &[]);

        assert!(out.contains("CVE-2024-1234 9.8"), "{out}");
        assert!(out.contains("verdict: block"), "{out}");
    }

    #[test]
    fn the_purl_is_the_first_thing_printed() {
        let out = rendered("version: 1", &facts(), &[]);

        assert!(out.starts_with("pkg:npm/lodash@4.17.21\n"), "{out}");
    }

    #[test]
    fn the_policy_view_separates_a_check_that_is_off_from_one_with_no_source() {
        let out = policy(&loaded("version: 1\ncooldown_days: 0"), false);

        assert!(out.contains("cooldown_days     off"), "{out}");
        assert!(out.contains("unenforced, no advisory stream"), "{out}");
        assert!(out.contains("install_scripts   enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_reports_a_cooldown_as_enforced_once_it_is_set() {
        let out = policy(&loaded("version: 1\ncooldown_days: 30"), false);

        assert!(out.contains("cooldown_days     enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_lists_settings_and_entries() {
        let out = policy(
            &loaded(
                "version: 1\nmax_cvss: 7.5\n\
                 denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: m\n\
                 packages:\n  - match: { ecosystem: npm, name: lodash }\n\
                 \x20   set: { install_scripts: allow }\n    reason: reviewed\n\
                 \x20   permanent: true\n",
            ),
            true,
        );

        assert!(out.contains("max_cvss         7.5"), "{out}");
        assert!(out.contains("denials          1"), "{out}");
        assert!(out.contains("packages[0]  reviewed"), "{out}");
        // With a stream, the advisory checks stop being unenforced.
        assert!(!out.contains("no advisory stream"), "{out}");
    }
}
