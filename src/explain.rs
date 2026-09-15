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

use crate::policy::decide::{self, Advisory, Check, Decision, Facts, Intel, Outcome};
use crate::policy::enforce::Unenforceable;
use crate::policy::{Action, Policy};

/// One line per check, then the verdict.
///
/// `policy` is the one `decision` was reached with. An excepted line names its entry's
/// expiry from it, and `max_cvss` names its advisories from the same split the check made.
pub fn decision(
    policy: &Policy,
    facts: &Facts,
    decision: &Decision,
    unenforceable: &[Unenforceable],
) -> String {
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
                found(policy, facts, decision.entry, result.check, false),
            ),
            (None, Outcome::Excepted { entry, action }) => (
                "excepted".to_owned(),
                format!(
                    "would have been {}: {}; packages[{entry}] excused it, {}",
                    action.as_str(),
                    found(policy, facts, Some(*entry), result.check, true),
                    lasts(policy, *entry)
                ),
            ),
        };
        let line = format!("  {:width$}  {:16}  {detail}", result.check.as_str(), state);
        out.push_str(line.trim_end());
        out.push('\n');
    }

    // The verdict is the strongest answer above, not a separate judgement, and an
    // unenforced line is not one of the answers: the proxy drops it before it acts.
    let verdict = crate::policy::enforce::enforced(decision, unenforceable).action();
    out.push_str(&format!("\n  verdict: {}\n", verdict.as_str()));
    if verdict == Action::Quarantine {
        out.push_str("  quarantine lapses on its own; block does not\n");
    }
    out
}

/// What a check found, in the terms the operator wrote.
///
/// `excepted` is whether the check's outcome was `Excepted`, which changes what `max_cvss`
/// and `cooldown_days` name: what was excused, and the wait the exception was measured
/// against.
fn found(
    policy: &Policy,
    facts: &Facts,
    entry: Option<usize>,
    check: Check,
    excepted: bool,
) -> String {
    match check {
        Check::Denials => "this exact version is denied".to_owned(),
        Check::KnownMalware => "reported as malware; this has no exception".to_owned(),
        Check::CooldownDays => {
            // Excepted, the wait worth naming is the global one the package failed. Failed,
            // it is the wait that applied, which an exception may have shortened.
            let wait = match entry.filter(|_| !excepted) {
                Some(i) if decide::cooldown_required(policy, entry) != policy.cooldown_days => {
                    format!(
                        "cooldown_days {}, from packages[{i}]",
                        decide::cooldown_required(policy, entry)
                    )
                }
                _ => format!("cooldown_days {}", policy.cooldown_days),
            };
            match facts.published {
                Some(published) => format!("published {published}, {wait}"),
                None => format!("no publish date, which is not old enough for {wait}"),
            }
        }
        Check::Kev => facts
            .advisories
            .iter()
            .filter(|a| a.kev)
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Check::MaxCvss => {
            let named = |advisories: &[&Advisory]| {
                advisories
                    .iter()
                    .map(|a| match &a.band {
                        Some(band) => format!("{} {:.1} from band {band}", a.id, a.cvss),
                        None => format!("{} {:.1}", a.id, a.cvss),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let (counting, excused) = decide::over_max_cvss(policy, facts, entry);
            match (excepted, entry) {
                (true, _) => format!("over max_cvss {}: {}", policy.max_cvss, named(&excused)),
                (false, Some(entry)) if !excused.is_empty() => format!(
                    "over max_cvss {}: {}; packages[{entry}] excused {}",
                    policy.max_cvss,
                    named(&counting),
                    named(&excused)
                ),
                (false, _) => format!("over max_cvss {}: {}", policy.max_cvss, named(&counting)),
            }
        }
        Check::InstallScripts => "declares an install script".to_owned(),
    }
}

/// How long an entry lasts, as the file says.
fn lasts(policy: &Policy, entry: usize) -> String {
    match policy.packages.get(entry) {
        Some(e) if e.permanent => "permanent".to_owned(),
        Some(e) => e
            .expires
            .as_ref()
            .map_or("no expiry".to_owned(), |d| format!("expires {}", d.0)),
        None => "which this policy does not have".to_owned(),
    }
}

/// The policy as loaded, and which of its checks can actually fire.
///
/// Separate from the settings themselves because a configured check with no fact source is
/// not the same as one that is off, and reading the file cannot tell them apart.
pub fn policy(policy: &Policy, intel: Intel) -> String {
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
        // `enforce::unenforceable` gives the same answers for a package.
        let state = match (check, intel) {
            (Check::MaxCvss | Check::KnownMalware | Check::Kev, Intel::NotConsulted) => {
                "unenforced, no advisory stream"
            }
            (
                Check::Kev,
                Intel::Consulted {
                    exploitation_loaded: false,
                },
            ) => "unenforced, no exploitation stream",
            (Check::CooldownDays, _) if !policy.uses_cooldown() => "off",
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
        decision(
            &policy,
            facts,
            &decide(&policy, facts, TODAY),
            unenforceable,
        )
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
            advisories: vec![
                Advisory {
                    id: "CVE-2024-1234".to_owned(),
                    aliases: Vec::new(),
                    cvss: 9.8,
                    band: None,
                    kev: true,
                },
                Advisory {
                    id: "GHSA-0000-0000-0000".to_owned(),
                    aliases: Vec::new(),
                    cvss: 8.9,
                    band: Some("HIGH".to_owned()),
                    kev: false,
                },
            ],
            ..facts()
        };
        let out = rendered("version: 1\nmax_cvss: 7.0", &facts, &[]);

        assert!(
            out.contains("CVE-2024-1234 9.8, GHSA-0000-0000-0000 8.9 from band HIGH"),
            "{out}"
        );
        assert!(out.contains("verdict: block"), "{out}");
    }

    #[test]
    fn the_purl_is_the_first_thing_printed() {
        let out = rendered("version: 1", &facts(), &[]);

        assert!(out.starts_with("pkg:npm/lodash@4.17.21\n"), "{out}");
    }

    #[test]
    fn the_policy_view_separates_a_check_that_is_off_from_one_with_no_source() {
        let out = policy(&loaded("version: 1\ncooldown_days: 0"), Intel::NotConsulted);

        assert!(out.contains("cooldown_days     off"), "{out}");
        assert!(out.contains("unenforced, no advisory stream"), "{out}");
        assert!(out.contains("install_scripts   enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_reports_a_cooldown_as_enforced_once_it_is_set() {
        let out = policy(
            &loaded("version: 1\ncooldown_days: 30"),
            Intel::NotConsulted,
        );

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
            Intel::Consulted {
                exploitation_loaded: false,
            },
        );

        assert!(out.contains("max_cvss         7.5"), "{out}");
        assert!(out.contains("denials          1"), "{out}");
        assert!(out.contains("packages[0]  reviewed"), "{out}");
        // A store without the KEV catalogue enforces every advisory check but `kev`.
        assert!(!out.contains("no advisory stream"), "{out}");
        assert!(out.contains("max_cvss          enforced"), "{out}");
        assert!(out.contains("known_malware     enforced"), "{out}");
        assert!(
            out.contains("kev               unenforced, no exploitation stream"),
            "{out}"
        );
    }

    fn golden(name: &str, actual: &str) {
        crate::golden::assert_matches("explain", name, actual);
    }

    struct Case {
        name: &'static str,
        policy: &'static str,
        facts: Facts,
        unenforceable: Vec<Unenforceable>,
    }

    fn advisory(id: &str, aliases: &[&str], cvss: f64, kev: bool) -> Advisory {
        Advisory {
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            cvss,
            band: None,
            kev,
        }
    }

    /// Every state each check can reach, and the exception cases around them.
    fn cases() -> Vec<Case> {
        let consulted = || Facts {
            intel: Intel::Consulted {
                exploitation_loaded: true,
            },
            ..facts()
        };
        let young = || Facts {
            published: Some(jiff::civil::date(2026, 9, 11)),
            ..consulted()
        };
        let case = |name, policy, facts| Case {
            name,
            policy,
            facts,
            unenforceable: Vec::new(),
        };
        vec![
            case("nothing found", "version: 1", consulted()),
            case(
                "denied",
                "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: compromised\n",
                consulted(),
            ),
            case(
                "known malware",
                "version: 1",
                Facts {
                    known_malware: true,
                    ..consulted()
                },
            ),
            case("too young", "version: 1\ncooldown_days: 7", young()),
            case(
                "no publish date",
                "version: 1\ncooldown_days: 7",
                Facts {
                    published: None,
                    ..consulted()
                },
            ),
            case(
                "too young, excepted",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: internal\n    permanent: true\n",
                young(),
            ),
            case(
                "too young, exception shortens the wait and not enough",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 3 }\n    reason: internal\n    expires: \"2026-10-01\"\n",
                young(),
            ),
            case(
                "too young, the narrowest matching entry applies",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: \"lod*\" }\n    set: { cooldown_days: 5 }\n    reason: broad\n    permanent: true\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: narrow\n    expires: \"2026-10-01\"\n",
                young(),
            ),
            case(
                "too young, the exception lapsed",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: internal\n    expires: \"2026-09-01\"\n",
                young(),
            ),
            Case {
                unenforceable: vec![Unenforceable {
                    check: Check::CooldownDays,
                    why: "the abbreviated packument carries no publish times",
                }],
                ..case(
                    "cooldown with no publish times to read",
                    "version: 1\ncooldown_days: 7",
                    Facts {
                        published: None,
                        ..consulted()
                    },
                )
            },
            case(
                "exploited",
                "version: 1\nmax_cvss: 6.9\nkev: block",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "exploited, excepted",
                "version: 1\nmax_cvss: 6.9\nkev: block\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { kev: allow }\n    reason: mitigated\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "exploited, kev: allow",
                "version: 1\nmax_cvss: 6.9\nkev: allow",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, one advisory under it",
                "version: 1\nmax_cvss: 7.0",
                Facts {
                    advisories: vec![
                        advisory("CVE-2024-1", &[], 9.8, false),
                        advisory("CVE-2024-2", &[], 5.3, false),
                    ],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, excepted by id",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, excepted by alias",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("GHSA-aaaa-bbbb-cccc", &["CVE-2024-1"], 9.8, false)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, one excused and one not",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![
                        advisory("GHSA-aaaa-bbbb-cccc", &["CVE-2024-1"], 9.8, false),
                        advisory("GHSA-dddd-eeee-ffff", &["CVE-2024-3"], 7.5, false),
                    ],
                    ..consulted()
                },
            ),
            case(
                "install script",
                "version: 1\ninstall_scripts: block",
                Facts {
                    has_install_scripts: true,
                    ..consulted()
                },
            ),
            case(
                "install script, excepted",
                "version: 1\ninstall_scripts: block\npackages:\n  - match: { ecosystem: npm, name: lodash, has_install_scripts: true }\n    set: { install_scripts: allow }\n    reason: reviewed\n    expires: \"2026-10-01\"\n",
                Facts {
                    has_install_scripts: true,
                    ..consulted()
                },
            ),
            case(
                "install script, an ecosystem with no install step",
                "version: 1\ninstall_scripts: block",
                Facts {
                    ecosystem: "go".to_owned(),
                    has_install_scripts: true,
                    ..consulted()
                },
            ),
            Case {
                unenforceable: [Check::KnownMalware, Check::Kev, Check::MaxCvss]
                    .map(|check| Unenforceable {
                        check,
                        why: "no intel store was consulted, so nothing was asked",
                    })
                    .to_vec(),
                ..case("no intel store", "version: 1", facts())
            },
            case(
                "several at once",
                "version: 1\ncooldown_days: 7\nmax_cvss: 7.0\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: compromised\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
                    ..young()
                },
            ),
        ]
    }

    #[test]
    fn every_reachable_state_renders_as_the_golden_file_says() {
        let mut out = String::new();
        for c in cases() {
            let policy = loaded(c.policy);
            out.push_str(&format!("=== {}\n", c.name));
            for line in c.policy.lines() {
                out.push_str(&format!("  | {line}\n"));
            }
            out.push('\n');
            out.push_str(&decision(
                &policy,
                &c.facts,
                &decide(&policy, &c.facts, TODAY),
                &c.unenforceable,
            ));
            out.push('\n');
        }
        golden("decisions.txt", &out);
    }

    #[test]
    fn the_policy_view_renders_as_the_golden_file_says() {
        let shipped = || loaded(include_str!("../examples/policy.yaml"));
        let mut out = String::new();
        for (name, policy, intel) in [
            (
                "version: 1, no store",
                loaded("version: 1"),
                Intel::NotConsulted,
            ),
            (
                "version: 1, cooldown_days: 0, no store",
                loaded("version: 1\ncooldown_days: 0"),
                Intel::NotConsulted,
            ),
            (
                "examples/policy.yaml, a store without the KEV catalogue",
                shipped(),
                Intel::Consulted {
                    exploitation_loaded: false,
                },
            ),
            (
                "examples/policy.yaml, a store with the KEV catalogue",
                shipped(),
                Intel::Consulted {
                    exploitation_loaded: true,
                },
            ),
        ] {
            out.push_str(&format!("=== {name}\n"));
            out.push_str(&policy_view(&policy, intel));
            out.push('\n');
        }
        golden("policy.txt", &out);
    }

    fn policy_view(p: &Policy, intel: Intel) -> String {
        policy(p, intel)
    }

    #[test]
    fn an_excepted_line_says_whether_its_entry_expires() {
        let yaml = "version: 1\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
                    set: { install_scripts: allow }\n    reason: t\n    permanent: true\n";
        let permanent = loaded(yaml);
        assert_eq!(lasts(&permanent, 0), "permanent");
        assert_eq!(lasts(&permanent, 1), "which this policy does not have");
        let mut open = loaded(yaml);
        open.packages[0].permanent = false;
        assert_eq!(lasts(&open, 0), "no expiry");
    }
}
