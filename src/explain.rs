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

use std::ffi::OsString;

use crate::ecosystem::Clients;
use crate::env::Env;
use crate::identity::PackageRef;
use crate::intel::store::Intel as IntelStore;
use crate::policy::decide::{self, Advisory, Check, Decision, Facts, Intel, Outcome};
use crate::policy::enforce::Unenforceable;
use crate::policy::{Action, AdvisoryScore, Policy};
use jiff::civil::Date;

/// One line per check, then the verdict.
///
/// `policy` is the one `decision` was reached with. An excepted line names its entry's
/// expiry from it, and `max_cvss` names its advisories from the same split the check made.
pub fn decision(
    policy: &Policy,
    facts: &Facts,
    decision: &Decision,
    unenforceable: &[Unenforceable],
    as_of: Date,
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
                found(policy, facts, decision.entry, result.check, false, as_of),
            ),
            (None, Outcome::Excepted { entry, action }) => (
                "excepted".to_owned(),
                format!(
                    "would have been {}: {}; packages[{entry}] excused it, {}",
                    action.as_str(),
                    found(policy, facts, Some(*entry), result.check, true, as_of),
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
    as_of: Date,
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
                    .map(|a| match (decide::score(policy, a, as_of), &a.band) {
                        (None, _) => format!("{} unscored", a.id),
                        (Some((cvss, Some(i))), _) => {
                            format!("{} {cvss:.1} from {}", a.id, AdvisoryScore::label(i))
                        }
                        (Some((cvss, None)), Some(band)) => {
                            format!("{} {cvss:.1} from band {band}", a.id)
                        }
                        (Some((cvss, None)), None) => format!("{} {cvss:.1}", a.id),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let (counting, excused) = decide::over_max_cvss(policy, facts, entry, as_of);
            let unscored = counting
                .iter()
                .chain(&excused)
                .any(|a| decide::score(policy, a, as_of).is_none());
            let over = match unscored {
                true => format!("over max_cvss {} or unscored", policy.max_cvss),
                false => format!("over max_cvss {}", policy.max_cvss),
            };
            match (excepted, entry) {
                (true, _) => format!("{over}: {}", named(&excused)),
                (false, Some(entry)) if !excused.is_empty() => format!(
                    "{over}: {}; packages[{entry}] excused {}",
                    named(&counting),
                    named(&excused)
                ),
                (false, _) => format!("{over}: {}", named(&counting)),
            }
        }
        Check::InstallScripts => "declares an install script".to_owned(),
        Check::Deprecated => match facts.deprecated.as_deref() {
            Some(message) => format!("deprecated by its publisher: {message}"),
            None => "deprecated by its publisher".to_owned(),
        },
        Check::Yanked => match facts.yanked.as_deref() {
            Some(reason) if !reason.is_empty() => format!("withdrawn by the registry: {reason}"),
            _ => "withdrawn by the registry".to_owned(),
        },
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
pub fn policy_report(policy: &Policy, intel: Intel) -> String {
    let mut out = String::from("settings\n");
    out.push_str(&format!("  cooldown_days    {}\n", policy.cooldown_days));
    out.push_str(&format!("  max_cvss         {}\n", policy.max_cvss));
    out.push_str(&format!(
        "  install_scripts  {}\n",
        policy.install_scripts.as_str()
    ));
    out.push_str(&format!("  kev              {}\n", policy.kev.as_str()));
    out.push_str(&format!("  yanked           {}\n", policy.yanked.as_str()));
    out.push_str(&format!(
        "  deprecated       {}\n",
        policy.deprecated.as_str()
    ));
    out.push_str(&format!("  denials          {}\n", policy.denials.len()));
    out.push_str(&format!("  packages         {}\n", policy.packages.len()));
    out.push_str(&format!(
        "  advisory_scores  {}\n",
        policy.advisory_scores.len()
    ));

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
    for (index, score) in policy.advisory_scores.iter().enumerate() {
        out.push_str(&format!(
            "\n{}  {} {:.1}  {}\n",
            AdvisoryScore::label(index),
            score.advisory_id,
            score.cvss,
            score.reason
        ));
    }
    out
}

/// What `waharoa explain` prints and exits with.
///
/// `notes` are stderr lines without the command's prefix, `answer` is stdout.
#[derive(Debug, Default)]
pub struct Answered {
    pub notes: Vec<String>,
    pub answer: String,
    pub code: u8,
}

impl Answered {
    /// Nothing is answered: what stopped it is the last note.
    fn stop(mut self, code: u8) -> Self {
        self.code = code;
        self
    }
}

/// Answer `target` against the policy the environment names.
///
/// The same policy the proxy reads and the same engine, so an answer here and a refusal in
/// the proxy cannot disagree. Metadata is fetched from the package's own registry rather
/// than through a running proxy: explain is a question about the policy, and requiring the
/// proxy to be up to ask it would be the wrong dependency.
pub async fn run<L: Fn(&str) -> Option<OsString>>(
    target: &crate::cli::Explain,
    environment: &Env<L>,
) -> Answered {
    let mut out = Answered::default();
    let path = match environment.policy() {
        Ok(path) => path,
        Err(e) => {
            out.notes.push(e.to_string());
            return out.stop(2);
        }
    };
    let Some(path) = path else {
        out.notes.push(format!(
            "set {} to the policy file to explain",
            crate::env::POLICY
        ));
        return out.stop(2);
    };
    let policy = match crate::policy::Policy::load(&path) {
        Ok(policy) => policy,
        Err(e) => {
            out.notes.push(e.to_string());
            return out.stop(2);
        }
    };

    let store = match crate::intel::postgres::from_env(environment).await {
        Ok(store) => store,
        Err(e) => {
            out.notes.push(format!("{}: {e}", crate::env::DATABASE_URL));
            return out.stop(1);
        }
    };

    // `cli::Explain` holds `--policy` or a purl, never both and never neither.
    let Some(argument) = target.purl.as_deref() else {
        // A store with no snapshot answers nothing, so the checks that need one are
        // reported as unenforced rather than as settings that will fire.
        let intel = match &store {
            Some(store) => match store.snapshot().await {
                Ok(Some(snapshot)) => crate::policy::decide::Intel::Consulted {
                    exploitation_loaded: snapshot.exploitation_loaded(),
                },
                Ok(None) => crate::policy::decide::Intel::NotConsulted,
                Err(e) => {
                    out.notes.push(e.to_string());
                    return out.stop(1);
                }
            },
            None => crate::policy::decide::Intel::NotConsulted,
        };
        out.answer = policy_report(&policy, intel);
        return out;
    };

    let reference = match argument.parse::<PackageRef>() {
        Ok(reference) => reference,
        Err(e) => {
            out.notes
                .push(format!("`{argument}` is not a package reference: {e}"));
            return out.stop(2);
        }
    };

    // The package is asked of its own ecosystem's registry.
    let clients = match Clients::from_env(environment) {
        Ok(clients) => clients,
        Err(e) => {
            out.notes.push(e.to_string());
            return out.stop(2);
        }
    };
    let metadata = match crate::ecosystem::fetched(clients.metadata(reference.key()).await) {
        Ok(metadata) => metadata,
        Err(e) => {
            out.notes.push(e.to_string());
            return out.stop(1);
        }
    };
    let Some(package) = metadata.version(reference.version()) else {
        out.notes
            .push(format!("the registry does not publish {argument}"));
        return out.stop(1);
    };

    // Only when the policy asks for it, the same gate the proxy uses.
    // A cooldown that cannot be judged is an answer `explain` cannot give.
    let times = if policy.uses_cooldown() {
        match clients.publish_times(reference.key()).await {
            Ok(times) => times,
            Err(e) => {
                out.notes.push(e.to_string());
                return out.stop(1);
            }
        }
    } else {
        None
    };

    let store = store.as_ref().map(|store| store as &dyn IntelStore);
    let (ecosystem, name) = crate::intel::snapshot_intel::key_of(reference.key());
    let intel = match crate::intel::store::for_command(store, &ecosystem, &name, true).await {
        Ok(intel) => intel,
        Err(e) => {
            out.notes.push(e.to_string());
            return out.stop(1);
        }
    };
    let mut facts = crate::policy::decide::Facts::from_record_and_times(package, times.as_ref());
    if let Some(intel) = &intel {
        facts = facts.with_intel(intel);
    }
    let as_of = crate::policy::today();
    out.answer = decision(
        &policy,
        &facts,
        &crate::policy::decide::decide(&policy, &facts, as_of),
        &crate::policy::enforce::unenforceable(&policy, package, times.as_ref(), facts.intel),
        as_of,
    );
    out
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use crate::env::testing::with;
    use crate::util::test_support::{Answer, scripted, tempdir};

    fn written(label: &str, yaml: &str) -> std::path::PathBuf {
        let dir = tempdir(label);
        let path = dir.join("policy.yaml");
        std::fs::write(&path, yaml).expect("writes");
        path
    }

    fn asked(purl: Option<&str>) -> crate::cli::Explain {
        crate::cli::Explain {
            purl: purl.map(str::to_owned),
            policy: purl.is_none(),
        }
    }

    /// No policy configured: exit 2 and a line saying which variable to set.
    #[tokio::test]
    async fn without_a_policy_there_is_nothing_to_explain() {
        let answered = run(&asked(None), &with(&[])).await;
        assert_eq!(answered.code, 2);
        assert!(answered.answer.is_empty());
        assert_eq!(
            answered.notes,
            [format!(
                "set {} to the policy file to explain",
                crate::env::POLICY
            )]
        );
    }

    /// `--policy` prints what every check is set to, with no registry asked.
    #[tokio::test]
    async fn the_policy_is_explained_without_asking_a_registry() {
        let path = written("explain-policy", "version: 1\ncooldown_days: 7\n");
        let answered = run(
            &asked(None),
            &with(&[(crate::env::POLICY, &path.display().to_string())]),
        )
        .await;
        assert_eq!(answered.code, 0, "{:?}", answered.notes);
        assert!(
            answered.answer.contains("cooldown_days"),
            "{}",
            answered.answer
        );
        assert!(answered.notes.is_empty());
    }

    /// A purl that does not parse is exit 2, before anything is fetched.
    #[tokio::test]
    async fn a_purl_that_does_not_parse_is_refused() {
        let path = written("explain-purl", "version: 1\ncooldown_days: 0\n");
        let answered = run(
            &asked(Some("lodash")),
            &with(&[(crate::env::POLICY, &path.display().to_string())]),
        )
        .await;
        assert_eq!(answered.code, 2);
        assert!(
            answered.notes[0].starts_with("`lodash` is not a package reference"),
            "{:?}",
            answered.notes
        );
    }

    /// One package, judged against the registry the environment names.
    #[tokio::test]
    async fn a_version_the_registry_publishes_is_judged() {
        let packument = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        let addr = scripted(vec![Answer::body(packument)]).await;
        let path = written("explain-version", "version: 1\ncooldown_days: 0\n");
        let answered = run(
            &asked(Some("pkg:npm/lodash@4.17.21")),
            &with(&[
                (crate::env::POLICY, &path.display().to_string()),
                (crate::env::UPSTREAM_NPM, &format!("http://{addr}")),
            ]),
        )
        .await;
        assert_eq!(answered.code, 0, "{:?}", answered.notes);
        assert!(
            answered.answer.contains("pkg:npm/lodash@4.17.21"),
            "{}",
            answered.answer
        );
        assert!(
            answered.answer.contains("verdict: allow"),
            "{}",
            answered.answer
        );
    }

    /// A version the registry does not publish is exit 1, and says so.
    #[tokio::test]
    async fn a_version_the_registry_does_not_publish_is_reported() {
        let packument = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        let addr = scripted(vec![Answer::body(packument)]).await;
        let path = written("explain-absent", "version: 1\ncooldown_days: 0\n");
        let answered = run(
            &asked(Some("pkg:npm/lodash@9.9.9")),
            &with(&[
                (crate::env::POLICY, &path.display().to_string()),
                (crate::env::UPSTREAM_NPM, &format!("http://{addr}")),
            ]),
        )
        .await;
        assert_eq!(answered.code, 1);
        assert_eq!(
            answered.notes,
            ["the registry does not publish pkg:npm/lodash@9.9.9"]
        );
    }
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
            yanked: None,
            deprecated: None,
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
            TODAY,
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
            yanked: None,
            deprecated: None,
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
                    cvss: Some(9.8),
                    band: None,
                    kev: true,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-0000-0000-0000".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(8.9),
                    band: Some("HIGH".to_owned()),
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-1111-1111-1111".to_owned(),
                    aliases: Vec::new(),
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-2222-2222-2222".to_owned(),
                    aliases: Vec::new(),
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
            ],
            ..facts()
        };
        let out = rendered(
            "version: 1\nmax_cvss: 7.0\nadvisory_scores:\n  - { advisory_id: GHSA-2222-2222-2222, \
             cvss: 7.5, reason: vendor, permanent: true }\n",
            &facts,
            &[],
        );

        assert!(
            out.contains(
                "over max_cvss 7 or unscored: CVE-2024-1234 9.8, \
                 GHSA-0000-0000-0000 8.9 from band HIGH, GHSA-1111-1111-1111 unscored, \
                 GHSA-2222-2222-2222 7.5 from advisory_scores[0]"
            ),
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
        let out = policy_report(&loaded("version: 1\ncooldown_days: 0"), Intel::NotConsulted);

        assert!(out.contains("cooldown_days     off"), "{out}");
        assert!(out.contains("unenforced, no advisory stream"), "{out}");
        assert!(out.contains("install_scripts   enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_reports_a_cooldown_as_enforced_once_it_is_set() {
        let out = policy_report(
            &loaded("version: 1\ncooldown_days: 30"),
            Intel::NotConsulted,
        );

        assert!(out.contains("cooldown_days     enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_lists_settings_and_entries() {
        let out = policy_report(
            &loaded(
                "version: 1\nmax_cvss: 7.5\n\
                 denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: m\n\
                 packages:\n  - match: { ecosystem: npm, name: lodash }\n\
                 \x20   set: { install_scripts: allow }\n    reason: reviewed\n\
                 \x20   permanent: true\n\
                 advisory_scores:\n  - { advisory_id: GHSA-x, cvss: 7.5, reason: vendor \
                 scored it, permanent: true }\n",
            ),
            Intel::Consulted {
                exploitation_loaded: false,
            },
        );

        assert!(out.contains("advisory_scores  1"), "{out}");
        assert!(
            out.contains("\nadvisory_scores[0]  GHSA-x 7.5  vendor scored it\n"),
            "{out}"
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
            cvss: Some(cvss),
            band: None,
            kev,
            sources: vec!["osv".to_owned()],
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
                "over max_cvss, an entry that excuses none of it",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-9\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
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
                "max_cvss, an unscored advisory and one scored in policy",
                "version: 1\nmax_cvss: 7.0\nadvisory_scores:\n  - { advisory_id: CVE-2024-2, cvss: 8.0, reason: vendor, permanent: true }\n",
                Facts {
                    advisories: vec![
                        Advisory {
                            cvss: None,
                            ..advisory("CVE-2024-1", &[], 0.0, false)
                        },
                        Advisory {
                            cvss: None,
                            ..advisory("CVE-2024-2", &[], 0.0, false)
                        },
                    ],
                    ..consulted()
                },
            ),
            case(
                "max_cvss, an unscored advisory excepted by id",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![Advisory {
                        cvss: None,
                        ..advisory("CVE-2024-1", &[], 0.0, false)
                    }],
                    ..consulted()
                },
            ),
            case(
                "install script",
                "version: 1\ninstall_scripts: block",
                Facts {
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
                    ..consulted()
                },
            ),
            case(
                "install script, excepted",
                "version: 1\ninstall_scripts: block\npackages:\n  - match: { ecosystem: npm, name: lodash, has_install_scripts: true }\n    set: { install_scripts: allow }\n    reason: reviewed\n    expires: \"2026-10-01\"\n",
                Facts {
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
                    ..consulted()
                },
            ),
            case(
                "deprecated, which is allowed unless a policy says otherwise",
                "version: 1\ndeprecated: block",
                Facts {
                    deprecated: Some("no longer supported, use rimraf@4".to_owned()),
                    ..consulted()
                },
            ),
            case(
                "yanked, with the reason the publisher gave",
                "version: 1",
                Facts {
                    ecosystem: "pypi".to_owned(),
                    yanked: Some(
                        "Yanked due to conflicts with CVE-2024-35195 mitigation".to_owned(),
                    ),
                    ..consulted()
                },
            ),
            case(
                "yanked, no reason given",
                "version: 1",
                Facts {
                    ecosystem: "pypi".to_owned(),
                    yanked: Some(String::new()),
                    ..consulted()
                },
            ),
            case(
                "install script, an ecosystem with no install step",
                "version: 1\ninstall_scripts: block",
                Facts {
                    ecosystem: "go".to_owned(),
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
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
                TODAY,
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
        policy_report(p, intel)
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
