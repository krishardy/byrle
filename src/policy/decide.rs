//! Judging one package against a policy.
//!
//! Every check runs. Each appends one result to a decision vector, and the disposition is
//! the strongest action in it. See `docs/engineering_decisions/policy-tier-resolution.md`
//! for the flow chart this implements.
//!
//! # Why not stop at the first failure
//!
//! The outcome would be identical: every check must pass for a package to be delivered,
//! so the decision is a plain conjunction. What changes is what is known when the answer
//! is given. A package both too young and carrying a known-exploited vulnerability
//! reports both, rather than only the reason that lapses on its own, which would send an
//! operator to grant an age exception and find it still refused.
//!
//! The cost is that a check runs after one has already failed. Here that is reading
//! fields off a struct. Gathering the facts can cost more: publish times for
//! `cooldown_days` are a full-packument request, made before this runs. Stage 4's
//! expensive analysis is the exception and short-circuits in front of this.
//!
//! # Facts come from somewhere else
//!
//! This evaluates a policy against facts, and does not gather them. `Facts` is what the
//! intel layer and the packument between them have to supply, written down as a type so
//! the engine can be built and tested before either exists.

use super::merge::{self, Rule};
use super::selector::Canonical;
use super::{Action, Policy};
use jiff::civil::Date;

/// What the policy is asked about one package.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    /// As the policy file spells it, not [`crate::identity::Ecosystem`]: a policy may
    /// name an ecosystem no adapter exists for.
    pub ecosystem: String,
    /// The name the registry uses, scope included.
    pub name: String,
    pub version: String,
    /// When this version was published. `None` when the registry did not say, which is
    /// not the same as "old enough".
    pub published: Option<Date>,
    pub known_malware: bool,
    /// Advisories against this version.
    pub advisories: Vec<Advisory>,
    /// Whether an advisory stream was asked at all.
    ///
    /// An empty `advisories` with `known_malware` false means two different things: a
    /// package nothing is known against, or a build with nothing to ask. The checks that
    /// read them cannot tell those apart, so the caller says which it is. Same distinction
    /// `intel::Capabilities::gaps` reports at startup.
    pub intel: Intel,
    pub has_install_scripts: bool,
}

/// Whether anything was in a position to answer about advisories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intel {
    /// A stream answered. Empty advisories mean nothing is known against this version.
    Consulted {
        /// Whether the answer included the KEV catalogue. Without it, no advisory is marked
        /// exploited because nothing was asked.
        exploitation_loaded: bool,
    },
    /// No stream exists or none covers this ecosystem. Empty advisories mean nothing was
    /// asked, which is not the same as nothing found.
    NotConsulted,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    /// The other ids it is known by. A GHSA advisory's CVE id is here.
    pub aliases: Vec<String>,
    /// `None` when no stream scored it. `max_cvss` refuses it until `advisory_scores` gives
    /// it a score.
    pub cvss: Option<f64>,
    /// The severity band `cvss` was read from, for `explain`. `None` when a vector gave it.
    pub band: Option<String>,
    /// Whether this advisory is in a known-exploited catalogue.
    ///
    /// A property of the advisory, not of the package: a KEV entry carries a `cveID` and
    /// no package identifier of any kind. See
    /// `docs/engineering_decisions/advisory-stream-licences.md`.
    pub kev: bool,
    /// Every stream that reported this advisory, sorted and once each.
    ///
    /// OSV and GitHub are signal streams checked independently, and both publish `GHSA-`
    /// ids, so one advisory is commonly reported twice. That is corroboration rather than
    /// two vulnerabilities: `decide` gives each check one result, and this is the set the
    /// result was reached over. Empty only for an advisory built without intel.
    pub sources: Vec<String>,
}

impl Advisory {
    /// Whether `id` is this advisory's id or one of its aliases. A `vuln_advisory_ids` exception
    /// names a CVE, and OSV stores the advisory under its GHSA id.
    pub fn is_named(&self, id: &str) -> bool {
        crate::intel::is_named(&self.id, &self.aliases, id)
    }
}

/// One check this build performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Denials,
    KnownMalware,
    CooldownDays,
    Kev,
    MaxCvss,
    InstallScripts,
}

impl Check {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denials => "denials",
            Self::KnownMalware => "known_malware",
            Self::CooldownDays => "cooldown_days",
            Self::Kev => "kev",
            Self::MaxCvss => "max_cvss",
            Self::InstallScripts => "install_scripts",
        }
    }

    /// Every check, in the order the flow chart draws them. One list, so a check added to
    /// the engine and not here is a compile error rather than one silently never run.
    pub const ALL: [Check; 6] = [
        Self::Denials,
        Self::KnownMalware,
        Self::CooldownDays,
        Self::Kev,
        Self::MaxCvss,
        Self::InstallScripts,
    ];

    /// Whether an exception can excuse this check.
    ///
    /// Fixed here rather than configured. A denial and known malware have no exception
    /// branch in the flow chart, which is what makes them the two an operator cannot
    /// write their way past.
    pub fn exceptable(self) -> bool {
        !matches!(self, Self::Denials | Self::KnownMalware)
    }
}

/// What one check decided.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The check had nothing against this package.
    Passed,
    /// It did, and this is what it contributes.
    Failed(Action),
    /// It did, and an exception excused it. Carries the entry, so an audit trail can say
    /// which one and a review can find the ones doing work.
    Excepted { entry: usize, action: Action },
    /// The check has no meaning for this ecosystem. Not the same as `Passed`: reporting
    /// it as one would claim a check ran that never could.
    NotApplicable,
}

impl Outcome {
    /// What this contributes to the decision. Three of the four contribute `allow`.
    pub fn action(&self) -> Action {
        match self {
            Self::Failed(action) => *action,
            Self::Passed | Self::Excepted { .. } | Self::NotApplicable => Action::Allow,
        }
    }

    /// Whether the check found something, whatever was then done about it.
    pub fn found_something(&self) -> bool {
        matches!(self, Self::Failed(_) | Self::Excepted { .. })
    }
}

/// One check and what it decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Result {
    pub check: Check,
    pub outcome: Outcome,
}

/// Every check, and the disposition taken from them.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub results: Vec<Result>,
    /// The `packages` entry that applied, if any, whether or not it excused anything.
    pub entry: Option<usize>,
}

impl Decision {
    /// The strongest action in the vector.
    ///
    /// `Action::strength` is the lattice order, proved. Under a short circuit no two
    /// actions were ever combined and the lattice did no work.
    pub fn action(&self) -> Action {
        self.results
            .iter()
            .map(|r| r.outcome.action())
            .max_by_key(|a| a.strength())
            .unwrap_or(Action::Allow)
    }

    /// Whether the package is delivered.
    pub fn delivered(&self) -> bool {
        self.action() == Action::Allow
    }

    /// The checks that decided against the package, strongest first. What `explain` leads
    /// with and what a refusal says.
    pub fn reasons(&self) -> Vec<&Result> {
        let mut reasons: Vec<&Result> = self
            .results
            .iter()
            .filter(|r| r.outcome.action() != Action::Allow)
            .collect();
        reasons.sort_by_key(|r| std::cmp::Reverse(r.outcome.action().strength()));
        reasons
    }

    /// The exceptions that did work. An entry that never appears here is doing none.
    pub fn exceptions_used(&self) -> Vec<usize> {
        let mut used: Vec<usize> = self
            .results
            .iter()
            .filter_map(|r| match r.outcome {
                Outcome::Excepted { entry, .. } => Some(entry),
                _ => None,
            })
            .collect();
        used.sort_unstable();
        used.dedup();
        used
    }
}

/// Judge one package.
///
/// `as_of` decides both whether a package is old enough and whether an exception has
/// lapsed, and is an argument rather than the clock so `policy diff --as-of` can ask what
/// a policy says on another day.
pub fn decide(policy: &Policy, facts: &Facts, as_of: Date) -> Decision {
    let selectors = policy.selectors();
    let entry = most_specific_match(policy, &selectors, facts, as_of);

    let results = Check::ALL
        .iter()
        .map(|&check| Result {
            check,
            outcome: run(policy, facts, check, entry, as_of),
        })
        .collect();

    Decision { results, entry }
}

/// The wait that applies to a package: the exception's where it sets one, else the global
/// setting.
pub fn cooldown_required(policy: &Policy, entry: Option<usize>) -> u32 {
    entry
        .and_then(|i| policy.packages[i].set.cooldown_days)
        .unwrap_or(policy.cooldown_days)
}

/// The advisories over `max_cvss` or with no score, split into those that still count and
/// those the exception names by id or alias.
///
/// Public so `explain` names the advisories from the same split the check decided on.
pub fn over_max_cvss<'a>(
    policy: &Policy,
    facts: &'a Facts,
    entry: Option<usize>,
    as_of: Date,
) -> (Vec<&'a Advisory>, Vec<&'a Advisory>) {
    let ignored = entry
        .map(|i| policy.packages[i].set.vuln_advisory_ids.as_slice())
        .unwrap_or(&[]);
    facts
        .advisories
        .iter()
        .filter(|a| score(policy, a, as_of).is_none_or(|(cvss, _)| cvss > policy.max_cvss))
        .partition(|a| !ignored.iter().any(|id| a.is_named(id)))
}

/// The score `max_cvss` compares for an advisory, and the `advisory_scores` entry it came
/// from when the advisory has none of its own.
///
/// A stored score is used whatever the policy says. Otherwise the highest score among the
/// entries in force on `as_of` naming the advisory by id or alias. `None` is unscored.
pub fn score(policy: &Policy, advisory: &Advisory, as_of: Date) -> Option<(f64, Option<usize>)> {
    if let Some(cvss) = advisory.cvss {
        return Some((cvss, None));
    }
    policy
        .advisory_scores
        .iter()
        .enumerate()
        .filter(|(_, s)| s.in_force(as_of) && advisory.is_named(&s.advisory_id))
        .max_by(|(_, a), (_, b)| a.cvss.total_cmp(&b.cvss))
        .map(|(i, s)| (s.cvss, Some(i)))
}

/// The exception that applies, if any.
///
/// Most specific wins, by strict subset containment. Overlapping entries that cannot be
/// ordered are refused at load, so whatever matches here forms a chain and the narrowest
/// is unique.
///
/// A lapsed entry does not match at all, which is what makes an expiry do anything.
fn most_specific_match(
    policy: &Policy,
    selectors: &[Canonical],
    facts: &Facts,
    as_of: Date,
) -> Option<usize> {
    let mut winner: Option<usize> = None;
    for (i, selector) in selectors.iter().enumerate() {
        let entry = &policy.packages[i];
        if entry.expires.is_some_and(|e| e.has_passed(as_of)) {
            continue;
        }
        if !selector.matches(
            &facts.ecosystem,
            &facts.name,
            &facts.version,
            facts.has_install_scripts,
        ) {
            continue;
        }
        winner = match winner {
            None => Some(i),
            Some(current) if selector.strictly_contained_by(&selectors[current]) => Some(i),
            Some(current) => Some(current),
        };
    }
    winner
}

/// Run one check.
fn run(policy: &Policy, facts: &Facts, check: Check, entry: Option<usize>, as_of: Date) -> Outcome {
    let set = entry.map(|i| &policy.packages[i].set);

    match check {
        // No exception branch: a denial is absolute.
        Check::Denials => {
            // Parsed, not string-compared. `pkg:npm/%40babel/core@1.0.0` and
            // `pkg:npm/@babel/core@1.0.0` are the same package, and the first is what
            // this codebase's own `Display` emits and what OSV publishes. Comparing the
            // written forms made a denial spelled the canonical way never fire, while the
            // same spelling in a `packages` selector matched. A denial is matched as a
            // selector is, so a VERS range and a PyPI version read the same way in both.
            let denied = policy.denial_selectors().iter().any(|d| {
                d.matches(
                    &facts.ecosystem,
                    &facts.name,
                    &facts.version,
                    facts.has_install_scripts,
                )
            });
            if denied {
                Outcome::Failed(Action::Block)
            } else {
                Outcome::Passed
            }
        }

        // No exception branch either: behaviour rather than policy.
        Check::KnownMalware => {
            if facts.known_malware {
                Outcome::Failed(Action::Block)
            } else {
                Outcome::Passed
            }
        }

        // Quarantine, not block: it lapses as the package ages. A package whose
        // publication date is unknown is treated as too young, because "we do not know"
        // is not "old enough".
        Check::CooldownDays => {
            // Zero days of waiting is satisfied by everything, including a package
            // whose publish date is unknown: there is no wait for it to be inside. This
            // is how the check is turned off, and without the short circuit it fails
            // every package the registry published no time for.
            let waited = |days: u32| {
                days == 0
                    || facts.published.is_some_and(|published| {
                        // A date so far out it cannot be represented is not a date this
                        // package will ever reach, so it is not old enough.
                        published
                            .checked_add(jiff::Span::new().days(i64::from(days)))
                            .is_ok_and(|ready| ready <= as_of)
                    })
            };
            if waited(policy.cooldown_days) {
                Outcome::Passed
            } else if let Some(entry) = entry.filter(|_| waited(cooldown_required(policy, entry))) {
                // Too young for the global wait and old enough for the exception's, so the
                // exception is what let it through: the flow chart's
                // `RECORD_cooldown_EXCEPTED`.
                Outcome::Excepted {
                    entry,
                    action: Action::Quarantine,
                }
            } else {
                // No exception, or one that shortened the wait and not enough. Either way
                // no exception let anything through.
                Outcome::Failed(Action::Quarantine)
            }
        }

        // Read from the advisories as they came, never from the list `vuln_advisory_ids` has
        // filtered. Excepting an advisory by id says it is not reachable from this code;
        // it says nothing about whether it is being exploited in the wild, and letting
        // one stand for the other would dismiss the broader finding by accident.
        //
        // "None at all" and "all of them excused" are different answers, and only the
        // second is an exception doing work, so both questions are asked.
        Check::Kev => {
            let exploited: Vec<&Advisory> = facts.advisories.iter().filter(|a| a.kev).collect();
            if exploited.is_empty() {
                return Outcome::Passed;
            }
            // The exception is per package, so the subtraction is all or nothing. Written
            // as a subtraction anyway, because a per-advisory list would be the same
            // shape and would change nothing else here.
            let excused = set.and_then(|s| s.kev) == Some(Action::Allow);
            let remaining = if excused { 0 } else { exploited.len() };

            match (remaining, entry) {
                (0, Some(entry)) => Outcome::Excepted {
                    entry,
                    action: policy.kev,
                },
                _ if policy.kev == Action::Allow => Outcome::Passed,
                (0, None) => Outcome::Passed,
                _ => Outcome::Failed(policy.kev),
            }
        }

        // Advisories the exception names are ignored; the rest are compared against the
        // threshold. Narrower than raising the threshold, which would apply to every
        // advisory this package acquires later. An advisory with no score is refused, as
        // "not known" is not "low".
        Check::MaxCvss => {
            let (counting, excused) = over_max_cvss(policy, facts, entry, as_of);
            match (counting.is_empty(), excused.is_empty(), entry) {
                (false, _, _) => Outcome::Failed(Action::Block),
                // Something was over the threshold and the exception named all of it, so
                // the exception is what saved it.
                (true, false, Some(entry)) => Outcome::Excepted {
                    entry,
                    action: Action::Block,
                },
                _ => Outcome::Passed,
            }
        }

        Check::InstallScripts => {
            if !merge::applies(&facts.ecosystem, Rule::InstallScripts) {
                return Outcome::NotApplicable;
            }
            on_off(
                facts.has_install_scripts,
                policy.install_scripts,
                set.and_then(|s| s.install_scripts),
                entry,
            )
        }
    }
}

/// A check that is on or off, with an exception that can turn it off for one package.
fn on_off(
    found: bool,
    setting: Action,
    exception: Option<Action>,
    entry: Option<usize>,
) -> Outcome {
    if !found {
        return Outcome::Passed;
    }
    match (exception, entry) {
        // The exception turned the check off, and the check had something to say, so the
        // exception is what let this package through.
        (Some(Action::Allow), Some(entry)) => Outcome::Excepted {
            entry,
            action: setting,
        },
        _ if setting == Action::Allow => Outcome::Passed,
        _ => Outcome::Failed(setting),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;

    const TODAY: Date = date(2026, 9, 12);

    fn policy(body: &str) -> Policy {
        Policy::parse(&format!("version: 1\n{body}")).expect("fixture should parse")
    }

    /// A package nothing has anything against.
    fn clean() -> Facts {
        Facts {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
            published: Some(date(2026, 1, 1)),
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: false,
            intel: Intel::NotConsulted,
        }
    }

    /// An advisory nobody is exploiting.
    fn advisory(id: &str, cvss: f64) -> Advisory {
        Advisory {
            id: id.to_owned(),
            aliases: Vec::new(),
            cvss: Some(cvss),
            band: None,
            kev: false,
            sources: vec!["osv".to_owned()],
        }
    }

    /// One that is.
    fn exploited(id: &str, cvss: f64) -> Advisory {
        Advisory {
            kev: true,
            ..advisory(id, cvss)
        }
    }

    fn outcome(d: &Decision, check: Check) -> &Outcome {
        &d.results
            .iter()
            .find(|r| r.check == check)
            .expect("every check is in the vector")
            .outcome
    }

    #[test]
    fn a_package_nothing_objects_to_is_delivered() {
        let d = decide(&policy(""), &clean(), TODAY);
        assert!(d.delivered());
        assert_eq!(d.action(), Action::Allow);
        assert!(d.reasons().is_empty());
        assert!(d.results.iter().all(|r| r.outcome == Outcome::Passed));
    }

    /// Every check appears in the vector, whatever the answer. A check that ran and found
    /// nothing is not the same as one that never ran.
    #[test]
    fn every_check_is_in_the_vector_every_time() {
        let d = decide(&policy(""), &clean(), TODAY);
        assert_eq!(d.results.len(), Check::ALL.len());
        for check in Check::ALL {
            assert!(d.results.iter().any(|r| r.check == check), "{check:?}");
        }
    }

    /// The point of the vector: a package failing several checks reports all of them, not
    /// the first. Under a short circuit this would say only "too young", the reason that
    /// lapses on its own, and an operator granting the age exception would find it still
    /// refused for a reason they only then see.
    #[test]
    fn a_package_failing_several_checks_reports_all_of_them() {
        let facts = Facts {
            published: Some(date(2026, 9, 11)),
            advisories: vec![exploited("CVE-2024-1", 9.8)],
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);

        assert_eq!(
            *outcome(&d, Check::CooldownDays),
            Outcome::Failed(Action::Quarantine)
        );
        assert_eq!(*outcome(&d, Check::Kev), Outcome::Failed(Action::Block));
        assert_eq!(
            *outcome(&d, Check::InstallScripts),
            Outcome::Failed(Action::Block)
        );
        // Four, not three: the exploited advisory scores 9.8, so it fails `max_cvss` as
        // well as `kev`. Being exploited does not remove an advisory from the score
        // comparison, and the two are separate results in the vector.
        assert_eq!(*outcome(&d, Check::MaxCvss), Outcome::Failed(Action::Block));
        assert_eq!(d.reasons().len(), 4);
    }

    /// The disposition is the strongest action, so one `block` among quarantines decides
    /// it. Reasons come back strongest first, because the one that will not lapse is the
    /// one to act on.
    #[test]
    fn the_strongest_action_decides_and_leads_the_reasons() {
        let facts = Facts {
            published: Some(date(2026, 9, 11)),
            advisories: vec![exploited("CVE-2024-1", 9.8)],
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);
        assert_eq!(d.action(), Action::Block);
        assert_eq!(d.reasons()[0].check, Check::Kev);
    }

    /// A package refused only for being too young is quarantined, which lapses by itself.
    /// That is the distinction the chart's two dispositions lose.
    #[test]
    fn too_young_alone_is_a_quarantine_and_not_a_block() {
        let facts = Facts {
            published: Some(date(2026, 9, 11)),
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);
        assert_eq!(d.action(), Action::Quarantine);
        assert!(!d.delivered());

        // Five days later the same package and the same policy deliver it.
        let later = decide(&policy(""), &facts, date(2026, 9, 18));
        assert!(later.delivered());
    }

    /// The day the wait is up, not the day after.
    #[test]
    fn a_package_is_old_enough_on_the_day_the_wait_ends() {
        let facts = Facts {
            published: Some(date(2026, 9, 5)),
            ..clean()
        };
        assert!(decide(&policy(""), &facts, date(2026, 9, 12)).delivered());
        assert!(!decide(&policy(""), &facts, date(2026, 9, 11)).delivered());
    }

    /// Zero days of waiting is how the check is turned off, and it has to be off for
    /// every package, including the ones the registry published no time for.
    #[test]
    fn a_cooldown_of_zero_days_passes_a_package_with_no_publish_date() {
        let facts = Facts {
            published: None,
            ..clean()
        };

        assert_eq!(
            *outcome(
                &decide(&policy("cooldown_days: 0"), &facts, date(2026, 9, 13)),
                Check::CooldownDays
            ),
            Outcome::Passed
        );
    }

    /// "We do not know when this was published" is not "old enough".
    #[test]
    fn a_package_with_no_publication_date_is_not_old_enough() {
        let facts = Facts {
            published: None,
            ..clean()
        };
        assert_eq!(
            *outcome(&decide(&policy(""), &facts, TODAY), Check::CooldownDays),
            Outcome::Failed(Action::Quarantine)
        );
    }

    #[test]
    fn a_denied_package_is_blocked() {
        let p = policy("denials:\n  - purl: \"pkg:npm/lodash@4.17.21\"\n    reason: compromised\n");
        let d = decide(&p, &clean(), TODAY);
        assert_eq!(*outcome(&d, Check::Denials), Outcome::Failed(Action::Block));
        assert_eq!(d.action(), Action::Block);

        // A different version of the same package is not denied.
        let other = Facts {
            version: "4.17.20".to_owned(),
            ..clean()
        };
        assert!(decide(&p, &other, TODAY).delivered());
    }

    /// A range blocks every version inside it and none outside, and the name is read the
    /// ecosystem's way.
    #[test]
    fn a_denied_range_blocks_the_versions_inside_it() {
        let p = policy(
            "denials:\n  - purl: \"pkg:npm/lodash\"\n    version: \"vers:npm/<4.17.21\"\n    \
             reason: prototype pollution\n",
        );
        let at = |version: &str| Facts {
            version: version.to_owned(),
            ..clean()
        };
        assert_eq!(
            *outcome(&decide(&p, &at("4.17.20"), TODAY), Check::Denials),
            Outcome::Failed(Action::Block)
        );
        assert!(decide(&p, &at("4.17.21"), TODAY).delivered());
    }

    #[test]
    fn known_malware_is_blocked() {
        let facts = Facts {
            known_malware: true,
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);
        assert_eq!(
            *outcome(&d, Check::KnownMalware),
            Outcome::Failed(Action::Block)
        );
    }

    /// The two checks an operator cannot write their way past.
    #[test]
    fn a_denial_and_known_malware_cannot_be_excepted() {
        assert!(!Check::Denials.exceptable());
        assert!(!Check::KnownMalware.exceptable());
        for check in Check::ALL {
            if !matches!(check, Check::Denials | Check::KnownMalware) {
                assert!(check.exceptable(), "{check:?}");
            }
        }

        // An exception matching the package changes neither.
        let p = policy(
            "denials:\n  - purl: \"pkg:npm/lodash@4.17.21\"\n    reason: compromised\npackages:\n  \
             - match: { ecosystem: npm, name: lodash }\n    set: { kev: allow }\n    \
             reason: r\n    permanent: true\n",
        );
        let facts = Facts {
            known_malware: true,
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert_eq!(*outcome(&d, Check::Denials), Outcome::Failed(Action::Block));
        assert_eq!(
            *outcome(&d, Check::KnownMalware),
            Outcome::Failed(Action::Block)
        );
    }

    /// An exception that let a package through is recorded as `Excepted`, not `Passed`.
    /// It is the one carrying operational risk, and it is what an expiry review has to
    /// find.
    #[test]
    fn an_exception_that_did_work_is_recorded_as_having_done_it() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { install_scripts: allow }\n    reason: reviewed\n    permanent: true\n",
        );
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);

        assert_eq!(
            *outcome(&d, Check::InstallScripts),
            Outcome::Excepted {
                entry: 0,
                action: Action::Block
            }
        );
        assert!(d.delivered());
        assert_eq!(d.exceptions_used(), vec![0]);
    }

    /// An exception on a check that found nothing did no work, so it is not recorded as
    /// having done any. This is how a dead exception becomes visible.
    #[test]
    fn an_exception_the_package_never_needed_is_not_recorded_as_used() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { install_scripts: allow }\n    reason: reviewed\n    permanent: true\n",
        );
        let d = decide(&p, &clean(), TODAY);
        assert_eq!(*outcome(&d, Check::InstallScripts), Outcome::Passed);
        assert!(d.exceptions_used().is_empty());
    }

    /// An expiry that has passed means the entry does not apply at all.
    #[test]
    fn a_lapsed_exception_stops_excusing_anything() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { install_scripts: allow }\n    reason: reviewed\n    \
             expires: \"2026-09-12\"\n",
        );
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        assert!(
            decide(&p, &facts, TODAY).delivered(),
            "in force on the day it names"
        );
        assert!(
            !decide(&p, &facts, date(2026, 9, 13)).delivered(),
            "and not after"
        );
    }

    /// Ignoring a named advisory is narrower than raising the threshold, which would apply
    /// to every advisory this package acquires later.
    #[test]
    fn an_advisory_may_be_ignored_by_id() {
        let p = policy(
            "max_cvss: 6.9\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { vuln_advisory_ids: [\"CVE-2024-1234\"] }\n    reason: not reachable\n    \
             permanent: true\n",
        );
        let facts = Facts {
            advisories: vec![Advisory {
                id: "CVE-2024-1234".to_owned(),
                aliases: Vec::new(),
                cvss: Some(9.8),
                band: None,
                kev: false,
                sources: vec!["osv".to_owned()],
            }],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert_eq!(
            *outcome(&d, Check::MaxCvss),
            Outcome::Excepted {
                entry: 0,
                action: Action::Block
            }
        );
        assert!(d.delivered());

        // A second advisory the exception does not name is still over the threshold.
        let more = Facts {
            advisories: vec![
                Advisory {
                    id: "CVE-2024-1234".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(9.8),
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "CVE-2025-9999".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(7.5),
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
            ],
            ..clean()
        };
        assert_eq!(
            *outcome(&decide(&p, &more, TODAY), Check::MaxCvss),
            Outcome::Failed(Action::Block)
        );
    }

    /// The flow chart's `RECORD_cooldown_EXCEPTED`: too young for the global wait, old
    /// enough for the exception's.
    #[test]
    fn an_exception_that_shortens_the_wait_enough_is_what_let_the_package_through() {
        let with = |set: &str| {
            policy(&format!(
                "cooldown_days: 7\npackages:\n  - match: {{ ecosystem: npm, name: lodash }}\n    \
                 set: {{ {set} }}\n    reason: t\n    permanent: true\n"
            ))
        };
        let young = Facts {
            published: Some(date(2026, 9, 11)),
            ..clean()
        };

        let d = decide(&with("cooldown_days: 0"), &young, TODAY);
        assert_eq!(
            *outcome(&d, Check::CooldownDays),
            Outcome::Excepted {
                entry: 0,
                action: Action::Quarantine
            }
        );
        assert_eq!(d.exceptions_used(), vec![0]);
        assert!(d.delivered());

        assert_eq!(
            *outcome(
                &decide(&with("cooldown_days: 5"), &young, TODAY),
                Check::CooldownDays
            ),
            Outcome::Failed(Action::Quarantine),
            "shortened, and not enough"
        );
        let old = Facts {
            published: Some(date(2026, 9, 1)),
            ..clean()
        };
        assert_eq!(
            *outcome(
                &decide(&with("cooldown_days: 0"), &old, TODAY),
                Check::CooldownDays
            ),
            Outcome::Passed,
            "old enough without it, so it excused nothing"
        );
    }

    /// OSV stores a GitHub advisory under its GHSA id, with the CVE as an alias.
    #[test]
    fn an_advisory_may_be_ignored_by_an_alias() {
        let p = policy(
            "max_cvss: 6.9\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { vuln_advisory_ids: [\"CVE-2024-1234\"] }\n    reason: not reachable\n    \
             permanent: true\n",
        );
        let ghsa = |aliases: &[&str]| Facts {
            advisories: vec![Advisory {
                aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
                ..advisory("GHSA-aaaa-bbbb-cccc", 9.8)
            }],
            ..clean()
        };

        let d = decide(&p, &ghsa(&["CVE-2020-1", "CVE-2024-1234"]), TODAY);
        assert_eq!(
            *outcome(&d, Check::MaxCvss),
            Outcome::Excepted {
                entry: 0,
                action: Action::Block
            }
        );
        assert_eq!(
            *outcome(&decide(&p, &ghsa(&["CVE-2020-1"]), TODAY), Check::MaxCvss),
            Outcome::Failed(Action::Block)
        );
    }

    /// The rule the gather-then-subtract shape exists to guarantee. Excepting an
    /// advisory by id says it is not reachable from this code; it says nothing about
    /// whether it is being exploited, and one must not stand for the other.
    #[test]
    fn excepting_an_advisory_by_id_does_not_excuse_its_exploitation() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { vuln_advisory_ids: [\"CVE-2024-1234\"] }\n    reason: not reachable\n    \
             permanent: true\n",
        );
        let facts = Facts {
            advisories: vec![exploited("CVE-2024-1234", 9.8)],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);

        assert_eq!(
            *outcome(&d, Check::MaxCvss),
            Outcome::Excepted {
                entry: 0,
                action: Action::Block
            },
            "the id exception covers the score"
        );
        assert_eq!(
            *outcome(&d, Check::Kev),
            Outcome::Failed(Action::Block),
            "and does not reach the exploitation"
        );
        assert!(!d.delivered());
    }

    /// Both exceptions, and it passes. This is what §5 asks an operator to write for a
    /// KEV'd advisory they have reviewed and accepted.
    #[test]
    fn a_kev_advisory_needs_both_exceptions_to_pass() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { vuln_advisory_ids: [\"CVE-2024-1234\"], kev: allow }\n    \
             reason: not reachable, and we accept the exploitation risk\n    \
             permanent: true\n",
        );
        let facts = Facts {
            advisories: vec![exploited("CVE-2024-1234", 9.8)],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert!(d.delivered());
        assert!(matches!(outcome(&d, Check::Kev), Outcome::Excepted { .. }));
        assert!(matches!(
            outcome(&d, Check::MaxCvss),
            Outcome::Excepted { .. }
        ));
        assert_eq!(d.exceptions_used(), vec![0]);
    }

    /// A `kev: allow` exception on its own leaves the score to answer for itself.
    #[test]
    fn excusing_the_exploitation_does_not_excuse_the_score() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { kev: allow }\n    reason: accepted\n    permanent: true\n",
        );
        let facts = Facts {
            advisories: vec![exploited("CVE-2024-1234", 9.8)],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert!(matches!(outcome(&d, Check::Kev), Outcome::Excepted { .. }));
        assert_eq!(*outcome(&d, Check::MaxCvss), Outcome::Failed(Action::Block));
        assert!(!d.delivered());
    }

    /// "None at all" and "all of them excused" are different answers, and only the second
    /// is an exception doing work. Collapsing them would lose the dead-exception signal.
    #[test]
    fn a_package_with_no_exploited_advisory_passes_rather_than_excepts() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { kev: allow }\n    reason: belt and braces\n    permanent: true\n",
        );
        // An advisory, but nobody is exploiting it.
        let facts = Facts {
            advisories: vec![advisory("CVE-2024-1234", 3.1)],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert_eq!(*outcome(&d, Check::Kev), Outcome::Passed);
        assert!(
            d.exceptions_used().is_empty(),
            "the exception did no work, so it is not recorded as having done any"
        );
    }

    /// Only the exploited advisories are subtracted. A second one nobody is exploiting is
    /// still scored.
    #[test]
    fn only_the_exploited_advisories_answer_the_kev_question() {
        let facts = Facts {
            advisories: vec![exploited("CVE-2024-1", 5.0), advisory("CVE-2024-2", 9.8)],
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);
        assert_eq!(*outcome(&d, Check::Kev), Outcome::Failed(Action::Block));
        assert_eq!(
            *outcome(&d, Check::MaxCvss),
            Outcome::Failed(Action::Block),
            "scored on the 9.8, which is the one nobody is exploiting"
        );
    }

    /// An advisory no stream scored.
    fn unscored(id: &str, aliases: &[&str]) -> Advisory {
        Advisory {
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            cvss: None,
            ..advisory(id, 0.0)
        }
    }

    /// A stored score is compared whatever the policy says. Otherwise the highest
    /// `advisory_scores` entry in force naming the advisory by id or alias, and with
    /// neither the advisory counts as over.
    #[test]
    fn an_unscored_advisory_counts_as_over_max_cvss_until_policy_scores_it() {
        let p = policy(
            "max_cvss: 6.9\nadvisory_scores:\n\
             - { advisory_id: GHSA-live, cvss: 6.9, reason: r, expires: \"2026-09-12\" }\n\
             - { advisory_id: GHSA-lapsed, cvss: 5.0, reason: r, expires: \"2026-09-11\" }\n\
             - { advisory_id: CVE-by-alias, cvss: 9.0, reason: r, permanent: true }\n\
             - { advisory_id: GHSA-two, cvss: 5.0, reason: r, permanent: true }\n\
             - { advisory_id: CVE-of-two, cvss: 8.0, reason: r, permanent: true }\n\
             - { advisory_id: GHSA-stored, cvss: 9.0, reason: r, permanent: true }\n",
        );
        let facts = Facts {
            advisories: vec![
                unscored("GHSA-live", &[]),
                unscored("GHSA-none", &[]),
                unscored("GHSA-lapsed", &[]),
                unscored("GHSA-alias", &["CVE-by-alias"]),
                unscored("GHSA-two", &["CVE-of-two"]),
                advisory("GHSA-stored", 5.0),
            ],
            ..clean()
        };

        let (counting, excused) = over_max_cvss(&p, &facts, None, TODAY);
        let ids: Vec<&str> = counting.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["GHSA-none", "GHSA-lapsed", "GHSA-alias", "GHSA-two"]);
        assert!(excused.is_empty());

        let scores: Vec<Option<(f64, Option<usize>)>> = facts
            .advisories
            .iter()
            .map(|a| score(&p, a, TODAY))
            .collect();
        assert_eq!(
            scores,
            [
                Some((6.9, Some(0))),
                None,
                None,
                Some((9.0, Some(2))),
                Some((8.0, Some(4))),
                Some((5.0, None)),
            ]
        );

        let only = |a: Advisory| Facts {
            advisories: vec![a],
            ..clean()
        };
        assert_eq!(
            *outcome(
                &decide(&p, &only(unscored("GHSA-live", &[])), TODAY),
                Check::MaxCvss
            ),
            Outcome::Passed
        );
        assert_eq!(
            *outcome(
                &decide(&p, &only(unscored("GHSA-lapsed", &[])), TODAY),
                Check::MaxCvss
            ),
            Outcome::Failed(Action::Block),
            "a lapsed score leaves the advisory unscored, and refused"
        );
        assert_eq!(
            *outcome(
                &decide(&p, &only(unscored("GHSA-live", &[])), date(2026, 9, 13)),
                Check::MaxCvss
            ),
            Outcome::Failed(Action::Block),
            "and the live one lapses the day after its expiry"
        );
    }

    /// `vuln_advisory_ids` excuses an unscored advisory the way it excuses a scored one, and
    /// `kev` reads exploitation whatever the score.
    #[test]
    fn an_unscored_advisory_is_excused_by_id_and_still_read_by_kev() {
        let p = policy(
            "max_cvss: 6.9\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: not reachable\n    \
             permanent: true\n",
        );
        let facts = Facts {
            advisories: vec![Advisory {
                kev: true,
                ..unscored("GHSA-aaaa", &["CVE-2024-1"])
            }],
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert_eq!(
            *outcome(&d, Check::MaxCvss),
            Outcome::Excepted {
                entry: 0,
                action: Action::Block
            }
        );
        assert_eq!(*outcome(&d, Check::Kev), Outcome::Failed(Action::Block));
    }

    /// At or below the threshold is allowed, above is not.
    #[test]
    fn the_cvss_threshold_allows_what_is_at_or_below_it() {
        let p = policy("max_cvss: 6.9\n");
        for (cvss, delivered) in [(6.8, true), (6.9, true), (7.0, false)] {
            let facts = Facts {
                advisories: vec![Advisory {
                    id: "CVE-2024-1".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(cvss),
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                }],
                ..clean()
            };
            assert_eq!(
                decide(&p, &facts, TODAY).delivered(),
                delivered,
                "cvss {cvss}"
            );
        }
    }

    /// Go has no install step, so the check reports not-applicable rather than a
    /// violation. Three of the four outcomes contribute `allow` and are distinguished
    /// anyway.
    #[test]
    fn a_check_with_no_meaning_for_an_ecosystem_is_not_applicable() {
        let facts = Facts {
            ecosystem: "golang".to_owned(),
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        let d = decide(&policy(""), &facts, TODAY);
        assert_eq!(*outcome(&d, Check::InstallScripts), Outcome::NotApplicable);
        assert!(d.delivered());
        assert_ne!(*outcome(&d, Check::InstallScripts), Outcome::Passed);
    }

    /// Turning a check off globally is not the same as excepting one package: nothing was
    /// excused, so nothing is recorded as having been.
    #[test]
    fn a_check_turned_off_globally_passes_rather_than_excepts() {
        let p = policy("install_scripts: allow\n");
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        let d = decide(&p, &facts, TODAY);
        assert_eq!(*outcome(&d, Check::InstallScripts), Outcome::Passed);
        assert!(d.exceptions_used().is_empty());
    }

    /// Most specific wins. Overlapping entries that cannot be ordered are refused at
    /// load, so whatever matches forms a chain and the narrowest is unique.
    ///
    /// The narrow entry is written **first** on purpose. With it last, "the narrowest
    /// wins" and "the last one wins" give the same answer and the test proves neither.
    #[test]
    fn the_most_specific_matching_exception_is_the_one_that_applies() {
        let narrow_first = policy(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { cooldown_days: 0 }\n    reason: narrow\n    permanent: true\n  \
             - match: { ecosystem: npm, name: \"lo*\" }\n    set: { cooldown_days: 30 }\n    \
             reason: wide\n    permanent: true\n",
        );
        let facts = Facts {
            published: Some(date(2026, 9, 11)),
            ..clean()
        };
        assert!(
            decide(&narrow_first, &facts, TODAY).delivered(),
            "the narrow entry waives the wait, and it is not the last one written"
        );

        // The same two entries the other way round give the same answer, which is what
        // makes the result about specificity rather than about file order.
        let narrow_last = policy(
            "packages:\n  - match: { ecosystem: npm, name: \"lo*\" }\n    \
             set: { cooldown_days: 30 }\n    reason: wide\n    permanent: true\n  \
             - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    \
             reason: narrow\n    permanent: true\n",
        );
        assert!(decide(&narrow_last, &facts, TODAY).delivered());

        // And a package the narrow entry does not name gets the wide one's longer wait.
        let other = Facts {
            name: "lolcat".to_owned(),
            published: Some(date(2026, 9, 11)),
            ..clean()
        };
        assert!(!decide(&narrow_first, &other, TODAY).delivered());
    }

    #[test]
    fn an_exception_for_another_package_does_not_apply() {
        let p = policy(
            "packages:\n  - match: { ecosystem: npm, name: express }\n    \
             set: { install_scripts: allow }\n    reason: r\n    permanent: true\n",
        );
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..clean()
        };
        assert_eq!(
            *outcome(&decide(&p, &facts, TODAY), Check::InstallScripts),
            Outcome::Failed(Action::Block)
        );
    }

    #[test]
    fn every_check_has_a_name() {
        for check in Check::ALL {
            assert!(!check.as_str().is_empty());
        }
        assert_eq!(Check::ALL.len(), 6);
    }
}
