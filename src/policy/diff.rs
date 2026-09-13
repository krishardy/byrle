//! `waharoa policy diff`: what changes if this policy replaces that one.
//!
//! # Vectors, not verdicts
//!
//! Two policies can both answer `block` for different reasons. Comparing
//! [`Decision::action`] reports no change there, and the change is real: one denial
//! lapsed and another check started firing. So the comparison is per check, and the report
//! names which check moved. That is the half an operator can act on.
//!
//! # A check that stops being enforced is a loosening
//!
//! `FAIL` to `unenforced` is not a loosening of the written policy. The setting is still
//! there. It is a loosening of what happens, because the package now installs. The gate
//! exists to stop a change slipping something through, so that is what it reports, and the
//! report says `unenforced` rather than pretending the check passed.
//!
//! # What is not compared
//!
//! `n/a` moves only if the ecosystem did, and a package does not change ecosystem between
//! two policies. A `n/a` on one side and anything else on the other is
//! [`Strictness::Incomparable`], which fails the gate rather than being guessed at.

use super::decide::{Check, Decision, Outcome};
use super::enforce::Unenforceable;
use super::strictness::Strictness;
use super::Action;

/// What a check answered, as the report shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    Pass,
    Fail(Action),
    /// Excused by a `packages` entry. Delivers, and the entry is worth naming.
    Excepted(usize),
    /// No meaning for this ecosystem.
    NotApplicable,
    /// The fact the check needs is not available in this build.
    Unenforced,
}

impl Shown {
    pub fn as_str(self) -> String {
        match self {
            Self::Pass => "pass".to_owned(),
            Self::Fail(action) => format!("FAIL {}", action.as_str()),
            Self::Excepted(entry) => format!("excepted by packages[{entry}]"),
            Self::NotApplicable => "n/a".to_owned(),
            Self::Unenforced => "unenforced".to_owned(),
        }
    }

    /// What the package actually gets. `None` where the check cannot be compared at all.
    fn effect(self) -> Option<Action> {
        match self {
            // An unenforced check delivers the package, whatever the setting says.
            Self::Pass | Self::Excepted(_) | Self::Unenforced => Some(Action::Allow),
            Self::Fail(action) => Some(action),
            Self::NotApplicable => None,
        }
    }
}

/// Read one check out of a decision.
pub fn shown(decision: &Decision, unenforceable: &[Unenforceable], check: Check) -> Shown {
    if unenforceable.iter().any(|u| u.check == check) {
        return Shown::Unenforced;
    }
    match decision.results.iter().find(|r| r.check == check) {
        None => Shown::Unenforced,
        Some(result) => match result.outcome {
            Outcome::Passed => Shown::Pass,
            Outcome::Failed(action) => Shown::Fail(action),
            Outcome::Excepted { entry, .. } => Shown::Excepted(entry),
            Outcome::NotApplicable => Shown::NotApplicable,
        },
    }
}

/// One check that answered differently.
#[derive(Debug, Clone, PartialEq)]
pub struct Moved {
    pub check: Check,
    pub from: Shown,
    pub to: Shown,
    pub strictness: Strictness,
}

/// How one check's two answers compare.
pub fn compare(from: Shown, to: Shown) -> Strictness {
    match (from.effect(), to.effect()) {
        (None, None) => Strictness::NotApplicable,
        // A package does not change ecosystem between two policies, so this is a
        // disagreement rather than a move. Refused rather than guessed at.
        (None, Some(_)) | (Some(_), None) => Strictness::Incomparable,
        (Some(before), Some(after)) => match after.strength().cmp(&before.strength()) {
            std::cmp::Ordering::Greater => Strictness::Stricter,
            std::cmp::Ordering::Less => Strictness::Looser,
            std::cmp::Ordering::Equal => Strictness::Same,
        },
    }
}

/// One package, decided twice.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub purl: String,
    pub from_verdict: Action,
    pub to_verdict: Action,
    /// Only the checks that answered differently.
    pub moved: Vec<Moved>,
}

impl Package {
    /// Whether anything about this package got looser.
    ///
    /// Per check, not on the verdict. A package whose verdict stays `block` while one
    /// check stopped firing has still loosened, and that is what the gate is for.
    pub fn loosened(&self) -> bool {
        self.moved
            .iter()
            .any(|m| m.strictness == Strictness::Looser)
    }

    pub fn incomparable(&self) -> bool {
        self.moved
            .iter()
            .any(|m| m.strictness == Strictness::Incomparable)
    }
}

/// Compare one package under two policies.
pub fn package(
    purl: &str,
    from: (&Decision, &[Unenforceable]),
    to: (&Decision, &[Unenforceable]),
) -> Package {
    let moved = Check::ALL
        .iter()
        .filter_map(|&check| {
            let before = shown(from.0, from.1, check);
            let after = shown(to.0, to.1, check);
            (before != after).then(|| Moved {
                check,
                from: before,
                to: after,
                strictness: compare(before, after),
            })
        })
        .collect();

    Package {
        purl: purl.to_owned(),
        from_verdict: from.0.action(),
        to_verdict: to.0.action(),
        moved,
    }
}

/// Every package that moved, and what it means for the gate.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Report {
    /// Packages evaluated, including ones that did not move.
    pub evaluated: usize,
    /// Only the packages that moved.
    pub changed: Vec<Package>,
}

impl Report {
    pub fn push(&mut self, package: Package) {
        self.evaluated += 1;
        if !package.moved.is_empty() {
            self.changed.push(package);
        }
    }

    pub fn loosened(&self) -> Vec<&Package> {
        self.changed.iter().filter(|p| p.loosened()).collect()
    }

    pub fn incomparable(&self) -> Vec<&Package> {
        self.changed.iter().filter(|p| p.incomparable()).collect()
    }

    /// Whether the gate fails.
    ///
    /// Incomparable fails too: §5.5 is fail loud when tightening cannot be proven, and a
    /// diff that cannot be decided is exactly that case.
    pub fn fails_the_gate(&self) -> bool {
        !self.loosened().is_empty() || !self.incomparable().is_empty()
    }

    /// Grouped by check and direction, which is what a person reads first.
    pub fn render(&self) -> String {
        let mut out = format!("{} packages evaluated\n", self.evaluated);
        if self.changed.is_empty() {
            out.push_str("nothing moved\n");
            return out;
        }

        let mut counts: std::collections::BTreeMap<(&str, &str), usize> =
            std::collections::BTreeMap::new();
        for package in &self.changed {
            for moved in &package.moved {
                *counts
                    .entry((moved.check.as_str(), strictness(moved.strictness)))
                    .or_default() += 1;
            }
        }
        out.push_str(&format!("{} moved\n\n", self.changed.len()));
        for ((check, direction), count) in &counts {
            out.push_str(&format!("  {count:>5}  {check} {direction}\n"));
        }

        out.push('\n');
        for package in &self.changed {
            out.push_str(&format!(
                "{}  {} -> {}\n",
                package.purl,
                package.from_verdict.as_str(),
                package.to_verdict.as_str()
            ));
            for moved in &package.moved {
                out.push_str(&format!(
                    "    {:16}  {} -> {}  ({})\n",
                    moved.check.as_str(),
                    moved.from.as_str(),
                    moved.to.as_str(),
                    strictness(moved.strictness)
                ));
            }
        }
        out
    }
}

fn strictness(s: Strictness) -> &'static str {
    match s {
        Strictness::Stricter => "stricter",
        Strictness::Looser => "LOOSER",
        Strictness::Same => "same",
        Strictness::Incomparable => "INCOMPARABLE",
        Strictness::NotApplicable => "n/a",
        Strictness::Unset => "unset",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::policy::decide::{Facts, Intel, decide};

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
            intel: Intel::Consulted,
        }
    }

    fn decided(yaml: &str, facts: &Facts) -> Decision {
        let policy = Policy::parse(yaml).expect("policy should load");
        decide(&policy, facts, TODAY)
    }

    fn diff(from: &str, to: &str, facts: &Facts) -> Package {
        package(
            "pkg:npm/lodash@4.17.21",
            (&decided(from, facts), &[]),
            (&decided(to, facts), &[]),
        )
    }

    #[test]
    fn an_unchanged_policy_moves_nothing() {
        let d = diff("version: 1", "version: 1", &facts());

        assert!(d.moved.is_empty());
        assert!(!d.loosened());
    }

    /// The requirement this is built for: both verdicts are `block`, and the change is
    /// real. Comparing verdicts would report nothing.
    #[test]
    fn two_policies_that_both_block_for_different_reasons_still_show_the_move() {
        let facts = Facts {
            has_install_scripts: true,
            ..facts()
        };
        let d = diff(
            "version: 1\ninstall_scripts: block\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            "version: 1\ninstall_scripts: block\n\
             denials:\n  - purl: pkg:npm/other@1.0.0\n    reason: t\n",
            &facts,
        );

        assert_eq!(d.from_verdict, Action::Block);
        assert_eq!(d.to_verdict, Action::Block);
        assert_eq!(d.moved.len(), 1);
        assert_eq!(d.moved[0].check, Check::Denials);
        assert_eq!(d.moved[0].strictness, Strictness::Looser);
        assert!(d.loosened(), "a check stopped firing; the verdict hid it");
    }

    #[test]
    fn dropping_a_denial_is_a_loosening() {
        let d = diff(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            "version: 1",
            &facts(),
        );

        assert_eq!(d.moved[0].from, Shown::Fail(Action::Block));
        assert_eq!(d.moved[0].to, Shown::Pass);
        assert!(d.loosened());
    }

    #[test]
    fn adding_a_denial_is_a_tightening() {
        let d = diff(
            "version: 1",
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        );

        assert_eq!(d.moved[0].strictness, Strictness::Stricter);
        assert!(!d.loosened());
    }

    /// Block to quarantine is a loosening: quarantine lapses on its own.
    #[test]
    fn moving_down_the_lattice_is_a_loosening() {
        let from = decided(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        );
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package("pkg:npm/lodash@4.17.21", (&from, &[]), (&to, &[]));

        assert_eq!(d.from_verdict, Action::Block);
        assert_eq!(d.to_verdict, Action::Quarantine);
        assert!(d.loosened());
    }

    /// The written policy did not loosen. What happens did, so the gate says so.
    #[test]
    fn a_check_that_stops_being_enforced_is_a_loosening() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "no publish date",
        }];
        let from = decided("version: 1\ncooldown_days: 3650", &facts());
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package("pkg:npm/lodash@4.17.21", (&from, &[]), (&to, &unenforceable));

        assert_eq!(d.moved.len(), 1);
        assert_eq!(d.moved[0].to, Shown::Unenforced);
        assert_eq!(d.moved[0].strictness, Strictness::Looser);
        assert!(d.loosened());
    }

    /// A check starting to be enforced is the other direction.
    #[test]
    fn a_check_that_starts_being_enforced_is_a_tightening() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "no publish date",
        }];
        let from = decided("version: 1\ncooldown_days: 3650", &facts());
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package("pkg:npm/lodash@4.17.21", (&from, &unenforceable), (&to, &[]));

        assert_eq!(d.moved[0].strictness, Strictness::Stricter);
        assert!(!d.loosened());
    }

    /// An exception delivers the package, so gaining one is a loosening even though the
    /// check still finds something.
    #[test]
    fn gaining_an_exception_is_a_loosening_and_names_the_entry() {
        let facts = Facts {
            has_install_scripts: true,
            ..facts()
        };
        let d = diff(
            "version: 1\ninstall_scripts: block",
            "version: 1\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    permanent: true\n",
            &facts,
        );

        assert_eq!(d.moved[0].from, Shown::Fail(Action::Block));
        assert_eq!(d.moved[0].to, Shown::Excepted(0));
        assert!(d.loosened());
        assert!(d.moved[0].to.as_str().contains("packages[0]"));
    }

    /// A package does not change ecosystem between two policies, so this is a
    /// disagreement. §5.5 fails loud when tightening cannot be proven.
    #[test]
    fn not_applicable_against_anything_else_is_incomparable_and_fails_the_gate() {
        assert_eq!(
            compare(Shown::NotApplicable, Shown::Pass),
            Strictness::Incomparable
        );
        assert_eq!(
            compare(Shown::Pass, Shown::NotApplicable),
            Strictness::Incomparable
        );
        assert_eq!(
            compare(Shown::NotApplicable, Shown::NotApplicable),
            Strictness::NotApplicable
        );

        let mut report = Report::default();
        report.push(Package {
            purl: "pkg:npm/x@1.0.0".to_owned(),
            from_verdict: Action::Allow,
            to_verdict: Action::Allow,
            moved: vec![Moved {
                check: Check::InstallScripts,
                from: Shown::NotApplicable,
                to: Shown::Pass,
                strictness: Strictness::Incomparable,
            }],
        });
        assert!(report.fails_the_gate());
    }

    #[test]
    fn the_gate_passes_when_everything_tightened() {
        let mut report = Report::default();
        report.push(diff(
            "version: 1",
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        ));

        assert_eq!(report.evaluated, 1);
        assert_eq!(report.changed.len(), 1);
        assert!(!report.fails_the_gate());
    }

    #[test]
    fn a_package_that_did_not_move_is_counted_but_not_listed() {
        let mut report = Report::default();
        report.push(diff("version: 1", "version: 1", &facts()));

        assert_eq!(report.evaluated, 1);
        assert!(report.changed.is_empty());
        assert!(report.render().contains("nothing moved"));
    }

    #[test]
    fn the_report_groups_by_check_and_direction_with_counts() {
        let mut report = Report::default();
        for name in ["a", "b"] {
            let facts = Facts {
                name: name.to_owned(),
                ..facts()
            };
            report.push(package(
                &format!("pkg:npm/{name}@4.17.21"),
                (
                    &decided(
                        &format!(
                            "version: 1\ndenials:\n  - purl: pkg:npm/{name}@4.17.21\n    reason: t\n"
                        ),
                        &facts,
                    ),
                    &[],
                ),
                (&decided("version: 1", &facts), &[]),
            ));
        }

        let out = report.render();
        assert!(out.contains("2 packages evaluated"), "{out}");
        assert!(out.contains("2 moved"), "{out}");
        assert!(out.contains("2  denials LOOSER"), "{out}");
        assert!(out.contains("pkg:npm/a@4.17.21  block -> allow"), "{out}");
        assert!(report.fails_the_gate());
        assert_eq!(report.loosened().len(), 2);
    }

    #[test]
    fn every_state_renders_with_its_own_words() {
        assert_eq!(Shown::Pass.as_str(), "pass");
        assert_eq!(Shown::Fail(Action::Quarantine).as_str(), "FAIL quarantine");
        assert_eq!(Shown::Excepted(3).as_str(), "excepted by packages[3]");
        assert_eq!(Shown::NotApplicable.as_str(), "n/a");
        assert_eq!(Shown::Unenforced.as_str(), "unenforced");
    }

    /// A check the decision never produced reads as unenforced rather than as a pass.
    #[test]
    fn a_check_absent_from_the_vector_is_not_a_pass() {
        let empty = Decision {
            results: Vec::new(),
        };

        assert_eq!(shown(&empty, &[], Check::Denials), Shown::Unenforced);
    }
}
