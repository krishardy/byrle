//! `waharoa policy check`: whether a policy loads, and which of its package entries do
//! nothing.
//!
//! Loading is the proxy's own, [`Policy::load`] then [`packages::check`], so a policy this
//! accepts is one the proxy starts with on the same date and ceiling. The proxy at startup
//! and `doctor` read the same [`Report`].
//!
//! # What does nothing
//!
//! - An entry that **changes nothing** sets every value to what the global settings
//!   already say. See [`packages::changes_nothing`].
//! - An entry that **never wins** matches no package that a narrower entry does not also
//!   match, so most-specific-wins always picks the narrower one.
//!
//! Loading has already refused duplicate selectors and overlaps that cannot be ordered.
//! What is left that can cover an entry is one shape: two entries with its ecosystem, name
//! and version, one `has_install_scripts: true` and one `false`, below an entry that sets
//! neither. Covering a name pattern or a version would take narrower entries listing every
//! name or version under it, and that is not looked for.
//!
//! A narrower entry with an expiry covers only until it lapses, so the wide entry is
//! reported as shadowed through that date, not as never winning. A lapsed entry matches
//! nothing and covers nothing, as in [`super::decide::decide`].

use super::packages::{self, PackageError};
use super::selector::Canonical;
use super::{Policy, PolicyError};
use jiff::civil::Date;
use std::fmt;
use std::path::Path;

/// Why a policy was refused.
#[derive(Debug)]
pub enum Refused {
    /// The document: unreadable, not valid, or a shape the schema refuses.
    Policy(PolicyError),
    /// A package entry that breaks the `packages` rules on the date it was judged.
    Package(PackageError),
}

impl Refused {
    /// 2 when the file could not be read, as for any command that could not run. 1 when it
    /// was read and refused.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Policy(PolicyError::Unreadable { .. }) => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "{e}"),
            Self::Package(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Refused {}

/// Load a policy the way the proxy does at startup, and report on it.
pub fn load(path: &Path, as_of: Date, ceiling_days: i64) -> Result<(Policy, Report), Refused> {
    let policy = Policy::load(path).map_err(Refused::Policy)?;
    packages::check(&policy, as_of, ceiling_days).map_err(Refused::Package)?;
    let report = Report::of(&policy, as_of);
    Ok((policy, report))
}

/// An entry, and the two narrower entries that between them match every package it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shadowed {
    pub index: usize,
    /// The `has_install_scripts: true` entry, then the `false` one.
    pub by: [usize; 2],
    /// The last day the cover holds: the earlier expiry of the two. `None` when neither
    /// expires.
    pub through: Option<Date>,
}

impl Shadowed {
    /// Which entries cover this one.
    pub fn cover(&self) -> String {
        format!(
            "{} and {} match every package it does",
            packages::label(self.by[0]),
            packages::label(self.by[1])
        )
    }
}

/// What a policy that loaded carries that does nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub as_of: Date,
    /// Each entry's selector and reason, for naming it.
    entries: Vec<(String, String)>,
    /// Entries that change nothing.
    pub unchanged: Vec<usize>,
    /// Entries covered by narrower ones, on `as_of`.
    pub shadowed: Vec<Shadowed>,
    /// Entries marked `permanent: true`, listed so each one stays visible.
    pub permanent: Vec<usize>,
}

impl Report {
    pub fn of(policy: &Policy, as_of: Date) -> Self {
        let findings = packages::findings(policy);
        let selectors = policy.selectors();
        let live = |i: usize| {
            !policy.packages[i]
                .expires
                .is_some_and(|e| e.has_passed(as_of))
        };

        let shadowed = selectors
            .iter()
            .enumerate()
            .filter(|&(i, wide)| wide.has_install_scripts.is_none() && live(i))
            .filter_map(|(index, wide)| {
                let half = |scripts| {
                    let narrow = Canonical {
                        has_install_scripts: Some(scripts),
                        ..wide.clone()
                    };
                    (0..selectors.len()).find(|&j| live(j) && selectors[j] == narrow)
                };
                let by = [half(true)?, half(false)?];
                let through = by
                    .iter()
                    .filter_map(|&j| policy.packages[j].expires)
                    .map(|e| e.0)
                    .min();
                Some(Shadowed { index, by, through })
            })
            .collect();

        Self {
            as_of,
            entries: policy
                .packages
                .iter()
                .zip(&selectors)
                .map(|(entry, selector)| (selector.to_string(), entry.reason.clone()))
                .collect(),
            unchanged: (0..policy.packages.len())
                .filter(|&i| packages::changes_nothing(&findings, i))
                .collect(),
            shadowed,
            permanent: (0..policy.packages.len())
                .filter(|&i| policy.packages[i].permanent)
                .collect(),
        }
    }

    /// Entries that never win, on any day.
    pub fn never_wins(&self) -> impl Iterator<Item = &Shadowed> {
        self.shadowed.iter().filter(|s| s.through.is_none())
    }

    /// Why `--strict` fails, when it does: an entry that changes nothing, or one that never
    /// wins.
    pub fn strict_failure(&self) -> Option<String> {
        let never = self.never_wins().count();
        (!self.unchanged.is_empty() || never > 0).then(|| {
            format!(
                "changes nothing: {}, never wins: {never}",
                self.unchanged.len()
            )
        })
    }

    pub fn render(&self) -> String {
        let name = |i: usize| format!("{} {}", packages::label(i), self.entries[i].0);
        let with_reason = |i: usize| format!("{}: {}", name(i), self.entries[i].1);
        let sections = [
            (
                "changes nothing",
                self.unchanged
                    .iter()
                    .map(|&i| with_reason(i))
                    .collect::<Vec<_>>(),
            ),
            (
                "never wins",
                self.never_wins()
                    .map(|s| format!("{}: {}", name(s.index), s.cover()))
                    .collect(),
            ),
            (
                "shadowed until a narrower entry lapses",
                self.shadowed
                    .iter()
                    .filter_map(|s| {
                        s.through
                            .map(|day| format!("{}: {}, through {day}", name(s.index), s.cover()))
                    })
                    .collect(),
            ),
            (
                "permanent",
                self.permanent.iter().map(|&i| with_reason(i)).collect(),
            ),
        ];

        let mut out = format!(
            "{} package entries, as of {}\n",
            self.entries.len(),
            self.as_of
        );
        for (title, lines) in sections {
            if lines.is_empty() {
                continue;
            }
            out.push_str(&format!("\n{title}\n"));
            for line in lines {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::DEFAULT_EXPIRY_CEILING_DAYS;
    use jiff::civil::date;

    const TODAY: Date = date(2026, 9, 13);
    const PERMANENT: &str = "    permanent: true\n";

    fn fixture(name: &str) -> std::path::PathBuf {
        format!(
            "{}/tests/fixtures/policy-check/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
        .into()
    }

    /// The report for `packages`, judged on `as_of`, after the checks the proxy makes.
    fn report_on(as_of: Date, packages: &str) -> Report {
        let policy = Policy::parse(&format!("version: 1\npackages:\n{packages}"))
            .expect("policy should load");
        packages::check(&policy, as_of, DEFAULT_EXPIRY_CEILING_DAYS)
            .expect("entries should pass the package rules");
        Report::of(&policy, as_of)
    }

    fn report(packages: &str) -> Report {
        report_on(TODAY, packages)
    }

    /// An entry for `left-pad` allowing install scripts, narrowed by `extra`.
    fn entry(extra: &str, tail: &str) -> String {
        format!(
            "  - match: {{ ecosystem: npm, name: left-pad{extra} }}\n    \
             set: {{ install_scripts: allow }}\n    reason: r\n{tail}"
        )
    }

    fn wide_and_halves(true_tail: &str, false_tail: &str) -> String {
        format!(
            "{}{}{}",
            entry("", PERMANENT),
            entry(", has_install_scripts: true", true_tail),
            entry(", has_install_scripts: false", false_tail)
        )
    }

    #[test]
    fn an_entry_whose_packages_both_halves_take_never_wins() {
        let found = report(&wide_and_halves(PERMANENT, PERMANENT));
        assert_eq!(
            found.shadowed,
            vec![Shadowed {
                index: 0,
                by: [1, 2],
                through: None
            }]
        );
        assert_eq!(
            found.strict_failure().as_deref(),
            Some("changes nothing: 0, never wins: 1")
        );
    }

    /// The wide entry wins again the day after the dated half lapses, so it is not dead.
    #[test]
    fn a_dated_half_shadows_only_through_its_expiry() {
        let packages = wide_and_halves(
            "    expires: \"2026-12-01\"\n",
            "    expires: \"2026-11-30\"\n",
        );
        let found = report(&packages);
        assert_eq!(found.shadowed[0].through, Some(date(2026, 11, 30)));
        assert_eq!(found.never_wins().count(), 0);
        assert_eq!(found.strict_failure(), None);

        assert!(report_on(date(2026, 12, 1), &packages).shadowed.is_empty());
    }

    #[test]
    fn one_half_is_not_a_cover() {
        let packages = format!(
            "{}{}",
            entry("", PERMANENT),
            entry(", has_install_scripts: true", PERMANENT)
        );
        assert!(report(&packages).shadowed.is_empty());
    }

    /// A half for one version leaves every other version to the wide entry.
    #[test]
    fn a_half_for_one_version_is_not_a_cover() {
        let packages = format!(
            "{}{}{}",
            entry("", PERMANENT),
            entry(", has_install_scripts: true", PERMANENT),
            entry(
                ", version: \"1.0.0\", has_install_scripts: false",
                PERMANENT
            )
        );
        assert!(report(&packages).shadowed.is_empty());
    }

    #[test]
    fn a_lapsed_entry_is_not_reported_as_shadowed() {
        let packages = format!(
            "{}{}{}",
            entry("", "    expires: \"2026-09-01\"\n"),
            entry(", has_install_scripts: true", PERMANENT),
            entry(", has_install_scripts: false", PERMANENT)
        );
        assert!(report(&packages).shadowed.is_empty());
    }

    #[test]
    fn an_entry_that_changes_nothing_fails_strict() {
        let found = report(
            "  - match: { ecosystem: npm, name: ms }\n    set: { cooldown_days: 7 }\n    reason: r\n",
        );
        assert_eq!(found.unchanged, vec![0]);
        assert_eq!(
            found.strict_failure().as_deref(),
            Some("changes nothing: 1, never wins: 0")
        );
    }

    #[test]
    fn the_shipped_example_lists_its_permanent_entry_and_nothing_else() {
        let (_, found) = load(
            Path::new(&format!(
                "{}/examples/policy.yaml",
                env!("CARGO_MANIFEST_DIR")
            )),
            date(2026, 9, 1),
            DEFAULT_EXPIRY_CEILING_DAYS,
        )
        .expect("the shipped example should load");
        assert_eq!(found.permanent, vec![0]);
        assert!(found.unchanged.is_empty() && found.shadowed.is_empty());
        assert_eq!(found.strict_failure(), None);
    }

    #[test]
    fn the_report_renders_as_the_golden_file_says() {
        let (_, found) = load(&fixture("dead.yaml"), TODAY, DEFAULT_EXPIRY_CEILING_DAYS)
            .expect("fixture should load");
        crate::golden::assert_matches("policy-check", "dead.txt", &found.render());
    }

    #[test]
    fn a_policy_that_cannot_be_read_exits_2_and_one_refused_exits_1() {
        let missing =
            load(&fixture("missing.yaml"), TODAY, DEFAULT_EXPIRY_CEILING_DAYS).unwrap_err();
        assert_eq!(missing.exit_code(), 2, "{missing}");

        let invalid = Refused::Policy(PolicyError::Invalid("x".to_owned()));
        assert_eq!(invalid.exit_code(), 1);
        assert_eq!(invalid.to_string(), "policy is not valid: x");

        let refused =
            load(&fixture("refused.yaml"), TODAY, DEFAULT_EXPIRY_CEILING_DAYS).unwrap_err();
        assert!(matches!(
            refused,
            Refused::Package(PackageError::Unjustified { .. })
        ));
        assert_eq!(refused.exit_code(), 1);
        assert!(
            refused.to_string().starts_with("packages[0] loosens"),
            "{refused}"
        );
    }
}
