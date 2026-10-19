//! `byrle policy check`: whether a policy loads, and which of its package entries do
//! nothing.
//!
//! See docs/engineering_decisions/0034-policy-check.md.

use super::merge::{self, Rule, RuleValues};
use super::packages::{self, PackageError};
use super::selector::Canonical;
use super::strictness::Strictness;
use super::{AdvisoryScore, Policy, PolicyError};
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
    checked(Policy::load(path), as_of, ceiling_days)
}

/// [`load`] on a policy already read.
pub fn checked(
    policy: Result<Policy, PolicyError>,
    as_of: Date,
    ceiling_days: i64,
) -> Result<(Policy, Report), Refused> {
    let policy = policy.map_err(Refused::Policy)?;
    packages::check(&policy, as_of, ceiling_days).map_err(Refused::Package)?;
    let report = Report::of(&policy, as_of);
    Ok((policy, report))
}

/// What `byrle policy check` prints and exits with.
#[derive(Debug, Default, PartialEq)]
pub struct Answer {
    pub report: String,
    pub notes: Vec<String>,
    pub code: u8,
}

/// `byrle policy check` on `loaded`, the policy `label` names, as of `as_of`: its report,
/// with outlived waivers when `fetch` gives the clients to ask, and `--strict`'s failure.
pub async fn answer(
    loaded: Result<(Policy, Report), Refused>,
    label: &str,
    as_of: Date,
    (strict, fetch): (bool, Option<&crate::ecosystem::Clients>),
) -> Answer {
    let (policy, mut report) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            return Answer {
                notes: vec![format!("{label}: {e}")],
                code: e.exit_code(),
                ..Answer::default()
            };
        }
    };
    let mut notes = Vec::new();
    if let Some(clients) = fetch {
        let (outlived, fetched) = outlived_waivers(&policy, clients, as_of).await;
        notes.extend(fetched);
        report.outlived = outlived;
    }
    let mut code = 0;
    if strict && let Some(failure) = report.strict_failure() {
        notes.push(format!("--strict: {failure}"));
        code = 1;
    }
    Answer {
        report: report.render(),
        notes,
        code,
    }
}

/// An entry whose every key later entries set again, for every package it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overridden {
    pub index: usize,
    /// The later entries that set its keys again, in file order.
    pub by: Vec<usize>,
    /// The last day the cover holds, the earliest expiry of `by`. `None` when none expires.
    pub through: Option<Date>,
}

impl Overridden {
    /// Which entries cover this one.
    pub fn cover(&self) -> String {
        let by: Vec<String> = self.by.iter().map(|&j| packages::label(j)).collect();
        let verb = if by.len() == 1 { "sets" } else { "set" };
        format!(
            "{}, after it, {verb} every key it sets again, for every package it matches",
            by.join(" and ")
        )
    }
}

/// A later entry that sets a key back over an earlier one, for the packages both match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reset {
    pub index: usize,
    pub over: usize,
    pub rule: Rule,
}

/// What a policy that loaded carries that does nothing.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub as_of: Date,
    /// Each entry's selector and reason, for naming it.
    entries: Vec<(String, String)>,
    /// Entries that change nothing.
    pub unchanged: Vec<usize>,
    /// Entries whose every key later entries set again, on `as_of`.
    pub overridden: Vec<Overridden>,
    /// Keys a later entry sets stricter than an earlier one, on `as_of`.
    pub resets: Vec<Reset>,
    /// Entries marked `permanent: true`, listed so each one stays visible.
    pub permanent: Vec<usize>,
    /// `advisory_scores` entries marked `permanent: true`, as their label, id and reason.
    pub permanent_scores: Vec<String>,
    /// Cooldown waivers whose version is now old enough without them, if dates were fetched.
    pub outlived: Vec<Outlived>,
}

/// A `packages` entry that shortens `cooldown_days` for one exact version.
pub struct Waiver {
    pub entry: usize,
    pub reference: crate::identity::PackageRef,
    /// The wait this entry shortens, which is the policy's own `cooldown_days`.
    pub global_days: u32,
}

/// A waiver whose version passed the global cooldown anyway.
#[derive(Debug, Clone, PartialEq)]
pub struct Outlived {
    pub entry: usize,
    pub purl: String,
    pub published: Date,
    /// The wait it passed, which is the policy's own `cooldown_days`.
    pub days: u32,
    /// The day the global `cooldown_days` stopped refusing this version.
    pub passed_on: Date,
}

/// Ask each waiver's registry when its version was published, and report the waivers whose
/// version the global `cooldown_days` would now admit anyway.
///
/// A waiver whose date cannot be read is reported as a note rather than as a finding: not
/// knowing is not the same as knowing it is unnecessary.
pub async fn outlived_waivers(
    policy: &Policy,
    clients: &crate::ecosystem::Clients,
    as_of: Date,
) -> (Vec<Outlived>, Vec<String>) {
    let mut outlived = Vec::new();
    let mut notes = Vec::new();
    for waiver in cooldown_waivers(policy) {
        match published(clients, &waiver.reference).await {
            Ok(Some(published)) => outlived.extend(waiver.outlived(published, as_of)),
            Ok(None) => notes.push(format!(
                "{} {}: the registry publishes no date for it",
                packages::label(waiver.entry),
                waiver.reference
            )),
            Err(e) => notes.push(format!(
                "{} {}: {e}",
                packages::label(waiver.entry),
                waiver.reference
            )),
        }
    }
    (outlived, notes)
}

/// When the registry says this version was published.
async fn published(
    clients: &crate::ecosystem::Clients,
    reference: &crate::identity::PackageRef,
) -> Result<Option<Date>, String> {
    let at = crate::ecosystem::Repository::of(reference.key().ecosystem());
    let metadata = crate::ecosystem::fetched(clients.metadata(at, reference.key()).await)?;
    let Some(record) = metadata.version(reference.version()) else {
        return Ok(None);
    };
    let times = clients.publish_times(at, reference.key()).await?;
    Ok(super::decide::Facts::from_record_and_times(record, times.as_ref()).published)
}

/// Every entry that shortens `cooldown_days` for one exact version.
pub fn cooldown_waivers(policy: &Policy) -> Vec<Waiver> {
    policy
        .packages
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            rule.set
                .cooldown_days
                .is_some_and(|days| days < policy.cooldown_days)
        })
        .filter_map(|(entry, rule)| {
            Some(Waiver {
                entry,
                reference: pinned_version(&rule.selector)?,
                global_days: policy.cooldown_days,
            })
        })
        .collect()
}

/// The one version a selector names, when it names one.
fn pinned_version(selector: &crate::policy::Selector) -> Option<crate::identity::PackageRef> {
    if let Some(purl) = &selector.purl {
        return purl.parse().ok();
    }
    let name = selector.name.as_deref()?;
    let version = selector.version.as_deref()?;
    if version.starts_with(super::selector::VERS) {
        return None;
    }
    let ecosystem = selector
        .ecosystem
        .parse()
        .expect("a version is loaded only for an ecosystem this build serves");
    let key = crate::identity::PackageKey::from_registry_name(ecosystem, name).ok()?;
    Some(
        key.at_version(version)
            .expect("a policy loads no empty version"),
    )
}

impl Waiver {
    /// Whether the version is old enough without this entry, as of `as_of`.
    pub fn outlived(&self, published: Date, as_of: Date) -> Option<Outlived> {
        let passed_on = published
            .checked_add(jiff::Span::new().days(i64::from(self.global_days)))
            .ok()?;
        (passed_on <= as_of).then(|| Outlived {
            entry: self.entry,
            purl: self.reference.to_string(),
            published,
            days: self.global_days,
            passed_on,
        })
    }
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

        let live: Vec<usize> = (0..policy.packages.len()).filter(|&i| live(i)).collect();
        let overridden = live
            .iter()
            .filter_map(|&i| overridden(policy, &selectors, &live, i))
            .collect();
        let mut resets = Vec::new();
        for (n, &j) in live.iter().enumerate() {
            for &i in live[..n]
                .iter()
                .filter(|&&i| selectors[i].overlaps(&selectors[j]))
            {
                let (later, earlier) = (&policy.packages[j], &policy.packages[i]);
                resets.extend(
                    Rule::ALL
                        .into_iter()
                        .filter(|&rule| {
                            merge::compare(
                                &later.selector.ecosystem,
                                rule,
                                RuleValues::from(&later.set),
                                RuleValues::from(&earlier.set),
                            ) == Strictness::Stricter
                        })
                        .map(|rule| Reset {
                            index: j,
                            over: i,
                            rule,
                        }),
                );
            }
        }

        Self {
            as_of,
            outlived: Vec::new(),
            entries: policy
                .packages
                .iter()
                .zip(&selectors)
                .map(|(entry, selector)| (selector.to_string(), entry.reason.clone()))
                .collect(),
            unchanged: (0..policy.packages.len())
                .filter(|&i| packages::changes_nothing(&findings, i))
                .filter(|&i| resets.iter().all(|r: &Reset| r.index != i))
                .collect(),
            overridden,
            resets,
            permanent: (0..policy.packages.len())
                .filter(|&i| policy.packages[i].permanent)
                .collect(),
            permanent_scores: policy
                .advisory_scores
                .iter()
                .enumerate()
                .filter(|(_, s)| s.permanent)
                .map(|(i, s)| {
                    format!(
                        "{} {}: {}",
                        AdvisoryScore::label(i),
                        s.advisory_id,
                        s.reason
                    )
                })
                .collect(),
        }
    }

    /// Entries that never apply, on any day.
    pub fn never_applies(&self) -> impl Iterator<Item = &Overridden> {
        self.overridden.iter().filter(|s| s.through.is_none())
    }

    /// Why `--strict` fails, when it does: an entry that changes nothing, or one that never
    /// applies.
    pub fn strict_failure(&self) -> Option<String> {
        let never = self.never_applies().count();
        let outlived = self.outlived.len();
        (!self.unchanged.is_empty() || never > 0 || outlived > 0).then(|| {
            format!(
                "changes nothing: {}, never applies: {never}, cooldown outlived: {outlived}",
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
                "never applies",
                self.never_applies()
                    .map(|s| format!("{}: {}", name(s.index), s.cover()))
                    .collect(),
            ),
            (
                "overridden until a later entry lapses",
                self.overridden
                    .iter()
                    .filter_map(|s| {
                        s.through
                            .map(|day| format!("{}: {}, through {day}", name(s.index), s.cover()))
                    })
                    .collect(),
            ),
            (
                "sets a key back over an earlier entry",
                self.resets
                    .iter()
                    .map(|r| {
                        format!(
                            "{}: sets `{}` back over {}, for the packages both match",
                            name(r.index),
                            r.rule.as_str(),
                            packages::label(r.over)
                        )
                    })
                    .collect(),
            ),
            (
                "cooldown waivers no longer needed",
                self.outlived
                    .iter()
                    .map(|o| {
                        format!(
                            "{} {}: published {}, past cooldown_days {} since {}",
                            packages::label(o.entry),
                            o.purl,
                            o.published,
                            o.days,
                            o.passed_on
                        )
                    })
                    .collect(),
            ),
            (
                "permanent",
                self.permanent
                    .iter()
                    .map(|&i| with_reason(i))
                    .chain(self.permanent_scores.iter().cloned())
                    .collect(),
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

/// Entry `i` of `live`, when every key it sets is set again by later live entries that
/// match every package it does: one whose selector contains it, or its two halves,
/// `has_install_scripts: true` and `false`. An id it ignores is set again only by an entry
/// that ignores it too, as ids add up.
fn overridden(
    policy: &Policy,
    selectors: &[Canonical],
    live: &[usize],
    i: usize,
) -> Option<Overridden> {
    let values = |j: usize| RuleValues::from(&policy.packages[j].set);
    let again = |j: usize, rule: Rule| match rule {
        Rule::IgnoredVulnAdvisoryIds => policy.packages[i]
            .set
            .ignored_vuln_advisory_ids
            .iter()
            .all(|id| {
                policy.packages[j]
                    .set
                    .ignored_vuln_advisory_ids
                    .contains(id)
            }),
        _ => values(j).sets(rule),
    };
    let later: Vec<usize> = live.iter().copied().filter(|&j| j > i).collect();
    let half = |scripts| {
        let narrow = Canonical {
            has_install_scripts: Some(scripts),
            ..selectors[i].clone()
        };
        later.iter().copied().find(|&j| selectors[j] == narrow)
    };
    let halves = selectors[i]
        .has_install_scripts
        .is_none()
        .then(|| Some([half(true)?, half(false)?]))
        .flatten();
    let mut by = Vec::new();
    let mut sets_any = false;
    for rule in Rule::ALL.into_iter().filter(|&rule| values(i).sets(rule)) {
        sets_any = true;
        let containing = later
            .iter()
            .copied()
            .find(|&j| selectors[i].contained_by(&selectors[j]) && again(j, rule));
        match (containing, halves) {
            (Some(j), _) => by.push(j),
            (None, Some([t, f])) if again(t, rule) && again(f, rule) => by.extend([t, f]),
            _ => return None,
        }
    }
    by.sort_unstable();
    by.dedup();
    let through = by
        .iter()
        .filter_map(|&j| policy.packages[j].expires)
        .map(|e| e.0)
        .min();
    sets_any.then_some(Overridden {
        index: i,
        by,
        through,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::DEFAULT_EXPIRY_CEILING_DAYS;
    use jiff::civil::date;

    const TODAY: Date = date(2026, 9, 13);
    const PERMANENT: &str = "    permanent: true\n";

    /// A policy with one waiver for `purl`, shortening a 30-day wait to nothing.
    fn waiving(selector: &str) -> Policy {
        Policy::parse(&format!(
            "version: 1\ncooldown_days: 30\npackages:\n  - match: {{ {selector} }}\n    \
             set: {{ cooldown_days: 0 }}\n    reason: urgent fix\n    permanent: true\n"
        ))
        .expect("the policy loads")
    }

    /// A waiver is an entry that shortens the wait for one exact version, not a range or a
    /// whole package.
    #[test]
    fn only_an_entry_naming_one_version_is_a_waiver() {
        for (selector, named) in [
            (
                "ecosystem: npm, purl: \"pkg:npm/lodash@4.17.21\"",
                Some("pkg:npm/lodash@4.17.21"),
            ),
            (
                "ecosystem: npm, name: lodash, version: \"4.17.21\"",
                Some("pkg:npm/lodash@4.17.21"),
            ),
            ("ecosystem: npm, name: lodash", None),
            (
                "ecosystem: npm, name: lodash, version: \"vers:npm/>=4.0.0\"",
                None,
            ),
        ] {
            let policy = waiving(selector);
            let found: Vec<String> = cooldown_waivers(&policy)
                .iter()
                .map(|w| w.reference.to_string())
                .collect();
            assert_eq!(found, named.into_iter().collect::<Vec<_>>(), "{selector}");
        }
    }

    /// An entry that does not shorten the wait is not a waiver, whatever else it sets. One
    /// setting the same wait changes nothing, which is its own section.
    #[test]
    fn an_entry_that_shortens_nothing_is_not_a_waiver() {
        for set in ["kev: allow", "cooldown_days: 30"] {
            let policy = Policy::parse(&format!(
                "version: 1\ncooldown_days: 30\npackages:\n  \
                 - match: {{ ecosystem: npm, purl: \"pkg:npm/lodash@4.17.21\" }}\n    \
                 set: {{ {set} }}\n    reason: reviewed\n    permanent: true\n"
            ))
            .expect("the policy loads");
            assert!(cooldown_waivers(&policy).is_empty(), "{set}");
        }
    }

    /// The day the global wait passed is the finding's date, and the day before it is not.
    #[test]
    fn a_waiver_outlives_its_cooldown_on_the_day_the_wait_passes() {
        let policy = waiving("ecosystem: npm, purl: \"pkg:npm/lodash@4.17.21\"");
        let waiver = &cooldown_waivers(&policy)[0];
        let published = date(2026, 9, 1);
        assert_eq!(waiver.outlived(published, date(2026, 9, 30)), None);
        assert_eq!(
            waiver.outlived(Date::MAX, Date::MAX),
            None,
            "a wait past the last date is never over"
        );
        let outlived = waiver
            .outlived(published, date(2026, 10, 1))
            .expect("30 days after 2026-09-01");
        assert_eq!(
            (outlived.published, outlived.passed_on, outlived.days),
            (published, date(2026, 10, 1), 30)
        );
    }

    /// The fetch path, against a registry that serves the lodash fixture.
    #[tokio::test]
    async fn a_waiver_whose_version_is_old_enough_is_reported() {
        use crate::util::test_support::{Answer, scripted};
        let full = crate::ecosystem::npm::fixture("lodash-4.17.21.full.json");
        let addr = scripted(vec![Answer::body(full)]).await;
        let clients = crate::ecosystem::Clients::from_env(&crate::env::testing::with(&[(
            crate::env::UPSTREAM_NPM,
            &format!("http://{addr}"),
        )]))
        .expect("the upstream parses");
        let policy = waiving("ecosystem: npm, purl: \"pkg:npm/lodash@4.17.21\"");

        let (outlived, notes) = outlived_waivers(&policy, &clients, TODAY).await;
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(outlived.len(), 1);
        assert_eq!(outlived[0].published, date(2021, 2, 20));

        let mut report = Report::of(&policy, TODAY);
        report.outlived = outlived;
        assert!(
            report.render().contains(
                "packages[0] pkg:npm/lodash@4.17.21: published 2021-02-20, \
                 past cooldown_days 30 since 2021-03-22"
            ),
            "{}",
            report.render()
        );
        assert!(report.strict_failure().is_some(), "--strict fails on it");
    }

    /// A version the registry does not publish is a note, not a finding: not knowing is
    /// not knowing it is unnecessary.
    #[tokio::test]
    async fn a_waiver_whose_version_cannot_be_dated_is_a_note() {
        use crate::util::test_support::{Answer, scripted};
        let addr = scripted(vec![Answer::Status(404)]).await;
        let clients = crate::ecosystem::Clients::from_env(&crate::env::testing::with(&[(
            crate::env::UPSTREAM_NPM,
            &format!("http://{addr}"),
        )]))
        .expect("the upstream parses");
        let policy = waiving("ecosystem: npm, purl: \"pkg:npm/lodash@4.17.21\"");

        let (outlived, notes) = outlived_waivers(&policy, &clients, TODAY).await;
        assert!(outlived.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("pkg:npm/lodash@4.17.21"), "{notes:?}");
    }

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

    /// Halves written after the wide entry set its key again for every package it matches.
    #[test]
    fn an_entry_whose_packages_both_later_halves_take_never_applies() {
        let found = report(&wide_and_halves(PERMANENT, PERMANENT));
        assert_eq!(
            found.overridden,
            vec![Overridden {
                index: 0,
                by: vec![1, 2],
                through: None
            }]
        );
        assert_eq!(
            found.strict_failure().as_deref(),
            Some("changes nothing: 0, never applies: 1, cooldown outlived: 0")
        );
        let halves_first = format!(
            "{}{}{}",
            entry(", has_install_scripts: true", PERMANENT),
            entry(", has_install_scripts: false", PERMANENT),
            entry("", PERMANENT)
        );
        assert_eq!(
            report(&halves_first).overridden,
            [
                Overridden {
                    index: 0,
                    by: vec![2],
                    through: None
                },
                Overridden {
                    index: 1,
                    by: vec![2],
                    through: None
                }
            ],
            "the wide entry, written last, contains each half"
        );
    }

    /// A later entry whose selector contains an earlier one sets its keys again; an earlier
    /// one does not, and a later one setting another key leaves the key it sets.
    #[test]
    fn a_later_containing_entry_overrides_and_an_earlier_one_does_not() {
        let wide = "  - match: { ecosystem: npm, name: \"left*\" }\n    \
                    set: { install_scripts: allow }\n    reason: r\n    permanent: true\n";
        let narrow = entry("", PERMANENT);
        let found = report(&format!("{narrow}{wide}"));
        assert_eq!(found.overridden.len(), 1);
        assert_eq!(
            (found.overridden[0].index, &found.overridden[0].by),
            (0, &vec![1])
        );
        assert_eq!(
            found.overridden[0].cover(),
            "packages[1], after it, sets every key it sets again, for every package it matches"
        );
        assert!(found.resets.is_empty());
        assert!(report(&format!("{wide}{narrow}")).overridden.is_empty());
        let other_key = "  - match: { ecosystem: npm, name: \"left*\" }\n    \
                         set: { kev: allow }\n    reason: r\n    permanent: true\n";
        assert!(
            report(&format!("{narrow}{other_key}"))
                .overridden
                .is_empty()
        );
    }

    /// Ids add up, so a later entry sets an earlier one's ignored ids again only by
    /// ignoring each of them.
    #[test]
    fn ignored_ids_are_set_again_only_by_an_entry_ignoring_all_of_them() {
        let ids = |name: &str, ids: &str| {
            format!(
                "  - match: {{ ecosystem: npm, name: \"{name}\" }}\n    \
                 set: {{ ignored_vuln_advisory_ids: [{ids}] }}\n    reason: r\n    permanent: true\n"
            )
        };
        let first = ids("lodash", "GHSA-a, GHSA-b");
        assert!(
            report(&format!("{first}{}", ids("lo*", "GHSA-a")))
                .overridden
                .is_empty()
        );
        assert_eq!(
            report(&format!("{first}{}", ids("lo*", "GHSA-b, GHSA-a, GHSA-c")))
                .overridden
                .len(),
            1
        );
    }

    /// A later entry setting a key back to the setting's own value, over an earlier entry
    /// it overlaps, is reported as doing so, not as changing nothing.
    #[test]
    fn a_later_entry_setting_a_key_back_is_reported() {
        let back = "  - match: { ecosystem: npm, name: \"left*\" }\n    \
                    set: { install_scripts: block }\n    reason: r\n";
        let found = report(&format!("{}{back}", entry("", PERMANENT)));
        assert_eq!(
            found.resets,
            [Reset {
                index: 1,
                over: 0,
                rule: Rule::InstallScripts
            }]
        );
        assert!(found.unchanged.is_empty(), "{:?}", found.unchanged);
        assert_eq!(found.never_applies().count(), 1, "packages[0] is undone");
        let rendered = found.render();
        assert!(
            rendered.contains(
                "packages[1] npm:left*: sets `install_scripts` back over packages[0], for the \
                 packages both match"
            ),
            "{rendered}"
        );
        let apart = "  - match: { ecosystem: npm, name: \"right*\" }\n    \
                     set: { install_scripts: block }\n    reason: r\n";
        let found = report(&format!("{}{apart}", entry("", PERMANENT)));
        assert!(found.resets.is_empty());
        assert_eq!(found.unchanged, [1]);
    }

    /// The wide entry applies again the day after the dated half lapses, so it is not dead.
    #[test]
    fn a_dated_half_overrides_only_through_its_expiry() {
        let packages = wide_and_halves(
            "    expires: \"2026-12-01\"\n",
            "    expires: \"2026-11-30\"\n",
        );
        let found = report(&packages);
        assert_eq!(found.overridden[0].through, Some(date(2026, 11, 30)));
        assert_eq!(found.never_applies().count(), 0);
        assert_eq!(found.strict_failure(), None);

        assert!(
            report_on(date(2026, 12, 1), &packages)
                .overridden
                .is_empty()
        );
    }

    /// Halves cover a key only when both set it.
    #[test]
    fn halves_of_which_one_sets_another_key_are_not_a_cover() {
        let packages = format!(
            "{}{}  - match: {{ ecosystem: npm, name: left-pad, has_install_scripts: false }}\n    \
             set: {{ cooldown_days: 0 }}\n    reason: r\n{PERMANENT}",
            entry("", PERMANENT),
            entry(", has_install_scripts: true", PERMANENT)
        );
        assert!(report(&packages).overridden.is_empty());
    }

    #[test]
    fn one_half_is_not_a_cover() {
        let packages = format!(
            "{}{}",
            entry("", PERMANENT),
            entry(", has_install_scripts: true", PERMANENT)
        );
        assert!(report(&packages).overridden.is_empty());
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
        assert!(report(&packages).overridden.is_empty());
    }

    #[test]
    fn a_lapsed_entry_is_not_reported_as_overridden() {
        let packages = format!(
            "{}{}{}",
            entry("", "    expires: \"2026-09-01\"\n"),
            entry(", has_install_scripts: true", PERMANENT),
            entry(", has_install_scripts: false", PERMANENT)
        );
        assert!(report(&packages).overridden.is_empty());
    }

    #[test]
    fn an_entry_that_changes_nothing_fails_strict() {
        let found = report(
            "  - match: { ecosystem: npm, name: ms }\n    set: { cooldown_days: 7 }\n    reason: r\n",
        );
        assert_eq!(found.unchanged, vec![0]);
        assert_eq!(
            found.strict_failure().as_deref(),
            Some("changes nothing: 1, never applies: 0, cooldown outlived: 0")
        );
    }

    #[test]
    fn a_permanent_advisory_score_is_listed_with_the_permanent_entries() {
        let policy = Policy::parse(
            "version: 1\nadvisory_scores:\n\
             - { advisory_id: GHSA-a, cvss: 5.0, reason: dated, expires: \"2026-10-01\" }\n\
             - { advisory_id: GHSA-b, cvss: 7.5, reason: vendor scored it, permanent: true }\n",
        )
        .expect("policy should load");
        let found = Report::of(&policy, TODAY);
        assert_eq!(
            found.permanent_scores,
            ["advisory_scores[1] GHSA-b: vendor scored it"]
        );
        let out = found.render();
        assert!(
            out.contains("\npermanent\n  advisory_scores[1] GHSA-b: vendor scored it\n"),
            "{out}"
        );
    }

    #[test]
    fn the_shipped_example_lists_its_permanent_entries_and_nothing_else() {
        let (_, found) = load(
            Path::new(&format!(
                "{}/examples/policy.yaml",
                env!("CARGO_MANIFEST_DIR")
            )),
            date(2026, 9, 1),
            DEFAULT_EXPIRY_CEILING_DAYS,
        )
        .expect("the shipped example should load");
        assert_eq!(found.permanent, vec![0, 4]);
        assert!(found.unchanged.is_empty() && found.overridden.is_empty());
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

    /// A version the registry does not list, or whose publish times cannot be fetched, is a
    /// note naming the entry.
    #[tokio::test]
    async fn a_waiver_that_cannot_be_dated_says_why() {
        use crate::util::test_support::{Answer, scripted};
        let abbrev = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        for (answers, purl, says) in [
            (
                vec![Answer::body(abbrev.clone())],
                "pkg:npm/lodash@0.0.1",
                "the registry publishes no date for it",
            ),
            (
                vec![Answer::body(abbrev.clone()), Answer::Status(500)],
                "pkg:npm/lodash@4.17.21",
                "publish times could not be fetched",
            ),
        ] {
            let addr = scripted(answers).await;
            let clients = crate::ecosystem::Clients::from_env(&crate::env::testing::with(&[(
                crate::env::UPSTREAM_NPM,
                &format!("http://{addr}"),
            )]))
            .expect("the upstream parses");
            let policy = waiving(&format!("ecosystem: npm, purl: \"{purl}\""));
            let (outlived, notes) = outlived_waivers(&policy, &clients, TODAY).await;
            assert!(outlived.is_empty());
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(notes[0].contains(says), "{says}: {notes:?}");
        }
    }

    /// An entry that names no package is no waiver.
    #[test]
    fn an_entry_naming_no_package_is_no_waiver() {
        assert!(cooldown_waivers(&waiving("ecosystem: npm, has_install_scripts: true")).is_empty());
        assert!(
            cooldown_waivers(&waiving(
                "ecosystem: npm, name: \"@scope/\", version: \"1.0.0\""
            ))
            .is_empty(),
            "a name that makes no package key"
        );
    }
}
