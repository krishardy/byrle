//! Where a decision becomes a response.
//!
//! Decision #4 splits enforcement in two, and the split is not a detail:
//!
//! - **On resolution**, a refused version is filtered out of the metadata so the
//!   resolver picks a clean one by itself. The client sees a 200 with fewer versions.
//! - **On a pinned fetch**, there is nothing to resolve. The client already decided, from
//!   a lockfile, and the only honest answer is a refusal.
//!
//! This module is the pinned half. A tarball request names one version, the record for it
//! is already in the store because the digest had to be known before the fetch, so the
//! engine can be asked and answered before a byte leaves upstream.
//!
//! # Why `quarantine` refuses here too
//!
//! Quarantine means "refused now, allowed later". On the resolution path that is a
//! filter and the install succeeds on another version. On a pinned fetch there is no
//! other version to pick, so it refuses like a block, and says when it lapses. The
//! difference survives in what the client is told, not in whether it gets bytes.

use super::decide::{Check, Decision, Intel, Outcome, Provenance};
use super::{Action, Policy};
use crate::intel::store::PackageIntel;
use crate::policy::decide::{Facts, decide};
use crate::record::PackageRecord;
use jiff::civil::Date;

/// What the proxy does with an artifact request.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Fetch it.
    Serve,
    /// Refuse it, and say why.
    Refuse(Refusal),
}

/// A refusal, in the words the client is given.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub action: Action,
    /// The purl, as the policy would spell it.
    pub purl: String,
    /// One line per check that decided against the package, strongest first.
    pub reasons: Vec<String>,
}

impl Refusal {
    /// The body the client reads. npm shows it on a failed install.
    pub fn message(&self) -> String {
        let mut out = format!(
            "waharoa: {} is {} by policy\n",
            self.purl,
            // `Verdict::Refuse` is only built from a non-allow action.
            if self.action == Action::Block {
                "blocked"
            } else {
                "held"
            }
        );
        for reason in &self.reasons {
            out.push_str("  - ");
            out.push_str(reason);
            out.push('\n');
        }
        out
    }
}

/// A check this build cannot answer, because the fact it needs is not there.
///
/// Not the same as a check that passed. `decide` answers every check in the vector, and
/// for a missing fact it answers in the safe direction: an unknown publish date is not
/// old enough, so `cooldown_days` fails. That is right for the engine and wrong for a
/// proxy, where it refuses every package on a fact the registry never sent.
///
/// So the result is dropped here rather than reported as a pass, and the reason is
/// carried out so startup can say which settings are configured and inert. A check that
/// quietly became a pass would be the worse failure.
#[derive(Debug, Clone, PartialEq)]
pub struct Unenforceable {
    pub check: Check,
    pub why: &'static str,
}

/// The checks this build cannot answer for a record.
///
/// `intel` is whether a store was consulted for these facts, taken from the caller's
/// `Facts`. Rebuilding the facts here from the record alone would always read
/// `NotConsulted`.
pub fn unenforceable(
    policy: &Policy,
    record: &PackageRecord,
    times: Option<&super::facts::PublishTimes>,
    intel: Intel,
    provenance: &Provenance,
) -> Vec<Unenforceable> {
    let cooldown = match Facts::can_answer_cooldown(record, times) {
        super::facts::Answerable::Missing(why) => Some(why),
        super::facts::Answerable::Yes => None,
    };
    unenforceable_given(policy, cooldown, intel, provenance)
}

/// [`unenforceable`] from facts alone, as `waharoa audit verify` has them. The same checks:
/// a record only changes why a cooldown has no date, not whether it has one.
pub fn unenforceable_of(policy: &Policy, facts: &Facts) -> Vec<Unenforceable> {
    let cooldown = facts
        .published
        .is_none()
        .then_some("no publish date was recorded for this version");
    unenforceable_given(policy, cooldown, facts.intel, &facts.provenance)
}

/// The checks that cannot be answered, given why the cooldown has no date when it has none.
fn unenforceable_given(
    policy: &Policy,
    cooldown: Option<&'static str>,
    intel: Intel,
    provenance: &Provenance,
) -> Vec<Unenforceable> {
    let mut out = Vec::new();
    if let Provenance::Unknown(why) = provenance {
        out.push(Unenforceable {
            check: Check::Provenance,
            why,
        });
    }
    if policy.uses_cooldown()
        && let Some(why) = cooldown
    {
        out.push(Unenforceable {
            check: Check::CooldownDays,
            why,
        });
    }
    // Three checks read the advisory list. With nothing to ask, an empty list is an absent
    // answer rather than a clean one, and reporting them as passes would claim a check ran
    // that never could.
    match intel {
        Intel::NotConsulted => out.extend([Check::KnownMalware, Check::Kev, Check::MaxCvss].map(
            |check| Unenforceable {
                check,
                why: "no intel store was consulted, so nothing was asked",
            },
        )),
        // The store answers and has not loaded the KEV catalogue. OSV carries no exploitation
        // data.
        Intel::Consulted {
            exploitation_loaded: false,
        } => out.push(Unenforceable {
            check: Check::Kev,
            why: "no exploitation stream is loaded, so no advisory is marked exploited",
        }),
        Intel::Consulted {
            exploitation_loaded: true,
        } => {}
    }
    out
}

/// The decision with the checks this build cannot answer taken out: what the proxy acts
/// on.
///
/// `Decision::action` over the whole vector counts an answer to a fact that was never
/// there, such as a quarantine for a publish date the registry did not send. `explain` and
/// `policy diff` report the action from this, so neither names a verdict the proxy does not
/// reach.
pub fn enforced(decision: &Decision, unenforceable: &[Unenforceable]) -> Decision {
    let mut kept = decision.clone();
    kept.results
        .retain(|r| !unenforceable.iter().any(|u| u.check == r.check));
    kept
}

/// Decide a pinned artifact request.
///
/// `None` for the policy is Stage 1 behaviour: nothing is enforced and everything
/// serves. That is a distinct state from a policy that allows everything, and the log
/// should be able to tell them apart. `None` for `intel` is a build with no store, and the
/// three checks that read advisories are dropped as unenforceable.
pub fn artifact(
    policy: Option<&Policy>,
    record: &PackageRecord,
    times: Option<&super::facts::PublishTimes>,
    intel: Option<&PackageIntel>,
    provenance: &Provenance,
    today: Date,
) -> Verdict {
    let Some(policy) = policy else {
        return Verdict::Serve;
    };
    let mut facts = Facts::from_record_and_times(record, times).with_provenance(provenance.clone());
    if let Some(intel) = intel {
        facts = facts.with_intel(intel);
    }
    let dropped = unenforceable(policy, record, times, facts.intel, &facts.provenance);
    verdict(
        policy,
        &facts,
        &enforced(&decide(policy, &facts, today), &dropped),
    )
}

fn verdict(policy: &Policy, facts: &Facts, decision: &Decision) -> Verdict {
    let action = decision.action();
    if action == Action::Allow {
        return Verdict::Serve;
    }
    Verdict::Refuse(Refusal {
        action,
        purl: format!("pkg:{}/{}@{}", facts.ecosystem, facts.name, facts.version),
        reasons: decision
            .reasons()
            .iter()
            .map(|r| reason(r, policy, facts, decision.entry))
            .collect(),
    })
}

/// The day `cooldown_days` stops refusing this version.
///
/// `None` when the registry published no date for it, which is the case the check is
/// dropped as unenforceable for anyway.
fn lifts_on(policy: &Policy, facts: &Facts, entry: Option<usize>) -> Option<Date> {
    let days = i64::from(super::decide::cooldown_required(policy, entry));
    facts
        .published?
        .checked_add(jiff::Span::new().days(days))
        .ok()
}

/// One check's answer, in a line a person can act on.
fn reason(
    result: &super::decide::Result,
    policy: &Policy,
    facts: &Facts,
    entry: Option<usize>,
) -> String {
    let name = result.check.as_str();
    match (&result.check, &result.outcome) {
        // The publisher's own words. A deprecation with nothing to say is not one: see
        // `npm::normalize`.
        (Check::Deprecated, _) => match facts.deprecated.as_deref() {
            Some(message) if !message.is_empty() => format!("{name}: {message}"),
            _ => format!("{name}: deprecated by its publisher"),
        },
        // The publisher's own words for why the release was withdrawn, when they gave any.
        (Check::Yanked, _) => match facts.yanked.as_deref() {
            Some(reason) if !reason.is_empty() => format!("{name}: withdrawn, {reason}"),
            _ => format!("{name}: withdrawn by the registry"),
        },
        (Check::Denials, _) => format!("{name}: this exact version is denied"),
        (Check::Provenance, _) => format!("{name}: {}", facts.provenance.describe()),
        (Check::KnownMalware, _) => format!("{name}: reported as malware"),
        // A quarantine that lapses is worth a date: the client is told when this version
        // becomes installable rather than only that it is too new.
        (Check::CooldownDays, _) => match lifts_on(policy, facts, entry) {
            Some(date) => format!("{name}: published too recently, installable on {date}"),
            None => format!("{name}: published too recently, and this lapses as it ages"),
        },
        (_, Outcome::Failed(action)) => format!("{name}: {}", action.as_str()),
        // A check that passed or was excepted is not a reason, so this is unreachable
        // through `reasons()`. Rendered rather than panicked on: a wrong line in an error
        // body is better than a crash in the refusal path.
        (_, outcome) => format!("{name}: {outcome:?}"),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ecosystem::npm::normalize_packument;
    use crate::record::DocumentDetail;

    const TODAY: Date = jiff::civil::date(2026, 9, 13);

    fn record() -> PackageRecord {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/lodash-4.17.21.full.json"
        );
        normalize_packument(
            &std::fs::read(path).expect("fixture is missing"),
            DocumentDetail::Full,
        )
        .expect("fixture should normalise")
        .version("4.17.21")
        .expect("version is in the fixture")
        .clone()
    }

    fn loaded(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    /// A store with one advisory for every version.
    fn everywhere(record: crate::intel::store::Record, exploitation_loaded: bool) -> PackageIntel {
        PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![(None, record)],
            ranges: Vec::new(),
            exploitation_loaded,
        }
    }

    fn malware_everywhere() -> PackageIntel {
        everywhere(
            crate::intel::store::Record {
                advisory_id: "MAL-1".to_owned(),
                aliases: Vec::new(),
                source: "osv".to_owned(),
                cvss: None,
                band: None,
                cvss_source: None,
                exploited: false,
                malware: true,
            },
            false,
        )
    }

    /// `waharoa audit verify` has the facts and not the record. Every way a record can have
    /// or lack a publish date gives the same checks from either.
    #[test]
    fn the_facts_alone_give_the_same_unenforced_checks_as_the_record() {
        let policy = loaded("version: 1\ncooldown_days: 7\nkev: block\n");
        let dated = record();
        let undated = PackageRecord {
            published_at: None,
            ..record()
        };
        let times: super::super::facts::PublishTimes =
            [("4.17.21".to_owned(), jiff::Timestamp::UNIX_EPOCH)].into();
        let names = |found: Vec<Unenforceable>| -> Vec<&'static str> {
            found.iter().map(|u| u.check.as_str()).collect()
        };
        for (record, times) in [
            (&dated, None),
            (&undated, None),
            (&undated, Some(&times)),
            (&undated, Some(&super::super::facts::PublishTimes::new())),
        ] {
            let facts =
                Facts::from_record_and_times(record, times).with_provenance(Provenance::Consistent);
            let from_record = names(unenforceable(
                &policy,
                record,
                times,
                Intel::NotConsulted,
                &Provenance::Consistent,
            ));

            assert_eq!(from_record, names(unenforceable_of(&policy, &facts)));
        }
        assert_eq!(
            names(unenforceable_of(
                &policy,
                &Facts::from_record_and_times(&undated, None)
            )),
            [
                "provenance",
                "cooldown_days",
                "known_malware",
                "kev",
                "max_cvss"
            ]
        );
    }

    /// Exploited, and scored under the default `max_cvss`, so only `kev` can refuse it.
    #[test]
    fn an_exploited_advisory_refuses_only_once_the_catalogue_is_loaded() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");
        let exploited = |exploitation_loaded| {
            everywhere(
                crate::intel::store::Record {
                    advisory_id: "GHSA-1".to_owned(),
                    aliases: vec!["CVE-2020-11023".to_owned()],
                    source: "osv".to_owned(),
                    cvss: Some(5.0),
                    band: None,
                    cvss_source: None,
                    exploited: exploitation_loaded,
                    malware: false,
                },
                exploitation_loaded,
            )
        };
        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &record(),
            None,
            Some(&exploited(true)),
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("an exploited advisory must be refused");
        };
        assert_eq!(refusal.reasons, ["kev: block"]);
        assert_eq!(
            artifact(
                Some(&policy),
                &record(),
                None,
                Some(&exploited(false)),
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    #[test]
    fn known_malware_in_the_store_refuses_the_artifact() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");
        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &record(),
            None,
            Some(&malware_everywhere()),
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("known malware must be refused");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons, ["known_malware: reported as malware"]);
    }

    /// The same record with no store: the malware check is dropped, not failed.
    #[test]
    fn without_a_store_the_malware_check_cannot_refuse() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");
        assert_eq!(
            artifact(
                Some(&policy),
                &record(),
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    #[test]
    fn a_consulted_store_leaves_every_intel_check_but_kev_enforced() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");
        let dropped = |exploitation_loaded| {
            unenforceable(
                &policy,
                &record(),
                None,
                Intel::Consulted {
                    exploitation_loaded,
                },
                &Provenance::Consistent,
            )
            .iter()
            .map(|u| u.check)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            dropped(false),
            [Check::Kev],
            "a store without the KEV catalogue has no exploitation data"
        );
        assert_eq!(dropped(true), []);
    }

    #[test]
    fn no_policy_at_all_serves_everything() {
        assert_eq!(
            artifact(None, &record(), None, None, &Provenance::Consistent, TODAY),
            Verdict::Serve
        );
    }

    #[test]
    fn a_policy_that_denies_nothing_serves() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");

        assert_eq!(
            artifact(
                Some(&policy),
                &record(),
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    #[test]
    fn a_denied_version_is_refused_and_the_reason_names_the_check() {
        let policy = loaded(
            "version: 1\ncooldown_days: 0\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
        );

        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &record(),
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("a denied version must be refused");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.purl, "pkg:npm/lodash@4.17.21");
        assert_eq!(refusal.reasons, ["denials: this exact version is denied"]);
        assert_eq!(
            refusal.message(),
            "waharoa: pkg:npm/lodash@4.17.21 is blocked by policy\n  \
             - denials: this exact version is denied\n"
        );
    }

    #[test]
    fn denying_a_different_version_of_the_same_package_does_not_refuse() {
        let policy = loaded(
            "version: 1\ncooldown_days: 0\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.20\n    reason: test\n",
        );

        assert_eq!(
            artifact(
                Some(&policy),
                &record(),
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    #[test]
    fn a_package_with_install_scripts_is_refused_when_the_policy_says_block() {
        let mut r = record();
        r.has_install_scripts = true;
        let policy = loaded("version: 1\ncooldown_days: 0\ninstall_scripts: block\n");

        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &r,
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("install scripts must be refused when the policy blocks them");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons, ["install_scripts: block"]);

        // The same package passes when the policy allows them.
        let allowing = loaded("version: 1\ncooldown_days: 0\ninstall_scripts: allow\n");
        assert_eq!(
            artifact(
                Some(&allowing),
                &r,
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    /// A pinned fetch has no other version to fall back to, so quarantine refuses. What
    /// separates it from a block is what the client is told: the day it lapses.
    #[test]
    fn quarantine_refuses_on_a_pinned_fetch_and_says_when_it_lapses() {
        let mut r = record();
        r.published_at = Some(
            "2026-09-12T00:00:00Z"
                .parse()
                .expect("timestamp should parse"),
        );
        let policy = loaded("version: 1\ncooldown_days: 30\n");

        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &r,
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("a version inside the cooldown must be refused on a pinned fetch");
        };
        assert_eq!(refusal.action, Action::Quarantine);
        assert!(
            refusal
                .message()
                .starts_with("waharoa: pkg:npm/lodash@4.17.21 is held by policy"),
            "held, not blocked: {}",
            refusal.message()
        );
        assert_eq!(
            refusal.reasons,
            ["cooldown_days: published too recently, installable on 2026-10-12"],
            "published 2026-09-12, 30 days"
        );

        // A package entry's own wait is the one the date is measured against.
        let shortened = loaded(
            "version: 1\ncooldown_days: 30\npackages:\n  \
             - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 3 }\n    \
             reason: reviewed\n    permanent: true\n",
        );
        let Verdict::Refuse(refusal) = artifact(
            Some(&shortened),
            &r,
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("2026-09-12 plus 3 days is still ahead of 2026-09-13");
        };
        assert_eq!(
            refusal.reasons,
            ["cooldown_days: published too recently, installable on 2026-09-15"]
        );
    }

    /// With no publish date there is no date to give. `unenforceable` drops the check
    /// before a verdict reaches this, so the line is reached only by asking for it.
    #[test]
    fn a_cooldown_with_no_publish_date_says_only_that_it_lapses() {
        let facts = Facts {
            published: None,
            ..Facts::from_record(&record())
        };
        let refused = super::super::decide::Result {
            check: Check::CooldownDays,
            outcome: Outcome::Failed(Action::Quarantine),
        };
        assert_eq!(
            reason(
                &refused,
                &loaded("version: 1\ncooldown_days: 30\n"),
                &facts,
                None
            ),
            "cooldown_days: published too recently, and this lapses as it ages"
        );
    }

    /// The lattice decides, so the strongest reason leads.
    #[test]
    fn a_block_and_a_quarantine_together_refuse_as_a_block() {
        let mut r = record();
        r.published_at = Some(
            "2026-09-12T00:00:00Z"
                .parse()
                .expect("timestamp should parse"),
        );
        let policy = loaded(
            "version: 1\ncooldown_days: 30\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
        );

        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &r,
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("must refuse");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons.len(), 2);
        assert!(
            refusal.reasons[0].starts_with("denials:"),
            "the block leads: {:?}",
            refusal.reasons
        );
    }

    /// Just the cooldown entry. The advisory checks are always unenforceable in this
    /// build, and that is covered on its own below.
    fn cooldown_entry(policy: &Policy, record: &PackageRecord) -> Option<Unenforceable> {
        unenforceable(
            policy,
            record,
            None,
            Intel::NotConsulted,
            &Provenance::Consistent,
        )
        .into_iter()
        .find(|u| u.check == Check::CooldownDays)
    }

    /// An empty advisory list with nothing to ask is not a clean answer.
    #[test]
    fn the_checks_that_read_advisories_are_unenforceable_with_no_stream() {
        let reported: Vec<Check> = unenforceable(
            &loaded("version: 1"),
            &record(),
            None,
            Intel::NotConsulted,
            &Provenance::Consistent,
        )
        .into_iter()
        .map(|u| u.check)
        .collect();

        assert!(reported.contains(&Check::KnownMalware), "{reported:?}");
        assert!(reported.contains(&Check::Kev), "{reported:?}");
        assert!(reported.contains(&Check::MaxCvss), "{reported:?}");
    }

    fn abbreviated() -> PackageRecord {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/lodash-4.17.21.abbrev.json"
        );
        normalize_packument(
            &std::fs::read(path).expect("fixture is missing"),
            DocumentDetail::Abbreviated,
        )
        .expect("fixture should normalise")
        .version("4.17.21")
        .expect("version is in the fixture")
        .clone()
    }

    /// The abbreviated packument is what `npm install` asks for and what the proxy
    /// fetches on its own behalf, so this is every record the build holds. Without the
    /// drop, a configured `cooldown_days` refuses all of them on a fact the registry
    /// never sent.
    #[test]
    fn a_cooldown_that_cannot_be_answered_is_dropped_rather_than_failed() {
        let policy = loaded("version: 1\ncooldown_days: 30\n");

        assert_eq!(
            cooldown_entry(&policy, &abbreviated()),
            Some(Unenforceable {
                check: Check::CooldownDays,
                why: "the abbreviated packument carries no publish times",
            })
        );
        assert_eq!(
            artifact(
                Some(&policy),
                &abbreviated(),
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    /// Dropping the check must not drop the rest of the vector.
    #[test]
    fn a_denial_still_refuses_an_abbreviated_record() {
        let policy = loaded(
            "version: 1\ncooldown_days: 30\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
        );

        let Verdict::Refuse(refusal) = artifact(
            Some(&policy),
            &abbreviated(),
            None,
            None,
            &Provenance::Consistent,
            TODAY,
        ) else {
            panic!("the denial must survive the cooldown being dropped");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons, ["denials: this exact version is denied"]);
    }

    /// A record that can answer is not dropped, so the check still bites where the fact
    /// exists.
    #[test]
    fn a_full_record_still_has_its_cooldown_enforced() {
        let mut r = record();
        r.published_at = Some(
            "2026-09-12T00:00:00Z"
                .parse()
                .expect("timestamp should parse"),
        );
        let policy = loaded("version: 1\ncooldown_days: 30\n");

        assert_eq!(cooldown_entry(&policy, &r), None);
        assert!(matches!(
            artifact(
                Some(&policy),
                &r,
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Refuse(_)
        ));
    }

    /// A cooldown of zero is off, so there is nothing to report as unenforceable.
    #[test]
    fn a_cooldown_of_zero_is_not_reported_as_unenforceable() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");

        assert_eq!(cooldown_entry(&policy, &abbreviated()), None);
        assert_eq!(
            artifact(
                Some(&policy),
                &abbreviated(),
                None,
                None,
                &Provenance::Consistent,
                TODAY
            ),
            Verdict::Serve
        );
    }

    #[test]
    fn a_scoped_package_is_refused_under_the_name_the_policy_spells() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/@babel_traverse-8.0.5.full.json"
        );
        let r = normalize_packument(
            &std::fs::read(path).expect("fixture is missing"),
            DocumentDetail::Full,
        )
        .expect("fixture should normalise")
        .version("8.0.5")
        .expect("version is in the fixture")
        .clone();

        // Both spellings of the same package. `%40` is what this codebase's own `Display`
        // emits for a scoped name, and what OSV uses.
        for spelling in [
            "pkg:npm/%40babel/traverse@8.0.5",
            "pkg:npm/@babel/traverse@8.0.5",
        ] {
            let policy = loaded(&format!(
                "version: 1\ncooldown_days: 0\n\
                 denials:\n  - purl: {spelling}\n    reason: test\n"
            ));

            let Verdict::Refuse(refusal) = artifact(
                Some(&policy),
                &r,
                None,
                None,
                &Provenance::Consistent,
                TODAY,
            ) else {
                panic!("a scoped package must be refusable, written as `{spelling}`");
            };
            assert_eq!(refusal.purl, "pkg:npm/@babel/traverse@8.0.5");
        }
    }

    /// A deprecation with nothing to say is still named, and a check that did not refuse
    /// renders as its outcome rather than panicking.
    #[test]
    fn a_reason_is_always_a_line() {
        let policy = loaded("version: 1\ndeprecated: block\n");
        let facts = Facts {
            deprecated: Some(String::new()),
            ..Facts::from_record(&record())
        };
        let result = |check, outcome| crate::policy::decide::Result { check, outcome };
        assert_eq!(
            reason(
                &result(Check::Deprecated, Outcome::Failed(Action::Block)),
                &policy,
                &facts,
                None
            ),
            "deprecated: deprecated by its publisher"
        );
        assert_eq!(
            reason(&result(Check::Kev, Outcome::Passed), &policy, &facts, None),
            "kev: Passed"
        );
    }
}
