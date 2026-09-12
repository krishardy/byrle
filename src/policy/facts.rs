//! What the proxy knows about a package, as the policy engine wants it.
//!
//! [`crate::record::PackageRecord`] is what Stage 1 normalises out of a packument.
//! [`Facts`] is what [`super::decide`] asks for. This is the join, and it is nearly
//! one-to-one: the fields the record carries map straight across, and the fields it
//! cannot carry are the intel ones.
//!
//! # What this build cannot answer
//!
//! `known_malware` is `false` and `advisories` is empty, because no advisory stream
//! exists yet. Those are not "clean" answers, they are absent ones, and
//! [`Facts::from_record`] cannot tell the difference. What stops that reading as a pass
//! is `Capabilities::gaps`, which reports at startup that nothing can originate a
//! finding for an enabled ecosystem.
//!
//! # `cooldown_days` cannot be answered from what the proxy fetches
//!
//! `published` comes from the packument's `time` map, which npm sends only in the full
//! document. `npm install` asks for the abbreviated one, and so does the proxy on its own
//! behalf (`fetch_and_store`), so `published` is `None` for every record this build holds.
//!
//! [`super::decide`] treats an unknown publish date as not old enough, which is the
//! correct direction and makes `cooldown_days` fail every package rather than pass it.
//! That is why this build does not enforce `cooldown_days`: see
//! [`Facts::can_answer`].

use super::decide::Facts;
use crate::record::{PackageRecord, PackumentDetail};
use jiff::civil::Date;
use jiff::tz::TimeZone;

/// A check this build can produce a real answer for.
///
/// Not a policy setting: the operator does not choose this, the available facts do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answerable {
    /// Every fact is present.
    Yes,
    /// The fact the check needs is not in what the registry sent.
    Missing(&'static str),
}

impl Facts {
    /// Build the facts from a record, with no intel.
    pub fn from_record(record: &PackageRecord) -> Self {
        let key = record.package.key();
        Self {
            ecosystem: key.ecosystem().as_str().to_owned(),
            name: key.registry_name(),
            version: record.package.version().to_owned(),
            published: published_date(record),
            // Absent, not clean. Nothing can originate a finding in this build.
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: record.has_install_scripts,
        }
    }

    /// Whether `cooldown_days` can be answered for this record.
    ///
    /// The abbreviated packument carries no `time` map, and that is the document both
    /// `npm install` and the proxy's own fetch ask for. Asking the engine anyway would
    /// fail every package on a fact the registry never sent.
    pub fn can_answer_cooldown(record: &PackageRecord) -> Answerable {
        match published_date(record) {
            Some(_) => Answerable::Yes,
            None => Answerable::Missing(match record.source {
                PackumentDetail::Abbreviated => {
                    "the abbreviated packument carries no publish times"
                }
                PackumentDetail::Full => "the registry published no time for this version",
            }),
        }
    }
}

/// The publish date in UTC.
///
/// The policy is written in civil dates and the registry publishes an instant, so a
/// timezone has to be chosen. UTC, so the same package gets the same answer on every
/// proxy: a local zone would put two replicas a day apart across midnight.
fn published_date(record: &PackageRecord) -> Option<Date> {
    record
        .published_at
        .map(|at| at.to_zoned(TimeZone::UTC).date())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npm::normalize_packument;
    use crate::policy::decide::{Check, Outcome, decide};
    use crate::policy::{Action, Policy};

    fn fixture(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
        std::fs::read(format!("{path}{name}")).expect("fixture is missing")
    }

    fn record(name: &str, detail: PackumentDetail, version: &str) -> PackageRecord {
        normalize_packument(&fixture(name), detail)
            .expect("fixture should normalise")
            .version(version)
            .expect("version is in the fixture")
            .clone()
    }

    fn abbreviated() -> PackageRecord {
        record(
            "lodash-4.17.21.abbrev.json",
            PackumentDetail::Abbreviated,
            "4.17.21",
        )
    }

    fn full() -> PackageRecord {
        record(
            "lodash-4.17.21.full.json",
            PackumentDetail::Full,
            "4.17.21",
        )
    }

    fn policy(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    #[test]
    fn a_record_becomes_the_facts_the_engine_asks_for() {
        let facts = Facts::from_record(&full());

        assert_eq!(facts.ecosystem, "npm");
        assert_eq!(facts.name, "lodash");
        assert_eq!(facts.version, "4.17.21");
        assert!(!facts.has_install_scripts);
        assert!(facts.published.is_some());
    }

    #[test]
    fn a_scoped_package_keeps_the_name_the_registry_uses() {
        let r = record(
            "@babel_traverse-8.0.5.abbrev.json",
            PackumentDetail::Abbreviated,
            "8.0.5",
        );

        assert_eq!(Facts::from_record(&r).name, "@babel/traverse");
    }

    /// The gap that decides what this build can enforce.
    ///
    /// `npm install` asks for the abbreviated document and so does the proxy's own
    /// fetch, so no record it holds carries a publish time.
    #[test]
    fn the_abbreviated_packument_answers_no_publish_date() {
        assert_eq!(Facts::from_record(&abbreviated()).published, None);
        assert_eq!(
            Facts::can_answer_cooldown(&abbreviated()),
            Answerable::Missing("the abbreviated packument carries no publish times")
        );

        // The same version read the other way does carry one.
        assert!(Facts::from_record(&full()).published.is_some());
        assert_eq!(Facts::can_answer_cooldown(&full()), Answerable::Yes);
    }

    /// Why `cooldown_days` is not enforced, stated as the engine's own answer rather
    /// than as a claim in a comment.
    #[test]
    fn asking_for_cooldown_on_an_abbreviated_record_fails_every_package() {
        let policy = policy("version: 1\ncooldown_days: 7\n");
        let today = jiff::civil::date(2026, 9, 13);

        let decision = decide(&policy, &Facts::from_record(&abbreviated()), today);
        let cooldown = decision
            .results
            .iter()
            .find(|r| r.check == Check::CooldownDays)
            .expect("cooldown is always asked");

        // lodash 4.17.21 was published in 2021 and is years past any cooldown. It fails
        // only because the document the proxy fetches does not say when.
        assert!(matches!(cooldown.outcome, Outcome::Failed(_)));
        assert_eq!(decision.action(), Action::Quarantine);

        // Read as the full document, the same version passes.
        let decision = decide(&policy, &Facts::from_record(&full()), today);
        assert_eq!(decision.action(), Action::Allow);
    }

    #[test]
    fn a_full_record_that_still_has_no_time_says_so_differently() {
        let mut r = full();
        r.published_at = None;

        assert_eq!(
            Facts::can_answer_cooldown(&r),
            Answerable::Missing("the registry published no time for this version")
        );
    }

    /// An absent intel answer is not a clean one, and nothing here can tell them apart.
    #[test]
    fn no_stream_means_no_advisories_rather_than_none_found() {
        let facts = Facts::from_record(&full());

        assert!(!facts.known_malware);
        assert!(facts.advisories.is_empty());
    }

    #[test]
    fn the_publish_date_is_read_in_utc_so_two_replicas_never_disagree() {
        let r = full();
        let at = r.published_at.expect("full carries a time");

        assert_eq!(
            Facts::from_record(&r).published,
            Some(at.to_zoned(TimeZone::UTC).date())
        );
    }
}
