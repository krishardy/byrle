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

use super::decide::{Advisory, Facts, Intel};
use crate::intel::store::PackageIntel;
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

/// When each version of a package was published, read from the full packument.
///
/// Separate from the record because the record comes from the abbreviated document, which
/// carries no `time` map. See [`crate::npm::parse_publish_times`].
pub type PublishTimes = std::collections::BTreeMap<String, jiff::Timestamp>;

impl Facts {
    /// Build the facts from a record, with no intel.
    pub fn from_record(record: &PackageRecord) -> Self {
        Self::from_record_and_times(record, None)
    }

    /// The same, with publish times fetched separately.
    pub fn from_record_and_times(record: &PackageRecord, times: Option<&PublishTimes>) -> Self {
        let key = record.package.key();
        Self {
            ecosystem: key.ecosystem().as_str().to_owned(),
            name: key.registry_name(),
            version: record.package.version().to_owned(),
            published: published_date(record, times),
            // Absent, not clean. Nothing can originate a finding in this build.
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: record.has_install_scripts,
            intel: Intel::NotConsulted,
        }
    }

    /// Whether `cooldown_days` can be answered for this record.
    ///
    /// The abbreviated packument carries no `time` map, and that is the document both
    /// `npm install` and the proxy's own fetch ask for. Asking the engine anyway would
    /// fail every package on a fact the registry never sent.
    /// Add what the intel store knows about this version.
    ///
    /// Marks the facts consulted even when nothing is known against the version, because
    /// the store was asked. An advisory with no score is left out of `advisories`, since
    /// `Advisory::cvss` is a number and zero would be a score nobody gave. It still counts
    /// toward `known_malware`.
    pub fn with_intel(mut self, intel: &PackageIntel) -> Self {
        let records = intel.for_version(&self.version);
        self.known_malware = records.iter().any(|r| r.malware);
        self.advisories = records
            .iter()
            .filter_map(|r| {
                r.score().map(|score| Advisory {
                    id: r.advisory_id.clone(),
                    aliases: r.aliases.clone(),
                    cvss: score.cvss(),
                    band: r.band.clone(),
                    kev: r.exploited,
                })
            })
            .collect();
        self.intel = Intel::of(Some(intel));
        self
    }

    pub fn can_answer_cooldown(record: &PackageRecord, times: Option<&PublishTimes>) -> Answerable {
        match published_date(record, times) {
            Some(_) => Answerable::Yes,
            None if times.is_some() => {
                Answerable::Missing("the registry published no time for this version")
            }
            None => Answerable::Missing(match record.source {
                PackumentDetail::Abbreviated => {
                    "the abbreviated packument carries no publish times"
                }
                PackumentDetail::Full => "the registry published no time for this version",
            }),
        }
    }
}

impl Intel {
    /// What a store's answer for a package lets the checks read. `None` is no store.
    pub fn of(intel: Option<&PackageIntel>) -> Self {
        match intel {
            Some(intel) => Self::Consulted {
                exploitation_loaded: intel.exploitation_loaded,
            },
            None => Self::NotConsulted,
        }
    }
}

/// The publish date in UTC.
///
/// The policy is written in civil dates and the registry publishes an instant, so a
/// timezone has to be chosen. UTC, so the same package gets the same answer on every
/// proxy: a local zone would put two replicas a day apart across midnight.
fn published_date(record: &PackageRecord, times: Option<&PublishTimes>) -> Option<Date> {
    record
        .published_at
        // The full document is the only source of a `time` map, so a record built from
        // the abbreviated one has nothing here and the separately fetched times are what
        // answer.
        .or_else(|| times?.get(record.package.version()).copied())
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
        record("lodash-4.17.21.full.json", PackumentDetail::Full, "4.17.21")
    }

    fn policy(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    fn stored(
        version: Option<&str>,
        id: &str,
        malware: bool,
        cvss: Option<f64>,
    ) -> (Option<String>, crate::intel::store::Record) {
        (
            version.map(str::to_owned),
            crate::intel::store::Record {
                advisory_id: id.to_owned(),
                aliases: vec![format!("CVE-of-{id}")],
                source: "osv".to_owned(),
                cvss,
                band: None,
                cvss_source: None,
                exploited: false,
                malware,
            },
        )
    }

    fn intel(records: Vec<(Option<String>, crate::intel::store::Record)>) -> PackageIntel {
        PackageIntel {
            snapshot: "s1".to_owned(),
            records,
            ranges: Vec::new(),
            exploitation_loaded: false,
        }
    }

    #[test]
    fn an_exploited_record_is_a_kev_advisory_and_the_facts_say_the_catalogue_was_asked() {
        let exploited = |version| {
            let (version, record) = stored(version, "GHSA-1", false, Some(5.0));
            (
                version,
                crate::intel::store::Record {
                    exploited: true,
                    ..record
                },
            )
        };
        let facts = Facts::from_record(&full()).with_intel(&PackageIntel {
            exploitation_loaded: true,
            ..intel(vec![exploited(None)])
        });
        assert_eq!(
            facts.intel,
            Intel::Consulted {
                exploitation_loaded: true
            }
        );
        assert_eq!(
            facts
                .advisories
                .iter()
                .map(|a| (a.id.as_str(), a.kev))
                .collect::<Vec<_>>(),
            [("GHSA-1", true)]
        );
        assert_eq!(Intel::of(None), Intel::NotConsulted);
    }

    #[test]
    fn malware_against_every_version_blocks_through_the_facts() {
        let facts =
            Facts::from_record(&full()).with_intel(&intel(vec![stored(None, "MAL-1", true, None)]));
        assert!(facts.known_malware);
        assert!(
            facts.advisories.is_empty(),
            "an unscored record is not an advisory"
        );
        assert_eq!(
            facts.intel,
            Intel::Consulted {
                exploitation_loaded: false
            }
        );

        let decision = decide(
            &policy(
                "version: 1
cooldown_days: 0
",
            ),
            &facts,
            jiff::civil::date(2026, 9, 13),
        );
        assert_eq!(decision.action(), Action::Block);
    }

    #[test]
    fn a_store_that_knows_nothing_was_still_consulted() {
        let facts = Facts::from_record(&full()).with_intel(&intel(Vec::new()));
        assert!(!facts.known_malware);
        assert_eq!(
            facts.intel,
            Intel::Consulted {
                exploitation_loaded: false
            }
        );
    }

    #[test]
    fn only_scored_advisories_for_this_version_become_advisories() {
        let facts = Facts::from_record(&full()).with_intel(&intel(vec![
            stored(Some("4.17.20"), "GHSA-other", false, Some(9.8)),
            stored(Some("4.17.21"), "GHSA-this", false, Some(5.0)),
            stored(Some("4.17.21"), "GHSA-unscored", false, None),
            {
                let (version, record) = stored(Some("4.17.21"), "GHSA-banded", false, Some(8.9));
                (
                    version,
                    crate::intel::store::Record {
                        band: Some("HIGH".to_owned()),
                        ..record
                    },
                )
            },
        ]));
        assert_eq!(
            facts.advisories,
            vec![
                Advisory {
                    id: "GHSA-this".to_owned(),
                    aliases: vec!["CVE-of-GHSA-this".to_owned()],
                    cvss: 5.0,
                    band: None,
                    kev: false,
                },
                Advisory {
                    id: "GHSA-banded".to_owned(),
                    aliases: vec!["CVE-of-GHSA-banded".to_owned()],
                    cvss: 8.9,
                    band: Some("HIGH".to_owned()),
                    kev: false,
                }
            ]
        );
        assert!(!facts.known_malware);
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
            Facts::can_answer_cooldown(&abbreviated(), None),
            Answerable::Missing("the abbreviated packument carries no publish times")
        );

        // The same version read the other way does carry one.
        assert!(Facts::from_record(&full()).published.is_some());
        assert_eq!(Facts::can_answer_cooldown(&full(), None), Answerable::Yes);
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

    /// Separately fetched times answer for a record that has none, which is what makes
    /// `cooldown_days` enforceable against the abbreviated document.
    #[test]
    fn fetched_times_answer_where_the_record_cannot() {
        let times: PublishTimes = [(
            "4.17.21".to_owned(),
            "2021-02-20T15:42:16.891Z".parse().unwrap(),
        )]
        .into_iter()
        .collect();

        assert_eq!(Facts::from_record(&abbreviated()).published, None);
        assert_eq!(
            Facts::from_record_and_times(&abbreviated(), Some(&times)).published,
            Some(jiff::civil::date(2021, 2, 20))
        );
        assert_eq!(
            Facts::can_answer_cooldown(&abbreviated(), Some(&times)),
            Answerable::Yes
        );
    }

    /// Times that do not name this version leave it unanswerable, and the reason is the
    /// registry's silence rather than the document shape.
    #[test]
    fn fetched_times_that_omit_this_version_say_the_registry_published_none() {
        let times: PublishTimes = [(
            "4.17.20".to_owned(),
            "2020-04-27T00:00:00Z".parse().unwrap(),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            Facts::can_answer_cooldown(&abbreviated(), Some(&times)),
            Answerable::Missing("the registry published no time for this version")
        );
    }

    /// The record wins where it has one, so a full document needs no second fetch.
    #[test]
    fn a_record_that_carries_its_own_time_ignores_the_fetched_map() {
        let times: PublishTimes = [(
            "4.17.21".to_owned(),
            "1999-01-01T00:00:00Z".parse().unwrap(),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            Facts::from_record_and_times(&full(), Some(&times)).published,
            Facts::from_record(&full()).published
        );
    }

    #[test]
    fn a_full_record_that_still_has_no_time_says_so_differently() {
        let mut r = full();
        r.published_at = None;

        assert_eq!(
            Facts::can_answer_cooldown(&r, None),
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
