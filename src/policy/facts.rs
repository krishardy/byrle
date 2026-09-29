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
//! [`Facts::can_answer_cooldown`].

use super::decide::{Advisory, Facts, Intel};
use crate::intel::store::PackageIntel;
use crate::record::{DocumentDetail, PackageRecord};
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
/// carries no `time` map. See [`crate::ecosystem::npm::parse_publish_times`].
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
            yanked: record.yanked.clone(),
            deprecated: record.deprecated.clone(),
            intel: Intel::NotConsulted,
            provenance: super::decide::Provenance::default(),
        }
    }

    /// The facts for `record`, which is `version` of `records`, with `intel` when the store
    /// knows the package.
    ///
    /// Provenance is what the document answers without verifying anything, as the proxy's
    /// resolution path decides it, over `policy`'s own window: dropped provenance, or nothing
    /// to verify.
    pub fn from_document(
        policy: &super::Policy,
        records: &[PackageRecord],
        record: &PackageRecord,
        version: &str,
        times: Option<&PublishTimes>,
        intel: Option<&PackageIntel>,
    ) -> Self {
        use crate::analysis::attestation;
        let provenance = attestation::from_metadata(
            record,
            &attestation::previous(records, version, times, policy.provenance_window()),
        );
        let facts = Self::from_record_and_times(record, times).with_provenance(provenance);
        match intel {
            Some(intel) => facts.with_intel(intel),
            None => facts,
        }
    }

    /// What the version's attestations say, once something has verified them.
    pub fn with_provenance(mut self, provenance: super::decide::Provenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Whether `cooldown_days` can be answered for this record.
    ///
    /// The abbreviated packument carries no `time` map, and that is the document both
    /// `npm install` and the proxy's own fetch ask for. Asking the engine anyway would
    /// fail every package on a fact the registry never sent.
    /// Add what the intel store knows about this version.
    ///
    /// Marks the facts consulted even when nothing is known against the version, because
    /// the store was asked. A malware record with no score is left out of `advisories`:
    /// `known_malware` refuses it, and `max_cvss` would refuse it a second time as unscored.
    /// Any other record with no score is kept, with `cvss` `None`, and `max_cvss` refuses it.
    pub fn with_intel(mut self, intel: &PackageIntel) -> Self {
        let records = intel.for_version(&self.ecosystem, &self.version);
        self.known_malware = records.iter().any(|r| r.malware);
        // One advisory per id, carrying every stream that reported it. `for_version` returns
        // a record per stream, and two streams holding one advisory is corroboration rather
        // than two vulnerabilities. Where they disagree the highest score stands, which is
        // the direction `max_cvss` already reads; making that configurable is its own item.
        let mut by_id: std::collections::BTreeMap<String, Advisory> =
            std::collections::BTreeMap::new();
        for record in &records {
            let score = record.score().map(|s| s.cvss());
            if record.malware && score.is_none() {
                continue;
            }
            let advisory = by_id
                .entry(record.advisory_id.clone())
                .or_insert_with(|| Advisory {
                    id: record.advisory_id.clone(),
                    aliases: Vec::new(),
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: Vec::new(),
                });
            for alias in &record.aliases {
                if !advisory.aliases.contains(alias) {
                    advisory.aliases.push(alias.clone());
                }
            }
            advisory.sources.push(record.source.clone());
            if score > advisory.cvss {
                advisory.cvss = score;
                advisory.band = record.band.clone();
            }
            advisory.kev |= record.exploited;
        }
        self.advisories = by_id
            .into_values()
            .map(|mut a| {
                a.aliases.sort();
                a.sources.sort();
                a.sources.dedup();
                a
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
            None => Answerable::Missing(match record.detail {
                DocumentDetail::Abbreviated => "the abbreviated packument carries no publish times",
                DocumentDetail::Full => "the registry published no time for this version",
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
    use crate::ecosystem::npm::normalize_packument;
    use crate::policy::decide::{Check, Outcome, decide};
    use crate::policy::{Action, Policy};

    fn fixture(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/npm/");
        std::fs::read(format!("{path}{name}")).expect("fixture is missing")
    }

    fn record(name: &str, detail: DocumentDetail, version: &str) -> PackageRecord {
        normalize_packument(&fixture(name), detail)
            .expect("fixture should normalise")
            .version(version)
            .expect("version is in the fixture")
            .clone()
    }

    fn abbreviated() -> PackageRecord {
        record(
            "lodash-4.17.21.abbrev.json",
            DocumentDetail::Abbreviated,
            "4.17.21",
        )
    }

    fn full() -> PackageRecord {
        record("lodash-4.17.21.full.json", DocumentDetail::Full, "4.17.21")
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

    /// OSV and GitHub both publish `GHSA-` ids, so one advisory arrives from two streams.
    /// That is corroboration, not two vulnerabilities: `decide` gives each check one result.
    #[test]
    fn two_streams_reporting_one_advisory_are_one_advisory_naming_both() {
        let from = |source: &str, cvss: Option<f64>, exploited: bool| {
            let (version, mut record) = stored(None, "GHSA-1", false, cvss);
            record.source = source.to_owned();
            record.exploited = exploited;
            (version, record)
        };
        let facts = Facts::from_record(&full()).with_intel(&intel(vec![
            from("osv", Some(5.0), false),
            from("github", Some(8.8), true),
        ]));
        assert_eq!(facts.advisories.len(), 1, "one advisory, not two");
        let advisory = &facts.advisories[0];
        assert_eq!(advisory.sources, ["github", "osv"], "sorted, once each");
        // The streams disagree on the score and the higher stands, the direction
        // `max_cvss` reads. Exploitation from either stream marks the advisory.
        assert_eq!(advisory.cvss, Some(8.8));
        assert!(advisory.kev);
        assert_eq!(
            advisory.aliases,
            ["CVE-of-GHSA-1"],
            "the alias is not repeated"
        );
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
    fn advisories_for_this_version_become_advisories_except_unscored_malware() {
        let facts = Facts::from_record(&full()).with_intel(&intel(vec![
            stored(Some("4.17.20"), "GHSA-other", false, Some(9.8)),
            stored(Some("4.17.21"), "GHSA-this", false, Some(5.0)),
            stored(Some("4.17.21"), "GHSA-unscored", false, None),
            stored(Some("4.17.20"), "MAL-other", true, None),
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
            // Sorted by id: the advisories are grouped through a `BTreeMap`, so the order
            // is the ids' and not the order the records came back in.
            vec![
                Advisory {
                    id: "GHSA-banded".to_owned(),
                    aliases: vec!["CVE-of-GHSA-banded".to_owned()],
                    cvss: Some(8.9),
                    band: Some("HIGH".to_owned()),
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-this".to_owned(),
                    aliases: vec!["CVE-of-GHSA-this".to_owned()],
                    cvss: Some(5.0),
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-unscored".to_owned(),
                    aliases: vec!["CVE-of-GHSA-unscored".to_owned()],
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
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
            DocumentDetail::Abbreviated,
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

        let consistent = |record: &crate::record::PackageRecord| {
            Facts::from_record(record).with_provenance(super::super::decide::Provenance::Consistent)
        };
        let decision = decide(&policy, &consistent(&abbreviated()), today);
        let cooldown = decision
            .results
            .iter()
            .find(|r| r.check == Check::CooldownDays)
            .expect("cooldown is always asked");

        // lodash 4.17.21 was published in 2021 and is years past any cooldown. It fails
        // only because the document the proxy fetches does not say when.
        assert_eq!(cooldown.outcome, Outcome::Failed(Action::Quarantine));
        assert_eq!(decision.action(), Action::Quarantine);

        // Read as the full document, the same version passes.
        let decision = decide(&policy, &consistent(&full()), today);
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
