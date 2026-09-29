//! Records from metadata documents the proxy has seen, for the artifact request that follows.
//! One store for every ecosystem, bounded by record count, and never used to answer a
//! metadata request: see docs/engineering_decisions/no-metadata-cache.md.

use crate::analysis::attestation::{Previous, previous};
use crate::heuristics::{Signal, signals};
use crate::identity::PackageKey;
use crate::policy::facts::PublishTimes;
use crate::record::{PackageMetadata, PackageRecord};
use std::collections::HashMap;

struct Entry {
    metadata: PackageMetadata,
    last_used: u64,
}

/// Packument records, keyed by package, bounded by total record count.
pub struct RecordStore {
    entries: HashMap<PackageKey, Entry>,
    records: usize,
    max_records: usize,
    clock: u64,
}

/// What a tarball request found when it asked for its own record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The document was seen and names this version.
    Found(Box<PackageRecord>),
    /// The document was seen and names neither this version nor this file.
    NoSuchVersion,
    /// No document for this package has gone past, as after a 304 to a warm client.
    Unknown,
}

impl RecordStore {
    pub fn new(max_records: usize) -> Self {
        Self {
            entries: HashMap::new(),
            records: 0,
            max_records,
            clock: 0,
        }
    }

    /// Packages held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records held across all packages. This is what the budget counts.
    pub fn records(&self) -> usize {
        self.records
    }

    /// Store a document's records, replacing any earlier copy of the same package.
    pub fn insert(&mut self, metadata: PackageMetadata) {
        self.clock += 1;
        let added = metadata.records.len();
        let key = metadata.key.clone();

        if let Some(previous) = self.entries.insert(
            key,
            Entry {
                metadata,
                last_used: self.clock,
            },
        ) {
            self.records -= previous.metadata.records.len();
        }
        self.records += added;
        self.evict_to_budget();
    }

    /// Every package held, in no order. Does not count as a use of any of them.
    pub fn packages(&self) -> Vec<PackageKey> {
        self.entries.keys().cloned().collect()
    }

    /// Replace the document held for a package with a newer copy, keeping when the package
    /// was last used, so the watcher's reads never keep a package held. `metadata` for a
    /// package not held is dropped. Returns the versions the new copy lists and the held
    /// one did not.
    pub fn refresh(&mut self, metadata: PackageMetadata) -> Vec<PackageRecord> {
        let Some(entry) = self.entries.get_mut(&metadata.key) else {
            return Vec::new();
        };
        let new: Vec<PackageRecord> = metadata
            .records
            .iter()
            .filter(|record| entry.metadata.version(record.package.version()).is_none())
            .cloned()
            .collect();
        self.records = self.records - entry.metadata.records.len() + metadata.records.len();
        entry.metadata = metadata;
        self.evict_to_budget();
        new
    }

    /// Whether any record is held for this package.
    ///
    /// Does not count as a use: this answers "is there anything to read", and a package
    /// that is only ever asked about should not outlive one that is installed.
    pub fn holds(&self, key: &PackageKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Find the record for one version, marking its package as recently used.
    ///
    /// A version the document does not list is found by `filename` instead, when a record
    /// names that file: 38 of 24,852 npm tarball URLs spell the version differently from
    /// the packument, `express-3.0.0rc1.tgz` for `3.0.0-rc1`.
    pub fn lookup(&mut self, key: &PackageKey, version: &str, filename: &str) -> Lookup {
        self.clock += 1;
        let clock = self.clock;
        let Some(entry) = self.entries.get_mut(key) else {
            return Lookup::Unknown;
        };
        entry.last_used = clock;
        let records = &entry.metadata.records;
        match entry.metadata.version(version).or_else(|| {
            records
                .iter()
                .find(|r| r.artifact_named(filename).is_some())
        }) {
            Some(record) => Lookup::Found(Box::new(record.clone())),
            None => Lookup::NoSuchVersion,
        }
    }

    /// The version of this package published before `version`, from the document held for
    /// it. [`Previous::Unknown`] when no document is held. Does not count as a use: the
    /// lookup for `version` just did.
    pub fn previous(
        &self,
        key: &PackageKey,
        version: &str,
        times: Option<&PublishTimes>,
        window: jiff::SignedDuration,
    ) -> Previous {
        self.entries.get(key).map_or(Previous::Unknown, |entry| {
            previous(&entry.metadata.records, version, times, window)
        })
    }

    /// What the metadata heuristics report for `record`, against the document held for its
    /// package and the names of the other packages held in its ecosystem.
    /// `now` is when they are asked for. Does not count as a use.
    pub fn signals(&self, record: &PackageRecord, now: jiff::Timestamp) -> Vec<Signal> {
        let key = record.package.key();
        let records = self
            .entries
            .get(key)
            .map_or(std::slice::from_ref(record), |entry| {
                &entry.metadata.records
            });
        let served: Vec<String> = self
            .entries
            .keys()
            .filter(|held| held.ecosystem() == key.ecosystem())
            .map(PackageKey::registry_name)
            .collect();
        signals(records, record, served.iter().map(String::as_str), now)
    }

    /// Drop least recently used packages until the budget is met, keeping the most recent,
    /// which the artifact request that follows needs even when it alone is over the budget.
    fn evict_to_budget(&mut self) {
        if self.records <= self.max_records {
            return;
        }
        let mut order: Vec<(u64, PackageKey)> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_used, key.clone()))
            .collect();
        order.sort_unstable_by_key(|(last_used, _)| *last_used);

        for (_, key) in order {
            if self.records <= self.max_records || self.entries.len() <= 1 {
                break;
            }
            let entry = self
                .entries
                .remove(&key)
                .expect("each key was read from the entries");
            self.records -= entry.metadata.records.len();
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ecosystem::npm::normalize_packument;
    use crate::record::DocumentDetail;

    fn packument(name: &str, versions: &[&str]) -> PackageMetadata {
        let entries: Vec<String> = versions
            .iter()
            .map(|v| {
                format!(
                    r#""{v}":{{"version":"{v}","dist":{{"tarball":"https://r/{name}/-/{name}-{v}.tgz","integrity":"sha512-{v}"}}}}"#
                )
            })
            .collect();
        let body = format!(
            r#"{{"name":"{name}","versions":{{{}}}}}"#,
            entries.join(",")
        );
        normalize_packument(body.as_bytes(), DocumentDetail::Abbreviated).expect("valid fixture")
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(crate::identity::Ecosystem::Npm, name).unwrap()
    }

    /// A refresh finds the versions the held copy lacked, keeps the package's place in the
    /// eviction order, and ignores a package not held.
    #[test]
    fn a_refresh_returns_new_versions_without_counting_as_a_use() {
        let mut store = RecordStore::new(5);
        store.insert(packument("old", &["1.0.0"]));
        store.insert(packument("recent", &["1.0.0"]));
        assert_eq!(store.packages().len(), 2);

        let new = store.refresh(packument("old", &["1.0.0", "1.1.0", "2.0.0"]));
        assert_eq!(
            new.iter().map(|r| r.package.version()).collect::<Vec<_>>(),
            ["1.1.0", "2.0.0"]
        );
        assert_eq!(store.records(), 4);
        assert!(
            store
                .refresh(packument("old", &["1.0.0", "1.1.0", "2.0.0"]))
                .is_empty(),
            "nothing new the second time"
        );

        store.insert(packument("third", &["1.0.0", "2.0.0"]));
        assert!(
            !store.holds(&key("old")),
            "refreshed, and still the least recently used"
        );
        assert!(store.holds(&key("recent")));
        assert!(
            store.refresh(packument("unheld", &["1.0.0"])).is_empty(),
            "a package not held is not added"
        );
        assert!(!store.holds(&key("unheld")));
    }

    #[test]
    fn a_stored_packument_answers_for_its_versions() {
        let mut store = RecordStore::new(100);
        assert!(store.is_empty());
        store.insert(packument("lodash", &["4.17.20", "4.17.21"]));

        assert_eq!(store.len(), 1);
        assert_eq!(store.records(), 2);
        let Lookup::Found(record) = store.lookup(&key("lodash"), "4.17.21", "lodash-4.17.21.tgz")
        else {
            panic!("the packument names this version");
        };
        assert_eq!(
            record.artifact().expect("one file").integrity.as_deref(),
            Some("sha512-4.17.21")
        );
    }

    /// `express-3.0.0rc1.tgz` is `3.0.0-rc1`'s tarball. The path's spelling is not in the
    /// packument, and the file is.
    #[test]
    fn a_version_spelled_differently_by_its_filename_is_found_by_the_file() {
        let mut store = RecordStore::new(100);
        let body = r#"{"name":"express","versions":{"3.0.0-rc1":{"version":"3.0.0-rc1",
            "dist":{"tarball":"https://r/express/-/express-3.0.0rc1.tgz","integrity":"sha512-x"}}}}"#;
        store.insert(normalize_packument(body.as_bytes(), DocumentDetail::Abbreviated).unwrap());

        let Lookup::Found(record) =
            store.lookup(&key("express"), "3.0.0rc1", "express-3.0.0rc1.tgz")
        else {
            panic!("found by its file");
        };
        assert_eq!(record.package.version(), "3.0.0-rc1");
    }

    /// A version the document does not name and a package never seen are different
    /// answers.
    #[test]
    fn a_missing_version_and_a_missing_package_are_different_answers() {
        let mut store = RecordStore::new(100);
        store.insert(packument("express", &["3.0.0-rc1"]));

        assert_eq!(
            store.lookup(&key("express"), "3.0.0rc2", "express-3.0.0rc2.tgz"),
            Lookup::NoSuchVersion,
            "neither the version nor the file is in the document"
        );
        assert_eq!(
            store.lookup(&key("lodash"), "4.17.21", "lodash-4.17.21.tgz"),
            Lookup::Unknown
        );
    }

    #[test]
    fn re_inserting_a_package_replaces_it_rather_than_accumulating() {
        let mut store = RecordStore::new(100);
        store.insert(packument("lodash", &["1.0.0"]));
        store.insert(packument("lodash", &["1.0.0", "1.0.1", "1.0.2"]));

        assert_eq!(store.len(), 1);
        assert_eq!(
            store.records(),
            3,
            "the old copy's records were not released"
        );
    }

    #[test]
    fn the_budget_evicts_least_recently_used_packages() {
        let mut store = RecordStore::new(5);
        store.insert(packument("a", &["1.0.0", "1.0.1"]));
        store.insert(packument("b", &["1.0.0", "1.0.1"]));
        store.insert(packument("c", &["1.0.0", "1.0.1"]));

        assert!(store.records() <= 5, "budget exceeded: {}", store.records());
        assert_eq!(
            store.lookup(&key("a"), "1.0.0", "a-1.0.0.tgz"),
            Lookup::Unknown,
            "`a` was least recently used"
        );
        assert!(matches!(
            store.lookup(&key("c"), "1.0.0", "c-1.0.0.tgz"),
            Lookup::Found(_)
        ));
    }

    /// A lookup is a use and asking whether anything is held is not, so a package only
    /// asked about does not outlive one that is installed.
    #[test]
    fn holds_reports_presence_without_counting_as_use() {
        let mut store = RecordStore::new(4);
        store.insert(packument("a", &["1.0.0", "1.0.1"]));
        store.insert(packument("b", &["1.0.0", "1.0.1"]));

        assert!(store.holds(&key("a")));
        assert!(!store.holds(&key("c")));

        store.insert(packument("c", &["1.0.0", "1.0.1"]));
        assert!(!store.holds(&key("a")), "asking about `a` did not keep it");
    }

    #[test]
    fn a_lookup_counts_as_use() {
        let mut store = RecordStore::new(4);
        store.insert(packument("a", &["1.0.0", "1.0.1"]));
        store.insert(packument("b", &["1.0.0", "1.0.1"]));
        assert!(matches!(
            store.lookup(&key("a"), "1.0.0", "a-1.0.0.tgz"),
            Lookup::Found(_)
        ));

        store.insert(packument("c", &["1.0.0", "1.0.1"]));
        assert!(
            matches!(
                store.lookup(&key("a"), "1.0.0", "a-1.0.0.tgz"),
                Lookup::Found(_)
            ),
            "`a` was used more recently than `b`"
        );
        assert_eq!(
            store.lookup(&key("b"), "1.0.0", "b-1.0.0.tgz"),
            Lookup::Unknown
        );
    }

    /// typescript is 3,822 versions. A packument over the whole budget is still kept,
    /// because the tarball request that follows it is the reason to store anything.
    #[test]
    fn a_packument_larger_than_the_budget_is_still_available() {
        let mut store = RecordStore::new(2);
        store.insert(packument("big", &["1.0.0", "1.0.1", "1.0.2", "1.0.3"]));

        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.lookup(&key("big"), "1.0.3", "big-1.0.3.tgz"),
            Lookup::Found(_)
        ));
        assert!(
            store.records() > store.max_records,
            "the budget is a target, and this case is why"
        );
    }

    /// Near names come from the other packages held in the same ecosystem. A record whose
    /// package is not held is judged on itself.
    #[test]
    fn signals_compare_names_held_in_the_same_ecosystem() {
        use crate::heuristics::Signal;
        let mut store = RecordStore::new(100);
        store.insert(packument("express", &["1.0.0"]));
        store.insert(packument("expres", &["1.0.0"]));
        store.insert(PackageMetadata {
            key: PackageKey::from_registry_name(crate::identity::Ecosystem::PyPI, "expresz")
                .unwrap(),
            latest: None,
            records: Vec::new(),
            skipped: Vec::new(),
        });
        let now = jiff::Timestamp::now();
        let expres = packument("expres", &["1.0.0"]).records.remove(0);
        assert_eq!(
            store.signals(&expres, now),
            [Signal::NearName {
                served: "express".to_owned()
            }]
        );
        let unheld = packument("lodash", &["1.0.0"]).records.remove(0);
        assert_eq!(store.signals(&unheld, now), []);

        let mut taken = packument("taken", &["1.0.0", "1.0.1"]);
        for (record, (days, publisher)) in taken.records.iter_mut().zip([(400, "ana"), (1, "eve")])
        {
            record.published_at = Some(now - jiff::SignedDuration::from_hours(24 * days));
            record.provenance.publisher = Some(publisher.to_owned());
        }
        let latest = taken.records[1].clone();
        store.insert(taken);
        assert_eq!(
            store.signals(&latest, now),
            [Signal::NewPublisher {
                publisher: "eve".to_owned()
            }],
            "the held document names the earlier publisher"
        );
    }
}
