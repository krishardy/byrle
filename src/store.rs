//! Records from metadata documents the proxy has seen, for the artifact request that follows.
//! One store for every ecosystem, bounded by record count, and never used to answer a
//! metadata request: see docs/engineering_decisions/0056-no-metadata-cache.md.

use crate::analysis::attestation::{Previous, previous};
use crate::analysis::detector::metadata::{Listing, Metadata};
use crate::analysis::detector::{Detection, built_in};
use crate::ecosystem::Repository;
use crate::identity::PackageKey;
use crate::policy::facts::PublishTimes;
use crate::record::{PackageMetadata, PackageRecord};
use std::collections::HashMap;

struct Entry {
    metadata: PackageMetadata,
    last_used: u64,
}

/// Packument records, keyed by repository and package, bounded by total record count.
pub struct RecordStore {
    entries: HashMap<(Repository, PackageKey), Entry>,
    records: usize,
    max_records: usize,
    clock: u64,
}

/// The store, and the repository the document being read came from.
#[derive(Clone, Copy)]
pub struct Keeping<'a> {
    pub store: &'a std::sync::Mutex<RecordStore>,
    pub at: Repository,
}

impl Keeping<'_> {
    /// Store a document's records as [`RecordStore::insert`] does. Returns the packages
    /// and records then held.
    pub fn keep(self, metadata: PackageMetadata) -> (usize, usize) {
        let mut store = self.store.lock().expect("record store lock");
        store.insert(self.at, metadata);
        (store.len(), store.records())
    }
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

    /// Store a document's records read from `at`, replacing any earlier copy of the same
    /// package from it.
    pub fn insert(&mut self, at: Repository, metadata: PackageMetadata) {
        self.clock += 1;
        let added = metadata.records.len();
        let key = (at, metadata.key.clone());

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

    /// Every package held, and the repository it was read from, in no order. Does not count
    /// as a use of any of them.
    pub fn packages(&self) -> Vec<(Repository, PackageKey)> {
        self.entries.keys().cloned().collect()
    }

    /// Replace the document held for a package with a newer copy, keeping when the package
    /// was last used, so the watcher's reads never keep a package held. `metadata` for a
    /// package not held is dropped. Returns the versions the new copy lists and the held
    /// one did not.
    pub fn refresh(&mut self, at: Repository, metadata: PackageMetadata) -> Vec<PackageRecord> {
        let Some(entry) = self.entries.get_mut(&(at, metadata.key.clone())) else {
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
    pub fn holds(&self, at: Repository, key: &PackageKey) -> bool {
        self.entries.contains_key(&(at, key.clone()))
    }

    /// Find the record for one version, marking its package as recently used.
    ///
    /// A version the document does not list is found by `filename` instead, when a record
    /// names that file: 38 of 24,852 npm tarball URLs spell the version differently from
    /// the packument, `express-3.0.0rc1.tgz` for `3.0.0-rc1`.
    pub fn lookup(
        &mut self,
        at: Repository,
        key: &PackageKey,
        version: &str,
        filename: &str,
    ) -> Lookup {
        self.clock += 1;
        let clock = self.clock;
        let Some(entry) = self.entries.get_mut(&(at, key.clone())) else {
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

    /// Whether the document held for `key` lists `filename`. Does not count as a use: the
    /// lookup that follows does.
    pub fn lists(&self, at: Repository, key: &PackageKey, filename: &str) -> bool {
        self.entries.get(&(at, key.clone())).is_some_and(|entry| {
            entry
                .metadata
                .records
                .iter()
                .any(|r| r.artifact_named(filename).is_some())
        })
    }

    /// The version of this package published before `version`, from the document held for
    /// it. [`Previous::Unknown`] when no document is held. Does not count as a use: the
    /// lookup for `version` just did.
    pub fn previous(
        &self,
        at: Repository,
        key: &PackageKey,
        version: &str,
        times: Option<&PublishTimes>,
        compared: (jiff::SignedDuration, usize),
    ) -> Previous {
        self.entries
            .get(&(at, key.clone()))
            .map_or(Previous::Unknown, |entry| {
                previous(&entry.metadata.records, version, times, compared)
            })
    }

    /// What the metadata heuristics find about `record`, against `full`, the full document,
    /// when it lists the version, else the document held, and the names of the other
    /// packages held from `at`. `now` is when they are asked for.
    /// Does not count as a use.
    pub fn metadata(
        &self,
        at: Repository,
        record: &PackageRecord,
        full: Option<&PackageMetadata>,
        now: jiff::Timestamp,
    ) -> (String, Detection) {
        let key = record.package.key();
        let records = self
            .entries
            .get(&(at, key.clone()))
            .map_or(std::slice::from_ref(record), |entry| {
                &entry.metadata.records
            });
        let served: Vec<String> = self
            .entries
            .keys()
            .filter(|(from, _)| *from == at)
            .map(|(_, held)| held.registry_name())
            .collect();
        let listing = Listing {
            records,
            record,
            full,
            served: served.iter().map(String::as_str).collect(),
            now,
        };
        built_in(&Metadata, &listing)
    }

    /// Drop least recently used packages until the budget is met, keeping the most recent,
    /// which the artifact request that follows needs even when it alone is over the budget.
    fn evict_to_budget(&mut self) {
        if self.records <= self.max_records {
            return;
        }
        let mut order: Vec<(u64, (Repository, PackageKey))> = self
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

    const NPM: Repository = Repository::of(crate::identity::Ecosystem::Npm);

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
        store.insert(NPM, packument("old", &["1.0.0"]));
        store.insert(NPM, packument("recent", &["1.0.0"]));
        assert_eq!(store.packages().len(), 2);

        let new = store.refresh(NPM, packument("old", &["1.0.0", "1.1.0", "2.0.0"]));
        assert_eq!(
            new.iter().map(|r| r.package.version()).collect::<Vec<_>>(),
            ["1.1.0", "2.0.0"]
        );
        assert_eq!(store.records(), 4);
        assert!(
            store
                .refresh(NPM, packument("old", &["1.0.0", "1.1.0", "2.0.0"]))
                .is_empty(),
            "nothing new the second time"
        );

        store.insert(NPM, packument("third", &["1.0.0", "2.0.0"]));
        assert!(
            !store.holds(NPM, &key("old")),
            "refreshed, and still the least recently used"
        );
        assert!(store.holds(NPM, &key("recent")));
        assert!(
            store
                .refresh(NPM, packument("unheld", &["1.0.0"]))
                .is_empty(),
            "a package not held is not added"
        );
        assert!(!store.holds(NPM, &key("unheld")));
    }

    #[test]
    fn a_stored_packument_answers_for_its_versions() {
        let mut store = RecordStore::new(100);
        assert!(store.is_empty());
        store.insert(NPM, packument("lodash", &["4.17.20", "4.17.21"]));

        assert_eq!(store.len(), 1);
        assert_eq!(store.records(), 2);
        let Lookup::Found(record) =
            store.lookup(NPM, &key("lodash"), "4.17.21", "lodash-4.17.21.tgz")
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
        store.insert(
            NPM,
            normalize_packument(body.as_bytes(), DocumentDetail::Abbreviated).unwrap(),
        );

        let Lookup::Found(record) =
            store.lookup(NPM, &key("express"), "3.0.0rc1", "express-3.0.0rc1.tgz")
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
        store.insert(NPM, packument("express", &["3.0.0-rc1"]));

        assert_eq!(
            store.lookup(NPM, &key("express"), "3.0.0rc2", "express-3.0.0rc2.tgz"),
            Lookup::NoSuchVersion,
            "neither the version nor the file is in the document"
        );
        assert_eq!(
            store.lookup(NPM, &key("lodash"), "4.17.21", "lodash-4.17.21.tgz"),
            Lookup::Unknown
        );
    }

    #[test]
    fn re_inserting_a_package_replaces_it_rather_than_accumulating() {
        let mut store = RecordStore::new(100);
        store.insert(NPM, packument("lodash", &["1.0.0"]));
        store.insert(NPM, packument("lodash", &["1.0.0", "1.0.1", "1.0.2"]));

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
        store.insert(NPM, packument("a", &["1.0.0", "1.0.1"]));
        store.insert(NPM, packument("b", &["1.0.0", "1.0.1"]));
        store.insert(NPM, packument("c", &["1.0.0", "1.0.1"]));

        assert!(store.records() <= 5, "budget exceeded: {}", store.records());
        assert_eq!(
            store.lookup(NPM, &key("a"), "1.0.0", "a-1.0.0.tgz"),
            Lookup::Unknown,
            "`a` was least recently used"
        );
        assert!(matches!(
            store.lookup(NPM, &key("c"), "1.0.0", "c-1.0.0.tgz"),
            Lookup::Found(_)
        ));
    }

    /// A lookup is a use and asking whether anything is held is not, so a package only
    /// asked about does not outlive one that is installed.
    #[test]
    fn holds_reports_presence_without_counting_as_use() {
        let mut store = RecordStore::new(4);
        store.insert(NPM, packument("a", &["1.0.0", "1.0.1"]));
        store.insert(NPM, packument("b", &["1.0.0", "1.0.1"]));

        assert!(store.holds(NPM, &key("a")));
        assert!(!store.holds(NPM, &key("c")));

        store.insert(NPM, packument("c", &["1.0.0", "1.0.1"]));
        assert!(
            !store.holds(NPM, &key("a")),
            "asking about `a` did not keep it"
        );
    }

    #[test]
    fn a_lookup_counts_as_use() {
        let mut store = RecordStore::new(4);
        store.insert(NPM, packument("a", &["1.0.0", "1.0.1"]));
        store.insert(NPM, packument("b", &["1.0.0", "1.0.1"]));
        assert!(matches!(
            store.lookup(NPM, &key("a"), "1.0.0", "a-1.0.0.tgz"),
            Lookup::Found(_)
        ));

        store.insert(NPM, packument("c", &["1.0.0", "1.0.1"]));
        assert!(
            matches!(
                store.lookup(NPM, &key("a"), "1.0.0", "a-1.0.0.tgz"),
                Lookup::Found(_)
            ),
            "`a` was used more recently than `b`"
        );
        assert_eq!(
            store.lookup(NPM, &key("b"), "1.0.0", "b-1.0.0.tgz"),
            Lookup::Unknown
        );
    }

    /// typescript is 3,822 versions. A packument over the whole budget is still kept,
    /// because the tarball request that follows it is the reason to store anything.
    #[test]
    fn a_packument_larger_than_the_budget_is_still_available() {
        let mut store = RecordStore::new(2);
        store.insert(NPM, packument("big", &["1.0.0", "1.0.1", "1.0.2", "1.0.3"]));

        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.lookup(NPM, &key("big"), "1.0.3", "big-1.0.3.tgz"),
            Lookup::Found(_)
        ));
        assert!(
            store.records() > store.max_records,
            "the budget is a target, and this case is why"
        );
    }

    /// Near names come from the other packages held from the same repository. A record
    /// whose package is not held is judged on itself.
    #[test]
    fn signals_compare_names_held_from_the_same_repository() {
        let fired = |(_, detection): (String, Detection)| -> Vec<String> {
            detection
                .findings
                .into_iter()
                .map(|finding| format!("{}: {}", finding.rule, finding.detail))
                .collect()
        };
        let mut store = RecordStore::new(100);
        store.insert(NPM, packument("express", &["1.0.0"]));
        store.insert(NPM, packument("expres", &["1.0.0"]));
        store.insert(
            Repository::of(crate::identity::Ecosystem::PyPI),
            PackageMetadata {
                key: PackageKey::from_registry_name(crate::identity::Ecosystem::PyPI, "expresz")
                    .unwrap(),
                latest: None,
                records: Vec::new(),
                skipped: Vec::new(),
            },
        );
        let now = jiff::Timestamp::now();
        let expres = packument("expres", &["1.0.0"]).records.remove(0);
        assert_eq!(
            fired(store.metadata(NPM, &expres, None, now)),
            ["near_name: one edit from `express`, served here"]
        );
        let unheld = packument("lodash", &["1.0.0"]).records.remove(0);
        assert_eq!(
            fired(store.metadata(NPM, &unheld, None, now)),
            Vec::<String>::new()
        );

        let mut taken = packument("taken", &["1.0.0", "1.0.1"]);
        for (record, (days, publisher)) in taken.records.iter_mut().zip([(400, "ana"), (1, "eve")])
        {
            record.published_at = Some(now - jiff::SignedDuration::from_hours(24 * days));
            record.provenance.publisher = Some(publisher.to_owned());
        }
        let latest = taken.records[1].clone();
        store.insert(NPM, taken);
        assert_eq!(
            fired(store.metadata(NPM, &latest, None, now)),
            ["new_publisher: eve published no earlier version"],
            "the held document names the earlier publisher"
        );
    }
}
