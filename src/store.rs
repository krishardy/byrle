//! What the proxy remembers from packuments it has already seen.
//!
//! The fetch path needs the artifact digest *before* the tarball is fetched (plan §5),
//! and the packument that published it went past on an earlier request. This holds those
//! records so the tarball request can find them.
//!
//! # Why it is bounded
//!
//! A packument carries every version ever published, not the one being installed:
//! measured over an `express + @babel/code-frame + typescript + eslint` install, 167
//! packuments totalling 9,690 records, the largest being typescript at 3,822. A proxy
//! left running accumulates these for as long as it runs, so the store evicts by total
//! record count, least recently used first.
//!
//! One packument larger than the whole budget is still kept, because the tarball request
//! that follows it is the reason to have stored anything. The budget is a target, not a
//! hard ceiling.
//!
//! The budget counts records, and a record was one artifact when it was calibrated. A PyPI
//! record holds one artifact per file, `requests` 2.32.3 being a wheel and an sdist, so the
//! count tracks memory less closely than it did. It is still a bound; it is no longer a
//! proportional one.

use crate::identity::PackageKey;
use crate::npm::NormalizedPackument;
use crate::record::PackageRecord;
use std::collections::HashMap;

struct Entry {
    packument: NormalizedPackument,
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
    /// The packument was seen and names this version.
    Found(Box<PackageRecord>),
    /// The packument was seen and does not name this version.
    ///
    /// Reached when a tarball filename spells a version differently from the packument:
    /// `express@3.0.0-rc1` is served at `express-3.0.0rc1.tgz`, 38 such cases in 24,852
    /// measured URLs.
    NoSuchVersion,
    /// No packument for this package has gone past. A warm npm cache produces this: the
    /// client sends `If-None-Match`, the registry answers 304 with no body.
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

    /// Store a packument, replacing any earlier copy of the same package.
    pub fn insert(&mut self, packument: NormalizedPackument) {
        self.clock += 1;
        let added = packument.records.len();
        let key = packument.key.clone();

        if let Some(previous) = self.entries.insert(
            key,
            Entry {
                packument,
                last_used: self.clock,
            },
        ) {
            self.records -= previous.packument.records.len();
        }
        self.records += added;
        self.evict_to_budget();
    }

    /// Whether any record is held for this package.
    ///
    /// Does not count as a use: this answers "is there anything to read", and a package
    /// that is only ever asked about should not outlive one that is installed.
    pub fn holds(&self, key: &PackageKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Find the record for one version, marking its package as recently used.
    pub fn lookup(&mut self, key: &PackageKey, version: &str) -> Lookup {
        self.clock += 1;
        let clock = self.clock;
        let Some(entry) = self.entries.get_mut(key) else {
            return Lookup::Unknown;
        };
        entry.last_used = clock;
        match entry.packument.version(version) {
            Some(record) => Lookup::Found(Box::new(record.clone())),
            None => Lookup::NoSuchVersion,
        }
    }

    /// Drop least recently used packages until the budget is met.
    ///
    /// Never drops the most recently used entry, so a package whose packument alone
    /// exceeds the budget is still there for the tarball request that follows it.
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
            if let Some(entry) = self.entries.remove(&key) {
                self.records -= entry.packument.records.len();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npm::normalize_packument;
    use crate::record::PackumentDetail;

    fn packument(name: &str, versions: &[&str]) -> NormalizedPackument {
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
        normalize_packument(body.as_bytes(), PackumentDetail::Abbreviated).expect("valid fixture")
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(crate::identity::Ecosystem::Npm, name).unwrap()
    }

    #[test]
    fn a_stored_packument_answers_for_its_versions() {
        let mut store = RecordStore::new(100);
        assert!(store.is_empty());
        store.insert(packument("lodash", &["4.17.20", "4.17.21"]));

        assert_eq!(store.len(), 1);
        assert_eq!(store.records(), 2);
        let Lookup::Found(record) = store.lookup(&key("lodash"), "4.17.21") else {
            panic!("the packument names this version");
        };
        assert_eq!(
            record.artifact().expect("one file").integrity.as_deref(),
            Some("sha512-4.17.21")
        );
    }

    /// Three outcomes, not two. A version the packument does not name is a different
    /// situation from a package never seen, and the fetch path has to tell them apart:
    /// one means the filename disagrees with the document, the other means nothing was
    /// observed at all.
    #[test]
    fn a_missing_version_and_a_missing_package_are_different_answers() {
        let mut store = RecordStore::new(100);
        store.insert(packument("express", &["3.0.0-rc1"]));

        assert_eq!(
            store.lookup(&key("express"), "3.0.0rc1"),
            Lookup::NoSuchVersion,
            "this is the spelling the tarball path uses, and the packument does not"
        );
        assert_eq!(store.lookup(&key("lodash"), "4.17.21"), Lookup::Unknown);
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
            store.lookup(&key("a"), "1.0.0"),
            Lookup::Unknown,
            "`a` was least recently used"
        );
        assert!(matches!(store.lookup(&key("c"), "1.0.0"), Lookup::Found(_)));
    }

    /// A lookup is a use. Without that, a package read on every install would be evicted
    /// in favour of one stored once and never touched again.
    /// Asking whether anything is held must not keep it alive, or a package that is only
    /// ever asked about outlives one that is installed.
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
        assert!(matches!(store.lookup(&key("a"), "1.0.0"), Lookup::Found(_)));

        store.insert(packument("c", &["1.0.0", "1.0.1"]));
        assert!(
            matches!(store.lookup(&key("a"), "1.0.0"), Lookup::Found(_)),
            "`a` was used more recently than `b`"
        );
        assert_eq!(store.lookup(&key("b"), "1.0.0"), Lookup::Unknown);
    }

    /// typescript is 3,822 versions. A packument over the whole budget is still kept,
    /// because the tarball request that follows it is the reason to store anything.
    #[test]
    fn a_packument_larger_than_the_budget_is_still_available() {
        let mut store = RecordStore::new(2);
        store.insert(packument("big", &["1.0.0", "1.0.1", "1.0.2", "1.0.3"]));

        assert_eq!(store.len(), 1);
        assert!(matches!(
            store.lookup(&key("big"), "1.0.3"),
            Lookup::Found(_)
        ));
        assert!(
            store.records() > store.max_records,
            "the budget is a target, and this case is why"
        );
    }
}
