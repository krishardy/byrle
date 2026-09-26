//! A map that keeps the most recently used entries and drops the rest.
//!
//! Every map keyed by artifact digest uses one, bounded by entry count because a proxy left
//! running accumulates entries for as long as it runs: [`crate::verified`] holds the
//! digests of artifacts that have been past, [`crate::analysis::store::InProcess`] what was
//! found in them, [`crate::analysis::run::Analyser`] the digests whose last fetch did not
//! match, and the proxy the artifacts it deferred.
//!
//! [`crate::store::RecordStore`] is not one of them. Its budget counts the records inside
//! an entry rather than the entries, because one packument carries up to 3,822 of them.

use std::collections::HashMap;
use std::hash::Hash;

struct Entry<V> {
    value: V,
    last_used: u64,
}

/// Values keyed by `K`, bounded by entry count, least recently used evicted first.
pub struct Lru<K, V> {
    entries: HashMap<K, Entry<V>>,
    max_entries: usize,
    /// Counts operations, not time. Nothing compares it across two maps.
    clock: u64,
}

impl<K: Eq + Hash + Clone, V> Lru<K, V> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            // Zero would mean paying for every lookup and holding nothing, so the smallest
            // useful budget is one.
            max_entries: max_entries.max(1),
            clock: 0,
        }
    }

    /// The value held under `key`, marking it recently used.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.clock += 1;
        let entry = self.entries.get_mut(key)?;
        entry.last_used = self.clock;
        Some(&entry.value)
    }

    /// Hold `value` under `key`, replacing what was there, then evict to the budget.
    pub fn insert(&mut self, key: K, value: V) {
        self.clock += 1;
        let last_used = self.clock;
        self.entries.insert(key, Entry { value, last_used });
        self.evict_to_budget();
    }

    /// Take the value held under `key` out of the map.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|entry| entry.value)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop least recently used entries until the budget is met.
    fn evict_to_budget(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }
        let mut order: Vec<(u64, K)> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_used, key.clone()))
            .collect();
        order.sort_unstable_by_key(|(last_used, _)| *last_used);

        for (_, key) in order {
            if self.entries.len() <= self.max_entries {
                break;
            }
            self.entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_holds_the_value_it_was_inserted_with() {
        let mut lru: Lru<u8, &str> = Lru::new(4);
        assert!(lru.is_empty());
        assert_eq!(lru.get(&1), None);

        lru.insert(1, "one");
        assert_eq!(lru.get(&1), Some(&"one"));
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn inserting_the_same_key_twice_holds_one_entry_with_the_later_value() {
        let mut lru: Lru<u8, &str> = Lru::new(4);
        lru.insert(1, "first");
        lru.insert(1, "second");
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.get(&1), Some(&"second"));
    }

    #[test]
    fn the_budget_evicts_least_recently_used_entries() {
        let mut lru: Lru<u8, &str> = Lru::new(2);
        lru.insert(1, "one");
        lru.insert(2, "two");
        // Reading 1 makes 2 the oldest.
        assert_eq!(lru.get(&1), Some(&"one"));
        lru.insert(3, "three");

        assert_eq!(lru.len(), 2);
        assert_eq!(lru.get(&1), Some(&"one"));
        assert_eq!(lru.get(&3), Some(&"three"));
        assert_eq!(lru.get(&2), None, "evicted");
    }

    /// A budget of zero would pay for every lookup and hold nothing.
    #[test]
    fn a_removed_key_holds_nothing() {
        let mut lru = Lru::new(4);
        lru.insert("a", 1);
        assert_eq!(lru.remove(&"a"), Some(1));
        assert_eq!(lru.remove(&"a"), None);
        assert!(lru.is_empty());
    }

    #[test]
    fn a_budget_below_one_is_raised_to_one() {
        let mut lru: Lru<u8, &str> = Lru::new(0);
        lru.insert(1, "one");
        assert_eq!(lru.get(&1), Some(&"one"));
    }
}
