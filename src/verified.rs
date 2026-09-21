//! Artifacts this proxy has fetched and verified, keyed by content digest.
//!
//! Plan §5 branches the fetch path on whether the artifact in hand has been seen before:
//! a hit streams through, a novel artifact may be analysed or deferred. The key is the
//! artifact's own content digest, which the packument publishes and which is therefore
//! known before the fetch rather than after it.
//!
//! # A hit does not skip verification
//!
//! It would be the obvious saving and it is the wrong one. A hit says that these bytes
//! were verified *on an earlier request*. It says nothing about the bytes arriving now,
//! which come from upstream on this request and could differ. Skipping the hash on a hit
//! would mean a registry that served correct bytes once could serve anything afterwards
//! and have it forwarded unchecked, which is the exact failure
//! `proxy::VerifyingStream` exists to catch.
//!
//! So every artifact is hashed every time, and this answers a different question: has
//! this artifact been past before? In Stage 1 that changes no response, because nothing
//! analyses and nothing defers. It makes the branch, the key and the counts real, and it
//! is the same key Stage 5's analysis cache is specified to use.
//!
//! # Why it is bounded
//!
//! One entry per artifact version ever fetched, and a proxy accumulates them for as long
//! as it runs. Evicted by count, least recently used first, like [`crate::store`].

use crate::integrity::Sri;
use crate::util::lru::Lru;

/// Whether this artifact has been fetched and verified before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// Verified on an earlier request. Plan §5's cache hit.
    Before,
    /// Not seen. Plan §5's novel artifact.
    First,
}

impl Seen {
    /// For logging, so a hit and a miss read the same width.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Before => "hit",
            Self::First => "miss",
        }
    }
}

/// Content digests of artifacts that have been fetched and verified.
pub struct VerifiedArtifacts(Lru<Sri, ()>);

impl VerifiedArtifacts {
    pub fn new(max_entries: usize) -> Self {
        Self(Lru::new(max_entries))
    }

    /// Whether this digest has been verified before, marking it recently used.
    pub fn lookup(&mut self, sri: &Sri) -> Seen {
        match self.0.get(sri) {
            Some(()) => Seen::Before,
            None => Seen::First,
        }
    }

    /// Record that this digest was verified against bytes that actually arrived.
    ///
    /// Called when the hash matches, never when it does not: a mismatch means the
    /// registry served bytes its own packument does not describe, and recording that
    /// would be recording the attack.
    pub fn record(&mut self, sri: Sri) {
        self.0.insert(sri, ());
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sri(seed: u8) -> Sri {
        use base64::Engine as _;
        let digest = vec![seed; 64];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&digest);
        Sri::parse(&format!("sha512-{encoded}")).unwrap()
    }

    #[test]
    fn an_artifact_is_novel_until_it_has_been_verified() {
        let mut seen = VerifiedArtifacts::new(crate::env::DEFAULT_MAX_VERIFIED);
        assert_eq!(seen.lookup(&sri(1)), Seen::First);
        assert!(seen.is_empty());

        seen.record(sri(1));
        assert_eq!(seen.lookup(&sri(1)), Seen::Before);
        assert_eq!(seen.lookup(&sri(2)), Seen::First, "a different artifact");
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn recording_the_same_artifact_twice_holds_one_entry() {
        let mut seen = VerifiedArtifacts::new(crate::env::DEFAULT_MAX_VERIFIED);
        seen.record(sri(1));
        seen.record(sri(1));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn the_budget_evicts_least_recently_used_artifacts() {
        let mut seen = VerifiedArtifacts::new(2);
        seen.record(sri(1));
        seen.record(sri(2));
        // Touching 1 makes 2 the oldest.
        assert_eq!(seen.lookup(&sri(1)), Seen::Before);
        seen.record(sri(3));

        assert_eq!(seen.len(), 2);
        assert_eq!(seen.lookup(&sri(1)), Seen::Before);
        assert_eq!(seen.lookup(&sri(3)), Seen::Before);
        assert_eq!(seen.lookup(&sri(2)), Seen::First, "evicted");
    }

    /// A budget of zero would pay for every lookup and remember nothing.
    #[test]
    fn a_budget_below_one_is_raised_to_one() {
        let mut seen = VerifiedArtifacts::new(0);
        seen.record(sri(1));
        assert_eq!(seen.lookup(&sri(1)), Seen::Before);
    }

    #[test]
    fn hit_and_miss_read_the_same_width_in_a_log() {
        assert_eq!(Seen::Before.as_str(), "hit");
        assert_eq!(Seen::First.as_str(), "miss");
    }
}
