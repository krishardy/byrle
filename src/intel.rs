//! What an advisory stream may say. An [`Enrichment`] never becomes a [`Finding`]:
//! ```compile_fail
//! let f: waharoa::intel::Finding = waharoa::intel::Enrichment::new("CVE-2024-1234").into();
//! ```

pub mod fetch;
pub mod history;
pub mod load;
pub mod postgres;
pub mod providers;
pub mod range;
pub mod refresh;
pub mod rows;
pub mod snapshot_dir;
pub mod snapshot_intel;
pub mod store;
pub mod stream;

use std::collections::{BTreeMap, BTreeSet};

/// What a stream may say about one ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Answers "what is wrong with this package". Originates findings.
    Match,
    /// Answers "what more is known about this advisory". Adds to findings, never makes one.
    Enrich,
    /// Answers "is this package malware", which feeds the one check with no exception.
    Malware,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Enrich => "enrich",
            Self::Malware => "malware",
        }
    }
}

/// A score, and which stream said so, for `explain`. The merge rule does not read the source.
#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    cvss: f64,
    pub source: String,
}

impl Score {
    /// A score from `source`, refused rather than clamped so enrichment order cannot matter.
    /// See docs/engineering_decisions/advisory-stream-licences.md.
    /// `cvss` must be 0.0 to 10.0, so NaN is refused. Returns `None` otherwise.
    pub fn new(source: &str, cvss: f64) -> Option<Self> {
        Self::in_range(cvss).then(|| Self {
            cvss,
            source: source.to_owned(),
        })
    }

    pub fn cvss(&self) -> f64 {
        self.cvss
    }

    /// The CVSS range. Rejects NaN and both infinities, because no comparison against
    /// those is true and `contains` is a pair of comparisons.
    pub fn in_range(cvss: f64) -> bool {
        (0.0..=10.0).contains(&cvss)
    }

    /// Whether an offered score replaces one already held.
    ///
    /// Split out from [`Finding::enriched_by`] because it allocates nothing and is what
    /// the kani proofs below reason about.
    fn replaces(held: Option<f64>, offered: f64) -> bool {
        held.is_none_or(|held| offered > held)
    }
}

/// Whether `wanted` is `advisory_id` or one of its `aliases`.
///
/// OSV stores a GitHub advisory under its `GHSA-` id with the CVE id as an alias, and an
/// exception, a KEV entry or NVD gives the CVE. See
/// docs/engineering_decisions/alias-matching.md.
pub fn is_named(advisory_id: &str, aliases: &[String], wanted: &str) -> bool {
    ids(advisory_id, aliases).any(|id| id == wanted)
}

/// `advisory_id`, then each of its `aliases`.
pub fn ids<'a>(advisory_id: &'a str, aliases: &'a [String]) -> impl Iterator<Item = &'a str> {
    std::iter::once(advisory_id).chain(aliases.iter().map(String::as_str))
}

/// Something wrong with a package. Only a `match` stream can make one.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub advisory_id: String,
    /// The other ids the advisory is known by. An enrichment keyed on any of them applies.
    pub aliases: Vec<String>,
    pub score: Option<Score>,
    /// Which stream originated this.
    pub source: String,
    /// Whether the advisory is known to be exploited. Always `false` as originated.
    exploited: bool,
}

impl Finding {
    pub fn new(source: &str, advisory_id: &str) -> Self {
        Self {
            advisory_id: advisory_id.to_owned(),
            aliases: Vec::new(),
            score: None,
            source: source.to_owned(),
            exploited: false,
        }
    }

    /// Record the other ids this stream gave the advisory.
    pub fn with_aliases(mut self, aliases: &[String]) -> Self {
        self.aliases = aliases.to_vec();
        self
    }

    /// Record a score this stream reported. `cvss` outside 0.0 to 10.0 is dropped, and the
    /// finding is kept with whatever score it had.
    pub fn with_score(mut self, cvss: f64) -> Self {
        if let Some(score) = Score::new(&self.source, cvss) {
            self.score = Some(score);
        }
        self
    }

    pub fn exploited(&self) -> bool {
        self.exploited
    }

    /// Apply what `enrich` streams know about this advisory, escalating only, so the order
    /// they arrive in does not matter. `enrichments` apply by the advisory's id or an alias.
    pub fn enriched_by(mut self, enrichments: &[Enrichment]) -> Self {
        for e in enrichments
            .iter()
            .filter(|e| is_named(&self.advisory_id, &self.aliases, &e.advisory_id))
        {
            if let Some(score) = &e.score
                && Score::replaces(self.score.as_ref().map(Score::cvss), score.cvss)
            {
                self.score = Some(score.clone());
            }
            if e.exploited {
                self.exploited = true;
            }
        }
        self
    }
}

/// What more is known about an advisory. Carries no package, and cannot become a [`Finding`].
#[derive(Debug, Clone, PartialEq)]
pub struct Enrichment {
    pub advisory_id: String,
    pub score: Option<Score>,
    pub exploited: bool,
}

impl Enrichment {
    pub fn new(advisory_id: &str) -> Self {
        Self {
            advisory_id: advisory_id.to_owned(),
            score: None,
            exploited: false,
        }
    }

    /// Record a score. Out of range is dropped, as in [`Finding::with_score`].
    pub fn with_score(mut self, source: &str, cvss: f64) -> Self {
        if let Some(score) = Score::new(source, cvss) {
            self.score = Some(score);
        }
        self
    }

    /// What a KEV catalogue contributes: this advisory is being exploited.
    pub fn exploited(mut self) -> Self {
        self.exploited = true;
        self
    }
}

/// A stream that can say what is wrong with a package.
pub trait MatchStream {
    fn name(&self) -> &str;
    fn findings(&self, ecosystem: &str, name: &str, version: &str) -> Vec<Finding>;
}

/// A stream that can only add to what another stream found, asked about advisories only.
pub trait EnrichStream {
    fn name(&self) -> &str;
    fn enrichments(&self, advisory_ids: &[String]) -> Vec<Enrichment>;
}

/// A stream that can say a package is malware, which no exception overrides.
pub trait MalwareStream {
    fn name(&self) -> &str;
    fn is_malware(&self, ecosystem: &str, name: &str, version: &str) -> bool;
}

/// What each stream is trusted to say, per ecosystem.
#[derive(Debug, Default)]
pub struct Capabilities {
    by_stream: BTreeMap<String, BTreeMap<String, BTreeSet<Capability>>>,
}

impl Capabilities {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant(mut self, stream: &str, ecosystem: &str, granted: &[Capability]) -> Self {
        self.by_stream
            .entry(stream.to_owned())
            .or_default()
            .entry(ecosystem.to_owned())
            .or_default()
            .extend(granted.iter().copied());
        self
    }

    pub fn has(&self, stream: &str, ecosystem: &str, capability: Capability) -> bool {
        self.by_stream
            .get(stream)
            .and_then(|by_eco| by_eco.get(ecosystem))
            .is_some_and(|c| c.contains(&capability))
    }

    /// Streams granted a capability for an ecosystem.
    pub fn providers(&self, ecosystem: &str, capability: Capability) -> Vec<&str> {
        self.by_stream
            .iter()
            .filter(|(_, by_eco)| {
                by_eco
                    .get(ecosystem)
                    .is_some_and(|c| c.contains(&capability))
            })
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Ecosystems in `enabled` with no stream providing `match`, for the startup warning and
    /// `doctor`. `LoadedSnapshot::gaps` adds those with no `malware` stream.
    /// Returns the gaps.
    pub fn gaps(&self, enabled: &[&str]) -> Vec<Gap> {
        self.uncovered_by(enabled, Capability::Match)
    }

    /// Enabled ecosystems no stream provides `capability` for.
    pub fn uncovered_by(&self, enabled: &[&str], capability: Capability) -> Vec<Gap> {
        enabled
            .iter()
            .filter(|&&ecosystem| self.providers(ecosystem, capability).is_empty())
            .map(|&ecosystem| Gap {
                ecosystem: ecosystem.to_owned(),
                missing: Missing::Capability(capability),
            })
            .collect()
    }
}

/// The ecosystems this build serves, as streams key them: one per row of
/// [`crate::ecosystem::TABLE`].
pub fn served() -> Vec<&'static str> {
    crate::ecosystem::TABLE
        .iter()
        .map(|registry| registry.ecosystem.as_str())
        .collect()
}

/// The ecosystems whose row lists the stream recorded as `stream`.
fn listing(stream: &str) -> Vec<&'static str> {
    crate::ecosystem::TABLE
        .iter()
        .filter(|registry| registry.streams.iter().any(|s| s.stream == stream))
        .map(|registry| registry.ecosystem.as_str())
        .collect()
}

/// What the streams a snapshot records may say, as this build declares it. A stream this
/// build does not know is granted nothing.
pub fn capabilities_of(streams: &[refresh::StreamDigest]) -> Capabilities {
    streams.iter().fold(Capabilities::new(), |caps, s| {
        let Some(declared) = stream::by_stream(&s.stream) else {
            return caps;
        };
        declared.grants.iter().fold(caps, |caps, grant| {
            let ecosystems = match grant.scope {
                stream::Scope::Listed => listing(&s.stream),
                stream::Scope::Served => served(),
            };
            ecosystems.into_iter().fold(caps, |caps, ecosystem| {
                caps.grant(&s.stream, ecosystem, grant.capabilities)
            })
        })
    })
}

/// A served ecosystem the snapshot cannot answer for, and what it lacks.
#[derive(Debug, PartialEq)]
pub struct Gap {
    pub ecosystem: String,
    pub missing: Missing,
}

/// What a [`Gap`] lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// No stream in the snapshot provides this capability.
    Capability(Capability),
    /// A stream the ecosystem lists that the snapshot does not hold, and that was configured.
    Stream(String),
}

impl std::fmt::Display for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.missing {
            Missing::Capability(capability) => write!(
                f,
                "`{}` is served with no stream providing {}, so a policy answers 503 for its \
                 packages. Nothing can {}",
                self.ecosystem,
                capability.as_str(),
                match capability {
                    Capability::Match => "originate a finding for it",
                    Capability::Enrich => "add to a finding for it",
                    Capability::Malware => "report malware for it",
                }
            ),
            Missing::Stream(stream) => write!(
                f,
                "`{}` lists `{stream}`, and the intel snapshot does not hold it, so a policy \
                 answers 503 for its packages. `waharoa intel history` says why it did not load",
                self.ecosystem
            ),
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::Score;

    /// Apply two offered scores in the order given.
    fn fold(held: Option<f64>, offered: [f64; 2]) -> Option<f64> {
        let mut held = held;
        for offer in offered {
            if Score::replaces(held, offer) {
                held = Some(offer);
            }
        }
        held
    }

    /// Rejecting out-of-range scores is what makes everything below true. Without it a
    /// NaN reaches `replaces`, where every comparison against it is false.
    #[kani::proof]
    fn nothing_outside_the_cvss_range_is_accepted() {
        let cvss: f64 = kani::any();
        kani::assume(Score::in_range(cvss));

        assert!(cvss >= 0.0);
        assert!(cvss <= 10.0);
        assert!(cvss.is_finite());
        assert!(!cvss.is_nan());
    }

    /// Two accepted scores are always comparable, so `>` decides between them.
    #[kani::proof]
    fn any_two_accepted_scores_stand_in_exactly_one_relation() {
        let (a, b): (f64, f64) = (kani::any(), kani::any());
        kani::assume(Score::in_range(a) && Score::in_range(b));

        assert!(usize::from(a > b) + usize::from(b > a) + usize::from(a == b) == 1);
    }

    /// The property the whole design rests on: which stream is read first cannot change
    /// what a finding ends up scored at.
    #[kani::proof]
    fn the_order_two_enrichments_arrive_in_does_not_change_the_score() {
        let (a, b): (f64, f64) = (kani::any(), kani::any());
        kani::assume(Score::in_range(a) && Score::in_range(b));

        let held: Option<f64> = if kani::any() {
            let held: f64 = kani::any();
            kani::assume(Score::in_range(held));
            Some(held)
        } else {
            None
        };

        assert!(fold(held, [a, b]) == fold(held, [b, a]));
    }

    /// An enrichment escalates or leaves alone, and never the reverse.
    #[kani::proof]
    fn an_enrichment_never_lowers_a_score() {
        let (held, offered): (f64, f64) = (kani::any(), kani::any());
        kani::assume(Score::in_range(held) && Score::in_range(offered));

        let after = fold(Some(held), [offered, offered]).unwrap();
        assert!(after >= held);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn recorded(stream: &str) -> refresh::StreamDigest {
        refresh::StreamDigest {
            stream: stream.to_owned(),
            sha256: "aa".to_owned(),
            etag: None,
            last_modified: None,
        }
    }

    #[test]
    fn each_stream_this_build_loads_is_granted_what_it_may_say_and_no_other_stream_is() {
        let caps = capabilities_of(&[
            recorded("osv/npm"),
            recorded("cisa/kev"),
            recorded("datadog/npm"),
            recorded("osv/pypi"),
        ]);
        assert_eq!(served(), ["npm", "pypi"]);
        assert_eq!(
            caps.providers("npm", Capability::Match),
            ["datadog/npm", "osv/npm"]
        );
        assert_eq!(
            caps.providers("npm", Capability::Malware),
            ["datadog/npm", "osv/npm"]
        );
        assert_eq!(caps.providers("npm", Capability::Enrich), ["cisa/kev"]);
        assert!(caps.has("osv/pypi", "pypi", Capability::Match));
        assert!(!caps.has("osv/pypi", "npm", Capability::Match));
        assert_eq!(caps.providers("pypi", Capability::Match), ["osv/pypi"]);
        assert!(caps.gaps(&["npm", "pypi"]).is_empty());
        assert!(caps.uncovered_by(&["npm"], Capability::Malware).is_empty());
        assert_eq!(caps.providers("pypi", Capability::Enrich), ["cisa/kev"]);
    }

    /// A row lists a stream by the name a snapshot records, and a catalogue is listed by
    /// no row.
    #[test]
    fn listing_is_the_rows_whose_streams_include_it() {
        assert_eq!(listing("osv/npm"), ["npm"]);
        assert!(listing("cisa/kev").is_empty());
        assert_eq!(listing("osv/pypi"), ["pypi"]);
    }

    /// PyPI is served and the snapshot records none of its streams, so both gaps are reported
    /// rather than PyPI reading as covered.
    #[test]
    fn a_served_ecosystem_no_stream_lists_is_reported_as_a_gap() {
        let caps = capabilities_of(&[
            recorded("osv/npm"),
            recorded("cisa/kev"),
            recorded("datadog/npm"),
        ]);
        let pypi_without = |capability| Gap {
            ecosystem: "pypi".to_owned(),
            missing: Missing::Capability(capability),
        };
        assert_eq!(caps.gaps(&served()), [pypi_without(Capability::Match)]);
        assert_eq!(
            caps.uncovered_by(&served(), Capability::Malware),
            [pypi_without(Capability::Malware)]
        );
    }

    /// Standing in for NVD or KEV: keyed on CVE ids, knowing nothing about packages.
    struct Catalogue;

    impl EnrichStream for Catalogue {
        fn name(&self) -> &str {
            "kev"
        }

        fn enrichments(&self, advisory_ids: &[String]) -> Vec<Enrichment> {
            advisory_ids
                .iter()
                .filter(|id| id.as_str() == "CVE-2021-44228")
                .map(|id| Enrichment::new(id).exploited())
                .collect()
        }
    }

    #[test]
    fn an_enrich_stream_is_asked_about_advisories_and_never_about_a_package() {
        let ids = vec!["CVE-2021-44228".to_owned(), "CVE-2020-0001".to_owned()];
        let enrichments = Catalogue.enrichments(&ids);

        assert_eq!(enrichments.len(), 1);
        assert_eq!(enrichments[0].advisory_id, "CVE-2021-44228");
        assert!(enrichments[0].exploited);
        assert_eq!(Catalogue.name(), "kev");
    }

    #[test]
    fn a_finding_is_not_exploited_until_something_that_knows_says_so() {
        let finding = Finding::new("osv", "CVE-2021-44228");
        assert!(!finding.exploited());

        let enriched = finding.enriched_by(&Catalogue.enrichments(&["CVE-2021-44228".to_owned()]));
        assert!(enriched.exploited());
    }

    /// OSV publishes `GHSA-` and `MAL-` ids and CISA keys on `cveID`. GHSA-jfh8-c2jp-5v3q
    /// carries CVE-2021-44228 as an alias, and the KEV entry reaches it only by that alias.
    #[test]
    fn a_kev_entry_reaches_an_osv_finding_through_its_alias_and_only_through_it() {
        let kev = Catalogue.enrichments(&["CVE-2021-44228".to_owned()]);
        let finding = Finding::new("osv", "GHSA-jfh8-c2jp-5v3q");

        assert!(!finding.clone().enriched_by(&kev).exploited());
        let aliased = finding.with_aliases(&["CVE-2021-44228".to_owned()]);
        assert!(aliased.enriched_by(&kev).exploited());
        assert!(
            !Finding::new("osv", "GHSA-other")
                .with_aliases(&["CVE-2021-45046".to_owned()])
                .enriched_by(&kev)
                .exploited()
        );
    }

    #[test]
    fn an_enrichment_raises_a_score_and_never_lowers_one() {
        let finding = Finding::new("osv", "CVE-1").with_score(5.0);

        let raised = finding
            .clone()
            .enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 9.8)]);
        assert_eq!(raised.score.as_ref().unwrap().cvss(), 9.8);
        assert_eq!(raised.score.as_ref().unwrap().source, "nvd");

        let lowered = finding.enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 1.0)]);
        assert_eq!(lowered.score.as_ref().unwrap().cvss(), 5.0);
        assert_eq!(lowered.score.as_ref().unwrap().source, "osv");
    }

    #[test]
    fn an_enrichment_supplies_a_score_the_matching_stream_did_not_have() {
        let finding = Finding::new("osv", "CVE-1")
            .enriched_by(&[Enrichment::new("CVE-1").with_score("nvd", 4.2)]);

        assert_eq!(finding.score.as_ref().unwrap().cvss(), 4.2);
        assert_eq!(finding.score.as_ref().unwrap().source, "nvd");
    }

    #[test]
    fn a_score_outside_the_cvss_range_is_not_a_score() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 10.1] {
            assert_eq!(Score::new("nvd", bad), None, "{bad} was accepted");
        }
        for good in [0.0, 5.0, 10.0] {
            assert_eq!(Score::new("nvd", good).unwrap().cvss(), good);
        }
    }

    #[test]
    fn a_malformed_score_is_dropped_and_the_finding_survives() {
        let finding = Finding::new("osv", "CVE-1")
            .with_score(7.5)
            .with_score(f64::NAN);
        assert_eq!(finding.score.unwrap().cvss(), 7.5);

        let finding = Finding::new("osv", "CVE-1").with_score(99.9);
        assert_eq!(
            finding.advisory_id, "CVE-1",
            "a finding whose only score is malformed is still a finding"
        );
        assert_eq!(finding.score, None);

        assert_eq!(
            Enrichment::new("CVE-1").with_score("nvd", f64::NAN).score,
            None
        );
    }

    #[test]
    fn a_score_no_stream_could_report_cannot_stick_wherever_it_landed_first() {
        let nan = Enrichment::new("CVE-1").with_score("a", f64::NAN);
        let real = Enrichment::new("CVE-1").with_score("b", 9.0);

        let nan_first = Finding::new("osv", "CVE-1").enriched_by(&[nan.clone(), real.clone()]);
        let nan_second = Finding::new("osv", "CVE-1").enriched_by(&[real, nan]);

        assert_eq!(nan_first, nan_second);
        assert_eq!(nan_first.score.unwrap().cvss(), 9.0);
    }

    #[test]
    fn two_streams_disagreeing_settle_the_same_way_whichever_is_read_first() {
        let low = Enrichment::new("CVE-1").with_score("a", 3.0);
        let high = Enrichment::new("CVE-1").with_score("b", 9.0);

        let one_way = Finding::new("osv", "CVE-1").enriched_by(&[low.clone(), high.clone()]);
        let other_way = Finding::new("osv", "CVE-1").enriched_by(&[high, low]);

        assert_eq!(one_way, other_way);
        assert_eq!(one_way.score.unwrap().source, "b");
    }

    #[test]
    fn an_enrichment_for_a_different_advisory_is_not_applied() {
        let finding = Finding::new("osv", "CVE-1")
            .with_score(2.0)
            .enriched_by(&[Enrichment::new("CVE-2").with_score("nvd", 9.8).exploited()]);

        assert_eq!(finding.score.unwrap().cvss(), 2.0);
        assert!(!finding.exploited);
    }

    #[test]
    fn an_ecosystem_a_stream_can_only_enrich_is_still_a_gap() {
        let caps = Capabilities::new().grant("nvd", "npm", &[Capability::Enrich]);

        let gaps = caps.gaps(&["npm"]);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing, Missing::Capability(Capability::Match));
        assert!(caps.providers("npm", Capability::Match).is_empty());
        assert_eq!(caps.providers("npm", Capability::Enrich), vec!["nvd"]);
    }

    #[test]
    fn holding_a_capability_for_one_ecosystem_does_not_grant_it_for_another() {
        let caps =
            Capabilities::new().grant("nvd", "maven", &[Capability::Match, Capability::Enrich]);

        assert!(caps.has("nvd", "maven", Capability::Match));
        assert!(!caps.has("nvd", "npm", Capability::Match));
        assert!(!caps.has("osv", "maven", Capability::Match));
        assert!(caps.gaps(&["maven"]).is_empty());
    }

    #[test]
    fn saying_what_is_wrong_with_a_package_does_not_carry_the_right_to_call_it_malware() {
        let caps = Capabilities::new().grant("ghsa", "npm", &[Capability::Match]);

        assert!(caps.has("ghsa", "npm", Capability::Match));
        assert!(!caps.has("ghsa", "npm", Capability::Malware));

        assert!(caps.gaps(&["npm"]).is_empty());
        assert_eq!(
            caps.uncovered_by(&["npm"], Capability::Malware)[0].missing,
            Missing::Capability(Capability::Malware)
        );
    }

    #[test]
    fn an_ecosystem_with_both_a_matcher_and_a_malware_stream_has_no_gap() {
        let caps = Capabilities::new()
            .grant("osv", "npm", &[Capability::Match, Capability::Malware])
            .grant("nvd", "npm", &[Capability::Enrich]);

        assert!(caps.gaps(&["npm"]).is_empty());
        assert!(caps.uncovered_by(&["npm"], Capability::Malware).is_empty());
    }

    #[test]
    fn an_ecosystem_served_with_no_stream_at_all_is_a_gap() {
        let caps =
            Capabilities::new().grant("osv", "npm", &[Capability::Match, Capability::Malware]);

        let gaps = caps.gaps(&["npm", "pypi"]);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].ecosystem, "pypi");
        assert_eq!(
            gaps[0].to_string(),
            "`pypi` is served with no stream providing match, so a policy answers 503 for its \
             packages. Nothing can originate a finding for it"
        );
    }

    #[test]
    fn every_gap_names_what_the_missing_capability_would_have_done() {
        let caps = Capabilities::new();
        let said = |c| caps.uncovered_by(&["npm"], c)[0].to_string();

        assert!(said(Capability::Match).ends_with("Nothing can originate a finding for it"));
        assert!(said(Capability::Enrich).ends_with("Nothing can add to a finding for it"));
        assert!(said(Capability::Malware).ends_with("Nothing can report malware for it"));
    }

    #[test]
    fn granting_the_same_stream_twice_adds_rather_than_replaces() {
        let caps = Capabilities::new()
            .grant("osv", "npm", &[Capability::Match])
            .grant("osv", "npm", &[Capability::Malware]);

        assert!(caps.has("osv", "npm", Capability::Match));
        assert!(caps.has("osv", "npm", Capability::Malware));
    }

    #[test]
    fn every_capability_has_the_name_the_plan_gives_it() {
        assert_eq!(Capability::Match.as_str(), "match");
        assert_eq!(Capability::Enrich.as_str(), "enrich");
        assert_eq!(Capability::Malware.as_str(), "malware");
    }

    #[test]
    fn a_matcher_reports_what_it_found_and_says_who_it_was() {
        struct Osv;

        impl MatchStream for Osv {
            fn name(&self) -> &str {
                "osv"
            }

            fn findings(&self, ecosystem: &str, name: &str, _version: &str) -> Vec<Finding> {
                if ecosystem == "npm" && name == "left-pad" {
                    vec![Finding::new(self.name(), "GHSA-xxxx").with_score(7.5)]
                } else {
                    Vec::new()
                }
            }
        }

        assert_eq!(Osv.name(), "osv");
        assert!(Osv.findings("npm", "right-pad", "1.0.0").is_empty());

        let found = Osv.findings("npm", "left-pad", "1.0.0");
        assert_eq!(found[0].source, "osv");
        assert_eq!(found[0].score.as_ref().unwrap().source, "osv");
        assert!(!found[0].exploited());
    }

    #[test]
    fn a_malware_stream_answers_only_yes_or_no() {
        struct Mal;

        impl MalwareStream for Mal {
            fn name(&self) -> &str {
                "osv-malware"
            }

            fn is_malware(&self, ecosystem: &str, name: &str, _version: &str) -> bool {
                ecosystem == "npm" && name == "evil-pkg"
            }
        }

        assert_eq!(Mal.name(), "osv-malware");
        assert!(Mal.is_malware("npm", "evil-pkg", "1.0.0"));
        assert!(!Mal.is_malware("npm", "left-pad", "1.0.0"));
    }

    /// A stream this build does not declare is granted nothing.
    #[test]
    fn an_unknown_stream_grants_nothing() {
        let capabilities = capabilities_of(&[recorded("somewhere/else")]);
        assert_eq!(
            capabilities.uncovered_by(&["npm"], Capability::Match).len(),
            1
        );
    }
}
