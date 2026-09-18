//! OSV version ranges, ordered by each ecosystem's own rules.
//!
//! [`VersionOrder`] is a row's field in [`crate::ecosystem::TABLE`]: SemVer 2.0 for npm, PEP
//! 440 for PyPI. Every version in a range is read and compared by the order of the ecosystem
//! the range is for.
//!
//! An OSV range is a list of events: `introduced`, `fixed` (the first version not affected)
//! and `last_affected` (the last one affected). Sorted by version, each `introduced` opens an
//! interval and the next `fixed` or `last_affected` closes it. An interval left open at the
//! end has no upper bound. This is the evaluation in the OSV schema's pseudocode, done once at
//! load so the store holds intervals rather than events.
//!
//! npm ranges are `SEMVER` or `ECOSYSTEM`, and both order by SemVer 2.0. Measured over
//! `npm/all.zip` fetched 2026-09-13, the 31 `ECOSYSTEM` ranges contain versions such as `13.0`
//! and `2026.04.1`. Each version is read by [`padded`], as osv.dev reads it, and stored
//! padded, so a stored column is strict SemVer. A range containing a version that is still not
//! SemVer is not stored rather than guessed at.
//!
//! SemVer 2.0 gives build metadata no precedence and the `semver` crate compares it, so it
//! is removed before any comparison. Pre-releases order below their release, so
//! `2.0.0-beta.1` is inside `introduced: 1.0.0, fixed: 2.0.0`.

use semver::{BuildMetadata, Version};
use std::collections::BTreeMap;

use crate::ecosystem::pypi::version::Version as Pep440;
use crate::identity::Ecosystem;

/// How an ecosystem orders its versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrder {
    /// SemVer 2.0, with a short version [`padded`] as osv.dev pads an npm one.
    SemVer,
    /// PEP 440, as pip orders versions.
    Pep440,
}

/// A version as its ecosystem orders it.
///
/// Versions are compared within one ecosystem only. The derived order puts every SemVer
/// version below every PEP 440 one, and nothing compares across the two.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ordered {
    SemVer(Version),
    Pep440(Pep440),
}

impl VersionOrder {
    /// The order of the ecosystem whose purl type is `ecosystem`, or `None` for one no row
    /// in [`crate::ecosystem::TABLE`] is for.
    pub fn of(ecosystem: &str) -> Option<Self> {
        let ecosystem = ecosystem.parse::<Ecosystem>().ok()?;
        Some(crate::ecosystem::of(ecosystem).versions)
    }

    /// A version as this order reads it, or `None` when it is not one.
    pub fn parse(self, s: &str) -> Option<Ordered> {
        match self {
            Self::SemVer => version(s).map(Ordered::SemVer),
            Self::Pep440 => Pep440::parse(s).map(Ordered::Pep440),
        }
    }

    /// The form a version is stored in: [`padded`] for SemVer, and PEP 440's normalised
    /// form, so `1.0-1` is `1.0.post1`. `None` when it is not a version.
    pub fn normalised(self, s: &str) -> Option<String> {
        match self {
            Self::SemVer => padded(s),
            Self::Pep440 => Pep440::parse(s).map(|v| v.to_string()),
        }
    }
}

/// A version as SemVer 2.0 orders it, or `None` when it is not SemVer.
pub fn version(s: &str) -> Option<Version> {
    let mut v = Version::parse(s).ok()?;
    v.build = BuildMetadata::EMPTY;
    Some(v)
}

/// A version as osv.dev reads an npm one: a missing minor or patch is 0 and leading zeros are
/// dropped, so `13.0` is `13.0.0` and `2026.04.1` is `2026.4.1`. What follows the numbers
/// must be SemVer's `-` pre-release or `+` build. `None` when the result is not SemVer 2.0.
pub fn padded(s: &str) -> Option<String> {
    let (numbers, rest) = s.split_at(s.find(['-', '+']).unwrap_or(s.len()));
    let mut parts = Vec::with_capacity(3);
    for part in numbers.split('.') {
        // `-` and `+` are split off above, and parsing refuses anything else but digits.
        if parts.len() == 3 {
            return None;
        }
        parts.push(part.parse::<u64>().ok()?);
    }
    parts.resize(3, 0);
    let written = format!("{}.{}.{}{rest}", parts[0], parts[1], parts[2]);
    version(&written).map(|_| written)
}

/// A listed version as it is stored: [`VersionOrder::normalised`], so a listed npm `12.0`
/// matches the published `12.0.0`, or as written when it is not a version.
pub fn stored(order: VersionOrder, s: &str) -> String {
    order.normalised(s).unwrap_or_else(|| s.to_owned())
}

/// Where an interval stops.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum End<V> {
    /// No upper bound.
    Open,
    /// Up to and excluding this version.
    Fixed(V),
    /// Up to and including this version.
    LastAffected(V),
}

impl End<String> {
    /// The `fixed` and `last_affected` columns this end is stored as.
    pub fn columns(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::Open => (None, None),
            Self::Fixed(v) => (Some(v), None),
            Self::LastAffected(v) => (None, Some(v)),
        }
    }
}

/// One run of affected versions. `V` is `String` as stored and [`Ordered`] as compared.
/// Where an interval starts.
///
/// OSV writes only inclusive lower bounds, so every OSV range is `First` or `Introduced`.
/// GitHub writes `> 4.0.2`, which says 4.0.2 is the last version not affected; that is
/// `After`, and storing it as `Introduced` would report 4.0.2 as vulnerable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Start<V> {
    /// From the first version. OSV's `introduced: "0"`.
    First,
    /// From and including this version.
    Introduced(V),
    /// From but excluding this version.
    After(V),
}

impl<V> Start<V> {
    /// OSV's `introduced`, which is always inclusive. `None` is from the first version.
    pub fn introduced(version: Option<V>) -> Self {
        match version {
            Some(v) => Self::Introduced(v),
            None => Self::First,
        }
    }
}

impl Start<String> {
    /// The `introduced` and `introduced_excluded` columns this start is stored as.
    pub fn columns(&self) -> (Option<&str>, bool) {
        match self {
            Self::First => (None, false),
            Self::Introduced(v) => (Some(v), false),
            Self::After(v) => (Some(v), true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interval<V> {
    pub start: Start<V>,
    pub end: End<V>,
}

impl<V> Interval<V> {
    /// No lower bound and no upper one.
    pub fn is_every_version(&self) -> bool {
        matches!(self.start, Start::First) && matches!(self.end, End::Open)
    }
}

impl Interval<Ordered> {
    pub fn contains(&self, v: &Ordered) -> bool {
        let from_start = match &self.start {
            Start::First => true,
            Start::Introduced(from) => v >= from,
            Start::After(from) => v > from,
        };
        from_start
            && match &self.end {
                End::Open => true,
                End::Fixed(fixed) => v < fixed,
                End::LastAffected(last) => v <= last,
            }
    }

    /// An interval from its stored columns, read by `order`. `None` when both ends are set or
    /// a version does not parse, neither of which the loader writes.
    pub fn from_columns(
        order: VersionOrder,
        introduced: Option<&str>,
        introduced_excluded: bool,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> Option<Self> {
        let start = match (introduced, introduced_excluded) {
            (Some(s), false) => Start::Introduced(order.parse(s)?),
            (Some(s), true) => Start::After(order.parse(s)?),
            // An excluded bound with no version is not a bound. The loader writes neither.
            (None, true) => return None,
            (None, false) => Start::First,
        };
        let end = match (fixed, last_affected) {
            (None, None) => End::Open,
            (Some(s), None) => End::Fixed(order.parse(s)?),
            (None, Some(s)) => End::LastAffected(order.parse(s)?),
            (Some(_), Some(_)) => return None,
        };
        Some(Self { start, end })
    }
}

/// Why a range was not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unstorable {
    /// A range type other than `SEMVER` or `ECOSYSTEM`, such as `GIT`.
    Type(String),
    /// An event naming something other than `introduced`, `fixed` or `last_affected`.
    /// `limit` is one; no npm record carried it on 2026-09-13.
    Event(String),
    /// An event object with other than one key.
    Malformed,
    /// A version the ecosystem's [`VersionOrder`] does not read.
    NotAVersion(String),
}

#[derive(Clone, Copy)]
enum Kind {
    Introduced,
    Fixed,
    LastAffected,
}

/// The intervals a range's events describe, each version [`VersionOrder::normalised`].
pub fn intervals(
    order: VersionOrder,
    kind: Option<&str>,
    events: &[BTreeMap<String, String>],
) -> Result<Vec<Interval<String>>, Unstorable> {
    match kind {
        Some("SEMVER" | "ECOSYSTEM") => {}
        other => return Err(Unstorable::Type(other.unwrap_or_default().to_owned())),
    }

    let mut sorted = Vec::with_capacity(events.len());
    for event in events {
        let [(key, value)] = event.iter().collect::<Vec<_>>()[..] else {
            return Err(Unstorable::Malformed);
        };
        let kind = match key.as_str() {
            "introduced" => Kind::Introduced,
            "fixed" => Kind::Fixed,
            "last_affected" => Kind::LastAffected,
            other => return Err(Unstorable::Event(other.to_owned())),
        };
        // `0` is OSV's "before the first version", and only means that as a lower bound.
        let (at, written) = match (kind, value.as_str()) {
            (Kind::Introduced, "0") => (None, value.clone()),
            _ => {
                let written = order
                    .normalised(value)
                    .ok_or_else(|| Unstorable::NotAVersion(value.clone()))?;
                (order.parse(&written), written)
            }
        };
        sorted.push((at, kind, written));
    }
    // Stable, so events at the same version keep the order the record gave them, which is
    // what the OSV pseudocode does with them.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    let mut open: Option<Option<String>> = None;
    for (at, kind, value) in sorted {
        let written = at.map(|_| value.clone());
        match (kind, open.take()) {
            // An `introduced` inside an open interval changes nothing.
            (Kind::Introduced, Some(from)) => open = Some(from),
            (Kind::Introduced, None) => open = Some(written),
            (Kind::Fixed, Some(from)) => out.push(Interval {
                start: Start::introduced(from),
                end: End::Fixed(value.clone()),
            }),
            (Kind::LastAffected, Some(from)) => out.push(Interval {
                start: Start::introduced(from),
                end: End::LastAffected(value.clone()),
            }),
            // An end with nothing open ends nothing.
            (Kind::Fixed | Kind::LastAffected, None) => {}
        }
    }
    if let Some(from) = open {
        out.push(Interval {
            start: Start::introduced(from),
            end: End::Open,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(pairs: &[(&str, &str)]) -> Vec<BTreeMap<String, String>> {
        pairs
            .iter()
            .map(|(k, v)| [((*k).to_owned(), (*v).to_owned())].into())
            .collect()
    }

    fn sv(s: &str) -> Option<Ordered> {
        VersionOrder::SemVer.parse(s)
    }

    fn semver(pairs: &[(&str, &str)]) -> Vec<Interval<String>> {
        intervals(VersionOrder::SemVer, Some("SEMVER"), &events(pairs)).expect("storable")
    }

    /// `> 4.0.2` says 4.0.2 is the last version not affected. Storing it as an inclusive
    /// `introduced` would refuse the one version the advisory clears.
    #[test]
    fn an_excluded_lower_bound_does_not_cover_its_own_version() {
        let after = parsed(&Interval {
            start: Start::After("4.0.2".to_owned()),
            end: End::Open,
        });
        assert!(!after.contains(&sv("4.0.2").expect("parses")));
        assert!(after.contains(&sv("4.0.3").expect("parses")));
        // A prerelease of the next patch sorts above 4.0.2, so it is affected.
        assert!(after.contains(&sv("4.0.3-alpha").expect("parses")));

        let introduced = parsed(&Interval {
            start: Start::Introduced("4.0.2".to_owned()),
            end: End::Open,
        });
        assert!(introduced.contains(&sv("4.0.2").expect("parses")));
    }

    /// The columns round-trip, so what a load writes is what a lookup reads.
    #[test]
    fn an_excluded_bound_survives_its_columns_and_one_with_no_version_is_refused() {
        let start = Start::After("4.0.2".to_owned());
        assert_eq!(start.columns(), (Some("4.0.2"), true));
        assert_eq!(
            Start::Introduced("4.0.2".to_owned()).columns(),
            (Some("4.0.2"), false)
        );
        assert_eq!(Start::<String>::First.columns(), (None, false));
        assert_eq!(
            Interval::from_columns(VersionOrder::SemVer, Some("4.0.2"), true, None, None)
                .expect("parses")
                .start,
            Start::After(sv("4.0.2").expect("parses"))
        );
        assert_eq!(
            Interval::from_columns(VersionOrder::SemVer, None, true, None, Some("1.0.0")),
            None
        );
    }

    fn parsed(interval: &Interval<String>) -> Interval<Ordered> {
        let (fixed, last) = interval.end.columns();
        let (introduced, excluded) = interval.start.columns();
        Interval::from_columns(VersionOrder::SemVer, introduced, excluded, fixed, last)
            .expect("parses")
    }

    /// Whether any interval of `pairs` holds `v`.
    fn affected(pairs: &[(&str, &str)], v: &str) -> bool {
        let v = sv(v).expect("a test version is SemVer");
        semver(pairs).iter().any(|i| parsed(i).contains(&v))
    }

    #[test]
    fn a_version_is_strict_semver() {
        for not in ["1.0", "v1.0.0", "01.0.0", "2026.04.1.0", "0", ""] {
            assert_eq!(version(not), None, "{not}");
        }
        assert!(version("1.0.0-rc.1").is_some());
    }

    /// Every such version in `npm/all.zip` on 2026-09-13 is a short or zero-padded one, and
    /// none is published: `next` publishes `13.0.0` and `qwc2` `2025.8.14`.
    #[test]
    fn a_short_or_zero_padded_version_is_padded_as_osv_dev_reads_it() {
        for (written, read) in [
            ("13.0", "13.0.0"),
            ("2026.04.1", "2026.4.1"),
            ("20260509.0340.15", "20260509.340.15"),
            ("1", "1.0.0"),
            ("1.0-rc.1+b", "1.0.0-rc.1+b"),
            ("1.2.3", "1.2.3"),
        ] {
            assert_eq!(padded(written).as_deref(), Some(read), "{written}");
        }
        for not in [
            "v1.0.0",
            "1.0.0rc1",
            "1.2.3.4",
            "1..2",
            "",
            "1.0-",
            "99999999999999999999",
        ] {
            assert_eq!(padded(not), None, "{not}");
        }
    }

    #[test]
    fn build_metadata_does_not_order() {
        assert_eq!(version("1.0.0+linux"), version("1.0.0"));
        assert!(affected(
            &[("introduced", "0"), ("last_affected", "1.0.0+a")],
            "1.0.0+b"
        ));
    }

    #[test]
    fn introduced_zero_alone_is_every_version() {
        let only = semver(&[("introduced", "0")]);
        assert_eq!(only.len(), 1);
        assert!(only[0].is_every_version());
        assert!(!semver(&[("introduced", "0"), ("fixed", "1.0.0")])[0].is_every_version());
        assert!(!semver(&[("introduced", "1.0.0")])[0].is_every_version());
    }

    #[test]
    fn fixed_excludes_itself_and_last_affected_includes_itself() {
        let fixed = [("introduced", "1.2.2"), ("fixed", "2.0.0")];
        assert!(!affected(&fixed, "1.2.1"));
        assert!(affected(&fixed, "1.2.2"));
        assert!(affected(&fixed, "1.99.0"));
        assert!(!affected(&fixed, "2.0.0"));

        let last = [("introduced", "1.2.2"), ("last_affected", "2.0.0")];
        assert!(affected(&last, "2.0.0"));
        assert!(!affected(&last, "2.0.1"));
    }

    #[test]
    fn an_introduced_with_no_end_is_everything_from_it() {
        assert!(!affected(&[("introduced", "1.2.2")], "1.2.1"));
        assert!(affected(&[("introduced", "1.2.2")], "99.0.0"));
    }

    #[test]
    fn a_pre_release_orders_below_its_release() {
        let fixed = [("introduced", "1.0.0"), ("fixed", "2.0.0")];
        assert!(affected(&fixed, "2.0.0-beta.1"));
        assert!(!affected(&fixed, "1.0.0-rc.1"));
    }

    #[test]
    fn events_are_sorted_before_they_pair() {
        let written = semver(&[
            ("fixed", "2.0.0"),
            ("introduced", "3.0.0"),
            ("introduced", "0"),
            ("fixed", "4.0.0"),
        ]);
        assert_eq!(
            written,
            vec![
                Interval {
                    start: Start::First,
                    end: End::Fixed("2.0.0".to_owned()),
                },
                Interval {
                    start: Start::Introduced("3.0.0".to_owned()),
                    end: End::Fixed("4.0.0".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn a_second_introduced_inside_an_open_interval_changes_nothing() {
        let written = semver(&[
            ("introduced", "1.0.0"),
            ("introduced", "1.5.0"),
            ("fixed", "2.0.0"),
        ]);
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].start, Start::Introduced("1.0.0".to_owned()));
    }

    #[test]
    fn an_end_with_nothing_open_ends_nothing() {
        assert!(semver(&[("fixed", "1.0.0")]).is_empty());
        assert_eq!(
            semver(&[("introduced", "0"), ("fixed", "1.0.0"), ("fixed", "2.0.0")]).len(),
            1
        );
    }

    #[test]
    fn events_at_one_version_keep_the_order_given() {
        assert!(!affected(
            &[("introduced", "1.0.0"), ("fixed", "1.0.0")],
            "1.0.0"
        ));
        let reopened = [
            ("introduced", "0"),
            ("fixed", "1.0.0"),
            ("introduced", "1.0.0"),
        ];
        assert!(affected(&reopened, "0.9.0"));
        assert!(affected(&reopened, "1.0.0"));
    }

    #[test]
    fn a_range_is_stored_and_ordered_by_its_padded_versions() {
        let written = intervals(
            VersionOrder::SemVer,
            Some("ECOSYSTEM"),
            &events(&[
                ("fixed", "13.1"),
                ("introduced", "13.0"),
                ("introduced", "2026.04.1"),
            ]),
        )
        .expect("storable");
        assert_eq!(
            written,
            vec![
                Interval {
                    start: Start::Introduced("13.0.0".to_owned()),
                    end: End::Fixed("13.1.0".to_owned()),
                },
                Interval {
                    start: Start::Introduced("2026.4.1".to_owned()),
                    end: End::Open,
                },
            ]
        );
        assert!(written.iter().all(|i| {
            let (fixed, last) = i.end.columns();
            let (introduced, excluded) = i.start.columns();
            Interval::from_columns(VersionOrder::SemVer, introduced, excluded, fixed, last)
                .is_some()
        }));
    }

    #[test]
    fn ecosystem_ranges_are_read_and_git_ones_are_not() {
        let e = events(&[("introduced", "1.0.0")]);
        assert!(intervals(VersionOrder::SemVer, Some("ECOSYSTEM"), &e).is_ok());
        assert_eq!(
            intervals(VersionOrder::SemVer, Some("GIT"), &e),
            Err(Unstorable::Type("GIT".to_owned()))
        );
        assert_eq!(
            intervals(VersionOrder::SemVer, None, &e),
            Err(Unstorable::Type(String::new()))
        );
    }

    #[test]
    fn a_range_that_cannot_be_evaluated_is_refused_whole() {
        assert_eq!(
            intervals(
                VersionOrder::SemVer,
                Some("ECOSYSTEM"),
                &events(&[("introduced", "0"), ("fixed", "1.0.0rc1")])
            ),
            Err(Unstorable::NotAVersion("1.0.0rc1".to_owned()))
        );
        assert_eq!(
            intervals(
                VersionOrder::SemVer,
                Some("SEMVER"),
                &events(&[("limit", "1.0.0")])
            ),
            Err(Unstorable::Event("limit".to_owned()))
        );
        assert_eq!(
            intervals(
                VersionOrder::SemVer,
                Some("SEMVER"),
                &events(&[("introduced", "1.0.0"), ("fixed", "v2")])
            ),
            Err(Unstorable::NotAVersion("v2".to_owned()))
        );
        let two_keys: BTreeMap<String, String> = [
            ("introduced".to_owned(), "0".to_owned()),
            ("fixed".to_owned(), "1.0.0".to_owned()),
        ]
        .into();
        assert_eq!(
            intervals(VersionOrder::SemVer, Some("SEMVER"), &[two_keys]),
            Err(Unstorable::Malformed)
        );
        assert_eq!(
            intervals(VersionOrder::SemVer, Some("SEMVER"), &[BTreeMap::new()]),
            Err(Unstorable::Malformed)
        );
    }

    #[test]
    fn stored_columns_that_the_loader_never_writes_do_not_parse() {
        assert_eq!(
            Interval::from_columns(
                VersionOrder::SemVer,
                Some("1.0.0"),
                false,
                Some("2.0.0"),
                Some("2.0.0")
            ),
            None
        );
        assert_eq!(
            Interval::from_columns(VersionOrder::SemVer, Some("1.0"), false, None, None),
            None
        );
        assert_eq!(
            Interval::from_columns(VersionOrder::SemVer, None, false, Some("x"), None),
            None
        );
        assert_eq!(
            Interval::from_columns(VersionOrder::SemVer, None, false, None, Some("x")),
            None
        );
        assert!(
            Interval::from_columns(VersionOrder::SemVer, None, false, None, None)
                .is_some_and(|i| i.is_every_version())
        );
    }

    fn pep440(pairs: &[(&str, &str)]) -> Vec<Interval<String>> {
        intervals(VersionOrder::Pep440, Some("ECOSYSTEM"), &events(pairs)).expect("storable")
    }

    fn pep440_affected(pairs: &[(&str, &str)], v: &str) -> bool {
        let v = VersionOrder::Pep440.parse(v).expect("a PEP 440 version");
        pep440(pairs).iter().any(|i| {
            let (fixed, last) = i.end.columns();
            let (introduced, excluded) = i.start.columns();
            Interval::from_columns(VersionOrder::Pep440, introduced, excluded, fixed, last)
                .expect("parses")
                .contains(&v)
        })
    }

    /// `GHSA-4vc9-4xpq-77vm` has `fixed: 2.6.11-1`, a post-release of 2.6.11. Read as SemVer
    /// it is a pre-release below 2.6.11, and 2.6.11 would be reported unaffected.
    #[test]
    fn a_pypi_range_orders_by_pep_440() {
        let fixed_by_a_post_release = [("introduced", "0"), ("fixed", "2.6.11-1")];
        assert_eq!(
            pep440(&fixed_by_a_post_release),
            vec![Interval {
                start: Start::First,
                end: End::Fixed("2.6.11.post1".to_owned()),
            }]
        );
        assert!(pep440_affected(&fixed_by_a_post_release, "2.6.11"));
        assert!(!pep440_affected(&fixed_by_a_post_release, "2.6.11.post1"));

        let fixed_by_a_release = [("introduced", "1.0rc1"), ("fixed", "1.0")];
        assert!(pep440_affected(&fixed_by_a_release, "1.0rc2"));
        assert!(pep440_affected(&fixed_by_a_release, "1.0.0rc1"));
        assert!(!pep440_affected(&fixed_by_a_release, "1.0.0"));
        assert!(!pep440_affected(&fixed_by_a_release, "1.0b9"));

        assert_eq!(
            intervals(
                VersionOrder::Pep440,
                Some("ECOSYSTEM"),
                &events(&[("introduced", "not a version")])
            ),
            Err(Unstorable::NotAVersion("not a version".to_owned()))
        );
    }

    #[test]
    fn each_ecosystem_has_its_own_order() {
        assert_eq!(VersionOrder::of("npm"), Some(VersionOrder::SemVer));
        assert_eq!(VersionOrder::of("pypi"), Some(VersionOrder::Pep440));
        assert_eq!(VersionOrder::of("cargo"), None);
        assert_eq!(stored(VersionOrder::Pep440, "1.0-1"), "1.0.post1");
        assert_eq!(stored(VersionOrder::SemVer, "13.0"), "13.0.0");
        assert_eq!(
            stored(VersionOrder::Pep440, "not a version"),
            "not a version"
        );
    }
}
