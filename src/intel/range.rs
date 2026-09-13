//! OSV version ranges, for npm.
//!
//! An OSV range is a list of events: `introduced`, `fixed` (the first version not affected)
//! and `last_affected` (the last one affected). Sorted by version, each `introduced` opens an
//! interval and the next `fixed` or `last_affected` closes it. An interval left open at the
//! end has no upper bound. This is the evaluation in the OSV schema's pseudocode, done once at
//! load so the store holds intervals rather than events.
//!
//! npm ranges are `SEMVER` or `ECOSYSTEM`, and both order by SemVer 2.0. A version is parsed
//! strictly. Measured over `npm/all.zip` fetched 2026-09-13, the 31 `ECOSYSTEM` ranges all
//! hold versions such as `13.0` and `2026.04.1` that are not SemVer, and a range holding one
//! is not stored rather than guessed at.
//!
//! SemVer 2.0 gives build metadata no precedence and the `semver` crate compares it, so it
//! is removed before any comparison. Pre-releases order below their release, so
//! `2.0.0-beta.1` is inside `introduced: 1.0.0, fixed: 2.0.0`.

use semver::{BuildMetadata, Version};
use std::collections::BTreeMap;

/// A version as SemVer 2.0 orders it, or `None` when it is not SemVer.
pub fn version(s: &str) -> Option<Version> {
    let mut v = Version::parse(s).ok()?;
    v.build = BuildMetadata::EMPTY;
    Some(v)
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

/// One run of affected versions. `V` is `String` as stored and [`Version`] as compared.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Interval<V> {
    /// `None` is from the first version.
    pub introduced: Option<V>,
    pub end: End<V>,
}

impl<V> Interval<V> {
    /// No lower bound and no upper one.
    pub fn is_every_version(&self) -> bool {
        self.introduced.is_none() && matches!(self.end, End::Open)
    }
}

impl Interval<Version> {
    pub fn contains(&self, v: &Version) -> bool {
        self.introduced.as_ref().is_none_or(|from| v >= from)
            && match &self.end {
                End::Open => true,
                End::Fixed(fixed) => v < fixed,
                End::LastAffected(last) => v <= last,
            }
    }

    /// An interval from its stored columns. `None` when both ends are set or a version does
    /// not parse, neither of which the loader writes.
    pub fn from_columns(
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> Option<Self> {
        let introduced = match introduced {
            Some(s) => Some(version(s)?),
            None => None,
        };
        let end = match (fixed, last_affected) {
            (None, None) => End::Open,
            (Some(s), None) => End::Fixed(version(s)?),
            (None, Some(s)) => End::LastAffected(version(s)?),
            (Some(_), Some(_)) => return None,
        };
        Some(Self { introduced, end })
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
    /// A version that is not SemVer 2.0.
    NotSemver(String),
}

#[derive(Clone, Copy)]
enum Kind {
    Introduced,
    Fixed,
    LastAffected,
}

/// The intervals a range's events describe, versions kept as written.
pub fn intervals(
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
        let at = match (kind, value.as_str()) {
            (Kind::Introduced, "0") => None,
            _ => Some(version(value).ok_or_else(|| Unstorable::NotSemver(value.clone()))?),
        };
        sorted.push((at, kind, value));
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
                introduced: from,
                end: End::Fixed(value.clone()),
            }),
            (Kind::LastAffected, Some(from)) => out.push(Interval {
                introduced: from,
                end: End::LastAffected(value.clone()),
            }),
            // An end with nothing open ends nothing.
            (Kind::Fixed | Kind::LastAffected, None) => {}
        }
    }
    if let Some(from) = open {
        out.push(Interval {
            introduced: from,
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

    fn semver(pairs: &[(&str, &str)]) -> Vec<Interval<String>> {
        intervals(Some("SEMVER"), &events(pairs)).expect("storable")
    }

    fn parsed(interval: &Interval<String>) -> Interval<Version> {
        let (fixed, last) = interval.end.columns();
        Interval::from_columns(interval.introduced.as_deref(), fixed, last).expect("parses")
    }

    /// Whether any interval of `pairs` holds `v`.
    fn affected(pairs: &[(&str, &str)], v: &str) -> bool {
        let v = version(v).expect("a test version is SemVer");
        semver(pairs).iter().any(|i| parsed(i).contains(&v))
    }

    #[test]
    fn a_version_is_strict_semver() {
        for not in ["1.0", "v1.0.0", "01.0.0", "2026.04.1.0", "0", ""] {
            assert_eq!(version(not), None, "{not}");
        }
        assert!(version("1.0.0-rc.1").is_some());
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
                    introduced: None,
                    end: End::Fixed("2.0.0".to_owned()),
                },
                Interval {
                    introduced: Some("3.0.0".to_owned()),
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
        assert_eq!(written[0].introduced.as_deref(), Some("1.0.0"));
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
    fn ecosystem_ranges_are_read_and_git_ones_are_not() {
        let e = events(&[("introduced", "1.0.0")]);
        assert!(intervals(Some("ECOSYSTEM"), &e).is_ok());
        assert_eq!(
            intervals(Some("GIT"), &e),
            Err(Unstorable::Type("GIT".to_owned()))
        );
        assert_eq!(intervals(None, &e), Err(Unstorable::Type(String::new())));
    }

    #[test]
    fn a_range_that_cannot_be_evaluated_is_refused_whole() {
        assert_eq!(
            intervals(
                Some("ECOSYSTEM"),
                &events(&[("introduced", "0"), ("fixed", "13.0")])
            ),
            Err(Unstorable::NotSemver("13.0".to_owned()))
        );
        assert_eq!(
            intervals(Some("SEMVER"), &events(&[("limit", "1.0.0")])),
            Err(Unstorable::Event("limit".to_owned()))
        );
        assert_eq!(
            intervals(Some("SEMVER"), &events(&[("fixed", "0")])),
            Err(Unstorable::NotSemver("0".to_owned()))
        );
        let two_keys: BTreeMap<String, String> = [
            ("introduced".to_owned(), "0".to_owned()),
            ("fixed".to_owned(), "1.0.0".to_owned()),
        ]
        .into();
        assert_eq!(
            intervals(Some("SEMVER"), &[two_keys]),
            Err(Unstorable::Malformed)
        );
        assert_eq!(
            intervals(Some("SEMVER"), &[BTreeMap::new()]),
            Err(Unstorable::Malformed)
        );
    }

    #[test]
    fn stored_columns_that_the_loader_never_writes_do_not_parse() {
        assert_eq!(
            Interval::from_columns(Some("1.0.0"), Some("2.0.0"), Some("2.0.0")),
            None
        );
        assert_eq!(Interval::from_columns(Some("1.0"), None, None), None);
        assert_eq!(Interval::from_columns(None, Some("x"), None), None);
        assert_eq!(Interval::from_columns(None, None, Some("x")), None);
        assert!(Interval::from_columns(None, None, None).is_some_and(|i| i.is_every_version()));
    }
}
