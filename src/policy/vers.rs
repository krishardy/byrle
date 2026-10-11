//! The versions a selector or a denial covers: one exact version, or a VERS range, held as a
//! sorted union of disjoint intervals so containment is decided rather than estimated. See
//! docs/engineering_decisions/policy-version-ranges.md.

use std::cmp::Ordering;
use std::fmt;

use crate::intel::range::{End, Interval, Ordered, Start, VersionOrder};

/// A set of versions, and how the policy wrote it.
#[derive(Debug, Clone)]
pub struct Versions {
    /// Sorted, disjoint and never touching, so one set has one representation.
    spans: Vec<Interval<Ordered>>,
    written: String,
}

/// Two sets are equal when they hold the same versions, however each was written.
impl PartialEq for Versions {
    fn eq(&self, other: &Self) -> bool {
        self.spans == other.spans
    }
}

impl Eq for Versions {}

impl fmt::Display for Versions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.written)
    }
}

/// Why a version or a range was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersError {
    pub written: String,
    pub reason: String,
}

impl fmt::Display for VersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` {}", self.written, self.reason)
    }
}

impl std::error::Error for VersError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparator {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl Comparator {
    /// Longer comparators first, so `<=` is not read as `<` followed by `=1.0`.
    const WRITTEN: [(&str, Comparator); 5] = [
        (">=", Self::GreaterOrEqual),
        ("<=", Self::LessOrEqual),
        ("!=", Self::NotEqual),
        ("<", Self::Less),
        (">", Self::Greater),
    ];

    fn is_lower(self) -> bool {
        matches!(self, Self::Greater | Self::GreaterOrEqual)
    }

    fn is_upper(self) -> bool {
        matches!(self, Self::Less | Self::LessOrEqual)
    }
}

/// Characters a version has to percent-encode, by Clause 5.3.3.2.
const ENCODED: [char; 6] = ['>', '<', '=', '!', '*', '|'];

impl Versions {
    /// One exact version, read by `order`.
    pub fn exact(order: VersionOrder, ecosystem: &str, written: &str) -> Result<Self, VersError> {
        let version = order.parse(written).ok_or_else(|| VersError {
            written: written.to_owned(),
            reason: format!("is not a version {ecosystem} publishes"),
        })?;
        Ok(Self {
            spans: vec![point(version)],
            written: written.to_owned(),
        })
    }

    /// A VERS string whose type is `ecosystem`, read by `order`.
    pub fn vers(order: VersionOrder, ecosystem: &str, written: &str) -> Result<Self, VersError> {
        let refuse = |reason: String| VersError {
            written: written.to_owned(),
            reason,
        };
        if written.chars().any(|c| c.is_ascii_whitespace()) {
            return Err(refuse(
                "contains whitespace, which VERS does not allow".into(),
            ));
        }
        let rest = written
            .strip_prefix("vers:")
            .ok_or_else(|| refuse("does not start with `vers:`".into()))?;
        let (kind, constraints) = rest
            .split_once('/')
            .ok_or_else(|| refuse("has no `/` between its type and its constraints".into()))?;
        if kind != ecosystem {
            return Err(refuse(format!(
                "is a `{kind}` range, and the entry is for `{ecosystem}`"
            )));
        }
        if constraints.is_empty() {
            return Err(refuse("has no constraints".into()));
        }
        if constraints == "*" {
            return Ok(Self {
                spans: vec![Interval {
                    start: Start::First,
                    end: End::Open,
                }],
                written: written.to_owned(),
            });
        }

        let mut read = Vec::new();
        for constraint in constraints.split('|') {
            read.push(self::constraint(order, ecosystem, constraint).map_err(refuse)?);
        }
        in_order(&read).map_err(refuse)?;
        Ok(Self {
            spans: spans(&read),
            written: written.to_owned(),
        })
    }

    /// Whether `version` is in the set.
    pub fn contains(&self, version: &Ordered) -> bool {
        self.spans.iter().any(|span| span.contains(version))
    }

    /// Whether every version in this set is in `other`.
    pub fn contained_by(&self, other: &Self) -> bool {
        self.spans
            .iter()
            .all(|a| other.spans.iter().any(|b| within(a, b)))
    }

    /// Whether some version is in both.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.spans.iter().any(|a| {
            other.spans.iter().any(|b| {
                nonempty(
                    lower(&a.start).max(lower(&b.start)),
                    upper(&a.end).min(upper(&b.end)),
                )
            })
        })
    }
}

/// A constraint as [`constraint`] reads it: comparator, version, and the version as written.
type Constraint = (Comparator, Ordered, String);

/// Whether `read` is sorted, names no version twice, and alternates its bounds. `Err` is the
/// reason it does not.
fn in_order(read: &[Constraint]) -> Result<(), String> {
    for pair in read.windows(2) {
        match pair[0].1.cmp(&pair[1].1) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(format!(
                    "names one version twice, `{}` and `{}`",
                    pair[0].2, pair[1].2
                ));
            }
            Ordering::Greater => {
                return Err(format!(
                    "is not sorted: `{}` comes before `{}`",
                    pair[0].2, pair[1].2
                ));
            }
        }
    }
    let bounds: Vec<&Constraint> = read
        .iter()
        .filter(|(comparator, _, _)| *comparator != Comparator::NotEqual)
        .collect();
    for pair in bounds.windows(2) {
        let (current, next) = (pair[0].0, pair[1].0);
        let follows = if current.is_lower() {
            next.is_upper()
        } else {
            next == Comparator::Equal || next.is_lower()
        };
        if !follows {
            return Err(format!(
                "puts `{}` after `{}`. Leaving out `!=`, a bare version or `<`/`<=` is \
                 followed by a version or `>`/`>=`, and `>`/`>=` by `<`/`<=`",
                pair[1].2, pair[0].2
            ));
        }
    }
    Ok(())
}

/// The versions `read` names, which [`in_order`] has accepted.
fn spans(read: &[Constraint]) -> Vec<Interval<Ordered>> {
    let mut spans = Vec::new();
    let mut open: Option<Start<Ordered>> = None;
    for (comparator, version, _) in read {
        let version = version.clone();
        match comparator {
            Comparator::Equal => spans.push(point(version)),
            Comparator::Greater => open = Some(Start::After(version)),
            Comparator::GreaterOrEqual => open = Some(Start::Introduced(version)),
            Comparator::Less | Comparator::LessOrEqual => spans.push(Interval {
                start: open.take().unwrap_or(Start::First),
                end: if *comparator == Comparator::Less {
                    End::Fixed(version)
                } else {
                    End::LastAffected(version)
                },
            }),
            Comparator::NotEqual => {}
        }
    }
    if let Some(start) = open {
        spans.push(Interval {
            start,
            end: End::Open,
        });
    }
    if read
        .iter()
        .all(|(comparator, _, _)| *comparator == Comparator::NotEqual)
    {
        spans.push(Interval {
            start: Start::First,
            end: End::Open,
        });
    }
    for (comparator, version, _) in read {
        if *comparator == Comparator::NotEqual {
            spans = without(spans, version);
        }
    }
    spans
}

/// One constraint: its comparator, its version as ordered, and the constraint as written.
fn constraint(order: VersionOrder, ecosystem: &str, written: &str) -> Result<Constraint, String> {
    if written.is_empty() {
        return Err("has an empty constraint, from a leading, trailing or doubled `|`".into());
    }
    if written.starts_with('=') {
        return Err(format!(
            "writes `{written}`. Equality is a bare version, with no `=`"
        ));
    }
    let (comparator, version) = Comparator::WRITTEN
        .iter()
        .find_map(|(prefix, comparator)| {
            written
                .strip_prefix(prefix)
                .map(|version| (*comparator, version))
        })
        .unwrap_or((Comparator::Equal, written));
    if version.is_empty() {
        return Err(format!("has `{written}`, a comparator with no version"));
    }
    if version.contains(ENCODED) {
        return Err(format!(
            "has `{written}`. `*` is a constraint on its own, and `> < = ! * |` inside a \
             version are percent-encoded"
        ));
    }
    let decoded = percent_decoded(version)
        .ok_or_else(|| format!("has `{version}`, whose `%` does not start a percent-encoding"))?;
    let ordered = order
        .parse(&decoded)
        .ok_or_else(|| format!("has `{decoded}`, which is not a version {ecosystem} publishes"))?;
    Ok((comparator, ordered, written.to_owned()))
}

/// `version` with each `%XX` decoded once, or `None` when a `%` is not followed by two hex
/// digits or the result is not UTF-8.
fn percent_decoded(version: &str) -> Option<String> {
    let bytes = version.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn point(version: Ordered) -> Interval<Ordered> {
    Interval {
        start: Start::Introduced(version.clone()),
        end: End::LastAffected(version),
    }
}

/// Where an interval starts, ordered: `None` is below every version, `true` excludes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Lower<'a>(Option<(&'a Ordered, bool)>);

/// Where an interval stops: `None` is above every version, and `true` includes the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Upper<'a>(Option<(&'a Ordered, bool)>);

impl PartialOrd for Upper<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Upper<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.0, other.0) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(&b),
        }
    }
}

fn lower(start: &Start<Ordered>) -> Lower<'_> {
    Lower(match start {
        Start::First => None,
        Start::Introduced(v) => Some((v, false)),
        Start::After(v) => Some((v, true)),
    })
}

fn upper(end: &End<Ordered>) -> Upper<'_> {
    Upper(match end {
        End::Open => None,
        End::Fixed(v) => Some((v, false)),
        End::LastAffected(v) => Some((v, true)),
    })
}

/// Whether some version lies from `from` up to `to`.
fn nonempty(from: Lower<'_>, to: Upper<'_>) -> bool {
    match (from.0, to.0) {
        (None, _) | (_, None) => true,
        (Some((a, excluded)), Some((b, included))) => a < b || (a == b && !excluded && included),
    }
}

/// Whether every version in `a` is in `b`.
fn within(a: &Interval<Ordered>, b: &Interval<Ordered>) -> bool {
    lower(&a.start) >= lower(&b.start) && upper(&a.end) <= upper(&b.end)
}

/// `spans` without `version`.
fn without(spans: Vec<Interval<Ordered>>, version: &Ordered) -> Vec<Interval<Ordered>> {
    let mut out = Vec::with_capacity(spans.len() + 1);
    for span in spans {
        if !span.contains(version) {
            out.push(span);
            continue;
        }
        let below = Interval {
            start: span.start,
            end: End::Fixed(version.clone()),
        };
        let above = Interval {
            start: Start::After(version.clone()),
            end: span.end,
        };
        out.extend(
            [below, above]
                .into_iter()
                .filter(|s| nonempty(lower(&s.start), upper(&s.end))),
        );
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn npm(written: &str) -> Result<Versions, VersError> {
        Versions::vers(VersionOrder::SemVer, "npm", written)
    }

    fn pypi(written: &str) -> Result<Versions, VersError> {
        Versions::vers(VersionOrder::Pep440, "pypi", written)
    }

    fn set(written: &str) -> Versions {
        npm(written).unwrap_or_else(|e| panic!("{e}"))
    }

    fn holds(versions: &Versions, version: &str) -> bool {
        versions.contains(&VersionOrder::SemVer.parse(version).expect("a test version"))
    }

    fn reason(result: Result<Versions, VersError>) -> String {
        result.expect_err("refused").reason
    }

    #[test]
    fn each_constraint_is_its_segment() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("vers:npm/*", &["0.0.1", "99.0.0"], &[]),
            ("vers:npm/1.2.3", &["1.2.3"], &["1.2.4", "1.2.2"]),
            (
                "vers:npm/<2.0.0",
                &["1.9.9", "2.0.0-rc.1"],
                &["2.0.0", "3.0.0"],
            ),
            ("vers:npm/<=2.0.0", &["2.0.0"], &["2.0.1"]),
            ("vers:npm/>1.0.0", &["1.0.1"], &["1.0.0"]),
            ("vers:npm/>=1.0.0", &["1.0.0", "9.0.0"], &["0.9.0"]),
            ("vers:npm/!=1.0.0", &["0.9.0", "1.0.1"], &["1.0.0"]),
            (
                "vers:npm/1.2.3|>=2.0.0|<5.0.0",
                &["1.2.3", "2.0.0", "4.9.9"],
                &["1.2.4", "5.0.0"],
            ),
            (
                "vers:npm/<1.4.1|>=2.0.0|<2.17.2",
                &["1.4.0", "2.17.1"],
                &["1.4.1", "1.9.0", "2.17.2"],
            ),
            (
                "vers:npm/>=2.0.0|!=2.2.1|<3.0.0",
                &["2.2.0", "2.2.2"],
                &["2.2.1", "3.0.0"],
            ),
        ];
        for (written, inside, outside) in cases {
            let versions = set(written);
            for v in *inside {
                assert!(holds(&versions, v), "{written} holds {v}");
            }
            for v in *outside {
                assert!(!holds(&versions, v), "{written} does not hold {v}");
            }
        }
    }

    #[test]
    fn a_pypi_range_is_ordered_by_pep_440() {
        let versions = pypi("vers:pypi/>=1.0rc1|<1.0.post1").expect("valid");
        let v = |s| VersionOrder::Pep440.parse(s).expect("a test version");
        assert!(versions.contains(&v("1.0")));
        assert!(versions.contains(&v("1.0.0")));
        assert!(versions.contains(&v("1.0rc2")));
        assert!(!versions.contains(&v("1.0b1")));
        assert!(!versions.contains(&v("1.0-1")));
    }

    #[test]
    fn a_vers_string_that_breaks_the_specification_is_refused() {
        for (written, expected) in [
            ("vers:npm/ >=1.0.0", "whitespace"),
            ("npm/>=1.0.0", "does not start with `vers:`"),
            ("vers:npm", "no `/`"),
            (
                "vers:pypi/>=1.0.0",
                "is a `pypi` range, and the entry is for `npm`",
            ),
            ("vers:npm/", "has no constraints"),
            ("vers:npm/|1.0.0", "empty constraint"),
            ("vers:npm/1.0.0|", "empty constraint"),
            ("vers:npm/1.0.0||2.0.0", "empty constraint"),
            ("vers:npm/=1.0.0", "Equality is a bare version"),
            ("vers:npm/>=", "a comparator with no version"),
            ("vers:npm/*|1.0.0", "percent-encoded"),
            ("vers:npm/>=1.0.0|<*", "percent-encoded"),
            ("vers:npm/1.0.0%2", "does not start a percent-encoding"),
            ("vers:npm/1.0.0%zz", "does not start a percent-encoding"),
            ("vers:npm/1.0.0%ff", "does not start a percent-encoding"),
            ("vers:npm/1.0", "not a version npm publishes"),
            ("vers:npm/2.0.0|1.0.0", "is not sorted"),
            ("vers:npm/1.0.0|>=1.0.0", "names one version twice"),
            ("vers:npm/>=1.0.0|>=2.0.0", "puts `>=2.0.0` after `>=1.0.0`"),
            ("vers:npm/<1.0.0|<2.0.0", "puts `<2.0.0` after `<1.0.0`"),
            ("vers:npm/>=1.0.0|2.0.0", "puts `2.0.0` after `>=1.0.0`"),
            ("vers:npm/1.0.0|<2.0.0", "puts `<2.0.0` after `1.0.0`"),
        ] {
            let reason = reason(npm(written));
            assert!(reason.contains(expected), "{written}: {reason}");
        }
        assert!(
            reason(pypi("vers:pypi/>=3.0.0|2.0.3")).contains("is not sorted"),
            "the registered pypi examples break Clause 5.4's sorting rule"
        );
    }

    /// `!=` may sit anywhere, and a percent-encoded version is decoded once.
    #[test]
    fn a_vers_string_the_specification_allows_is_read() {
        for written in [
            "vers:npm/!=1.0.0|>=2.0.0",
            "vers:npm/>=1.0.0|!=1.5.0|<2.0.0|!=3.0.0",
            "vers:npm/1.0.0|2.0.0|>=3.0.0",
            "vers:npm/<1.0.0|1.5.0|>=2.0.0",
        ] {
            assert!(npm(written).is_ok(), "{written}");
        }
        assert!(holds(&set("vers:npm/%31.0.0"), "1.0.0"));
    }

    #[test]
    fn an_exact_version_equals_its_vers_string_and_each_displays_as_written() {
        assert_eq!(
            set("vers:npm/1.0.0"),
            Versions::exact(VersionOrder::SemVer, "npm", "1.0.0").expect("a version")
        );
        assert_ne!(set("vers:npm/<2.0.0"), set("vers:npm/<=2.0.0"));
        assert_ne!(
            set("vers:npm/>=1.0.0|!=1.5.0|<2.0.0"),
            set("vers:npm/>=1.0.0|<2.0.0")
        );
        assert_eq!(set("vers:npm/<=2.0.0").to_string(), "vers:npm/<=2.0.0");
        let exact = Versions::exact(VersionOrder::Pep440, "pypi", "1.0").expect("a version");
        assert_eq!(
            exact,
            Versions::exact(VersionOrder::Pep440, "pypi", "1.0.0").expect("a version")
        );
        assert_eq!(exact.to_string(), "1.0");
        assert!(
            Versions::exact(VersionOrder::SemVer, "npm", "1.0")
                .expect_err("not SemVer")
                .to_string()
                .contains("is not a version npm publishes")
        );
    }

    #[test]
    fn containment_is_decided_on_the_intervals() {
        let contained = [
            ("vers:npm/>=1.2.0|<1.3.0", "vers:npm/>=1.0.0|<2.0.0"),
            ("vers:npm/1.5.0", "vers:npm/>=1.0.0|<2.0.0"),
            ("vers:npm/>=1.0.0|<2.0.0", "vers:npm/*"),
            ("vers:npm/>1.0.0|<2.0.0", "vers:npm/>=1.0.0|<2.0.0"),
            ("vers:npm/>=1.0.0|<2.0.0", "vers:npm/>=1.0.0|<=2.0.0"),
            ("vers:npm/>=1.0.0|!=1.5.0|<2.0.0", "vers:npm/>=1.0.0|<2.0.0"),
            ("vers:npm/>=1.0.0|<1.5.0", "vers:npm/>=1.0.0|!=1.5.0|<2.0.0"),
            ("vers:npm/<1.0.0|>=2.0.0", "vers:npm/!=1.5.0"),
        ];
        for (a, b) in contained {
            assert!(set(a).contained_by(&set(b)), "{a} inside {b}");
            assert!(set(a).overlaps(&set(b)), "{a} overlaps {b}");
        }
        let not_contained = [
            ("vers:npm/>=1.0.0|<2.0.0", "vers:npm/>=1.2.0|<1.3.0"),
            ("vers:npm/>=1.0.0|<=2.0.0", "vers:npm/>=1.0.0|<2.0.0"),
            ("vers:npm/>=1.0.0|<2.0.0", "vers:npm/>=1.0.0|!=1.5.0|<2.0.0"),
            ("vers:npm/*", "vers:npm/<1.0.0|>=2.0.0"),
        ];
        for (a, b) in not_contained {
            assert!(!set(a).contained_by(&set(b)), "{a} not inside {b}");
        }
        let disjoint = [
            ("vers:npm/<1.0.0", "vers:npm/>=1.0.0"),
            ("vers:npm/<=1.0.0", "vers:npm/>1.0.0"),
            ("vers:npm/1.5.0", "vers:npm/>=1.0.0|!=1.5.0|<2.0.0"),
            ("vers:npm/>=1.0.0|<2.0.0", "vers:npm/>=3.0.0"),
        ];
        for (a, b) in disjoint {
            assert!(!set(a).overlaps(&set(b)), "{a} and {b} share nothing");
            assert!(!set(b).overlaps(&set(a)), "{b} and {a} share nothing");
        }
        assert!(set("vers:npm/<=1.0.0").overlaps(&set("vers:npm/>=1.0.0")));
    }

    /// A `%` needs two hex digits after it, and what they decode to has to be UTF-8.
    #[test]
    fn a_percent_escape_is_decoded_once() {
        assert_eq!(percent_decoded("1.0.0%2Bb").as_deref(), Some("1.0.0+b"));
        assert_eq!(percent_decoded("1.0%"), None, "no digits");
        assert_eq!(percent_decoded("1%a\u{e9}"), None, "split character");
        assert_eq!(percent_decoded("1%zz"), None, "not hex");
        assert_eq!(percent_decoded("%ff"), None, "not UTF-8");
    }
}
