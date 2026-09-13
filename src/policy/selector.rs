//! What a `packages` selector matches, and which of two selectors is more specific.
//!
//! §5.5 resolves overlapping entries by **strict subset containment**, not a heuristic
//! score: A is more specific than B when the set of packages A matches is a strict subset
//! of B's. That is decidable only because the predicate vocabulary is closed, which is the
//! payoff §5.5 claims for a hand-rolled engine over an open expression language.
//!
//! # Keeping the vocabulary closed
//!
//! A selector accepting arbitrary version ranges or arbitrary glob syntax would reopen
//! exactly what that claim depends on: nobody can decide whether `^1.2` contains `>=1.0,
//! <2` without range algebra, and the answer for `a*` against `*b` needs a matcher. So
//! both are restricted at load rather than admitted and then compared by guesswork:
//!
//! - a name is `*`, `prefix*`, or a literal. A `*` anywhere else is refused.
//! - a version is an exact version or absent. A range is refused.
//!
//! Admitting them and reporting "incomparable" would be worse than refusing them: the
//! load-time check for overlapping entries could no longer fire either, so the policy
//! would carry pairs nobody can reason about and nothing would say so.
//!
//! # `purl` and `name` say the same thing
//!
//! `purl: "pkg:npm/chalk@5.6.2"` and `{name: chalk, version: "5.6.2"}` denote one set
//! through different fields. Compared field by field they would come out incomparable
//! while being identical, so every selector is canonicalised first and containment is
//! decided on that. A selector setting both is refused: agreeing is redundant and
//! disagreeing is a contradiction, and resolving it silently would pick one for reasons
//! the operator never sees.

use super::Selector;
use std::fmt;

/// Which package names a selector covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamePattern {
    /// `*`: every name in the ecosystem.
    Any,
    /// `prefix*`: every name starting with it. `@mycompany/*` is the case §5.5 names.
    Prefix(String),
    /// One name.
    Exact(String),
}

impl NamePattern {
    /// Whether every name this covers is also covered by `other`.
    fn contained_by(&self, other: &Self) -> bool {
        match (self, other) {
            (_, Self::Any) => true,
            (Self::Any, _) => false,
            (Self::Prefix(a), Self::Prefix(b)) => a.starts_with(b.as_str()),
            (Self::Exact(a), Self::Prefix(b)) => a.starts_with(b.as_str()),
            (Self::Exact(a), Self::Exact(b)) => a == b,
            // A prefix covers names an exact name does not, unless the prefix is empty,
            // which is `Any` and handled above.
            (Self::Prefix(_), Self::Exact(_)) => false,
        }
    }

    /// Whether one name is covered.
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Prefix(p) => name.starts_with(p.as_str()),
            Self::Exact(n) => n == name,
        }
    }

    /// Whether some name is covered by both.
    fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Prefix(a), Self::Prefix(b)) => a.starts_with(b.as_str()) || b.starts_with(a),
            (Self::Exact(a), Self::Prefix(b)) | (Self::Prefix(b), Self::Exact(a)) => {
                a.starts_with(b.as_str())
            }
            (Self::Exact(a), Self::Exact(b)) => a == b,
        }
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Prefix(p) => write!(f, "{p}*"),
            Self::Exact(n) => f.write_str(n),
        }
    }
}

/// A selector reduced to the four things containment is decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    pub ecosystem: String,
    pub name: NamePattern,
    /// An exact version, or every version.
    pub version: Option<String>,
    /// A predicate narrows a selector to the packages it holds for.
    pub has_install_scripts: Option<bool>,
}

/// Why a selector could not be canonicalised.
#[derive(Debug, PartialEq)]
pub enum SelectorError {
    BothPurlAndName,
    InteriorWildcard(String),
    VersionRange(String),
    UnreadablePurl { purl: String, reason: String },
    PurlEcosystemDiffers { purl: String, ecosystem: String },
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothPurlAndName => f.write_str(
                "a selector sets both `purl` and `name`. They say the same thing, so one \
                 of them is redundant and the other is a contradiction, and which one \
                 cannot be guessed",
            ),
            Self::InteriorWildcard(p) => write!(
                f,
                "`{p}` puts `*` somewhere other than the end. A name is `*`, `prefix*`, \
                 or a literal: the vocabulary is kept closed so that which of two \
                 selectors is more specific can be decided rather than estimated"
            ),
            Self::VersionRange(v) => write!(
                f,
                "`{v}` is a version range, and a selector takes an exact version or none. \
                 Deciding whether one range contains another needs range algebra, and a \
                 policy carrying pairs nobody can compare is one the overlap check cannot \
                 report on"
            ),
            Self::UnreadablePurl { purl, reason } => {
                write!(f, "`{purl}` is not a readable purl: {reason}")
            }
            Self::PurlEcosystemDiffers { purl, ecosystem } => write!(
                f,
                "`{purl}` is not a `{ecosystem}` package, but the selector says \
                 `ecosystem: {ecosystem}`"
            ),
        }
    }
}

impl std::error::Error for SelectorError {}

/// Operators that make a version string a range rather than one version.
const RANGE_OPERATORS: [char; 9] = ['^', '~', '>', '<', '=', '*', '|', ',', ' '];

/// Whether a version string names more than one version.
///
/// Two shapes, because the operators alone do not catch all of them: `1.x` is a range
/// written without one. A wildcard is a whole component of the release part, so
/// `1.0.0-x` stays an exact version with a prerelease tag of `x`, which is a real thing
/// to publish.
///
/// This is deliberately a little eager. Refusing a version that turns out to be exact
/// costs an operator one clear error; admitting a range costs the overlap check its
/// ability to report anything about that entry.
fn looks_like_a_range(version: &str) -> bool {
    if version.contains(RANGE_OPERATORS) {
        return true;
    }
    let release = version.split(['-', '+']).next().unwrap_or(version);
    release
        .split('.')
        .any(|component| matches!(component, "x" | "X"))
}

impl Canonical {
    /// Reduce a written selector to what containment is decided on.
    pub fn of(selector: &Selector) -> Result<Self, SelectorError> {
        if selector.purl.is_some() && selector.name.is_some() {
            return Err(SelectorError::BothPurlAndName);
        }

        let (name, version) = match &selector.purl {
            Some(purl) => {
                let (kind, name, version) = decompose(purl)?;
                if kind != selector.ecosystem {
                    return Err(SelectorError::PurlEcosystemDiffers {
                        purl: purl.clone(),
                        ecosystem: selector.ecosystem.clone(),
                    });
                }
                (
                    NamePattern::Exact(name),
                    version.or_else(|| selector.version.clone()),
                )
            }
            None => (
                pattern_of(selector.name.as_deref())?,
                selector.version.clone(),
            ),
        };

        if let Some(version) = &version
            && looks_like_a_range(version)
        {
            return Err(SelectorError::VersionRange(version.clone()));
        }

        Ok(Self {
            ecosystem: selector.ecosystem.clone(),
            name,
            version,
            has_install_scripts: selector.has_install_scripts,
        })
    }

    /// Whether every package this matches is also matched by `other`.
    ///
    /// Per dimension, all of them: a selector is narrower only if it is narrower or equal
    /// everywhere. Narrower in one dimension and wider in another is neither, which is
    /// §5.5's incomparable case.
    pub fn contained_by(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem
            && self.name.contained_by(&other.name)
            && contained(self.version.as_ref(), other.version.as_ref())
            && contained(
                self.has_install_scripts.as_ref(),
                other.has_install_scripts.as_ref(),
            )
    }

    /// Whether some package matches both.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem
            && self.name.overlaps(&other.name)
            && intersects(self.version.as_ref(), other.version.as_ref())
            && intersects(
                self.has_install_scripts.as_ref(),
                other.has_install_scripts.as_ref(),
            )
    }

    /// Whether one specific package is in the set this selector names.
    ///
    /// Containment asks how two selectors relate; this asks whether a package is in one
    /// of them. Both read the same four dimensions, so a selector cannot match a package
    /// one way here and be ordered another way there.
    pub fn matches(&self, ecosystem: &str, name: &str, version: &str, scripts: bool) -> bool {
        self.ecosystem == ecosystem
            && self.name.matches(name)
            && self.version.as_deref().is_none_or(|v| v == version)
            && self.has_install_scripts.is_none_or(|s| s == scripts)
    }

    /// Whether this matches strictly fewer packages than `other`.
    pub fn strictly_contained_by(&self, other: &Self) -> bool {
        self.contained_by(other) && !other.contained_by(self)
    }
}

/// A dimension that is set is narrower than one that is not; two that are set agree or
/// neither contains the other.
fn contained<T: PartialEq>(value: Option<&T>, other: Option<&T>) -> bool {
    match (value, other) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => a == b,
    }
}

/// Two dimensions share a package when either is unset or both name the same thing.
fn intersects<T: PartialEq>(value: Option<&T>, other: Option<&T>) -> bool {
    match (value, other) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => a == b,
    }
}

/// Split a purl into its type, its registry-style name, and its version.
///
/// The type is kept as a string rather than resolved to [`crate::identity::Ecosystem`],
/// because a policy may name an ecosystem no adapter exists for. That is the same
/// decision the floor check and the not-applicable table already make: what the document
/// says and what this build serves are separate questions.
pub(super) fn decompose(purl: &str) -> Result<(String, String, Option<String>), SelectorError> {
    use purl::GenericPurl;
    use std::str::FromStr as _;

    let parsed =
        GenericPurl::<String>::from_str(purl).map_err(|e| SelectorError::UnreadablePurl {
            purl: purl.to_owned(),
            reason: e.to_string(),
        })?;
    // The scope is rejoined, because a selector is written in the name the registry
    // uses: `@babel/core`, not a namespace and a name side by side.
    let name = match parsed.namespace() {
        Some(namespace) => format!("{namespace}/{}", parsed.name()),
        None => parsed.name().to_owned(),
    };
    Ok((
        parsed.package_type().to_owned(),
        name,
        parsed.version().map(str::to_owned),
    ))
}

/// Read a written name into a pattern, refusing the shapes that cannot be compared.
fn pattern_of(name: Option<&str>) -> Result<NamePattern, SelectorError> {
    let Some(name) = name else {
        return Ok(NamePattern::Any);
    };
    match name.split('*').count() {
        1 => Ok(NamePattern::Exact(name.to_owned())),
        2 if name.ends_with('*') => {
            let prefix = &name[..name.len() - 1];
            Ok(if prefix.is_empty() {
                NamePattern::Any
            } else {
                NamePattern::Prefix(prefix.to_owned())
            })
        }
        _ => Err(SelectorError::InteriorWildcard(name.to_owned())),
    }
}

/// Two entries that cannot be ordered, or that are the same entry twice.
#[derive(Debug, PartialEq)]
pub enum OverlapError {
    /// The same set of packages selected twice. Comparable, and still wrong: whichever
    /// wins, the other is dead, and which one that is depends on file order.
    Duplicate { first: usize, second: usize },
    /// Two entries match a common package and neither is more specific, so §5.5's
    /// most-specific-wins has no answer.
    Incomparable {
        first: usize,
        second: usize,
        first_selector: String,
        second_selector: String,
    },
}

impl fmt::Display for OverlapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { first, second } => write!(
                f,
                "packages[{first}] and packages[{second}] select the same packages. One \
                 of them can never win, and which one depends on the order they happen \
                 to be written in"
            ),
            Self::Incomparable {
                first,
                second,
                first_selector,
                second_selector,
            } => write!(
                f,
                "packages[{first}] ({first_selector}) and packages[{second}] \
                 ({second_selector}) both match some packages, and neither is more \
                 specific than the other. Most-specific-wins has no answer here, so one \
                 of them has to be narrowed until it does"
            ),
        }
    }
}

impl std::error::Error for OverlapError {}

/// Every pair of entries is either disjoint, or ordered by containment.
///
/// Checked at load rather than at the first request that hits the pair, because the
/// request that would expose it may be months away and the file is in front of the
/// operator now.
pub fn check_overlaps(selectors: &[Canonical]) -> Result<(), OverlapError> {
    for (i, a) in selectors.iter().enumerate() {
        for (j, b) in selectors.iter().enumerate().skip(i + 1) {
            if !a.overlaps(b) {
                continue;
            }
            if a == b {
                return Err(OverlapError::Duplicate {
                    first: i,
                    second: j,
                });
            }
            if !a.contained_by(b) && !b.contained_by(a) {
                return Err(OverlapError::Incomparable {
                    first: i,
                    second: j,
                    first_selector: a.to_string(),
                    second_selector: b.to_string(),
                });
            }
        }
    }
    Ok(())
}

impl fmt::Display for Canonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ecosystem, self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        if let Some(scripts) = self.has_install_scripts {
            write!(f, " has_install_scripts={scripts}")?;
        }
        Ok(())
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Names drawn from a set where every containment relation appears: two prefixes one
    /// inside the other, an exact name inside both, an exact name outside them, and
    /// everything.
    fn any_name() -> NamePattern {
        let i: usize = kani::any();
        kani::assume(i < 5);
        match i {
            0 => NamePattern::Any,
            1 => NamePattern::Prefix("a".to_owned()),
            2 => NamePattern::Prefix("ab".to_owned()),
            3 => NamePattern::Exact("abc".to_owned()),
            _ => NamePattern::Exact("z".to_owned()),
        }
    }

    fn any_optional_flag() -> Option<bool> {
        let i: usize = kani::any();
        kani::assume(i < 3);
        match i {
            0 => None,
            1 => Some(true),
            _ => Some(false),
        }
    }

    fn any_version() -> Option<String> {
        let i: usize = kani::any();
        kani::assume(i < 3);
        match i {
            0 => None,
            1 => Some("1".to_owned()),
            _ => Some("2".to_owned()),
        }
    }

    fn any_canonical() -> Canonical {
        let npm: bool = kani::any();
        Canonical {
            ecosystem: if npm {
                "npm".to_owned()
            } else {
                "pypi".to_owned()
            },
            name: any_name(),
            version: any_version(),
            has_install_scripts: any_optional_flag(),
        }
    }

    /// A selector matches everything it matches. Without this, an entry could fail to be
    /// recognised as a duplicate of itself, and the load-time check would pass a file
    /// whose two identical entries make one of them permanently dead.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_selector_contains_itself_and_is_not_strictly_inside_itself() {
        let a = any_canonical();
        assert!(a.contained_by(&a));
        assert!(!a.strictly_contained_by(&a));
        assert!(a.overlaps(&a));
    }

    /// Two selectors cannot each be strictly inside the other. §5.5's most-specific-wins
    /// picks the contained one, so a pair that contained each other would have two
    /// winners and the answer would come down to which was written first.
    #[kani::proof]
    #[kani::unwind(8)]
    fn two_selectors_cannot_each_be_strictly_inside_the_other() {
        let a = any_canonical();
        let b = any_canonical();
        assert!(!(a.strictly_contained_by(&b) && b.strictly_contained_by(&a)));
    }

    /// Containment implies overlap, for anything that matches at all. A selector inside
    /// another that shared no package with it would mean the load-time check skipping
    /// exactly the pairs most-specific-wins has to order.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_selector_inside_another_shares_packages_with_it() {
        let a = any_canonical();
        let b = any_canonical();
        if a.contained_by(&b) {
            assert!(a.overlaps(&b));
        }
    }

    /// Overlap does not depend on which side is asked.
    #[kani::proof]
    #[kani::unwind(8)]
    fn overlapping_is_the_same_question_from_either_side() {
        let a = any_canonical();
        let b = any_canonical();
        assert!(a.overlaps(&b) == b.overlaps(&a));
    }

    // Not proved here: that two equal selectors report as a duplicate rather than as an
    // unorderable pair. Cloning a `Canonical` copies its `String` fields, and the loop
    // that does it does not unwind at any bound worth waiting for. Reflexivity above
    // covers the containment half, and the distinction between the two errors is a
    // property of `check_overlaps`, which walks a slice and is not a kani shape either.
    // `the_same_entry_written_twice_is_refused_at_load` covers it.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(
        ecosystem: &str,
        name: Option<&str>,
        version: Option<&str>,
        scripts: Option<bool>,
    ) -> Selector {
        Selector {
            ecosystem: ecosystem.to_owned(),
            name: name.map(str::to_owned),
            purl: None,
            version: version.map(str::to_owned),
            has_install_scripts: scripts,
        }
    }

    fn canon(
        ecosystem: &str,
        name: Option<&str>,
        version: Option<&str>,
        scripts: Option<bool>,
    ) -> Canonical {
        Canonical::of(&sel(ecosystem, name, version, scripts)).expect("valid selector")
    }

    /// §5.5's own chain: `@mycompany/foo` ⊂ `@mycompany/*` ⊂ `*`.
    #[test]
    fn a_name_is_contained_by_a_prefix_and_a_prefix_by_everything() {
        let exact = canon("npm", Some("@mycompany/foo"), None, None);
        let prefix = canon("npm", Some("@mycompany/*"), None, None);
        let any = canon("npm", Some("*"), None, None);

        assert!(exact.strictly_contained_by(&prefix));
        assert!(prefix.strictly_contained_by(&any));
        assert!(exact.strictly_contained_by(&any));
        assert!(!any.contained_by(&prefix));
        assert!(!prefix.contained_by(&exact));
    }

    /// An absent name is the same set as `*`.
    #[test]
    fn no_name_at_all_means_every_name() {
        assert_eq!(canon("npm", None, None, None).name, NamePattern::Any);
        assert_eq!(canon("npm", Some("*"), None, None).name, NamePattern::Any);
    }

    /// §5.5: exact version ⊂ any version, and a predicate narrows a selector.
    #[test]
    fn a_version_and_a_predicate_each_narrow_a_selector() {
        let bare = canon("npm", Some("x"), None, None);
        let versioned = canon("npm", Some("x"), Some("1.0.0"), None);
        let predicated = canon("npm", Some("x"), None, Some(true));

        assert!(versioned.strictly_contained_by(&bare));
        assert!(predicated.strictly_contained_by(&bare));
        assert!(!bare.contained_by(&versioned));
    }

    /// Two different values in the same dimension are neither contained nor overlapping.
    #[test]
    fn two_different_versions_select_nothing_in_common() {
        let a = canon("npm", Some("x"), Some("1.0.0"), None);
        let b = canon("npm", Some("x"), Some("2.0.0"), None);
        assert!(!a.contained_by(&b) && !b.contained_by(&a));
        assert!(!a.overlaps(&b));
    }

    /// Ecosystems do not mix. npm `requests` and PyPI `requests` are unrelated projects,
    /// which is §5.5's reason for requiring the field.
    #[test]
    fn selectors_in_different_ecosystems_never_meet() {
        let npm = canon("npm", Some("requests"), None, None);
        let pypi = canon("pypi", Some("requests"), None, None);
        assert!(!npm.overlaps(&pypi));
        assert!(!npm.contained_by(&pypi));
    }

    /// A purl and the fields it decomposes into denote one set, so they have to compare
    /// as equal rather than as incomparable.
    #[test]
    fn a_purl_and_the_fields_it_stands_for_are_the_same_selector() {
        let from_purl = Canonical::of(&Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("pkg:npm/chalk@5.6.2".to_owned()),
            version: None,
            has_install_scripts: None,
        })
        .unwrap();
        assert_eq!(from_purl, canon("npm", Some("chalk"), Some("5.6.2"), None));
    }

    #[test]
    fn a_scoped_purl_keeps_the_name_the_registry_uses() {
        let scoped = Canonical::of(&Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("pkg:npm/%40babel/core".to_owned()),
            version: None,
            has_install_scripts: None,
        })
        .unwrap();
        assert_eq!(scoped.name, NamePattern::Exact("@babel/core".to_owned()));
        assert_eq!(scoped.version, None);
    }

    #[test]
    fn a_selector_cannot_say_the_same_thing_twice() {
        let both = Selector {
            ecosystem: "npm".to_owned(),
            name: Some("chalk".to_owned()),
            purl: Some("pkg:npm/chalk".to_owned()),
            version: None,
            has_install_scripts: None,
        };
        assert_eq!(Canonical::of(&both), Err(SelectorError::BothPurlAndName));
    }

    #[test]
    fn a_purl_that_contradicts_its_own_selector_is_refused() {
        let mismatched = Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("pkg:pypi/requests".to_owned()),
            version: None,
            has_install_scripts: None,
        };
        assert!(matches!(
            Canonical::of(&mismatched),
            Err(SelectorError::PurlEcosystemDiffers { .. })
        ));
    }

    #[test]
    fn an_unreadable_purl_is_refused_by_name() {
        let bad = Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("not-a-purl".to_owned()),
            version: None,
            has_install_scripts: None,
        };
        let error = Canonical::of(&bad).unwrap_err();
        assert!(error.to_string().contains("not-a-purl"));
    }

    /// The closed vocabulary. A `*` anywhere but the end would need a matcher to compare,
    /// and a version range would need range algebra.
    #[test]
    fn the_shapes_that_could_not_be_compared_are_refused_rather_than_guessed_at() {
        for name in ["*foo", "a*b", "@my*/foo", "**"] {
            let error = Canonical::of(&sel("npm", Some(name), None, None)).unwrap_err();
            assert!(
                matches!(error, SelectorError::InteriorWildcard(_))
                    && error.to_string().contains(name),
                "`{name}`: {error}"
            );
        }
        for version in [
            "^1.0.0",
            ">=1.0 <2",
            "1.x",
            "1.X",
            "x",
            "1.0.*",
            "1.0.0 || 2.0.0",
            "1.0.0,2.0.0",
        ] {
            let error = Canonical::of(&sel("npm", Some("x"), Some(version), None)).unwrap_err();
            assert!(
                matches!(error, SelectorError::VersionRange(_)),
                "`{version}`: {error}"
            );
        }
        // Exact versions that look like ranges and are not: a prerelease tag may be
        // anything, `x` included.
        for version in ["1.0.0", "1.0.0-rc.1", "1.0.0-x", "1.0.0+build.x", "0.1.2"] {
            assert!(
                Canonical::of(&sel("npm", Some("pkg"), Some(version), None)).is_ok(),
                "`{version}` is one version"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Overlaps
    // -----------------------------------------------------------------------

    #[test]
    fn selectors_that_share_nothing_are_fine() {
        let set = [
            canon("npm", Some("a"), None, None),
            canon("npm", Some("b"), None, None),
            canon("pypi", Some("a"), None, None),
        ];
        assert!(check_overlaps(&set).is_ok());
    }

    /// A chain is fine: each is strictly inside the next, so most-specific-wins has an
    /// answer for every package they share.
    #[test]
    fn a_chain_from_narrow_to_wide_is_fine() {
        let set = [
            canon("npm", Some("@mycompany/foo"), None, None),
            canon("npm", Some("@mycompany/*"), None, None),
            canon("npm", Some("*"), None, None),
        ];
        assert!(check_overlaps(&set).is_ok());
    }

    #[test]
    fn the_same_selector_written_twice_is_refused() {
        let set = [
            canon("npm", Some("x"), None, None),
            canon("npm", Some("x"), None, None),
        ];
        assert_eq!(
            check_overlaps(&set),
            Err(OverlapError::Duplicate {
                first: 0,
                second: 1
            })
        );
    }

    /// The same set written two different ways is still the same set.
    #[test]
    fn a_duplicate_written_as_a_purl_is_still_a_duplicate() {
        let set = [
            canon("npm", Some("chalk"), Some("5.6.2"), None),
            Canonical::of(&Selector {
                ecosystem: "npm".to_owned(),
                name: None,
                purl: Some("pkg:npm/chalk@5.6.2".to_owned()),
                version: None,
                has_install_scripts: None,
            })
            .unwrap(),
        ];
        assert!(matches!(
            check_overlaps(&set),
            Err(OverlapError::Duplicate { .. })
        ));
    }

    /// The case the whole mechanism exists for: one is narrower by name, the other by
    /// predicate, and they share the packages that satisfy both. §5.5's most-specific-wins
    /// has no answer, so the file is refused rather than resolved by position.
    #[test]
    fn two_selectors_narrower_in_different_dimensions_are_refused() {
        let set = [
            canon("npm", Some("a*"), None, Some(true)),
            canon("npm", Some("ab*"), None, None),
        ];
        let error = check_overlaps(&set).unwrap_err();
        assert!(matches!(error, OverlapError::Incomparable { .. }));
        let text = error.to_string();
        assert!(
            text.contains("npm:a*")
                && text.contains("npm:ab*")
                && text.contains("has_install_scripts"),
            "the refusal has to show both selectors: {text}"
        );
    }

    /// Narrower in different dimensions but sharing nothing is not a problem: there is no
    /// package for most-specific-wins to be asked about.
    #[test]
    fn incomparable_selectors_that_never_meet_are_fine() {
        let set = [
            canon("npm", Some("a*"), None, Some(true)),
            canon("npm", Some("zz*"), None, None),
        ];
        assert!(check_overlaps(&set).is_ok());
    }

    /// A predicate and its opposite select disjoint sets, however the names overlap.
    #[test]
    fn opposite_predicates_never_share_a_package() {
        let set = [
            canon("npm", Some("*"), None, Some(true)),
            canon("npm", Some("x"), None, Some(false)),
        ];
        assert!(check_overlaps(&set).is_ok());
    }

    #[test]
    fn one_selector_has_nothing_to_overlap_with() {
        assert!(check_overlaps(&[canon("npm", Some("x"), None, None)]).is_ok());
        assert!(check_overlaps(&[]).is_ok());
    }

    /// Matching a package reads the same four dimensions containment does, so a selector
    /// cannot match one way and be ordered another.
    #[test]
    fn a_selector_matches_the_packages_it_names() {
        let prefix = canon("npm", Some("@mycompany/*"), None, None);
        assert!(prefix.matches("npm", "@mycompany/foo", "1.0.0", false));
        assert!(!prefix.matches("npm", "lodash", "1.0.0", false));
        assert!(!prefix.matches("pypi", "@mycompany/foo", "1.0.0", false));

        let pinned = canon("npm", Some("x"), Some("1.0.0"), None);
        assert!(pinned.matches("npm", "x", "1.0.0", false));
        assert!(!pinned.matches("npm", "x", "1.0.1", false));

        let predicated = canon("npm", Some("x"), None, Some(true));
        assert!(predicated.matches("npm", "x", "1.0.0", true));
        assert!(!predicated.matches("npm", "x", "1.0.0", false));

        assert!(canon("npm", None, None, None).matches("npm", "anything", "0.0.1", true));
    }

    /// A narrower selector matches a subset of what a wider one matches. This is the
    /// relation containment claims, checked against real packages rather than asserted.
    #[test]
    fn a_contained_selector_matches_a_subset_of_what_contains_it() {
        let narrow = canon("npm", Some("@mycompany/foo"), None, None);
        let wide = canon("npm", Some("@mycompany/*"), None, None);
        assert!(narrow.strictly_contained_by(&wide));

        for (name, version) in [("@mycompany/foo", "1.0.0"), ("@mycompany/bar", "2.0.0")] {
            if narrow.matches("npm", name, version, false) {
                assert!(
                    wide.matches("npm", name, version, false),
                    "{name} is matched by the narrower selector and not the wider one"
                );
            }
        }
        assert!(wide.matches("npm", "@mycompany/bar", "2.0.0", false));
        assert!(!narrow.matches("npm", "@mycompany/bar", "2.0.0", false));
    }

    #[test]
    fn containment_is_reflexive_and_a_set_is_not_strictly_inside_itself() {
        let a = canon("npm", Some("a*"), Some("1.0.0"), Some(true));
        assert!(a.contained_by(&a));
        assert!(!a.strictly_contained_by(&a));
        assert!(a.overlaps(&a));
    }
}
