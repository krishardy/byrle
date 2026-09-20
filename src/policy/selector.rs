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
//! <2` without each ecosystem's range algebra, and the answer for `a*` against `*b` needs a
//! matcher. So both are restricted at load rather than admitted and then compared by
//! guesswork:
//!
//! - a name is `*`, `prefix*`, or a literal. A `*` anywhere else is refused.
//! - a version is an exact version, a VERS range, or absent. A VERS range is a union of
//!   intervals over the ecosystem's version order, so containment is decided on the
//!   intervals ([`super::vers`]). Every other range notation is refused.
//!
//! Names and versions are compared the ecosystem's way: a PyPI name by PEP 503, so
//! `Django` is `django`, and a PyPI version by PEP 440, so `1.0` is `1.0.0`.
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
use super::vers::{VersError, Versions};
use crate::ecosystem::canonical_name;
use crate::intel::range::VersionOrder;
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

impl NamePattern {
    /// This pattern with its name as `ecosystem` compares it.
    fn canonical(self, ecosystem: &str) -> Self {
        match self {
            Self::Any => Self::Any,
            Self::Prefix(p) => Self::Prefix(canonical_name(ecosystem, &p)),
            Self::Exact(n) => Self::Exact(canonical_name(ecosystem, &n)),
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

/// The version dimension containment is decided on: [`Versions`] in a policy. The proofs
/// below use a smaller set, because a set of parsed versions is more state than a proof
/// unwinds in reasonable time, and what they prove is how the dimensions combine.
pub trait VersionSet: Clone + PartialEq + fmt::Display {
    /// Whether every version in this set is in `other`.
    fn contained_by(&self, other: &Self) -> bool;
    /// Whether some version is in both.
    fn overlaps(&self, other: &Self) -> bool;
}

impl VersionSet for Versions {
    fn contained_by(&self, other: &Self) -> bool {
        Versions::contained_by(self, other)
    }

    fn overlaps(&self, other: &Self) -> bool {
        Versions::overlaps(self, other)
    }
}

/// A selector reduced to the four things containment is decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical<V = Versions> {
    pub ecosystem: String,
    pub name: NamePattern,
    /// The versions it covers, or every version.
    pub version: Option<V>,
    /// A predicate narrows a selector to the packages it holds for.
    pub has_install_scripts: Option<bool>,
}

/// Why a selector could not be canonicalised.
#[derive(Debug, PartialEq)]
pub enum SelectorError {
    BothPurlAndName,
    /// A purl with `@version` beside a `version`.
    PurlAndVersion,
    /// A version or a VERS range that does not read.
    Version(VersError),
    /// A version for an ecosystem this build has no version order for.
    UnorderedEcosystem(String),
    /// A denial with neither `@version` in its purl nor a `version`.
    NoVersion,
    /// A denial's `version` that is not a VERS range.
    DenialVersionNotARange(String),
    InteriorWildcard(String),
    VersionRange(String),
    UnreadablePurl {
        purl: String,
        reason: String,
    },
    /// A purl whose name its ecosystem's name rule refuses.
    NotAPackageName {
        purl: String,
        reason: String,
    },
    PurlEcosystemDiffers {
        purl: String,
        ecosystem: String,
    },
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
                "`{v}` is a version range in an ecosystem's own notation. A range is written \
                 as VERS, such as `vers:npm/>=1.2.0|<2.0.0`, which reads the same in every \
                 ecosystem"
            ),
            Self::PurlAndVersion => f.write_str(
                "sets a version twice, in the purl's `@version` and in `version`. Write it \
                 once",
            ),
            Self::Version(e) => write!(f, "{e}"),
            Self::UnorderedEcosystem(ecosystem) => write!(
                f,
                "names a version for `{ecosystem}`, and this build has no version order for \
                 it"
            ),
            Self::NoVersion => f.write_str(
                "names no version. A denial refuses one version, `@version` in its purl, or \
                 a VERS range in `version`",
            ),
            Self::DenialVersionNotARange(v) => write!(
                f,
                "`{v}` is one version, which a denial writes in its purl as `@{v}`. \
                 `version` takes a VERS range, such as `vers:npm/<2.0.0`"
            ),
            Self::UnreadablePurl { purl, reason } => {
                write!(f, "`{purl}` is not a readable purl: {reason}")
            }
            Self::NotAPackageName { purl, reason } => write!(
                f,
                "`{purl}` names no package its ecosystem can have, so it would match \
                 nothing: {reason}"
            ),
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
        let ecosystem = selector.ecosystem.as_str();

        let (name, version) = match &selector.purl {
            Some(purl) => {
                let (kind, name, version) = decompose(purl)?;
                if kind != ecosystem {
                    return Err(SelectorError::PurlEcosystemDiffers {
                        purl: purl.clone(),
                        ecosystem: selector.ecosystem.clone(),
                    });
                }
                let version = match (version, &selector.version) {
                    (Some(_), Some(_)) => return Err(SelectorError::PurlAndVersion),
                    (Some(exact), None) => Some(exact_version(ecosystem, &exact)?),
                    (None, written) => written
                        .as_deref()
                        .map(|w| version_or_range(ecosystem, w))
                        .transpose()?,
                };
                (NamePattern::Exact(name), version)
            }
            None => (
                pattern_of(selector.name.as_deref())?,
                selector
                    .version
                    .as_deref()
                    .map(|w| version_or_range(ecosystem, w))
                    .transpose()?,
            ),
        };

        Ok(Self {
            ecosystem: selector.ecosystem.clone(),
            name: name.canonical(ecosystem),
            version,
            has_install_scripts: selector.has_install_scripts,
        })
    }

    /// What a denial refuses, as a selector: one package, at the version its purl names or
    /// in the VERS range `version` names.
    pub fn of_denial(purl: &str, version: Option<&str>) -> Result<Self, SelectorError> {
        let (ecosystem, name, exact) = decompose(purl)?;
        let versions = match (exact, version) {
            (Some(_), Some(_)) => return Err(SelectorError::PurlAndVersion),
            (Some(exact), None) => exact_version(&ecosystem, &exact)?,
            (None, Some(range)) if range.starts_with(VERS) => version_or_range(&ecosystem, range)?,
            (None, Some(exact)) => {
                return Err(SelectorError::DenialVersionNotARange(exact.to_owned()));
            }
            (None, None) => return Err(SelectorError::NoVersion),
        };
        Ok(Self {
            name: NamePattern::Exact(name).canonical(&ecosystem),
            ecosystem,
            version: Some(versions),
            has_install_scripts: None,
        })
    }

    /// Whether one specific package is in the set this selector names.
    ///
    /// Containment asks how two selectors relate; this asks whether a package is in one
    /// of them. Both read the same four dimensions, so a selector cannot match a package
    /// one way here and be ordered another way there.
    ///
    /// `name` and `version` are read the ecosystem's way, as the selector's own were.
    pub fn matches(&self, ecosystem: &str, name: &str, version: &str, scripts: bool) -> bool {
        self.ecosystem == ecosystem
            && self.name.matches(&canonical_name(ecosystem, name))
            && self.version.as_ref().is_none_or(|versions| {
                VersionOrder::of(ecosystem)
                    .and_then(|order| order.parse(version))
                    .is_some_and(|v| versions.contains(&v))
            })
            && self.has_install_scripts.is_none_or(|s| s == scripts)
    }
}

impl<V: VersionSet> Canonical<V> {
    /// Whether every package this matches is also matched by `other`.
    ///
    /// Per dimension, all of them: a selector is narrower only if it is narrower or equal
    /// everywhere. Narrower in one dimension and wider in another is neither, which is
    /// §5.5's incomparable case.
    pub fn contained_by(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem
            && self.name.contained_by(&other.name)
            && contained(
                self.version.as_ref(),
                other.version.as_ref(),
                V::contained_by,
            )
            && contained(
                self.has_install_scripts.as_ref(),
                other.has_install_scripts.as_ref(),
                bool::eq,
            )
    }

    /// Whether some package matches both.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem
            && self.name.overlaps(&other.name)
            && intersects(self.version.as_ref(), other.version.as_ref(), V::overlaps)
            && intersects(
                self.has_install_scripts.as_ref(),
                other.has_install_scripts.as_ref(),
                bool::eq,
            )
    }

    /// Whether this matches strictly fewer packages than `other`.
    pub fn strictly_contained_by(&self, other: &Self) -> bool {
        self.contained_by(other) && !other.contained_by(self)
    }
}

/// A dimension that is set is narrower than one that is not; two that are set are decided
/// by `inside`.
fn contained<T>(value: Option<&T>, other: Option<&T>, inside: fn(&T, &T) -> bool) -> bool {
    match (value, other) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => inside(a, b),
    }
}

/// Two dimensions share a package when either is unset, or `share` says the two set ones
/// do.
fn intersects<T>(value: Option<&T>, other: Option<&T>, share: fn(&T, &T) -> bool) -> bool {
    match (value, other) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => share(a, b),
    }
}

/// How a VERS string starts.
pub(super) const VERS: &str = "vers:";

/// The order `ecosystem`'s versions are read by.
fn order_of(ecosystem: &str) -> Result<VersionOrder, SelectorError> {
    VersionOrder::of(ecosystem)
        .ok_or_else(|| SelectorError::UnorderedEcosystem(ecosystem.to_owned()))
}

/// One exact version, refusing a range in an ecosystem's own notation by name.
fn exact_version(ecosystem: &str, written: &str) -> Result<Versions, SelectorError> {
    let order = order_of(ecosystem)?;
    if looks_like_a_range(written) {
        return Err(SelectorError::VersionRange(written.to_owned()));
    }
    Versions::exact(order, ecosystem, written).map_err(SelectorError::Version)
}

/// A VERS range, or one exact version.
fn version_or_range(ecosystem: &str, written: &str) -> Result<Versions, SelectorError> {
    if written.starts_with(VERS) {
        Versions::vers(order_of(ecosystem)?, ecosystem, written).map_err(SelectorError::Version)
    } else {
        exact_version(ecosystem, written)
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
    // A selector is written in the name the registry uses, `@babel/core`, not a namespace
    // and a name side by side. For an ecosystem this build serves, that name is built by the
    // ecosystem's own rule, as a package key's is, so a purl no package can have is refused
    // rather than loaded to match nothing. An ecosystem it does not serve has no rule here,
    // and its parts are joined as they are written.
    let name = match parsed.package_type().parse::<crate::identity::Ecosystem>() {
        Ok(ecosystem) => {
            crate::identity::key_from_purl(ecosystem, parsed.namespace(), parsed.name())
                .map_err(|e| SelectorError::NotAPackageName {
                    purl: purl.to_owned(),
                    reason: e.to_string(),
                })?
                .registry_name()
        }
        Err(_) => match parsed.namespace() {
            Some(namespace) => format!("{namespace}/{}", parsed.name()),
            None => parsed.name().to_owned(),
        },
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
pub fn check_overlaps<V: VersionSet>(selectors: &[Canonical<V>]) -> Result<(), OverlapError> {
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

impl<V: VersionSet> fmt::Display for Canonical<V> {
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

    /// Versions 0, 1 and 2 as bits. Each set is non-empty, as every [`Versions`] is.
    #[derive(Debug, Clone, PartialEq)]
    struct Bits(u8);

    impl fmt::Display for Bits {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:03b}", self.0)
        }
    }

    impl VersionSet for Bits {
        fn contained_by(&self, other: &Self) -> bool {
            self.0 & !other.0 == 0
        }

        fn overlaps(&self, other: &Self) -> bool {
            self.0 & other.0 != 0
        }
    }

    /// A point inside a range, the range, and a point outside it, or every version.
    fn any_version() -> Option<Bits> {
        let i: usize = kani::any();
        kani::assume(i < 4);
        match i {
            0 => None,
            1 => Some(Bits(0b001)),
            2 => Some(Bits(0b011)),
            _ => Some(Bits(0b100)),
        }
    }

    fn any_canonical() -> Canonical<Bits> {
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
    /// and a range in an ecosystem's own notation would need that ecosystem's range
    /// algebra.
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
        // PEP 440 specifiers each carry one of the operators, and a PEP 440 version,
        // epoch and post-release included, carries none.
        for version in ["~=1.4", "!=1.4", "===1.4", "==1.4.*", ">=1.4,<2"] {
            let error = Canonical::of(&sel("pypi", Some("x"), Some(version), None)).unwrap_err();
            assert!(
                matches!(error, SelectorError::VersionRange(_)),
                "`{version}`: {error}"
            );
        }
        for version in ["1!2.0", "1.0-1", "1.0.post1", "1.0rc1", "1.0+ubuntu.1"] {
            assert!(
                Canonical::of(&sel("pypi", Some("pkg"), Some(version), None)).is_ok(),
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
        assert!(check_overlaps::<Versions>(&[]).is_ok());
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

    /// A VERS range is a version set like any other: a range inside another is narrower,
    /// and two ranges that cross cannot be ordered.
    #[test]
    fn a_vers_range_is_ordered_by_containment() {
        let wide = canon("npm", Some("x"), Some("vers:npm/>=1.0.0|<2.0.0"), None);
        let narrow = canon("npm", Some("x"), Some("vers:npm/>=1.2.0|<1.3.0"), None);
        let exact = canon("npm", Some("x"), Some("1.2.5"), None);
        let crossing = canon("npm", Some("x"), Some("vers:npm/>=1.5.0|<3.0.0"), None);
        let after = canon("npm", Some("x"), Some("vers:npm/>=2.0.0"), None);

        assert!(narrow.strictly_contained_by(&wide));
        assert!(exact.strictly_contained_by(&narrow));
        assert!(wide.overlaps(&crossing));
        assert!(!wide.contained_by(&crossing) && !crossing.contained_by(&wide));
        assert!(!wide.overlaps(&after));
        assert_eq!(
            check_overlaps(&[wide.clone(), crossing]),
            Err(OverlapError::Incomparable {
                first: 0,
                second: 1,
                first_selector: "npm:x@vers:npm/>=1.0.0|<2.0.0".to_owned(),
                second_selector: "npm:x@vers:npm/>=1.5.0|<3.0.0".to_owned(),
            })
        );
        assert_eq!(check_overlaps(&[wide.clone(), narrow, after]), Ok(()));

        assert!(wide.matches("npm", "x", "1.9.9", false));
        assert!(!wide.matches("npm", "x", "2.0.0", false));
        assert!(!wide.matches("npm", "x", "not a version", false));
        assert!(!wide.matches("cargo", "x", "1.0.0", false));
    }

    /// A PyPI name compares by PEP 503 and a PyPI version by PEP 440, as pip reads them.
    #[test]
    fn a_pypi_selector_reads_names_and_versions_as_pip_does() {
        let django = canon("pypi", Some("Django"), Some("4.2"), None);
        assert_eq!(django.name, NamePattern::Exact("django".to_owned()));
        assert!(django.matches("pypi", "django", "4.2.0", false));
        assert!(django.matches("pypi", "DJANGO", "4.2", false));
        assert!(!django.matches("pypi", "django", "4.2.1", false));

        let zope = canon("pypi", Some("zope.*"), None, None);
        assert_eq!(zope.name, NamePattern::Prefix("zope-".to_owned()));
        assert!(zope.matches("pypi", "zope.interface", "1.0", false));
        assert!(!zope.matches("pypi", "zopefoo", "1.0", false));

        let post = canon("pypi", Some("x"), Some("vers:pypi/>=1.0|<1.0.post2"), None);
        assert!(post.matches("pypi", "x", "1.0-1", false));
        assert!(!post.matches("pypi", "x", "1.0.post2", false));

        // An ecosystem this build does not serve keeps its name as written.
        assert_eq!(
            canon("cargo", Some("Serde"), None, None).name,
            NamePattern::Exact("Serde".to_owned())
        );
    }

    #[test]
    fn a_version_that_cannot_be_read_is_refused_by_what_is_wrong_with_it() {
        let refused = |selector: Selector| Canonical::of(&selector).unwrap_err();
        assert_eq!(
            refused(sel("cargo", Some("serde"), Some("1.0.0"), None)),
            SelectorError::UnorderedEcosystem("cargo".to_owned())
        );
        assert!(matches!(
            refused(sel("npm", Some("x"), Some("vers:pypi/>=1.0"), None)),
            SelectorError::Version(_)
        ));
        assert!(matches!(
            refused(sel("npm", Some("x"), Some("1.0"), None)),
            SelectorError::Version(_)
        ));
        let both = Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("pkg:npm/chalk@5.6.2".to_owned()),
            version: Some("5.6.2".to_owned()),
            has_install_scripts: None,
        };
        assert_eq!(refused(both), SelectorError::PurlAndVersion);
        let purl_and_range = Selector {
            ecosystem: "npm".to_owned(),
            name: None,
            purl: Some("pkg:npm/chalk".to_owned()),
            version: Some("vers:npm/<5.6.2".to_owned()),
            has_install_scripts: None,
        };
        assert_eq!(
            Canonical::of(&purl_and_range)
                .expect("a range beside a purl")
                .name,
            NamePattern::Exact("chalk".to_owned())
        );
    }

    #[test]
    fn a_denial_is_one_version_in_its_purl_or_a_vers_range_beside_it() {
        let one = Canonical::of_denial("pkg:npm/chalk@5.6.1", None).expect("one version");
        assert!(one.matches("npm", "chalk", "5.6.1", true));
        assert!(!one.matches("npm", "chalk", "5.6.2", false));

        let range =
            Canonical::of_denial("pkg:pypi/Requests", Some("vers:pypi/<2.31")).expect("a range");
        assert!(range.matches("pypi", "requests", "2.30.0", false));
        assert!(!range.matches("pypi", "requests", "2.31.0", false));

        for (purl, version, error) in [
            ("pkg:npm/chalk", None, SelectorError::NoVersion),
            (
                "pkg:npm/chalk@5.6.1",
                Some("vers:npm/<6.0.0"),
                SelectorError::PurlAndVersion,
            ),
            (
                "pkg:npm/chalk",
                Some("5.6.1"),
                SelectorError::DenialVersionNotARange("5.6.1".to_owned()),
            ),
        ] {
            assert_eq!(Canonical::of_denial(purl, version), Err(error));
        }
        assert!(Canonical::of_denial("not-a-purl", None).is_err());
    }

    /// Each refusal says what to write instead.
    #[test]
    fn each_version_error_names_the_way_to_write_it() {
        for (error, expected) in [
            (
                SelectorError::VersionRange("^1.0.0".to_owned()),
                "vers:npm/>=1.2.0|<2.0.0",
            ),
            (SelectorError::PurlAndVersion, "Write it once"),
            (
                SelectorError::UnorderedEcosystem("cargo".to_owned()),
                "no version order for it",
            ),
            (SelectorError::NoVersion, "a VERS range in `version`"),
            (
                SelectorError::DenialVersionNotARange("1.0.0".to_owned()),
                "writes in its purl as `@1.0.0`",
            ),
        ] {
            assert!(error.to_string().contains(expected), "{error}");
        }
        let unread = Canonical::of(&sel("npm", Some("x"), Some("1.0"), None)).unwrap_err();
        assert!(
            unread
                .to_string()
                .contains("is not a version npm publishes")
        );
    }

    /// A purl is read by its ecosystem's name rule, as a package key is, so a denial or a
    /// selector naming no package that can exist is refused at load rather than matching
    /// nothing.
    #[test]
    fn a_purl_is_read_by_its_ecosystems_name_rule() {
        for (purl, expected) in [
            ("pkg:npm/foo/bar@1.0.0", "a `/` needs an `@` scope"),
            ("pkg:pypi/ns/idna@3.10", "not a valid PyPI project name"),
        ] {
            let error = Canonical::of_denial(purl, None).unwrap_err();
            assert!(
                matches!(error, SelectorError::NotAPackageName { .. }),
                "{purl}: {error:?}"
            );
            let message = error.to_string();
            assert!(message.contains(expected), "{message}");
            assert!(message.contains("would match nothing"), "{message}");
        }
        for (purl, ecosystem, name, version) in [
            (
                "pkg:npm/%40babel%2Fcore@7.0.0",
                "npm",
                "@babel/core",
                "7.0.0",
            ),
            ("pkg:pypi/Django@4.2", "pypi", "django", "4.2.0"),
        ] {
            let denial = Canonical::of_denial(purl, None).expect("a package that can exist");
            assert!(denial.matches(ecosystem, name, version, false), "{purl}");
        }
        // An ecosystem this build does not serve keeps its parts as written.
        assert_eq!(
            decompose("pkg:cargo/ns/serde@1.0.0").expect("readable"),
            (
                "cargo".to_owned(),
                "ns/serde".to_owned(),
                Some("1.0.0".to_owned())
            )
        );
    }
}
