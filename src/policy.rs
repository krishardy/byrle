//! The policy document: its schema, and loading it.
//!
//! A policy is global settings and per-package exceptions to them. Nothing is per
//! ecosystem. See `docs/engineering_decisions/policy-tier-resolution.md`, which carries
//! the decision flow chart this schema serves.
//!
//! # Fail closed on anything unrecognised
//!
//! `deny_unknown_fields` on every struct. A typo'd key in a security policy is not a
//! harmless extra: `expiress` where `expires` was meant silently produces a rule that
//! never expires, and `blcok` produces a rule that does nothing. Both read as working.
//!
//! # Never `#[serde(untagged)]`
//!
//! No field is polymorphic today. When one is, it needs a hand-written `Deserialize`
//! rather than an `untagged` enum: untagged refuses a typo'd key but names neither the
//! key nor the right line, reporting only that no variant matched and putting the caret
//! on the line above the mistake. Measured in both formats by
//! `spikes/config-format/src/bin/poly.rs`.

pub mod check;
pub mod decide;
pub mod diff;
pub mod enforce;
pub mod facts;
pub mod merge;
pub mod packages;
pub mod selector;
pub mod strictness;
pub mod vers;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::path::{Path, PathBuf};

/// The only document version this understands.
///
/// A policy naming another version is refused rather than read as this one. The schema is
/// the security boundary, so a document written against a different one is not something
/// to interpret optimistically.
pub const SUPPORTED_VERSION: u32 = 1;

/// Today, in UTC.
///
/// The policy is written in civil dates, so a zone has to be chosen. UTC, so two replicas
/// never land a day apart across midnight, and the proxy, `explain`, `policy check` and
/// `policy diff` judge an expiry on the same day. See `policy::facts`.
pub fn today() -> jiff::civil::Date {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
}

/// Shipped defaults for the four settings, used when a policy does not name one.
///
/// Both checks block by default. An operator who has not thought about install scripts or
/// known-exploited vulnerabilities is better served by the strict answer, and turning one
/// off is a line they have to write.
pub const DEFAULT_COOLDOWN_DAYS: u32 = 7;
pub const DEFAULT_MAX_CVSS: f64 = 6.9;
/// Seven days, the cooldown's own default. Nx's 19 malicious versions came within two
/// hours: see `docs/engineering_decisions/incident-benchmark.md`.
pub const DEFAULT_PROVENANCE_WINDOW_DAYS: u32 = 7;

fn default_cooldown_days() -> u32 {
    DEFAULT_COOLDOWN_DAYS
}
fn default_provenance_window_days() -> u32 {
    DEFAULT_PROVENANCE_WINDOW_DAYS
}
fn default_max_cvss() -> f64 {
    DEFAULT_MAX_CVSS
}
/// `sha256:` and the hex digest of a policy file's bytes. See [`Policy::digest`].
pub fn digest_of(source: &str) -> String {
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(source.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// A window of `days`, which the proxy uses under no policy with
/// [`DEFAULT_PROVENANCE_WINDOW_DAYS`].
pub fn window_of(days: u32) -> jiff::SignedDuration {
    jiff::SignedDuration::from_hours(i64::from(days) * 24)
}

fn default_block() -> Action {
    Action::Block
}
fn default_allow() -> Action {
    Action::Allow
}

/// Why a policy could not be loaded.
#[derive(Debug)]
pub enum PolicyError {
    /// The file could not be read.
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The document does not name a version, or names one this does not understand.
    UnsupportedVersion { found: String, supported: u32 },
    /// The document is not valid YAML, or does not match the schema.
    Invalid(String),
    /// A package entry is both dated and permanent.
    BothDatedAndPermanent { at: String },
    /// A setting was given a value it cannot take.
    NotAnOnOffSetting { at: String, found: Action },
    /// A selector is written in a shape containment cannot be decided on.
    BadSelector {
        at: String,
        source: selector::SelectorError,
    },
    /// Two entries cannot be ordered by most-specific-wins.
    Overlapping(selector::OverlapError),
    /// A denial does not name one exact version.
    DenialNeedsAVersion { at: String, purl: String },
    /// A denial's purl or version could not be read.
    UnreadableDenial {
        at: String,
        source: selector::SelectorError,
    },
    /// An advisory score is not a CVSS score.
    ScoreOutOfRange { at: String, found: f64 },
    /// An advisory score says neither when it stops nor that it does not.
    UndatedScore { at: String },
    /// Two advisory scores name the same id.
    DuplicateScore {
        at: String,
        first: String,
        advisory_id: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, source } => {
                write!(f, "cannot read policy `{}`: {source}", path.display())
            }
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "policy version {found} is not supported; this build understands \
                 version {supported}"
            ),
            Self::Invalid(e) => write!(f, "policy is not valid: {e}"),
            Self::BothDatedAndPermanent { at } => write!(
                f,
                "{at} sets both `expires` and `permanent: true`. They are alternatives: \
                 one says when the entry stops being true, the other says it does not"
            ),
            Self::NotAnOnOffSetting { at, found } => write!(
                f,
                "{at} is `{}`, and this setting takes `block` or `allow`. Waiting does \
                 not change whether a package has an install script or a known-exploited \
                 vulnerability, so there is nothing for `quarantine` to mean here",
                found.as_str()
            ),
            Self::BadSelector { at, source } => write!(f, "{at}: {source}"),
            Self::Overlapping(e) => write!(f, "{e}"),
            Self::DenialNeedsAVersion { at, purl } => write!(
                f,
                "{at} denies `{purl}`, which names no version. A denial is permanent and \
                 absolute, so it names what it refuses: one version, `{purl}@<version>`, or \
                 a VERS range in `version`. Without either it would match nothing and read \
                 as a package that had been dealt with"
            ),
            Self::UnreadableDenial { at, source } => write!(f, "{at}: {source}"),
            Self::ScoreOutOfRange { at, found } => {
                write!(f, "{at}.cvss is {found}, and a CVSS score is 0.0 to 10.0")
            }
            Self::UndatedScore { at } => write!(
                f,
                "{at} carries neither `expires` nor `permanent: true`. A score given here \
                 is what lets an unscored advisory past `max_cvss`, so it says when it stops \
                 being true"
            ),
            Self::DuplicateScore {
                at,
                first,
                advisory_id,
            } => write!(
                f,
                "{at} scores `{advisory_id}`, which {first} already scores. One advisory \
                 has one score"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Read just the version, so a document written against another one is refused before
/// its body is judged against a schema it was never written for.
///
/// Without this, a version 2 document reports whichever version 1 key it happens to be
/// missing, which sends an operator editing keys rather than reading the version line.
/// Unknown fields are allowed here and rejected by the real parse.
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    version: Option<VersionValue>,
}

/// Whatever the version line held, so the refusal can quote it back.
///
/// `serde-saphyr` has no document model to inspect, which is deliberate: it parses
/// straight to Rust types. So the shape is captured here rather than borrowed from the
/// parser.
#[derive(Debug, PartialEq)]
enum VersionValue {
    Number(i64),
    Other(String),
}

impl<'de> Deserialize<'de> for VersionValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl Visitor<'_> for V {
            type Value = VersionValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a policy schema version number")
            }

            fn visit_i64<E>(self, v: i64) -> Result<VersionValue, E> {
                Ok(VersionValue::Number(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<VersionValue, E> {
                Ok(i64::try_from(v)
                    .map(VersionValue::Number)
                    .unwrap_or_else(|_| VersionValue::Other(v.to_string())))
            }

            // Everything else is reported as written rather than coerced. `version: "1"`
            // is a string, and a policy that says so should be told, not guessed at.
            fn visit_str<E>(self, v: &str) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(format!("`{v}`")))
            }

            fn visit_bool<E>(self, v: bool) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(v.to_string()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(v.to_string()))
            }

            // No arm for an empty value: `version:` with nothing after it reaches the
            // `Option` as `None` and never descends here, so it is reported as absent,
            // which is what it says.
        }

        deserializer.deserialize_any(V)
    }
}

/// Global settings, and per-package exceptions to them.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,

    /// How old a package must be before it is served. Produces `quarantine`, which lapses
    /// on its own as the package ages.
    #[serde(default = "default_cooldown_days")]
    pub cooldown_days: u32,
    /// The highest CVSS score a package may carry and still be served. At or below is
    /// allowed, above is not.
    ///
    /// A number rather than a severity band: bands are not stable across CVSS versions,
    /// where the same score falls in different ones under v2 and v3.
    #[serde(default = "default_max_cvss")]
    pub max_cvss: f64,
    /// Whether a package carrying an install script is served. `block` or `allow`.
    #[serde(default = "default_block")]
    pub install_scripts: Action,
    /// Whether a package carrying a known-exploited vulnerability is served. `block` or
    /// `allow`.
    #[serde(default = "default_block")]
    pub kev: Action,
    /// Whether a version its publisher deprecated is served. `block` or `allow`, and
    /// `allow` by default.
    ///
    /// npm's `deprecated`. npm installs a deprecated version after printing a warning and
    /// no npm client skips one, and publishers deprecate whole release lines: `eslint`
    /// marks 405 of its 430 versions, measured 2026-09-20. `block` is a choice an operator
    /// makes. PyPI has no deprecation marker, and the check reports not-applicable there.
    #[serde(default = "default_allow")]
    pub deprecated: Action,
    /// Whether a version the registry withdrew is served. `block` or `allow`.
    ///
    /// PyPI's PEP 592 yank. A resolver skips a yanked file unless the requirement pins
    /// that version, so `block` is what a pinned install of a withdrawn version meets.
    /// npm has no yank, and the check reports not-applicable there.
    #[serde(default = "default_block")]
    pub yanked: Action,
    /// Whether a version whose attestations contradict it is served. `block` or `allow`.
    ///
    /// Refused when an attestation it publishes fails verification, when it publishes none
    /// and the version published before it did, or when its attestation names a different
    /// repository or workflow file than the version published before it. A version with
    /// no attestation after one with none passes: plan §5 does not require provenance.
    /// See `docs/engineering_decisions/provenance-check.md`.
    #[serde(default = "default_block")]
    pub provenance: Action,
    /// How far back `provenance` looks, in days. A version is compared with the version
    /// published just before it, with every version published in this window before it,
    /// and with the most recent attested version, however old. The window compares each
    /// version in a burst with the identities of the others. 0 leaves the version just
    /// before and the most recent attested one.
    #[serde(default = "default_provenance_window_days")]
    pub provenance_window_days: u32,

    #[serde(default)]
    pub denials: Vec<Denial>,
    #[serde(default)]
    pub packages: Vec<PackageRule>,
    /// Scores for advisories the streams gave none. `max_cvss` refuses an unscored
    /// advisory until an entry here names it.
    #[serde(default)]
    pub advisory_scores: Vec<AdvisoryScore>,

    /// `sha256:` and the hex digest of the file's bytes, as loaded. The audit log records it
    /// with every pinned decision, so a replay can find the policy a verdict was reached
    /// under. Not a key in the file.
    #[serde(skip)]
    pub digest: String,
}

impl Policy {
    /// Parse a policy document.
    pub fn parse(source: &str) -> Result<Self, PolicyError> {
        let probe: VersionProbe =
            serde_saphyr::from_str(source).map_err(|e| PolicyError::Invalid(e.to_string()))?;
        match probe.version {
            Some(VersionValue::Number(v)) if v == i64::from(SUPPORTED_VERSION) => {}
            other => {
                return Err(PolicyError::UnsupportedVersion {
                    found: describe_version(other),
                    supported: SUPPORTED_VERSION,
                });
            }
        }

        let mut policy: Self =
            serde_saphyr::from_str(source).map_err(|e| PolicyError::Invalid(e.to_string()))?;
        policy.digest = digest_of(source);
        policy.check_on_off_settings()?;
        policy.check_package_expiry_shape()?;
        policy.check_selectors()?;
        policy.check_denials()?;
        policy.check_advisory_scores()?;
        Ok(policy)
    }

    /// Read and parse a policy file.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let source = std::fs::read_to_string(path).map_err(|source| PolicyError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&source)
    }

    /// `install_scripts`, `kev`, `yanked`, `deprecated` and `provenance` take `block` or
    /// `allow`, and nothing else.
    ///
    /// Refused rather than silently treated as one of the two. `quarantine` means "refused
    /// now, allowed later", and neither of these lapses: waiting does not change whether a
    /// package has an install script or a known-exploited vulnerability.
    /// [`Policy::provenance_window_days`] as a duration.
    pub fn provenance_window(&self) -> jiff::SignedDuration {
        window_of(self.provenance_window_days)
    }

    /// Whether any cooldown is in force, globally or in a package entry.
    pub fn uses_cooldown(&self) -> bool {
        self.cooldown_days > 0
            || self
                .packages
                .iter()
                .any(|entry| entry.set.cooldown_days.is_some_and(|days| days > 0))
    }

    /// Whether any check reads publish times: a cooldown, or `provenance`, which compares a
    /// version with the one published before it. An exception can only loosen, so
    /// `provenance: allow` at the top level means no package is checked.
    ///
    /// Gates the full-packument fetch: publish times are only in the full document, and
    /// fetching it is 1.7x to 3.6x the bytes plus a request the client never made. An
    /// operator who has turned neither check on pays none of that.
    pub fn needs_publish_times(&self) -> bool {
        self.uses_cooldown() || self.provenance == Action::Block
    }

    /// Every denial names one version, in its purl, or a VERS range, in `version`, or the
    /// file does not load.
    ///
    /// A denial with no version would match nothing. Refusing it at load is the difference
    /// between a policy that is wrong and a policy that is silently doing nothing.
    fn check_denials(&self) -> Result<(), PolicyError> {
        for (i, denial) in self.denials.iter().enumerate() {
            let at = format!("denials[{i}]");
            match selector::Canonical::of_denial(&denial.purl, denial.version.as_deref()) {
                Ok(_) => {}
                Err(selector::SelectorError::NoVersion) => {
                    return Err(PolicyError::DenialNeedsAVersion {
                        at,
                        purl: denial.purl.clone(),
                    });
                }
                Err(source) => return Err(PolicyError::UnreadableDenial { at, source }),
            }
        }
        Ok(())
    }

    /// Each `advisory_scores` entry gives a CVSS score, says when it stops being true, and is
    /// the only entry for its id.
    ///
    /// Every entry loosens: without it the advisory is refused. So every entry carries
    /// `expires` or `permanent: true`, which a `packages` entry needs only when it loosens.
    fn check_advisory_scores(&self) -> Result<(), PolicyError> {
        for (i, score) in self.advisory_scores.iter().enumerate() {
            let at = AdvisoryScore::label(i);
            if !crate::intel::Score::in_range(score.cvss) {
                return Err(PolicyError::ScoreOutOfRange {
                    at,
                    found: score.cvss,
                });
            }
            match (score.expires, score.permanent) {
                (Some(_), true) => return Err(PolicyError::BothDatedAndPermanent { at }),
                (None, false) => return Err(PolicyError::UndatedScore { at }),
                _ => {}
            }
            if let Some(first) = self.advisory_scores[..i]
                .iter()
                .position(|s| s.advisory_id == score.advisory_id)
            {
                return Err(PolicyError::DuplicateScore {
                    at,
                    first: AdvisoryScore::label(first),
                    advisory_id: score.advisory_id.clone(),
                });
            }
        }
        Ok(())
    }

    fn check_on_off_settings(&self) -> Result<(), PolicyError> {
        let mut checked: Vec<(String, Action)> = vec![
            ("install_scripts".to_owned(), self.install_scripts),
            ("kev".to_owned(), self.kev),
            ("yanked".to_owned(), self.yanked),
            ("deprecated".to_owned(), self.deprecated),
            ("provenance".to_owned(), self.provenance),
        ];
        for (i, entry) in self.packages.iter().enumerate() {
            if let Some(action) = entry.set.install_scripts {
                checked.push((format!("packages[{i}].set.install_scripts"), action));
            }
            if let Some(action) = entry.set.kev {
                checked.push((format!("packages[{i}].set.kev"), action));
            }
            if let Some(action) = entry.set.yanked {
                checked.push((format!("packages[{i}].set.yanked"), action));
            }
            if let Some(action) = entry.set.deprecated {
                checked.push((format!("packages[{i}].set.deprecated"), action));
            }
            if let Some(action) = entry.set.provenance {
                checked.push((format!("packages[{i}].set.provenance"), action));
            }
        }
        for (at, found) in checked {
            if found == Action::Quarantine {
                return Err(PolicyError::NotAnOnOffSetting { at, found });
            }
        }
        Ok(())
    }

    /// `permanent: true` is the explicit alternative to `expires`, not a companion.
    ///
    /// An entry carrying both says two different things about when it stops being true,
    /// and whichever one the code happened to read would be a silent choice.
    fn check_package_expiry_shape(&self) -> Result<(), PolicyError> {
        for (i, rule) in self.packages.iter().enumerate() {
            if rule.permanent && rule.expires.is_some() {
                return Err(PolicyError::BothDatedAndPermanent {
                    at: packages::label(i),
                });
            }
        }
        Ok(())
    }

    /// Every selector is written in a shape containment can be decided on, and no two
    /// entries leave most-specific-wins without an answer.
    ///
    /// At load, because the request that would expose an unordered pair may be months
    /// away and the file is in front of the operator now.
    fn check_selectors(&self) -> Result<(), PolicyError> {
        let mut canonical = Vec::with_capacity(self.packages.len());
        for (i, rule) in self.packages.iter().enumerate() {
            canonical.push(selector::Canonical::of(&rule.selector).map_err(|source| {
                PolicyError::BadSelector {
                    at: format!("packages[{i}].match"),
                    source,
                }
            })?);
        }
        selector::check_overlaps(&canonical).map_err(PolicyError::Overlapping)
    }

    /// What each denial refuses, as a selector. Parsing has already refused a denial that
    /// does not read, so this cannot fail.
    pub fn denial_selectors(&self) -> Vec<selector::Canonical> {
        self.denials
            .iter()
            .map(|denial| {
                selector::Canonical::of_denial(&denial.purl, denial.version.as_deref())
                    .expect("a policy that loaded has readable denials")
            })
            .collect()
    }

    /// Every package selector, canonicalised. Parsing has already refused the shapes that
    /// cannot be canonicalised, so this cannot fail.
    pub fn selectors(&self) -> Vec<selector::Canonical> {
        self.packages
            .iter()
            .map(|rule| {
                selector::Canonical::of(&rule.selector)
                    .expect("a policy that loaded has canonicalisable selectors")
            })
            .collect()
    }
}

/// What the version line said, for an operator who has to go and look at it.
fn describe_version(found: Option<VersionValue>) -> String {
    match found {
        None => "absent".to_owned(),
        Some(VersionValue::Number(v)) => v.to_string(),
        Some(VersionValue::Other(s)) => s,
    }
}

/// A calendar date an exception runs out on.
///
/// Parsed at load, so a policy that carries an unreadable date is refused rather than
/// loaded with an entry whose expiry silently never arrives.
///
/// A plain calendar date, not an instant: `expires: "2026-11-30"` is a day, and which
/// second of it the entry lapses on is not a question a policy file should have to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpiryDate(pub jiff::civil::Date);

impl fmt::Display for ExpiryDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ExpiryDate {
    /// Whether this has run out by `as_of`.
    ///
    /// The date itself is the last day it is in force, so an entry expiring on the 30th is
    /// still in force on the 30th. An operator writing a date means "until then".
    pub fn has_passed(self, as_of: jiff::civil::Date) -> bool {
        self.0 < as_of
    }
}

impl<'de> Deserialize<'de> for ExpiryDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl Visitor<'_> for V {
            type Value = ExpiryDate;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a calendar date written as YYYY-MM-DD")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ExpiryDate, E> {
                v.parse::<jiff::civil::Date>().map(ExpiryDate).map_err(|e| {
                    E::custom(format!("`{v}` is not a date written as YYYY-MM-DD: {e}"))
                })
            }
        }

        deserializer.deserialize_str(V)
    }
}

/// Permanent and absolute. There is no `expires` field, so an expiring denial is
/// unrepresentable rather than merely discouraged, and no exception can undo one.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    /// The package, with `@version` when the denial is for one version.
    pub purl: String,
    /// A VERS range, when the purl has no `@version`.
    #[serde(default)]
    pub version: Option<String>,
    pub reason: String,
}

/// What a check decides about a package.
///
/// `allow < quarantine < block`. There is no `warn`: nothing delivers-with-a-concern.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Refused now, allowed later. Lapses without anyone doing anything, which is what
    /// separates it from `Block`.
    Quarantine,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One exception. May only loosen.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageRule {
    #[serde(rename = "match")]
    pub selector: Selector,
    pub set: SetBlock,
    /// Always required, on every entry. A required field cannot be ignored the way a
    /// warning can, which is why this tier asks for one instead of warning.
    pub reason: String,
    #[serde(default)]
    pub expires: Option<ExpiryDate>,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub added_by: Option<String>,
}

/// A CVSS score for an advisory that has none.
///
/// Used only while the advisory has no stored score. Once a stream scores it, the stream's
/// score is compared and this entry does nothing.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryScore {
    /// Matched against an advisory's id and each of its aliases.
    pub advisory_id: String,
    pub cvss: f64,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<ExpiryDate>,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub added_by: Option<String>,
}

impl AdvisoryScore {
    /// How an entry is named in messages.
    pub fn label(index: usize) -> String {
        format!("advisory_scores[{index}]")
    }

    /// Whether it is still in force on `as_of`.
    pub fn in_force(&self, as_of: jiff::civil::Date) -> bool {
        !self.expires.is_some_and(|e| e.has_passed(as_of))
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    /// Required on every selector. Package names do not collide meaningfully across
    /// registries, npm `requests` and PyPI `requests` being unrelated projects, so a
    /// cross-ecosystem match is almost always a mistake.
    pub ecosystem: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub has_install_scripts: Option<bool>,
}

/// What an exception changes for the packages it matches.
#[derive(Debug, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct SetBlock {
    #[serde(default)]
    pub cooldown_days: Option<u32>,
    #[serde(default)]
    pub kev: Option<Action>,
    #[serde(default)]
    pub install_scripts: Option<Action>,
    #[serde(default)]
    pub yanked: Option<Action>,
    #[serde(default)]
    pub deprecated: Option<Action>,
    #[serde(default)]
    pub provenance: Option<Action>,
    /// Specific vulnerability advisories to ignore for this package, by id. An id matches an
    /// advisory's own id or any of its aliases, so a CVE id reaches a `GHSA-` advisory.
    ///
    /// The only exception keyed by something other than the package itself. Ignoring a
    /// named advisory is narrower than raising `max_cvss`, which would apply to every advisory
    /// the package carries and every one it acquires later.
    #[serde(default)]
    pub vuln_advisory_ids: Vec<String>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn parse(body: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!("version: 1\n{body}"))
    }

    #[test]
    fn the_smallest_valid_policy_is_a_version() {
        let policy = parse("").unwrap();
        assert_eq!(policy.version, SUPPORTED_VERSION);
        assert!(policy.denials.is_empty());
        assert!(policy.packages.is_empty());
    }

    /// A policy that says nothing gets the shipped settings, and both checks block.
    /// An operator who has not thought about install scripts is better served by the
    /// strict answer, and turning one off is a line they have to write.
    #[test]
    fn a_policy_that_says_nothing_blocks_every_on_off_check() {
        let policy = parse("").unwrap();
        assert_eq!(policy.cooldown_days, DEFAULT_COOLDOWN_DAYS);
        assert_eq!(policy.max_cvss, DEFAULT_MAX_CVSS);
        assert_eq!(policy.install_scripts, Action::Block);
        assert_eq!(policy.kev, Action::Block);
        assert_eq!(policy.yanked, Action::Block);
        assert_eq!(policy.provenance, Action::Block);
        assert_eq!(
            policy.provenance_window_days,
            DEFAULT_PROVENANCE_WINDOW_DAYS
        );
        assert_eq!(
            policy.provenance_window(),
            jiff::SignedDuration::from_hours(168)
        );
        // npm installs a deprecated version after a warning, and publishers deprecate whole
        // release lines, so this one is a choice an operator makes rather than a default.
        assert_eq!(policy.deprecated, Action::Allow);
    }

    #[test]
    fn every_setting_can_be_given_a_value() {
        let policy = parse(
            "cooldown_days: 14\nmax_cvss: 3.9\ninstall_scripts: allow\nkev: allow\nyanked: allow\n\
             deprecated: block\nprovenance: allow\nprovenance_window_days: 30\n",
        )
        .unwrap();
        assert_eq!(policy.cooldown_days, 14);
        assert_eq!(policy.max_cvss, 3.9);
        assert_eq!(policy.install_scripts, Action::Allow);
        assert_eq!(policy.yanked, Action::Allow);
        assert_eq!(policy.deprecated, Action::Block);
        assert_eq!(policy.provenance, Action::Allow);
        assert_eq!(policy.provenance_window_days, 30);
        assert_eq!(policy.kev, Action::Allow);
    }

    /// `install_scripts` and `kev` take `block` or `allow`. `quarantine` means "refused
    /// now, allowed later", and neither lapses: waiting does not change whether a package
    /// has an install script or a known-exploited vulnerability.
    #[test]
    fn a_setting_that_cannot_lapse_refuses_quarantine() {
        for (at, body) in [
            ("install_scripts", "install_scripts: quarantine\n"),
            ("kev", "kev: quarantine\n"),
            ("provenance", "provenance: quarantine\n"),
        ] {
            let error = parse(body).unwrap_err();
            assert!(
                matches!(error, PolicyError::NotAnOnOffSetting { .. })
                    && error.to_string().contains(at),
                "{at}: {error}"
            );
        }
    }

    /// And so does an exception that sets one.
    #[test]
    fn an_exception_cannot_quarantine_either() {
        for key in ["kev", "provenance"] {
            let error = parse(&format!(
                "packages:\n  - match: {{ ecosystem: npm, name: x }}\n    \
                 set: {{ {key}: quarantine }}\n    reason: r\n    permanent: true\n",
            ))
            .unwrap_err();
            assert!(matches!(error, PolicyError::NotAnOnOffSetting { .. }));
            assert!(
                error
                    .to_string()
                    .contains(&format!("packages[0].set.{key}")),
                "{error}"
            );
        }
    }

    /// `cooldown_days` is the one setting that can quarantine, and it is a number rather
    /// than an action, so there is nothing to refuse.
    #[test]
    fn the_shipped_example_parses() {
        let policy = Policy::load(Path::new("examples/policy.yaml")).unwrap();
        assert_eq!(policy.version, SUPPORTED_VERSION);
        assert_eq!(policy.denials.len(), 2);
        assert_eq!(policy.packages.len(), 3);
    }

    /// `deny_unknown_fields` at every depth, which is what a typo'd key in a security
    /// policy needs. `expiress` where `expires` was meant is an entry that never expires.
    #[test]
    fn an_unknown_key_is_refused_at_every_depth() {
        let cases = [
            ("top level", "cooldown_dayz: 7\n"),
            (
                "inside a selector",
                "packages:\n  - match: { ecosystem: npm, nmae: x }\n    set: {}\n    reason: r\n",
            ),
            (
                "inside a set block",
                "packages:\n  - match: { ecosystem: npm, name: x }\n    \
                 set: { cooldown_dayz: 0 }\n    reason: r\n",
            ),
            (
                "on an entry",
                "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    \
                 reason: r\n    expiress: \"2026-11-30\"\n",
            ),
            (
                "on a denial",
                "denials:\n  - purl: pkg:npm/x\n    resaon: r\n",
            ),
        ];
        for (depth, body) in cases {
            let error = parse(body).unwrap_err();
            assert!(
                matches!(error, PolicyError::Invalid(_)),
                "{depth}: expected a schema error, got {error}"
            );
        }
    }

    /// Version 1 is closed: `docs/engineering_decisions/policy-schema-v1-frozen.md`.
    ///
    /// Refusing an unknown key, serde names every key the struct accepts, so this pins the
    /// key set at each of the five levels. A key added, removed or renamed fails here, and
    /// belongs in `version: 2`.
    #[test]
    fn the_version_1_key_set_is_closed() {
        let cases: [(&str, &str, &[&str]); 6] = [
            (
                "top level",
                "unknown: 1\n",
                &[
                    "version",
                    "cooldown_days",
                    "max_cvss",
                    "install_scripts",
                    "kev",
                    "deprecated",
                    "yanked",
                    "provenance",
                    "provenance_window_days",
                    "denials",
                    "packages",
                    "advisory_scores",
                ],
            ),
            (
                "an advisory_scores entry",
                "advisory_scores:\n  - advisory_id: x\n    unknown: 1\n",
                &[
                    "advisory_id",
                    "cvss",
                    "reason",
                    "expires",
                    "permanent",
                    "added_by",
                ],
            ),
            (
                "a denial",
                "denials:\n  - purl: pkg:npm/x@1.0.0\n    unknown: r\n",
                &["purl", "version", "reason"],
            ),
            (
                "a packages entry",
                "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    \
                 reason: r\n    unknown: 1\n",
                &["match", "set", "reason", "expires", "permanent", "added_by"],
            ),
            (
                "match",
                "packages:\n  - match: { ecosystem: npm, unknown: x }\n    set: {}\n    \
                 reason: r\n",
                &[
                    "ecosystem",
                    "name",
                    "purl",
                    "version",
                    "has_install_scripts",
                ],
            ),
            (
                "set",
                "packages:\n  - match: { ecosystem: npm, name: x }\n    set: { unknown: 1 }\n    \
                 reason: r\n",
                &[
                    "cooldown_days",
                    "kev",
                    "install_scripts",
                    "yanked",
                    "deprecated",
                    "provenance",
                    "vuln_advisory_ids",
                ],
            ),
        ];
        for (level, body, keys) in cases {
            let error = parse(body).unwrap_err().to_string();
            assert_eq!(
                accepted_keys(&error),
                keys,
                "{level}: the keys changed, which version 1 does not allow: {error}"
            );
        }
    }

    /// The keys an unknown-field error lists, whichever way it joins them: `expected one
    /// of a, b, c` or `expected a or b`, with or without backticks.
    fn accepted_keys(error: &str) -> Vec<String> {
        let listed = error
            .split("expected ")
            .nth(1)
            .and_then(|rest| rest.lines().next())
            .unwrap_or_default();
        listed
            .trim_start_matches("one of ")
            .replace(" or ", ", ")
            .split(", ")
            .map(|key| key.trim().trim_matches('`').to_owned())
            .filter(|key| !key.is_empty())
            .collect()
    }

    /// An action name that is not one of the three is refused rather than read as the
    /// nearest thing. `blcok` would otherwise be a setting that does nothing.
    #[test]
    fn an_action_that_is_not_in_the_lattice_is_refused() {
        assert!(matches!(
            parse("kev: blcok\n").unwrap_err(),
            PolicyError::Invalid(_)
        ));
        // `warn` left the lattice: nothing delivers-with-a-concern.
        assert!(matches!(
            parse("kev: warn\n").unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A document written against another schema version is refused before its body is
    /// judged, and the refusal quotes both numbers.
    #[test]
    fn a_version_this_build_does_not_understand_is_refused_by_number() {
        let error = Policy::parse("version: 2\ncooldown_days: 7\n").unwrap_err();
        assert!(matches!(
            error,
            PolicyError::UnsupportedVersion { supported: 1, .. }
        ));
        let text = error.to_string();
        assert!(text.contains('2') && text.contains('1'), "{text}");
    }

    /// A version 2 document whose body does not match version 1's schema still reports
    /// the version, not the first key it happens to be missing.
    #[test]
    fn a_future_version_reports_the_version_rather_than_its_unfamiliar_keys() {
        assert!(matches!(
            Policy::parse("version: 2\nrules:\n  - everything: different\n").unwrap_err(),
            PolicyError::UnsupportedVersion { .. }
        ));
    }

    #[test]
    fn a_version_that_is_missing_or_not_a_number_is_refused_as_it_was_written() {
        for (source, expected) in [
            ("cooldown_days: 7\n", "absent"),
            ("version: \"1\"\n", "`1`"),
            ("version: true\n", "true"),
            // An empty version line says no more than a missing one.
            ("version:\n", "absent"),
            ("version: 1.5\n", "1.5"),
            ("version: -1\n", "-1"),
        ] {
            let error = Policy::parse(source).unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(error, PolicyError::UnsupportedVersion { .. }) && text.contains(expected),
                "expected {expected} in: {text}"
            );
        }
    }

    /// A shape the visitor has no arm for, which is where `expecting` is read.
    #[test]
    fn a_value_of_the_wrong_shape_says_what_was_expected() {
        let error = Policy::parse("version: [1]\n").unwrap_err();
        assert!(
            error.to_string().contains("policy schema version number"),
            "{error}"
        );
    }

    /// `ecosystem` is required on every selector. An entry that does not say which
    /// ecosystem it is about would apply to that name in all of them.
    #[test]
    fn a_package_selector_without_an_ecosystem_is_refused() {
        assert!(matches!(
            parse("packages:\n  - match: { name: lodash }\n    set: {}\n    reason: r\n")
                .unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A denial has no `expires` field at all, so an expiring denial is unrepresentable
    /// rather than discouraged.
    #[test]
    fn a_denial_is_permanent_by_having_nowhere_to_put_an_expiry() {
        assert!(matches!(
            parse("denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: m\n    expires: \"2026-01-01\"\n")
                .unwrap_err(),
            PolicyError::Invalid(_)
        ));
        let policy =
            parse("denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: malware\n").unwrap();
        assert_eq!(policy.denials[0].reason, "malware");
    }

    /// A denial with no version matches nothing, so the file does not load.
    ///
    /// The failure this prevents is silent: an operator writes the package they mean,
    /// reads it back in the file, and it denies nobody.
    #[test]
    fn a_denial_that_names_no_version_is_refused_at_load() {
        let err = parse("denials:\n  - purl: pkg:npm/evil\n    reason: malware\n")
            .expect_err("a versionless denial must not load");
        let message = err.to_string();
        assert!(message.contains("denials[0]"), "{message}");
        assert!(message.contains("names no version"), "{message}");
        assert!(message.contains("pkg:npm/evil@<version>"), "{message}");

        // The same denial with a version loads, and so does one with a VERS range.
        assert!(parse("denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: malware\n").is_ok());
        assert!(
            parse("denials:\n  - purl: pkg:npm/evil\n    version: \"vers:npm/<2.0.0\"\n    reason: m\n")
                .is_ok()
        );
        let both = parse(
            "denials:\n  - purl: pkg:npm/evil@1.0.0\n    version: \"vers:npm/<2.0.0\"\n    reason: m\n",
        )
        .expect_err("a version written twice must not load");
        assert!(both.to_string().contains("denials[0]"), "{both}");
        assert!(both.to_string().contains("Write it once"), "{both}");
    }

    #[test]
    fn a_denial_whose_purl_cannot_be_read_is_refused_by_name() {
        let err = parse("denials:\n  - purl: not-a-purl\n    reason: malware\n")
            .expect_err("an unreadable denial must not load");
        assert!(err.to_string().contains("denials[0]"), "{err}");
    }

    /// A scoped denial is the case the parser exists for: `%40babel` and `@babel` are the
    /// same package, and the first is what this codebase's own `Display` emits.
    #[test]
    fn a_scoped_denial_loads_written_either_way() {
        for spelling in ["pkg:npm/%40babel/core@1.0.0", "pkg:npm/@babel/core@1.0.0"] {
            assert!(
                parse(&format!("denials:\n  - purl: {spelling}\n    reason: m\n")).is_ok(),
                "{spelling} should load"
            );
        }
    }

    /// `permanent: true` is the alternative to `expires`, not a companion.
    #[test]
    fn a_package_entry_cannot_be_both_dated_and_permanent() {
        let base = "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    \
                    reason: r\n";
        assert!(matches!(
            parse(&format!(
                "{base}    expires: \"2026-11-30\"\n    permanent: true\n"
            ))
            .unwrap_err(),
            PolicyError::BothDatedAndPermanent { .. }
        ));
        assert!(parse(&format!("{base}    expires: \"2026-11-30\"\n")).is_ok());
        assert!(parse(&format!("{base}    permanent: true\n")).is_ok());
    }

    const SCORE: &str = "advisory_scores:\n  - advisory_id: GHSA-x\n    reason: r\n";

    #[test]
    fn an_advisory_score_is_a_cvss_score() {
        let scored = |cvss: &str| parse(&format!("{SCORE}    cvss: {cvss}\n    permanent: true\n"));
        for good in ["0.0", "6.9", "10.0"] {
            assert!(scored(good).is_ok(), "{good}");
        }
        for bad in ["-0.1", "10.1"] {
            let error = scored(bad).unwrap_err();
            assert!(
                matches!(error, PolicyError::ScoreOutOfRange { .. }),
                "{bad}: {error}"
            );
        }
        assert_eq!(
            scored("10.1").unwrap_err().to_string(),
            "advisory_scores[0].cvss is 10.1, and a CVSS score is 0.0 to 10.0"
        );
    }

    /// Every entry lets a refused advisory past `max_cvss`, so every entry says when it
    /// stops being true.
    #[test]
    fn an_advisory_score_is_dated_or_permanent_and_not_both() {
        let base = format!("{SCORE}    cvss: 5.0\n");
        let undated = parse(&base).unwrap_err();
        assert!(
            matches!(undated, PolicyError::UndatedScore { .. }),
            "{undated}"
        );
        assert!(
            undated
                .to_string()
                .starts_with("advisory_scores[0] carries neither `expires` nor `permanent: true`"),
            "{undated}"
        );
        assert!(matches!(
            parse(&format!(
                "{base}    expires: \"2026-11-30\"\n    permanent: true\n"
            ))
            .unwrap_err(),
            PolicyError::BothDatedAndPermanent { .. }
        ));
        assert!(parse(&format!("{base}    expires: \"2026-11-30\"\n")).is_ok());
        assert!(parse(&format!("{base}    permanent: true\n")).is_ok());
    }

    #[test]
    fn an_advisory_id_is_scored_once() {
        let entry = |id: &str| {
            format!("  - {{ advisory_id: {id}, cvss: 5.0, reason: r, permanent: true }}\n")
        };
        let error = parse(&format!(
            "advisory_scores:\n{}{}{}",
            entry("GHSA-a"),
            entry("GHSA-b"),
            entry("GHSA-a")
        ))
        .unwrap_err();
        assert!(
            matches!(
                &error,
                PolicyError::DuplicateScore { at, first, advisory_id }
                    if at == "advisory_scores[2]"
                        && first == "advisory_scores[0]"
                        && advisory_id == "GHSA-a"
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("scores `GHSA-a`, which advisory_scores[0] already scores"),
            "{error}"
        );
        assert!(
            parse(&format!(
                "advisory_scores:\n{}{}",
                entry("GHSA-a"),
                entry("GHSA-b")
            ))
            .is_ok()
        );
    }

    /// The `exceptions` block was replaced by `packages`: one syntax, one code path.
    #[test]
    fn the_exceptions_block_no_longer_exists() {
        let error = parse("exceptions:\n  - match: { ecosystem: npm, name: x }\n").unwrap_err();
        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(error.to_string().contains("exceptions"), "{error}");
    }

    /// There is no floor tier and no per-ecosystem settings. A config written against the
    /// old shape is told which key is gone rather than having it ignored.
    #[test]
    fn the_tiers_that_were_removed_are_refused_by_name() {
        for key in ["floor", "ecosystems", "defaults"] {
            let error = parse(&format!("{key}:\n  npm:\n    known_malware: block\n")).unwrap_err();
            assert!(
                matches!(error, PolicyError::Invalid(_)) && error.to_string().contains(key),
                "`{key}`: {error}"
            );
        }
        // `provenance_required` was replaced by `provenance`, which does not require any.
        assert!(matches!(
            parse("provenance_required: true\n").unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A date that cannot be read is refused at load, not carried as an entry whose
    /// expiry silently never arrives.
    #[test]
    fn an_expiry_that_is_not_a_date_is_refused() {
        for bad in ["soon", "30-11-2026", "2026-13-01", "2026-11-31"] {
            let error = parse(&format!(
                "packages:\n  - match: {{ ecosystem: npm, name: x }}\n    set: {{}}\n    \
                 reason: r\n    expires: \"{bad}\"\n"
            ))
            .unwrap_err();
            assert!(
                matches!(error, PolicyError::Invalid(_)) && error.to_string().contains(bad),
                "`{bad}` should be refused by name: {error}"
            );
        }
    }

    #[test]
    fn a_readable_expiry_is_kept_as_a_date() {
        let policy = parse(
            "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: r\n    \
             expires: \"2026-11-30\"\n",
        )
        .unwrap();
        let expires = policy.packages[0].expires.unwrap();
        assert_eq!(expires.to_string(), "2026-11-30");
        assert!(!expires.has_passed(jiff::civil::date(2026, 11, 30)));
        assert!(expires.has_passed(jiff::civil::date(2026, 12, 1)));
    }

    /// §5's most-specific-wins needs every pair to be orderable, and a pair that is not is
    /// refused at load: the request that would expose it may be months away.
    #[test]
    fn two_entries_that_cannot_be_ordered_are_refused_at_load() {
        let error = parse(
            "packages:\n  - match: { ecosystem: npm, name: \"a*\", has_install_scripts: true }\n    \
             set: {}\n    reason: r\n  - match: { ecosystem: npm, name: \"ab*\" }\n    \
             set: {}\n    reason: r\n",
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::Overlapping(_)));
        assert!(
            error.to_string().contains("neither is more specific"),
            "{error}"
        );
    }

    #[test]
    fn the_same_entry_written_twice_is_refused_at_load() {
        let error = parse(
            "packages:\n  - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: first\n  \
             - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: second\n",
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::Overlapping(_)));
        let text = error.to_string();
        assert!(
            text.contains("packages[0]") && text.contains("packages[1]"),
            "{text}"
        );
    }

    /// A chain of strictly narrowing selectors is what most-specific-wins is for.
    #[test]
    fn entries_that_narrow_each_other_are_accepted() {
        assert!(
            parse(
                "packages:\n  - match: { ecosystem: npm, name: \"@mycompany/foo\" }\n    \
                 set: {}\n    reason: r\n  - match: { ecosystem: npm, name: \"@mycompany/*\" }\n    \
                 set: {}\n    reason: r\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_selector_that_cannot_be_compared_names_its_entry() {
        let error = parse(
            "packages:\n  - match: { ecosystem: npm, name: \"a*b\" }\n    set: {}\n    reason: r\n",
        )
        .unwrap_err();
        assert!(matches!(error, PolicyError::BadSelector { .. }));
        let text = error.to_string();
        assert!(
            text.contains("packages[0].match") && text.contains("a*b"),
            "{text}"
        );
    }

    #[test]
    fn the_shipped_examples_selectors_are_all_orderable() {
        let policy = Policy::load(Path::new("examples/policy.yaml")).unwrap();
        assert_eq!(policy.selectors().len(), policy.packages.len());
    }

    #[test]
    fn an_action_prints_the_name_it_is_written_with() {
        assert_eq!(Action::Allow.to_string(), "allow");
        assert_eq!(Action::Quarantine.to_string(), "quarantine");
        assert_eq!(Action::Block.to_string(), "block");
    }

    #[test]
    fn a_file_that_is_not_there_names_itself() {
        let error = Policy::load(Path::new("does/not/exist.yaml")).unwrap_err();
        assert!(matches!(error, PolicyError::Unreadable { .. }));
        assert!(error.to_string().contains("does/not/exist.yaml"));
    }

    #[test]
    fn malformed_yaml_is_reported_as_invalid_rather_than_panicking() {
        assert!(matches!(
            Policy::parse("version: 1\npackages:\n\t- x\n").unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// Each way an entry or a version is written wrong says so in its own words.
    #[test]
    fn a_policy_written_wrong_says_how() {
        let both = parse(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { kev: allow }\n    \
             reason: reviewed\n    expires: \"2026-12-01\"\n    permanent: true\n",
        )
        .expect_err("both");
        assert!(
            both.to_string()
                .contains("sets both `expires` and `permanent: true`"),
            "{both}"
        );
        let huge = Policy::parse("version: 18446744073709551615\n").expect_err("too large");
        assert!(huge.to_string().contains("18446744073709551615"), "{huge}");
        let not_a_date = serde_json::from_str::<ExpiryDate>("5").expect_err("a number");
        assert!(
            not_a_date
                .to_string()
                .contains("a calendar date written as YYYY-MM-DD"),
            "{not_a_date}"
        );
    }

    /// An entry's own cooldown is a cooldown, and its yanked and deprecated settings are
    /// on-off settings like the global ones.
    #[test]
    fn an_entry_can_set_a_cooldown_yanked_and_deprecated() {
        let policy = parse(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { cooldown_days: 5, yanked: allow, deprecated: allow }\n    \
             reason: reviewed\n    expires: \"2026-12-01\"\n",
        )
        .expect("loads");
        assert!(policy.uses_cooldown());
        let refused = parse(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { deprecated: quarantine }\n    reason: reviewed\n    expires: \"2026-12-01\"\n",
        )
        .expect_err("not on or off");
        assert!(
            refused.to_string().contains("packages[0].set.deprecated"),
            "{refused}"
        );
        let refused = parse(
            "packages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { yanked: quarantine }\n    reason: reviewed\n    expires: \"2026-12-01\"\n",
        )
        .expect_err("not on or off");
        assert!(
            refused.to_string().contains("packages[0].set.yanked"),
            "{refused}"
        );
    }
}
