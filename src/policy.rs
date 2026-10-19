//! The policy document: its schema, and loading it. Every struct refuses unknown fields,
//! and no field is `#[serde(untagged)]`.
//!
//! See docs/engineering_decisions/0030-policy-schema-v1-frozen.md.

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
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The only document version this understands; any other is refused.
pub const SUPPORTED_VERSION: u32 = 1;

/// Today, in UTC, so every replica and command judges an expiry on the same day.
pub fn today() -> jiff::civil::Date {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
}

/// The shipped default for `cooldown_days`.
pub const DEFAULT_COOLDOWN_DAYS: u32 = 7;
pub const DEFAULT_MAX_CVSS: f64 = 6.9;
/// The shipped default for `provenance_window_days`, the cooldown's own.
pub const DEFAULT_PROVENANCE_WINDOW_DAYS: u32 = 7;
/// The shipped default for `provenance_half_life`, from docs/risk-score-plan.md step 6.
pub const DEFAULT_PROVENANCE_HALF_LIFE: u32 = 16;

fn default_cooldown_days() -> u32 {
    DEFAULT_COOLDOWN_DAYS
}
fn default_provenance_window_days() -> u32 {
    DEFAULT_PROVENANCE_WINDOW_DAYS
}
fn default_provenance_half_life() -> u32 {
    DEFAULT_PROVENANCE_HALF_LIFE
}
fn default_risk_threshold() -> u32 {
    decide::DEFAULT_RISK_THRESHOLD
}
fn default_max_cvss() -> f64 {
    DEFAULT_MAX_CVSS
}
/// `sha256:` and the hex digest of a policy file's bytes. See [`Policy::digest`].
pub fn digest_of(source: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{}",
        crate::util::hex(&Sha256::digest(source.as_bytes()))
    )
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
    /// `risk_threshold` is 0, at which every version would be refused.
    ZeroThreshold,
    /// `provenance_half_life` is 0, under which no earlier version weighs.
    ZeroHalfLife,
    /// `signal_weights` weighs the rule of a check `setting` turns off.
    WeighedButAllowed { setting: &'static str, rule: String },
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
            Self::ZeroThreshold => write!(
                f,
                "risk_threshold is 0, at which every version would be refused; it is at \
                 least 1"
            ),
            Self::ZeroHalfLife => write!(
                f,
                "provenance_half_life is 0, under which no earlier version weighs; it is at \
                 least 1"
            ),
            Self::WeighedButAllowed { setting, rule } => write!(
                f,
                "signal_weights weighs `{rule}`, and `{setting}: allow` turns that check off, \
                 so the weight is never added. Set `{setting}: block` to weigh it"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Just the version, read before the body so another version is refused as that.
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    version: Option<VersionValue>,
}

/// Whatever the version line held, so the refusal can quote it back.
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

            fn visit_str<E>(self, v: &str) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(format!("`{v}`")))
            }

            fn visit_bool<E>(self, v: bool) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(v.to_string()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<VersionValue, E> {
                Ok(VersionValue::Other(v.to_string()))
            }
        }

        deserializer.deserialize_any(V)
    }
}

/// Each detector rule's weight in a risk score, by [`crate::analysis::detector::key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignalWeights(BTreeMap<String, u32>);

/// A rule built in, or a `detector.rule` that `detector::KNOWN` lists; nothing else.
impl<'de> Deserialize<'de> for SignalWeights {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let set = BTreeMap::<String, u32>::deserialize(deserializer)?;
        if let Some(unknown) = set
            .keys()
            .find(|key| !crate::analysis::detector::knows(key))
        {
            return Err(serde::de::Error::unknown_field(
                unknown,
                &crate::analysis::detector::BUILT_IN_RULES,
            ));
        }
        Ok(Self(set))
    }
}

/// What a rule weighs when the policy does not say.
pub const DEFAULT_SIGNAL_WEIGHT: u32 = 1;

impl SignalWeights {
    /// The weight of the rule `key` names, its [`crate::signal::default_weight`] unless set.
    pub fn of(&self, key: &str) -> u32 {
        self.set(key)
            .unwrap_or_else(|| crate::signal::default_weight(key))
    }

    /// The weight the policy gives the rule `key`, `None` when it gives none.
    pub fn set(&self, key: &str) -> Option<u32> {
        self.0.get(key).copied()
    }

    /// Weights set as `pairs`, of a key and its weight, for a test.
    #[cfg(test)]
    pub fn of_pairs(pairs: &[(&str, u32)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(key, weight)| ((*key).to_owned(), *weight))
                .collect(),
        )
    }
}

/// Global settings, and per-package exceptions to them.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,

    /// How old a package must be before it is served. Produces `quarantine`.
    #[serde(default = "default_cooldown_days")]
    pub cooldown_days: u32,
    /// The highest CVSS score a package may carry and still be served.
    #[serde(default = "default_max_cvss")]
    pub max_cvss: f64,
    /// Whether a package carrying an install script is served. `block` or `allow`.
    #[serde(default = "default_block")]
    pub install_scripts: Action,
    /// Whether a package carrying a known-exploited vulnerability is served.
    #[serde(default = "default_block")]
    pub kev: Action,
    /// Whether a version its publisher deprecated is served. `allow` by default.
    #[serde(default = "default_allow")]
    pub deprecated: Action,
    /// Whether a version the registry withdrew, PyPI's PEP 592 yank, is served.
    #[serde(default = "default_block")]
    pub yanked: Action,
    /// Whether a version whose attestations contradict the versions before it is served.
    #[serde(default = "default_block")]
    pub provenance: Action,
    /// How far back `provenance` looks for versions to compare with, in days.
    #[serde(default = "default_provenance_window_days")]
    pub provenance_window_days: u32,
    /// How many versions back a version's attestation weighs half in `provenance_surprise`.
    #[serde(default = "default_provenance_half_life")]
    pub provenance_half_life: u32,

    #[serde(default)]
    pub denials: Vec<Denial>,
    #[serde(default)]
    pub packages: Vec<PackageRule>,
    /// Scores for advisories the streams gave none, which `max_cvss` otherwise refuses.
    #[serde(default)]
    pub advisory_scores: Vec<AdvisoryScore>,
    /// What each kind of signal adds to a version's risk score.
    #[serde(default)]
    pub signal_weights: SignalWeights,
    /// The risk score a version is refused at.
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: u32,

    /// `sha256:` and the hex digest of the file's bytes, for the audit log. Not a key.
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
        policy.check_weights()?;
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

    /// This policy with `weights` set in `signal_weights`, over what it sets: how a verdict
    /// recorded with its weights is decided again after a default has moved.
    pub fn with_weights(&self, weights: &BTreeMap<String, u32>) -> Self {
        let mut policy = self.clone();
        policy
            .signal_weights
            .0
            .extend(weights.iter().map(|(key, weight)| (key.clone(), *weight)));
        policy
    }

    /// What the rule `key` adds to a risk score: its `signal_weights` entry, else
    /// [`decide::default_weight`] against this threshold.
    pub fn weight_of(&self, key: &str) -> u32 {
        self.signal_weights
            .set(key)
            .unwrap_or_else(|| decide::default_weight(key, self.risk_threshold))
    }

    /// A threshold of at least 1, and no weight for a check the policy sets to `allow`,
    /// which never fails so its weight is never added.
    fn check_weights(&self) -> Result<(), PolicyError> {
        if self.risk_threshold == 0 {
            return Err(PolicyError::ZeroThreshold);
        }
        if self.provenance_half_life == 0 {
            return Err(PolicyError::ZeroHalfLife);
        }
        let off = [
            (
                "install_scripts",
                self.install_scripts,
                &["install_scripts"][..],
            ),
            ("kev", self.kev, &["kev"]),
            ("yanked", self.yanked, &["yanked"]),
            ("deprecated", self.deprecated, &["deprecated"]),
            (
                "provenance",
                self.provenance,
                &[
                    "provenance_unverified",
                    "provenance_dropped",
                    "provenance_identity_changed",
                    "provenance_surprise",
                ],
            ),
        ];
        for (setting, action, rules) in off {
            if action != Action::Allow {
                continue;
            }
            if let Some(rule) = rules
                .iter()
                .find(|rule| self.signal_weights.set(rule).is_some())
            {
                return Err(PolicyError::WeighedButAllowed {
                    setting,
                    rule: (*rule).to_owned(),
                });
            }
        }
        Ok(())
    }

    /// [`Policy::provenance_window_days`] as a duration.
    pub fn provenance_window(&self) -> jiff::SignedDuration {
        window_of(self.provenance_window_days)
    }

    /// The longest cooldown in force, globally or in a package entry, in days.
    pub fn longest_cooldown(&self) -> u32 {
        self.packages
            .iter()
            .filter_map(|entry| entry.set.cooldown_days)
            .fold(self.cooldown_days, u32::max)
    }

    /// Whether any cooldown is in force, globally or in a package entry.
    pub fn uses_cooldown(&self) -> bool {
        self.cooldown_days > 0
            || self
                .packages
                .iter()
                .any(|entry| entry.set.cooldown_days.is_some_and(|days| days > 0))
    }

    /// Whether any check reads publish times, a cooldown or `provenance`, which decides
    /// whether the full packument is fetched.
    pub fn needs_publish_times(&self) -> bool {
        self.uses_cooldown() || self.provenance == Action::Block
    }

    /// Every denial names one version, in its purl, or a VERS range, in `version`.
    /// Returns which denial names neither.
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

    /// Each `advisory_scores` entry gives a CVSS score, says when it stops being true, and
    /// is the only entry for its id. Returns the first that does not.
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

    /// `install_scripts`, `kev`, `yanked`, `deprecated` and `provenance` take `block` or
    /// `allow`, never `quarantine`, since none of them lapses.
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

    /// Every selector is written in a shape containment can be decided on. Returns the first
    /// that is not.
    fn check_selectors(&self) -> Result<(), PolicyError> {
        for (i, rule) in self.packages.iter().enumerate() {
            selector::Canonical::of(&rule.selector).map_err(|source| PolicyError::BadSelector {
                at: format!("packages[{i}].match"),
                source,
            })?;
        }
        Ok(())
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

/// A calendar date an exception runs out on, parsed at load.
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

/// A denial: permanent, with no `expires` field, and no exception undoes one.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    /// The package, with `@version` when the denial is for one version.
    pub purl: String,
    /// A VERS range, when the purl has no `@version`.
    #[serde(default)]
    pub version: Option<String>,
    pub reason: String,
}

/// What a check decides about a package: `allow < quarantine < block`.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Refused now, allowed later, lapsing on its own.
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
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageRule {
    #[serde(rename = "match")]
    pub selector: Selector,
    pub set: SetBlock,
    /// Why the entry exists. Required on every entry.
    pub reason: String,
    #[serde(default)]
    pub expires: Option<ExpiryDate>,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub added_by: Option<String>,
}

/// A CVSS score for an advisory, used only while no stream has scored it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    /// Required on every selector: npm `requests` and PyPI `requests` are different projects.
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
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
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
    /// Advisories to ignore for this package, by their id or any alias.
    #[serde(default)]
    pub ignored_vuln_advisory_ids: Vec<String>,
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

    /// A policy that says nothing gets the shipped settings, which block every on/off check.
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

    /// A setting that cannot lapse refuses `quarantine`.
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
        assert_eq!(policy.denials.len(), 4);
        assert_eq!(policy.packages.len(), 5);
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

    /// A weight is 1 unless set, an advisory's that of its kind, and a whole number.
    #[test]
    fn signal_weights_default_to_1_and_are_whole_numbers() {
        use crate::analysis::detector::BUILT_IN_RULES;
        assert_eq!(parse("").unwrap().signal_weights, SignalWeights::default());
        assert!(
            BUILT_IN_RULES
                .iter()
                .filter(|rule| !crate::signal::ADVISORY_RULES.contains(rule))
                .all(|rule| SignalWeights::default().of(rule) == 1)
        );
        let set = parse("signal_weights: { near_name: 0, source_install_files: 5 }\n")
            .unwrap()
            .signal_weights;
        assert_eq!(
            (
                set.of("near_name"),
                set.of("source_install_files"),
                set.of("new_package")
            ),
            (0, 5, 1)
        );
        for bad in ["-1", "1.5", "high"] {
            assert!(
                parse(&format!("signal_weights: {{ near_name: {bad} }}\n")).is_err(),
                "{bad}"
            );
        }
        let rules = parse(
            "signal_weights: { guarddog.threat-process-hooks: 5, guarddog.bundled_binary: 0 }\n",
        )
        .unwrap()
        .signal_weights;
        assert_eq!(rules.of("guarddog.threat-process-hooks"), 5);
        assert_eq!(rules.of("guarddog.bundled_binary"), 0);
        assert_eq!(rules.of("guarddog.typosquatting"), 1, "unset");
        for unknown in [
            "guarddog.threat-proces-hooks",
            "other.rule",
            "guarddog",
            "metadata.new_package",
        ] {
            let error = parse(&format!("signal_weights: {{ {unknown}: 2 }}\n")).unwrap_err();
            assert!(
                error.to_string().contains("unknown field"),
                "{unknown}: {error}"
            );
        }
        for (weight, rule) in (10..).zip(BUILT_IN_RULES) {
            let body = format!("deprecated: block\nsignal_weights: {{ {rule}: {weight} }}\n");
            let policy = parse(&body).unwrap_or_else(|e| panic!("{rule}: {e}"));
            assert_eq!(policy.signal_weights.of(rule), weight, "{rule}");
        }
    }

    /// A check's rule weighs the threshold unless the policy weighs it, and a detector's
    /// rule its default.
    #[test]
    fn a_check_weighs_the_threshold_unless_weighed() {
        let policy = parse("").unwrap();
        assert_eq!(policy.risk_threshold, 100);
        assert_eq!(policy.weight_of("install_scripts"), 100);
        assert_eq!(policy.weight_of("near_name"), 1);
        let set = parse("risk_threshold: 40\nsignal_weights: { install_scripts: 25 }\n").unwrap();
        assert_eq!(set.weight_of("install_scripts"), 25);
        assert_eq!(set.weight_of("kev"), 40);
        assert_eq!(
            set.weight_of("no_strong_digest"),
            0,
            "passed unless weighed"
        );
        assert_eq!(
            (
                policy.weight_of("provenance_dropped"),
                policy.weight_of("provenance_surprise")
            ),
            (50, 25),
            "half the threshold, and a quarter per bit"
        );
        assert_eq!(
            (
                set.weight_of("provenance_dropped"),
                set.weight_of("provenance_surprise")
            ),
            (20, 10)
        );
        assert_eq!(policy.provenance_half_life, 16);
        assert_eq!(set.weight_of("unservable"), 40);
        let digest = ["no_strong_digest".to_owned()];
        let unservable = ["unservable".to_owned()];
        assert!(!decide::weighs(None, &digest));
        assert!(decide::weighs(None, &unservable));
        assert!(!decide::weighs(None, &[]));
        let weighed = parse("signal_weights: { no_strong_digest: 100 }\n").unwrap();
        assert!(decide::weighs(Some(&weighed), &digest));
        assert!(!decide::weighs(Some(&set), &digest));
    }

    /// A threshold of 0 refuses everything, and a weight on a check turned off adds nothing.
    #[test]
    fn a_threshold_of_0_and_a_weight_on_a_check_turned_off_are_refused() {
        assert_eq!(
            parse("risk_threshold: 0\n").unwrap_err().to_string(),
            "risk_threshold is 0, at which every version would be refused; it is at least 1"
        );
        assert_eq!(
            parse("provenance_half_life: 0\n").unwrap_err().to_string(),
            "provenance_half_life is 0, under which no earlier version weighs; it is at least 1"
        );
        assert_eq!(
            parse("provenance_half_life: 4\n")
                .unwrap()
                .provenance_half_life,
            4
        );
        for (setting, rule) in [
            ("install_scripts", "install_scripts"),
            ("kev", "kev"),
            ("yanked", "yanked"),
            ("deprecated", "deprecated"),
            ("provenance", "provenance_unverified"),
            ("provenance", "provenance_dropped"),
            ("provenance", "provenance_identity_changed"),
            ("provenance", "provenance_surprise"),
        ] {
            let error = parse(&format!(
                "{setting}: allow\nsignal_weights: {{ {rule}: 50 }}\n"
            ))
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "signal_weights weighs `{rule}`, and `{setting}: allow` turns that check \
                     off, so the weight is never added. Set `{setting}: block` to weigh it"
                )
            );
            assert!(
                parse(&format!(
                    "{setting}: block\nsignal_weights: {{ {rule}: 50 }}\n"
                ))
                .is_ok(),
                "{rule}"
            );
        }
    }

    /// The key set at each level is pinned by serde's list of the keys it accepts.
    /// See docs/engineering_decisions/0030-policy-schema-v1-frozen.md.
    #[test]
    fn the_version_1_key_set_is_closed() {
        let cases: [(&str, &str, &[&str]); 7] = [
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
                    "provenance_half_life",
                    "denials",
                    "packages",
                    "advisory_scores",
                    "signal_weights",
                    "risk_threshold",
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
                    "ignored_vuln_advisory_ids",
                ],
            ),
            (
                "signal_weights",
                "signal_weights: { unknown: 1 }\n",
                &[
                    "denied",
                    "known_malware",
                    "cooldown",
                    "kev",
                    "max_cvss",
                    "install_scripts",
                    "yanked",
                    "deprecated",
                    "provenance_unverified",
                    "provenance_dropped",
                    "provenance_identity_changed",
                    "provenance_surprise",
                    "no_strong_digest",
                    "unservable",
                    "digest_mismatch",
                    "signature_failed",
                    "new_package",
                    "new_publisher",
                    "no_repository",
                    "near_name",
                    "source_install_scripts",
                    "source_dependencies",
                    "source_install_files",
                    "source_differing",
                    "virustotal_detected",
                    "trustpub_dropped",
                    "trustpub_repository_changed",
                    "signing_key_new",
                    "signing_key_expired",
                    "advisory_malware",
                    "advisory_vulnerability",
                    "advisory_unsound",
                    "advisory_unmaintained",
                    "advisory_notice",
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
    #[test]
    fn a_denial_that_names_no_version_is_refused_at_load() {
        let err = parse("denials:\n  - purl: pkg:npm/evil\n    reason: malware\n")
            .expect_err("a versionless denial must not load");
        let message = err.to_string();
        assert!(message.contains("denials[0]"), "{message}");
        assert!(message.contains("names no version"), "{message}");
        assert!(message.contains("pkg:npm/evil@<version>"), "{message}");

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

    /// Entries that overlap load, whether one is inside the other, neither is, or they
    /// select the same packages: every one that matches applies.
    #[test]
    fn overlapping_entries_load() {
        for second in [
            "{ ecosystem: npm, name: \"ab*\" }",
            "{ ecosystem: npm, name: \"a*\", has_install_scripts: true }",
            "{ ecosystem: npm, name: \"abc\" }",
        ] {
            let body = format!(
                "packages:\n  - match: {{ ecosystem: npm, name: \"a*\", has_install_scripts: true }}\n    \
                 set: {{}}\n    reason: r\n  - match: {second}\n    set: {{}}\n    reason: r\n"
            );
            assert!(parse(&body).is_ok(), "{second}");
        }
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
            "cooldown_days: 0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
             set: { cooldown_days: 5, yanked: allow, deprecated: allow }\n    \
             reason: reviewed\n    expires: \"2026-12-01\"\n",
        )
        .expect("loads");
        assert!(policy.uses_cooldown());
        assert_eq!(
            policy.longest_cooldown(),
            5,
            "the entry's, past the global 0"
        );
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
