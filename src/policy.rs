//! The policy document: its schema, and loading it.
//!
//! §5.5's policy, as a Rust type. This is the schema and nothing else: evaluating a
//! request against it is the engine's job, and it does not exist yet.
//!
//! # Fail closed on anything unrecognised
//!
//! `deny_unknown_fields` on every struct. A typo'd key in a security policy is not a
//! harmless extra: `expiress` where `expires` was meant silently produces a rule that
//! never expires, and `blcok` produces a rule that does nothing. Both read as working.
//!
//! # Never `#[serde(untagged)]`
//!
//! An `untagged` enum still refuses a typo'd key. What it destroys is the diagnosis.
//! Serde tries each variant, all of them fail, and the error says only that none matched:
//!
//! ```text
//! untagged      line 7: data did not match any variant of untagged enum ScriptRule
//!               7 |     action: allow
//!                 |     ^ data did not match any variant of untagged enum ScriptRule
//!
//! hand-written  line 8: unknown field `expiress`, expected one of action,
//!                       loosens_global, reason, expires
//!               8 |     expiress: "2026-11-30"
//!                 |     ^ unknown field `expiress`, expected one of ...
//! ```
//!
//! The untagged caret sits on line 7, which is correct, while the typo on line 8 appears
//! only as trailing context. An operator reads it as the line above being wrong.
//!
//! So the one polymorphic field, `install_scripts`, has a hand-written `Deserialize` that
//! dispatches on the shape of the node and delegates to the struct, which keeps the inner
//! error. Any polymorphic field added later has to do the same. Measured in both formats
//! by `spikes/config-format/src/bin/poly.rs`, and again here by
//! `an_unknown_key_inside_the_polymorphic_field_is_named`.

pub mod merge;
pub mod strictness;

use serde::de::value::{MapAccessDeserializer, StrDeserializer};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The only document version this understands.
///
/// A policy naming another version is refused rather than read as this one. The schema is
/// the security boundary, so a document written against a different one is not something
/// to interpret optimistically.
pub const SUPPORTED_VERSION: u32 = 1;

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
    /// A `loosens_global` acknowledgment is missing what §5.5 requires of one.
    IncompleteAcknowledgment { at: String, missing: &'static str },
    /// A floor does not block known malware.
    FloorDoesNotBlockMalware { ecosystem: String, found: Action },
    /// An ecosystem this build serves has no floor.
    NoFloor { ecosystem: String },
    /// A package rule is both dated and permanent.
    BothDatedAndPermanent { at: String },
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
            Self::FloorDoesNotBlockMalware { ecosystem, found } => write!(
                f,
                "floor.{ecosystem} sets `known_malware: {}`. It is pinned to `block` and \
                 cannot be weakened, because a floor that can be talked out of blocking \
                 malware is not a floor",
                format!("{found:?}").to_lowercase()
            ),
            Self::NoFloor { ecosystem } => write!(
                f,
                "this build serves `{ecosystem}` and the policy declares no \
                 `floor.{ecosystem}`. An ecosystem cannot be proxied with no floor, so \
                 this is a startup failure rather than a default"
            ),
            Self::BothDatedAndPermanent { at } => write!(
                f,
                "{at} sets both `expires` and `permanent: true`. They are alternatives: \
                 one says when the entry stops being true, the other says it does not"
            ),
            Self::IncompleteAcknowledgment { at, missing } => write!(
                f,
                "`loosens_global: true` at {at} has no {missing}. An acknowledgment \
                 without one is a loosening nobody has to answer for"
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
/// parser, by the same `deserialize_any` dispatch the module docs describe.
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
            // which is what it says. An arm serde never calls would read as a gap in the
            // tests rather than as what it is.
        }

        deserializer.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub denials: Vec<Denial>,
    pub floor: BTreeMap<String, FloorRules>,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub ecosystems: BTreeMap<String, EcosystemRules>,
    #[serde(default)]
    pub packages: Vec<PackageRule>,
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

        let policy: Self =
            serde_saphyr::from_str(source).map_err(|e| PolicyError::Invalid(e.to_string()))?;
        policy.check_acknowledgments()?;
        policy.check_floors()?;
        policy.check_package_expiry_shape()?;
        Ok(policy)
    }

    /// §5.5: `known_malware: block` is pinned into every floor and cannot be removed.
    ///
    /// The schema already makes the field mandatory, so a floor without it does not
    /// parse. This is the other half: a floor that declares it and weakens it. Otherwise
    /// "editable floor" collapses into "no floor".
    fn check_floors(&self) -> Result<(), PolicyError> {
        for (ecosystem, rules) in &self.floor {
            if rules.known_malware != Action::Block {
                return Err(PolicyError::FloorDoesNotBlockMalware {
                    ecosystem: ecosystem.clone(),
                    found: rules.known_malware,
                });
            }
        }
        Ok(())
    }

    /// §5.5: `permanent: true` is the explicit alternative to `expires`, not a companion.
    ///
    /// An entry carrying both says two different things about when it stops being true,
    /// and whichever one the code happened to read would be a silent choice.
    fn check_package_expiry_shape(&self) -> Result<(), PolicyError> {
        for (i, rule) in self.packages.iter().enumerate() {
            if rule.permanent && rule.expires.is_some() {
                return Err(PolicyError::BothDatedAndPermanent {
                    at: format!("packages[{i}]"),
                });
            }
        }
        Ok(())
    }

    /// Every ecosystem this build serves has a floor.
    ///
    /// Separate from parsing, and taking the list as an argument, because it is a
    /// question about this build rather than about the document. A policy may name an
    /// ecosystem no adapter exists for yet, which is not an error: `examples/policy.yaml`
    /// declares `ecosystems.cargo` and is a valid document. It becomes a startup failure
    /// the day a cargo adapter ships without a `floor.cargo` being written, which is
    /// §5.5's breaking-change policy working as intended.
    pub fn check_enabled(&self, enabled: &[&str]) -> Result<(), PolicyError> {
        for ecosystem in enabled {
            if !self.floor.contains_key(*ecosystem) {
                return Err(PolicyError::NoFloor {
                    ecosystem: (*ecosystem).to_owned(),
                });
            }
        }
        Ok(())
    }

    /// §5.5: an acknowledgment is `loosens_global: true` **plus** a reason and an expiry.
    ///
    /// Refused at load rather than warned about, because the point of the acknowledgment
    /// is that someone answered for the loosening and said when it stops. A flag on its
    /// own silences the warning and records neither, which is worse than not having the
    /// mechanism: the loosening is still there and nothing now reports it.
    fn check_acknowledgments(&self) -> Result<(), PolicyError> {
        let carriers = self
            .ecosystems
            .iter()
            .map(|(name, rules)| (format!("ecosystems.{name}"), rules.install_scripts.as_ref()))
            .chain(std::iter::once((
                "defaults".to_owned(),
                self.defaults.install_scripts.as_ref(),
            )))
            .chain(
                self.floor
                    .iter()
                    .map(|(name, rules)| (format!("floor.{name}"), rules.install_scripts.as_ref())),
            )
            .chain(self.packages.iter().enumerate().map(|(i, rule)| {
                (
                    format!("packages[{i}].set"),
                    rule.set.install_scripts.as_ref(),
                )
            }));

        for (at, rule) in carriers {
            let Some(ScriptRule::Detailed(detail)) = rule else {
                continue;
            };
            if !detail.loosens_global {
                continue;
            }
            if detail.reason.as_deref().is_none_or(str::is_empty) {
                return Err(PolicyError::IncompleteAcknowledgment {
                    at,
                    missing: "reason",
                });
            }
            if detail.expires.is_none() {
                return Err(PolicyError::IncompleteAcknowledgment {
                    at,
                    missing: "expires",
                });
            }
        }
        Ok(())
    }

    /// Read and parse a policy file.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let source = std::fs::read_to_string(path).map_err(|source| PolicyError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&source)
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

/// A calendar date an acknowledgment or an override runs out on.
///
/// Parsed at load, so a policy that carries an unreadable date is refused rather than
/// loaded with a rule whose expiry silently never arrives. Hand-written rather than
/// relying on a date crate's serde support, so the error names the value and the format
/// an operator has to write.
///
/// A plain calendar date, not an instant: `expires: "2026-11-30"` is a day, and which
/// second of it the rule lapses on is not a question a policy file should have to answer.
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
    /// The date itself is the last day it is in force, so a rule expiring on the 30th is
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
/// unrepresentable rather than merely discouraged (§5.5).
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    pub purl: String,
    pub reason: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FloorRules {
    /// Pinned into every floor and not removable, which is why it has no `Option`.
    pub known_malware: Action,
    #[serde(default)]
    pub provenance_required: Option<bool>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default)]
    pub known_malware: Option<Action>,
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub provenance_required: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EcosystemRules {
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub provenance_required: Option<bool>,
}

/// §5.5's lattice, weakest to strongest. The ordering is not derived here: the engine's
/// lattice is its own item, and reading a name is all this does.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Warn,
    Quarantine,
    Block,
}

/// `install_scripts: warn`, or a table carrying §5's acknowledgment.
#[derive(Debug, PartialEq, Clone)]
pub enum ScriptRule {
    Bare(Action),
    Detailed(ScriptDetail),
}

impl<'de> Deserialize<'de> for ScriptRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ShapeVisitor;

        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = ScriptRule;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an action (allow, warn, quarantine or block) or a rule table")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<ScriptRule, E> {
                Action::deserialize(StrDeserializer::new(s)).map(ScriptRule::Bare)
            }

            // Delegated rather than read key by key, so `ScriptDetail`'s own
            // `deny_unknown_fields` applies and its error survives naming the bad key.
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<ScriptRule, M::Error> {
                ScriptDetail::deserialize(MapAccessDeserializer::new(map)).map(ScriptRule::Detailed)
            }
        }

        deserializer.deserialize_any(ShapeVisitor)
    }
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScriptDetail {
    pub action: Action,
    #[serde(default)]
    pub loosens_global: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires: Option<ExpiryDate>,
}

#[derive(Debug, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct CooldownRule {
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub days: Option<u32>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageRule {
    #[serde(rename = "match")]
    pub selector: Selector,
    pub set: SetBlock,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<ExpiryDate>,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub added_by: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    /// Required on every selector (§5.5). A rule that does not say which ecosystem it is
    /// about would apply to a name across all of them.
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

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SetBlock {
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub provenance_required: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal document that parses, so each test can change one thing.
    fn minimal() -> String {
        "version: 1\nfloor:\n  npm:\n    known_malware: block\n".to_owned()
    }

    #[test]
    fn the_smallest_valid_policy_is_a_version_and_a_floor() {
        let policy = Policy::parse(&minimal()).unwrap();
        assert_eq!(policy.version, SUPPORTED_VERSION);
        assert_eq!(policy.floor["npm"].known_malware, Action::Block);
        assert!(policy.denials.is_empty());
        assert_eq!(policy.defaults, Defaults::default());
    }

    /// The shipped example is the config-format spike's artifact and the only full-size
    /// policy in the repository, so it is what proves the schema covers §5.5.
    ///
    /// It asserts parsing and nothing more. The file deliberately declares
    /// `ecosystems.cargo` with no `floor.cargo`, which is the case the floor check will
    /// reject when that lands: asserting completeness here would mean editing the example
    /// and losing the record of what the spike tested.
    #[test]
    fn the_shipped_example_policy_parses() {
        let source = std::fs::read_to_string("examples/policy.yaml").unwrap();
        let policy = Policy::parse(&source).unwrap();
        assert!(!policy.packages.is_empty());
        assert!(policy.floor.contains_key("npm"));
        assert!(
            policy.ecosystems.contains_key("cargo") && !policy.floor.contains_key("cargo"),
            "left incomplete on purpose; see this test's doc comment"
        );
    }

    /// `deny_unknown_fields` at every depth, which is what a typo'd key in a security
    /// policy needs. `expiress` where `expires` was meant is a rule that never expires.
    #[test]
    fn an_unknown_key_is_refused_at_every_depth() {
        let cases = [
            (
                "top level",
                "version: 1\nfloor:\n  npm:\n    known_malware: block\nfloorr: {}\n",
            ),
            (
                "inside floor",
                "version: 1\nfloor:\n  npm:\n    known_malware: block\n    typo: 1\n",
            ),
            (
                "inside defaults",
                "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  cooldownn: {}\n",
            ),
            (
                "inside a package selector",
                "version: 1\nfloor:\n  npm:\n    known_malware: block\npackages:\n  \
                 - match: { ecosystem: npm, nmae: x }\n    set: {}\n    reason: r\n",
            ),
        ];
        for (depth, source) in cases {
            let error = Policy::parse(source).unwrap_err();
            assert!(
                matches!(error, PolicyError::Invalid(_)),
                "{depth}: expected a schema error, got {error}"
            );
        }
    }

    /// The reason `ScriptRule` has a hand-written `Deserialize`.
    ///
    /// Both shapes refuse this document, so refusal is not what distinguishes them.
    /// `untagged` reports only "data did not match any variant" with the caret on the
    /// line above the typo. Asserting that the key appears anywhere in the message does
    /// not discriminate either: the error carries a source-context snippet, and the
    /// offending line shows up there under both. What only the delegating version
    /// produces is the diagnosis, so that is what this asserts.
    #[test]
    fn an_unknown_key_inside_the_polymorphic_field_is_named() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  \
                      install_scripts:\n    action: allow\n    expiress: \"2026-11-30\"\n";
        let text = Policy::parse(source).unwrap_err().to_string();
        assert!(
            text.contains("unknown field `expiress`"),
            "the error has to say which key is unknown: {text}"
        );
        assert!(
            text.contains("expected one of"),
            "and which keys were allowed instead: {text}"
        );
        // The caret has to sit on the typo, not on the correct line above it.
        assert!(text.contains("line 8"), "wrong line reported: {text}");
    }

    /// Both shapes of the one polymorphic field.
    #[test]
    fn install_scripts_takes_a_bare_action_or_a_table() {
        let bare = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  \
                    install_scripts: warn\n";
        assert_eq!(
            Policy::parse(bare).unwrap().defaults.install_scripts,
            Some(ScriptRule::Bare(Action::Warn))
        );

        // A complete acknowledgment, because an incomplete one no longer loads: see
        // `an_acknowledgment_without_a_reason_or_an_expiry_is_refused`.
        let table = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  \
                     install_scripts:\n    action: allow\n    loosens_global: true\n    \
                     reason: reviewed\n    expires: \"2026-11-30\"\n";
        assert_eq!(
            Policy::parse(table).unwrap().defaults.install_scripts,
            Some(ScriptRule::Detailed(ScriptDetail {
                action: Action::Allow,
                loosens_global: true,
                reason: Some("reviewed".to_owned()),
                expires: Some(ExpiryDate(jiff::civil::date(2026, 11, 30))),
            }))
        );
    }

    /// An action name that is not one of the four is refused rather than read as the
    /// nearest thing. `blcok` would otherwise be a rule that does nothing.
    #[test]
    fn an_action_that_is_not_in_the_lattice_is_refused() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: blcok\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A document written against another schema version is refused before its body is
    /// judged, and the refusal quotes both numbers: an operator whose file parsed
    /// cleanly and still will not load needs to be sent to the version line.
    #[test]
    fn a_version_this_build_does_not_understand_is_refused_by_number() {
        let source = "version: 2\nfloor:\n  npm:\n    known_malware: block\n";
        let error = Policy::parse(source).unwrap_err();
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
        let source = "version: 2\nrules:\n  - everything: different\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::UnsupportedVersion { .. }
        ));
    }

    /// No version at all, and the shapes that are not a number. Each is reported as it
    /// was written rather than coerced into one.
    #[test]
    fn a_version_that_is_missing_or_not_a_number_is_refused_as_it_was_written() {
        for (source, expected) in [
            ("floor:\n  npm:\n    known_malware: block\n", "absent"),
            ("version: \"1\"\nfloor: {}\n", "`1`"),
            ("version: true\nfloor: {}\n", "true"),
            // An empty version line says no more than a missing one.
            ("version:\nfloor: {}\n", "absent"),
            ("version: 1.5\nfloor: {}\n", "1.5"),
            // Negative, which is the signed path: a positive integer arrives unsigned.
            ("version: -1\nfloor: {}\n", "-1"),
        ] {
            let error = Policy::parse(source).unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(error, PolicyError::UnsupportedVersion { .. }) && text.contains(expected),
                "expected {expected} in: {text}"
            );
        }
    }

    /// A floor is required. Without one, an ecosystem has no rule that cannot be
    /// overridden, which is the whole point of the tier.
    #[test]
    fn a_policy_with_no_floor_at_all_is_refused() {
        let source = "version: 1\ndefaults:\n  known_malware: block\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// `known_malware` is not optional in a floor: §5.5 pins it into every one, and an
    /// `Option` would make a floor without it representable.
    #[test]
    fn a_floor_without_known_malware_is_refused() {
        let source = "version: 1\nfloor:\n  npm:\n    cooldown: { days: 7 }\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// `ecosystem` is required on every selector. A rule that does not say which
    /// ecosystem it is about would apply to that name in all of them.
    #[test]
    fn a_package_selector_without_an_ecosystem_is_refused() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\npackages:\n  \
                      - match: { name: lodash }\n    set: {}\n    reason: r\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A denial has no `expires` field, so writing one is an error rather than a setting
    /// that quietly does nothing.
    #[test]
    fn a_denial_cannot_be_given_an_expiry() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndenials:\n  \
                      - purl: pkg:npm/evil\n    reason: malware\n    expires: \"2026-01-01\"\n";
        assert!(matches!(
            Policy::parse(source).unwrap_err(),
            PolicyError::Invalid(_)
        ));
    }

    /// A shape neither visitor has an arm for, which is where `expecting` is read. The
    /// message has to say what would have been accepted, since the value is not a near
    /// miss of anything.
    #[test]
    fn a_value_of_the_wrong_shape_says_what_was_expected() {
        let version = Policy::parse("version: [1]\nfloor: {}\n").unwrap_err();
        assert!(
            version.to_string().contains("policy schema version number"),
            "{version}"
        );

        let action = Policy::parse(
            "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  \
             install_scripts:\n      - warn\n",
        )
        .unwrap_err();
        let text = action.to_string();
        assert!(
            text.contains("action") && text.contains("rule table"),
            "both shapes the field takes have to be named: {text}"
        );
    }

    /// §5.5's acknowledgment is the flag **plus** a reason and an expiry. A flag on its
    /// own silences the warning and records neither, which is worse than not having the
    /// mechanism: the loosening is still there and nothing now reports it.
    #[test]
    fn an_acknowledgment_without_a_reason_or_an_expiry_is_refused() {
        let cases = [
            ("neither", "      loosens_global: true\n"),
            (
                "no expiry",
                "      loosens_global: true\n      reason: reviewed\n",
            ),
            (
                "an empty reason",
                "      loosens_global: true\n      reason: \"\"\n      \
                 expires: \"2026-11-30\"\n",
            ),
        ];
        for (missing, tail) in cases {
            let source = format!(
                "version: 1\nfloor:\n  npm:\n    known_malware: block\necosystems:\n  \
                 npm:\n    install_scripts:\n      action: allow\n{tail}"
            );
            let error = Policy::parse(&source).unwrap_err();
            assert!(
                matches!(error, PolicyError::IncompleteAcknowledgment { .. }),
                "{missing}: got {error}"
            );
            assert!(
                error.to_string().contains("ecosystems.npm"),
                "the refusal has to say where: {error}"
            );
        }
    }

    /// Every place the schema lets an acknowledgment be written is checked, not just the
    /// ecosystem block. A flag that is only enforced in one of four places is a flag an
    /// operator will find the gap in.
    #[test]
    fn an_incomplete_acknowledgment_is_refused_wherever_it_is_written() {
        let places = [
            ("defaults", "defaults:\n  install_scripts:\n"),
            (
                "floor.npm",
                "floor:\n  npm:\n    known_malware: block\n    install_scripts:\n",
            ),
            (
                "packages[0].set",
                "packages:\n  - match: { ecosystem: npm, name: x }\n    reason: r\n    \
                 set:\n      install_scripts:\n",
            ),
        ];
        for (at, block) in places {
            // The floor case writes its own floor; the others need one adding.
            let floor = if at == "floor.npm" {
                String::new()
            } else {
                "floor:\n  npm:\n    known_malware: block\n".to_owned()
            };
            let source = format!(
                "version: 1\n{floor}{block}        action: allow\n        \
                 loosens_global: true\n"
            );
            let error = Policy::parse(&source).unwrap_err();
            assert!(
                matches!(error, PolicyError::IncompleteAcknowledgment { .. })
                    && error.to_string().contains(at),
                "{at}: got {error}"
            );
        }
    }

    /// A complete one loads.
    #[test]
    fn a_complete_acknowledgment_is_accepted() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\necosystems:\n  \
                      npm:\n    install_scripts:\n      action: allow\n      \
                      loosens_global: true\n      reason: reviewed\n      \
                      expires: \"2026-11-30\"\n";
        assert!(Policy::parse(source).is_ok());
    }

    /// A date that cannot be read is refused at load, not carried as a rule whose expiry
    /// silently never arrives.
    #[test]
    fn an_expiry_that_is_not_a_date_is_refused() {
        for bad in ["soon", "30-11-2026", "2026-13-01", "2026-11-31"] {
            let source = format!(
                "version: 1\nfloor:\n  npm:\n    known_malware: block\npackages:\n  \
                 - match: {{ ecosystem: npm, name: x }}\n    set: {{}}\n    reason: r\n    \
                 expires: \"{bad}\"\n"
            );
            let error = Policy::parse(&source).unwrap_err();
            assert!(
                matches!(error, PolicyError::Invalid(_)) && error.to_string().contains(bad),
                "`{bad}` should be refused by name: {error}"
            );
        }
    }

    #[test]
    fn a_readable_expiry_is_kept_as_a_date() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\npackages:\n  \
                      - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: r\n    \
                      expires: \"2026-11-30\"\n";
        let policy = Policy::parse(source).unwrap();
        let expires = policy.packages[0].expires.unwrap();
        assert_eq!(expires.to_string(), "2026-11-30");
        assert!(!expires.has_passed(jiff::civil::date(2026, 11, 30)));
        assert!(expires.has_passed(jiff::civil::date(2026, 12, 1)));
    }

    /// §5.5: `known_malware: block` is pinned into every floor. Otherwise "editable
    /// floor" collapses into "no floor".
    #[test]
    fn a_floor_that_does_not_block_malware_is_refused() {
        for weaker in ["allow", "warn", "quarantine"] {
            let source = format!("version: 1\nfloor:\n  npm:\n    known_malware: {weaker}\n");
            let error = Policy::parse(&source).unwrap_err();
            assert!(
                matches!(error, PolicyError::FloorDoesNotBlockMalware { .. })
                    && error.to_string().contains(weaker),
                "`{weaker}` should be refused by name: {error}"
            );
        }
        assert!(Policy::parse("version: 1\nfloor:\n  npm:\n    known_malware: block\n").is_ok());
    }

    /// The other half is the schema's: a floor with no `known_malware` at all does not
    /// parse, because the field is not an `Option`.
    #[test]
    fn the_two_halves_of_the_pin_cover_removal_and_weakening() {
        assert!(matches!(
            Policy::parse("version: 1\nfloor:\n  npm:\n    cooldown: { days: 7 }\n").unwrap_err(),
            PolicyError::Invalid(_),
        ));
        assert!(matches!(
            Policy::parse("version: 1\nfloor:\n  npm:\n    known_malware: allow\n").unwrap_err(),
            PolicyError::FloorDoesNotBlockMalware { .. },
        ));
    }

    /// §5.5: an ecosystem this build serves and has no floor for is a startup failure,
    /// not a default. Asked of the build rather than of the document, because a policy
    /// may name an ecosystem no adapter exists for yet.
    #[test]
    fn an_ecosystem_this_build_serves_must_have_a_floor() {
        let policy =
            Policy::parse("version: 1\nfloor:\n  npm:\n    known_malware: block\n").unwrap();

        assert!(policy.check_enabled(&["npm"]).is_ok());
        let error = policy.check_enabled(&["npm", "pypi"]).unwrap_err();
        assert!(matches!(error, PolicyError::NoFloor { .. }));
        assert!(
            error.to_string().contains("floor.pypi"),
            "the failure has to name the floor that is missing: {error}"
        );
        assert!(
            policy.check_enabled(&[]).is_ok(),
            "a build serving nothing has nothing to require"
        );
    }

    /// The spike artifact declares `ecosystems.cargo` with no `floor.cargo`. That is a
    /// valid document and stays one until a cargo adapter ships, which is §5.5's
    /// breaking-change policy rather than a bug in the example.
    #[test]
    fn naming_an_ecosystem_with_no_adapter_yet_is_not_a_missing_floor() {
        let policy = Policy::load(Path::new("examples/policy.yaml")).unwrap();
        assert!(policy.ecosystems.contains_key("cargo"));
        assert!(!policy.floor.contains_key("cargo"));
        assert!(policy.check_enabled(&["npm"]).is_ok());
        assert!(policy.check_enabled(&["cargo"]).is_err());
    }

    /// §5.5: `permanent: true` is the alternative to `expires`, not a companion. An entry
    /// with both says two different things about when it stops being true.
    #[test]
    fn a_package_rule_cannot_be_both_dated_and_permanent() {
        let base = "version: 1\nfloor:\n  npm:\n    known_malware: block\npackages:\n  \
                    - match: { ecosystem: npm, name: x }\n    set: {}\n    reason: r\n";
        let both = format!("{base}    expires: \"2026-11-30\"\n    permanent: true\n");
        assert!(matches!(
            Policy::parse(&both).unwrap_err(),
            PolicyError::BothDatedAndPermanent { .. }
        ));

        assert!(Policy::parse(&format!("{base}    expires: \"2026-11-30\"\n")).is_ok());
        assert!(Policy::parse(&format!("{base}    permanent: true\n")).is_ok());
    }

    /// §5.5 replaced the separate `exceptions` block with the unified `packages` tier:
    /// one syntax, one code path. Writing the old one is a typo now, and
    /// `deny_unknown_fields` says so rather than ignoring it.
    #[test]
    fn the_exceptions_block_no_longer_exists() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\nexceptions:\n  \
                      - match: { ecosystem: npm, name: x }\n";
        let error = Policy::parse(source).unwrap_err();
        assert!(matches!(error, PolicyError::Invalid(_)));
        assert!(
            error.to_string().contains("exceptions"),
            "a config written against the old shape has to be told which key is gone: \
             {error}"
        );
    }

    /// A denial has no `expires` field at all, so an expiring denial is unrepresentable
    /// rather than discouraged. Tested from both sides: writing one is an error, and a
    /// denial that loads carries only what §5.5 allows it to.
    #[test]
    fn a_denial_is_permanent_by_having_nowhere_to_put_an_expiry() {
        let source = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndenials:\n  \
                      - purl: pkg:npm/evil\n    reason: malware\n";
        let policy = Policy::parse(source).unwrap();
        assert_eq!(policy.denials.len(), 1);
        assert_eq!(policy.denials[0].reason, "malware");
    }

    #[test]
    fn a_file_that_is_not_there_names_itself() {
        let error = Policy::load(Path::new("does/not/exist.yaml")).unwrap_err();
        assert!(matches!(error, PolicyError::Unreadable { .. }));
        assert!(error.to_string().contains("does/not/exist.yaml"));
    }

    #[test]
    fn a_policy_file_loads_from_disk() {
        let policy = Policy::load(Path::new("examples/policy.yaml")).unwrap();
        assert_eq!(policy.version, SUPPORTED_VERSION);
    }

    #[test]
    fn malformed_yaml_is_reported_as_invalid_rather_than_panicking() {
        let error = Policy::parse("version: 1\nfloor:\n\tnpm: {}\n").unwrap_err();
        assert!(matches!(error, PolicyError::Invalid(_)));
    }
}
