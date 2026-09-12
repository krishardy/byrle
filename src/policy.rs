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

        serde_saphyr::from_str(source).map_err(|e| PolicyError::Invalid(e.to_string()))
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
#[derive(Debug, PartialEq)]
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

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScriptDetail {
    pub action: Action,
    #[serde(default)]
    pub loosens_global: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
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
    pub expires: Option<String>,
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

        let table = "version: 1\nfloor:\n  npm:\n    known_malware: block\ndefaults:\n  \
                     install_scripts:\n    action: allow\n    loosens_global: true\n    \
                     reason: reviewed\n";
        assert_eq!(
            Policy::parse(table).unwrap().defaults.install_scripts,
            Some(ScriptRule::Detailed(ScriptDetail {
                action: Action::Allow,
                loosens_global: true,
                reason: Some("reviewed".to_owned()),
                expires: None,
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
