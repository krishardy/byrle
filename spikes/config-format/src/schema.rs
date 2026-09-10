//! The real §5.5 policy schema. Fail-closed: `deny_unknown_fields` everywhere.
#![allow(dead_code)] // fields exist to be deserialized into, not read
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
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

/// Permanent, absolute. No `expires` field exists, so an expiring denial is
/// unrepresentable rather than merely discouraged (§5.5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denial {
    pub purl: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorRules {
    /// Pinned: cannot be removed.
    pub known_malware: Action,
    #[serde(default)]
    pub provenance_required: Option<bool>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
}

#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemRules {
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub provenance_required: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Warn,
    Quarantine,
    Block,
}

/// Polymorphic: `install_scripts: warn` or a struct carrying the §5 acknowledgment.
/// This is the construct most likely to break `deny_unknown_fields`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ScriptRule {
    Bare(Action),
    Detailed(ScriptDetail),
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooldownRule {
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub days: Option<u32>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    /// Required on every selector (§5.5).
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetBlock {
    #[serde(default)]
    pub cooldown: Option<CooldownRule>,
    #[serde(default)]
    pub install_scripts: Option<ScriptRule>,
    #[serde(default)]
    pub provenance_required: Option<bool>,
}
