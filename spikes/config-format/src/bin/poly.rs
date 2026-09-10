#![allow(dead_code)]
use serde::de::{value::MapAccessDeserializer, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Action { Allow, Warn, Quarantine, Block }

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptDetail {
    action: Action,
    #[serde(default)] loosens_global: bool,
    #[serde(default)] reason: Option<String>,
    #[serde(default)] expires: Option<String>,
}

// --- A: the naive version ---
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Untagged { Bare(Action), Detailed(ScriptDetail) }

// --- B: hand-written, dispatching on the shape of the node ---
#[derive(Debug)]
enum Manual { Bare(Action), Detailed(ScriptDetail) }

impl<'de> Deserialize<'de> for Manual {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Manual;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an action (allow/warn/quarantine/block) or a rule table")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Manual, E> {
                Action::deserialize(serde::de::value::StrDeserializer::new(s)).map(Manual::Bare)
            }
            fn visit_map<M: MapAccess<'de>>(self, m: M) -> Result<Manual, M::Error> {
                // Delegate: the inner error survives instead of being swallowed.
                ScriptDetail::deserialize(MapAccessDeserializer::new(m)).map(Manual::Detailed)
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize)]
struct WrapU { install_scripts: Untagged }
#[derive(Debug, Deserialize)]
struct WrapM { install_scripts: Manual }

fn main() {
    let cases = [
        ("YAML bare       ", "install_scripts: warn"),
        ("YAML detail ok  ", "install_scripts:\n  action: allow\n  reason: \"x\""),
        ("YAML typo'd key ", "install_scripts:\n  action: allow\n  expiress: \"2026-11-30\""),
    ];
    println!("### YAML (serde-saphyr)");
    for (name, src) in cases {
        let u = serde_saphyr::from_str::<WrapU>(src).map(|_| ()).map_err(|e| first(&e.to_string()));
        let m = serde_saphyr::from_str::<WrapM>(src).map(|_| ()).map_err(|e| first(&e.to_string()));
        println!("  {name}\n     untagged: {u:?}\n     manual  : {m:?}");
    }
    let tcases = [
        ("TOML bare       ", "install_scripts = \"warn\""),
        ("TOML detail ok  ", "[install_scripts]\naction = \"allow\"\nreason = \"x\""),
        ("TOML typo'd key ", "[install_scripts]\naction = \"allow\"\nexpiress = \"2026-11-30\""),
    ];
    println!("\n### TOML");
    for (name, src) in tcases {
        let u = toml::from_str::<WrapU>(src).map(|_| ()).map_err(|e| first(&e.to_string()));
        let m = toml::from_str::<WrapM>(src).map(|_| ()).map_err(|e| first(&e.to_string()));
        println!("  {name}\n     untagged: {u:?}\n     manual  : {m:?}");
    }
}

fn first(s: &str) -> String {
    s.lines().filter(|l| !l.trim().is_empty()).map(|l| l.trim()).collect::<Vec<_>>().join(" / ")
}
