//! A packument as npm serves it: the deserialisation targets `normalize` reads, visible no
//! further than this ecosystem. See docs/engineering_decisions/npm-packument-shapes.md.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::record::Repository;

#[derive(Debug, Deserialize)]
pub(super) struct WirePackument {
    pub(super) name: String,
    #[serde(default, rename = "dist-tags")]
    pub(super) dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) versions: BTreeMap<String, WireVersion>,
    /// Full packument only. Keyed by version, plus `created` and `modified`.
    #[serde(default)]
    pub(super) time: BTreeMap<String, String>,
    /// Package-level fallbacks for the per-version copies.
    #[serde(default)]
    pub(super) maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default)]
    pub(super) repository: Option<Repository>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireVersion {
    #[serde(default)]
    pub(super) dist: Option<WireDist>,
    /// Abbreviated only, and present only when true.
    #[serde(default, rename = "hasInstallScript")]
    pub(super) has_install_script: Option<bool>,
    /// The message `npm deprecate` set, in both documents.
    #[serde(default)]
    pub(super) deprecated: Option<String>,
    /// Full only.
    #[serde(default)]
    pub(super) scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(super) maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default)]
    pub(super) repository: Option<Repository>,
    #[serde(default, rename = "_npmUser")]
    pub(super) npm_user: Option<WireNpmUser>,
    /// Only the entries a client fetches from where they point, kept as they are read.
    #[serde(default)]
    pub(super) dependencies: DirectSpecs,
    #[serde(default, rename = "optionalDependencies")]
    pub(super) optional_dependencies: DirectSpecs,
    #[serde(default, rename = "peerDependencies")]
    pub(super) peer_dependencies: DirectSpecs,
}

/// A dependency map, keeping only the entries [`is_direct`] accepts.
#[derive(Debug, Default)]
pub(super) struct DirectSpecs(pub(super) Vec<(String, String)>);

impl<'de> Deserialize<'de> for DirectSpecs {
    /// Any shape other than a map keeps nothing: old packuments write an array, `null`, or
    /// worse here, and a malformed field must not make the whole document unreadable. A
    /// specifier that is not a string is skipped, as npm skips it.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let serde_json::Value::Object(map) = serde_json::Value::deserialize(deserializer)? else {
            return Ok(DirectSpecs::default());
        };
        Ok(DirectSpecs(
            map.into_iter()
                .filter_map(|(name, spec)| match spec {
                    serde_json::Value::String(spec) if is_direct(&spec) => Some((name, spec)),
                    _ => None,
                })
                .collect(),
        ))
    }
}

/// Whether a dependency specifier names where to fetch from rather than a version range,
/// as npm-package-arg classifies them. See docs/engineering_decisions/bypass-self-detection.md.
pub fn is_direct(spec: &str) -> bool {
    const PREFIXES: [&str; 13] = [
        "git+",
        "git://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "http://",
        "https://",
        "file:",
        "./",
        "../",
        "/",
        "~/",
    ];
    let spec = spec.trim();
    if PREFIXES.iter().any(|p| spec.starts_with(p)) {
        return true;
    }
    let path = spec.split('#').next().unwrap_or(spec);
    match path.split_once('/') {
        Some((owner, repo)) => {
            !owner.is_empty()
                && !repo.is_empty()
                && !repo.contains('/')
                && !path.contains(':')
                && !path.contains(char::is_whitespace)
                && !owner.starts_with('@')
        }
        None => false,
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct WireDist {
    #[serde(default)]
    pub(super) tarball: Option<String>,
    #[serde(default)]
    pub(super) integrity: Option<String>,
    #[serde(default)]
    pub(super) shasum: Option<String>,
    #[serde(default, rename = "fileCount")]
    pub(super) file_count: Option<u64>,
    #[serde(default, rename = "unpackedSize")]
    pub(super) unpacked_size: Option<u64>,
    #[serde(default)]
    pub(super) attestations: Option<WireAttestations>,
    #[serde(default)]
    pub(super) signatures: Option<Vec<WireSignature>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireAttestations {
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) provenance: Option<WireProvenance>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireProvenance {
    #[serde(default, rename = "predicateType")]
    pub(super) predicate_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireSignature {
    pub(super) keyid: String,
    pub(super) sig: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireMaintainer {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireNpmUser {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default, rename = "trustedPublisher")]
    pub(super) trusted_publisher: Option<WireTrustedPublisher>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireTrustedPublisher {
    pub(super) id: String,
}

/// `repository` as an object or a shorthand string, such as `github:user/repo`.
impl<'de> Deserialize<'de> for Repository {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RepositoryVisitor;

        impl<'de> Visitor<'de> for RepositoryVisitor {
            type Value = Repository;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a repository URL string or an object with a `url` field")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Repository {
                    url: value.to_owned(),
                    kind: None,
                    directory: None,
                })
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut url = None;
                let mut kind = None;
                let mut directory = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "url" => url = map.next_value::<Option<String>>()?,
                        "type" => kind = map.next_value::<Option<String>>()?,
                        "directory" => directory = map.next_value::<Option<String>>()?,
                        _ => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Repository {
                    url: url.ok_or_else(|| de::Error::missing_field("url"))?,
                    kind,
                    directory,
                })
            }
        }

        deserializer.deserialize_any(RepositoryVisitor)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The visitor's `expecting` is what a operator sees when `repository` is neither
    /// shape, so it has to describe both.
    #[test]
    fn a_repository_of_the_wrong_type_says_what_was_expected() {
        let err =
            serde_json::from_str::<Repository>("42").expect_err("a number is not a repository");
        let message = err.to_string();
        assert!(message.contains("repository URL string"), "got: {message}");
        assert!(message.contains("object"), "got: {message}");
    }

    /// A repository or dependency map whose JSON is broken, or whose fields have the wrong
    /// type, is an error from the deserializer rather than a value.
    #[test]
    fn broken_json_in_a_repository_or_dependency_map_is_an_error() {
        for json in [
            r#"{"url": 5}"#,
            r#"{"url": "u", "type": 5}"#,
            r#"{"url": "u", "directory": 5}"#,
            r#"{"url": "u", "other": }"#,
            r#"{"url": "u", "#,
            r#"{"type": "git"}"#,
        ] {
            assert!(
                serde_json::from_slice::<Repository>(json.as_bytes()).is_err(),
                "{json}"
            );
        }
        assert!(serde_json::from_slice::<DirectSpecs>(b"{").is_err());
    }
}
