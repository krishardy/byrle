//! A packument as npm serves it.
//!
//! These are the deserialisation targets and nothing else. A packument is already
//! version-keyed, which is the shape [`crate::record::PackageMetadata`] holds, so
//! `normalize` reads these directly with no intermediate form. PyPI needs one; see
//! `crate::ecosystem::pypi::wire`.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::record::Repository;

// These mirror npm's JSON and nothing else. Visible no further than this ecosystem's
// module: the crate's contract is PackageRecord, and letting a registry's field names leak
// upward is how an ecosystem quirk becomes everyone's problem.

#[derive(Debug, Deserialize)]
pub(super) struct WirePackument {
    pub(super) name: String,
    #[serde(default, rename = "dist-tags")]
    pub(super) dist_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) versions: BTreeMap<String, WireVersion>,
    /// Full packument only. Keyed by version string, plus the `created` and `modified`
    /// entries, which are document metadata and not versions.
    #[serde(default)]
    pub(super) time: BTreeMap<String, String>,
    /// Package-level fallbacks. npm repeats both inside each version object, and the
    /// per-version copy is what was true at publish time, so it wins.
    #[serde(default)]
    pub(super) maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default)]
    pub(super) repository: Option<Repository>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireVersion {
    #[serde(default)]
    pub(super) dist: Option<WireDist>,
    /// Abbreviated only, and present only when true (measured: 3 of 9,321 versions
    /// carried the key, none of them `false`).
    #[serde(default, rename = "hasInstallScript")]
    pub(super) has_install_script: Option<bool>,
    /// The message `npm deprecate` set, in both documents. `npm deprecate pkg@range ""`
    /// clears it, and npm then omits the key.
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
    #[serde(default, rename = "trustedPublisher")]
    pub(super) trusted_publisher: Option<WireTrustedPublisher>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireTrustedPublisher {
    pub(super) id: String,
}

/// `repository` is either an object or a shorthand string such as `github:user/repo`.
///
/// Hand-written rather than `#[serde(untagged)]` on purpose. `untagged` buffers into an
/// intermediate value and tries each variant, which silently discards any
/// `deny_unknown_fields` on the variants and turns a field-level mistake into "no
/// variant matched" (plan §5). Here it would also cost an allocation per version on a
/// document that can hold several thousand.
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
                        // Unknown keys are skipped, matching the rest of this module.
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
}
