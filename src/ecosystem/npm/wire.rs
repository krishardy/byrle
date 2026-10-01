//! A packument as npm serves it: the deserialisation targets `normalize` reads, visible no
//! further than this ecosystem. See docs/engineering_decisions/npm-packument-shapes.md.

use std::collections::BTreeMap;

use serde::de;
use serde::{Deserialize, Deserializer};

use crate::record::Repository;

#[derive(Debug, Deserialize)]
pub(super) struct WirePackument {
    pub(super) name: String,
    #[serde(default, rename = "dist-tags", deserialize_with = "strings")]
    pub(super) dist_tags: BTreeMap<String, String>,
    /// Each version as written, read one at a time: a malformed one skips only itself.
    #[serde(default)]
    pub(super) versions: BTreeMap<String, Box<serde_json::value::RawValue>>,
    /// Full packument only. Keyed by version, plus `created` and `modified`.
    #[serde(default, deserialize_with = "strings")]
    pub(super) time: BTreeMap<String, String>,
    /// Package-level fallbacks for the per-version copies.
    #[serde(default, deserialize_with = "lenient")]
    pub(super) maintainers: Option<Vec<WireMaintainer>>,
    #[serde(default, deserialize_with = "repository")]
    pub(super) repository: Option<Repository>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WireVersion {
    #[serde(default)]
    pub(super) dist: Option<WireDist>,
    /// Abbreviated only, and present only when true.
    #[serde(default, rename = "hasInstallScript")]
    pub(super) has_install_script: Option<bool>,
    /// The message `npm deprecate` set, in both documents. `react` writes `false`.
    #[serde(default, deserialize_with = "lenient")]
    pub(super) deprecated: Option<String>,
    /// Full only.
    #[serde(default)]
    pub(super) scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(super) maintainers: Option<Vec<WireMaintainer>>,
    /// `qs` writes `{}`.
    #[serde(default, deserialize_with = "repository")]
    pub(super) repository: Option<Repository>,
    #[serde(default, rename = "_npmUser")]
    pub(super) npm_user: Option<WireNpmUser>,
    /// Full only.
    #[serde(default, rename = "gitHead", deserialize_with = "lenient")]
    pub(super) git_head: Option<String>,
    /// Only the entries a client fetches from where they point, kept as they are read.
    #[serde(default)]
    pub(super) dependencies: DirectSpecs,
    #[serde(default, rename = "optionalDependencies")]
    pub(super) optional_dependencies: DirectSpecs,
    #[serde(default, rename = "peerDependencies")]
    pub(super) peer_dependencies: DirectSpecs,
}

/// A field read as `T`, or `None` when it has another shape, so that a malformed field
/// does not make the whole document unreadable.
fn lenient<'de, D: Deserializer<'de>, T: de::DeserializeOwned>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Ok(T::deserialize(serde_json::Value::deserialize(deserializer)?).ok())
}

/// A map of strings, keeping only the entries whose value is one: a malformed `time` or
/// `dist-tags` entry does not make the whole document unreadable.
pub(super) fn strings<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    let map = BTreeMap::<String, serde_json::Value>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(text) => Some((key, text)),
            _ => None,
        })
        .collect())
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

/// `repository` as an object with a string `url`, or a shorthand string such as
/// `github:user/repo`. `None` for any other shape, such as `qs`'s `{}`.
/// Errors only when the JSON itself is broken.
fn repository<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Repository>, D::Error> {
    let text = |value: &serde_json::Value| value.as_str().map(str::to_owned);
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(url) => Some(Repository {
            url,
            kind: None,
            directory: None,
        }),
        serde_json::Value::Object(fields) => {
            fields.get("url").and_then(text).map(|url| Repository {
                url,
                kind: fields.get("type").and_then(text),
                directory: fields.get("directory").and_then(text),
            })
        }
        _ => None,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Each shape `repository` takes, and broken JSON, which is still an error.
    #[test]
    fn a_repository_reads_each_shape_and_nothing_else() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(deserialize_with = "repository")]
            repository: Option<Repository>,
        }
        let read = |json: &str| {
            serde_json::from_str::<Holder>(&format!(r#"{{"repository": {json}}}"#))
                .map(|holder| holder.repository)
        };
        let repo = |url: &str, kind: Option<&str>, directory: Option<&str>| {
            Some(Repository {
                url: url.to_owned(),
                kind: kind.map(str::to_owned),
                directory: directory.map(str::to_owned),
            })
        };
        assert_eq!(
            read(r#""github:o/r""#).unwrap(),
            repo("github:o/r", None, None)
        );
        assert_eq!(
            read(r#"{"url": "u", "type": "git", "directory": "d", "other": 1}"#).unwrap(),
            repo("u", Some("git"), Some("d"))
        );
        assert_eq!(
            read(r#"{"url": "u", "type": 5, "directory": 5}"#).unwrap(),
            repo("u", None, None)
        );
        for json in [r#"{"url": 5}"#, r#"{"type": "git"}"#, "{}", "42"] {
            assert_eq!(read(json).unwrap(), None, "{json}");
        }
        assert!(read(r#"{"url": "u", "#).is_err());
        assert!(serde_json::from_slice::<DirectSpecs>(b"{").is_err());
        for cut in [r#"{"deprecated":"#, r#"{"gitHead":"#, r#"{"dependencies":"#] {
            assert!(serde_json::from_str::<WireVersion>(cut).is_err(), "{cut}");
        }
    }
}
