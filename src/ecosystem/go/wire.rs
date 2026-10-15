//! A module's `@v/list` and `@latest` as records: the list one version per line, and
//! `@latest` one version's JSON with its time. Neither carries a digest; sum.golang.org holds
//! each version's.

use serde::Deserialize;

use crate::identity::PackageKey;
use crate::intel::range::{Ordered, VersionOrder};
use crate::record::{
    Artifact, DocumentDetail, PackageMetadata, PackageRecord, Provenance, SkippedVersion,
};

use super::paths::{escape, filename};

/// `@latest`'s JSON, and an `.info`'s: a version and when it was published.
#[derive(Debug, Clone, Deserialize)]
pub struct Info {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Time")]
    pub time: Option<String>,
}

/// The version a list line names: its first word, as the go command reads it. `None` when
/// that is not a Go version.
pub fn listed(line: &[u8]) -> Option<&str> {
    let word = std::str::from_utf8(line).ok()?.split_whitespace().next()?;
    (word.starts_with('v') && VersionOrder::Go.parse(word).is_some()).then_some(word)
}

/// `versions` in the order the go command prefers them, as `@latest` does: releases newest
/// first, then pre-releases and pseudo-versions, then `+incompatible` versions.
pub fn preferred<'a>(versions: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut sorted: Vec<&str> = versions.collect();
    sorted.sort_by_cached_key(|version| {
        let parsed = VersionOrder::Go.parse(version);
        let pre = matches!(&parsed, Some(Ordered::SemVer(v)) if !v.pre.is_empty());
        (
            version.ends_with("+incompatible"),
            pre,
            std::cmp::Reverse(parsed),
        )
    });
    sorted
}

/// Each version a `@v/list` names as a record of `key`, its zip under `files`. A line that
/// names no version is kept in `skipped`; an empty line is not.
pub fn list(key: &PackageKey, decoded: &[u8], files: &str) -> PackageMetadata {
    let (mut records, mut skipped) = (Vec::new(), Vec::new());
    for (at, line) in decoded.split(|b| *b == b'\n').enumerate() {
        if line.trim_ascii().is_empty() {
            continue;
        }
        match listed(line) {
            Some(version) => records.push(record(key, version, None, files)),
            None => skipped.push(SkippedVersion {
                version: format!("line {}", at + 1),
                reason: "names no Go version".to_owned(),
            }),
        }
    }
    PackageMetadata {
        key: key.clone(),
        latest: None,
        records,
        skipped,
    }
}

/// The version `@latest` names as a record of `key`, its `Time` the publish time.
/// Errors when the body names no version, or a time that does not parse.
pub fn latest(key: &PackageKey, decoded: &[u8], files: &str) -> Result<PackageMetadata, String> {
    let info: Info = serde_json::from_slice(decoded).map_err(|e| e.to_string())?;
    if listed(info.version.as_bytes()) != Some(info.version.as_str()) {
        return Err(format!("`{}` is not a Go version", info.version));
    }
    let published_at = published(&info)?;
    Ok(PackageMetadata {
        key: key.clone(),
        latest: Some(info.version.clone()),
        records: vec![record(key, &info.version, published_at, files)],
        skipped: Vec::new(),
    })
}

/// When `info` says its version was published. Errors when its `Time` does not parse.
pub fn published(info: &Info) -> Result<Option<jiff::Timestamp>, String> {
    info.time
        .as_deref()
        .map(|time| {
            time.parse::<jiff::Timestamp>()
                .map_err(|e| format!("Time `{time}`: {e}"))
        })
        .transpose()
}

/// One version as the common record, its one file the zip.
pub fn record(
    key: &PackageKey,
    version: &str,
    published_at: Option<jiff::Timestamp>,
    files: &str,
) -> PackageRecord {
    PackageRecord {
        package: key
            .at_version(version)
            .expect("a listed version is not empty"),
        detail: DocumentDetail::Full,
        published_at,
        maintainers: None,
        repository: None,
        yanked: None,
        deprecated: None,
        has_install_scripts: false,
        install_scripts: None,
        provenance: Provenance::default(),
        direct_dependencies: Vec::new(),
        artifacts: vec![Artifact {
            filename: filename(version),
            runs_install_scripts: false,
            url: format!("{files}{}.zip", escape(version)),
            integrity: None,
            yanked: None,
            legacy_sha1: None,
            attestation_url: None,
            file_count: None,
            unpacked_size: None,
        }],
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;

    const FILES: &str = "https://proxy.golang.org/golang.org/x/text/@v/";

    fn text() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Go, "golang.org/x/text").unwrap()
    }

    /// golang.org/x/text's list from proxy.golang.org: 51 versions, in no order.
    #[test]
    fn each_listed_version_is_a_record_with_its_zip_and_no_digest() {
        let metadata = list(&text(), &super::super::fixture("text.list"), FILES);
        assert_eq!(metadata.records.len(), 51);
        assert!(metadata.skipped.is_empty());
        let record = metadata.version("v0.20.0").expect("listed");
        assert_eq!(
            record.package.to_string(),
            "pkg:golang/golang.org/x/text@v0.20.0"
        );
        assert_eq!(record.published_at, None);
        let zip = &record.artifacts[0];
        assert_eq!(zip.filename, "v0.20.0.zip");
        assert_eq!(zip.url, format!("{FILES}v0.20.0.zip"));
        assert_eq!(zip.integrity, None);
    }

    /// A version is escaped in its URL, and a line the go command would skip is skipped.
    #[test]
    fn a_line_naming_no_version_is_skipped() {
        let metadata = list(&text(), b"v1.0.0-RC1 2020-01-01\n\nnot\nv1.x\n", FILES);
        assert_eq!(
            metadata.records[0].artifacts[0].url,
            format!("{FILES}v1.0.0-!r!c1.zip")
        );
        let skipped: Vec<&str> = metadata
            .skipped
            .iter()
            .map(|s| s.version.as_str())
            .collect();
        assert_eq!(skipped, ["line 3", "line 4"]);
        assert_eq!(listed(b"\xff"), None);
        assert_eq!(listed(b"1.0.0"), None, "no v");
    }

    /// k8s.io/client-go's v1.5.2 is its `@latest` though every v0.x came after it, and a
    /// pre-release is chosen only when there is no release.
    #[test]
    fn versions_are_preferred_as_the_go_command_prefers_them() {
        let listed = [
            "v0.20.0",
            "v1.5.2",
            "v11.0.0+incompatible",
            "v0.0.0-20170915032832-14c0d48ead0c",
            "v1.6.0-rc.1",
            "v0.34.1",
        ];
        assert_eq!(
            preferred(listed.into_iter()),
            [
                "v1.5.2",
                "v0.34.1",
                "v0.20.0",
                "v1.6.0-rc.1",
                "v0.0.0-20170915032832-14c0d48ead0c",
                "v11.0.0+incompatible",
            ]
        );
    }

    #[test]
    fn latest_names_one_version_with_its_time() {
        let metadata =
            latest(&text(), &super::super::fixture("text.latest"), FILES).expect("reads");
        assert_eq!(metadata.latest.as_deref(), Some("v0.43.0"));
        assert_eq!(
            metadata.records[0].published_at,
            Some("2026-10-09T15:18:32Z".parse().unwrap())
        );
        let untimed = latest(&text(), br#"{"Version":"v1.0.0"}"#, FILES).expect("reads");
        assert_eq!(untimed.records[0].published_at, None);
        for (body, error) in [
            (&b"not json"[..], "expected"),
            (br#"{"Version":"1.0.0"}"#, "is not a Go version"),
            (br#"{"Version":" "}"#, "is not a Go version"),
            (br#"{"Version":"v1.0.0","Time":"then"}"#, "Time `then`"),
        ] {
            let found = latest(&text(), body, FILES).unwrap_err();
            assert!(found.contains(error), "{found}");
        }
    }
}
