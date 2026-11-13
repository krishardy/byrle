//! An index file as cargo's sparse protocol serves it: one JSON object per line, one line
//! per version. Keys a line carries beyond these are not read.

use serde::Deserialize;

use crate::identity::{Ecosystem, PackageKey};
use crate::record::{
    Artifact, DocumentDetail, PackageMetadata, PackageRecord, Provenance, SkippedVersion,
};

use super::FILES;
use super::paths::{CRATES, filename};

/// One line of an index file.
#[derive(Debug, Clone, Deserialize)]
pub struct Line {
    pub name: String,
    pub vers: String,
    /// The `.crate`'s sha256, in hex.
    pub cksum: String,
    #[serde(default)]
    pub yanked: bool,
    /// When the version was published. crates.io writes it on every line it serves.
    pub pubtime: Option<String>,
}

/// The version a line names, read alone, for removing a line without reading the rest.
#[derive(Deserialize)]
pub(super) struct Version {
    pub vers: String,
}

/// The lines of `decoded` that hold anything, with their 1-based line numbers.
pub(super) fn lines(decoded: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    decoded
        .split(|b| *b == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.trim_ascii().is_empty())
        .map(|(at, line)| (at + 1, line))
}

/// Every version in an index file as records. A line that does not parse, or names
/// another crate, is kept in `skipped`.
/// Errors when no line names a crate.
pub fn normalize(decoded: &[u8]) -> Result<PackageMetadata, String> {
    let mut key: Option<PackageKey> = None;
    let (mut records, mut skipped) = (Vec::new(), Vec::new());
    for (at, text) in lines(decoded) {
        let read = serde_json::from_slice::<Line>(text)
            .map_err(|e| e.to_string())
            .and_then(|line| {
                let this = PackageKey::from_registry_name(Ecosystem::Cargo, &line.name)
                    .map_err(|e| e.to_string())?;
                let key = key.get_or_insert_with(|| this.clone());
                if *key != this {
                    return Err(format!("names `{}`, not `{}`", line.name, key.name()));
                }
                record(key, &line)
            });
        match read {
            Ok(record) => records.push(record),
            Err(reason) => skipped.push(SkippedVersion {
                version: format!("line {at}"),
                reason,
            }),
        }
    }
    Ok(PackageMetadata {
        key: key.ok_or("no line names a crate")?,
        latest: None,
        records,
        skipped,
    })
}

/// One line as the common record, its one file the `.crate`.
fn record(key: &PackageKey, line: &Line) -> Result<PackageRecord, String> {
    let package = key.at_version(&line.vers).map_err(|e| e.to_string())?;
    let published_at = match &line.pubtime {
        Some(time) => Some(
            time.parse::<jiff::Timestamp>()
                .map_err(|e| format!("pubtime `{time}`: {e}"))?,
        ),
        None => None,
    };
    let yanked = line.yanked.then(String::new);
    Ok(PackageRecord {
        package,
        detail: DocumentDetail::Full,
        published_at,
        maintainers: None,
        repository: None,
        yanked: yanked.clone(),
        deprecated: None,
        has_install_scripts: false,
        install_scripts: None,
        provenance: Provenance::default(),
        direct_dependencies: Vec::new(),
        artifacts: vec![Artifact {
            filename: filename(key, &line.vers),
            runs_install_scripts: false,
            url: format!("{FILES}/{CRATES}/{}/{}/download", line.name, line.vers),
            integrity: crate::integrity::sri_from_sha256_hex(&line.cksum),
            yanked,
            legacy_sha1: None,
            attestation_url: None,
            published_at: None,
            file_count: None,
            unpacked_size: None,
        }],
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// itoa's index file from index.crates.io, 2026-10-14: 37 lines, each with `pubtime`.
    #[test]
    fn itoa_s_index_file_becomes_a_record_per_line() {
        let metadata = normalize(&super::super::fixture()).expect("reads");
        assert_eq!(metadata.key.to_string(), "pkg:cargo/itoa");
        assert_eq!(metadata.records.len(), 37);
        assert!(metadata.skipped.is_empty());
        let latest = metadata.version("1.0.18").expect("listed");
        assert_eq!(
            latest.artifacts[0].integrity.as_deref(),
            crate::integrity::sri_from_sha256_hex(
                "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"
            )
            .as_deref()
        );
        assert_eq!(latest.artifacts[0].filename, "itoa-1.0.18.crate");
        assert_eq!(
            latest.artifacts[0].url,
            "https://static.crates.io/crates/itoa/1.0.18/download"
        );
        let first = metadata.version("0.1.0").expect("listed");
        assert_eq!(
            first.published_at,
            Some("2016-06-25T21:50:33Z".parse().unwrap())
        );
        assert!(metadata.records.iter().all(|r| r.published_at.is_some()));
    }

    /// The download keeps the published spelling, which static.crates.io needs.
    #[test]
    fn a_mixed_case_name_keys_lowercased_and_downloads_as_published() {
        let line = br#"{"name":"Inflector","vers":"0.11.4","cksum":"fe438567e2a3a2d5a28d0fb8c1a9b8b8b6b6c1c9b8f6b8b8b6b6c1c9b8f6b8b8","yanked":true}"#;
        let metadata = normalize(line).expect("reads");
        let record = &metadata.records[0];
        assert_eq!(record.package.to_string(), "pkg:cargo/inflector@0.11.4");
        assert_eq!(record.published_at, None);
        assert_eq!(record.yanked.as_deref(), Some(""));
        assert_eq!(record.artifacts[0].yanked.as_deref(), Some(""));
        assert_eq!(record.artifacts[0].filename, "inflector-0.11.4.crate");
        assert_eq!(
            record.artifacts[0].url,
            "https://static.crates.io/crates/Inflector/0.11.4/download"
        );
    }

    #[test]
    fn a_line_that_cannot_be_read_is_skipped_with_its_reason() {
        let body = concat!(
            r#"{"name":"a","vers":"1.0.0","cksum":"00"}"#,
            "\n\nnot json\n",
            r#"{"name":"b","vers":"1.0.0","cksum":"00"}"#,
            "\n",
            r#"{"name":"a","vers":" ","cksum":"00"}"#,
            "\n",
            r#"{"name":"a","vers":"2.0.0","cksum":"00","pubtime":"yesterday"}"#,
            "\n",
        );
        let metadata = normalize(body.as_bytes()).expect("reads");
        assert_eq!(metadata.records.len(), 1);
        let skipped: Vec<(&str, &str)> = metadata
            .skipped
            .iter()
            .map(|s| (s.version.as_str(), s.reason.as_str()))
            .collect();
        assert_eq!(skipped[0].0, "line 3");
        assert_eq!(skipped[1], ("line 4", "names `b`, not `a`"));
        assert!(skipped[2].1.contains("empty version"), "{skipped:?}");
        assert!(
            skipped[3].1.starts_with("pubtime `yesterday`"),
            "{skipped:?}"
        );
        assert_eq!(
            metadata.records[0].artifacts[0].integrity, None,
            "not a sha256"
        );
    }

    #[test]
    fn a_file_naming_no_crate_is_an_error() {
        assert_eq!(normalize(b"").unwrap_err(), "no line names a crate");
        assert_eq!(normalize(b"x\n").unwrap_err(), "no line names a crate");
        assert!(normalize(br#"{"name":"a/b","vers":"1","cksum":""}"#).is_err());
    }
}
