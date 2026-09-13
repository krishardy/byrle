//! Reading OSV's npm bundle, and naming what was read.
//!
//! The bundle is `npm/all.zip`. On 2026-09-13 it was 214,977,916 bytes: 228,951 deflate
//! entries, 379,092,155 bytes expanded, the largest entry 73,089 bytes. It is read from
//! memory. `ZipArchive` needs `Read + Seek` to reach the central directory at the end, and
//! holding the bytes avoids a temp file to create, protect and remove. The two ceilings below
//! bound what a broken or hostile upstream can make this allocate.

use super::load::Snapshot;
use super::osv::{self, Parsed, Rows, Skipped};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

pub const NPM_BUNDLE: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/// The name a snapshot records the npm bundle under.
pub const NPM_STREAM: &str = "osv/npm";

/// 2.5 times the bundle on 2026-09-13.
pub const MAX_BUNDLE_BYTES: usize = 512 << 20;

/// 14 times the largest record on 2026-09-13. Checked against the bytes decompression
/// produces, not the size an entry's header declares.
pub const MAX_RECORD_BYTES: u64 = 1 << 20;

/// What a bundle's records came to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub every_version: u64,
    pub listed_versions: u64,
    pub withdrawn: u64,
    pub not_malware: u64,
    pub no_npm_package: u64,
    pub needs_range_evaluation: u64,
}

impl Tally {
    fn count(&mut self, parsed: &Parsed) {
        let slot = match parsed {
            Parsed::Rows(rows) if rows.affected.iter().any(|a| a.version.is_none()) => {
                &mut self.every_version
            }
            Parsed::Rows(_) => &mut self.listed_versions,
            Parsed::Skipped(Skipped::Withdrawn) => &mut self.withdrawn,
            Parsed::Skipped(Skipped::NotMalware) => &mut self.not_malware,
            Parsed::Skipped(Skipped::NoNpmPackage) => &mut self.no_npm_package,
            Parsed::Skipped(Skipped::NeedsRangeEvaluation) => &mut self.needs_range_evaluation,
        };
        *slot += 1;
    }

    pub fn records(&self) -> u64 {
        self.every_version
            + self.listed_versions
            + self.withdrawn
            + self.not_malware
            + self.no_npm_package
            + self.needs_range_evaluation
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (label, count) in [
            ("stored: every version", self.every_version),
            ("stored: listed versions", self.listed_versions),
            ("skipped: withdrawn", self.withdrawn),
            ("skipped: not malware", self.not_malware),
            ("skipped: no npm package", self.no_npm_package),
            (
                "skipped: needs range evaluation",
                self.needs_range_evaluation,
            ),
            ("records", self.records()),
        ] {
            writeln!(f, "{label:32} {count:>8}")?;
        }
        Ok(())
    }
}

/// The rows a bundle holds, and what its records came to.
#[derive(Debug, Default)]
pub struct Bundle {
    pub rows: Vec<Rows>,
    pub tally: Tally,
}

/// Why a bundle could not be read. Any of these fails the whole bundle.
#[derive(Debug)]
pub enum BundleError {
    Archive(zip::result::ZipError),
    /// Reading an entry failed, a CRC mismatch included.
    Entry {
        name: String,
        error: std::io::Error,
    },
    TooLarge {
        name: String,
    },
    Record {
        name: String,
        error: serde_json::Error,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Archive(e) => write!(f, "not a readable zip archive: {e}"),
            Self::Entry { name, error } => write!(f, "{name}: {error}"),
            Self::TooLarge { name } => {
                write!(f, "{name}: expands past {MAX_RECORD_BYTES} bytes")
            }
            Self::Record { name, error } => write!(f, "{name}: not an OSV record: {error}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Read every record in a bundle.
///
/// One unreadable record fails the bundle. Skipping it would load a set missing whatever it
/// held with nothing to say so; failing leaves the previous load in place.
pub fn read_bundle(bytes: &[u8]) -> Result<Bundle, BundleError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(BundleError::Archive)?;
    let mut bundle = Bundle::default();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(BundleError::Archive)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        let mut record = Vec::new();
        if let Err(error) = entry.take(MAX_RECORD_BYTES + 1).read_to_end(&mut record) {
            return Err(BundleError::Entry { name, error });
        }
        if record.len() as u64 > MAX_RECORD_BYTES {
            return Err(BundleError::TooLarge { name });
        }
        let parsed = match osv::parse(&record) {
            Ok(parsed) => parsed,
            Err(error) => return Err(BundleError::Record { name, error }),
        };
        bundle.tally.count(&parsed);
        if let Parsed::Rows(rows) = parsed {
            bundle.rows.push(rows);
        }
    }
    Ok(bundle)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One stream's bundle, as a snapshot records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDigest {
    pub stream: String,
    pub sha256: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// Name what was loaded.
///
/// The id is the hash of the per-stream digests (plan §3), sorted by stream so the order
/// streams were fetched in cannot change it. `taken_at`, the etag and `last-modified` are
/// recorded and are not part of the id, so two proxies holding the same bytes agree.
pub fn snapshot(streams: &[StreamDigest], taken_at: &str) -> Snapshot {
    let mut sorted: Vec<&StreamDigest> = streams.iter().collect();
    sorted.sort_by(|a, b| a.stream.cmp(&b.stream));
    let joined: String = sorted
        .iter()
        .map(|s| format!("{}:{}\n", s.stream, s.sha256))
        .collect();
    let recorded: serde_json::Map<String, serde_json::Value> = sorted
        .iter()
        .map(|s| {
            (
                s.stream.clone(),
                serde_json::json!({
                    "sha256": s.sha256,
                    "etag": s.etag,
                    "last_modified": s.last_modified,
                }),
            )
        })
        .collect();
    Snapshot {
        id: format!("sha256:{}", sha256_hex(joined.as_bytes())),
        taken_at: taken_at.to_owned(),
        streams: serde_json::Value::Object(recorded).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/osv/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(path).expect("fixture is missing")
    }

    /// A stored (uncompressed) archive, so a test can place exact bytes in it.
    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("start entry");
            writer.write_all(bytes).expect("write entry");
        }
        writer.finish().expect("finish archive").into_inner()
    }

    fn stream(name: &str, sha256: &str) -> StreamDigest {
        StreamDigest {
            stream: name.to_owned(),
            sha256: sha256.to_owned(),
            etag: Some("\"e\"".to_owned()),
            last_modified: None,
        }
    }

    #[test]
    fn the_fixture_bundle_is_read_through_deflate() {
        let bundle = read_bundle(&fixture("bundle.zip")).expect("bundle reads");
        assert_eq!(
            bundle.tally,
            Tally {
                every_version: 3,
                listed_versions: 2,
                withdrawn: 1,
                needs_range_evaluation: 1,
                ..Tally::default()
            }
        );
        assert_eq!(bundle.rows.len(), 5);
        assert_eq!(bundle.tally.records(), 7);
    }

    #[test]
    fn a_directory_entry_is_not_a_record() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .add_directory("npm/", SimpleFileOptions::default())
            .expect("directory");
        writer
            .start_file("MAL-2021-1.json", SimpleFileOptions::default())
            .expect("start entry");
        writer
            .write_all(&fixture("MAL-2021-1.json"))
            .expect("write entry");
        let bytes = writer.finish().expect("finish").into_inner();

        assert_eq!(read_bundle(&bytes).expect("reads").tally.records(), 1);
    }

    #[test]
    fn a_record_past_the_ceiling_is_refused_and_one_at_it_is_not() {
        let over = vec![b' '; MAX_RECORD_BYTES as usize + 1];
        let err = read_bundle(&zip_of(&[("big.json", &over)])).expect_err("over the cap");
        assert!(matches!(&err, BundleError::TooLarge { name } if name == "big.json"));
        assert!(
            err.to_string().starts_with("big.json: expands past"),
            "{err}"
        );

        // At the ceiling it is read, and fails only as JSON.
        let at = vec![b' '; MAX_RECORD_BYTES as usize];
        assert!(matches!(
            read_bundle(&zip_of(&[("at.json", &at)])),
            Err(BundleError::Record { .. })
        ));
    }

    #[test]
    fn one_unreadable_record_fails_the_whole_bundle() {
        let good = fixture("MAL-2021-1.json");
        let err = read_bundle(&zip_of(&[
            ("MAL-2021-1.json", &good),
            ("broken.json", b"{"),
        ]))
        .expect_err("one bad record");
        assert!(matches!(&err, BundleError::Record { name, .. } if name == "broken.json"));
        assert!(
            err.to_string()
                .starts_with("broken.json: not an OSV record"),
            "{err}"
        );
    }

    #[test]
    fn a_corrupted_entry_fails_its_checksum() {
        let good = fixture("MAL-2021-1.json");
        let mut bytes = zip_of(&[("MAL-2021-1.json", &good)]);
        let at = bytes
            .windows(good.len())
            .position(|w| w == good.as_slice())
            .expect("stored bytes are in the archive");
        // A space inside the JSON, so only the checksum can notice.
        let space = at + good.iter().position(|&b| b == b' ').expect("a space");
        bytes[space] = b'\t';

        let err = read_bundle(&bytes).expect_err("checksum mismatch");
        assert!(matches!(&err, BundleError::Entry { name, .. } if name == "MAL-2021-1.json"));
        assert!(err.to_string().starts_with("MAL-2021-1.json: "), "{err}");
    }

    #[test]
    fn bytes_that_are_not_a_zip_are_refused() {
        let err = read_bundle(b"not a zip").expect_err("not an archive");
        assert!(matches!(err, BundleError::Archive(_)));
        assert!(err.to_string().starts_with("not a readable zip archive"));
    }

    #[test]
    fn the_tally_prints_every_outcome_and_the_total() {
        let tally = Tally {
            every_version: 2,
            not_malware: 1,
            no_npm_package: 1,
            ..Tally::default()
        };
        let text = tally.to_string();
        assert!(
            text.contains("stored: every version                   2\n"),
            "{text}"
        );
        assert!(
            text.contains("skipped: no npm package                 1\n"),
            "{text}"
        );
        assert!(
            text.ends_with("records                                 4\n"),
            "{text}"
        );
    }

    #[test]
    fn a_digest_is_lowercase_hex_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_snapshot_id_depends_on_the_digests_and_nothing_else() {
        let a = snapshot(&[stream("osv/npm", "aa"), stream("osv/pypi", "bb")], "t1");
        let reordered = snapshot(&[stream("osv/pypi", "bb"), stream("osv/npm", "aa")], "t2");
        assert_eq!(a.id, reordered.id, "order and time are not identity");
        assert!(a.id.starts_with("sha256:"));

        let changed = snapshot(&[stream("osv/npm", "ab"), stream("osv/pypi", "bb")], "t1");
        assert_ne!(a.id, changed.id);

        let recorded: serde_json::Value = serde_json::from_str(&a.streams).expect("json");
        assert_eq!(recorded["osv/npm"]["sha256"], "aa");
        assert_eq!(recorded["osv/npm"]["etag"], "\"e\"");
        assert_eq!(a.taken_at, "t1");
    }
}
