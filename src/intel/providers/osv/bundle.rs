//! Reading one ecosystem's OSV bundle, `npm/all.zip` or `PyPI/all.zip`, from memory, within
//! the two ceilings below. See docs/engineering_decisions/osv-malware-load.md.

use crate::identity::Ecosystem;
use crate::intel::providers::osv::{self, Parsed, Skipped};
use crate::intel::rows::Rows;
use std::io::{Cursor, Read};

pub const NPM_BUNDLE: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/// The name a snapshot records the npm bundle under.
pub const NPM_STREAM: &str = "osv/npm";

/// 34,417,496 bytes on 2026-09-18.
pub const PYPI_BUNDLE: &str = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip";

/// The name a snapshot records the PyPI bundle under.
pub const PYPI_STREAM: &str = "osv/pypi";

/// 2.5 times the bundle on 2026-09-13.
pub const MAX_BUNDLE_BYTES: usize = 512 << 20;

/// Bytes past which one record is refused, counted as they decompress, not as declared.
pub const MAX_RECORD_BYTES: u64 = 1 << 20;

/// What a bundle's records came to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub malware: u64,
    pub scored: u64,
    /// Scored from a severity band rather than a CVSS vector. Already counted in `scored`.
    pub banded: u64,
    /// Scored from a scored alias in the same bundle, and counted in `scored` too.
    pub from_alias: u64,
    pub unscored: u64,
    pub withdrawn: u64,
    pub other_publisher: u64,
    /// Records with no `affected` entry for the ecosystem being read.
    pub no_package: u64,
    pub nothing_storable: u64,
    /// Stored records with an entry or a range left out. Already counted above.
    pub partly_stored: u64,
    /// CVSS vectors that did not parse, across stored records.
    pub unread_vectors: u64,
}

impl Tally {
    fn count(&mut self, parsed: &Parsed) {
        let slot = match parsed {
            Parsed::Rows(rows) => {
                self.partly_stored += u64::from(rows.unexpressed > 0);
                self.unread_vectors += rows.unread_vectors as u64;
                self.banded += u64::from(!rows.malware && rows.band.is_some());
                match (rows.malware, rows.cvss) {
                    (true, _) => &mut self.malware,
                    (false, Some(_)) => &mut self.scored,
                    (false, None) => &mut self.unscored,
                }
            }
            Parsed::Skipped(Skipped::Withdrawn) => &mut self.withdrawn,
            Parsed::Skipped(Skipped::OtherPublisher) => &mut self.other_publisher,
            Parsed::Skipped(Skipped::NoPackage) => &mut self.no_package,
            Parsed::Skipped(Skipped::NothingStorable) => &mut self.nothing_storable,
        };
        *slot += 1;
    }

    pub fn records(&self) -> u64 {
        self.malware
            + self.scored
            + self.unscored
            + self.withdrawn
            + self.other_publisher
            + self.no_package
            + self.nothing_storable
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lines: String = [
            ("stored: malware", self.malware),
            ("stored: vulnerability, scored", self.scored),
            ("scored from a severity band", self.banded),
            ("scored from an alias", self.from_alias),
            ("stored: vulnerability, unscored", self.unscored),
            ("skipped: withdrawn", self.withdrawn),
            ("skipped: other publisher", self.other_publisher),
            ("skipped: no package", self.no_package),
            ("skipped: nothing storable", self.nothing_storable),
            ("records", self.records()),
            ("stored with something left out", self.partly_stored),
            ("CVSS vectors unread", self.unread_vectors),
        ]
        .iter()
        .map(|(label, count)| format!("{label:32} {count:>8}\n"))
        .collect();
        f.write_str(&lines)
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

/// Read every record in `ecosystem`'s bundle.
///
/// One unreadable record fails the bundle. Skipping it would load a set missing whatever it
/// held with nothing to say so; failing leaves the previous load in place.
pub fn read_bundle(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Bundle, BundleError> {
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
        let parsed = match osv::parse(ecosystem, &record) {
            Ok(parsed) => parsed,
            Err(error) => return Err(BundleError::Record { name, error }),
        };
        bundle.tally.count(&parsed);
        if let Parsed::Rows(rows) = parsed {
            bundle.rows.push(*rows);
        }
    }
    let from_alias = crate::intel::rows::score_from_aliases(&mut bundle.rows);
    bundle.tally.unscored -= from_alias;
    bundle.tally.scored += from_alias;
    bundle.tally.from_alias = from_alias;
    Ok(bundle)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// 215,141,389 bytes on 2026-09-17, so the ceiling holds it with room to grow.
    #[test]
    fn the_bundle_ceiling_is_512_mib() {
        assert_eq!(MAX_BUNDLE_BYTES, 536_870_912);
        const { assert!(MAX_BUNDLE_BYTES > 215_141_389) };
    }

    #[test]
    fn the_fixture_bundle_is_read_through_deflate() {
        let bundle = read_bundle(Ecosystem::Npm, &fixture("bundle.zip")).expect("bundle reads");
        assert_eq!(
            bundle.tally,
            Tally {
                malware: 6,
                withdrawn: 1,
                ..Tally::default()
            }
        );
        assert_eq!(bundle.rows.len(), 6);
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

        assert_eq!(
            read_bundle(Ecosystem::Npm, &bytes)
                .expect("reads")
                .tally
                .records(),
            1
        );
    }

    #[test]
    fn a_record_past_the_ceiling_is_refused_and_one_at_it_is_not() {
        let over = vec![b' '; MAX_RECORD_BYTES as usize + 1];
        let err =
            read_bundle(Ecosystem::Npm, &zip_of(&[("big.json", &over)])).expect_err("over the cap");
        assert!(matches!(&err, BundleError::TooLarge { name } if name == "big.json"));
        assert!(
            err.to_string().starts_with("big.json: expands past"),
            "{err}"
        );

        let at = vec![b' '; MAX_RECORD_BYTES as usize];
        assert!(matches!(
            read_bundle(Ecosystem::Npm, &zip_of(&[("at.json", &at)])),
            Err(BundleError::Record { .. })
        ));
    }

    #[test]
    fn one_unreadable_record_fails_the_whole_bundle() {
        let good = fixture("MAL-2021-1.json");
        let err = read_bundle(
            Ecosystem::Npm,
            &zip_of(&[("MAL-2021-1.json", &good), ("broken.json", b"{")]),
        )
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
        let space = at + good.iter().position(|&b| b == b' ').expect("a space");
        bytes[space] = b'\t';

        let err = read_bundle(Ecosystem::Npm, &bytes).expect_err("checksum mismatch");
        assert!(matches!(&err, BundleError::Entry { name, .. } if name == "MAL-2021-1.json"));
        assert!(err.to_string().starts_with("MAL-2021-1.json: "), "{err}");
    }

    #[test]
    fn bytes_that_are_not_a_zip_are_refused() {
        let err = read_bundle(Ecosystem::Npm, b"not a zip").expect_err("not an archive");
        assert!(matches!(err, BundleError::Archive(_)));
        assert!(err.to_string().starts_with("not a readable zip archive"));
    }

    #[test]
    fn the_tally_prints_every_outcome_and_the_total() {
        let tally = Tally {
            malware: 2,
            scored: 1,
            banded: 1,
            from_alias: 1,
            unscored: 1,
            other_publisher: 1,
            no_package: 1,
            nothing_storable: 1,
            withdrawn: 1,
            partly_stored: 3,
            unread_vectors: 5,
        };
        let text = tally.to_string();
        assert_eq!(
            text,
            "stored: malware                         2\n\
             stored: vulnerability, scored           1\n\
             scored from a severity band             1\n\
             scored from an alias                    1\n\
             stored: vulnerability, unscored         1\n\
             skipped: withdrawn                      1\n\
             skipped: other publisher                1\n\
             skipped: no package                     1\n\
             skipped: nothing storable               1\n\
             records                                 8\n\
             stored with something left out          3\n\
             CVSS vectors unread                     5\n"
        );
    }

    #[test]
    fn stored_records_are_tallied_by_kind_and_what_they_left_out() {
        let mut tally = Tally::default();
        let rows = |malware, cvss, band: Option<&str>, unexpressed, unread_vectors| {
            Parsed::Rows(Box::new(Rows {
                id: "X".to_owned(),
                summary: None,
                modified: None,
                malware,
                cvss,
                band: band.map(str::to_owned),
                unread_vectors,
                aliases: Default::default(),
                affected: Default::default(),
                ranges: Default::default(),
                unexpressed,
            }))
        };
        tally.count(&rows(true, Some(8.9), Some("HIGH"), 0, 0));
        tally.count(&rows(false, Some(9.8), None, 1, 2));
        tally.count(&rows(false, Some(8.9), Some("HIGH"), 0, 0));
        tally.count(&rows(false, Some(3.9), Some("LOW"), 0, 0));
        tally.count(&rows(false, None, None, 2, 1));
        tally.count(&Parsed::Skipped(Skipped::OtherPublisher));
        tally.count(&Parsed::Skipped(Skipped::NothingStorable));
        assert_eq!(
            tally,
            Tally {
                malware: 1,
                scored: 3,
                banded: 2,
                unscored: 1,
                other_publisher: 1,
                nothing_storable: 1,
                partly_stored: 2,
                unread_vectors: 3,
                ..Tally::default()
            }
        );
    }

    /// A bundle's unscored vulnerability takes its scored alias's score, and the tally moves
    /// it from unscored to scored.
    #[test]
    fn an_unscored_record_in_a_bundle_takes_its_aliass_score() {
        let pypi = |id: &str, extra: &str| {
            format!(
                r#"{{"id": "{id}", {extra} "affected": [{{"package": {{"ecosystem": "PyPI", "name": "requests"}}, "versions": ["2.19.0"]}}]}}"#
            )
        };
        let (pysec, ghsa, lone) = (
            pypi("PYSEC-2018-28", r#""aliases": ["GHSA-x84v-xcm2-53pg"],"#),
            pypi(
                "GHSA-x84v-xcm2-53pg",
                r#""severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],"#,
            ),
            pypi("PYSEC-2099-1", ""),
        );
        let bundle = read_bundle(
            Ecosystem::PyPI,
            &zip_of(&[
                ("a.json", pysec.as_bytes()),
                ("b.json", ghsa.as_bytes()),
                ("c.json", lone.as_bytes()),
            ]),
        )
        .expect("reads");
        assert_eq!(
            (
                bundle.tally.scored,
                bundle.tally.from_alias,
                bundle.tally.unscored
            ),
            (2, 1, 1)
        );
        let cvss = |id: &str| bundle.rows.iter().find(|r| r.id == id).and_then(|r| r.cvss);
        assert_eq!(cvss("PYSEC-2018-28"), cvss("GHSA-x84v-xcm2-53pg"));
        assert_eq!(cvss("PYSEC-2018-28"), Some(7.5));
        assert_eq!(cvss("PYSEC-2099-1"), None);
    }

    /// A record naming no package is counted as skipped for it.
    #[test]
    fn a_record_with_no_package_is_counted() {
        let mut tally = Tally::default();
        tally.count(&Parsed::Skipped(Skipped::NoPackage));
        assert_eq!(
            tally,
            Tally {
                no_package: 1,
                ..Tally::default()
            }
        );
    }

    /// An entry whose local header is not one fails the bundle, as the archive does.
    #[test]
    fn an_entry_that_cannot_be_opened_is_an_archive_error() {
        let mut bytes = zip_of(&[("MAL-2021-1.json", b"{}")]);
        bytes[..4].copy_from_slice(b"XXXX");
        let err = read_bundle(Ecosystem::Npm, &bytes).expect_err("a broken entry");
        assert!(matches!(err, BundleError::Archive(_)), "{err}");
    }
}
