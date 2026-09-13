//! An intel store read from a kept snapshot, for `waharoa policy diff --snapshot`.
//!
//! Answers what [`PgIntel`](super::postgres::PgIntel) answers, from a snapshot's files
//! rather than Postgres's latest load. Every source's rows are decoded and indexed by package
//! when the snapshot is read. See docs/engineering_decisions/snapshot-identity.md.
//!
//! A kept snapshot records no streams: its manifest holds only what the id is the digest of.
//! `taken_at` is when the manifest was last written.

use super::range::Interval;
use super::snapshot_dir::{KeptError, SnapshotDir};
use super::store::{Intel, LoadedSnapshot, Lookup, PackageIntel, Record};
use std::collections::HashMap;

/// One kept snapshot, in memory.
#[derive(Debug)]
pub struct SnapshotIntel {
    snapshot: LoadedSnapshot,
    /// By ecosystem and name.
    packages: HashMap<(String, String), PackageIntel>,
}

impl SnapshotIntel {
    /// Read snapshot `id` from `dir`. Every file is checked against its digest.
    pub fn read(dir: &SnapshotDir, id: &str) -> Result<Self, KeptError> {
        let taken_at = dir.written(id)?;
        let mut packages = HashMap::new();
        for (source, digest) in dir.sources(id)? {
            for rows in dir.read_source(&source, &digest)? {
                // Every column but these two comes from the rows. The loader writes neither.
                let record = Record {
                    advisory_id: rows.id.clone(),
                    aliases: rows.aliases.iter().cloned().collect(),
                    source: source.clone(),
                    cvss: rows.cvss,
                    cvss_source: None,
                    exploited: false,
                    malware: rows.malware,
                };
                for affected in &rows.affected {
                    package(&mut packages, id, &affected.ecosystem, &affected.name)
                        .records
                        .push((affected.version.clone(), record.clone()));
                }
                for ranged in &rows.ranges {
                    let (fixed, last_affected) = ranged.interval.end.columns();
                    let interval = Interval::from_columns(
                        ranged.interval.introduced.as_deref(),
                        fixed,
                        last_affected,
                    )
                    .ok_or_else(|| KeptError::Range {
                        digest: digest.clone(),
                        advisory_id: rows.id.clone(),
                    })?;
                    package(&mut packages, id, &ranged.ecosystem, &ranged.name)
                        .ranges
                        .push((interval, record.clone()));
                }
            }
        }
        Ok(Self {
            snapshot: LoadedSnapshot {
                digest: id.to_owned(),
                taken_at,
                streams: Vec::new(),
            },
            packages,
        })
    }

    fn answer(&self, ecosystem: &str, name: &str) -> PackageIntel {
        self.packages
            .get(&(ecosystem.to_owned(), name.to_owned()))
            .cloned()
            .unwrap_or_else(|| nothing_against(&self.snapshot.digest))
    }
}

fn package<'a>(
    packages: &'a mut HashMap<(String, String), PackageIntel>,
    id: &str,
    ecosystem: &str,
    name: &str,
) -> &'a mut PackageIntel {
    packages
        .entry((ecosystem.to_owned(), name.to_owned()))
        .or_insert_with(|| nothing_against(id))
}

/// A package no advisory in snapshot `id` is against.
fn nothing_against(id: &str) -> PackageIntel {
    PackageIntel {
        snapshot: id.to_owned(),
        records: Vec::new(),
        ranges: Vec::new(),
    }
}

impl Intel for SnapshotIntel {
    fn lookup<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
        version: &'a str,
    ) -> Lookup<'a, Vec<Record>> {
        Box::pin(async move {
            Ok(self
                .answer(ecosystem, name)
                .for_version(version)
                .into_iter()
                .cloned()
                .collect())
        })
    }

    fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
        Box::pin(async move { Ok(Some(self.snapshot.clone())) })
    }

    /// Always `Some`: a snapshot that was read has been loaded.
    fn package<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
    ) -> Lookup<'a, Option<PackageIntel>> {
        Box::pin(async move { Ok(Some(self.answer(ecosystem, name))) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::load;
    use crate::intel::osv::{Affected, Ranged, Rows};
    use crate::intel::range::End;
    use crate::test_support::tempdir;

    fn advisory(id: &str) -> Rows {
        Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware: id.starts_with("MAL-"),
            cvss: None,
            unread_vectors: 0,
            aliases: Default::default(),
            affected: Default::default(),
            ranges: Default::default(),
            unexpressed: 0,
        }
    }

    fn affected(name: &str, version: Option<&str>) -> Affected {
        Affected {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    fn ranged(name: &str, introduced: &str, end: End<String>) -> Ranged {
        Ranged {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            interval: Interval {
                introduced: Some(introduced.to_owned()),
                end,
            },
        }
    }

    /// Keep `sources` as one snapshot in a directory of its own, and give its id.
    fn kept(label: &str, sources: &[(&str, Vec<Rows>)]) -> (SnapshotDir, String) {
        let dir = SnapshotDir::open(&tempdir(label)).expect("opens");
        let mut digests = Vec::new();
        for (source, rows) in sources {
            let encoded = load::encode(source, rows);
            dir.write_rows(&encoded).expect("writes rows");
            digests.push((source.to_string(), encoded.digest));
        }
        let manifest = load::manifest(digests.iter().map(|(s, d)| (s.as_str(), d.as_str())));
        dir.write_snapshot(&manifest).expect("writes the snapshot");
        (dir, load::snapshot_id(&manifest))
    }

    #[tokio::test]
    async fn a_kept_snapshot_answers_each_package_from_its_rows() {
        let malware = Rows {
            aliases: ["GHSA-e".to_owned()].into(),
            affected: [affected("evil", None)].into(),
            ..advisory("MAL-1")
        };
        let vulnerability = Rows {
            cvss: Some(7.5),
            affected: [affected("lib", Some("1.0.0"))].into(),
            ranges: [ranged("lib", "2.0.0", End::Fixed("2.1.0".to_owned()))].into(),
            ..advisory("GHSA-1")
        };
        let (dir, id) = kept("intel-answers", &[("osv", vec![malware, vulnerability])]);
        let intel = SnapshotIntel::read(&dir, &id).expect("reads");

        let evil = intel
            .package("npm", "evil")
            .await
            .expect("answers")
            .expect("loaded");
        assert_eq!(
            evil,
            PackageIntel {
                snapshot: id.clone(),
                records: vec![(
                    None,
                    Record {
                        advisory_id: "MAL-1".to_owned(),
                        aliases: vec!["GHSA-e".to_owned()],
                        source: "osv".to_owned(),
                        cvss: None,
                        cvss_source: None,
                        exploited: false,
                        malware: true,
                    }
                )],
                ranges: Vec::new(),
            }
        );

        for (version, hits) in [("1.0.0", 1), ("1.5.0", 0), ("2.0.5", 1), ("2.1.0", 0)] {
            let found = intel.lookup("npm", "lib", version).await.expect("answers");
            assert_eq!(found.len(), hits, "{version}");
            assert!(found.iter().all(|r| r.cvss == Some(7.5) && !r.malware));
        }
    }

    #[tokio::test]
    async fn a_package_nothing_is_against_is_an_empty_answer_naming_the_snapshot() {
        let malware = Rows {
            affected: [affected("evil", None)].into(),
            ..advisory("MAL-1")
        };
        let (dir, id) = kept("intel-nothing", &[("osv", vec![malware])]);
        let intel = SnapshotIntel::read(&dir, &id).expect("reads");

        for (ecosystem, name) in [("npm", "lodash"), ("PyPI", "evil")] {
            assert_eq!(
                intel.package(ecosystem, name).await.expect("answers"),
                Some(nothing_against(&id)),
                "{ecosystem} {name}"
            );
        }
        let snapshot = intel.snapshot().await.expect("answers").expect("loaded");
        assert_eq!(snapshot.digest, id);
        assert!(snapshot.streams.is_empty());
        assert_eq!(snapshot.taken_at.len(), "2026-09-13T01:02:03Z".len());
    }

    #[tokio::test]
    async fn every_source_in_the_snapshot_answers() {
        let ours = Rows {
            affected: [affected("evil", None)].into(),
            ..advisory("MAL-1")
        };
        let theirs = Rows {
            affected: [affected("evil", Some("1.0.0"))].into(),
            ..advisory("GHSA-2")
        };
        let (dir, id) = kept(
            "intel-sources",
            &[("osv", vec![ours]), ("other", vec![theirs])],
        );
        let intel = SnapshotIntel::read(&dir, &id).expect("reads");

        let mut found: Vec<(String, String)> = intel
            .lookup("npm", "evil", "1.0.0")
            .await
            .expect("answers")
            .into_iter()
            .map(|r| (r.advisory_id, r.source))
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                ("GHSA-2".to_owned(), "other".to_owned()),
                ("MAL-1".to_owned(), "osv".to_owned())
            ]
        );
    }

    #[test]
    fn a_stored_range_that_does_not_parse_is_refused() {
        let unparsed = Rows {
            ranges: [ranged("lib", "13.0", End::Open)].into(),
            ..advisory("GHSA-1")
        };
        let rows = vec![unparsed];
        let digest = load::encode("osv", &rows).digest;
        let (dir, id) = kept("intel-range", &[("osv", rows)]);

        let err = SnapshotIntel::read(&dir, &id).expect_err("13.0 is not SemVer");
        assert_eq!(
            err.to_string(),
            format!("the rows {digest} hold a range of GHSA-1 that does not parse")
        );
    }

    #[test]
    fn a_snapshot_not_in_the_directory_is_an_error() {
        let (dir, _) = kept("intel-absent", &[("osv", Vec::new())]);
        let err =
            SnapshotIntel::read(&dir, &load::digest(b"no such snapshot")).expect_err("not kept");
        assert!(matches!(err, KeptError::Io { .. }), "{err:?}");
    }
}
