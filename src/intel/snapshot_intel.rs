//! An intel store read from a kept snapshot, for `waharoa policy diff --snapshot`.
//!
//! Answers what [`PgIntel`](super::postgres::PgIntel) answers, from a snapshot's files
//! rather than Postgres's latest load. The snapshot is read for a set of packages given up
//! front, and only their records are kept: npm's 224,391 packages cost 195 MB, and `policy
//! diff` asks for the few its audit log lists. Any other package is an error. See
//! docs/engineering_decisions/snapshot-identity.md.
//!
//! A kept snapshot records no streams: its manifest holds only what the id is the digest of.
//! `taken_at` is when the manifest was last written.

use super::load::Row;
use super::range::Interval;
use super::snapshot_dir::{KeptError, SnapshotDir};
use super::store::{Intel, IntelError, LoadedSnapshot, Lookup, PackageIntel, Record};
use super::{ids, kev};
use std::collections::{HashMap, HashSet};

/// A package, by ecosystem and name.
pub type Package = (String, String);

/// One kept snapshot, in memory, for the packages it was read for.
#[derive(Debug)]
pub struct SnapshotIntel {
    snapshot: LoadedSnapshot,
    /// The packages given to [`SnapshotIntel::read`].
    read: HashSet<Package>,
    /// Those of them with an advisory.
    packages: HashMap<Package, PackageIntel>,
    /// Whether the snapshot includes the KEV catalogue.
    exploitation_loaded: bool,
}

impl SnapshotIntel {
    /// Read snapshot `id` from `dir` for `packages`. Every file is checked against its digest.
    pub fn read(
        dir: &SnapshotDir,
        id: &str,
        packages: HashSet<Package>,
    ) -> Result<Self, KeptError> {
        let taken_at = dir.written(id)?;
        let sources = dir.sources(id)?;
        let exploitation_loaded = sources.iter().any(|(source, _)| source == kev::SOURCE);
        let mut found = HashMap::new();
        let mut exploited: HashSet<String> = HashSet::new();
        for (source, digest) in sources {
            // By index in the advisory table. Aliases are read before affected rows and ranges,
            // so a record has every alias when it is copied to a package.
            let mut records: Vec<Record> = Vec::new();
            dir.read_source(&source, &digest, |row| {
                match row {
                    // Every column but `cvss_source` and `exploited` comes from the rows. The
                    // loader writes no `cvss_source`, and `exploited` is marked below.
                    Row::Advisory(rows) => records.push(Record {
                        advisory_id: rows.id,
                        aliases: Vec::new(),
                        source: source.clone(),
                        cvss: rows.cvss,
                        cvss_source: None,
                        exploited: false,
                        malware: rows.malware,
                    }),
                    Row::Alias(i, alias) => records[i].aliases.push(alias),
                    Row::Affected(i, affected) => {
                        let package = (affected.ecosystem, affected.name);
                        if packages.contains(&package) {
                            entry(&mut found, id, package)
                                .records
                                .push((affected.version, records[i].clone()));
                        }
                    }
                    Row::Ranged(i, ranged) => {
                        let package = (ranged.ecosystem, ranged.name);
                        if packages.contains(&package) {
                            let (fixed, last_affected) = ranged.interval.end.columns();
                            let interval = Interval::from_columns(
                                ranged.interval.introduced.as_deref(),
                                fixed,
                                last_affected,
                            )
                            .ok_or_else(|| KeptError::Range {
                                digest: digest.clone(),
                                advisory_id: records[i].advisory_id.clone(),
                            })?;
                            entry(&mut found, id, package)
                                .ranges
                                .push((interval, records[i].clone()));
                        }
                    }
                    Row::Exploited(cve_id) => {
                        exploited.insert(cve_id);
                    }
                }
                Ok(())
            })?;
        }
        // After every source is read, so ids mark advisories in whichever order the manifest
        // lists their sources.
        for package in found.values_mut() {
            let (records, ranges) = (&mut package.records, &mut package.ranges);
            for record in records
                .iter_mut()
                .map(|(_, r)| r)
                .chain(ranges.iter_mut().map(|(_, r)| r))
            {
                record.exploited =
                    ids(&record.advisory_id, &record.aliases).any(|id| exploited.contains(id));
            }
            package.exploitation_loaded = exploitation_loaded;
        }
        Ok(Self {
            snapshot: LoadedSnapshot {
                digest: id.to_owned(),
                taken_at,
                streams: Vec::new(),
            },
            read: packages,
            packages: found,
            exploitation_loaded,
        })
    }

    fn answer(&self, ecosystem: &str, name: &str) -> Result<PackageIntel, IntelError> {
        let package = (ecosystem.to_owned(), name.to_owned());
        if !self.read.contains(&package) {
            let (ecosystem, name) = package;
            return Err(IntelError::Unread { ecosystem, name });
        }
        Ok(self
            .packages
            .get(&package)
            .cloned()
            .unwrap_or_else(|| PackageIntel {
                exploitation_loaded: self.exploitation_loaded,
                ..nothing_against(&self.snapshot.digest)
            }))
    }
}

fn entry<'a>(
    packages: &'a mut HashMap<Package, PackageIntel>,
    id: &str,
    package: Package,
) -> &'a mut PackageIntel {
    packages
        .entry(package)
        .or_insert_with(|| nothing_against(id))
}

/// A package no advisory in snapshot `id` affects, before the snapshot's sources are known.
fn nothing_against(id: &str) -> PackageIntel {
    PackageIntel {
        snapshot: id.to_owned(),
        records: Vec::new(),
        ranges: Vec::new(),
        exploitation_loaded: false,
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
                .answer(ecosystem, name)?
                .for_version(version)
                .into_iter()
                .cloned()
                .collect())
        })
    }

    fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
        Box::pin(async move { Ok(Some(self.snapshot.clone())) })
    }

    /// `Some` for every package the snapshot was read for: a snapshot that was read has been
    /// loaded.
    fn package<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
    ) -> Lookup<'a, Option<PackageIntel>> {
        Box::pin(async move { self.answer(ecosystem, name).map(Some) })
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

    fn npm(names: &[&str]) -> HashSet<Package> {
        names
            .iter()
            .map(|name| ("npm".to_owned(), name.to_string()))
            .collect()
    }

    /// Keep `sources` as one snapshot in a directory of its own, and give its id.
    fn kept(label: &str, sources: &[(&str, Vec<Rows>)]) -> (SnapshotDir, String) {
        let encoded: Vec<load::Encoded> = sources
            .iter()
            .map(|(source, rows)| load::encode(source, rows))
            .collect();
        kept_encoded(label, &encoded)
    }

    fn kept_encoded(label: &str, sources: &[load::Encoded]) -> (SnapshotDir, String) {
        let dir = SnapshotDir::open(&tempdir(label)).expect("opens");
        for encoded in sources {
            dir.write_rows(encoded).expect("writes rows");
        }
        let manifest = load::manifest(
            sources
                .iter()
                .map(|e| (e.source.as_str(), e.digest.as_str())),
        );
        dir.write_snapshot(&manifest).expect("writes the snapshot");
        (dir, load::snapshot_id(&manifest))
    }

    #[tokio::test]
    async fn a_kept_catalogue_marks_each_advisory_it_lists_by_id_or_alias() {
        let by_alias = Rows {
            aliases: ["CVE-2020-11023".to_owned()].into(),
            ranges: [ranged("jquery", "1.2.0", End::Fixed("3.5.0".to_owned()))].into(),
            ..advisory("GHSA-jpcq-cgw6-v4j6")
        };
        let by_id = Rows {
            affected: [affected("jquery", Some("3.4.0"))].into(),
            ..advisory("CVE-2021-1")
        };
        let unlisted = Rows {
            aliases: ["CVE-2099-1".to_owned()].into(),
            affected: [affected("jquery", None)].into(),
            ..advisory("GHSA-2")
        };
        let catalogue: std::collections::BTreeSet<String> =
            ["CVE-2020-11023", "CVE-2021-1"].map(str::to_owned).into();
        let (dir, id) = kept_encoded(
            "intel-kev",
            &[
                load::encode("osv", &[by_alias, by_id, unlisted]),
                load::encode_exploited(kev::SOURCE, &catalogue),
            ],
        );
        let intel = SnapshotIntel::read(&dir, &id, npm(&["jquery", "lodash"])).expect("reads");

        let jquery = intel
            .package("npm", "jquery")
            .await
            .expect("answers")
            .expect("loaded");
        assert!(jquery.exploitation_loaded);
        let mut marked: Vec<(&str, bool)> = jquery
            .records
            .iter()
            .map(|(_, r)| r)
            .chain(jquery.ranges.iter().map(|(_, r)| r))
            .map(|r| (r.advisory_id.as_str(), r.exploited))
            .collect();
        marked.sort();
        assert_eq!(
            marked,
            [
                ("CVE-2021-1", true),
                ("GHSA-2", false),
                ("GHSA-jpcq-cgw6-v4j6", true)
            ]
        );

        let lodash = intel
            .package("npm", "lodash")
            .await
            .expect("answers")
            .expect("loaded");
        assert!(lodash.exploitation_loaded && lodash.records.is_empty());
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
        // Sorts first, so neither record under test is the advisory at index 0.
        let first = advisory("GHSA-0");
        let (dir, id) = kept(
            "intel-answers",
            &[("osv", vec![malware, vulnerability, first])],
        );
        let intel = SnapshotIntel::read(&dir, &id, npm(&["evil", "lib"])).expect("reads");

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
                exploitation_loaded: false,
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
        let wanted = [("npm", "lodash"), ("PyPI", "evil")];
        let packages = wanted
            .iter()
            .map(|(e, n)| (e.to_string(), n.to_string()))
            .collect();
        let intel = SnapshotIntel::read(&dir, &id, packages).expect("reads");

        for (ecosystem, name) in wanted {
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
    async fn a_package_the_snapshot_was_not_read_for_is_an_error_and_is_not_kept() {
        let rows = vec![
            Rows {
                affected: [affected("evil", None)].into(),
                ..advisory("MAL-1")
            },
            Rows {
                affected: [affected("lib", Some("1.0.0"))].into(),
                // Not SemVer, and not refused: nothing asked for `other`.
                ranges: [ranged("other", "13.0", End::Open)].into(),
                ..advisory("GHSA-1")
            },
        ];
        let (dir, id) = kept("intel-unread", &[("osv", rows)]);
        let intel = SnapshotIntel::read(&dir, &id, npm(&["evil"])).expect("reads");

        let err = intel
            .package("npm", "lib")
            .await
            .expect_err("lib was not read");
        assert_eq!(
            err.to_string(),
            "intel store: the kept snapshot was not read for npm lib"
        );
        assert!(matches!(
            intel.lookup("npm", "lib", "1.0.0").await,
            Err(IntelError::Unread { .. })
        ));
        assert_eq!(
            intel.packages.keys().collect::<Vec<_>>(),
            [&("npm".to_owned(), "evil".to_owned())]
        );
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
        let intel = SnapshotIntel::read(&dir, &id, npm(&["evil"])).expect("reads");

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

        let err = SnapshotIntel::read(&dir, &id, npm(&["lib"])).expect_err("13.0 is not SemVer");
        assert_eq!(
            err.to_string(),
            format!("the rows {digest} hold a range of GHSA-1 that does not parse")
        );
    }

    #[test]
    fn a_snapshot_not_in_the_directory_is_an_error() {
        let (dir, _) = kept("intel-absent", &[("osv", Vec::new())]);
        let err = SnapshotIntel::read(&dir, &load::digest(b"no such snapshot"), npm(&[]))
            .expect_err("not kept");
        assert!(matches!(err, KeptError::Io { .. }), "{err:?}");
    }
}
