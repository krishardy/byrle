//! An intel store read from a kept snapshot, for `byrle policy diff --snapshot`.
//!
//! Keeps only the records of the packages given up front; any other is an error.
//! See docs/engineering_decisions/snapshot-identity.md.

use super::ids;
use super::load::Row;
use super::range::{Interval, VersionOrder};
use super::snapshot_dir::{KeptError, SnapshotDir};
use super::store::{Intel, IntelError, LoadedSnapshot, Lookup, PackageIntel, Record};
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
        let snapshot = LoadedSnapshot {
            digest: id.to_owned(),
            taken_at,
            sources: sources.iter().map(|(source, _)| source.clone()).collect(),
            streams: Vec::new(),
            unconfigured: Vec::new(),
        };
        let exploitation_loaded = snapshot.exploitation_loaded();
        let mut found = HashMap::new();
        let mut exploited: HashSet<String> = HashSet::new();
        for (source, digest) in sources {
            let mut records: Vec<Record> = Vec::new();
            dir.read_source(&source, &digest, &mut |row| {
                match row {
                    Row::Advisory(rows) => records.push(Record {
                        advisory_id: rows.id,
                        aliases: Vec::new(),
                        source: source.clone(),
                        cvss: rows.cvss,
                        cvss_source: None,
                        band: rows.band,
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
                            let (introduced, excluded) = ranged.interval.start.columns();
                            let interval = VersionOrder::of(&package.0)
                                .and_then(|order| {
                                    Interval::from_columns(
                                        order,
                                        introduced,
                                        excluded,
                                        fixed,
                                        last_affected,
                                    )
                                })
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
            snapshot,
            read: packages,
            packages: found,
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
                exploitation_loaded: self.snapshot.exploitation_loaded(),
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

/// The ecosystem and name a store keys a package by.
pub fn key_of(key: &crate::identity::PackageKey) -> Package {
    (key.ecosystem().as_str().to_owned(), key.registry_name())
}

/// The kept snapshot `id`, read for `packages`, from the directory the environment names.
pub fn kept<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &crate::env::Env<L>,
    id: &str,
    packages: std::collections::HashSet<Package>,
) -> Result<SnapshotIntel, String> {
    let Some(path) = environment.snapshot_dir().map_err(|e| e.to_string())? else {
        return Err(format!(
            "{} is not set, so there is no kept snapshot to read",
            crate::env::SNAPSHOT_DIR
        ));
    };
    let dir = super::snapshot_dir::SnapshotDir::open_to_read(&path);
    SnapshotIntel::read(&dir, id, packages).map_err(|e| e.to_string())
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
                .for_version(ecosystem, version)
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
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use super::*;
    use crate::intel::load;
    use crate::intel::rows::{Affected, Rows};
    use crate::util::test_support::tempdir;

    pub(crate) fn advisory(id: &str) -> Rows {
        Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware: id.starts_with("MAL-"),
            cvss: None,
            band: None,
            unread_vectors: 0,
            aliases: Default::default(),
            affected: Default::default(),
            ranges: Default::default(),
            unexpressed: 0,
        }
    }

    pub(crate) fn affected(name: &str, version: Option<&str>) -> Affected {
        Affected {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    /// Keep `sources` as one snapshot in a directory of its own, and give its id.
    pub(crate) fn kept(label: &str, sources: &[(&str, Vec<Rows>)]) -> (SnapshotDir, String) {
        kept_encoded(label, &encoded(sources))
    }

    /// [`kept`], giving the directory's path rather than the directory, for a test that names
    /// it in the environment.
    pub(crate) fn kept_path(
        label: &str,
        sources: &[(&str, Vec<Rows>)],
    ) -> (std::path::PathBuf, String) {
        let path = tempdir(label);
        let (_, id) = kept_at(&path, &encoded(sources));
        (path, id)
    }

    fn encoded(sources: &[(&str, Vec<Rows>)]) -> Vec<load::Encoded> {
        sources
            .iter()
            .map(|(source, rows)| load::encode(source, rows))
            .collect()
    }

    pub(crate) fn kept_encoded(label: &str, sources: &[load::Encoded]) -> (SnapshotDir, String) {
        kept_at(&tempdir(label), sources)
    }

    fn kept_at(path: &std::path::Path, sources: &[load::Encoded]) -> (SnapshotDir, String) {
        let dir = SnapshotDir::open(path).expect("opens");
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    /// A store keys a package by its ecosystem as a purl spells it and its registry name,
    /// casing preserved.
    #[test]
    fn a_package_is_keyed_by_ecosystem_and_registry_name() {
        let key: crate::identity::PackageKey = "pkg:npm/%40Scope/Name".parse().expect("a purl");
        assert_eq!(key_of(&key), ("npm".to_owned(), "@Scope/Name".to_owned()));
        let pypi: crate::identity::PackageKey = "pkg:pypi/requests".parse().expect("a purl");
        assert_eq!(key_of(&pypi), ("pypi".to_owned(), "requests".to_owned()));
    }
    use super::testing::{advisory, affected, kept, kept_encoded};
    use super::*;
    use crate::intel::load;
    use crate::intel::providers::kev;
    use crate::intel::range::{End, Start};
    use crate::intel::rows::{Ranged, Rows};

    fn ranged(name: &str, introduced: &str, end: End<String>) -> Ranged {
        Ranged {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            interval: Interval {
                start: Start::Introduced(introduced.to_owned()),
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
                load::encode_exploited(kev::STREAM, &catalogue),
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
                        band: None,
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

    /// A snapshot directory that cannot be named or does not hold the snapshot is an error
    /// naming why, and so is a snapshot file that no longer matches its id.
    #[test]
    fn a_kept_snapshot_that_cannot_be_read_is_an_error() {
        use crate::env::testing::{with, with_unreadable};

        let Err(unreadable) = super::kept(
            &with_unreadable(&[], crate::env::SNAPSHOT_DIR),
            "s",
            npm(&[]),
        ) else {
            panic!("an unreadable variable");
        };
        assert!(
            unreadable.starts_with(crate::env::SNAPSHOT_DIR.name),
            "{unreadable}"
        );

        let empty = crate::util::test_support::tempdir("kept-empty");
        let Err(absent) = super::kept(
            &with(&[(crate::env::SNAPSHOT_DIR, &empty.display().to_string())]),
            "sha256:00",
            npm(&[]),
        ) else {
            panic!("no such snapshot");
        };
        assert!(absent.contains("sha256:00"), "{absent}");

        let (path, id) = super::testing::kept_path("kept-altered", &[("osv", Vec::new())]);
        let hex = id.strip_prefix("sha256:").expect("a digest");
        std::fs::write(path.join(format!("{hex}.snapshot")), "altered\n").expect("writes");
        let dir = SnapshotDir::open_to_read(&path);
        assert!(SnapshotIntel::read(&dir, &id, npm(&[])).is_err());
        let _ = std::fs::remove_dir_all(&empty);
        let _ = std::fs::remove_dir_all(&path);
    }
}
