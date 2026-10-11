//! The metadata heuristics: a detector built in, reading the document the proxy holds for a
//! package. It runs on each decision and stores nothing, since its answer moves with the
//! clock and with the packages served.
//! See docs/engineering_decisions/metadata-heuristics.md.

use super::{Detecting, Detection, Detector, Finding};
use crate::identity::Ecosystem;
use crate::record::{DocumentDetail, PackageMetadata, PackageRecord};

/// Its name, which its rules are not prefixed with in `signal_weights`.
pub const NAME: &str = "metadata";

/// Its version.
pub const VERSION: &str = "metadata 1";

/// Every rule it reports, in the order it reports them.
pub const RULES: [&str; 4] = ["new_package", "new_publisher", "no_repository", "near_name"];

/// A package whose first version is younger than this is new.
pub const NEW_PACKAGE_DAYS: i64 = 30;

/// Names shorter than this are not compared, since most short names are one edit apart.
pub const MIN_COMPARED_NAME: usize = 4;

/// The metadata heuristics.
#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata;

/// What the heuristics read about one version.
#[derive(Debug, Clone)]
pub struct Listing<'a> {
    /// The package's held records.
    pub records: &'a [PackageRecord],
    /// The version asked about.
    pub record: &'a PackageRecord,
    /// The full document, read in place of `records` when it lists the version.
    pub full: Option<&'a PackageMetadata>,
    /// The names of other packages this proxy has served in the same ecosystem.
    pub served: Vec<&'a str>,
    /// When the heuristics are asked.
    pub now: jiff::Timestamp,
}

impl Detector<Listing<'_>> for Metadata {
    fn name(&self) -> &str {
        NAME
    }

    fn version(&self) -> &str {
        VERSION
    }

    /// Answers on the first poll: see [`super::at_once`].
    fn detect<'a>(&'a self, listing: &'a Listing<'_>) -> Detecting<'a> {
        Box::pin(std::future::ready(Ok(detection(listing))))
    }
}

/// The rules that fire for `listing`, in the order [`RULES`] lists them.
fn detection(listing: &Listing<'_>) -> Detection {
    let (records, record) = listing
        .full
        .and_then(|full| {
            Some((
                full.records.as_slice(),
                full.version(listing.record.package.version())?,
            ))
        })
        .unwrap_or((listing.records, listing.record));
    let mut findings = Vec::new();
    let mut fired = |rule: &str, detail: String| {
        findings.push(Finding {
            rule: rule.to_owned(),
            detail,
        });
    };
    let first = records.iter().filter_map(|r| r.published_at).min();
    if let Some(days) = first.map(|first| listing.now.duration_since(first).as_hours().max(0) / 24)
        && days < NEW_PACKAGE_DAYS
    {
        let unit = if days == 1 { "day" } else { "days" };
        fired(RULES[0], format!("first published {days} {unit} ago"));
    }
    if let Some(publisher) = new_publisher(records, record) {
        fired(
            RULES[1],
            format!("{publisher} published no earlier version"),
        );
    }
    let key = record.package.key();
    if key.ecosystem() == Ecosystem::Npm
        && record.detail == DocumentDetail::Full
        && record.repository.is_none()
    {
        fired(RULES[2], "the metadata names none".to_owned());
    }
    let name = key.registry_name();
    for served in listing.served.iter().filter(|served| near(&name, served)) {
        fired(RULES[3], format!("one edit from `{served}`, served here"));
    }
    Detection {
        findings,
        errors: Vec::new(),
    }
}

/// The publisher of `record` when earlier versions name publishers and none is it.
/// `records` are the package's held versions.
/// Returns `None` when nothing earlier names a publisher, or one of them is this one.
fn new_publisher(records: &[PackageRecord], record: &PackageRecord) -> Option<String> {
    let publisher = record.provenance.publisher.as_deref()?;
    let published = record.published_at?;
    let earlier: Vec<&str> = records
        .iter()
        .filter(|r| r.published_at.is_some_and(|at| at < published))
        .filter_map(|r| r.provenance.publisher.as_deref())
        .collect();
    (!earlier.is_empty() && !earlier.contains(&publisher)).then(|| publisher.to_owned())
}

/// Whether two names, both at least [`MIN_COMPARED_NAME`] long, differ yet are one edit
/// apart once lowercased. `name` and `other` are registry names.
fn near(name: &str, other: &str) -> bool {
    name != other
        && name.chars().count() >= MIN_COMPARED_NAME
        && other.chars().count() >= MIN_COMPARED_NAME
        && within_one_edit(&name.to_lowercase(), &other.to_lowercase())
}

/// Whether `a` becomes `b` by at most one insertion, deletion or substitution.
fn within_one_edit(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let prefix = short.iter().zip(&long).take_while(|(x, y)| x == y).count();
    if prefix == long.len() {
        return true;
    }
    let rest = if short.len() == long.len() {
        prefix + 1
    } else {
        prefix
    };
    short[rest..] == long[prefix + 1..]
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::detector::at_once;
    use crate::ecosystem::npm::normalize::normalize_packument;

    /// A full npm packument for `name` whose versions are each a version, days before
    /// 2026-09-29, a publisher, and whether it names a repository.
    fn document(name: &str, versions: &[(&str, i64, &str, bool)]) -> Vec<PackageRecord> {
        let now = now();
        let mut times = Vec::new();
        let mut entries = Vec::new();
        for (version, days, publisher, repository) in versions {
            let at = now - jiff::SignedDuration::from_hours(24 * days);
            times.push(format!(r#""{version}":"{at}""#));
            let repository = if *repository {
                r#""repository":{"type":"git","url":"git+https://github.com/o/r.git"},"#
            } else {
                ""
            };
            entries.push(format!(
                r#""{version}":{{"version":"{version}",{repository}"_npmUser":{{"name":"{publisher}"}},"dist":{{"tarball":"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz","integrity":"sha512-AAAA"}}}}"#
            ));
        }
        let body = format!(
            r#"{{"name":"{name}","time":{{{}}},"versions":{{{}}}}}"#,
            times.join(","),
            entries.join(",")
        );
        normalize_packument(body.as_bytes(), DocumentDetail::Full)
            .expect("a full packument")
            .records
    }

    fn now() -> jiff::Timestamp {
        "2026-09-29T00:00:00Z".parse().expect("a timestamp")
    }

    /// Each rule fired for `record`, as `rule: detail`.
    fn fired(
        records: &[PackageRecord],
        record: &PackageRecord,
        full: Option<&PackageMetadata>,
        served: &[&str],
    ) -> Vec<String> {
        let listing = Listing {
            records,
            record,
            full,
            served: served.to_vec(),
            now: now(),
        };
        at_once(Metadata.detect(&listing))
            .expect("it answers at once")
            .expect("it runs")
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.rule, finding.detail))
            .collect()
    }

    fn of(records: &[PackageRecord], version: &str, served: &[&str]) -> Vec<String> {
        let record = records
            .iter()
            .find(|r| r.package.version() == version)
            .expect("the version is listed");
        fired(records, record, None, served)
    }

    const NONE: [&str; 0] = [];

    #[test]
    fn an_old_package_from_its_usual_publisher_with_a_repository_fires_nothing() {
        let records = document(
            "steady",
            &[("1.0.0", 400, "ana", true), ("1.1.0", 5, "ana", true)],
        );
        assert_eq!(of(&records, "1.1.0", &["lodash", "express"]), NONE);
        assert_eq!((Metadata.name(), Metadata.version()), (NAME, VERSION));
    }

    #[test]
    fn a_package_first_published_under_30_days_ago_is_new() {
        let records = document("fresh", &[("1.0.0", 3, "ana", true)]);
        assert_eq!(
            of(&records, "1.0.0", &[]),
            ["new_package: first published 3 days ago"]
        );
        let records = document("fresh", &[("1.0.0", 1, "ana", true)]);
        assert_eq!(
            of(&records, "1.0.0", &[]),
            ["new_package: first published 1 day ago"]
        );
        let records = document("fresh", &[("1.0.0", 30, "ana", true)]);
        assert_eq!(of(&records, "1.0.0", &[]), NONE, "30 days is no longer new");
    }

    /// A version published by an account that published no earlier version.
    #[test]
    fn a_version_from_an_account_that_published_none_before_is_a_new_publisher() {
        let records = document(
            "taken",
            &[("1.0.0", 400, "ana", true), ("1.0.1", 1, "mallory", true)],
        );
        assert_eq!(
            of(&records, "1.0.1", &[]),
            ["new_publisher: mallory published no earlier version"]
        );
        assert_eq!(
            of(&records, "1.0.0", &[]),
            NONE,
            "nothing earlier to compare"
        );
        let mut untimed = records[1].clone();
        untimed.published_at = None;
        assert_eq!(
            fired(&records, &untimed, None, &[]),
            NONE,
            "no time says which versions are earlier"
        );
    }

    /// The full document is read in place of the held one when it lists the version, and
    /// not when it does not.
    #[test]
    fn a_full_document_is_read_when_it_lists_the_version() {
        let held = document("pkg", &[("1.0.0", 400, "ana", true)]);
        let full = PackageMetadata {
            key: held[0].package.key().clone(),
            latest: None,
            records: document("pkg", &[("1.0.0", 3, "ana", true)]),
            skipped: Vec::new(),
        };
        assert_eq!(
            fired(&held, &held[0], Some(&full), &[]),
            ["new_package: first published 3 days ago"]
        );
        let other = PackageMetadata {
            records: document("pkg", &[("2.0.0", 3, "ana", true)]),
            ..full
        };
        assert_eq!(
            fired(&held, &held[0], Some(&other), &[]),
            NONE,
            "2.0.0 only: the held document is read"
        );
    }

    /// Only a full npm document answers whether there is a repository: the abbreviated one
    /// omits it, and a PyPI record never holds one.
    #[test]
    fn a_full_npm_document_naming_no_repository_fires() {
        let records = document("loose", &[("1.0.0", 400, "ana", false)]);
        assert_eq!(
            of(&records, "1.0.0", &[]),
            ["no_repository: the metadata names none"]
        );

        let mut abbreviated = records[0].clone();
        abbreviated.detail = DocumentDetail::Abbreviated;
        assert_eq!(fired(&records, &abbreviated, None, &[]), NONE);

        let mut pypi = records[0].clone();
        pypi.package = crate::identity::PackageKey::from_registry_name(Ecosystem::PyPI, "loose")
            .and_then(|key| key.at_version("1.0.0"))
            .expect("a PyPI package");
        assert_eq!(fired(&records, &pypi, None, &[]), NONE);
    }

    /// One edit from a served name, or the same name in another case, and never a name
    /// compared with itself or one too short to compare.
    #[test]
    fn a_name_one_edit_from_a_served_name_is_near() {
        let records = document("expres", &[("1.0.0", 400, "ana", true)]);
        assert_eq!(
            of(&records, "1.0.0", &["express", "expres", "lodash"]),
            ["near_name: one edit from `express`, served here"]
        );
        for (name, other, expected) in [
            ("lodash", "lodahs", false),
            ("lodash", "l0dash", true),
            ("lodash", "lodashs", true),
            ("lodash", "Lodash", true),
            ("lodash", "odash", true),
            ("lodash", "loash", true),
            ("lodash", "lodash", false),
            ("ms", "mz", false),
            ("abc", "abcd", false),
            ("abcd", "abc", false),
            ("lodash", "LODASH", true),
            ("abcd", "abcdef", false),
        ] {
            assert_eq!(near(name, other), expected, "{name} {other}");
        }
    }
}
