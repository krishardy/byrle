//! Signals about a package version from its metadata and its source: reported in the log,
//! the audit line and `explain`, and never refused on.
//!
//! See docs/engineering_decisions/metadata-heuristics.md and source-diff.md.

use crate::analysis::source::Sourced;
use crate::identity::Ecosystem;
use crate::policy::SignalWeights;
use crate::record::{DocumentDetail, PackageMetadata, PackageRecord};

/// A package whose first version is younger than this is new.
pub const NEW_PACKAGE_DAYS: i64 = 30;

/// Names shorter than this are not compared, since most short names are one edit apart.
pub const MIN_COMPARED_NAME: usize = 4;

/// One signal, as the log and the audit line name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// The first version was published this many days ago, under [`NEW_PACKAGE_DAYS`].
    NewPackage { days: i64 },
    /// No earlier version of the package was published by this account.
    NewPublisher { publisher: String },
    /// The npm document names no source repository for this version.
    NoRepository,
    /// A served package's name is one edit away, or the same name in another case.
    NearName { served: String },
    /// The artifact holds what its source, `at` as `owner/name@reference`, does not.
    Source { at: String, finding: SourceFinding },
    /// A detector's rule fired on the version.
    Detected { detector: String, rule: String },
}

/// What a comparison with the source found that is a signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFinding {
    /// Install scripts the source lacks, or has with another body.
    InstallScripts(Vec<String>),
    /// Dependencies the source lacks.
    Dependencies(Vec<String>),
    /// Files that run on install which the source lacks, or has otherwise.
    InstallFiles(Vec<String>),
    /// This many files differ from the source, `first` in path order.
    Differing { count: usize, first: String },
}

impl std::fmt::Display for SourceFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstallScripts(names) => {
                write!(
                    f,
                    "install scripts it lacks or has otherwise: {}",
                    names.join(", ")
                )
            }
            Self::Dependencies(names) => write!(f, "dependencies it lacks: {}", names.join(", ")),
            Self::InstallFiles(files) => {
                write!(
                    f,
                    "install files it lacks or has otherwise: {}",
                    files.join(", ")
                )
            }
            Self::Differing { count: 1, first } => write!(f, "1 file differs from it: `{first}`"),
            Self::Differing { count, first } => {
                write!(f, "{count} files differ from it, first `{first}`")
            }
        }
    }
}

/// Each kind of signal, as `signal_weights` in a policy names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignalKind {
    NewPackage,
    NewPublisher,
    NoRepository,
    NearName,
    SourceInstallScripts,
    SourceDependencies,
    SourceInstallFiles,
    SourceDiffering,
}

impl SignalKind {
    pub const ALL: [Self; 8] = [
        Self::NewPackage,
        Self::NewPublisher,
        Self::NoRepository,
        Self::NearName,
        Self::SourceInstallScripts,
        Self::SourceDependencies,
        Self::SourceInstallFiles,
        Self::SourceDiffering,
    ];

    /// The name a policy's `signal_weights` gives it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewPackage => "new_package",
            Self::NewPublisher => "new_publisher",
            Self::NoRepository => "no_repository",
            Self::NearName => "near_name",
            Self::SourceInstallScripts => "source_install_scripts",
            Self::SourceDependencies => "source_dependencies",
            Self::SourceInstallFiles => "source_install_files",
            Self::SourceDiffering => "source_differing",
        }
    }
}

impl Signal {
    /// Its built-in kind. `None` for a detector's rule, which [`Signal::key`] names.
    pub fn kind(&self) -> Option<SignalKind> {
        Some(match self {
            Self::NewPackage { .. } => SignalKind::NewPackage,
            Self::NewPublisher { .. } => SignalKind::NewPublisher,
            Self::NoRepository => SignalKind::NoRepository,
            Self::NearName { .. } => SignalKind::NearName,
            Self::Source { finding, .. } => match finding {
                SourceFinding::InstallScripts(_) => SignalKind::SourceInstallScripts,
                SourceFinding::Dependencies(_) => SignalKind::SourceDependencies,
                SourceFinding::InstallFiles(_) => SignalKind::SourceInstallFiles,
                SourceFinding::Differing { .. } => SignalKind::SourceDiffering,
            },
            Self::Detected { .. } => return None,
        })
    }

    /// The name `signal_weights` weighs it under: its kind's, or `detector.rule`.
    pub fn key(&self) -> String {
        match (self, self.kind()) {
            (Self::Detected { detector, rule }, _) => format!("{detector}.{rule}"),
            (_, kind) => kind
                .expect("every other signal has a kind")
                .as_str()
                .to_owned(),
        }
    }

    /// What it weighs under `weights`.
    pub fn weight(&self, weights: &SignalWeights) -> u32 {
        match self.kind() {
            Some(kind) => weights.of(kind),
            None => weights.of_rule(&self.key()),
        }
    }
}

/// A version's risk score: the weight `weights` gives each kind of signal present, summed,
/// each kind, and each detector rule, once however often it fires.
pub fn score(signals: &[Signal], weights: &SignalWeights) -> u32 {
    let mut seen = std::collections::BTreeSet::new();
    signals
        .iter()
        .filter(|signal| seen.insert(signal.key()))
        .map(|signal| signal.weight(weights))
        .sum()
}

/// The signals `detections`, each a detector's name and what it found, give: one per rule
/// that fired.
pub fn of_detections(detections: &[(String, crate::analysis::detector::Detection)]) -> Vec<Signal> {
    detections
        .iter()
        .flat_map(|(detector, detection)| {
            detection.findings.iter().map(|finding| Signal::Detected {
                detector: detector.clone(),
                rule: finding.rule.clone(),
            })
        })
        .collect()
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewPackage { days: 1 } => f.write_str("new package: first published 1 day ago"),
            Self::NewPackage { days } => write!(f, "new package: first published {days} days ago"),
            Self::NewPublisher { publisher } => {
                write!(f, "new publisher: {publisher} published no earlier version")
            }
            Self::NoRepository => f.write_str("no repository: the metadata names none"),
            Self::NearName { served } => {
                write!(f, "near name: one edit from `{served}`, served here")
            }
            Self::Source { at, finding } => write!(f, "source {at}: {finding}"),
            Self::Detected { detector, rule } => write!(f, "{detector}: {rule}"),
        }
    }
}

/// The signals a comparison with the source gives: install scripts, dependencies and
/// install files the source lacks, and files that differ. Optional dependencies, Markdown and
/// files only in the package are kept by the store and give none: see source-diff.md.
pub fn of_source(sourced: &Sourced) -> Vec<Signal> {
    let Sourced::Compared {
        repository,
        reference,
        comparison,
    } = sourced
    else {
        return Vec::new();
    };
    let files: Vec<String> = comparison
        .lifecycle_files
        .iter()
        .map(|(_, file)| file.clone())
        .collect();
    [
        (!comparison.lifecycle_scripts.is_empty())
            .then(|| SourceFinding::InstallScripts(comparison.lifecycle_scripts.clone())),
        (!comparison.dependencies.is_empty())
            .then(|| SourceFinding::Dependencies(comparison.dependencies.clone())),
        (!files.is_empty()).then_some(SourceFinding::InstallFiles(files)),
        comparison
            .differing
            .first()
            .map(|first| SourceFinding::Differing {
                count: comparison.differing.len(),
                first: first.clone(),
            }),
    ]
    .into_iter()
    .flatten()
    .map(|finding| Signal::Source {
        at: format!("{repository}@{reference}"),
        finding,
    })
    .collect()
}

/// The signals for `record`, one version of the package whose held records are `records`.
/// `full` is the full document, read in their place when it lists the version.
/// `served` are the names of other packages this proxy has served in the same ecosystem,
/// and `now` is when the signals are asked for.
/// Returns them in the order [`Signal`] declares.
pub fn signals<'a>(
    records: &[PackageRecord],
    record: &PackageRecord,
    full: Option<&PackageMetadata>,
    served: impl IntoIterator<Item = &'a str>,
    now: jiff::Timestamp,
) -> Vec<Signal> {
    let (records, record) = full
        .and_then(|full| {
            Some((
                full.records.as_slice(),
                full.version(record.package.version())?,
            ))
        })
        .unwrap_or((records, record));
    let mut found = Vec::new();
    let first = records.iter().filter_map(|r| r.published_at).min();
    if let Some(days) = first.map(|first| now.duration_since(first).as_hours().max(0) / 24)
        && days < NEW_PACKAGE_DAYS
    {
        found.push(Signal::NewPackage { days });
    }
    if let Some(publisher) = new_publisher(records, record) {
        found.push(Signal::NewPublisher { publisher });
    }
    let key = record.package.key();
    if key.ecosystem() == Ecosystem::Npm
        && record.detail == DocumentDetail::Full
        && record.repository.is_none()
    {
        found.push(Signal::NoRepository);
    }
    let name = key.registry_name();
    found.extend(
        served
            .into_iter()
            .filter(|served| near(&name, served))
            .map(|served| Signal::NearName {
                served: served.to_owned(),
            }),
    );
    found
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

    fn of(records: &[PackageRecord], version: &str, served: &[&str]) -> Vec<Signal> {
        let record = records
            .iter()
            .find(|r| r.package.version() == version)
            .expect("the version is listed");
        signals(records, record, None, served.iter().copied(), now())
    }

    #[test]
    fn an_old_package_from_its_usual_publisher_with_a_repository_signals_nothing() {
        let records = document(
            "steady",
            &[("1.0.0", 400, "ana", true), ("1.1.0", 5, "ana", true)],
        );
        assert_eq!(of(&records, "1.1.0", &["lodash", "express"]), []);
    }

    #[test]
    fn a_package_first_published_under_30_days_ago_is_new() {
        let records = document("fresh", &[("1.0.0", 3, "ana", true)]);
        assert_eq!(of(&records, "1.0.0", &[]), [Signal::NewPackage { days: 3 }]);
        let records = document("fresh", &[("1.0.0", 30, "ana", true)]);
        assert_eq!(of(&records, "1.0.0", &[]), [], "30 days is no longer new");
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
            [Signal::NewPublisher {
                publisher: "mallory".to_owned()
            }]
        );
        assert_eq!(of(&records, "1.0.0", &[]), [], "nothing earlier to compare");
        let mut untimed = records[1].clone();
        untimed.published_at = None;
        assert_eq!(
            signals(&records, &untimed, None, [], now()),
            [],
            "no time says which versions are earlier"
        );
    }

    /// The full document is read in place of the held one when it lists the version, and
    /// not when it does not.
    #[test]
    fn a_full_document_is_read_when_it_lists_the_version() {
        let held = document("pkg", &[("1.0.0", 400, "ana", true)]);
        let full = crate::record::PackageMetadata {
            key: held[0].package.key().clone(),
            latest: None,
            records: document("pkg", &[("1.0.0", 3, "ana", true)]),
            skipped: Vec::new(),
        };
        let judged =
            |full: &crate::record::PackageMetadata| signals(&held, &held[0], Some(full), [], now());
        assert_eq!(judged(&full), [Signal::NewPackage { days: 3 }]);
        let other = crate::record::PackageMetadata {
            records: document("pkg", &[("2.0.0", 3, "ana", true)]),
            ..full
        };
        assert_eq!(judged(&other), [], "2.0.0 only: the held document is read");
    }

    /// Only a full npm document answers whether there is a repository: the abbreviated one
    /// omits it, and a PyPI record never holds one.
    #[test]
    fn a_full_npm_document_naming_no_repository_signals_it() {
        let records = document("loose", &[("1.0.0", 400, "ana", false)]);
        assert_eq!(of(&records, "1.0.0", &[]), [Signal::NoRepository]);

        let mut abbreviated = records[0].clone();
        abbreviated.detail = DocumentDetail::Abbreviated;
        assert_eq!(signals(&records, &abbreviated, None, [], now()), []);

        let mut pypi = records[0].clone();
        pypi.package = crate::identity::PackageKey::from_registry_name(Ecosystem::PyPI, "loose")
            .and_then(|key| key.at_version("1.0.0"))
            .expect("a PyPI package");
        assert_eq!(signals(&records, &pypi, None, [], now()), []);
    }

    /// One edit from a served name, or the same name in another case, and never a name
    /// compared with itself or one too short to compare.
    #[test]
    fn a_name_one_edit_from_a_served_name_is_near() {
        let records = document("expres", &[("1.0.0", 400, "ana", true)]);
        assert_eq!(
            of(&records, "1.0.0", &["express", "expres", "lodash"]),
            [Signal::NearName {
                served: "express".to_owned()
            }]
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

    #[test]
    fn each_signal_says_what_it_found() {
        for (signal, text) in [
            (
                Signal::NewPackage { days: 2 },
                "new package: first published 2 days ago",
            ),
            (
                Signal::NewPackage { days: 1 },
                "new package: first published 1 day ago",
            ),
            (
                Signal::NewPublisher {
                    publisher: "m".to_owned(),
                },
                "new publisher: m published no earlier version",
            ),
            (
                Signal::NoRepository,
                "no repository: the metadata names none",
            ),
            (
                Signal::NearName {
                    served: "express".to_owned(),
                },
                "near name: one edit from `express`, served here",
            ),
        ] {
            assert_eq!(signal.to_string(), text);
        }
    }

    /// Install scripts, dependencies, install files and differing files each give a signal.
    /// Optional dependencies, Markdown, files only in the package and no comparison do not.
    #[test]
    fn a_comparison_with_the_source_gives_its_signals() {
        use crate::analysis::source::Comparison;
        let comparison = Comparison {
            manifests: true,
            lifecycle_scripts: vec!["postinstall".to_owned()],
            dependencies: vec!["a".to_owned(), "b".to_owned()],
            optional_dependencies: vec!["c".to_owned()],
            lifecycle_files: vec![("postinstall".to_owned(), "x.js".to_owned())],
            lifecycle_targets: 1,
            differing: vec!["x.js".to_owned(), "y.js".to_owned()],
            differing_markdown: vec!["README.md".to_owned()],
            only_in_package: vec!["dist/x.js".to_owned()],
            same: 3,
        };
        let sourced = Sourced::Compared {
            repository: "o/r".to_owned(),
            reference: "v1".to_owned(),
            comparison: Box::new(comparison),
        };
        let said: Vec<String> = of_source(&sourced)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            said,
            [
                "source o/r@v1: install scripts it lacks or has otherwise: postinstall",
                "source o/r@v1: dependencies it lacks: a, b",
                "source o/r@v1: install files it lacks or has otherwise: x.js",
                "source o/r@v1: 2 files differ from it, first `x.js`",
            ]
        );
        assert_eq!(
            of_source(&sourced)
                .iter()
                .filter_map(Signal::kind)
                .collect::<Vec<_>>(),
            SignalKind::ALL[4..]
        );
        let quiet = Sourced::Compared {
            repository: "o/r".to_owned(),
            reference: "v1".to_owned(),
            comparison: Box::new(Comparison {
                optional_dependencies: vec!["c".to_owned()],
                differing_markdown: vec!["README.md".to_owned()],
                only_in_package: vec!["dist/x.js".to_owned()],
                ..Comparison::default()
            }),
        };
        assert_eq!(of_source(&quiet), []);
        let one = Sourced::Compared {
            repository: "o/r".to_owned(),
            reference: "v1".to_owned(),
            comparison: Box::new(Comparison {
                differing: vec!["x.js".to_owned()],
                ..Comparison::default()
            }),
        };
        assert_eq!(
            of_source(&one)[0].to_string(),
            "source o/r@v1: 1 file differs from it: `x.js`"
        );
        assert_eq!(of_source(&Sourced::NotCompared("why".to_owned())), []);
    }

    /// A kind counts once however often it fires, and each kind adds its own weight.
    #[test]
    fn the_risk_score_sums_the_weight_of_each_kind_present() {
        let weights = SignalWeights {
            near_name: 4,
            source_differing: 2,
            ..SignalWeights::default()
        };
        let near = |served: &str| Signal::NearName {
            served: served.to_owned(),
        };
        let differing = Signal::Source {
            at: "o/r@v1".to_owned(),
            finding: SourceFinding::Differing {
                count: 2,
                first: "x.js".to_owned(),
            },
        };
        assert_eq!(score(&[], &weights), 0);
        assert_eq!(score(&[near("a"), near("b")], &weights), 4);
        assert_eq!(
            score(&[near("a"), differing, Signal::NoRepository], &weights),
            7
        );
        let kinds: Vec<SignalKind> = [
            Signal::NewPackage { days: 1 },
            Signal::NewPublisher {
                publisher: "m".to_owned(),
            },
            Signal::NoRepository,
            near("a"),
        ]
        .iter()
        .filter_map(Signal::kind)
        .collect();
        assert_eq!(kinds, SignalKind::ALL[..4]);
    }

    /// Each rule a detector fired is a signal, weighed by its own `detector.rule` weight,
    /// once however many detections repeat it.
    #[test]
    fn a_detector_rule_is_a_signal_with_its_own_weight() {
        use crate::analysis::detector::{Detection, Finding};
        let fired = |rules: &[&str]| Detection {
            findings: rules
                .iter()
                .map(|rule| Finding {
                    rule: (*rule).to_owned(),
                    detail: String::new(),
                })
                .collect(),
            errors: vec![Finding {
                rule: "e".to_owned(),
                detail: "no dns".to_owned(),
            }],
        };
        let detected = [
            (
                "guarddog".to_owned(),
                fired(&["threat-process-hooks", "bundled_binary"]),
            ),
            ("guarddog".to_owned(), fired(&["bundled_binary"])),
        ];
        let signals = of_detections(&detected);
        assert_eq!(
            signals.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "guarddog: threat-process-hooks",
                "guarddog: bundled_binary",
                "guarddog: bundled_binary"
            ]
        );
        assert_eq!(signals[0].kind(), None);
        assert_eq!(signals[0].key(), "guarddog.threat-process-hooks");
        assert_eq!(Signal::NoRepository.key(), "no_repository");
        let mut weights = SignalWeights::default();
        weights
            .detectors
            .insert("guarddog.threat-process-hooks".to_owned(), 4);
        assert_eq!(signals[0].weight(&weights), 4);
        assert_eq!(
            score(&signals, &weights),
            5,
            "4, and bundled_binary once at 1"
        );
    }
}
