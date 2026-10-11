//! Measure the analyser's source comparison on real packages: each npm tarball, and each PyPI
//! version's first wheel and its sdist, a lockfile locks, against GitHub's archive of its source.
//! Needs registry.npmjs.org, pypi.org and codeload.github.com. See
//! docs/engineering_decisions/source-diff.md. Run: `cargo run --release --example source_diff -- <lockfile>...`
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use byrle::analysis::run::{Analyser, SourceJob};
use byrle::analysis::source::{self, Sourced};
use byrle::analysis::store::InProcess;
use byrle::ecosystem::npm::transport::Client;
use byrle::ecosystem::pypi::transport::Client as PypiClient;
use byrle::identity::{Ecosystem, PackageKey};
use byrle::integrity::Sri;
use byrle::record::{DocumentDetail, PackageRecord};
use futures_util::StreamExt as _;

/// What one file came to.
struct Measured {
    /// `npm tarball`, `pypi wheel` or `pypi sdist`: each is reported apart.
    kind: &'static str,
    name: String,
    version: String,
    /// Why no job was made, when none was.
    unjobbed: Option<&'static str>,
    record: Option<PackageRecord>,
    digest: Option<Sri>,
}

#[tokio::main]
async fn main() {
    // nosemgrep: rust.lang.security.args.args
    let paths: Vec<String> = std::env::args().skip(1).collect();
    tracing::subscriber::set_global_default(byrle::logging::subscriber(
        tracing_subscriber::EnvFilter::new(
            byrle::env::process()
                .log_filter()
                .expect("a readable log filter"),
        ),
        byrle::logging::Format::Text,
        std::io::stderr,
    ))
    .expect("the only subscriber");
    assert!(!paths.is_empty(), "usage: source_diff <lockfile>...");
    let mut versions = BTreeSet::new();
    for path in &paths {
        let locked = byrle::lockfile::read(std::path::Path::new(path)).expect("a lockfile");
        versions.extend(
            locked
                .into_iter()
                .filter(|(ecosystem, _, _)| ecosystem == "npm" || ecosystem == "pypi"),
        );
    }
    let http = reqwest::Client::new();
    let registry = Client::new(http.clone(), "https://registry.npmjs.org");
    let index = PypiClient::new(http.clone(), byrle::ecosystem::pypi::INDEX);
    let spool_dir = std::env::temp_dir().join(format!("source-diff-{}", std::process::id()));
    let (spool, _) = byrle::spool::Spool::open(&spool_dir, 1 << 30).expect("a spool");
    let analyser = Analyser::new(
        http.clone(),
        Arc::new(spool),
        Arc::new(InProcess::new(2 * versions.len().max(1))),
        1,
        16,
    )
    .with_sources(Some(source::ARCHIVES.to_owned()));

    let measured: Vec<Vec<Measured>> = futures_util::stream::iter(versions)
        .map(|(ecosystem, name, version)| {
            let (registry, index, analyser) = (registry.clone(), index.clone(), analyser.clone());
            async move { measure(&registry, &index, &analyser, &ecosystem, name, version).await }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    let mut kinds = BTreeMap::<&str, Vec<Measured>>::new();
    for each in measured.into_iter().flatten() {
        kinds.entry(each.kind).or_default().push(each);
    }
    for (kind, measured) in kinds {
        println!("\n== {kind}");
        report(&analyser, measured).await;
    }
    let _ = std::fs::remove_dir_all(spool_dir);
}

/// Start comparing each file measured of one version, and wait for them.
async fn measure(
    registry: &Client,
    index: &PypiClient,
    analyser: &Analyser,
    ecosystem: &str,
    name: String,
    version: String,
) -> Vec<Measured> {
    let pypi = ecosystem == "pypi";
    let unjobbed = |kind, why| {
        vec![Measured {
            kind,
            name: name.clone(),
            version: version.clone(),
            unjobbed: Some(why),
            record: None,
            digest: None,
        }]
    };
    let kind = if pypi { "pypi" } else { "npm tarball" };
    let ecosystem = if pypi {
        Ecosystem::PyPI
    } else {
        Ecosystem::Npm
    };
    let Ok(key) = PackageKey::from_registry_name(ecosystem, &name) else {
        return unjobbed(kind, "name not read");
    };
    let metadata = if pypi {
        index.metadata(&key).await.ok().and_then(Result::ok)
    } else {
        registry
            .packument(&key, DocumentDetail::Full)
            .await
            .ok()
            .and_then(Result::ok)
    };
    let Some(record) = metadata.and_then(|metadata| metadata.version(&version).cloned()) else {
        return unjobbed(kind, "metadata not read, or the version not listed");
    };
    let files: Vec<(&'static str, &byrle::record::Artifact)> = if pypi {
        let first = |suffix: &str| {
            record
                .artifacts
                .iter()
                .find(|a| a.filename.ends_with(suffix))
        };
        [
            ("pypi wheel", first(".whl")),
            ("pypi sdist", first(".tar.gz")),
        ]
        .into_iter()
        .filter_map(|(kind, file)| Some((kind, file?)))
        .collect()
    } else {
        vec![(
            "npm tarball",
            record.artifact().expect("a version has a file"),
        )]
    };
    let mut measured = Vec::new();
    for (kind, artifact) in files {
        let digest = artifact
            .integrity
            .as_deref()
            .and_then(|i| Sri::parse(i).ok());
        let job = digest.as_ref().and_then(|digest| {
            SourceJob::of(&record, &artifact.filename, digest, artifact.url.clone())
        });
        let unjobbed = match (&digest, &job) {
            (None, _) => Some("no strong digest"),
            (_, None) => Some("no repository on GitHub"),
            _ => None,
        };
        if let Some(handle) = job.and_then(|job| analyser.start_source(job)) {
            let _ = handle.await;
        }
        measured.push(Measured {
            kind,
            name: name.clone(),
            version: version.clone(),
            unjobbed,
            record: Some(record.clone()),
            digest,
        });
    }
    measured
}

/// One line per version with a finding or not compared, then a count per outcome and finding.
async fn report(analyser: &Analyser, measured: Vec<Measured>) {
    let mut outcomes = BTreeMap::<String, usize>::new();
    let (mut by_commit, mut head_missed, mut with_scripts, mut with_targets) = (0, 0, 0, 0);
    let mut counts = [0usize; 7];
    let total = measured.len();
    for Measured {
        name,
        version,
        unjobbed,
        record,
        digest,
        ..
    } in measured
    {
        let (Some(record), Some(digest), None) = (record, digest, unjobbed) else {
            let why = unjobbed.expect("a file without a job says why");
            *outcomes.entry(format!("not compared: {why}")).or_default() += 1;
            println!("{name}@{version}\tnot compared: {why}");
            continue;
        };
        let head = record.provenance.git_head.clone().unwrap_or_default();
        let (reference, found) = match analyser.sourced(&digest).await {
            None => {
                let why = if head.is_empty() {
                    "no gitHead, and no tag found, or a fetch failed"
                } else {
                    "gitHead not on GitHub, and no tag found, or a fetch failed"
                };
                *outcomes.entry(format!("not compared: {why}")).or_default() += 1;
                println!("{name}@{version}\tnot compared: {why}");
                continue;
            }
            Some(Sourced::NotCompared(why)) => {
                let why = why.split(':').next().unwrap_or_default().to_owned();
                *outcomes.entry(format!("not compared: {why}")).or_default() += 1;
                println!("{name}@{version}\tnot compared: {why}");
                continue;
            }
            Some(Sourced::Compared {
                reference,
                comparison,
                ..
            }) => (reference, comparison),
        };
        *outcomes.entry("compared".to_owned()).or_default() += 1;
        by_commit += usize::from(reference == head);
        head_missed += usize::from(!head.is_empty() && reference != head);
        with_scripts += usize::from(record.has_install_scripts);
        with_targets += usize::from(found.lifecycle_targets > 0);
        let each = [
            found.lifecycle_scripts.len(),
            found.dependencies.len(),
            found.optional_dependencies.len(),
            found.lifecycle_files.len(),
            found.differing.len(),
            found.differing_markdown.len(),
            found.only_in_package.len(),
        ];
        for (count, n) in counts.iter_mut().zip(each) {
            *count += usize::from(n > 0);
        }
        if each[..5].iter().any(|&n| n > 0) {
            println!(
                "{name}@{version}\tscripts {:?}\tdependencies {:?}\toptional {}\tlifecycle files {:?}\tdiffering {} {:?}",
                found.lifecycle_scripts,
                found.dependencies,
                found.optional_dependencies.len(),
                found.lifecycle_files,
                found.differing.len(),
                found.differing.iter().take(5).collect::<Vec<_>>(),
            );
        }
    }
    println!("\nversions\t{total}");
    for (outcome, n) in &outcomes {
        println!("{outcome}\t{n}");
    }
    println!("by gitHead\t{by_commit}\nby tag, with a gitHead GitHub lacks\t{head_missed}");
    println!("declaring an install script\t{with_scripts}");
    println!("whose install scripts name a file in the package\t{with_targets}");
    for (label, n) in [
        "lifecycle scripts added or changed",
        "dependencies added",
        "optional dependencies added",
        "lifecycle files absent or different",
        "a file differing",
        "a Markdown file differing",
        "a file only in the package",
    ]
    .iter()
    .zip(counts)
    {
        println!("{label}\t{n}");
    }
}
