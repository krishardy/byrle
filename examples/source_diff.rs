//! Measure the analyser's source comparison on real packages: each npm version a lockfile
//! locks, its published tarball against GitHub's archive of the commit or tag it names.
//!
//! Needs registry.npmjs.org and codeload.github.com. See
//! docs/engineering_decisions/source-diff.md for the corpus and the results.
//!
//! Run: cargo run --release --example source_diff -- <package-lock.json>...
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use futures_util::StreamExt as _;
use waharoa::analysis::run::{Analyser, SourceJob};
use waharoa::analysis::source::{self, Sourced};
use waharoa::analysis::store::InProcess;
use waharoa::ecosystem::npm::transport::Client;
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::integrity::Sri;
use waharoa::record::{DocumentDetail, PackageRecord};

/// What one version came to.
struct Measured {
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
    assert!(!paths.is_empty(), "usage: source_diff <lockfile>...");
    let mut versions = BTreeSet::new();
    for path in &paths {
        let locked = waharoa::lockfile::read(std::path::Path::new(path)).expect("a lockfile");
        versions.extend(
            locked
                .into_iter()
                .filter(|(ecosystem, _, _)| ecosystem == "npm")
                .map(|(_, name, version)| (name, version)),
        );
    }
    let http = reqwest::Client::new();
    let registry = Client::new(http.clone(), "https://registry.npmjs.org");
    let spool_dir = std::env::temp_dir().join(format!("source-diff-{}", std::process::id()));
    let (spool, _) = waharoa::spool::Spool::open(&spool_dir, 1 << 30).expect("a spool");
    let analyser = Analyser::new(
        http.clone(),
        Arc::new(spool),
        Arc::new(InProcess::new(versions.len().max(1))),
        1,
        16,
    )
    .with_sources(Some(source::ARCHIVES.to_owned()));

    let measured: Vec<Measured> = futures_util::stream::iter(versions)
        .map(|(name, version)| {
            let (registry, analyser) = (registry.clone(), analyser.clone());
            async move { measure(&registry, &analyser, name, version).await }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    report(&analyser, measured).await;
    let _ = std::fs::remove_dir_all(spool_dir);
}

/// Start comparing one version, and wait for it.
async fn measure(
    registry: &Client,
    analyser: &Analyser,
    name: String,
    version: String,
) -> Measured {
    let unjobbed = |why| Measured {
        name: name.clone(),
        version: version.clone(),
        unjobbed: Some(why),
        record: None,
        digest: None,
    };
    let Ok(key) = PackageKey::from_registry_name(Ecosystem::Npm, &name) else {
        return unjobbed("name not read");
    };
    let Ok(Ok(metadata)) = registry.packument(&key, DocumentDetail::Full).await else {
        return unjobbed("packument not read");
    };
    let Some(record) = metadata.version(&version).cloned() else {
        return unjobbed("version not listed");
    };
    let artifact = record.artifact().expect("a version has a file");
    let Some(digest) = artifact
        .integrity
        .as_deref()
        .and_then(|i| Sri::parse(i).ok())
    else {
        return unjobbed("no strong digest");
    };
    let Some(job) = SourceJob::of(&record, &digest, artifact.url.clone()) else {
        return unjobbed("no repository on GitHub");
    };
    if let Some(handle) = analyser.start_source(job) {
        let _ = handle.await;
    }
    Measured {
        name,
        version,
        unjobbed: None,
        record: Some(record),
        digest: Some(digest),
    }
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
    } in measured
    {
        let (Some(record), Some(digest)) = (record, digest) else {
            let why = unjobbed.expect("a version without a job says why");
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
