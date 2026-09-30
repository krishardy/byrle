//! Measure `analysis::source` on real packages: each npm version a lockfile locks, its
//! published tarball against GitHub's archive of the commit or tag it names.
//!
//! Needs registry.npmjs.org and codeload.github.com. See
//! docs/engineering_decisions/source-diff.md for the corpus and the results.
//!
//! Run: cargo run --release --example source_diff -- <package-lock.json>...
use std::collections::BTreeSet;

use futures_util::StreamExt as _;
use waharoa::analysis::source::{self, Comparison, Repo};
use waharoa::ecosystem::npm::transport::Client;
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::record::DocumentDetail;

/// The member sizes a source archive may state, together.
const MAX_SOURCE_BYTES: usize = 512 << 20;

/// What one version came to.
enum Outcome {
    Compared {
        by_commit: bool,
        /// A `gitHead` was published, whether or not GitHub has it.
        head: bool,
        /// The registry says installing it runs a lifecycle script.
        scripts: bool,
        comparison: Comparison,
    },
    NotCompared(&'static str),
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
    let outcomes: Vec<_> = futures_util::stream::iter(versions)
        .map(|(name, version)| {
            let (http, registry) = (http.clone(), registry.clone());
            async move {
                let outcome = measure(&http, &registry, &name, &version).await;
                (name, version, outcome)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    report(outcomes);
}

/// Compare one version with its source.
async fn measure(http: &reqwest::Client, registry: &Client, name: &str, version: &str) -> Outcome {
    let Ok(key) = PackageKey::from_registry_name(Ecosystem::Npm, name) else {
        return Outcome::NotCompared("name not read");
    };
    let Ok(Ok(metadata)) = registry.packument(&key, DocumentDetail::Full).await else {
        return Outcome::NotCompared("packument not read");
    };
    let Some(record) = metadata.version(version) else {
        return Outcome::NotCompared("version not listed");
    };
    let Some(repository) = &record.repository else {
        return Outcome::NotCompared("no repository");
    };
    let Some(repo) = Repo::from_url(&repository.url) else {
        return Outcome::NotCompared("not on GitHub");
    };
    let Some(tarball) = fetch(http, &record.artifact().expect("a version has a file").url).await
    else {
        return Outcome::NotCompared("tarball not fetched");
    };
    let Ok(package) = source::tree(&mut &*tarball, MAX_SOURCE_BYTES) else {
        return Outcome::NotCompared("tarball not read");
    };
    let head = record.provenance.git_head.clone().unwrap_or_default();
    for reference in source::references(record) {
        let Some(archive) = fetch(http, &repo.archive_url(&reference)).await else {
            continue;
        };
        let built = source::tree(&mut &*archive, MAX_SOURCE_BYTES)
            .map(|tree| tree.package(name, repository.directory.as_deref()));
        return match built {
            Ok(Some(built)) => Outcome::Compared {
                by_commit: reference == head,
                head: !head.is_empty(),
                scripts: record.has_install_scripts,
                comparison: source::compare(&package, &built),
            },
            Ok(None) => Outcome::NotCompared("no package.json in the source names it"),
            Err(waharoa::analysis::ReadError::TooLarge { .. }) => {
                Outcome::NotCompared("source over the limit")
            }
            Err(_) => Outcome::NotCompared("source not read"),
        };
    }
    if head.is_empty() {
        Outcome::NotCompared("no gitHead, and no tag found")
    } else {
        Outcome::NotCompared("gitHead not on GitHub, and no tag found")
    }
}

/// The body at `url`, or `None` for anything but a 200.
async fn fetch(http: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let response = http.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    Some(response.bytes().await.ok()?.to_vec())
}

/// One line per version with a finding, then a count per outcome and per finding.
fn report(outcomes: Vec<(String, String, Outcome)>) {
    let mut not_compared = std::collections::BTreeMap::<&str, usize>::new();
    let (mut compared, mut by_commit, mut manifests) = (0, 0, 0);
    let (mut head_missed, mut with_scripts, mut with_targets) = (0, 0, 0);
    let mut counts = [0usize; 7];
    for (name, version, outcome) in &outcomes {
        let (by, found) = match outcome {
            Outcome::NotCompared(why) => {
                *not_compared.entry(why).or_default() += 1;
                println!("{name}@{version}\tnot compared: {why}");
                continue;
            }
            Outcome::Compared {
                by_commit: by,
                head,
                scripts,
                comparison,
            } => {
                head_missed += usize::from(*head && !*by);
                with_scripts += usize::from(*scripts);
                with_targets += usize::from(comparison.lifecycle_targets > 0);
                (*by, comparison)
            }
        };
        compared += 1;
        by_commit += usize::from(by);
        manifests += usize::from(found.manifests);
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
    println!("\nversions\t{}", outcomes.len());
    for (why, n) in &not_compared {
        println!("not compared: {why}\t{n}");
    }
    println!(
        "compared\t{compared}\nby gitHead\t{by_commit}\nby tag\t{}",
        compared - by_commit
    );
    println!("by tag, with a gitHead GitHub lacks\t{head_missed}");
    println!("both manifests\t{manifests}");
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
