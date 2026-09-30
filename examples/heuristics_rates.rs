//! Measure how often each metadata heuristic fires on the versions lockfiles lock: npm from
//! the full packument, PyPI from the index, and near names against every other package name
//! the lockfiles lock in the same ecosystem, as a proxy serving those projects would hold.
//! Needs registry.npmjs.org and pypi.org. See docs/engineering_decisions/metadata-heuristics.md.
//! Run: `cargo run --release --example heuristics_rates -- <lockfile>...`
use std::collections::{BTreeMap, BTreeSet};

use futures_util::StreamExt as _;
use waharoa::ecosystem::npm::transport::Client;
use waharoa::ecosystem::pypi::transport::Client as PypiClient;
use waharoa::heuristics::{Signal, signals};
use waharoa::identity::{Ecosystem, PackageKey};
use waharoa::record::DocumentDetail;

#[tokio::main]
async fn main() {
    // nosemgrep: rust.lang.security.args.args
    let paths: Vec<String> = std::env::args().skip(1).collect();
    assert!(!paths.is_empty(), "usage: heuristics_rates <lockfile>...");
    let mut versions = BTreeSet::new();
    for path in &paths {
        let locked = waharoa::lockfile::read(std::path::Path::new(path)).expect("a lockfile");
        versions.extend(
            locked
                .into_iter()
                .filter(|(ecosystem, _, _)| ecosystem == "npm" || ecosystem == "pypi"),
        );
    }
    let mut served = BTreeMap::<String, BTreeSet<String>>::new();
    for (ecosystem, name, _) in &versions {
        served
            .entry(ecosystem.clone())
            .or_default()
            .insert(name.clone());
    }
    let http = reqwest::Client::new();
    let registry = Client::new(http.clone(), "https://registry.npmjs.org");
    let index = PypiClient::new(http, waharoa::ecosystem::pypi::INDEX);
    let now = jiff::Timestamp::now();

    let found: Vec<(String, String, String, Option<Vec<Signal>>)> =
        futures_util::stream::iter(versions)
            .map(|(ecosystem, name, version)| {
                let (registry, index, served) = (&registry, &index, &served);
                async move {
                    let others = served[&ecosystem]
                        .iter()
                        .filter(|other| **other != name)
                        .map(String::as_str);
                    let found =
                        measure(registry, index, &ecosystem, &name, &version, others, now).await;
                    (ecosystem, name, version, found)
                }
            })
            .buffer_unordered(8)
            .collect()
            .await;
    report(found, now);
}

/// The signals for one version, or `None` when its metadata could not be read.
async fn measure<'a>(
    registry: &Client,
    index: &PypiClient,
    ecosystem: &str,
    name: &str,
    version: &str,
    served: impl Iterator<Item = &'a str>,
    now: jiff::Timestamp,
) -> Option<Vec<Signal>> {
    let pypi = ecosystem == "pypi";
    let ecosystem = if pypi {
        Ecosystem::PyPI
    } else {
        Ecosystem::Npm
    };
    let key = PackageKey::from_registry_name(ecosystem, name).ok()?;
    let metadata = if pypi {
        index.metadata(&key).await.ok()?.ok()?
    } else {
        registry
            .packument(&key, DocumentDetail::Full)
            .await
            .ok()?
            .ok()?
    };
    let record = metadata.version(version)?;
    Some(signals(&metadata.records, record, None, served, now))
}

/// One line per version with a signal, then per ecosystem the count of versions each fired on.
fn report(mut found: Vec<(String, String, String, Option<Vec<Signal>>)>, now: jiff::Timestamp) {
    found.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
    println!("as of {now}");
    let mut counts = BTreeMap::<(String, String), usize>::new();
    let mut totals = BTreeMap::<String, (usize, usize)>::new();
    for (ecosystem, name, version, signals) in &found {
        let total = totals.entry(ecosystem.clone()).or_default();
        total.0 += 1;
        let Some(signals) = signals else {
            total.1 += 1;
            println!("{ecosystem}\t{name}@{version}\tnot read");
            continue;
        };
        let mut kinds = BTreeSet::new();
        for signal in signals {
            kinds.insert(signal.key());
        }
        for kind in kinds {
            *counts.entry((ecosystem.clone(), kind)).or_default() += 1;
        }
        if !signals.is_empty() {
            let said: Vec<String> = signals.iter().map(ToString::to_string).collect();
            println!("{ecosystem}\t{name}@{version}\t{}", said.join("; "));
        }
    }
    for (ecosystem, (versions, unread)) in &totals {
        println!("\n== {ecosystem}\nversions\t{versions}\nnot read\t{unread}");
        for kind in ["new_package", "new_publisher", "no_repository", "near_name"] {
            let n = counts
                .get(&(ecosystem.clone(), kind.to_owned()))
                .copied()
                .unwrap_or(0);
            println!("{kind}\t{n}");
        }
    }
}
