//! Measure a detector on the versions lockfiles lock, through the adapter the proxy runs: how
//! often each rule fires, and how long a run takes.
//! See docs/engineering_decisions/detectors.md for the corpus and the results.
//! Run: `cargo run --release --example detector_rates -- '<name=command ...>' <lockfile>...`
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use futures_util::StreamExt as _;
use waharoa::analysis::detector::{Command, Detector, Target};
use waharoa::identity::{Ecosystem, PackageKey};

/// One run: the ecosystem, `name@version`, the rules that fired or why it failed, and seconds.
type Ran = (String, String, Result<Vec<String>, String>, f64);

#[tokio::main]
async fn main() {
    // nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (spec, paths) = args
        .split_first()
        .expect("usage: detector_rates '<name=command ...>' <lockfile>...");
    let detector = Command::configured(spec, waharoa::env::process().detector_environment())
        .await
        .expect("the detector says its version");
    let mut versions = BTreeSet::new();
    for path in paths {
        let locked = waharoa::lockfile::read(std::path::Path::new(path)).expect("a lockfile");
        versions.extend(
            locked
                .into_iter()
                .filter(|(ecosystem, _, _)| ecosystem == "npm" || ecosystem == "pypi"),
        );
    }
    let ran: Vec<Ran> = futures_util::stream::iter(versions)
        .map(|(ecosystem, name, version)| {
            let detector = &detector;
            async move {
                let pypi = ecosystem == "pypi";
                let key = PackageKey::from_registry_name(
                    if pypi {
                        Ecosystem::PyPI
                    } else {
                        Ecosystem::Npm
                    },
                    &name,
                )
                .expect("a lockfile name");
                let target = Target {
                    ecosystem: key.ecosystem(),
                    name: key.registry_name(),
                    version: version.clone(),
                };
                let started = Instant::now();
                let found = detector
                    .detect(&target)
                    .await
                    .map(|detection| detection.findings.into_iter().map(|f| f.rule).collect());
                let seconds = started.elapsed().as_secs_f64();
                (ecosystem, format!("{name}@{version}"), found, seconds)
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    report(detector.name(), detector.version(), ran);
}

/// Per ecosystem: versions, runs that failed, median and slowest run, the mean number of rules
/// fired, and how many versions each rule fired on.
fn report(name: &str, version: &str, ran: Vec<Ran>) {
    println!("{name} {version}");
    let ecosystems: BTreeSet<&String> = ran.iter().map(|(ecosystem, ..)| ecosystem).collect();
    for ecosystem in ecosystems {
        let runs: Vec<_> = ran.iter().filter(|(e, ..)| e == ecosystem).collect();
        let mut seconds: Vec<f64> = runs.iter().map(|(.., s)| *s).collect();
        seconds.sort_by(f64::total_cmp);
        let fired: Vec<&Vec<String>> = runs
            .iter()
            .filter_map(|(_, _, f, _)| f.as_ref().ok())
            .collect();
        let mut rules = BTreeMap::<&str, usize>::new();
        for rule in fired.iter().flat_map(|f| f.iter()) {
            *rules.entry(rule).or_default() += 1;
        }
        println!("\n== {ecosystem}");
        println!("versions\t{}", runs.len());
        println!("failed\t{}", runs.len() - fired.len());
        for (_, version, found, _) in &runs {
            if let Err(why) = found {
                println!("  {version}\t{why}");
            }
        }
        println!("median seconds\t{:.1}", seconds[seconds.len() / 2]);
        println!("slowest seconds\t{:.1}", seconds[seconds.len() - 1]);
        println!(
            "any rule fired\t{}",
            fired.iter().filter(|f| !f.is_empty()).count()
        );
        let total: usize = fired.iter().map(|f| f.len()).sum();
        println!(
            "rules fired per version\t{:.2}",
            total as f64 / fired.len().max(1) as f64
        );
        let mut by_count: Vec<_> = rules.into_iter().collect();
        by_count.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        for (rule, count) in by_count {
            println!("  {count:4}\t{rule}");
        }
    }
}
