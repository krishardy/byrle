//! `waharoa policy diff`: what changes if this policy replaces that one.
//!
//! # Vectors, not verdicts
//!
//! Two policies can both answer `block` for different reasons. Comparing
//! [`Decision::action`] reports no change there, and the change is real: one denial
//! lapsed and another check started firing. So the comparison is per check, and the report
//! names which check moved. That is the half an operator can act on.
//!
//! # A check that stops being enforced is a loosening
//!
//! `FAIL` to `unenforced` is not a loosening of the written policy. The setting is still
//! there. It is a loosening of what happens, because the package now installs. The gate
//! exists to stop a change slipping something through, so that is what it reports, and the
//! report says `unenforced` rather than pretending the check passed.
//!
//! # What is not compared
//!
//! `n/a` moves only if the ecosystem did, and a package does not change ecosystem between
//! two policies. A `n/a` on one side and anything else on the other is
//! [`Strictness::Incomparable`], which fails the gate rather than being guessed at.
//!
//! # Exit bits
//!
//! The exit code is the OR of [`LOOSENED`], [`TIGHTENED`] and [`ERROR`], so a scheduled run can
//! see a lapsing entry tighten a package while a CI gate still fails only on a loosening.
//! [`ERROR`] is set when a listed version could not be read or none was judged, so a run that
//! judged nothing cannot pass. An error before the report, such as a policy that does not load,
//! exits [`ERROR`] alone. See docs/engineering_decisions/policy-diff-dates-and-exit-bits.md.

use std::ffi::OsString;

use super::decide::{Check, Decision, Outcome};
use super::enforce::Unenforceable;
use super::strictness::Strictness;
use super::{Action, Policy, today};
use crate::ecosystem::Clients;
use crate::env::Env;
use crate::intel::snapshot_intel;
use crate::intel::store::{self, Intel};

/// Exit bit: a check got looser, or cannot be compared.
pub const LOOSENED: u8 = 1;
/// Exit bit: a check got stricter.
pub const TIGHTENED: u8 = 2;
/// Exit bit: a listed version could not be read, none was judged, or the diff could not be run.
pub const ERROR: u8 = 4;

/// What a check answered, as the report shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    Pass,
    Fail(Action),
    /// Excused by a `packages` entry. Delivers, and the entry is worth naming.
    Excepted(usize),
    /// No meaning for this ecosystem.
    NotApplicable,
    /// The fact the check needs is not available in this build.
    Unenforced,
}

impl Shown {
    pub fn as_str(self) -> String {
        match self {
            Self::Pass => "pass".to_owned(),
            Self::Fail(action) => format!("FAIL {}", action.as_str()),
            Self::Excepted(entry) => format!("excepted by packages[{entry}]"),
            Self::NotApplicable => "n/a".to_owned(),
            Self::Unenforced => "unenforced".to_owned(),
        }
    }

    /// What the package actually gets. `None` where the check cannot be compared at all.
    fn effect(self) -> Option<Action> {
        match self {
            // An unenforced check delivers the package, whatever the setting says.
            Self::Pass | Self::Excepted(_) | Self::Unenforced => Some(Action::Allow),
            Self::Fail(action) => Some(action),
            Self::NotApplicable => None,
        }
    }
}

/// Read one check out of a decision.
pub fn shown(decision: &Decision, unenforceable: &[Unenforceable], check: Check) -> Shown {
    if unenforceable.iter().any(|u| u.check == check) {
        return Shown::Unenforced;
    }
    match decision.results.iter().find(|r| r.check == check) {
        None => Shown::Unenforced,
        Some(result) => match result.outcome {
            Outcome::Passed => Shown::Pass,
            Outcome::Failed(action) => Shown::Fail(action),
            Outcome::Excepted { entry, .. } => Shown::Excepted(entry),
            Outcome::NotApplicable => Shown::NotApplicable,
        },
    }
}

/// One check that answered differently.
#[derive(Debug, Clone, PartialEq)]
pub struct Moved {
    pub check: Check,
    pub from: Shown,
    pub to: Shown,
    pub strictness: Strictness,
}

/// How one check's two answers compare.
pub fn compare(from: Shown, to: Shown) -> Strictness {
    match (from.effect(), to.effect()) {
        (None, None) => Strictness::NotApplicable,
        // A package does not change ecosystem between two policies, so this is a
        // disagreement rather than a move. Refused rather than guessed at.
        (None, Some(_)) | (Some(_), None) => Strictness::Incomparable,
        (Some(before), Some(after)) => match after.strength().cmp(&before.strength()) {
            std::cmp::Ordering::Greater => Strictness::Stricter,
            std::cmp::Ordering::Less => Strictness::Looser,
            std::cmp::Ordering::Equal => Strictness::Same,
        },
    }
}

/// One package, decided twice.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub purl: String,
    pub from_verdict: Action,
    pub to_verdict: Action,
    /// Only the checks that answered differently.
    pub moved: Vec<Moved>,
}

impl Package {
    /// Whether anything about this package got looser.
    ///
    /// Per check, not on the verdict. A package whose verdict stays `block` while one
    /// check stopped firing has still loosened, and that is what the gate is for.
    pub fn loosened(&self) -> bool {
        self.moved
            .iter()
            .any(|m| m.strictness == Strictness::Looser)
    }

    pub fn incomparable(&self) -> bool {
        self.moved
            .iter()
            .any(|m| m.strictness == Strictness::Incomparable)
    }

    /// Whether any check got stricter.
    pub fn tightened(&self) -> bool {
        self.moved
            .iter()
            .any(|m| m.strictness == Strictness::Stricter)
    }
}

/// Compare one package under two policies.
pub fn package(
    purl: &str,
    from: (&Decision, &[Unenforceable]),
    to: (&Decision, &[Unenforceable]),
) -> Package {
    let moved = Check::ALL
        .iter()
        .filter_map(|&check| {
            let before = shown(from.0, from.1, check);
            let after = shown(to.0, to.1, check);
            (before != after).then(|| Moved {
                check,
                from: before,
                to: after,
                strictness: compare(before, after),
            })
        })
        .collect();

    Package {
        purl: purl.to_owned(),
        from_verdict: super::enforce::enforced(from.0, from.1).action(),
        to_verdict: super::enforce::enforced(to.0, to.1).action(),
        moved,
    }
}

/// Every package that moved, and what it means for the gate.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Report {
    /// Package versions listed to compare, including ones not judged.
    pub listed: usize,
    /// Listed versions whose packument or publish times could not be read.
    pub unread: usize,
    /// Packages evaluated, including ones that did not move.
    pub evaluated: usize,
    /// Only the packages that moved.
    pub changed: Vec<Package>,
}

impl Report {
    pub fn push(&mut self, package: Package) {
        self.evaluated += 1;
        if !package.moved.is_empty() {
            self.changed.push(package);
        }
    }

    pub fn loosened(&self) -> Vec<&Package> {
        self.changed.iter().filter(|p| p.loosened()).collect()
    }

    pub fn incomparable(&self) -> Vec<&Package> {
        self.changed.iter().filter(|p| p.incomparable()).collect()
    }

    pub fn tightened(&self) -> Vec<&Package> {
        self.changed.iter().filter(|p| p.tightened()).collect()
    }

    /// Whether versions were listed and none was judged, for any reason.
    pub fn judged_none(&self) -> bool {
        self.listed > 0 && self.evaluated == 0
    }

    /// The exit code: [`LOOSENED`] if a check loosened or cannot be compared,
    /// [`TIGHTENED`] if one got stricter, and [`ERROR`] if a listed version could not be read
    /// or none was judged, OR-ed.
    ///
    /// Incomparable sets the loosening bit: §5.5 is fail loud when tightening cannot be
    /// proven, and a diff that cannot be decided is exactly that case.
    pub fn exit_bits(&self) -> u8 {
        let loosened = !self.loosened().is_empty() || !self.incomparable().is_empty();
        let tightened = !self.tightened().is_empty();
        let failed = self.unread > 0 || self.judged_none();
        (if loosened { LOOSENED } else { 0 })
            | (if tightened { TIGHTENED } else { 0 })
            | (if failed { ERROR } else { 0 })
    }

    /// Grouped by check and direction, which is what a person reads first.
    pub fn render(&self) -> String {
        let mut out = format!("{} packages evaluated\n", self.evaluated);
        if self.unread > 0 {
            out.push_str(&format!("{} could not be read\n", self.unread));
        }
        if self.changed.is_empty() {
            out.push_str("nothing moved\n");
            return out;
        }

        let mut counts: std::collections::BTreeMap<(&str, &str), usize> =
            std::collections::BTreeMap::new();
        for package in &self.changed {
            for moved in &package.moved {
                *counts
                    .entry((moved.check.as_str(), strictness(moved.strictness)))
                    .or_default() += 1;
            }
        }
        out.push_str(&format!("{} moved\n\n", self.changed.len()));
        for ((check, direction), count) in &counts {
            out.push_str(&format!("  {count:>5}  {check} {direction}\n"));
        }

        out.push('\n');
        for package in &self.changed {
            out.push_str(&format!(
                "{}  {} -> {}\n",
                package.purl,
                package.from_verdict.as_str(),
                package.to_verdict.as_str()
            ));
            for moved in &package.moved {
                out.push_str(&format!(
                    "    {:16}  {} -> {}  ({})\n",
                    moved.check.as_str(),
                    moved.from.as_str(),
                    moved.to.as_str(),
                    strictness(moved.strictness)
                ));
            }
        }
        out
    }
}

fn strictness(s: Strictness) -> &'static str {
    match s {
        Strictness::Stricter => "stricter",
        Strictness::Looser => "LOOSER",
        Strictness::Same => "same",
        Strictness::Incomparable => "INCOMPARABLE",
        Strictness::NotApplicable => "n/a",
        Strictness::Unset => "unset",
    }
}

/// What a `waharoa policy diff` run prints and exits with.
///
/// `notes` and `summary` are stderr lines, before and after the report, without the
/// command's prefix. The binary prints them and exits with `code`.
#[derive(Debug, Default)]
pub struct Run {
    pub notes: Vec<String>,
    pub report: String,
    pub summary: Vec<String>,
    pub code: u8,
}

impl Run {
    /// Nothing was compared: what stopped it is the last note.
    fn stop(mut self) -> Self {
        self.code = ERROR;
        self
    }
}

/// Compare two policies over the packages the audit log and the lockfiles list.
///
/// Every package is asked of its own ecosystem's registry, and of the intel store or the
/// kept snapshot `--snapshot` names. One package that cannot be read is counted and the
/// rest are still compared, because the exit bit says a package was missed.
pub async fn run<L: Fn(&str) -> Option<OsString>>(
    args: &crate::cli::Diff,
    environment: &Env<L>,
) -> Run {
    let mut out = Run::default();
    let now = today();
    let dates = [
        args.from_date.map_or(now, |when| when.date(now)),
        args.to_date.map_or(now, |when| when.date(now)),
    ];
    if dates[0] != dates[1] {
        out.notes.push(format!(
            "<FROM> as of {}, <TO> as of {}",
            dates[0], dates[1]
        ));
    }
    let comparison = match Comparison::read(args, environment, dates, &mut out.notes).await {
        Ok(comparison) => comparison,
        Err(note) => {
            out.notes.push(note);
            return out.stop();
        }
    };

    let mut report = Report {
        listed: comparison.versions.len(),
        ..Report::default()
    };
    for (purl, reference, version) in &comparison.versions {
        match comparison.compare(reference, version).await {
            Ok(Compared::Decided(decided)) => report.push(package(
                purl,
                (&decided[0].0, &decided[0].1),
                (&decided[1].0, &decided[1].1),
            )),
            Ok(Compared::Unpublished) => out.notes.push(format!("{purl}: no longer published")),
            Ok(Compared::Unread(e)) => {
                out.notes.push(format!("{purl}: {e}"));
                report.unread += 1;
            }
            Err(e) => {
                out.notes.push(format!("{purl}: {e}"));
                return out.stop();
            }
        }
    }

    out.report = report.render();
    let bits = report.exit_bits();
    if bits != 0 {
        out.summary.push(format!(
            "{} loosened, {} incomparable, {} tightened, {} could not be read",
            report.loosened().len(),
            report.incomparable().len(),
            report.tightened().len(),
            report.unread
        ));
    }
    if report.judged_none() {
        out.summary.push(format!(
            "none of the {} package versions listed was judged",
            report.listed
        ));
    }
    out.code = bits;
    out
}

/// What [`run`] compares the two policies with, read before any package is.
struct Comparison {
    /// `<FROM>` then `<TO>`.
    policies: Vec<Policy>,
    /// The date each policy is decided as of, in the order of `policies`.
    dates: [jiff::civil::Date; 2],
    versions: Vec<crate::lockfile::Reference>,
    store: Option<Box<dyn Intel>>,
    clients: Clients,
    needs_times: bool,
    /// False with `--snapshot`, whose kept snapshot records no streams.
    streams_recorded: bool,
}

/// What reading one listed version came to.
enum Compared {
    /// Each policy's decision and what it could not enforce, in the order of
    /// [`Comparison::policies`].
    Decided(Vec<(Decision, Vec<Unenforceable>)>),
    /// The registry no longer publishes the version.
    Unpublished,
    /// Its metadata, publish times or intel could not be read.
    Unread(String),
}

impl Comparison {
    /// Load both policies, the listed versions, the intel store and the registry clients.
    /// `Err` is the note that stops the run. The intel snapshot is noted in `notes`.
    async fn read<L: Fn(&str) -> Option<OsString>>(
        args: &crate::cli::Diff,
        environment: &Env<L>,
        dates: [jiff::civil::Date; 2],
        notes: &mut Vec<String>,
    ) -> Result<Self, String> {
        let policies = [&args.from, &args.to]
            .into_iter()
            .map(|path| Policy::load(path).map_err(|e| format!("{}: {e}", path.display())))
            .collect::<Result<Vec<_>, _>>()?;
        let versions = crate::lockfile::references(listed(args, environment)?);
        let store = open_store(args, environment, &versions).await?;
        if let Some(store) = &store
            && let Ok(Some(snapshot)) = store.snapshot().await
        {
            notes.push(format!("intel snapshot {}", snapshot.digest));
        }
        // Each package is asked of its own ecosystem's registry.
        let clients = Clients::from_env(environment).map_err(|e| e.to_string())?;
        let needs_times = policies.iter().any(Policy::needs_publish_times);
        Ok(Self {
            policies,
            dates,
            versions,
            store,
            clients,
            needs_times,
            streams_recorded: args.snapshot.is_none(),
        })
    }

    /// Read one listed version and decide it under both policies. `Err` is an intel store
    /// that failed, which stops the run.
    async fn compare(
        &self,
        reference: &crate::identity::PackageRef,
        version: &str,
    ) -> Result<Compared, String> {
        // Metadata that cannot be read is reported and counted, and the run goes on, so
        // one bad package does not hide the rest. The count sets the exit's error bit.
        let metadata = match crate::ecosystem::fetched(self.clients.metadata(reference.key()).await)
        {
            Ok(metadata) => metadata,
            Err(e) => return Ok(Compared::Unread(e)),
        };
        let Some(record) = metadata.version(version) else {
            // The registry no longer publishes it. That is a real answer for a lockfile
            // and is not a diff between two policies, so it is reported and skipped.
            return Ok(Compared::Unpublished);
        };
        let times = if self.needs_times {
            match self.clients.publish_times(reference.key()).await {
                Ok(times) => times,
                Err(e) => return Ok(Compared::Unread(e)),
            }
        } else {
            None
        };
        let (ecosystem, name) = snapshot_intel::key_of(reference.key());
        let intel = match store::for_command(
            self.store.as_deref(),
            &ecosystem,
            &name,
            self.streams_recorded,
        )
        .await
        {
            Ok(intel) => intel,
            // Counted with the packages that could not be read, so the others are still
            // compared and the exit's error bit is set.
            Err(store::NoIntel::Uncovered(e)) => return Ok(Compared::Unread(e)),
            Err(store::NoIntel::Failed(e)) => return Err(e),
        };
        Ok(Compared::Decided(
            self.policies
                .iter()
                .zip(self.dates)
                .map(|(policy, as_of)| {
                    decide_under(
                        policy,
                        as_of,
                        &metadata.records,
                        record,
                        version,
                        times.as_ref(),
                        intel.as_ref(),
                    )
                })
                .collect(),
        ))
    }
}

/// The packages the audit log and the lockfiles list. `Err` is the note that stops the run.
fn listed<L: Fn(&str) -> Option<OsString>>(
    args: &crate::cli::Diff,
    environment: &Env<L>,
) -> Result<Vec<crate::lockfile::Locked>, String> {
    let log_path = environment.audit_log().map_err(|e| e.to_string())?;
    if log_path.is_none() && args.lockfile.is_empty() {
        return Err(format!(
            "set {} or pass --lockfile, for the packages to compare over",
            crate::env::AUDIT_LOG
        ));
    }
    let mut listed = Vec::new();
    if let Some(log_path) = log_path {
        let log = std::fs::read_to_string(&log_path)
            .map_err(|e| format!("{}: {e}", log_path.display()))?;
        listed.extend(crate::audit::packages(&log));
    }
    for path in &args.lockfile {
        listed.extend(crate::lockfile::read(path).map_err(|e| e.to_string())?);
    }
    Ok(listed)
}

/// The kept snapshot `--snapshot` names, or else the intel store, if one is configured.
/// `Err` is the note that stops the run.
///
/// A kept snapshot when one is named, so a changed result is the policy's and not an
/// advisory published since. It is read for `versions` only.
async fn open_store<L: Fn(&str) -> Option<OsString>>(
    args: &crate::cli::Diff,
    environment: &Env<L>,
    versions: &[crate::lockfile::Reference],
) -> Result<Option<Box<dyn Intel>>, String> {
    let Some(id) = &args.snapshot else {
        return crate::intel::postgres::from_env(environment)
            .await
            .map(|store| store.map(|store| Box::new(store) as Box<dyn Intel>))
            .map_err(|e| format!("{}: {e}", crate::env::DATABASE_URL));
    };
    let packages = versions
        .iter()
        .map(|(_, reference, _)| snapshot_intel::key_of(reference.key()))
        .collect();
    snapshot_intel::kept(environment, id, packages)
        .map(|kept| Some(Box::new(kept) as Box<dyn Intel>))
        .map_err(|e| format!("--snapshot {id}: {e}"))
}

/// `record`, which is `version` of `records`, decided under `policy` as of `as_of`, and
/// what `policy` could not enforce.
fn decide_under(
    policy: &Policy,
    as_of: jiff::civil::Date,
    records: &[crate::record::PackageRecord],
    record: &crate::record::PackageRecord,
    version: &str,
    times: Option<&super::facts::PublishTimes>,
    intel: Option<&crate::intel::store::PackageIntel>,
) -> (Decision, Vec<Unenforceable>) {
    let facts = super::decide::Facts::from_document(policy, records, record, version, times, intel);
    (
        super::decide::decide(policy, &facts, as_of),
        super::enforce::unenforceable(policy, record, times, facts.intel, &facts.provenance),
    )
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use crate::env::testing::with;
    use crate::util::test_support::{Answer, scripted, tempdir};

    /// Two policies on disk, and a lockfile naming one package the scripted registry
    /// publishes.
    fn written(label: &str, from: &str, to: &str) -> (std::path::PathBuf, crate::cli::Diff) {
        let dir = tempdir(label);
        let (from_path, to_path) = (dir.join("from.yaml"), dir.join("to.yaml"));
        std::fs::write(&from_path, from).expect("writes");
        std::fs::write(&to_path, to).expect("writes");
        let lockfile = dir.join("package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21",
               "resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}}}"#,
        )
        .expect("writes");
        (
            dir,
            crate::cli::Diff {
                from: from_path,
                to: to_path,
                from_date: None,
                to_date: None,
                snapshot: None,
                lockfile: vec![lockfile],
            },
        )
    }

    /// A policy that does not load stops the run before any package is asked about.
    #[tokio::test]
    async fn a_policy_that_does_not_load_stops_the_run() {
        let (dir, args) = written("diff-unloadable", "version: 9\n", "version: 1\n");
        let run = run(&args, &with(&[])).await;
        assert_eq!(run.code, ERROR);
        assert!(run.report.is_empty());
        assert_eq!(run.notes.len(), 1, "{:?}", run.notes);
        assert!(run.notes[0].contains("from.yaml"), "{:?}", run.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No audit log and no lockfile is nothing to compare over.
    #[tokio::test]
    async fn with_no_packages_to_compare_over_it_says_so() {
        let (dir, mut args) = written(
            "diff-no-packages",
            "version: 1\ncooldown_days: 0\n",
            "version: 1\ncooldown_days: 0\n",
        );
        args.lockfile.clear();
        let run = run(&args, &with(&[])).await;
        assert_eq!(run.code, ERROR);
        assert!(
            run.notes[0].starts_with(&format!("set {} or pass --lockfile", crate::env::AUDIT_LOG)),
            "{:?}",
            run.notes
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A check that starts firing is a tightening, and the report names it.
    #[tokio::test]
    async fn a_stricter_policy_is_reported_as_tightened() {
        let (dir, args) = written(
            "diff-tightened",
            "version: 1\ncooldown_days: 0\n",
            "version: 1\ncooldown_days: 36500\n",
        );
        let addr = scripted(vec![Answer::body(crate::ecosystem::npm::fixture(
            "lodash-4.17.21.full.json",
        ))])
        .await;
        let run = run(
            &args,
            &with(&[(crate::env::UPSTREAM_NPM, &format!("http://{addr}"))]),
        )
        .await;
        assert_eq!(run.code, TIGHTENED, "{:?} {:?}", run.notes, run.summary);
        assert!(
            run.report.contains("pkg:npm/lodash@4.17.21"),
            "{}",
            run.report
        );
        assert!(run.report.contains("cooldown_days"), "{}", run.report);
        assert_eq!(
            run.summary,
            ["0 loosened, 0 incomparable, 1 tightened, 0 could not be read"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cooldown needs publish times, and a package whose times cannot be read is
    /// counted rather than judged without them.
    #[tokio::test]
    async fn a_package_whose_publish_times_cannot_be_read_is_counted() {
        let (dir, args) = written(
            "diff-times",
            "version: 1\ncooldown_days: 1\n",
            "version: 1\ncooldown_days: 2\n",
        );
        // The abbreviated packument answers first, then the full one is refused, which is
        // the request a cooldown adds.
        let addr = scripted(vec![
            Answer::body(crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json")),
            Answer::Status(500),
        ])
        .await;
        let run = run(
            &args,
            &with(&[(crate::env::UPSTREAM_NPM, &format!("http://{addr}"))]),
        )
        .await;
        assert_eq!(run.code, ERROR, "{:?} {:?}", run.notes, run.summary);
        assert!(
            run.notes
                .iter()
                .any(|note| note.contains("publish times could not be fetched")),
            "{:?}",
            run.notes
        );
        assert_eq!(
            run.summary,
            [
                "0 loosened, 0 incomparable, 0 tightened, 1 could not be read".to_owned(),
                "none of the 1 package versions listed was judged".to_owned()
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A package the registry cannot be asked about is counted and the run goes on.
    #[tokio::test]
    async fn a_package_that_cannot_be_read_is_counted() {
        let (dir, args) = written(
            "diff-unread",
            "version: 1\ncooldown_days: 0\n",
            "version: 1\ncooldown_days: 0\n",
        );
        let addr = scripted(vec![Answer::Status(404)]).await;
        let run = run(
            &args,
            &with(&[(crate::env::UPSTREAM_NPM, &format!("http://{addr}"))]),
        )
        .await;
        assert_eq!(run.code, ERROR);
        assert!(
            run.notes
                .iter()
                .any(|note| note.starts_with("pkg:npm/lodash@4.17.21: metadata could not be")),
            "{:?}",
            run.notes
        );
        assert_eq!(
            run.summary,
            [
                "0 loosened, 0 incomparable, 0 tightened, 1 could not be read".to_owned(),
                "none of the 1 package versions listed was judged".to_owned()
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::policy::decide::{Facts, Intel, decide};

    const TODAY: jiff::civil::Date = jiff::civil::date(2026, 9, 13);

    fn facts() -> Facts {
        Facts {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
            published: Some(jiff::civil::date(2021, 2, 20)),
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: false,
            yanked: None,
            deprecated: None,
            intel: Intel::Consulted {
                exploitation_loaded: true,
            },
            provenance: crate::policy::decide::Provenance::Consistent,
        }
    }

    fn decided(yaml: &str, facts: &Facts) -> Decision {
        let policy = Policy::parse(yaml).expect("policy should load");
        decide(&policy, facts, TODAY)
    }

    fn diff(from: &str, to: &str, facts: &Facts) -> Package {
        package(
            "pkg:npm/lodash@4.17.21",
            (&decided(from, facts), &[]),
            (&decided(to, facts), &[]),
        )
    }

    #[test]
    fn an_unchanged_policy_moves_nothing() {
        let d = diff("version: 1", "version: 1", &facts());

        assert!(d.moved.is_empty());
        assert!(!d.loosened());
    }

    /// The requirement this is built for: both verdicts are `block`, and the change is
    /// real. Comparing verdicts would report nothing.
    #[test]
    fn two_policies_that_both_block_for_different_reasons_still_show_the_move() {
        let facts = Facts {
            has_install_scripts: true,
            yanked: None,
            deprecated: None,
            ..facts()
        };
        let d = diff(
            "version: 1\ninstall_scripts: block\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            "version: 1\ninstall_scripts: block\n\
             denials:\n  - purl: pkg:npm/other@1.0.0\n    reason: t\n",
            &facts,
        );

        assert_eq!(d.from_verdict, Action::Block);
        assert_eq!(d.to_verdict, Action::Block);
        assert_eq!(d.moved.len(), 1);
        assert_eq!(d.moved[0].check, Check::Denials);
        assert_eq!(d.moved[0].strictness, Strictness::Looser);
        assert!(d.loosened(), "a check stopped firing; the verdict hid it");
    }

    #[test]
    fn dropping_a_denial_is_a_loosening() {
        let d = diff(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            "version: 1",
            &facts(),
        );

        assert_eq!(d.moved[0].from, Shown::Fail(Action::Block));
        assert_eq!(d.moved[0].to, Shown::Pass);
        assert!(d.loosened());
    }

    #[test]
    fn adding_a_denial_is_a_tightening() {
        let d = diff(
            "version: 1",
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        );

        assert_eq!(d.moved[0].strictness, Strictness::Stricter);
        assert!(!d.loosened());
    }

    /// Block to quarantine is a loosening: quarantine lapses on its own.
    #[test]
    fn moving_down_the_lattice_is_a_loosening() {
        let from = decided(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        );
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package("pkg:npm/lodash@4.17.21", (&from, &[]), (&to, &[]));

        assert_eq!(d.from_verdict, Action::Block);
        assert_eq!(d.to_verdict, Action::Quarantine);
        assert!(d.loosened());
    }

    /// The written policy did not loosen. What happens did, so the gate says so.
    #[test]
    fn a_check_that_stops_being_enforced_is_a_loosening() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "no publish date",
        }];
        let from = decided("version: 1\ncooldown_days: 3650", &facts());
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package(
            "pkg:npm/lodash@4.17.21",
            (&from, &[]),
            (&to, &unenforceable),
        );

        assert_eq!(d.moved.len(), 1);
        assert_eq!(d.moved[0].to, Shown::Unenforced);
        assert_eq!(d.moved[0].strictness, Strictness::Looser);
        assert!(d.loosened());
        assert_eq!(
            (d.from_verdict, d.to_verdict),
            (Action::Quarantine, Action::Allow),
            "the proxy serves it once the check is unenforced"
        );
    }

    /// A check starting to be enforced is the other direction.
    #[test]
    fn a_check_that_starts_being_enforced_is_a_tightening() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "no publish date",
        }];
        let from = decided("version: 1\ncooldown_days: 3650", &facts());
        let to = decided("version: 1\ncooldown_days: 3650", &facts());
        let d = package(
            "pkg:npm/lodash@4.17.21",
            (&from, &unenforceable),
            (&to, &[]),
        );

        assert_eq!(d.moved[0].strictness, Strictness::Stricter);
        assert!(!d.loosened());
        assert_eq!(
            (d.from_verdict, d.to_verdict),
            (Action::Allow, Action::Quarantine),
            "the proxy served it while the check was unenforced"
        );
    }

    /// An exception delivers the package, so gaining one is a loosening even though the
    /// check still finds something.
    #[test]
    fn gaining_an_exception_is_a_loosening_and_names_the_entry() {
        let facts = Facts {
            has_install_scripts: true,
            yanked: None,
            deprecated: None,
            ..facts()
        };
        let d = diff(
            "version: 1\ninstall_scripts: block",
            "version: 1\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    permanent: true\n",
            &facts,
        );

        assert_eq!(d.moved[0].from, Shown::Fail(Action::Block));
        assert_eq!(d.moved[0].to, Shown::Excepted(0));
        assert!(d.loosened());
        assert!(d.moved[0].to.as_str().contains("packages[0]"));
    }

    /// A package does not change ecosystem between two policies, so this is a
    /// disagreement. §5.5 fails loud when tightening cannot be proven.
    #[test]
    fn not_applicable_against_anything_else_is_incomparable_and_fails_the_gate() {
        assert_eq!(
            compare(Shown::NotApplicable, Shown::Pass),
            Strictness::Incomparable
        );
        assert_eq!(
            compare(Shown::Pass, Shown::NotApplicable),
            Strictness::Incomparable
        );
        assert_eq!(
            compare(Shown::NotApplicable, Shown::NotApplicable),
            Strictness::NotApplicable
        );

        let mut report = Report::default();
        report.push(Package {
            purl: "pkg:npm/x@1.0.0".to_owned(),
            from_verdict: Action::Allow,
            to_verdict: Action::Allow,
            moved: vec![Moved {
                check: Check::InstallScripts,
                from: Shown::NotApplicable,
                to: Shown::Pass,
                strictness: Strictness::Incomparable,
            }],
        });
        assert_eq!(report.exit_bits(), LOOSENED);
    }

    #[test]
    fn a_version_not_read_or_nothing_judged_sets_the_error_bit() {
        let loosening = diff(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            "version: 1",
            &facts(),
        );
        let mut report = Report {
            listed: 2,
            unread: 1,
            ..Report::default()
        };
        report.push(loosening);
        assert_eq!(report.exit_bits(), LOOSENED | ERROR);
        assert!(
            report
                .render()
                .contains("1 packages evaluated\n1 could not be read\n")
        );

        let none = Report {
            listed: 3,
            ..Report::default()
        };
        assert!(none.judged_none());
        assert_eq!(none.exit_bits(), ERROR);
        assert!(!none.render().contains("could not be read"));

        let nothing_listed = Report::default();
        assert!(!nothing_listed.judged_none());
        assert_eq!(nothing_listed.exit_bits(), 0);
    }

    /// Scripts read these numbers, so the values are part of the command.
    #[test]
    fn the_exit_bits_are_1_2_and_4() {
        assert_eq!((LOOSENED, TIGHTENED, ERROR), (1, 2, 4));
    }

    #[test]
    fn everything_tightening_sets_only_the_tightening_bit() {
        let mut report = Report::default();
        report.push(diff(
            "version: 1",
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
        ));

        assert_eq!(report.evaluated, 1);
        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.tightened().len(), 1);
        assert_eq!(report.exit_bits(), TIGHTENED);
    }

    /// The scheduled run: one policy today and in 30 days. The exception lapses, which
    /// tightens `install_scripts`, and the package ages past its cooldown, which loosens it.
    #[test]
    fn one_policy_at_two_dates_tightens_as_an_entry_lapses_and_loosens_as_a_cooldown_passes() {
        let policy = Policy::parse(
            "version: 1\ncooldown_days: 30\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    expires: \"2026-09-20\"\n",
        )
        .expect("policy should load");
        let facts = Facts {
            has_install_scripts: true,
            yanked: None,
            deprecated: None,
            published: Some(jiff::civil::date(2026, 9, 1)),
            ..facts()
        };
        let later = jiff::civil::date(2026, 10, 13);
        let d = package(
            "pkg:npm/lodash@4.17.21",
            (&decide(&policy, &facts, TODAY), &[]),
            (&decide(&policy, &facts, later), &[]),
        );

        let moved: Vec<(Check, Shown, Shown, Strictness)> = d
            .moved
            .iter()
            .map(|m| (m.check, m.from, m.to, m.strictness))
            .collect();
        assert_eq!(
            moved,
            [
                (
                    Check::CooldownDays,
                    Shown::Fail(Action::Quarantine),
                    Shown::Pass,
                    Strictness::Looser
                ),
                (
                    Check::InstallScripts,
                    Shown::Excepted(0),
                    Shown::Fail(Action::Block),
                    Strictness::Stricter
                ),
            ]
        );
        let mut report = Report::default();
        report.push(d);
        assert_eq!(report.exit_bits(), LOOSENED | TIGHTENED);

        let mut unmoved = Report::default();
        unmoved.push(diff("version: 1", "version: 1", &facts));
        assert_eq!(unmoved.exit_bits(), 0);
    }

    #[test]
    fn a_package_that_did_not_move_is_counted_but_not_listed() {
        let mut report = Report::default();
        report.push(diff("version: 1", "version: 1", &facts()));

        assert_eq!(report.evaluated, 1);
        assert!(report.changed.is_empty());
        assert!(report.render().contains("nothing moved"));
    }

    #[test]
    fn the_report_groups_by_check_and_direction_with_counts() {
        let mut report = Report::default();
        for name in ["a", "b"] {
            let facts = Facts {
                name: name.to_owned(),
                ..facts()
            };
            report.push(package(
                &format!("pkg:npm/{name}@4.17.21"),
                (
                    &decided(
                        &format!(
                            "version: 1\ndenials:\n  - purl: pkg:npm/{name}@4.17.21\n    reason: t\n"
                        ),
                        &facts,
                    ),
                    &[],
                ),
                (&decided("version: 1", &facts), &[]),
            ));
        }

        let out = report.render();
        assert!(out.contains("2 packages evaluated"), "{out}");
        assert!(out.contains("2 moved"), "{out}");
        assert!(out.contains("2  denials LOOSER"), "{out}");
        assert!(out.contains("pkg:npm/a@4.17.21  block -> allow"), "{out}");
        assert_eq!(report.exit_bits(), LOOSENED);
        assert_eq!(report.loosened().len(), 2);
    }

    /// `kev` is unenforced on both sides when the store has not loaded the KEV catalogue, so
    /// changing its setting moves nothing and does not fail the gate.
    #[test]
    fn changing_kev_moves_nothing_while_it_is_unenforced() {
        let unenforceable = [Unenforceable {
            check: Check::Kev,
            why: "no exploitation stream is loaded, so no advisory is marked exploited",
        }];
        let facts = Facts {
            advisories: vec![crate::policy::decide::Advisory {
                id: "CVE-2024-1".to_owned(),
                aliases: Vec::new(),
                cvss: Some(5.0),
                band: None,
                kev: true,
                sources: vec!["osv".to_owned()],
            }],
            ..facts()
        };
        let from = decided("version: 1\nkev: block", &facts);
        let to = decided("version: 1\nkev: allow", &facts);
        assert_eq!(from.action(), Action::Block, "the engine alone refuses it");

        let d = package(
            "pkg:npm/lodash@4.17.21",
            (&from, &unenforceable),
            (&to, &unenforceable),
        );
        assert!(d.moved.is_empty(), "{:?}", d.moved);
        assert!(!d.loosened());
    }

    #[test]
    fn every_state_renders_with_its_own_words() {
        assert_eq!(Shown::Pass.as_str(), "pass");
        assert_eq!(Shown::Fail(Action::Quarantine).as_str(), "FAIL quarantine");
        assert_eq!(Shown::Excepted(3).as_str(), "excepted by packages[3]");
        assert_eq!(Shown::NotApplicable.as_str(), "n/a");
        assert_eq!(Shown::Unenforced.as_str(), "unenforced");
    }

    /// A check the decision never produced reads as unenforced rather than as a pass.
    #[test]
    fn a_check_absent_from_the_vector_is_not_a_pass() {
        let empty = Decision {
            results: Vec::new(),
            entry: None,
        };

        assert_eq!(shown(&empty, &[], Check::Denials), Shown::Unenforced);
    }
}
