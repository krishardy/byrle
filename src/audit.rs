//! One line per policy decision, in JSON Lines.
//!
//! Separate from the tracing log on purpose. Tracing output is diagnostic and its shape is
//! free to change. This is a record an operator keeps and `waharoa policy diff` parses, so
//! it has a schema, one line per decision, and no diagnostics interleaved.
//!
//! # The unit is a request, not a version
//!
//! A packument request evaluates every version in the document. typescript has 3,823 of
//! them. One line per refused version would put thousands of lines in the log for one
//! request, so a resolution event names the versions it removed and the checks that
//! removed them. Per-version reasoning is what `explain` is for.
//!
//! # Writing never fails an install
//!
//! Same rule as `UNINSPECTED`: a full disk or an unwritable path is a warning, not a
//! refusal. The warning is emitted once rather than per line, because a log that cannot be
//! written is one problem and not one per package.

use crate::policy::decide::{Decision, Outcome};
use crate::policy::enforce::Unenforceable;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

/// Which of decision #4's two paths produced this.
///
/// The same verdict means different things on each. A version filtered out of a packument
/// left the client free to pick another; a refused pinned fetch did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionPath {
    /// The packument was filtered. The client resolves against what is left.
    Resolution,
    /// One version was asked for by name and answered.
    Pinned,
}

/// One decision, as written.
///
/// `Default` exists for `#[serde(default)]`, so a line written by an older build that
/// lacks a field still reads rather than being dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Event {
    /// RFC 3339, UTC. The zone is fixed so two proxies' logs can be concatenated.
    pub at: String,
    pub path: DecisionPath,
    pub ecosystem: String,
    pub name: String,
    /// The version decided on. Absent on a resolution event, which decides many.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `allow`, `quarantine` or `block`. On a resolution event this is the strongest
    /// action taken against any version.
    pub action: String,
    /// Versions no longer in the document. Resolution events only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// The checks that decided against the package.
    ///
    /// Ordered strongest first on a `pinned` event, which decides one version. Sorted on a
    /// `resolution` event, which is the union across every version removed and has no
    /// single strongest to lead with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<String>,
    /// Indices of the `packages` entries that did work.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exceptions_used: Vec<usize>,
    /// Checks that could not be answered, and why.
    ///
    /// Present so an unenforced `cooldown_days` does not read as a passed one. An absent
    /// answer is not a clean answer, the same distinction `policy::facts` makes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unenforceable: Vec<String>,
    /// Which intel the verdict was reached against.
    ///
    /// `None` when no intel store was consulted. Absent rather than empty, so a decision
    /// reached without intel cannot be read as one reached against an empty snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_snapshot: Option<String>,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            at: String::new(),
            path: DecisionPath::Pinned,
            ecosystem: String::new(),
            name: String::new(),
            version: None,
            action: String::new(),
            removed: Vec::new(),
            checks: Vec::new(),
            exceptions_used: Vec::new(),
            unenforceable: Vec::new(),
            intel_snapshot: None,
        }
    }
}

impl Event {
    /// A pinned artifact decision.
    pub fn pinned(
        ecosystem: &str,
        name: &str,
        version: &str,
        decision: &Decision,
        unenforceable: &[Unenforceable],
    ) -> Self {
        // What the proxy acted on: an unenforced check's answer is not part of it.
        let decision = &crate::policy::enforce::enforced(decision, unenforceable);
        Self {
            at: now(),
            path: DecisionPath::Pinned,
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            action: decision.action().as_str().to_owned(),
            removed: Vec::new(),
            checks: decided_against(decision),
            exceptions_used: decision.exceptions_used(),
            unenforceable: unenforceable.iter().map(|u| u.check.as_str().to_owned()).collect(),
            intel_snapshot: None,
        }
    }

    /// Name the intel snapshot the decision was reached against.
    pub fn with_intel_snapshot(mut self, snapshot: Option<&str>) -> Self {
        self.intel_snapshot = snapshot.map(str::to_owned);
        self
    }

    /// A packument that was filtered.
    pub fn resolution(
        ecosystem: &str,
        name: &str,
        action: &str,
        removed: Vec<String>,
        checks: Vec<String>,
        unenforceable: &[Unenforceable],
    ) -> Self {
        Self {
            at: now(),
            path: DecisionPath::Resolution,
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            version: None,
            action: action.to_owned(),
            removed,
            checks,
            exceptions_used: Vec::new(),
            unenforceable: unenforceable.iter().map(|u| u.check.as_str().to_owned()).collect(),
            intel_snapshot: None,
        }
    }
}

/// The checks that decided against the package, strongest first.
///
/// Taken from the `Decision` rather than from the refusal message, so the machine-readable
/// record and the text the client reads cannot drift apart.
fn decided_against(decision: &Decision) -> Vec<String> {
    decision
        .reasons()
        .iter()
        .map(|r| r.check.as_str().to_owned())
        .collect()
}

/// Whether a check let the package through only because an exception applied.
pub fn excepted(decision: &Decision) -> bool {
    decision
        .results
        .iter()
        .any(|r| matches!(r.outcome, Outcome::Excepted { .. }))
}

fn now() -> String {
    jiff::Timestamp::now().to_string()
}

/// Every package version the log names, oldest first, without duplicates.
///
/// The package set `policy diff` re-decides. A `pinned` line names one version. A
/// `resolution` line names every version it removed, so one request can contribute many.
/// Versions that were offered and not removed are not in the log at all: a resolution line
/// records what the policy acted on, not the whole document.
pub fn packages(log: &str) -> Vec<(String, String, String)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in log.lines().filter(|l| !l.trim().is_empty()) {
        // A line that will not parse is skipped rather than failing the run. A log with a
        // torn last write is the ordinary case after a crash.
        let Ok(event) = serde_json::from_str::<Event>(line) else {
            continue;
        };
        let versions = event
            .version
            .into_iter()
            .chain(event.removed)
            .collect::<Vec<_>>();
        for version in versions {
            let key = (event.ecosystem.clone(), event.name.clone(), version);
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
    }
    out
}

/// The audit log, when one is configured.
#[derive(Debug)]
pub struct AuditLog {
    file: Mutex<File>,
    /// So an unwritable log warns once rather than once per package.
    warned: AtomicBool,
}

impl AuditLog {
    /// Open for appending, creating it if it is not there.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(OpenOptions::new().create(true).append(true).open(path)?),
            warned: AtomicBool::new(false),
        })
    }

    /// Append one event. Failure is warned about once and otherwise ignored.
    pub fn write(&self, event: &Event) {
        let Ok(mut line) = serde_json::to_vec(event) else {
            self.warn_once("audit event could not be serialised");
            return;
        };
        line.push(b'\n');

        let mut file = match self.file.lock() {
            Ok(file) => file,
            Err(poisoned) => poisoned.into_inner(),
        };
        if file.write_all(&line).is_err() {
            self.warn_once("audit log could not be written");
        }
    }

    fn warn_once(&self, message: &str) {
        if !self.warned.swap(true, Ordering::Relaxed) {
            warn!("{message}; the audit log is incomplete from here on");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::policy::decide::{Facts, Intel, decide};

    fn facts() -> Facts {
        Facts {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.21".to_owned(),
            published: Some(jiff::civil::date(2021, 2, 20)),
            known_malware: false,
            advisories: Vec::new(),
            has_install_scripts: false,
            intel: Intel::NotConsulted,
        }
    }

    fn decision(yaml: &str) -> Decision {
        let policy = Policy::parse(yaml).expect("policy should load");
        decide(&policy, &facts(), jiff::civil::date(2026, 9, 13))
    }

    fn field<'a>(json: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        &json[name]
    }

    fn line(event: &Event) -> serde_json::Value {
        serde_json::to_value(event).expect("an event serialises")
    }

    #[test]
    fn a_clean_package_records_an_allow_with_nothing_against_it() {
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[]);
        let json = line(&event);

        assert_eq!(field(&json, "action"), "allow");
        assert_eq!(field(&json, "path"), "pinned");
        assert_eq!(field(&json, "name"), "lodash");
        assert_eq!(field(&json, "version"), "4.17.21");
        // Empty collections are left out rather than written as `[]`.
        assert!(json.get("checks").is_none());
        assert!(json.get("removed").is_none());
    }

    #[test]
    fn a_refusal_records_the_check_that_fired() {
        let event = Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decision(
                "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            ),
            &[],
        );
        let json = line(&event);

        assert_eq!(field(&json, "action"), "block");
        assert_eq!(field(&json, "checks"), &serde_json::json!(["denials"]));
    }

    /// The strongest reason leads, the same order the refusal body uses.
    #[test]
    fn two_checks_firing_are_recorded_strongest_first() {
        let event = Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decision(
                "version: 1\ncooldown_days: 3650\n\
                 denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            ),
            &[],
        );
        let json = line(&event);

        assert_eq!(field(&json, "action"), "block");
        assert_eq!(
            field(&json, "checks"),
            &serde_json::json!(["denials", "cooldown_days"])
        );
    }

    /// An unenforced check must not read as a passed one.
    #[test]
    fn a_check_that_could_not_be_answered_is_named() {
        let unenforceable = [Unenforceable {
            check: crate::policy::decide::Check::CooldownDays,
            why: "the abbreviated packument carries no publish times",
        }];
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &unenforceable);

        assert_eq!(
            field(&line(&event), "unenforceable"),
            &serde_json::json!(["cooldown_days"])
        );
    }

    /// The engine alone quarantines this, and the proxy serves it because the check is
    /// unenforced. The line records what the proxy did.
    #[test]
    fn an_unenforced_check_is_not_in_the_recorded_action() {
        let unenforceable = [Unenforceable {
            check: crate::policy::decide::Check::CooldownDays,
            why: "the abbreviated packument carries no publish times",
        }];
        let young = decision("version: 1\ncooldown_days: 36500");
        assert_eq!(young.action(), crate::policy::Action::Quarantine);

        let json = line(&Event::pinned("npm", "lodash", "4.17.21", &young, &unenforceable));
        assert_eq!(field(&json, "action"), "allow");
        assert!(json.get("checks").is_none_or(|c| c == &serde_json::json!([])), "{json}");
    }

    #[test]
    fn a_resolution_event_names_the_versions_it_removed_and_carries_no_single_version() {
        let event = Event::resolution(
            "npm",
            "ms",
            "quarantine",
            vec!["2.1.3".to_owned(), "2.1.2".to_owned()],
            vec!["cooldown_days".to_owned()],
            &[],
        );
        let json = line(&event);

        assert_eq!(field(&json, "path"), "resolution");
        assert_eq!(field(&json, "removed"), &serde_json::json!(["2.1.3", "2.1.2"]));
        assert_eq!(field(&json, "checks"), &serde_json::json!(["cooldown_days"]));
        assert!(json.get("version").is_none(), "a resolution decides many");
    }

    /// With no store consulted, the field is absent rather than invented.
    #[test]
    fn the_intel_snapshot_is_absent_rather_than_invented() {
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[]);

        assert_eq!(event.intel_snapshot, None);
        assert!(line(&event).get("intel_snapshot").is_none());
    }

    #[test]
    fn a_consulted_snapshot_is_recorded() {
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[])
            .with_intel_snapshot(Some("sha256:abc"));

        assert_eq!(field(&line(&event), "intel_snapshot"), "sha256:abc");
    }

    #[test]
    fn the_timestamp_is_utc_and_round_trips() {
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[]);

        assert!(event.at.ends_with('Z'), "{}", event.at);
        assert!(event.at.parse::<jiff::Timestamp>().is_ok(), "{}", event.at);
    }

    /// `cooldown_days` is deliberately not the check used here: it reports `Failed` even
    /// when an exception shortened the wait, because the exception applied and the package
    /// is still too young.
    #[test]
    fn an_exception_that_did_work_is_recorded() {
        let policy = Policy::parse(
            "version: 1\ncooldown_days: 0\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    permanent: true\n",
        )
        .expect("policy should load");
        let facts = Facts {
            has_install_scripts: true,
            intel: Intel::NotConsulted,
            ..facts()
        };
        let decision = decide(&policy, &facts, jiff::civil::date(2026, 9, 13));
        let json = line(&Event::pinned("npm", "lodash", "4.17.21", &decision, &[]));

        assert_eq!(field(&json, "action"), "allow");
        assert_eq!(field(&json, "exceptions_used"), &serde_json::json!([0]));
        assert!(excepted(&decision), "the exception is what let it through");
    }

    #[test]
    fn the_package_set_takes_one_version_from_a_pinned_line_and_many_from_a_resolution() {
        let log = "\
{\"at\":\"\",\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\",\"action\":\"block\"}
{\"at\":\"\",\"path\":\"resolution\",\"ecosystem\":\"npm\",\"name\":\"b\",\"action\":\"block\",\"removed\":[\"2.0.0\",\"2.0.1\"]}
";

        assert_eq!(
            packages(log),
            [
                ("npm".to_owned(), "a".to_owned(), "1.0.0".to_owned()),
                ("npm".to_owned(), "b".to_owned(), "2.0.0".to_owned()),
                ("npm".to_owned(), "b".to_owned(), "2.0.1".to_owned()),
            ]
        );
    }

    #[test]
    fn the_same_version_seen_twice_appears_once() {
        let line = "{\"at\":\"\",\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\",\"action\":\"allow\"}";

        assert_eq!(packages(&format!("{line}\n{line}\n")).len(), 1);
    }

    /// A torn last write is the ordinary case after a crash, so it is skipped rather than
    /// failing the run.
    #[test]
    fn an_unparseable_line_is_skipped_and_the_rest_still_read() {
        let log = "\
not json
{\"at\":\"\",\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\",\"action\":\"allow\"}
{\"truncated\":
";

        assert_eq!(packages(log).len(), 1);
    }

    /// A line written before a field existed still reads.
    #[test]
    fn a_line_missing_a_field_this_build_knows_about_still_reads() {
        let log = "{\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\"}";

        assert_eq!(packages(log).len(), 1);
    }

    #[test]
    fn an_empty_log_yields_no_packages() {
        assert!(packages("").is_empty());
        assert!(packages("\n\n").is_empty());
    }

    #[test]
    fn every_line_is_one_json_object_and_ends_with_a_newline() {
        let dir = tempdir();
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).expect("should open");

        log.write(&Event::pinned("npm", "a", "1.0.0", &decision("version: 1"), &[]));
        log.write(&Event::pinned("npm", "b", "2.0.0", &decision("version: 1"), &[]));

        let written = std::fs::read_to_string(&path).expect("should read");
        assert!(written.ends_with('\n'));
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each line is one object");
        }
    }

    #[test]
    fn opening_an_existing_log_appends_rather_than_truncates() {
        let dir = tempdir();
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, "{\"kept\":true}\n").expect("should write");

        AuditLog::open(&path)
            .expect("should open")
            .write(&Event::pinned("npm", "a", "1.0.0", &decision("version: 1"), &[]));

        let written = std::fs::read_to_string(&path).expect("should read");
        assert_eq!(written.lines().count(), 2);
        assert!(written.starts_with("{\"kept\":true}"));
    }

    #[test]
    fn a_path_that_cannot_be_opened_is_an_error_rather_than_a_panic() {
        let dir = tempdir();
        assert!(AuditLog::open(&dir.join("no-such-dir").join("audit.jsonl")).is_err());
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "waharoa-audit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("should create");
        dir
    }
}
