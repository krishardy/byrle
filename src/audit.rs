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

use crate::policy::decide::{Advisory, Decision, Facts, Intel, Outcome, Provenance};
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

/// What a pinned request was answered. The policy's action is one input to it; a deferral
/// or a digest mismatch answers a request the policy would have served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Answered {
    /// The artifact was fetched for the client.
    Served,
    /// Refused: by the policy, or because its origin is not served.
    Refused,
    /// 503 while the artifact is analysed. The retry is audited again.
    Deferred,
    /// 502: the upstream's last bytes for it did not match their digest.
    UpstreamMismatch,
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
    /// What the request was answered. Pinned events only; absent on a line written before
    /// it was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered: Option<Answered>,
    /// Everything the engine read to reach the verdict, so `waharoa audit verify` can reach
    /// it again. Pinned events only; absent on a line written before it was recorded. See
    /// `docs/engineering_decisions/reproducible-verdicts.md`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Inputs>,
}

/// What a pinned verdict was decided on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inputs {
    /// The day the engine decided as of, `YYYY-MM-DD`, UTC. Not read from `at`: a cooldown
    /// and an expiry are decided on this date.
    pub as_of: String,
    /// [`crate::policy::Policy::digest`] of the policy in force.
    pub policy_digest: String,
    /// The build's version. `0.1.0` on every commit until releases are versioned, so a
    /// replay reports a difference rather than failing on it.
    pub build: String,
    /// The reader and verifier whose stored results the facts were built from:
    /// [`crate::analysis::READER`] and
    /// [`crate::analysis::attestation::verifier_id`].
    pub reader: String,
    pub verifier: String,
    pub facts: RecordedFacts,
}

impl Inputs {
    /// What this build decides `facts` on under `policy` as of `as_of`.
    pub fn of(policy: &crate::policy::Policy, facts: &Facts, as_of: jiff::civil::Date) -> Self {
        Self {
            as_of: as_of.to_string(),
            policy_digest: policy.digest.clone(),
            build: env!("CARGO_PKG_VERSION").to_owned(),
            reader: crate::analysis::READER.to_owned(),
            verifier: crate::analysis::attestation::verifier_id().to_owned(),
            facts: RecordedFacts::of(facts),
        }
    }
}

/// [`Facts`] as the audit log writes them. The advisories are written out rather than
/// named by snapshot: a kept snapshot is optional and pruned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedFacts {
    pub published: Option<String>,
    pub known_malware: bool,
    pub advisories: Vec<RecordedAdvisory>,
    /// `consulted`, `consulted-without-exploitation` or `not-consulted`.
    pub intel: String,
    pub has_install_scripts: bool,
    pub yanked: Option<String>,
    pub deprecated: Option<String>,
    pub provenance: RecordedProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedAdvisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub cvss: Option<f64>,
    pub band: Option<String>,
    pub kev: bool,
    pub sources: Vec<String>,
}

/// [`Provenance`], with the reason an unknown one gives kept as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RecordedProvenance {
    Unknown {
        why: String,
    },
    Consistent,
    Unverified {
        why: String,
    },
    Dropped {
        previous: String,
    },
    IdentityChanged {
        previous: String,
        from: String,
        to: String,
    },
}

impl RecordedFacts {
    pub fn of(facts: &Facts) -> Self {
        Self {
            published: facts.published.map(|d| d.to_string()),
            known_malware: facts.known_malware,
            advisories: facts
                .advisories
                .iter()
                .map(|a| RecordedAdvisory {
                    id: a.id.clone(),
                    aliases: a.aliases.clone(),
                    cvss: a.cvss,
                    band: a.band.clone(),
                    kev: a.kev,
                    sources: a.sources.clone(),
                })
                .collect(),
            intel: match facts.intel {
                Intel::Consulted {
                    exploitation_loaded: true,
                } => "consulted",
                Intel::Consulted {
                    exploitation_loaded: false,
                } => "consulted-without-exploitation",
                Intel::NotConsulted => "not-consulted",
            }
            .to_owned(),
            has_install_scripts: facts.has_install_scripts,
            yanked: facts.yanked.clone(),
            deprecated: facts.deprecated.clone(),
            provenance: match &facts.provenance {
                Provenance::Unknown(why) => RecordedProvenance::Unknown {
                    why: (*why).to_owned(),
                },
                Provenance::Consistent => RecordedProvenance::Consistent,
                Provenance::Unverified { why } => {
                    RecordedProvenance::Unverified { why: why.clone() }
                }
                Provenance::Dropped { previous } => RecordedProvenance::Dropped {
                    previous: previous.clone(),
                },
                Provenance::IdentityChanged { previous, from, to } => {
                    RecordedProvenance::IdentityChanged {
                        previous: previous.clone(),
                        from: from.clone(),
                        to: to.clone(),
                    }
                }
            },
        }
    }

    /// The facts again, for the package the event names. `None` when a value does not
    /// read: a date that is not one, or an intel state no build writes.
    pub fn facts(&self, ecosystem: &str, name: &str, version: &str) -> Option<Facts> {
        let published = match &self.published {
            Some(date) => Some(date.parse().ok()?),
            None => None,
        };
        let intel = match self.intel.as_str() {
            "consulted" => Intel::Consulted {
                exploitation_loaded: true,
            },
            "consulted-without-exploitation" => Intel::Consulted {
                exploitation_loaded: false,
            },
            "not-consulted" => Intel::NotConsulted,
            _ => return None,
        };
        Some(Facts {
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            published,
            known_malware: self.known_malware,
            advisories: self
                .advisories
                .iter()
                .map(|a| Advisory {
                    id: a.id.clone(),
                    aliases: a.aliases.clone(),
                    cvss: a.cvss,
                    band: a.band.clone(),
                    kev: a.kev,
                    sources: a.sources.clone(),
                })
                .collect(),
            intel,
            has_install_scripts: self.has_install_scripts,
            yanked: self.yanked.clone(),
            deprecated: self.deprecated.clone(),
            provenance: match &self.provenance {
                // The reason is text in the log; the engine decides an unknown one the same
                // whatever it says.
                RecordedProvenance::Unknown { .. } => Provenance::Unknown("recorded as unknown"),
                RecordedProvenance::Consistent => Provenance::Consistent,
                RecordedProvenance::Unverified { why } => {
                    Provenance::Unverified { why: why.clone() }
                }
                RecordedProvenance::Dropped { previous } => Provenance::Dropped {
                    previous: previous.clone(),
                },
                RecordedProvenance::IdentityChanged { previous, from, to } => {
                    Provenance::IdentityChanged {
                        previous: previous.clone(),
                        from: from.clone(),
                        to: to.clone(),
                    }
                }
            },
        })
    }
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
            answered: None,
            inputs: None,
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
            unenforceable: unenforceable
                .iter()
                .map(|u| u.check.as_str().to_owned())
                .collect(),
            intel_snapshot: None,
            answered: None,
            inputs: None,
        }
    }

    /// Record what the verdict was decided on.
    pub fn with_inputs(mut self, inputs: Inputs) -> Self {
        self.inputs = Some(inputs);
        self
    }

    /// Say what the request was answered.
    pub fn answered(mut self, answered: Answered) -> Self {
        self.answered = Some(answered);
        self
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
            unenforceable: unenforceable
                .iter()
                .map(|u| u.check.as_str().to_owned())
                .collect(),
            intel_snapshot: None,
            answered: None,
            inputs: None,
        }
    }
}

/// What re-deciding every pinned line of an audit log found. See `waharoa audit verify`
/// and `docs/engineering_decisions/reproducible-verdicts.md`.
#[derive(Debug, Default, PartialEq)]
pub struct Replay {
    /// Pinned lines decided again to the same action, checks, exceptions and unenforced
    /// checks.
    pub reproduced: usize,
    /// Line number, and what differs.
    pub differ: Vec<(usize, String)>,
    /// Line number, and why it could not be decided again.
    pub not_replayable: Vec<(usize, String)>,
    /// Reproduced or not, lines another build wrote.
    pub other_build: usize,
}

impl Replay {
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (line, what) in &self.differ {
            out.push_str(&format!("line {line}: differs: {what}\n"));
        }
        for (line, why) in &self.not_replayable {
            out.push_str(&format!("line {line}: not replayable: {why}\n"));
        }
        out.push_str(&format!(
            "{} reproduced, {} differ, {} not replayable",
            self.reproduced,
            self.differ.len(),
            self.not_replayable.len()
        ));
        if self.other_build > 0 {
            out.push_str(&format!(
                "; {} written by another build than {}",
                self.other_build,
                env!("CARGO_PKG_VERSION")
            ));
        }
        out.push('\n');
        out
    }
}

/// What `waharoa audit verify` prints, and its exit code.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// For stderr: why nothing was replayed.
    pub notes: Vec<String>,
    pub report: String,
    /// 0 when every replayable line reproduced, 1 when one differs, 2 when a policy or the
    /// log does not read.
    pub code: u8,
}

/// `waharoa audit verify`: load `policies`, then [`replay`] the log at `log`.
pub fn verify(log: &std::path::Path, policies: &[std::path::PathBuf]) -> Verified {
    let unread = |note: String| Verified {
        notes: vec![note],
        report: String::new(),
        code: 2,
    };
    let mut loaded = Vec::new();
    for path in policies {
        match crate::policy::Policy::load(path) {
            Ok(policy) => loaded.push(policy),
            Err(e) => return unread(e.to_string()),
        }
    }
    let source = match std::fs::read_to_string(log) {
        Ok(source) => source,
        Err(e) => return unread(format!("{}: {e}", log.display())),
    };
    let replayed = replay(&source, &loaded);
    Verified {
        notes: Vec::new(),
        report: replayed.render(),
        code: u8::from(!replayed.differ.is_empty()),
    }
}

/// Decide every pinned line of `log` again from what it recorded, under whichever of
/// `policies` has the digest it names, as of the date it names.
pub fn replay(log: &str, policies: &[crate::policy::Policy]) -> Replay {
    let mut out = Replay::default();
    for (i, line) in log
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let number = i + 1;
        let mut not = |why: String| out.not_replayable.push((number, why));
        let Ok(event) = serde_json::from_str::<Event>(line) else {
            not("not an audit line".to_owned());
            continue;
        };
        if event.path != DecisionPath::Pinned {
            continue;
        }
        let Some(inputs) = &event.inputs else {
            not("written before inputs were recorded".to_owned());
            continue;
        };
        let Some(policy) = policies.iter().find(|p| p.digest == inputs.policy_digest) else {
            not(format!(
                "no policy given has digest {}",
                inputs.policy_digest
            ));
            continue;
        };
        let version = event.version.as_deref().unwrap_or("");
        let (Ok(as_of), Some(facts)) = (
            inputs.as_of.parse::<jiff::civil::Date>(),
            inputs.facts.facts(&event.ecosystem, &event.name, version),
        ) else {
            not("its recorded inputs do not read".to_owned());
            continue;
        };
        if inputs.build != env!("CARGO_PKG_VERSION") {
            out.other_build += 1;
        }
        let again = Event::pinned(
            &event.ecosystem,
            &event.name,
            version,
            &crate::policy::decide::decide(policy, &facts, as_of),
            &crate::policy::enforce::unenforceable_of(policy, &facts),
        );
        let mut differences = Vec::new();
        let mut compare = |field: &str, recorded: String, now: String| {
            if recorded != now {
                differences.push(format!("{field} {recorded} now {now}"));
            }
        };
        compare("action", event.action.clone(), again.action);
        compare(
            "checks",
            format!("{:?}", event.checks),
            format!("{:?}", again.checks),
        );
        compare(
            "exceptions_used",
            format!("{:?}", event.exceptions_used),
            format!("{:?}", again.exceptions_used),
        );
        compare(
            "unenforceable",
            format!("{:?}", event.unenforceable),
            format!("{:?}", again.unenforceable),
        );
        if differences.is_empty() {
            out.reproduced += 1;
        } else {
            out.differ.push((
                number,
                format!(
                    "pkg:{}/{}@{version}: {}",
                    event.ecosystem,
                    event.name,
                    differences.join("; ")
                ),
            ));
        }
    }
    out
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
    use crate::util::test_support::tempdir;

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
            intel: Intel::NotConsulted,
            provenance: crate::policy::decide::Provenance::Consistent,
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
            &decision("version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n"),
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
        let event = Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decision("version: 1"),
            &unenforceable,
        );

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

        let json = line(&Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &young,
            &unenforceable,
        ));
        assert_eq!(field(&json, "action"), "allow");
        assert!(
            json.get("checks")
                .is_none_or(|c| c == &serde_json::json!([])),
            "{json}"
        );
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
        assert_eq!(
            field(&json, "removed"),
            &serde_json::json!(["2.1.3", "2.1.2"])
        );
        assert_eq!(
            field(&json, "checks"),
            &serde_json::json!(["cooldown_days"])
        );
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
            yanked: None,
            deprecated: None,
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
        let log =
            "{\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\"}";

        assert_eq!(packages(log).len(), 1);
    }

    #[test]
    fn an_empty_log_yields_no_packages() {
        assert!(packages("").is_empty());
        assert!(packages("\n\n").is_empty());
    }

    #[test]
    fn every_line_is_one_json_object_and_ends_with_a_newline() {
        let dir = tempdir("audit-lines");
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).expect("should open");

        log.write(&Event::pinned(
            "npm",
            "a",
            "1.0.0",
            &decision("version: 1"),
            &[],
        ));
        log.write(&Event::pinned(
            "npm",
            "b",
            "2.0.0",
            &decision("version: 1"),
            &[],
        ));

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
        let dir = tempdir("audit-append");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, "{\"kept\":true}\n").expect("should write");

        AuditLog::open(&path)
            .expect("should open")
            .write(&Event::pinned(
                "npm",
                "a",
                "1.0.0",
                &decision("version: 1"),
                &[],
            ));

        let written = std::fs::read_to_string(&path).expect("should read");
        assert_eq!(written.lines().count(), 2);
        assert!(written.starts_with("{\"kept\":true}"));
    }

    #[test]
    fn a_path_that_cannot_be_opened_is_an_error_rather_than_a_panic() {
        let dir = tempdir("audit-unopenable");
        assert!(AuditLog::open(&dir.join("no-such-dir").join("audit.jsonl")).is_err());
    }

    const REPLAYED: &str = "version: 1\ncooldown_days: 0\nmax_cvss: 7.0\n";

    fn advisory(id: &str, cvss: f64) -> Advisory {
        Advisory {
            id: id.to_owned(),
            aliases: vec![format!("{id}-alias")],
            cvss: Some(cvss),
            band: None,
            kev: false,
            sources: vec!["osv".to_owned()],
        }
    }

    fn refused_facts() -> Facts {
        Facts {
            advisories: vec![advisory("GHSA-1", 9.8), advisory("GHSA-2", 8.1)],
            intel: Intel::Consulted {
                exploitation_loaded: true,
            },
            ..facts()
        }
    }

    /// A pinned line as the proxy writes one.
    fn recorded(policy: &Policy, facts: &Facts) -> String {
        let as_of = jiff::civil::date(2026, 9, 13);
        let event = Event::pinned(
            &facts.ecosystem,
            &facts.name,
            &facts.version,
            &decide(policy, facts, as_of),
            &crate::policy::enforce::unenforceable_of(policy, facts),
        )
        .with_inputs(Inputs::of(policy, facts, as_of));
        serde_json::to_string(&event).expect("an event serialises")
    }

    fn policy(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    #[test]
    fn a_pinned_line_decides_the_same_again() {
        let policy = policy(REPLAYED);
        let log = recorded(&policy, &refused_facts());

        assert!(log.contains("\"action\":\"block\""), "{log}");
        assert_eq!(
            replay(&log, &[policy]),
            Replay {
                reproduced: 1,
                ..Replay::default()
            }
        );
    }

    #[test]
    fn a_line_that_decides_differently_is_reported_with_what_differs() {
        let policy = policy(REPLAYED);
        let log = recorded(&policy, &refused_facts())
            .replace("\"action\":\"block\"", "\"action\":\"allow\"");

        let replay = replay(&log, &[policy]);

        assert_eq!(replay.reproduced, 0);
        assert_eq!(
            replay.differ,
            [(
                1,
                "pkg:npm/lodash@4.17.21: action allow now block".to_owned()
            )]
        );
    }

    #[test]
    fn each_recorded_field_is_compared() {
        let policy = policy(
            "version: 1\ncooldown_days: 7\nmax_cvss: 7.0\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { vuln_advisory_ids: [GHSA-1, GHSA-2] }\n    reason: t\n    permanent: true\n",
        );
        let facts = Facts {
            published: None,
            ..refused_facts()
        };
        let log = recorded(&policy, &facts);
        let json: serde_json::Value = serde_json::from_str(&log).expect("a line");
        assert_eq!(json["exceptions_used"], serde_json::json!([0]));
        assert_eq!(json["unenforceable"], serde_json::json!(["cooldown_days"]));
        let tampered = log
            .replace("\"exceptions_used\":[0]", "\"exceptions_used\":[1]")
            .replace(
                "\"unenforceable\":[\"cooldown_days\"]",
                "\"unenforceable\":[]",
            )
            .replace(
                "\"action\":\"allow\"",
                "\"action\":\"allow\",\"checks\":[\"kev\"]",
            );

        let replay = replay(&tampered, &[policy]);

        assert_eq!(
            replay.differ,
            [(
                1,
                "pkg:npm/lodash@4.17.21: checks [\"kev\"] now []; exceptions_used [1] now [0]; \
                 unenforceable [] now [\"cooldown_days\"]"
                    .to_owned()
            )]
        );
    }

    #[test]
    fn a_line_is_decided_under_the_policy_with_its_digest() {
        let strict = policy(REPLAYED);
        let loose = policy("version: 1\ncooldown_days: 0\n");
        let log = format!(
            "{}\n{}\n",
            recorded(&strict, &refused_facts()),
            recorded(&loose, &refused_facts())
        );

        assert_eq!(replay(&log, &[loose, strict]).reproduced, 2);
    }

    #[test]
    fn a_line_that_cannot_be_decided_again_is_not_replayable_rather_than_different() {
        let policy = policy(REPLAYED);
        let good = recorded(&policy, &refused_facts());
        let log = [
            // Written before inputs were recorded: it still reads.
            "{\"at\":\"\",\"path\":\"pinned\",\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":\"1.0.0\",\"action\":\"block\"}".to_owned(),
            recorded(&crate::policy::Policy::parse("version: 1\n").expect("loads"), &facts()),
            good.replace("\"as_of\":\"2026-09-13\"", "\"as_of\":\"yesterday\""),
            good.replace("\"published\":\"2021-02-20\"", "\"published\":\"then\""),
            good.replace("\"intel\":\"consulted\"", "\"intel\":\"asked\""),
            "not json".to_owned(),
            String::new(),
            "{\"at\":\"\",\"path\":\"resolution\",\"ecosystem\":\"npm\",\"name\":\"b\",\"action\":\"block\",\"removed\":[\"2.0.0\"]}".to_owned(),
        ]
        .join("\n");

        let replay = replay(&log, &[policy]);

        let unreadable = "its recorded inputs do not read".to_owned();
        assert_eq!(
            replay,
            Replay {
                not_replayable: vec![
                    (1, "written before inputs were recorded".to_owned()),
                    (
                        2,
                        format!(
                            "no policy given has digest {}",
                            crate::policy::digest_of("version: 1\n")
                        )
                    ),
                    (3, unreadable.clone()),
                    (4, unreadable.clone()),
                    (5, unreadable),
                    (6, "not an audit line".to_owned()),
                ],
                ..Replay::default()
            }
        );
    }

    #[test]
    fn a_line_another_build_wrote_is_counted() {
        let policy = policy(REPLAYED);
        let log = recorded(&policy, &refused_facts()).replace(
            &format!("\"build\":\"{}\"", env!("CARGO_PKG_VERSION")),
            "\"build\":\"0.0.0\"",
        );

        let replay = replay(&log, &[policy]);

        assert_eq!((replay.reproduced, replay.other_build), (1, 1));
        assert_eq!(
            replay.render(),
            format!(
                "1 reproduced, 0 differ, 0 not replayable; 1 written by another build than {}\n",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn the_report_lists_each_line_then_the_counts() {
        let replay = Replay {
            reproduced: 3,
            differ: vec![(2, "pkg:npm/a@1: action allow now block".to_owned())],
            not_replayable: vec![(5, "not an audit line".to_owned())],
            other_build: 0,
        };

        assert_eq!(
            replay.render(),
            "line 2: differs: pkg:npm/a@1: action allow now block\n\
             line 5: not replayable: not an audit line\n\
             3 reproduced, 1 differ, 1 not replayable\n"
        );
    }

    #[test]
    fn every_provenance_reads_back_as_recorded() {
        let each = [
            Provenance::Consistent,
            Provenance::Unverified {
                why: "no bundle".to_owned(),
            },
            Provenance::Dropped {
                previous: "1.0.0".to_owned(),
            },
            Provenance::IdentityChanged {
                previous: "1.0.0".to_owned(),
                from: "a".to_owned(),
                to: "b".to_owned(),
            },
            Provenance::Unknown("recorded as unknown"),
        ];
        for provenance in each {
            for intel in [
                Intel::NotConsulted,
                Intel::Consulted {
                    exploitation_loaded: false,
                },
                Intel::Consulted {
                    exploitation_loaded: true,
                },
            ] {
                let facts = Facts {
                    provenance: provenance.clone(),
                    intel,
                    known_malware: true,
                    has_install_scripts: true,
                    yanked: Some("y".to_owned()),
                    deprecated: Some("d".to_owned()),
                    published: None,
                    ..refused_facts()
                };
                let json = serde_json::to_string(&RecordedFacts::of(&facts)).expect("serialises");
                let read: RecordedFacts = serde_json::from_str(&json).expect("reads");

                assert_eq!(read.facts("npm", "lodash", "4.17.21"), Some(facts));
            }
        }
    }

    /// An unknown provenance's reason is not a check's input, so it is not kept.
    #[test]
    fn an_unknown_provenance_reads_back_as_unknown() {
        let facts = Facts {
            provenance: Provenance::Unknown("the registry did not answer"),
            ..facts()
        };
        let read = RecordedFacts::of(&facts)
            .facts("npm", "lodash", "4.17.21")
            .expect("reads");

        assert_eq!(read.provenance, Provenance::Unknown("recorded as unknown"));
    }

    /// The same advisories in another order: a replay reads them in the order recorded, and
    /// the store does not promise one.
    #[test]
    fn the_order_of_the_advisories_does_not_change_the_verdict() {
        let policy = policy(
            "version: 1\ncooldown_days: 0\nmax_cvss: 7.0\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { vuln_advisory_ids: [GHSA-2] }\n    reason: t\n    permanent: true\n",
        );
        let as_of = jiff::civil::date(2026, 9, 13);
        let mut facts = refused_facts();
        let forward = Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decide(&policy, &facts, as_of),
            &[],
        );
        facts.advisories.reverse();
        let reversed = Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decide(&policy, &facts, as_of),
            &[],
        );

        assert_eq!(forward.action, "block");
        assert_eq!(
            (&forward.action, &forward.checks, &forward.exceptions_used),
            (
                &reversed.action,
                &reversed.checks,
                &reversed.exceptions_used
            )
        );
    }

    #[test]
    fn verify_exits_1_only_when_a_line_differs() {
        let dir = tempdir("audit-verify");
        let (policy_path, log_path) = (dir.join("p.yaml"), dir.join("audit.jsonl"));
        std::fs::write(&policy_path, REPLAYED).unwrap();
        let line = recorded(&policy(REPLAYED), &refused_facts());
        let run = |log: &str| {
            std::fs::write(&log_path, log).unwrap();
            verify(&log_path, std::slice::from_ref(&policy_path))
        };

        assert_eq!(
            run(&line),
            Verified {
                notes: Vec::new(),
                report: "1 reproduced, 0 differ, 0 not replayable\n".to_owned(),
                code: 0,
            }
        );
        assert_eq!(run("not json").code, 0);
        let differs = run(&line.replace("\"action\":\"block\"", "\"action\":\"allow\""));
        assert_eq!(differs.code, 1);
        assert!(
            differs.report.starts_with("line 1: differs: "),
            "{}",
            differs.report
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_exits_2_when_a_policy_or_the_log_does_not_read() {
        let dir = tempdir("audit-verify-unread");
        let (policy_path, log_path) = (dir.join("p.yaml"), dir.join("audit.jsonl"));
        std::fs::write(&policy_path, REPLAYED).unwrap();

        let no_log = verify(&log_path, std::slice::from_ref(&policy_path));
        let no_policy = verify(&log_path, &[dir.join("missing.yaml")]);

        assert_eq!((no_log.code, no_policy.code), (2, 2));
        assert!(no_log.notes[0].starts_with(&log_path.display().to_string()));
        assert!(
            no_policy.notes[0].contains("missing.yaml"),
            "{:?}",
            no_policy.notes
        );
        assert!(no_log.report.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
