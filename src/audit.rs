//! One line per policy decision, in JSON Lines.
//!
//! See docs/engineering_decisions/audit-log.md.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionPath {
    /// The packument was filtered. The client resolves against what is left.
    Resolution,
    /// One version was asked for by name and answered.
    Pinned,
}

/// What a pinned request was answered, of which the policy's action is one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Answered {
    /// The artifact was fetched for the client.
    Served,
    /// Refused by the policy.
    Refused,
    /// Refused because its origin is one the proxy does not serve.
    Unservable,
    /// Refused because its metadata publishes no strong digest.
    NoStrongDigest,
    /// Refused because its metadata names neither its version nor its file. Nothing decided.
    NotListed,
    /// 502: the registry gave no metadata for it. Nothing decided.
    NoMetadata,
    /// 503 while the artifact is analysed. The retry is audited again.
    Deferred,
    /// 502: the upstream's last bytes for it did not match their digest.
    UpstreamMismatch,
}

/// One decision, as written. A field an older build did not write reads as its default.
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
    /// `allow`, `quarantine` or `block`, the strongest on a resolution event; empty if undecided.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub action: String,
    /// Versions no longer in the document. Resolution events only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// The checks that decided against the package: strongest first if pinned, else sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<String>,
    /// Indices of the `packages` entries that did work.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exceptions_used: Vec<usize>,
    /// Checks that could not be answered, and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unenforceable: Vec<String>,
    /// Which intel the verdict was reached against. `None` when no intel store was asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_snapshot: Option<String>,
    /// What the request was answered. Pinned events only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered: Option<Answered>,
    /// Everything the engine read, so `waharoa audit verify` can decide again. Pinned only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Inputs>,
    /// The signals the detectors reported, which no verdict uses. Pinned events only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    /// The signals' risk score under the policy's `signal_weights`. Absent with no signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u32>,
}

/// What a pinned verdict was decided on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inputs {
    /// The day the engine decided as of, `YYYY-MM-DD`, UTC.
    pub as_of: String,
    /// [`crate::policy::Policy::digest`] of the policy in force.
    pub policy_digest: String,
    /// The build's version.
    pub build: String,
    /// [`crate::analysis::READER`], whose stored results the facts were built from.
    pub reader: String,
    /// [`crate::analysis::attestation::verifier_id`], whose stored results were read too.
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

/// [`Facts`] as the audit log writes them, advisories included, since snapshots are pruned.
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
            signals: Vec::new(),
            risk_score: None,
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
            signals: Vec::new(),
            risk_score: None,
        }
    }

    /// A pinned request answered before anything was decided: `answered` is
    /// [`Answered::NotListed`] or [`Answered::NoMetadata`]. `ecosystem`, `name` and
    /// `version` are the package the request named.
    pub fn undecided(ecosystem: &str, name: &str, version: &str, answered: Answered) -> Self {
        Self {
            at: now(),
            path: DecisionPath::Pinned,
            ecosystem: ecosystem.to_owned(),
            name: name.to_owned(),
            version: Some(version.to_owned()),
            answered: Some(answered),
            ..Self::default()
        }
    }

    /// Whether a policy decision is behind this line, which a replay and `policy diff` read.
    pub fn decided(&self) -> bool {
        !matches!(
            self.answered,
            Some(Answered::NotListed | Answered::NoMetadata)
        )
    }

    /// Record what the verdict was decided on.
    pub fn with_inputs(mut self, inputs: Inputs) -> Self {
        self.inputs = Some(inputs);
        self
    }

    /// Add the signals reported, and their risk score under `weights` when there is any.
    pub fn with_signals(
        mut self,
        signals: &[crate::signal::Signal],
        weights: &crate::policy::SignalWeights,
    ) -> Self {
        self.signals = signals.iter().map(ToString::to_string).collect();
        self.risk_score = (!signals.is_empty()).then(|| crate::signal::score(signals, weights));
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
            signals: Vec::new(),
            risk_score: None,
        }
    }
}

/// What re-deciding every pinned line of an audit log found.
#[derive(Debug, Default, PartialEq)]
pub struct Replay {
    /// Pinned lines decided again to the same action, checks, exceptions and unenforced checks.
    pub reproduced: usize,
    /// Line number, and what differs.
    pub differ: Vec<(usize, String)>,
    /// Line number, and why it could not be decided again.
    pub not_replayable: Vec<(usize, String)>,
    /// Reproduced or not, lines another build wrote.
    pub other_build: usize,
}

impl Replay {
    /// [`DIFFERS`] and [`NOT_REPLAYABLE`], each set when a line is.
    pub fn code(&self) -> u8 {
        let bit = |set: bool, bit: u8| if set { bit } else { 0 };
        bit(!self.differ.is_empty(), DIFFERS) | bit(!self.not_replayable.is_empty(), NOT_REPLAYABLE)
    }

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

/// Exit bit: a pinned line decides differently.
pub const DIFFERS: u8 = 1;
/// Exit bit: a pinned line could not be decided again, so it was not verified.
pub const NOT_REPLAYABLE: u8 = 2;
/// Exit code, on its own: a policy or the log does not read.
pub const UNREAD: u8 = 4;

/// What `waharoa audit verify` prints, and its exit code.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// For stderr: why nothing was replayed.
    pub notes: Vec<String>,
    pub report: String,
    /// The OR of [`DIFFERS`] and [`NOT_REPLAYABLE`], or [`UNREAD`] on its own.
    pub code: u8,
}

/// `waharoa audit verify`: load `policies`, then [`replay`] the log at `log`.
pub fn verify(log: &std::path::Path, policies: &[std::path::PathBuf]) -> Verified {
    let unread = |note: String| Verified {
        notes: vec![note],
        report: String::new(),
        code: UNREAD,
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
        code: replayed.code(),
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
        if event.path != DecisionPath::Pinned || !event.decided() {
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

/// Every package version the log names, oldest first, without duplicates: the set
/// `policy diff` decides again. A line of `log` that does not parse is skipped.
/// Returns each ecosystem, name and version.
pub fn packages(log: &str) -> Vec<(String, String, String)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in log.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(event) = serde_json::from_str::<Event>(line) else {
            continue;
        };
        if !event.decided() {
            continue;
        }
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
        let mut line = serde_json::to_vec(event).expect("an event serialises");
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
            warn!(
                waharoa.reason = message,
                "the audit log is incomplete from here on"
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    /// An exception that did work is recorded. Not tested with `cooldown_days`, which
    /// fails even when an exception shortened the wait.
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

    /// A request answered before anything was decided is written with no action, and
    /// neither a replay nor `policy diff` reads it.
    #[test]
    fn an_undecided_line_is_recorded_and_read_by_neither_replay_nor_policy_diff() {
        let line = serde_json::to_string(&Event::undecided(
            "npm",
            "widget",
            "2.0.0",
            Answered::NotListed,
        ))
        .expect("serialises");
        assert!(line.contains(r#""answered":"not-listed""#), "{line}");
        assert!(!line.contains("\"action\""), "nothing was decided: {line}");
        let policy = policy("version: 1\ncooldown_days: 0\n");
        let replayed = replay(&format!("{line}\n"), &[policy]);
        assert_eq!(
            (replayed.reproduced, replayed.not_replayable.len()),
            (0, 0),
            "skipped, not counted as unreplayable"
        );
        assert!(
            packages(&line).is_empty(),
            "not a package policy diff judges"
        );
    }

    #[test]
    fn a_line_that_cannot_be_decided_again_is_not_replayable_rather_than_different() {
        let policy = policy(REPLAYED);
        let good = recorded(&policy, &refused_facts());
        let log = [
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
    fn verify_sets_a_bit_for_a_line_that_differs_and_one_that_is_not_replayable() {
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
        assert_eq!(run("not json").code, NOT_REPLAYABLE);
        let differs = run(&line.replace("\"action\":\"block\"", "\"action\":\"allow\""));
        assert_eq!(differs.code, DIFFERS);
        let both = format!(
            "{}\nnot json\n",
            line.replace("\"action\":\"block\"", "\"action\":\"allow\"")
        );
        assert_eq!(run(&both).code, DIFFERS | NOT_REPLAYABLE);
        assert_eq!(run("").code, 0, "an empty log has nothing unverified");
        assert!(
            differs.report.starts_with("line 1: differs: "),
            "{}",
            differs.report
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_exits_4_when_a_policy_or_the_log_does_not_read() {
        let dir = tempdir("audit-verify-unread");
        let (policy_path, log_path) = (dir.join("p.yaml"), dir.join("audit.jsonl"));
        std::fs::write(&policy_path, REPLAYED).unwrap();

        let no_log = verify(&log_path, std::slice::from_ref(&policy_path));
        let no_policy = verify(&log_path, &[dir.join("missing.yaml")]);

        assert_eq!((no_log.code, no_policy.code), (UNREAD, UNREAD));
        assert!(no_log.notes[0].starts_with(&log_path.display().to_string()));
        assert!(
            no_policy.notes[0].contains("missing.yaml"),
            "{:?}",
            no_policy.notes
        );
        assert!(no_log.report.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A log that cannot be written warns once, and the proxy goes on.
    #[test]
    fn a_log_that_cannot_be_written_warns_once() {
        use crate::util::test_support::{capture, text};

        let log = AuditLog::open(Path::new("/dev/full")).expect("opens");
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[]);
        let (_guard, buf) = capture(tracing::Level::WARN);
        log.write(&event);
        log.write(&event);
        let logged = text(&buf);
        assert_eq!(
            logged
                .matches("the audit log is incomplete from here on")
                .count(),
            1,
            "{logged}"
        );
        assert!(
            logged.contains("audit log could not be written"),
            "{logged}"
        );
    }

    /// A writer that panicked holding the lock does not stop the next event.
    #[test]
    fn a_lock_a_writer_panicked_holding_is_still_used() {
        let path = crate::util::test_support::tempdir("audit-poisoned").join("audit.log");
        let log = std::sync::Arc::new(AuditLog::open(&path).expect("opens"));
        let held = log.clone();
        let _ = std::thread::spawn(move || {
            let _file = held.file.lock().unwrap();
            panic!("poisons the lock");
        })
        .join();
        assert!(log.file.is_poisoned());
        log.write(&Event::pinned(
            "npm",
            "lodash",
            "4.17.21",
            &decision("version: 1"),
            &[],
        ));
        assert_eq!(packages(&std::fs::read_to_string(&path).unwrap()).len(), 1);
    }

    /// A line with signals carries their score, and one without carries none.
    #[test]
    fn the_risk_score_is_written_only_with_signals() {
        let weights = crate::policy::SignalWeights::default();
        let event = Event::pinned("npm", "lodash", "4.17.21", &decision("version: 1"), &[]);
        assert_eq!(event.clone().with_signals(&[], &weights).risk_score, None);
        let signals = [crate::signal::Signal {
            detector: "metadata".to_owned(),
            rule: "no_repository".to_owned(),
            detail: "the metadata names none".to_owned(),
        }];
        assert_eq!(event.with_signals(&signals, &weights).risk_score, Some(1));
    }
}
