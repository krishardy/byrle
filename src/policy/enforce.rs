//! Where a decision becomes a response.
//!
//! Decision #4 splits enforcement in two, and the split is not a detail:
//!
//! - **On resolution**, a refused version is filtered out of the metadata so the
//!   resolver picks a clean one by itself. The client sees a 200 with fewer versions.
//! - **On a pinned fetch**, there is nothing to resolve. The client already decided, from
//!   a lockfile, and the only honest answer is a refusal.
//!
//! This module is the pinned half. A tarball request names one version, the record for it
//! is already in the store because the digest had to be known before the fetch, so the
//! engine can be asked and answered before a byte leaves upstream.
//!
//! # Why `quarantine` refuses here too
//!
//! Quarantine means "refused now, allowed later". On the resolution path that is a
//! filter and the install succeeds on another version. On a pinned fetch there is no
//! other version to pick, so it refuses like a block, and says when it lapses. The
//! difference survives in what the client is told, not in whether it gets bytes.

use super::decide::{Check, Decision, Outcome};
use super::{Action, Policy};
use crate::policy::decide::{Facts, decide};
use crate::record::PackageRecord;
use jiff::civil::Date;

/// What the proxy does with an artifact request.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Fetch it.
    Serve,
    /// Refuse it, and say why.
    Refuse(Refusal),
}

/// A refusal, in the words the client is given.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub action: Action,
    /// The purl, as the policy would spell it.
    pub purl: String,
    /// One line per check that decided against the package, strongest first.
    pub reasons: Vec<String>,
}

impl Refusal {
    /// The body the client reads. npm shows it on a failed install.
    pub fn message(&self) -> String {
        let mut out = format!(
            "waharoa: {} is {} by policy\n",
            self.purl,
            match self.action {
                Action::Block => "blocked",
                Action::Quarantine => "held",
                // `Verdict::Refuse` is only built from a non-allow action.
                Action::Allow => "allowed",
            }
        );
        for reason in &self.reasons {
            out.push_str("  - ");
            out.push_str(reason);
            out.push('\n');
        }
        out
    }
}

/// Decide a pinned artifact request.
///
/// `None` for the policy is Stage 1 behaviour: nothing is enforced and everything
/// serves. That is a distinct state from a policy that allows everything, and the log
/// should be able to tell them apart.
pub fn artifact(policy: Option<&Policy>, record: &PackageRecord, today: Date) -> Verdict {
    let Some(policy) = policy else {
        return Verdict::Serve;
    };
    let facts = Facts::from_record(record);
    let decision = decide(policy, &facts, today);
    verdict(&facts, &decision)
}

fn verdict(facts: &Facts, decision: &Decision) -> Verdict {
    let action = decision.action();
    if action == Action::Allow {
        return Verdict::Serve;
    }
    Verdict::Refuse(Refusal {
        action,
        purl: format!(
            "pkg:{}/{}@{}",
            facts.ecosystem, facts.name, facts.version
        ),
        reasons: decision.reasons().iter().map(|r| reason(r)).collect(),
    })
}

/// One check's answer, in a line a person can act on.
fn reason(result: &super::decide::Result) -> String {
    let name = result.check.as_str();
    match (&result.check, &result.outcome) {
        (Check::Denials, _) => format!("{name}: this exact version is denied"),
        (Check::KnownMalware, _) => format!("{name}: reported as malware"),
        (Check::CooldownDays, _) => {
            format!("{name}: published too recently, and this lapses as it ages")
        }
        (_, Outcome::Failed(action)) => format!("{name}: {}", action.as_str()),
        // A check that passed or was excepted is not a reason, so this is unreachable
        // through `reasons()`. Rendered rather than panicked on: a wrong line in an error
        // body is better than a crash in the refusal path.
        (_, outcome) => format!("{name}: {outcome:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npm::normalize_packument;
    use crate::record::PackumentDetail;

    const TODAY: Date = jiff::civil::date(2026, 9, 13);

    fn record() -> PackageRecord {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/lodash-4.17.21.full.json"
        );
        normalize_packument(
            &std::fs::read(path).expect("fixture is missing"),
            PackumentDetail::Full,
        )
        .expect("fixture should normalise")
        .version("4.17.21")
        .expect("version is in the fixture")
        .clone()
    }

    fn loaded(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    #[test]
    fn no_policy_at_all_serves_everything() {
        assert_eq!(artifact(None, &record(), TODAY), Verdict::Serve);
    }

    #[test]
    fn a_policy_that_denies_nothing_serves() {
        let policy = loaded("version: 1\ncooldown_days: 0\n");

        assert_eq!(artifact(Some(&policy), &record(), TODAY), Verdict::Serve);
    }

    #[test]
    fn a_denied_version_is_refused_and_the_reason_names_the_check() {
        let policy = loaded(
            "version: 1\ncooldown_days: 0\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
        );

        let Verdict::Refuse(refusal) = artifact(Some(&policy), &record(), TODAY) else {
            panic!("a denied version must be refused");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.purl, "pkg:npm/lodash@4.17.21");
        assert_eq!(refusal.reasons, ["denials: this exact version is denied"]);
        assert_eq!(
            refusal.message(),
            "waharoa: pkg:npm/lodash@4.17.21 is blocked by policy\n  \
             - denials: this exact version is denied\n"
        );
    }

    #[test]
    fn denying_a_different_version_of_the_same_package_does_not_refuse() {
        let policy = loaded(
            "version: 1\ncooldown_days: 0\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.20\n    reason: test\n",
        );

        assert_eq!(artifact(Some(&policy), &record(), TODAY), Verdict::Serve);
    }

    #[test]
    fn a_package_with_install_scripts_is_refused_when_the_policy_says_block() {
        let mut r = record();
        r.has_install_scripts = true;
        let policy = loaded("version: 1\ncooldown_days: 0\ninstall_scripts: block\n");

        let Verdict::Refuse(refusal) = artifact(Some(&policy), &r, TODAY) else {
            panic!("install scripts must be refused when the policy blocks them");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons, ["install_scripts: block"]);

        // The same package passes when the policy allows them.
        let allowing = loaded("version: 1\ncooldown_days: 0\ninstall_scripts: allow\n");
        assert_eq!(artifact(Some(&allowing), &r, TODAY), Verdict::Serve);
    }

    /// A pinned fetch has no other version to fall back to, so quarantine refuses. What
    /// separates it from a block is what the client is told.
    #[test]
    fn quarantine_refuses_on_a_pinned_fetch_and_says_it_lapses() {
        let mut r = record();
        r.published_at = Some(
            "2026-09-12T00:00:00Z"
                .parse()
                .expect("timestamp should parse"),
        );
        let policy = loaded("version: 1\ncooldown_days: 30\n");

        let Verdict::Refuse(refusal) = artifact(Some(&policy), &r, TODAY) else {
            panic!("a version inside the cooldown must be refused on a pinned fetch");
        };
        assert_eq!(refusal.action, Action::Quarantine);
        assert!(
            refusal.message().starts_with(
                "waharoa: pkg:npm/lodash@4.17.21 is held by policy"
            ),
            "held, not blocked: {}",
            refusal.message()
        );
        assert!(refusal.reasons[0].contains("lapses as it ages"));
    }

    /// The lattice decides, so the strongest reason leads.
    #[test]
    fn a_block_and_a_quarantine_together_refuse_as_a_block() {
        let mut r = record();
        r.published_at = Some(
            "2026-09-12T00:00:00Z"
                .parse()
                .expect("timestamp should parse"),
        );
        let policy = loaded(
            "version: 1\ncooldown_days: 30\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: test\n",
        );

        let Verdict::Refuse(refusal) = artifact(Some(&policy), &r, TODAY) else {
            panic!("must refuse");
        };
        assert_eq!(refusal.action, Action::Block);
        assert_eq!(refusal.reasons.len(), 2);
        assert!(
            refusal.reasons[0].starts_with("denials:"),
            "the block leads: {:?}",
            refusal.reasons
        );
    }

    #[test]
    fn a_scoped_package_is_refused_under_the_name_the_policy_spells() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/npm/@babel_traverse-8.0.5.full.json"
        );
        let r = normalize_packument(
            &std::fs::read(path).expect("fixture is missing"),
            PackumentDetail::Full,
        )
        .expect("fixture should normalise")
        .version("8.0.5")
        .expect("version is in the fixture")
        .clone();

        // Both spellings of the same package. `%40` is what this codebase's own `Display`
        // emits for a scoped name, and what OSV uses.
        for spelling in [
            "pkg:npm/%40babel/traverse@8.0.5",
            "pkg:npm/@babel/traverse@8.0.5",
        ] {
            let policy = loaded(&format!(
                "version: 1\ncooldown_days: 0\n\
                 denials:\n  - purl: {spelling}\n    reason: test\n"
            ));

            let Verdict::Refuse(refusal) = artifact(Some(&policy), &r, TODAY) else {
                panic!("a scoped package must be refusable, written as `{spelling}`");
            };
            assert_eq!(refusal.purl, "pkg:npm/@babel/traverse@8.0.5");
        }
    }
}
