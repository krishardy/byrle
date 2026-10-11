//! `waharoa explain`: the whole decision vector, not just the verdict.
//!
//! See docs/engineering_decisions/explain-output.md.

use std::ffi::OsString;

use crate::analysis::detector::built_in;
use crate::analysis::detector::metadata::{Listing, Metadata};
use crate::ecosystem::Clients;
use crate::env::Env;
use crate::identity::PackageRef;
use crate::intel::store::Intel as IntelStore;
use crate::policy::decide::{self, Advisory, Check, Decision, Facts, Intel, Outcome};
use crate::policy::enforce::Unenforceable;
use crate::policy::{Action, AdvisoryScore, Policy};
use jiff::civil::Date;

/// One line per check, then the verdict.
///
/// `policy` is the one `decision` was reached with. An excepted line names its entry's
/// expiry from it, and `max_cvss` names its advisories from the same split the check made.
pub fn decision(
    policy: &Policy,
    facts: &Facts,
    decision: &Decision,
    unenforceable: &[Unenforceable],
    as_of: Date,
) -> String {
    let mut out = format!(
        "pkg:{}/{}@{}\n\n",
        facts.ecosystem, facts.name, facts.version
    );

    let width = Check::ALL
        .iter()
        .map(|c| c.as_str().len())
        .max()
        .unwrap_or(0);

    for result in &decision.results {
        let unenforced = unenforceable.iter().find(|u| u.check == result.check);
        let (state, detail) = match (unenforced, &result.outcome) {
            (Some(u), _) => ("unenforced".to_owned(), u.why.to_owned()),
            (None, Outcome::Passed) => ("pass".to_owned(), String::new()),
            (None, Outcome::NotApplicable) => (
                "n/a".to_owned(),
                format!("no meaning for {}", facts.ecosystem),
            ),
            (None, Outcome::Failed(action)) => (
                format!("FAIL {}", action.as_str()),
                found(policy, facts, decision.entry, result.check, false, as_of),
            ),
            (None, Outcome::Excepted { entry, action }) => (
                "excepted".to_owned(),
                format!(
                    "would have been {}: {}; packages[{entry}] excused it, {}",
                    action.as_str(),
                    found(policy, facts, Some(*entry), result.check, true, as_of),
                    lasts(policy, *entry)
                ),
            ),
        };
        let line = format!("  {:width$}  {:16}  {detail}", result.check.as_str(), state);
        out.push_str(line.trim_end());
        out.push('\n');
    }

    let verdict = crate::policy::enforce::enforced(decision, unenforceable).action();
    out.push_str(&format!("\n  verdict: {}\n", verdict.as_str()));
    if verdict == Action::Quarantine {
        out.push_str("  quarantine lapses on its own; block does not\n");
    }
    out
}

/// What a check found, in the terms the operator wrote.
///
/// `excepted` is whether the check's outcome was `Excepted`, which changes what `max_cvss`
/// and `cooldown_days` name: what was excused, and the wait the exception was measured
/// against.
fn found(
    policy: &Policy,
    facts: &Facts,
    entry: Option<usize>,
    check: Check,
    excepted: bool,
    as_of: Date,
) -> String {
    match check {
        Check::Denials => "this exact version is denied".to_owned(),
        Check::KnownMalware => "reported as malware; this has no exception".to_owned(),
        Check::CooldownDays => {
            let wait = match entry.filter(|_| !excepted) {
                Some(i) if decide::cooldown_required(policy, entry) != policy.cooldown_days => {
                    format!(
                        "cooldown_days {}, from packages[{i}]",
                        decide::cooldown_required(policy, entry)
                    )
                }
                _ => format!("cooldown_days {}", policy.cooldown_days),
            };
            match facts.published {
                Some(published) => format!("published {published}, {wait}"),
                None => format!("no publish date, which is not old enough for {wait}"),
            }
        }
        Check::Kev => facts
            .advisories
            .iter()
            .filter(|a| a.kev)
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Check::MaxCvss => {
            let named = |advisories: &[&Advisory]| {
                advisories
                    .iter()
                    .map(|a| match (decide::score(policy, a, as_of), &a.band) {
                        (None, _) => format!("{} unscored", a.id),
                        (Some((cvss, Some(i))), _) => {
                            format!("{} {cvss:.1} from {}", a.id, AdvisoryScore::label(i))
                        }
                        (Some((cvss, None)), Some(band)) => {
                            format!("{} {cvss:.1} from band {band}", a.id)
                        }
                        (Some((cvss, None)), None) => format!("{} {cvss:.1}", a.id),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let (counting, excused) = decide::over_max_cvss(policy, facts, entry, as_of);
            let unscored = counting
                .iter()
                .chain(&excused)
                .any(|a| decide::score(policy, a, as_of).is_none());
            let over = match unscored {
                true => format!("over max_cvss {} or unscored", policy.max_cvss),
                false => format!("over max_cvss {}", policy.max_cvss),
            };
            match (excepted, entry) {
                (true, _) => format!("{over}: {}", named(&excused)),
                (false, Some(entry)) if !excused.is_empty() => format!(
                    "{over}: {}; packages[{entry}] excused {}",
                    named(&counting),
                    named(&excused)
                ),
                (false, _) => format!("{over}: {}", named(&counting)),
            }
        }
        Check::InstallScripts => "declares an install script".to_owned(),
        Check::Deprecated => match facts.deprecated.as_deref() {
            Some(message) if !message.is_empty() => {
                format!("deprecated by its publisher: {message}")
            }
            _ => "deprecated by its publisher".to_owned(),
        },
        Check::Yanked => match facts.yanked.as_deref() {
            Some(reason) if !reason.is_empty() => format!("withdrawn by the registry: {reason}"),
            _ => "withdrawn by the registry".to_owned(),
        },
        Check::Provenance => facts.provenance.describe(),
    }
}

/// How long an entry lasts, as the file says.
fn lasts(policy: &Policy, entry: usize) -> String {
    match policy.packages.get(entry) {
        Some(e) if e.permanent => "permanent".to_owned(),
        Some(e) => e
            .expires
            .as_ref()
            .map_or("no expiry".to_owned(), |d| format!("expires {}", d.0)),
        None => "which this policy does not have".to_owned(),
    }
}

/// The policy as loaded, and which of its checks can actually fire.
///
/// Separate from the settings themselves because a configured check with no fact source is
/// not the same as one that is off, and reading the file cannot tell them apart.
pub fn policy_report(policy: &Policy, intel: Intel) -> String {
    let mut out = String::from("settings\n");
    out.push_str(&format!("  cooldown_days    {}\n", policy.cooldown_days));
    out.push_str(&format!("  max_cvss         {}\n", policy.max_cvss));
    out.push_str(&format!(
        "  install_scripts  {}\n",
        policy.install_scripts.as_str()
    ));
    out.push_str(&format!("  kev              {}\n", policy.kev.as_str()));
    out.push_str(&format!("  yanked           {}\n", policy.yanked.as_str()));
    out.push_str(&format!(
        "  deprecated       {}\n",
        policy.deprecated.as_str()
    ));
    out.push_str(&format!(
        "  provenance       {}, over {} days\n",
        policy.provenance.as_str(),
        policy.provenance_window_days
    ));
    out.push_str(&format!("  denials          {}\n", policy.denials.len()));
    out.push_str(&format!("  packages         {}\n", policy.packages.len()));
    out.push_str(&format!(
        "  advisory_scores  {}\n",
        policy.advisory_scores.len()
    ));

    out.push_str("\nsignal weights, for the risk score\n");
    for rule in crate::analysis::detector::BUILT_IN_RULES {
        out.push_str(&format!(
            "  {rule:22}  {}\n",
            policy.signal_weights.of(rule)
        ));
    }

    out.push_str("\nchecks\n");
    for check in Check::ALL {
        let state = match (check, intel) {
            (Check::MaxCvss | Check::KnownMalware | Check::Kev, Intel::NotConsulted) => {
                "unenforced, no advisory stream"
            }
            (
                Check::Kev,
                Intel::Consulted {
                    exploitation_loaded: false,
                },
            ) => "unenforced, no exploitation stream",
            (Check::CooldownDays, _) if !policy.uses_cooldown() => "off",
            _ => "enforced",
        };
        out.push_str(&format!("  {:16}  {state}\n", check.as_str()));
    }

    for (index, entry) in policy.packages.iter().enumerate() {
        out.push_str(&format!("\npackages[{index}]  {}\n", entry.reason));
    }
    for (index, score) in policy.advisory_scores.iter().enumerate() {
        out.push_str(&format!(
            "\n{}  {} {:.1}  {}\n",
            AdvisoryScore::label(index),
            score.advisory_id,
            score.cvss,
            score.reason
        ));
    }
    out
}

/// What `waharoa explain` prints and exits with: `notes` to stderr, `answer` to stdout.
#[derive(Debug, Default)]
pub struct Answered {
    pub notes: Vec<String>,
    pub answer: String,
    pub code: u8,
}

impl Answered {
    /// Nothing is answered: what stopped it is the last note.
    fn stop(mut self, code: u8) -> Self {
        self.code = code;
        self
    }
}

/// Answer `target`, a package or `--policy`, against the policy `environment` names.
/// Metadata comes from the package's own registry, not a running proxy.
pub async fn run<L: Fn(&str) -> Option<OsString>>(
    target: &crate::cli::Explain,
    environment: &Env<L>,
) -> Answered {
    let mut out = Answered::default();
    match answer(target, environment).await {
        Ok(answer) => out.answer = answer,
        Err(Stopped { code, note }) => {
            out.notes.push(note);
            return out.stop(code);
        }
    }
    out
}

/// Why `explain` answered nothing: the note it prints and the code it exits with.
struct Stopped {
    code: u8,
    note: String,
}

fn stopped(code: u8, note: impl ToString) -> Stopped {
    Stopped {
        code,
        note: note.to_string(),
    }
}

/// What [`run`] prints on stdout.
async fn answer<L: Fn(&str) -> Option<OsString>>(
    target: &crate::cli::Explain,
    environment: &Env<L>,
) -> Result<String, Stopped> {
    let path = environment.policy().map_err(|e| stopped(2, e))?;
    let Some(path) = path else {
        return Err(stopped(
            2,
            format!("set {} to the policy file to explain", crate::env::POLICY),
        ));
    };
    let policy = Policy::load(&path).map_err(|e| stopped(2, e))?;
    let store = crate::intel::postgres::intel_from_env(environment)
        .await
        .map_err(|e| stopped(1, e))?;
    answer_using(target, environment, &policy, store.as_deref()).await
}

/// [`answer`] with `policy` and `store` already open.
async fn answer_using<L: Fn(&str) -> Option<OsString>>(
    target: &crate::cli::Explain,
    environment: &Env<L>,
    policy: &Policy,
    store: Option<&dyn IntelStore>,
) -> Result<String, Stopped> {
    match target.purl.as_deref() {
        Some(argument) => package_answer(policy, store, argument, environment).await,
        None => Ok(policy_report(policy, consulted(store).await?)),
    }
}

/// Whether the checks that need intel can be enforced. A store with no snapshot answers
/// nothing, so they are reported as unenforced rather than as settings that will fire.
async fn consulted(store: Option<&dyn IntelStore>) -> Result<Intel, Stopped> {
    let Some(store) = store else {
        return Ok(Intel::NotConsulted);
    };
    Ok(match store.snapshot().await.map_err(|e| stopped(1, e))? {
        Some(snapshot) => Intel::Consulted {
            exploitation_loaded: snapshot.exploitation_loaded(),
        },
        None => Intel::NotConsulted,
    })
}

/// The decision `policy` makes about the package `argument` names, as of today.
async fn package_answer<L: Fn(&str) -> Option<OsString>>(
    policy: &Policy,
    store: Option<&dyn IntelStore>,
    argument: &str,
    environment: &Env<L>,
) -> Result<String, Stopped> {
    let reference = argument
        .parse::<PackageRef>()
        .map_err(|e| stopped(2, format!("`{argument}` is not a package reference: {e}")))?;

    let clients = Clients::from_env(environment).map_err(|e| stopped(2, e))?;
    let metadata = crate::ecosystem::fetched(clients.metadata(reference.key()).await)
        .map_err(|e| stopped(1, e))?;
    let Some(package) = metadata.version(reference.version()) else {
        return Err(stopped(
            1,
            format!("the registry does not publish {argument}"),
        ));
    };

    let full = clients.full_document(reference.key()).await;
    let times = match (full.as_ref(), policy.needs_publish_times()) {
        (Err(e), true) => return Err(stopped(1, e)),
        (Ok(Some(full)), _) => Some(full.times.clone()),
        _ => None,
    };
    let full = full.ok().flatten().and_then(|full| full.metadata.ok());

    let (ecosystem, name) = crate::intel::snapshot_intel::key_of(reference.key());
    let intel = crate::intel::store::for_command(store, &ecosystem, &name, true)
        .await
        .map_err(|e| stopped(1, e))?;
    let facts = Facts::from_document(
        policy,
        &metadata.records,
        package,
        reference.version(),
        times.as_ref(),
        intel.as_ref(),
    );
    let as_of = crate::policy::today();
    let mut answer = decision(
        policy,
        &facts,
        &decide::decide(policy, &facts, as_of),
        &crate::policy::enforce::unenforceable(
            policy,
            package,
            times.as_ref(),
            facts.intel,
            &facts.provenance,
        ),
        as_of,
    );
    let listing = Listing {
        records: &metadata.records,
        record: package,
        full: full.as_ref(),
        served: Vec::new(),
        now: jiff::Timestamp::now(),
    };
    answer.push_str(&signals(
        &crate::signal::of_detections(&[built_in(&Metadata, &listing)]),
        &policy.signal_weights,
    ));
    Ok(answer)
}

/// The metadata heuristics' signals, which refuse nothing, under the verdict, read from the full
/// packument when there is one. `explain` holds no served names, so no near name.
/// `weights` are the policy's, which give the risk score.
fn signals(signals: &[crate::signal::Signal], weights: &crate::policy::SignalWeights) -> String {
    if signals.is_empty() {
        return "  signals: none\n".to_owned();
    }
    let mut out = "  signals, which refuse nothing:\n".to_owned();
    for signal in signals {
        out.push_str(&format!(
            "    {signal} (weight {})\n",
            signal.weight(weights)
        ));
    }
    out.push_str(&format!(
        "  risk score: {}\n",
        crate::signal::score(signals, weights)
    ));
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod run_tests {
    use super::*;
    use crate::env::testing::with;
    use crate::util::test_support::{Answer, scripted, tempdir};

    fn written(label: &str, yaml: &str) -> std::path::PathBuf {
        let dir = tempdir(label);
        let path = dir.join("policy.yaml");
        std::fs::write(&path, yaml).expect("writes");
        path
    }

    fn asked(purl: Option<&str>) -> crate::cli::Explain {
        crate::cli::Explain {
            purl: purl.map(str::to_owned),
            policy: purl.is_none(),
        }
    }

    /// No policy configured: exit 2 and a line saying which variable to set.
    #[tokio::test]
    async fn without_a_policy_there_is_nothing_to_explain() {
        let answered = run(&asked(None), &with(&[])).await;
        assert_eq!(answered.code, 2);
        assert!(answered.answer.is_empty());
        assert_eq!(
            answered.notes,
            [format!(
                "set {} to the policy file to explain",
                crate::env::POLICY
            )]
        );
    }

    /// `--policy` prints what every check is set to, with no registry asked.
    #[tokio::test]
    async fn the_policy_is_explained_without_asking_a_registry() {
        let path = written("explain-policy", "version: 1\ncooldown_days: 7\n");
        let answered = run(
            &asked(None),
            &with(&[(crate::env::POLICY, &path.display().to_string())]),
        )
        .await;
        assert_eq!(answered.code, 0, "{:?}", answered.notes);
        assert!(
            answered.answer.contains("cooldown_days"),
            "{}",
            answered.answer
        );
        assert!(answered.notes.is_empty());
    }

    /// A purl that does not parse is exit 2, before anything is fetched.
    #[tokio::test]
    async fn a_purl_that_does_not_parse_is_refused() {
        let path = written("explain-purl", "version: 1\ncooldown_days: 0\n");
        let answered = run(
            &asked(Some("lodash")),
            &with(&[(crate::env::POLICY, &path.display().to_string())]),
        )
        .await;
        assert_eq!(answered.code, 2);
        assert!(
            answered.notes[0].starts_with("`lodash` is not a package reference"),
            "{:?}",
            answered.notes
        );
    }

    /// One package, judged against the registry the environment names.
    #[tokio::test]
    async fn a_version_the_registry_publishes_is_judged() {
        let packument = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        let published = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24 * 2);
        let full = serde_json::json!({
            "name": "lodash",
            "time": {"4.17.21": published.to_string()},
            "versions": {"4.17.21": {
                "version": "4.17.21",
                "repository": {"type": "git", "url": "git+https://github.com/lodash/lodash.git"},
                "dist": {"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-AAAA"},
            }},
        });
        let addr = scripted(vec![
            Answer::body(packument),
            Answer::body(full.to_string().into_bytes()),
        ])
        .await;
        let path = written("explain-version", "version: 1\ncooldown_days: 7\n");
        let answered = run(
            &asked(Some("pkg:npm/lodash@4.17.21")),
            &with(&[
                (crate::env::POLICY, &path.display().to_string()),
                (crate::env::UPSTREAM_NPM, &format!("http://{addr}")),
            ]),
        )
        .await;
        assert_eq!(answered.code, 0, "{:?}", answered.notes);
        assert!(
            answered.answer.contains("pkg:npm/lodash@4.17.21"),
            "{}",
            answered.answer
        );
        assert!(
            answered.answer.contains("verdict: quarantine"),
            "the full packument's publish time, 2 days ago: {}",
            answered.answer
        );
        assert!(
            answered.answer.ends_with(
                "  signals, which refuse nothing:\n    new package: first published 2 days ago (weight 1)\n  risk score: 1\n"
            ),
            "the full packument's publish time: {}",
            answered.answer
        );
    }

    /// Each signal gets a line with its weight, and the score closes the block.
    #[test]
    fn each_signal_gets_a_line_under_the_verdict() {
        use crate::signal::Signal;
        let weights = crate::policy::SignalWeights::of_pairs(&[("no_repository", 3)]);
        let metadata = |rule: &str, detail: &str| Signal {
            detector: "metadata".to_owned(),
            rule: rule.to_owned(),
            detail: detail.to_owned(),
        };
        assert_eq!(signals(&[], &weights), "  signals: none\n");
        assert_eq!(
            signals(
                &[
                    metadata("no_repository", "the metadata names none"),
                    metadata("new_package", "first published 1 day ago")
                ],
                &weights
            ),
            "  signals, which refuse nothing:\n    no repository: the metadata names none (weight 3)\n    new package: first published 1 day ago (weight 1)\n  risk score: 4\n"
        );
    }

    /// With no check reading publish times, a full packument that cannot be fetched stops
    /// nothing, and the signals read the abbreviated one.
    #[tokio::test]
    async fn a_full_packument_no_check_needs_may_fail() {
        let packument = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        let addr = scripted(vec![Answer::body(packument), Answer::cut_short()]).await;
        let path = written(
            "explain-no-full",
            "version: 1\ncooldown_days: 0\nprovenance: allow\n",
        );
        let answered = run(
            &asked(Some("pkg:npm/lodash@4.17.21")),
            &with(&[
                (crate::env::POLICY, &path.display().to_string()),
                (crate::env::UPSTREAM_NPM, &format!("http://{addr}")),
            ]),
        )
        .await;
        assert_eq!(answered.code, 0, "{:?}", answered.notes);
        assert!(
            answered.answer.ends_with("  signals: none\n"),
            "{}",
            answered.answer
        );
    }

    /// A version the registry does not publish is exit 1, and says so.
    #[tokio::test]
    async fn a_version_the_registry_does_not_publish_is_reported() {
        let packument = crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json");
        let addr = scripted(vec![Answer::body(packument)]).await;
        let path = written("explain-absent", "version: 1\ncooldown_days: 0\n");
        let answered = run(
            &asked(Some("pkg:npm/lodash@9.9.9")),
            &with(&[
                (crate::env::POLICY, &path.display().to_string()),
                (crate::env::UPSTREAM_NPM, &format!("http://{addr}")),
            ]),
        )
        .await;
        assert_eq!(answered.code, 1);
        assert_eq!(
            answered.notes,
            ["the registry does not publish pkg:npm/lodash@9.9.9"]
        );
    }
    /// Each thing that stops `explain` before an answer, with the code it exits with.
    #[tokio::test]
    async fn each_stop_names_its_cause_and_exit_code() {
        use crate::env::testing::with_unreadable;
        use crate::env::{DATABASE_URL, POLICY, UPSTREAM_NPM};

        let policy = written("explain-stops", "version: 1\ncooldown_days: 0\n");
        let policy = policy.display().to_string();
        let cooldown = written("explain-stops-cooldown", "version: 1\ncooldown_days: 1\n");
        let cooldown = cooldown.display().to_string();
        let unloadable = written("explain-stops-unloadable", "version: 9\n");
        let unloadable = unloadable.display().to_string();
        let closed = format!(
            "http://{}",
            crate::util::test_support::closing_server().await
        );
        let refused_times = scripted(vec![
            Answer::body(crate::ecosystem::npm::fixture("lodash-4.17.21.abbrev.json")),
            Answer::Status(500),
        ])
        .await;
        let refused_times = format!("http://{refused_times}");
        let lodash = Some("pkg:npm/lodash@4.17.21");

        let cases = [
            (with_unreadable(&[], POLICY), None, 2, POLICY.name),
            (with(&[(POLICY, &unloadable)]), None, 2, "policy version 9"),
            (
                with(&[(POLICY, &policy), (DATABASE_URL, "not a url")]),
                None,
                1,
                DATABASE_URL.name,
            ),
            (
                with(&[(POLICY, &policy), (UPSTREAM_NPM, "ftp://registry.example")]),
                lodash,
                2,
                UPSTREAM_NPM.name,
            ),
            (
                with(&[(POLICY, &policy), (UPSTREAM_NPM, &closed)]),
                lodash,
                1,
                "metadata could not be fetched",
            ),
            (
                with(&[(POLICY, &cooldown), (UPSTREAM_NPM, &refused_times)]),
                lodash,
                1,
                "publish times could not be fetched",
            ),
        ];
        for (environment, purl, code, starts) in &cases {
            let answered = run(&asked(*purl), environment).await;
            assert_eq!(answered.code, *code, "{:?}", answered.notes);
            assert!(answered.answer.is_empty());
            assert_eq!(answered.notes.len(), 1);
            assert!(
                answered.notes[0].starts_with(starts),
                "{starts}: {:?}",
                answered.notes
            );
        }
    }

    /// With a store, `--policy` says whether the checks that need intel can be enforced, and
    /// a package is judged with what the store knows. A store that errors stops both.
    #[tokio::test]
    async fn a_store_is_asked_for_its_snapshot_and_the_package() {
        use crate::intel::store::testing::FixedIntel;
        use crate::intel::store::{PackageIntel, Record};

        let policy = Policy::parse("version: 1\ncooldown_days: 0\nkev: block\nprovenance: allow\n")
            .expect("loads");
        let malware = PackageIntel {
            snapshot: "s1".to_owned(),
            records: vec![(
                Some("4.17.21".to_owned()),
                Record {
                    advisory_id: "MAL-1".to_owned(),
                    aliases: Vec::new(),
                    source: "osv".to_owned(),
                    cvss: None,
                    cvss_source: None,
                    band: None,
                    exploited: false,
                    malware: true,
                },
            )],
            ranges: Vec::new(),
            exploitation_loaded: false,
        };
        let loaded = FixedIntel(Ok(Some(malware)));
        let empty = FixedIntel(Ok(None));
        let down = FixedIntel(Err(()));
        let environment = with(&[]);

        let policy_only = asked(None);
        let answer = |store| answer_using(&policy_only, &environment, &policy, Some(store));
        let consulted = answer(&loaded).await.map_err(|s| s.note).expect("answers");
        assert!(
            consulted.contains("unenforced, no exploitation stream"),
            "{consulted}"
        );
        let not_consulted = answer(&empty).await.map_err(|s| s.note).expect("answers");
        assert_ne!(consulted, not_consulted);
        let stopped = answer(&down).await.expect_err("a store that errors");
        assert_eq!(stopped.code, 1);

        let addr = scripted(vec![Answer::body(crate::ecosystem::npm::fixture(
            "lodash-4.17.21.abbrev.json",
        ))])
        .await;
        let registry = with(&[(crate::env::UPSTREAM_NPM, &format!("http://{addr}"))]);
        let lodash = asked(Some("pkg:npm/lodash@4.17.21"));
        let judged = answer_using(&lodash, &registry, &policy, Some(&loaded))
            .await
            .map_err(|s| s.note)
            .expect("answers");
        assert!(judged.contains("verdict: block"), "{judged}");
        assert!(judged.contains("reported as malware"), "{judged}");
        let failed = answer_using(&lodash, &registry, &policy, Some(&down))
            .await
            .expect_err("a store that errors");
        assert_eq!(failed.code, 1);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::policy::decide::{Advisory, Intel, Provenance, decide};

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
            intel: Intel::NotConsulted,
            provenance: crate::policy::decide::Provenance::Consistent,
        }
    }

    fn loaded(yaml: &str) -> Policy {
        Policy::parse(yaml).expect("policy should load")
    }

    fn rendered(yaml: &str, facts: &Facts, unenforceable: &[Unenforceable]) -> String {
        let policy = loaded(yaml);
        decision(
            &policy,
            facts,
            &decide(&policy, facts, TODAY),
            unenforceable,
            TODAY,
        )
    }

    /// The whole point: every check answers, not just the one that decided.
    #[test]
    fn every_check_gets_a_line() {
        let out = rendered("version: 1", &facts(), &[]);

        for check in Check::ALL {
            let name = check.as_str();
            assert!(out.contains(name), "{name} is missing from:\n{out}");
        }
    }

    #[test]
    fn a_clean_package_is_allowed_and_says_so() {
        let out = rendered("version: 1", &facts(), &[]);

        assert!(out.contains("verdict: allow"), "{out}");
        assert!(!out.contains("FAIL"), "{out}");
    }

    #[test]
    fn a_failing_check_names_the_action_it_contributes() {
        let out = rendered(
            "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
            &[],
        );

        assert!(out.contains("denials"), "{out}");
        assert!(out.contains("FAIL block"), "{out}");
        assert!(out.contains("this exact version is denied"), "{out}");
        assert!(out.contains("verdict: block"), "{out}");
    }

    /// A refusal that named only the strongest reason would hide the rest.
    #[test]
    fn two_failing_checks_are_both_shown_under_one_verdict() {
        let out = rendered(
            "version: 1\ncooldown_days: 3650\n\
             denials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: t\n",
            &facts(),
            &[],
        );

        assert!(out.contains("FAIL block"), "{out}");
        assert!(out.contains("FAIL quarantine"), "{out}");
        assert!(out.contains("published 2021-02-20"), "{out}");
        assert!(out.contains("verdict: block"), "{out}");
    }

    /// Quarantine lapses and block does not, so the difference is stated.
    #[test]
    fn a_quarantine_verdict_says_it_lapses() {
        let out = rendered("version: 1\ncooldown_days: 3650", &facts(), &[]);

        assert!(out.contains("verdict: quarantine"), "{out}");
        assert!(out.contains("lapses on its own"), "{out}");
    }

    #[test]
    fn an_excepted_check_names_the_entry_that_excused_it() {
        let facts = Facts {
            has_install_scripts: true,
            yanked: None,
            deprecated: None,
            intel: Intel::NotConsulted,
            ..facts()
        };
        let out = rendered(
            "version: 1\ncooldown_days: 0\ninstall_scripts: block\n\
             packages:\n  - match: { ecosystem: npm, name: lodash }\n\
             \x20   set: { install_scripts: allow }\n    reason: t\n    permanent: true\n",
            &facts,
            &[],
        );

        assert!(out.contains("excepted"), "{out}");
        assert!(out.contains("packages[0] excused it"), "{out}");
        assert!(out.contains("would have been block"), "{out}");
        assert!(out.contains("verdict: allow"), "{out}");
    }

    /// `unenforced` is not `pass`. Reporting it as one would claim a check ran.
    #[test]
    fn a_check_with_no_fact_source_reads_as_unenforced_not_passed() {
        let unenforceable = [Unenforceable {
            check: Check::CooldownDays,
            why: "the abbreviated packument carries no publish times",
        }];
        let facts = Facts {
            published: None,
            ..facts()
        };
        let out = rendered("version: 1\ncooldown_days: 30", &facts, &unenforceable);

        assert!(out.contains("unenforced"), "{out}");
        assert!(out.contains("carries no publish times"), "{out}");
        assert!(
            !out.contains("FAIL quarantine"),
            "the engine's failed check is not what is shown: {out}"
        );
    }

    /// `n/a` is not `pass` either, and says which ecosystem it is not applicable to.
    #[test]
    fn a_check_with_no_meaning_for_the_ecosystem_reads_as_not_applicable() {
        let facts = Facts {
            ecosystem: "go".to_owned(),
            ..facts()
        };
        let out = rendered("version: 1", &facts, &[]);

        assert!(out.contains("n/a"), "{out}");
        assert!(out.contains("no meaning for go"), "{out}");
    }

    #[test]
    fn an_advisory_that_fired_is_named_by_id() {
        let facts = Facts {
            advisories: vec![
                Advisory {
                    id: "CVE-2024-1234".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(9.8),
                    band: None,
                    kev: true,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-0000-0000-0000".to_owned(),
                    aliases: Vec::new(),
                    cvss: Some(8.9),
                    band: Some("HIGH".to_owned()),
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-1111-1111-1111".to_owned(),
                    aliases: Vec::new(),
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
                Advisory {
                    id: "GHSA-2222-2222-2222".to_owned(),
                    aliases: Vec::new(),
                    cvss: None,
                    band: None,
                    kev: false,
                    sources: vec!["osv".to_owned()],
                },
            ],
            ..facts()
        };
        let out = rendered(
            "version: 1\nmax_cvss: 7.0\nadvisory_scores:\n  - { advisory_id: GHSA-2222-2222-2222, \
             cvss: 7.5, reason: vendor, permanent: true }\n",
            &facts,
            &[],
        );

        assert!(
            out.contains(
                "over max_cvss 7 or unscored: CVE-2024-1234 9.8, \
                 GHSA-0000-0000-0000 8.9 from band HIGH, GHSA-1111-1111-1111 unscored, \
                 GHSA-2222-2222-2222 7.5 from advisory_scores[0]"
            ),
            "{out}"
        );
        assert!(out.contains("verdict: block"), "{out}");
    }

    #[test]
    fn the_purl_is_the_first_thing_printed() {
        let out = rendered("version: 1", &facts(), &[]);

        assert!(out.starts_with("pkg:npm/lodash@4.17.21\n"), "{out}");
    }

    #[test]
    fn the_policy_view_separates_a_check_that_is_off_from_one_with_no_source() {
        let out = policy_report(&loaded("version: 1\ncooldown_days: 0"), Intel::NotConsulted);

        assert!(out.contains("cooldown_days     off"), "{out}");
        assert!(out.contains("unenforced, no advisory stream"), "{out}");
        assert!(out.contains("install_scripts   enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_reports_a_cooldown_as_enforced_once_it_is_set() {
        let out = policy_report(
            &loaded("version: 1\ncooldown_days: 30"),
            Intel::NotConsulted,
        );

        assert!(out.contains("cooldown_days     enforced"), "{out}");
    }

    #[test]
    fn the_policy_view_lists_settings_and_entries() {
        let out = policy_report(
            &loaded(
                "version: 1\nmax_cvss: 7.5\n\
                 denials:\n  - purl: pkg:npm/evil@1.0.0\n    reason: m\n\
                 packages:\n  - match: { ecosystem: npm, name: lodash }\n\
                 \x20   set: { install_scripts: allow }\n    reason: reviewed\n\
                 \x20   permanent: true\n\
                 advisory_scores:\n  - { advisory_id: GHSA-x, cvss: 7.5, reason: vendor \
                 scored it, permanent: true }\n",
            ),
            Intel::Consulted {
                exploitation_loaded: false,
            },
        );

        assert!(out.contains("advisory_scores  1"), "{out}");
        assert!(
            out.contains("\nadvisory_scores[0]  GHSA-x 7.5  vendor scored it\n"),
            "{out}"
        );
        assert!(out.contains("max_cvss         7.5"), "{out}");
        assert!(out.contains("denials          1"), "{out}");
        assert!(out.contains("packages[0]  reviewed"), "{out}");
        assert!(
            !out.contains("no advisory stream"),
            "a store without the KEV catalogue enforces every advisory check but kev: {out}"
        );
        assert!(out.contains("max_cvss          enforced"), "{out}");
        assert!(out.contains("known_malware     enforced"), "{out}");
        assert!(
            out.contains("kev               unenforced, no exploitation stream"),
            "{out}"
        );
    }

    fn golden(name: &str, actual: &str) {
        crate::golden::assert_matches("explain", name, actual);
    }

    struct Case {
        name: &'static str,
        policy: &'static str,
        facts: Facts,
        unenforceable: Vec<Unenforceable>,
    }

    fn advisory(id: &str, aliases: &[&str], cvss: f64, kev: bool) -> Advisory {
        Advisory {
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            cvss: Some(cvss),
            band: None,
            kev,
            sources: vec!["osv".to_owned()],
        }
    }

    /// Every state each check can reach, and the exception cases around them.
    fn cases() -> Vec<Case> {
        let consulted = || Facts {
            intel: Intel::Consulted {
                exploitation_loaded: true,
            },
            ..facts()
        };
        let young = || Facts {
            published: Some(jiff::civil::date(2026, 9, 11)),
            ..consulted()
        };
        let case = |name, policy, facts| Case {
            name,
            policy,
            facts,
            unenforceable: Vec::new(),
        };
        vec![
            case("nothing found", "version: 1", consulted()),
            case(
                "denied",
                "version: 1\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: compromised\n",
                consulted(),
            ),
            case(
                "known malware",
                "version: 1",
                Facts {
                    known_malware: true,
                    ..consulted()
                },
            ),
            case("too young", "version: 1\ncooldown_days: 7", young()),
            case(
                "no publish date",
                "version: 1\ncooldown_days: 7",
                Facts {
                    published: None,
                    ..consulted()
                },
            ),
            case(
                "too young, excepted",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: internal\n    permanent: true\n",
                young(),
            ),
            case(
                "too young, exception shortens the wait and not enough",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 3 }\n    reason: internal\n    expires: \"2026-10-01\"\n",
                young(),
            ),
            case(
                "too young, the narrowest matching entry applies",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: \"lod*\" }\n    set: { cooldown_days: 5 }\n    reason: broad\n    permanent: true\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: narrow\n    expires: \"2026-10-01\"\n",
                young(),
            ),
            case(
                "too young, the exception lapsed",
                "version: 1\ncooldown_days: 7\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { cooldown_days: 0 }\n    reason: internal\n    expires: \"2026-09-01\"\n",
                young(),
            ),
            Case {
                unenforceable: vec![Unenforceable {
                    check: Check::CooldownDays,
                    why: "the abbreviated packument carries no publish times",
                }],
                ..case(
                    "cooldown with no publish times to read",
                    "version: 1\ncooldown_days: 7",
                    Facts {
                        published: None,
                        ..consulted()
                    },
                )
            },
            case(
                "exploited",
                "version: 1\nmax_cvss: 6.9\nkev: block",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "exploited, excepted",
                "version: 1\nmax_cvss: 6.9\nkev: block\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { kev: allow }\n    reason: mitigated\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "exploited, kev: allow",
                "version: 1\nmax_cvss: 6.9\nkev: allow",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 5.0, true)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, one advisory under it",
                "version: 1\nmax_cvss: 7.0",
                Facts {
                    advisories: vec![
                        advisory("CVE-2024-1", &[], 9.8, false),
                        advisory("CVE-2024-2", &[], 5.3, false),
                    ],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, an entry that excuses none of it",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-9\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, excepted by id",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, excepted by alias",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![advisory("GHSA-aaaa-bbbb-cccc", &["CVE-2024-1"], 9.8, false)],
                    ..consulted()
                },
            ),
            case(
                "over max_cvss, one excused and one not",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![
                        advisory("GHSA-aaaa-bbbb-cccc", &["CVE-2024-1"], 9.8, false),
                        advisory("GHSA-dddd-eeee-ffff", &["CVE-2024-3"], 7.5, false),
                    ],
                    ..consulted()
                },
            ),
            case(
                "max_cvss, an unscored advisory and one scored in policy",
                "version: 1\nmax_cvss: 7.0\nadvisory_scores:\n  - { advisory_id: CVE-2024-2, cvss: 8.0, reason: vendor, permanent: true }\n",
                Facts {
                    advisories: vec![
                        Advisory {
                            cvss: None,
                            ..advisory("CVE-2024-1", &[], 0.0, false)
                        },
                        Advisory {
                            cvss: None,
                            ..advisory("CVE-2024-2", &[], 0.0, false)
                        },
                    ],
                    ..consulted()
                },
            ),
            case(
                "max_cvss, an unscored advisory excepted by id",
                "version: 1\nmax_cvss: 7.0\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { vuln_advisory_ids: [\"CVE-2024-1\"] }\n    reason: unreachable\n    expires: \"2026-11-30\"\n",
                Facts {
                    advisories: vec![Advisory {
                        cvss: None,
                        ..advisory("CVE-2024-1", &[], 0.0, false)
                    }],
                    ..consulted()
                },
            ),
            case(
                "install script",
                "version: 1\ninstall_scripts: block",
                Facts {
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
                    ..consulted()
                },
            ),
            case(
                "install script, excepted",
                "version: 1\ninstall_scripts: block\npackages:\n  - match: { ecosystem: npm, name: lodash, has_install_scripts: true }\n    set: { install_scripts: allow }\n    reason: reviewed\n    expires: \"2026-10-01\"\n",
                Facts {
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
                    ..consulted()
                },
            ),
            case(
                "deprecated, which is allowed unless a policy says otherwise",
                "version: 1\ndeprecated: block",
                Facts {
                    deprecated: Some("no longer supported, use rimraf@4".to_owned()),
                    ..consulted()
                },
            ),
            case(
                "deprecated, no message given",
                "version: 1\ndeprecated: block",
                Facts {
                    deprecated: Some(String::new()),
                    ..consulted()
                },
            ),
            case(
                "yanked, with the reason the publisher gave",
                "version: 1",
                Facts {
                    ecosystem: "pypi".to_owned(),
                    yanked: Some(
                        "Yanked due to conflicts with CVE-2024-35195 mitigation".to_owned(),
                    ),
                    ..consulted()
                },
            ),
            case(
                "yanked, no reason given",
                "version: 1",
                Facts {
                    ecosystem: "pypi".to_owned(),
                    yanked: Some(String::new()),
                    ..consulted()
                },
            ),
            case(
                "install script, an ecosystem with no install step",
                "version: 1\ninstall_scripts: block",
                Facts {
                    ecosystem: "go".to_owned(),
                    has_install_scripts: true,
                    yanked: None,
                    deprecated: None,
                    ..consulted()
                },
            ),
            case(
                "provenance: an attestation that does not verify",
                "version: 1",
                Facts {
                    provenance: Provenance::Unverified {
                        why: "artifact hash does not match any subject in attestation".to_owned(),
                    },
                    ..consulted()
                },
            ),
            case(
                "provenance: dropped after the version before it published some",
                "version: 1",
                Facts {
                    provenance: Provenance::Dropped {
                        previous: "4.17.20".to_owned(),
                    },
                    ..consulted()
                },
            ),
            case(
                "provenance: another workflow built it, excepted",
                "version: 1\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    set: { provenance: allow }\n    reason: moved to release.yml\n    expires: \"2026-10-01\"\n",
                Facts {
                    provenance: Provenance::IdentityChanged {
                        previous: "4.17.20".to_owned(),
                        from: "github.com/lodash/lodash/.github/workflows/publish.yml".to_owned(),
                        to: "github.com/lodash/lodash/.github/workflows/release.yml".to_owned(),
                    },
                    ..consulted()
                },
            ),
            Case {
                unenforceable: vec![Unenforceable {
                    check: Check::Provenance,
                    why: "no attestation of it has been verified",
                }],
                ..case(
                    "provenance: nothing verified yet",
                    "version: 1",
                    Facts {
                        provenance: Provenance::NOT_VERIFIED,
                        ..consulted()
                    },
                )
            },
            Case {
                unenforceable: [Check::KnownMalware, Check::Kev, Check::MaxCvss]
                    .map(|check| Unenforceable {
                        check,
                        why: "no intel store was consulted, so nothing was asked",
                    })
                    .to_vec(),
                ..case("no intel store", "version: 1", facts())
            },
            case(
                "several at once",
                "version: 1\ncooldown_days: 7\nmax_cvss: 7.0\ndenials:\n  - purl: pkg:npm/lodash@4.17.21\n    reason: compromised\n",
                Facts {
                    advisories: vec![advisory("CVE-2024-1", &[], 9.8, false)],
                    ..young()
                },
            ),
        ]
    }

    #[test]
    fn every_reachable_state_renders_as_the_golden_file_says() {
        let mut out = String::new();
        for c in cases() {
            let policy = loaded(c.policy);
            out.push_str(&format!("=== {}\n", c.name));
            for line in c.policy.lines() {
                out.push_str(&format!("  | {line}\n"));
            }
            out.push('\n');
            out.push_str(&decision(
                &policy,
                &c.facts,
                &decide(&policy, &c.facts, TODAY),
                &c.unenforceable,
                TODAY,
            ));
            out.push('\n');
        }
        golden("decisions.txt", &out);
    }

    #[test]
    fn the_policy_view_renders_as_the_golden_file_says() {
        let shipped = || loaded(include_str!("../examples/policy.yaml"));
        let mut out = String::new();
        for (name, policy, intel) in [
            (
                "version: 1, no store",
                loaded("version: 1"),
                Intel::NotConsulted,
            ),
            (
                "version: 1, cooldown_days: 0, near_name weighing 2, no store",
                loaded("version: 1\ncooldown_days: 0\nsignal_weights: { near_name: 2 }"),
                Intel::NotConsulted,
            ),
            (
                "examples/policy.yaml, a store without the KEV catalogue",
                shipped(),
                Intel::Consulted {
                    exploitation_loaded: false,
                },
            ),
            (
                "examples/policy.yaml, a store with the KEV catalogue",
                shipped(),
                Intel::Consulted {
                    exploitation_loaded: true,
                },
            ),
        ] {
            out.push_str(&format!("=== {name}\n"));
            out.push_str(&policy_view(&policy, intel));
            out.push('\n');
        }
        golden("policy.txt", &out);
    }

    fn policy_view(p: &Policy, intel: Intel) -> String {
        policy_report(p, intel)
    }

    #[test]
    fn an_excepted_line_says_whether_its_entry_expires() {
        let yaml = "version: 1\npackages:\n  - match: { ecosystem: npm, name: lodash }\n    \
                    set: { install_scripts: allow }\n    reason: t\n    permanent: true\n";
        let permanent = loaded(yaml);
        assert_eq!(lasts(&permanent, 0), "permanent");
        assert_eq!(lasts(&permanent, 1), "which this policy does not have");
        let mut open = loaded(yaml);
        open.packages[0].permanent = false;
        assert_eq!(lasts(&open, 0), "no expiry");
    }
}
