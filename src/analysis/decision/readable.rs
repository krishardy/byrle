//! `byrle artifact show` without `-o json`: each decision as a list to read.

use super::{Decided, DetectorRun, Disposition, Features, Scan, Unrun};
use crate::analysis::detector::virustotal::NAME as VIRUSTOTAL;
use crate::audit::{RecordedAdvisory, RecordedFacts};

/// `json_lines`, as [`super::command::show`] prints them, each decision as a readable list
/// with a blank line between them. A line that is not a decision is kept as it is.
pub fn lines(json_lines: &str) -> String {
    json_lines
        .lines()
        .map(|line| match Decided::from_json(line) {
            Some(decided) => readable(&decided),
            None => format!("{line}\n"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One decision: what it is about, what was decided, what it was decided on and under.
fn readable(decided: &Decided) -> String {
    let mut out = format!("{}\n", purl(decided));
    let rows = [
        (
            "digest",
            decided
                .digest
                .clone()
                .unwrap_or_else(|| "none published".to_owned()),
        ),
        ("repository", decided.repository.clone().unwrap_or_default()),
        ("decided", decided.at.clone()),
        (
            "account",
            decided.account.clone().unwrap_or_else(|| "none".to_owned()),
        ),
    ];
    push_rows(
        &mut out,
        "  ",
        rows.iter().filter(|(_, value)| !value.is_empty()),
    );
    out.push_str("\n  disposition\n");
    push_rows(&mut out, "    ", disposition(&decided.disposition).iter());
    out.push_str("\n  facts\n");
    push_rows(&mut out, "    ", facts(&decided.features.facts).iter());
    out.push_str("\n  detectors\n");
    push_rows(&mut out, "    ", detectors(&decided.features).iter());
    out.push_str("\n  decided under\n");
    let under = [
        ("policy", decided.disposition.policy_digest.clone()),
        (
            "intel snapshot",
            or_none(decided.disposition.intel_snapshot.as_deref()),
        ),
        ("as of", decided.disposition.as_of.clone()),
        ("build", decided.disposition.build.clone()),
        ("reader", decided.disposition.reader.clone()),
        ("verifier", decided.disposition.verifier.clone()),
    ];
    push_rows(&mut out, "    ", under.iter());
    out
}

/// The version's purl, or `pkg:<ecosystem>/<name>@<version>` for one that does not parse.
fn purl(decided: &Decided) -> String {
    super::Artifact::Version {
        ecosystem: decided.ecosystem.clone(),
        name: decided.name.clone(),
        version: decided.version.clone(),
    }
    .to_string()
}

/// Each row as `<indent><label>  <value>`, labels padded to the longest.
fn push_rows<'a, L: AsRef<str> + 'a>(
    out: &mut String,
    indent: &str,
    rows: impl Iterator<Item = &'a (L, String)> + Clone,
) {
    let width = rows
        .clone()
        .map(|(label, _)| label.as_ref().len())
        .max()
        .unwrap_or(0);
    for (label, value) in rows {
        let label = label.as_ref();
        out.push_str(&format!("{indent}{label:<width$}  {value}\n"));
    }
}

fn disposition(disposition: &Disposition) -> Vec<(&'static str, String)> {
    let answered = match (kebab(&disposition.answered), disposition.upstream_status) {
        (answered, Some(status)) => format!("{answered} {status}"),
        (answered, None) => answered,
    };
    let mut rows = vec![
        ("action", disposition.action.clone()),
        ("answered", answered),
        ("mode", disposition.mode.clone()),
        ("checks failed", listed(&disposition.checks)),
        ("unenforceable", listed(&disposition.unenforceable)),
    ];
    if !disposition.not_analyzed.is_empty() {
        rows.push(("not analysed", listed(&disposition.not_analyzed)));
    }
    let exceptions: Vec<String> = disposition
        .exceptions_used
        .iter()
        .map(|index| format!("packages[{index}]"))
        .collect();
    rows.push(("exceptions used", listed(&exceptions)));
    rows.push((
        "risk score",
        disposition
            .risk_score
            .map_or_else(|| "none".to_owned(), |score| score.to_string()),
    ));
    rows
}

fn facts(facts: &RecordedFacts) -> Vec<(&'static str, String)> {
    let install_scripts = match (facts.has_install_scripts, facts.install_scripts_analyzed) {
        (_, false) => "not analysed",
        (true, true) => "yes",
        (false, true) => "no",
    };
    vec![
        ("published", or_none(facts.published.as_deref())),
        ("known malware", yes_no(facts.known_malware)),
        ("advisories", advisories(&facts.advisories)),
        ("intel", facts.intel.clone()),
        ("install scripts", install_scripts.to_owned()),
        ("yanked", or_no(facts.yanked.as_deref())),
        ("deprecated", or_no(facts.deprecated.as_deref())),
        ("provenance", tagged(&facts.provenance)),
    ]
}

/// Each advisory as `<id> (cvss <score>, <band>, kev)`, by `, `.
fn advisories(advisories: &[RecordedAdvisory]) -> String {
    let each: Vec<String> = advisories
        .iter()
        .map(|advisory| {
            let mut about = Vec::new();
            if let Some(cvss) = advisory.cvss {
                about.push(format!("cvss {cvss}"));
            }
            about.extend(advisory.band.clone());
            if advisory.kev {
                about.push("kev".to_owned());
            }
            match about.is_empty() {
                true => advisory.id.clone(),
                false => format!("{} ({})", advisory.id, about.join(", ")),
            }
        })
        .collect();
    listed(&each)
}

/// One row per detector: each run's findings and errors, or `no findings`; then each
/// detector with no result, and why; then VirusTotal, once, whose run its answer reports.
fn detectors(features: &Features) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = features
        .detectors
        .iter()
        .filter(|run| run.detector != VIRUSTOTAL)
        .map(|run| (run.detector.clone(), found(run)))
        .collect();
    rows.extend(
        features
            .not_run
            .iter()
            .filter(|not_run| not_run.detector != VIRUSTOTAL)
            .map(|not_run| (not_run.detector.clone(), unrun(&not_run.why))),
    );
    let not_run = features.not_run.iter().find(|n| n.detector == VIRUSTOTAL);
    let scanned = match (&features.virustotal, not_run) {
        (Some(scan), _) => scanned(scan),
        (None, Some(not_run)) => unrun(&not_run.why),
        (None, None) => unrun(&Unrun::Pending),
    };
    rows.push((VIRUSTOTAL.to_owned(), scanned));
    rows
}

/// A run's findings and errors, or `no findings`.
fn found(run: &DetectorRun) -> String {
    let found: Vec<String> = run
        .detection
        .findings
        .iter()
        .map(|f| format!("{}: {}", f.rule, f.detail))
        .chain(
            run.detection
                .errors
                .iter()
                .map(|e| format!("error {}: {}", e.rule, e.detail)),
        )
        .collect();
    match found.is_empty() {
        true => "no findings".to_owned(),
        false => found.join(", "),
    }
}

/// VirusTotal's state, with its counts when it knew the file.
fn scanned(scan: &Scan) -> String {
    match (scan.malicious, scan.suspicious, scan.engines) {
        (Some(malicious), Some(suspicious), Some(engines)) => format!(
            "{}: {malicious} malicious, {suspicious} suspicious, of {engines} engines",
            scan.state
        ),
        _ => scan.state.clone(),
    }
}

/// Why a detector had no result when the decision was made.
fn unrun(why: &Unrun) -> String {
    match why {
        Unrun::Off => "off".to_owned(),
        Unrun::Pending => "no result when decided".to_owned(),
        Unrun::DidNotRun { why } => format!("did not run: {why}"),
    }
}

/// `value` serialised, a kebab-case string such as `no-strong-digest`.
fn kebab(value: &crate::audit::Answered) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The provenance as its `state`, then each other field, all strings, as `key value`.
fn tagged(value: &crate::audit::RecordedProvenance) -> String {
    let fields = serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut state = String::new();
    let mut rest = Vec::new();
    for (key, field) in fields {
        let text = field.as_str().unwrap_or_default().to_owned();
        match key.as_str() {
            "state" => state = text,
            "why" => rest.push(text),
            _ => rest.push(format!("{key} {text}")),
        }
    }
    match rest.is_empty() {
        true => state,
        false => format!("{state}: {}", rest.join(", ")),
    }
}

fn listed(items: &[String]) -> String {
    match items.is_empty() {
        true => "none".to_owned(),
        false => items.join(", "),
    }
}

fn or_none(value: Option<&str>) -> String {
    value.unwrap_or("none").to_owned()
}

fn or_no(value: Option<&str>) -> String {
    value.map_or_else(|| "no".to_owned(), |why| format!("yes: {why}"))
}

fn yes_no(value: bool) -> String {
    (if value { "yes" } else { "no" }).to_owned()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::decision::tests::decided;
    use crate::analysis::detector::Finding;
    use crate::audit::{Answered, RecordedProvenance};

    fn at_a_fixed_time(mut decided: Decided) -> Decided {
        decided.at = "2026-11-25T05:32:50Z".to_owned();
        decided
    }

    /// Every part of a decision, in the order it is printed.
    #[test]
    fn a_decision_reads_as_a_list() {
        let decided = at_a_fixed_time(decided("ms", "sha512-x"));
        assert_eq!(
            lines(&decided.to_json()),
            "pkg:npm/ms@1.0.0
  digest   sha512-x
  decided  2026-11-25T05:32:50Z
  account  alice

  disposition
    action           block
    answered         served
    mode             observe
    checks failed    provenance, cooldown_days
    unenforceable    none
    exceptions used  none
    risk score       none

  facts
    published        none
    known malware    no
    advisories       none
    intel            not-consulted
    install scripts  no
    yanked           no
    deprecated       no
    provenance       unknown: no attestation of it has been verified

  detectors
    metadata    typosquat: near express
    guarddog    no findings
    virustotal  known: 2 malicious, 1 suspicious, of 70 engines

  decided under
    policy          sha256:09bfcc6a14b83e2192b8673677725c84883ee9cd0c70e45c9ec09daa8f2b2847
    intel snapshot  none
    as of           2026-10-12
    build           0.1.0
    reader          install-scripts 7
    verifier        sigstore-verify 0.14.0; root sha256:6494e21ea73fa7ee
"
        );
    }

    /// The rows that print only when set, and each value's other forms.
    #[test]
    fn each_value_that_is_set_is_printed() {
        let mut decided = at_a_fixed_time(decided("@babel/core", "sha512-x"));
        decided.digest = None;
        decided.repository = Some("gradle-plugins".to_owned());
        decided.account = None;
        let disposition = &mut decided.disposition;
        disposition.answered = Answered::UpstreamStatus;
        disposition.upstream_status = Some(404);
        disposition.unenforceable = vec!["kev".to_owned()];
        disposition.not_analyzed = vec!["install_scripts".to_owned()];
        disposition.exceptions_used = vec![0, 2];
        disposition.risk_score = Some(101);
        disposition.intel_snapshot = Some("sha256:snap".to_owned());
        let facts = &mut decided.features.facts;
        facts.published = Some("2026-11-24".to_owned());
        facts.known_malware = true;
        facts.advisories = vec![
            RecordedAdvisory {
                id: "GHSA-1".to_owned(),
                aliases: Vec::new(),
                cvss: Some(9.8),
                band: Some("critical".to_owned()),
                kev: true,
                sources: Vec::new(),
            },
            RecordedAdvisory {
                id: "MAL-2".to_owned(),
                aliases: Vec::new(),
                cvss: None,
                band: None,
                kev: false,
                sources: Vec::new(),
            },
        ];
        facts.has_install_scripts = true;
        facts.yanked = Some("broken".to_owned());
        facts.deprecated = Some("use v2".to_owned());
        facts.provenance = RecordedProvenance::IdentityChanged {
            previous: "0.9.0".to_owned(),
            from: "a/b".to_owned(),
            to: "c/d".to_owned(),
        };
        decided.features.detectors[1].detection.errors = vec![Finding {
            rule: "whois".to_owned(),
            detail: "port 43 refused".to_owned(),
        }];
        decided.features.virustotal = None;
        let printed = lines(&decided.to_json());
        for row in [
            "pkg:npm/%40babel/core@1.0.0\n",
            "  digest      none published\n",
            "  repository  gradle-plugins\n",
            "  account     none\n",
            "    answered         upstream-status 404\n",
            "    unenforceable    kev\n",
            "    not analysed     install_scripts\n",
            "    exceptions used  packages[0], packages[2]\n",
            "    risk score       101\n",
            "    published        2026-11-24\n",
            "    known malware    yes\n",
            "    advisories       GHSA-1 (cvss 9.8, critical, kev), MAL-2\n",
            "    install scripts  yes\n",
            "    yanked           yes: broken\n",
            "    deprecated       yes: use v2\n",
            "    provenance       identity-changed: from a/b, previous 0.9.0, to c/d\n",
            "    guarddog    error whois: port 43 refused\n",
            "    virustotal  no result when decided\n",
            "    intel snapshot  sha256:snap\n",
        ] {
            assert!(printed.contains(row), "{row:?} in\n{printed}");
        }
    }

    /// Install scripts a decision did not read the artifact for, and a VirusTotal lookup
    /// without counts, say so. A provenance state with no detail is the state alone.
    #[test]
    fn what_was_not_read_says_so() {
        let mut decided = at_a_fixed_time(decided("ms", "sha512-x"));
        decided.features.facts.install_scripts_analyzed = false;
        decided.features.facts.provenance = RecordedProvenance::Consistent;
        decided.features.virustotal.as_mut().unwrap().state = "unknown".to_owned();
        decided.features.virustotal.as_mut().unwrap().malicious = None;
        let printed = lines(&decided.to_json());
        assert!(
            printed.contains("    install scripts  not analysed\n"),
            "{printed}"
        );
        assert!(printed.contains("    virustotal  unknown\n"), "{printed}");
        assert!(
            printed.contains("    provenance       consistent\n"),
            "{printed}"
        );
    }

    /// Each detector with no result reads as why, after those that ran. VirusTotal reads
    /// once: its answer over its run and its `not_run` entry, else that entry.
    #[test]
    fn a_detector_with_no_result_says_why() {
        use crate::analysis::decision::NotRun;
        let mut decided = at_a_fixed_time(decided("ms", "sha512-x"));
        decided.features.detectors.push(DetectorRun {
            detector: VIRUSTOTAL.to_owned(),
            detection: Default::default(),
        });
        decided.features.not_run = vec![
            NotRun::new("archive", Unrun::Pending),
            NotRun::new(
                "source",
                Unrun::DidNotRun {
                    why: "no repository".to_owned(),
                },
            ),
            NotRun::new("signing", Unrun::Off),
            NotRun::new(VIRUSTOTAL, Unrun::Pending),
        ];
        let printed = lines(&decided.to_json());
        assert!(
            printed.contains(
                "  detectors
    metadata    typosquat: near express
    guarddog    no findings
    archive     no result when decided
    source      did not run: no repository
    signing     off
    virustotal  known: 2 malicious, 1 suspicious, of 70 engines
"
            ),
            "{printed}"
        );
        decided.features.virustotal = None;
        decided.features.not_run[3].why = Unrun::DidNotRun {
            why: "VirusTotal answered 429".to_owned(),
        };
        let printed = lines(&decided.to_json());
        assert!(
            printed.contains("    virustotal  did not run: VirusTotal answered 429\n"),
            "{printed}"
        );
    }

    /// Two decisions are separated by a blank line, and a line that is not one is kept.
    #[test]
    fn each_line_is_a_decision_or_kept_as_it_is() {
        let one = at_a_fixed_time(decided("ms", "sha512-x")).to_json();
        let printed = lines(&format!("{one}\nnot json\n{one}\n"));
        let single = lines(&one);
        assert_eq!(printed, format!("{single}\nnot json\n\n{single}"));
        assert_eq!(lines(""), "");
    }
}
