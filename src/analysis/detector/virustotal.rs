//! VirusTotal's stored answer about an artifact read as a detector built in. The lookup runs
//! in the analyser, keyed by the artifact's digest. Report only: see
//! docs/engineering_decisions/virustotal.md.

use super::{Detecting, Detection, Detector, Finding};
use crate::analysis::virustotal::{Counts, Scanned, Verdict};

/// Its name, which its rule is not prefixed with in `signal_weights`.
pub const NAME: &str = "virustotal";

/// Its version, which a stored answer is not keyed by: VirusTotal's counts are its own.
pub const VERSION: &str = "virustotal 1";

/// Every rule it reports.
pub const RULES: [&str; 1] = ["virustotal_detected"];

/// VirusTotal's findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirusTotal;

impl Detector<Scanned> for VirusTotal {
    fn name(&self) -> &str {
        NAME
    }

    fn version(&self) -> &str {
        VERSION
    }

    /// Answers on the first poll: see [`super::at_once`].
    fn detect<'a>(&'a self, scanned: &'a Scanned) -> Detecting<'a> {
        Box::pin(std::future::ready(Ok(detection(scanned))))
    }
}

/// `virustotal_detected` when an engine called the file malicious or suspicious. Unknown, or
/// an analysis still queued, fires nothing.
fn detection(scanned: &Scanned) -> Detection {
    let findings = match scanned.verdict {
        Verdict::Known(Counts {
            malicious,
            suspicious,
            engines,
        }) if malicious + suspicious > 0 => vec![Finding {
            rule: RULES[0].to_owned(),
            detail: format!("{malicious} malicious, {suspicious} suspicious of {engines} engines"),
        }],
        _ => Vec::new(),
    };
    Detection {
        findings,
        errors: Vec::new(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::detector::at_once;

    fn fired(verdict: Verdict) -> Vec<String> {
        let scanned = Scanned {
            sha256: "0".repeat(64),
            verdict,
            asked: 0,
        };
        at_once(VirusTotal.detect(&scanned))
            .expect("it answers at once")
            .expect("it runs")
            .findings
            .iter()
            .map(|finding| format!("{}: {}", finding.rule, finding.detail))
            .collect()
    }

    /// A malicious or suspicious count fires the rule; none, unknown or queued fire nothing.
    #[test]
    fn a_detection_by_any_engine_fires_the_rule() {
        let counts = |malicious, suspicious| {
            Verdict::Known(Counts {
                malicious,
                suspicious,
                engines: 70,
            })
        };
        assert_eq!(
            fired(counts(3, 1)),
            ["virustotal_detected: 3 malicious, 1 suspicious of 70 engines"]
        );
        assert_eq!(
            fired(counts(0, 2)),
            ["virustotal_detected: 0 malicious, 2 suspicious of 70 engines"]
        );
        assert!(fired(counts(0, 0)).is_empty());
        assert!(fired(Verdict::Unknown).is_empty());
        assert!(fired(Verdict::Queued("id".to_owned())).is_empty());
        assert_eq!((VirusTotal.name(), VirusTotal.version()), (NAME, VERSION));
    }
}
