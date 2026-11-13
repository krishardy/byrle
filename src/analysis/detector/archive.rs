//! What in a tarball's shape no packer writes, read as a detector built in from the stored
//! analysis. See docs/engineering_decisions/0122-tarballs-read-as-the-widest-extractor.md.

use super::{Detection, Finding};
use crate::analysis::Anomaly;

/// Its name, which its rule is not prefixed with in `signal_weights`.
pub const NAME: &str = "archive";

/// Every rule it reports.
pub const RULES: [&str; 1] = ["archive_suspicious"];

/// `archive_suspicious`, naming each of `anomalies`, when there are any.
pub fn detection(anomalies: &[Anomaly]) -> Detection {
    let findings = if anomalies.is_empty() {
        Vec::new()
    } else {
        let named: Vec<String> = anomalies.iter().map(ToString::to_string).collect();
        vec![Finding {
            rule: RULES[0].to_owned(),
            detail: named.join("; "),
        }]
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

    /// One finding naming every anomaly; none fires nothing.
    #[test]
    fn each_anomaly_is_named_in_one_finding() {
        assert_eq!(detection(&[]), Detection::default());
        let found = detection(&[
            Anomaly::GzipMembers(2),
            Anomaly::Duplicate("package.json".to_owned()),
        ]);
        assert_eq!(
            found.findings,
            [Finding {
                rule: "archive_suspicious".to_owned(),
                detail: "2 gzip members; two entries extract to `package.json`".to_owned(),
            }]
        );
    }
}
