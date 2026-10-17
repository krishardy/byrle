//! Which key signed a version, against the versions published before it, read as a detector
//! built in from Maven's `.asc` files. Report only: see
//! docs/engineering_decisions/0113-maven-signatures.md.

use super::{Detection, Finding};

/// Its name, which its rules are not prefixed with in `signal_weights`.
pub const NAME: &str = "signing";

/// Its version.
pub const VERSION: &str = "signing 1";

/// Every rule it reports, in the order it reports them.
pub const RULES: [&str; 2] = ["signing_key_new", "signing_key_expired"];

/// One version, when it was published, and what its signature says of its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub version: String,
    pub published: jiff::Timestamp,
    /// The primary key that signed it, `None` for a version no key there signed.
    pub key: Option<String>,
    /// How that key had expired when it signed, `None` when it had not.
    pub expired: Option<String>,
}

/// The rules that fire for `version` among `signed`, a key being established once a version
/// published `window` or more before it was signed with it. `None` when it is not listed.
pub fn detection(
    signed: &[Signed],
    version: &str,
    window: jiff::SignedDuration,
) -> Option<Detection> {
    let this = signed.iter().find(|s| s.version == version)?;
    let opens = this.published - window;
    let mut established: Vec<&Signed> = signed
        .iter()
        .filter(|s| s.published <= opens && s.key.is_some())
        .collect();
    established.sort_by_key(|s| std::cmp::Reverse(s.published));
    let mut findings = Vec::new();
    if let (Some(key), Some(before)) = (&this.key, established.first())
        && !established.iter().any(|s| s.key.as_ref() == Some(key))
    {
        findings.push(Finding {
            rule: RULES[0].to_owned(),
            detail: format!(
                "signed by {key}; {} was signed by {}",
                before.version,
                before.key.as_deref().unwrap_or_default()
            ),
        });
    }
    if let Some(expired) = &this.expired {
        findings.push(Finding {
            rule: RULES[1].to_owned(),
            detail: expired.clone(),
        });
    }
    Some(Detection {
        findings,
        errors: Vec::new(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const WEEK: jiff::SignedDuration = jiff::SignedDuration::from_hours(24 * 7);

    /// `version`, published `day` days into 2026, signed by `key`.
    fn v(version: &str, day: i64, key: Option<&str>) -> Signed {
        let start: jiff::Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        Signed {
            version: version.to_owned(),
            published: start + jiff::SignedDuration::from_hours(24 * day),
            key: key.map(str::to_owned),
            expired: None,
        }
    }

    fn rules(signed: &[Signed], version: &str) -> Vec<String> {
        detection(signed, version, WEEK)
            .expect("listed")
            .findings
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    /// Apache's release managers each sign with their own key: a key an established version
    /// used, however long ago, is no new key.
    #[test]
    fn a_key_no_established_version_used_is_new() {
        let history = [
            v("1.0", 0, Some("A")),
            v("1.1", 30, Some("B")),
            v("1.2", 60, Some("A")),
            v("1.3", 90, Some("C")),
            v("1.4", 95, Some("D")),
        ];
        assert!(rules(&history, "1.2").is_empty(), "A signed 1.0");
        assert_eq!(rules(&history, "1.3"), ["signing_key_new"]);
        assert_eq!(
            rules(&history, "1.4"),
            ["signing_key_new"],
            "C signed 1.3 inside the window, so it is not established"
        );
        let detail = &detection(&history, "1.3", WEEK).unwrap().findings[0].detail;
        assert_eq!(detail, "signed by C; 1.2 was signed by A");
        assert!(rules(&history, "1.0").is_empty(), "nothing before it");
        assert!(detection(&history, "9.9", WEEK).is_none());
    }

    /// Versions with no signature establish nothing, and a version with none fires nothing.
    #[test]
    fn an_unsigned_version_is_neither_a_key_nor_new() {
        let history = [
            v("1.0", 0, None),
            v("1.1", 30, Some("A")),
            v("1.2", 60, None),
        ];
        assert!(rules(&history, "1.1").is_empty());
        assert!(rules(&history, "1.2").is_empty());
    }

    #[test]
    fn a_key_expired_when_it_signed_is_its_own_signal() {
        let mut expired = v("1.0", 0, Some("A"));
        expired.expired = Some("the key expired before it signed".to_owned());
        let found = detection(&[expired], "1.0", WEEK).unwrap();
        assert_eq!(found.findings[0].rule, "signing_key_expired");
        assert_eq!(found.findings[0].detail, "the key expired before it signed");
    }
}
