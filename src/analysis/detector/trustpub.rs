//! Whether trusted publishing published a version, and from which repository, read as a
//! detector built in. crates.io's `trustpub_data` is the record read: nothing signs it, and
//! only its API serves it, so the adapter asks. Report only: see
//! docs/engineering_decisions/0110-cargo-provenance.md.

use super::{Detection, Finding};

/// Its name, which its rules are not prefixed with in `signal_weights`.
pub const NAME: &str = "trustpub";

/// Its version.
pub const VERSION: &str = "trustpub 1";

/// Every rule it reports, in the order it reports them.
pub const RULES: [&str; 2] = ["trustpub_dropped", "trustpub_repository_changed"];

/// The month crates.io opened trusted publishing, which the API is paged back to.
pub const OPENED: &str = "2025-07";

/// The gap between two requests crates.io asks of an API client: 1 a second.
pub const DEFAULT_INTERVAL_MS: u64 = 1000;

/// One version as the registry lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub version: String,
    /// RFC 3339 in UTC, as crates.io writes it, so its order is the string's.
    pub created_at: String,
    /// The provider and repository trusted publishing named, `None` when it did not publish it.
    pub identity: Option<String>,
    /// The login of the user who published it, `None` for trusted publishing.
    pub publisher: Option<String>,
}

/// The rules that fire for `version` among `published`, in publish order. `None` when
/// `published` does not list it.
pub fn detection(published: &[Published], version: &str) -> Option<Detection> {
    let mut ordered: Vec<&Published> = published.iter().collect();
    ordered.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    let at = ordered.iter().position(|p| p.version == version)?;
    let this = ordered[at];
    let before = ordered[..at]
        .iter()
        .rev()
        .find_map(|p| Some((p, p.identity.as_deref()?)));
    let mut findings = Vec::new();
    if let Some((before, was)) = before {
        match this.identity.as_deref() {
            None => findings.push(Finding {
                rule: RULES[0].to_owned(),
                detail: format!(
                    "published by {}; {} was published from {was}",
                    this.publisher.as_deref().unwrap_or("an unnamed user"),
                    before.version
                ),
            }),
            Some(now) if now != was => findings.push(Finding {
                rule: RULES[1].to_owned(),
                detail: format!("published from {now}; {} was from {was}", before.version),
            }),
            Some(_) => {}
        }
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

    /// `version`, published in the month `month` and at `seq` within it.
    fn v(version: &str, month: &str, seq: u8, identity: Option<&str>) -> Published {
        Published {
            version: version.to_owned(),
            created_at: format!("{month}-01T00:00:{seq:02}.000000Z"),
            identity: identity.map(str::to_owned),
            publisher: identity.is_none().then(|| "owner".to_owned()),
        }
    }

    fn rules(published: &[Published], version: &str) -> Vec<String> {
        detection(published, version)
            .expect("listed")
            .findings
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    const CORE: Option<&str> = Some("github rust-random/core");
    const RAND_CORE: Option<&str> = Some("github rust-random/rand_core");

    /// `rand_core` as crates.io listed it on 2026-10-15: four versions by hand after the first
    /// attested one, a new repository, then four backports by hand.
    fn rand_core() -> Vec<Published> {
        vec![
            v("0.9.3", "2025-02", 0, None),
            v("0.10.0-rc-2", "2025-10", 0, CORE),
            v("0.10.0-rc-3", "2025-12", 0, None),
            v("0.9.4", "2026-01", 1, None),
            v("0.9.5", "2026-01", 2, None),
            v("0.10.0-rc-4", "2026-01", 3, None),
            v("0.10.0-rc-5", "2026-01", 4, RAND_CORE),
            v("0.10.0", "2026-02", 0, RAND_CORE),
            v("0.4.3", "2026-09", 1, None),
            v("0.3.2", "2026-09", 2, None),
            v("0.2.3", "2026-09", 3, None),
            v("0.1.1", "2026-09", 4, None),
        ]
    }

    /// The counts of docs/engineering_decisions/0110-cargo-provenance.md for `rand_core`: 8 drops
    /// and 1 change, in whatever order the versions are listed.
    #[test]
    fn rand_core_has_eight_drops_and_one_change() {
        let mut published = rand_core();
        published.reverse();
        let fired: Vec<(String, Vec<String>)> = rand_core()
            .iter()
            .map(|p| (p.version.clone(), rules(&published, &p.version)))
            .filter(|(_, rules)| !rules.is_empty())
            .collect();
        let dropped = |v: &str| (v.to_owned(), vec![RULES[0].to_owned()]);
        assert_eq!(
            fired,
            [
                dropped("0.10.0-rc-3"),
                dropped("0.9.4"),
                dropped("0.9.5"),
                dropped("0.10.0-rc-4"),
                ("0.10.0-rc-5".to_owned(), vec![RULES[1].to_owned()]),
                dropped("0.4.3"),
                dropped("0.3.2"),
                dropped("0.2.3"),
                dropped("0.1.1"),
            ]
        );
    }

    /// `zip` 9.0.2 by hand between two attested releases: the one after it is compared with
    /// the attested one before it, not with 9.0.2.
    #[test]
    fn the_attested_version_after_a_drop_is_compared_with_the_last_attested_one() {
        let zip = Some("github zip-rs/zip2");
        let published = [
            v("9.0.1", "2026-10", 0, zip),
            v("9.0.2", "2026-10", 1, None),
            v("9.0.3", "2026-10", 2, zip),
        ];
        assert_eq!(rules(&published, "9.0.1"), Vec::<String>::new());
        assert_eq!(rules(&published, "9.0.2"), [RULES[0]]);
        assert_eq!(rules(&published, "9.0.3"), Vec::<String>::new());
        assert_eq!(detection(&published, "9.0.4"), None);
    }

    #[test]
    fn each_finding_says_who_and_from_where() {
        let published = rand_core();
        let detail = |version: &str| {
            detection(&published, version).unwrap().findings[0]
                .detail
                .clone()
        };
        assert_eq!(
            detail("0.9.4"),
            "published by owner; 0.10.0-rc-2 was published from github rust-random/core"
        );
        assert_eq!(
            detail("0.10.0-rc-5"),
            "published from github rust-random/rand_core; 0.10.0-rc-2 was from github rust-random/core"
        );
        let unnamed = [
            v("1.0.0", "2026-01", 0, CORE),
            Published {
                publisher: None,
                ..v("1.0.1", "2026-01", 1, None)
            },
        ];
        assert_eq!(
            detection(&unnamed, "1.0.1").unwrap().findings[0].detail,
            "published by an unnamed user; 1.0.0 was published from github rust-random/core"
        );
    }
}
