//! `byrle status`: what this build does for each ecosystem, and which advisory streams
//! cover it. The two fail separately, so both are shown, each read from
//! [`crate::ecosystem::TABLE`] or the loaded snapshot.

use std::fmt::Write as _;

use crate::ecosystem::{Registry, TABLE, Upstreams};
use crate::intel::store::LoadedSnapshot;
use crate::intel::{Capability, capabilities_of};
use crate::policy::merge::{Rule, applies};

/// The report, as `byrle status` prints it.
///
/// `snapshot` is what the intel store last loaded, `None` when there is no store or it
/// holds nothing.
pub fn report(upstreams: &Upstreams, snapshot: Option<&LoadedSnapshot>) -> String {
    let mut out = String::from("byrle status\n");
    let _ = writeln!(
        out,
        "  intel snapshot   {}",
        match snapshot {
            Some(snapshot) => format!("{} taken {}", snapshot.digest, snapshot.taken_at),
            None => "none loaded: every check that reads advisories is unenforceable".to_owned(),
        }
    );
    for registry in TABLE {
        let _ = write!(out, "\n{}\n", registry.ecosystem.as_str());
        let _ = write!(out, "{}", adapter(registry, upstreams));
        let _ = write!(out, "{}", intel(registry, snapshot));
    }
    out
}

/// What this build reads and decides for one ecosystem.
fn adapter(registry: &Registry, upstreams: &Upstreams) -> String {
    let mut out = String::new();
    let line = |out: &mut String, label: &str, value: String| {
        let _ = writeln!(out, "  {label:<16} {value}");
    };
    line(
        &mut out,
        "upstream",
        crate::origin::without_credentials(upstreams.get(registry.ecosystem)),
    );
    line(
        &mut out,
        "documents",
        registry.documents.join(", ").to_string(),
    );
    line(
        &mut out,
        "publish times",
        match registry.publish_times {
            crate::ecosystem::PublishTimeSource::Record => "in the document".to_owned(),
            crate::ecosystem::PublishTimeSource::FullPackument => {
                "the full packument, fetched under a cooldown".to_owned()
            }
        },
    );
    line(
        &mut out,
        "versions",
        match registry.versions {
            crate::intel::range::VersionOrder::SemVer => "SemVer 2.0".to_owned(),
            crate::intel::range::VersionOrder::Pep440 => "PEP 440".to_owned(),
        },
    );
    let not_applicable: Vec<&str> = Rule::ALL
        .iter()
        .filter(|rule| !applies(registry.ecosystem.as_str(), **rule))
        .map(|rule| rule.as_str())
        .collect();
    line(
        &mut out,
        "checks",
        joined(&not_applicable).map_or("every one applies".to_owned(), |rules| {
            format!("no meaning here: {rules}")
        }),
    );
    line(
        &mut out,
        "clients",
        joined(&registry.clients.iter().map(|c| c.name).collect::<Vec<_>>())
            .unwrap_or("none checked by doctor".to_owned()),
    );
    line(
        &mut out,
        "client lockfiles",
        joined(
            &registry
                .lockfiles
                .iter()
                .map(|l| l.name)
                .collect::<Vec<_>>(),
        )
        .unwrap_or("none read".to_owned()),
    );
    out
}

/// Which streams cover this ecosystem, and what they let it decide.
fn intel(registry: &Registry, snapshot: Option<&LoadedSnapshot>) -> String {
    let mut out = String::new();
    let listed: Vec<&str> = registry
        .streams
        .iter()
        .map(|stream| stream.stream)
        .collect();
    let _ = writeln!(
        out,
        "  {:<16} {}",
        "streams",
        joined(&listed)
            .unwrap_or("none: this ecosystem is served with nothing to decide on".to_owned())
    );
    let Some(snapshot) = snapshot else {
        return out;
    };
    let loaded: Vec<&str> = snapshot
        .streams
        .iter()
        .map(|stream| stream.stream.as_str())
        .filter(|stream| listed.contains(stream))
        .collect();
    let _ = writeln!(
        out,
        "  {:<16} {}",
        "loaded",
        joined(&loaded).unwrap_or("none of them".to_owned())
    );
    let capabilities = capabilities_of(&snapshot.streams);
    let missing: Vec<&str> = [Capability::Match, Capability::Malware, Capability::Enrich]
        .into_iter()
        .filter(|capability| {
            !capabilities
                .uncovered_by(&[registry.ecosystem.as_str()], *capability)
                .is_empty()
        })
        .map(Capability::as_str)
        .collect();
    let _ = writeln!(
        out,
        "  {:<16} {}",
        "not covered",
        joined(&missing).unwrap_or("nothing: every capability has a stream".to_owned())
    );
    out
}

/// `items` separated by commas, `None` when there are none.
fn joined(items: &[&str]) -> Option<String> {
    (!items.is_empty()).then(|| items.join(", "))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::intel::refresh::StreamDigest;

    fn snapshot(streams: &[&str]) -> LoadedSnapshot {
        LoadedSnapshot {
            digest: "s1".to_owned(),
            taken_at: "2026-09-21T00:00:00Z".to_owned(),
            sources: Vec::new(),
            streams: streams
                .iter()
                .map(|stream| StreamDigest {
                    stream: (*stream).to_owned(),
                    sha256: "aa".to_owned(),
                    etag: None,
                    last_modified: None,
                })
                .collect(),
            unconfigured: Vec::new(),
        }
    }

    /// The whole report, so a row added to the table or a stream added to one shows up
    /// here as a diff to review rather than silently.
    #[test]
    fn the_report_renders_as_the_golden_file_says() {
        let loaded = snapshot(&["osv/npm", "osv/pypi", "datadog/npm", "cisa/kev"]);
        let out = report(&Upstreams::defaults(), Some(&loaded));
        crate::golden::assert_matches("status", "report.txt", &out);
    }

    /// Every ecosystem in the table is reported, with both axes.
    #[test]
    fn each_served_ecosystem_is_reported_on_both_axes() {
        let out = report(&Upstreams::defaults(), Some(&snapshot(&["osv/npm"])));
        for registry in TABLE {
            assert!(
                out.contains(registry.ecosystem.as_str()),
                "{} is missing: {out}",
                registry.ecosystem.as_str()
            );
        }
        assert!(out.contains("streams"), "{out}");
        assert!(out.contains("loaded           osv/npm"), "{out}");
        assert!(
            out.contains("none of them"),
            "no PyPI stream is loaded: {out}"
        );
        assert!(out.contains("not covered"), "{out}");
    }

    /// The not-applicable axis is per ecosystem: npm has no yank and PyPI no deprecation.
    #[test]
    fn a_check_with_no_meaning_for_an_ecosystem_is_named() {
        let out = report(&Upstreams::defaults(), None);
        let npm = out.split("\npypi\n").next().expect("npm comes first");
        assert!(npm.contains("no meaning here: yanked"), "{npm}");
        let pypi = out.split("\npypi\n").nth(1).expect("pypi is reported");
        assert!(pypi.contains("no meaning here: deprecated"), "{pypi}");
    }

    /// With no store, every check that reads advisories is unenforceable, and the report
    /// says so rather than leaving the line out.
    #[test]
    fn no_snapshot_is_said_out_loud() {
        let out = report(&Upstreams::defaults(), None);
        assert!(out.contains("none loaded"), "{out}");
        assert!(!out.contains("not covered"), "nothing to measure against");
    }

    /// A credential in an upstream URL is not printed, as everywhere else one is not.
    #[test]
    fn a_credential_in_an_upstream_is_not_printed() {
        let upstreams = Upstreams::defaults().with(
            crate::identity::Ecosystem::PyPI,
            "https://user:secret@example.test/simple",
        );
        let out = report(&upstreams, None);
        assert!(!out.contains("secret"), "{out}");
        assert!(out.contains("https://example.test/simple"), "{out}");
    }

    #[test]
    fn nothing_listed_is_none() {
        assert_eq!(joined(&[]), None);
        assert_eq!(joined(&["a", "b"]).as_deref(), Some("a, b"));
    }
}
