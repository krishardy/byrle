//! `byrle artifact show` and `byrle artifact export`: what each prints and exits with,
//! against any [`Analyses`].

use std::io::Write;

use super::{Artifact, Page};
use crate::analysis::store::Analyses;

/// Rows `export` reads per query.
pub const PAGE: usize = 1000;

/// Print the latest decision on each artifact `artifact` names to `out`, a JSON line each.
/// Returns 0, 1 when none is recorded, or 2 when the store or `out` fails.
pub async fn show(
    store: &dyn Analyses,
    artifact: &Artifact,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let found = match store.dispositions(artifact).await {
        Ok(found) => found,
        Err(e) => return failed(err, &e.to_string()),
    };
    if found.is_empty() {
        let _ = writeln!(err, "byrle artifact show: no decision is recorded on it");
        return 1;
    }
    for decided in &found {
        if let Err(e) = writeln!(out, "{}", decided.to_json()) {
            return failed(err, &e.to_string());
        }
    }
    0
}

/// Print every decision from `since` to `until`, days included, to `out`, oldest first, a
/// JSON line each. Returns 0, or 2 when the store or `out` fails.
pub async fn export(
    store: &dyn Analyses,
    since: Option<String>,
    until: Option<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut page = Page {
        after: 0,
        since,
        until,
        limit: PAGE,
    };
    loop {
        let rows = match store.decisions(&page).await {
            Ok(rows) => rows,
            Err(e) => return failed(err, &e.to_string()),
        };
        for (_, decided) in &rows {
            if let Err(e) = writeln!(out, "{}", decided.to_json()) {
                return failed(err, &e.to_string());
            }
        }
        let Some((id, _)) = rows.last() else {
            return 0;
        };
        page.after = *id;
    }
}

fn failed(err: &mut dyn Write, why: &str) -> u8 {
    let _ = writeln!(err, "byrle artifact: {why}");
    2
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::decision::Decided;
    use crate::analysis::decision::tests::decided;
    use crate::analysis::store::InProcess;
    use crate::analysis::store::tests::Broken;

    /// A writer that refuses every write.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    async fn holding(rows: &[Decided]) -> InProcess {
        let store = InProcess::new(PAGE * 3);
        store.put_decisions(rows).await.unwrap();
        store
    }

    fn lines(out: &[u8]) -> Vec<Decided> {
        String::from_utf8_lossy(out)
            .lines()
            .map(|line| Decided::from_json(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn show_prints_the_latest_decision_on_each_artifact() {
        let rows = [
            decided("a", "sha512-1"),
            decided("a", "sha512-2"),
            decided("a", "sha512-1"),
        ];
        let store = holding(&rows).await;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let version = Artifact::parse("pkg:npm/a@1.0.0").unwrap();
        assert_eq!(show(&store, &version, &mut out, &mut err).await, 0);
        assert_eq!(lines(&out), [rows[1].clone(), rows[2].clone()]);
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn show_exits_1_when_nothing_is_recorded_and_2_when_it_cannot_say() {
        let store = holding(&[]).await;
        let artifact = Artifact::Digest("sha512-1".into());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(show(&store, &artifact, &mut out, &mut err).await, 1);
        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&err),
            "byrle artifact show: no decision is recorded on it\n"
        );

        let mut err = Vec::new();
        assert_eq!(show(&Broken, &artifact, &mut out, &mut err).await, 2);
        assert!(String::from_utf8_lossy(&err).starts_with("byrle artifact: analysis store:"));

        let store = holding(&[decided("a", "sha512-1")]).await;
        let mut err = Vec::new();
        assert_eq!(show(&store, &artifact, &mut Closed, &mut err).await, 2);
        assert!(!err.is_empty());
    }

    /// More rows than one page are all printed, in order, between the days asked.
    #[tokio::test]
    async fn export_prints_every_decision_in_the_days_asked_across_pages() {
        let mut rows: Vec<Decided> = (0..PAGE + 2)
            .map(|n| decided(&format!("p{n}"), "sha512-1"))
            .collect();
        rows[0].at = "2026-10-01T00:00:00Z".into();
        let store = holding(&rows).await;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(export(&store, None, None, &mut out, &mut err).await, 0);
        assert_eq!(lines(&out), rows);

        let mut out = Vec::new();
        let since = Some("2026-10-02".to_owned());
        assert_eq!(export(&store, since, None, &mut out, &mut err).await, 0);
        assert_eq!(lines(&out), rows[1..]);

        let mut out = Vec::new();
        let until = Some("2026-10-01".to_owned());
        assert_eq!(export(&store, None, until, &mut out, &mut err).await, 0);
        assert_eq!(lines(&out), rows[..1]);
        assert!(err.is_empty());
    }

    #[tokio::test]
    async fn export_exits_2_when_the_store_or_the_output_fails() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(export(&Broken, None, None, &mut out, &mut err).await, 2);
        assert!(String::from_utf8_lossy(&err).starts_with("byrle artifact: analysis store:"));
        let store = holding(&[decided("a", "sha512-1")]).await;
        let mut err = Vec::new();
        assert_eq!(export(&store, None, None, &mut Closed, &mut err).await, 2);
        assert!(!err.is_empty());
    }
}
