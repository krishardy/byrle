//! Writing each decision to the analysis store through a bounded queue, in batches, so a
//! request never waits on the write. See docs/engineering_decisions/artifact-decisions.md.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use jiff::civil::Date;
use tracing::{info, warn};

use super::Analyser;
use crate::analysis::decision::{Artifact, Decided, Page};
use crate::analysis::store::{Analyses, AnalysisError};
use crate::util::batched::{Batched, Sink};

/// How often decisions past their retention period are deleted.
const FORGET_EVERY: std::time::Duration = std::time::Duration::from_secs(86_400);

/// The analysis store, as where queued decisions are written.
struct Decisions(Arc<dyn Analyses>);

impl Sink<Decided> for Decisions {
    fn put<'a>(&'a self, rows: &'a [Decided]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.0.put_decisions(rows).await.map_err(|e| e.to_string()) })
    }
}

/// The queue of decisions to write to `store`.
pub(super) fn recorder(store: Arc<dyn Analyses>) -> Batched<Decided> {
    Batched::new("decisions", Arc::new(Decisions(store)))
}

impl Analyser {
    /// Queue `decided` to be written. On a full queue it is dropped and counted.
    pub fn record(&self, decided: Decided) {
        self.recorder.send(decided);
    }

    /// Decisions not written since the proxy started: dropped on a full queue, or in a
    /// write the store failed.
    pub fn decisions_unrecorded(&self) -> u64 {
        self.recorder.unrecorded()
    }

    /// The latest decision on each artifact `artifact` names.
    pub async fn dispositions(&self, artifact: &Artifact) -> Result<Vec<Decided>, AnalysisError> {
        self.store.dispositions(artifact).await
    }

    /// The decisions `page` asks for, oldest first, with their row ids.
    pub async fn decisions(&self, page: &Page) -> Result<Vec<(i64, Decided)>, AnalysisError> {
        self.store.decisions(page).await
    }

    /// Delete the decisions older than `retention_days` now, then once a day.
    pub fn forget_decisions_daily(&self, retention_days: u32) -> tokio::task::JoinHandle<()> {
        let store = self.store.clone();
        tokio::spawn(async move {
            let mut each = tokio::time::interval(FORGET_EVERY);
            loop {
                each.tick().await;
                forget(store.as_ref(), crate::rotation::today(), retention_days).await;
            }
        })
    }

    /// Wait until `count` decisions have been written in all. Panics after 10 s.
    pub async fn decisions_written(&self, count: u64) {
        self.recorder.written(count).await;
    }
}

/// Delete the decisions made before the day `retention_days` before `today`, so that day's
/// are kept. Returns how many, or 0 when the store fails, which is warned about.
async fn forget(store: &dyn Analyses, today: Date, retention_days: u32) -> u64 {
    let before = jiff::Span::new()
        .try_days(i64::from(retention_days))
        .and_then(|days| today.checked_sub(days))
        .unwrap_or(Date::MIN)
        .to_string();
    match store.forget_decisions(&before).await {
        Ok(count) => {
            info!(byrle.decisions.deleted = count, byrle.decisions.before = %before, "decisions past their retention period deleted");
            count
        }
        Err(e) => {
            warn!(byrle.reason = %e, "decisions past their retention period not deleted");
            0
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::analysis::decision::tests::decided;
    use crate::analysis::store::InProcess;
    use crate::analysis::store::tests::Broken;

    fn analyser(label: &str, store: Arc<dyn Analyses>) -> Analyser {
        crate::analysis::run::tests::analyser(label, 1 << 20, store)
    }

    #[tokio::test]
    async fn each_decision_is_written_in_order() {
        let analyser = analyser("recording-order", Arc::new(InProcess::new(16)));
        for n in 1..=3 {
            analyser.record(decided(&format!("p{n}"), "sha512-x"));
        }
        analyser.decisions_written(3).await;
        let page = Page {
            after: 0,
            since: None,
            until: None,
            limit: 10,
        };
        let names: Vec<String> = analyser
            .decisions(&page)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, d)| d.name)
            .collect();
        assert_eq!(names, ["p1", "p2", "p3"]);
        let latest = analyser
            .dispositions(&Artifact::Digest("sha512-x".into()))
            .await
            .unwrap();
        assert_eq!(latest[0].name, "p3");
        assert_eq!(analyser.decisions_unrecorded(), 0);
    }

    #[tokio::test]
    async fn a_failed_write_is_counted() {
        let analyser = analyser("recording-failed", Arc::new(Broken));
        analyser.record(decided("a", "sha512-x"));
        analyser.record(decided("b", "sha512-x"));
        for _ in 0..200 {
            if analyser.decisions_unrecorded() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(analyser.decisions_unrecorded(), 2);
    }

    /// A decision on the day `retention_days` before today is kept, and one the day before
    /// that is deleted. A store that fails deletes none.
    #[tokio::test]
    async fn decisions_before_the_retention_period_are_deleted() {
        let store = InProcess::new(16);
        let mut rows = [decided("old", "sha512-x"), decided("kept", "sha512-x")];
        rows[0].at = "2026-10-02T23:59:59Z".into();
        rows[1].at = "2026-10-03T00:00:00Z".into();
        store.put_decisions(&rows).await.unwrap();
        let today = jiff::civil::date(2026, 10, 13);
        assert_eq!(forget(&store, today, 10).await, 1);
        assert_eq!(forget(&store, today, 10).await, 0);
        assert_eq!(forget(&store, today, u32::MAX).await, 0);
        let page = Page {
            after: 0,
            since: None,
            until: None,
            limit: 10,
        };
        let left = store.decisions(&page).await.unwrap();
        assert_eq!(left, [(2, rows[1].clone())]);
        assert_eq!(forget(&Broken, today, 10).await, 0);
    }

    /// The task deletes at once, without waiting a day.
    #[tokio::test]
    async fn the_daily_deletion_runs_at_start() {
        let store = Arc::new(InProcess::new(16));
        let mut old = decided("old", "sha512-x");
        old.at = "2000-01-01T00:00:00Z".into();
        store.put_decisions(&[old]).await.unwrap();
        let analyser = analyser("recording-forget", store.clone());
        let task = analyser.forget_decisions_daily(1);
        let page = Page {
            after: 0,
            since: None,
            until: None,
            limit: 10,
        };
        for _ in 0..200 {
            if store.decisions(&page).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        task.abort();
        assert!(store.decisions(&page).await.unwrap().is_empty());
    }

    /// Every path of the queue, for its instantiation on decisions.
    #[tokio::test(flavor = "current_thread")]
    async fn the_queue_of_decisions_takes_each_path() {
        let store = Arc::new(InProcess::new(crate::util::batched::QUEUE + 2));
        crate::util::batched::tests::each_path(
            || decided("a", "sha512-x"),
            Arc::new(Decisions(store)),
        )
        .await;
    }
}
