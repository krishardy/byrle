//! Writing each decision to the analysis store through a bounded queue, in batches, so a
//! request never waits on the write. See docs/engineering_decisions/artifact-decisions.md.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::{mpsc, watch};
use tracing::warn;

use super::Analyser;
use crate::analysis::decision::{Artifact, Decided, Page};
use crate::analysis::store::{Analyses, AnalysisError};

/// How many decisions wait to be written before more are dropped and counted.
pub const QUEUE: usize = 4096;

/// The most decisions written in one statement.
pub const BATCH: usize = 256;

/// The queue, started by the first decision, and what became of the decisions sent to it.
#[derive(Clone, Default)]
pub(super) struct Recorder {
    queue: Arc<OnceLock<mpsc::Sender<Decided>>>,
    /// Decisions dropped on a full queue or a failed write.
    unrecorded: Arc<AtomicU64>,
    /// Decisions written. What a test waits on.
    written: Arc<watch::Sender<u64>>,
}

impl Analyser {
    /// Queue `decided` to be written. On a full queue it is dropped and counted.
    pub fn record(&self, decided: Decided) {
        let recorder = &self.recorder;
        let queue = recorder.queue.get_or_init(|| {
            let (queue, waiting) = mpsc::channel(QUEUE);
            tokio::spawn(write(
                self.store.clone(),
                waiting,
                recorder.unrecorded.clone(),
                recorder.written.clone(),
            ));
            queue
        });
        if queue.try_send(decided).is_err() {
            lost(&recorder.unrecorded, 1, "the queue is full");
        }
    }

    /// Decisions not written since the proxy started: dropped on a full queue, or in a
    /// write the store failed.
    pub fn decisions_unrecorded(&self) -> u64 {
        self.recorder.unrecorded.load(Ordering::Relaxed)
    }

    /// The latest decision on each artifact `artifact` names.
    pub async fn dispositions(&self, artifact: &Artifact) -> Result<Vec<Decided>, AnalysisError> {
        self.store.dispositions(artifact).await
    }

    /// The decisions `page` asks for, oldest first, with their row ids.
    pub async fn decisions(&self, page: &Page) -> Result<Vec<(i64, Decided)>, AnalysisError> {
        self.store.decisions(page).await
    }

    /// Wait until `count` decisions have been written in all. Panics after 10 s: a test
    /// waits on it, and a write that never comes is a failure, not a hang.
    pub async fn decisions_written(&self, count: u64) {
        let mut written = self.recorder.written.subscribe();
        let wait = written.wait_for(|n| *n >= count);
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .expect("the decisions are written within 10 s")
            .expect("the recorder outlives its subscriber");
    }
}

/// Count `count` decisions lost, and why. The total is `decisions_unrecorded` on health.
fn lost(unrecorded: &AtomicU64, count: usize, why: &str) {
    unrecorded.fetch_add(count as u64, Ordering::Relaxed);
    warn!(
        byrle.decisions.dropped = count,
        "decisions not recorded: {why}"
    );
}

/// Write what arrives on `waiting`, up to [`BATCH`] at a time, until every sender is gone.
async fn write(
    store: Arc<dyn Analyses>,
    mut waiting: mpsc::Receiver<Decided>,
    unrecorded: Arc<AtomicU64>,
    written: Arc<watch::Sender<u64>>,
) {
    let mut batch = Vec::with_capacity(BATCH);
    while waiting.recv_many(&mut batch, BATCH).await > 0 {
        match store.put_decisions(&batch).await {
            Ok(()) => written.send_modify(|n| *n += batch.len() as u64),
            Err(e) => lost(&unrecorded, batch.len(), &e.to_string()),
        }
        batch.clear();
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

    /// The writer ends once every sender is gone, rather than asking again forever.
    #[tokio::test]
    async fn the_writer_ends_when_the_queue_closes() {
        let (queue, waiting) = mpsc::channel(1);
        drop(queue);
        let ends = write(
            Arc::new(InProcess::new(1)),
            waiting,
            Arc::default(),
            Arc::new(watch::Sender::new(0)),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), ends)
            .await
            .expect("the writer ends");
    }

    /// A full queue drops the decision rather than making the request wait.
    #[tokio::test(flavor = "current_thread")]
    async fn a_full_queue_drops_and_counts() {
        let analyser = analyser("recording-full", Arc::new(InProcess::new(QUEUE + 2)));
        for _ in 0..=QUEUE {
            analyser.record(decided("a", "sha512-x"));
        }
        assert_eq!(
            analyser.decisions_unrecorded(),
            1,
            "the writer has not run on this thread yet, so the queue holds {QUEUE}"
        );
        analyser.decisions_written(QUEUE as u64).await;
    }
}
