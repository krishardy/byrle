//! A bounded queue one task writes in batches, so a request never waits on a write. The
//! rows a full queue or a failed write lose are counted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use futures_util::future::BoxFuture;
use tokio::sync::{mpsc, watch};
use tracing::warn;

/// How many rows wait to be written before more are dropped and counted.
pub const QUEUE: usize = 4096;

/// The most rows written in one statement.
pub const BATCH: usize = 256;

/// Where a batch of rows is written.
pub trait Sink<T>: Send + Sync {
    /// Write `rows` in one go. The error says why not.
    fn put<'a>(&'a self, rows: &'a [T]) -> BoxFuture<'a, Result<(), String>>;
}

/// The queue, started by the first row, and what became of the rows sent to it.
pub struct Batched<T> {
    queue: Arc<OnceLock<mpsc::Sender<T>>>,
    shared: Arc<Shared<T>>,
}

/// What the writing task shares with the senders.
struct Shared<T> {
    /// What a row is, such as `decisions`, for the warning when rows are lost.
    rows: &'static str,
    sink: Arc<dyn Sink<T>>,
    /// Rows dropped on a full queue or a failed write.
    unrecorded: AtomicU64,
    /// Rows written. What a test waits on.
    written: watch::Sender<u64>,
}

impl<T> Clone for Batched<T> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            shared: self.shared.clone(),
        }
    }
}

impl<T: Send + 'static> Batched<T> {
    /// A queue of `rows` into `sink`. The writing task starts with the first row.
    pub fn new(rows: &'static str, sink: Arc<dyn Sink<T>>) -> Self {
        Self {
            queue: Arc::default(),
            shared: Arc::new(Shared {
                rows,
                sink,
                unrecorded: AtomicU64::new(0),
                written: watch::Sender::new(0),
            }),
        }
    }

    /// Queue `row` to be written. On a full queue it is dropped and counted.
    pub fn send(&self, row: T) {
        let queue = self.queue.get_or_init(|| {
            let (queue, waiting) = mpsc::channel(QUEUE);
            tokio::spawn(write(self.shared.clone(), waiting));
            queue
        });
        if queue.try_send(row).is_err() {
            self.shared.lost(1, "the queue is full");
        }
    }

    /// Rows not written since the proxy started: dropped on a full queue, or in a write
    /// the sink failed.
    pub fn unrecorded(&self) -> u64 {
        self.shared.unrecorded.load(Ordering::Relaxed)
    }

    /// Wait until `count` rows have been written in all. Panics after 10 s: a test waits
    /// on it, and a write that never comes is a failure, not a hang.
    pub async fn written(&self, count: u64) {
        let mut written = self.shared.written.subscribe();
        let wait = written.wait_for(|n| *n >= count);
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .expect("the rows are written within 10 s")
            .expect("the queue outlives its subscriber");
    }
}

impl<T> Shared<T> {
    /// Count `count` rows lost, and why.
    fn lost(&self, count: usize, why: &str) {
        self.unrecorded.fetch_add(count as u64, Ordering::Relaxed);
        warn!(
            byrle.queue = self.rows,
            byrle.queue.dropped = count,
            "{} not recorded: {why}",
            self.rows
        );
    }
}

/// Write what arrives on `waiting`, up to [`BATCH`] at a time, until every sender is gone.
async fn write<T>(shared: Arc<Shared<T>>, mut waiting: mpsc::Receiver<T>) {
    let mut batch = Vec::with_capacity(BATCH);
    while waiting.recv_many(&mut batch, BATCH).await > 0 {
        match shared.sink.put(&batch).await {
            Ok(()) => shared.written.send_modify(|n| *n += batch.len() as u64),
            Err(e) => shared.lost(batch.len(), &e),
        }
        batch.clear();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    /// A sink that fails every write.
    pub struct Failing;

    impl<T> Sink<T> for Failing {
        fn put<'a>(&'a self, _: &'a [T]) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async { Err("the sink is closed".to_owned()) })
        }
    }

    /// Every path of a queue of `T`, run once for each row type the crate queues, since
    /// each is its own instantiation. `row` makes a row; `sink` keeps what it is given.
    pub async fn each_path<T: Send + 'static>(row: fn() -> T, sink: Arc<dyn Sink<T>>) {
        let queue = Batched::new("rows", sink);
        for _ in 0..=QUEUE {
            queue.send(row());
        }
        assert_eq!(
            queue.unrecorded(),
            1,
            "the writer has not run on this thread yet, so the queue holds {QUEUE}"
        );
        queue.written(QUEUE as u64).await;

        let failing = Batched::new("rows", Arc::new(Failing));
        failing.send(row());
        failing.send(row());
        for _ in 0..200 {
            if failing.unrecorded() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(failing.unrecorded(), 2);

        let (sender, waiting) = mpsc::channel::<T>(1);
        drop(sender);
        let ends = write(Batched::new("rows", Arc::new(Failing)).shared, waiting);
        tokio::time::timeout(std::time::Duration::from_secs(1), ends)
            .await
            .expect("the writer ends once every sender is gone");
    }
}
