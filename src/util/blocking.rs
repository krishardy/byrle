//! Work on a blocking thread that stops reading once the future awaiting it is dropped, as
//! `tokio::time::timeout` drops it at a deadline. A dropped `spawn_blocking` future does not
//! stop its thread on its own.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// What a read past its stop says.
pub const STOPPED: &str = "stopped: the work reading this was abandoned";

/// Set once the future awaiting the work is dropped.
#[derive(Clone)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    /// `inner`, whose reads fail once this is set.
    pub fn reading<R>(&self, inner: R) -> Stoppable<R> {
        Stoppable {
            inner,
            stop: self.clone(),
        }
    }
}

/// A reader that fails each read after its [`Stop`] is set.
pub struct Stoppable<R> {
    inner: R,
    stop: Stop,
}

impl<R: Read> Read for Stoppable<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stop.0.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, STOPPED));
        }
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for Stoppable<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// Sets its [`Stop`] when dropped.
struct OnDrop(Arc<AtomicBool>);

impl Drop for OnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// `work` on a blocking thread, given the [`Stop`] set when this future is dropped.
/// Errors when `work` panics.
pub async fn run<T: Send + 'static>(
    work: impl FnOnce(Stop) -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let stop = Arc::new(AtomicBool::new(false));
    let _set = OnDrop(stop.clone());
    tokio::task::spawn_blocking(move || work(Stop(stop))).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// How long [`read_endlessly`] reads unstopped, so a test that fails ends.
    const UNSTOPPED: Duration = Duration::from_secs(10);

    /// Read `file` from its start over and over until a read fails, or [`UNSTOPPED`]
    /// passes, putting what the failure said in `said`.
    pub fn read_endlessly(file: &mut dyn crate::ecosystem::Source, said: &Mutex<Option<String>>) {
        let began = Instant::now();
        let why = loop {
            if began.elapsed() > UNSTOPPED {
                break "read without being stopped".to_owned();
            }
            if let Err(e) = file.read(&mut [0u8; 1]).and_then(|_| file.rewind()) {
                break e.to_string();
            }
        };
        *said.lock().unwrap() = Some(why);
    }

    /// What [`read_endlessly`] put in `said`, once it has.
    pub async fn stopped(said: &Mutex<Option<String>>) -> String {
        loop {
            if let Some(why) = said.lock().unwrap().clone() {
                return why;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Work reading without end stops once the future awaiting it is dropped at a timeout.
    #[tokio::test]
    async fn work_stops_reading_once_its_future_is_dropped() {
        static SAID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        let work = run(|stop| {
            let mut endless = stop.reading(std::io::Cursor::new(vec![0u8; 8]));
            testing::read_endlessly(&mut endless, &SAID);
        });
        let timed_out = tokio::time::timeout(Duration::from_millis(50), work).await;
        assert!(timed_out.is_err());
        assert_eq!(testing::stopped(&SAID).await, STOPPED);
        let kind = Stop(Arc::new(AtomicBool::new(true)))
            .reading(std::io::empty())
            .read(&mut [0u8; 1])
            .unwrap_err()
            .kind();
        assert_eq!(kind, std::io::ErrorKind::TimedOut);
    }

    /// Work that ends is answered, and its reader seeks as the one it wraps.
    #[tokio::test]
    async fn work_that_ends_is_answered() {
        let read = run(|stop| {
            let mut file = stop.reading(std::io::Cursor::new(b"abc".to_vec()));
            file.seek(SeekFrom::Start(1)).unwrap();
            let mut rest = String::new();
            file.read_to_string(&mut rest).unwrap();
            rest
        })
        .await;
        assert_eq!(read.unwrap(), "bc");
    }
}
