//! Where an artifact being analysed is written while the request that fetched it is open.
//!
//! The file is deleted when the [`Spooled`] holding it is dropped. [`Spool::open`] locks the
//! directory. See `docs/engineering_decisions/artifact-spool.md`.

use std::fs::{self, File, TryLockError};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use tokio::io::AsyncWriteExt;
use tracing::debug;

const LOCK: &str = ".lock";

/// Every spool file's name starts with this, and the sweep removes nothing else.
const PREFIX: &str = "artifact-";

/// The directory the spool uses when none is configured: `byrle-spool` in the OS
/// temporary directory. A directory of its own, because the sweep empties it.
pub fn default_dir() -> PathBuf {
    std::env::temp_dir().join("byrle-spool")
}

/// A spool directory, locked while this value lives.
#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    /// The most bytes one artifact may write. See [`crate::env::MAX_ARTIFACT_BYTES`].
    ceiling: u64,
    /// Numbers the files, unique within this process.
    next: AtomicU64,
    /// Held for its lock, which is released when the file is closed.
    _lock: File,
}

/// Why a spool directory could not be used.
#[derive(Debug)]
pub enum OpenError {
    /// Another process holds the directory's lock.
    Locked(PathBuf),
    /// The directory, its lock or a leftover file could not be created, read or removed.
    Io { path: PathBuf, error: io::Error },
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked(path) => write!(
                f,
                "{} is locked by another process; two proxies cannot share a spool directory",
                path.display()
            ),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for OpenError {}

/// Why an artifact was not written to the spool.
#[derive(Debug)]
pub enum WriteError {
    /// The artifact is larger than the ceiling; `claimed` when `Content-Length` said so.
    TooLarge { ceiling: u64, claimed: bool },
    /// The upstream body ended in an error.
    Upstream(String),
    /// The file could not be created or written.
    Io(io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge {
                ceiling,
                claimed: true,
            } => write!(
                f,
                "the artifact's Content-Length is over the {ceiling}-byte ceiling set by {}",
                crate::env::MAX_ARTIFACT_BYTES
            ),
            Self::TooLarge {
                ceiling,
                claimed: false,
            } => write!(
                f,
                "the artifact is over the {ceiling}-byte ceiling set by {}",
                crate::env::MAX_ARTIFACT_BYTES
            ),
            Self::Upstream(why) => write!(f, "the upstream body failed: {why}"),
            Self::Io(e) => write!(f, "the spool could not be written: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl Spool {
    /// Open `dir`, creating it with mode `0700` if it does not exist, lock it, and remove
    /// the spool files a previous process left. Returns the spool and how many files were
    /// removed.
    pub fn open(dir: &Path, ceiling: u64) -> Result<(Self, usize), OpenError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(at(dir))?;
        let lock_path = dir.join(LOCK);
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(at(&lock_path))?;
        lock.try_lock()
            .map_err(|e| lock_error(dir, &lock_path, e))?;
        let swept = sweep(dir).map_err(at(dir))?;
        let spool = Self {
            dir: dir.to_owned(),
            ceiling,
            next: AtomicU64::new(0),
            _lock: lock,
        };
        Ok((spool, swept))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn ceiling(&self) -> u64 {
        self.ceiling
    }

    /// Write `body` to a new file, passing each chunk to `observe` as it is written.
    ///
    /// `claimed` is the response's `Content-Length`. Over the ceiling, nothing is written.
    /// The ceiling is enforced again on the bytes that arrive, because the header is a
    /// claim. On any error the file is already deleted.
    pub async fn write<S, E>(
        &self,
        body: S,
        claimed: Option<u64>,
        mut observe: impl FnMut(&[u8]) + Send,
    ) -> Result<Spooled, WriteError>
    where
        S: Stream<Item = Result<Bytes, E>> + Send,
        E: std::fmt::Display,
    {
        let body = body.map(|chunk| chunk.map_err(|e| e.to_string()));
        self.write_chunks(std::pin::pin!(body), claimed, &mut observe)
            .await
    }

    /// [`Spool::write`] for one stream type and one observer type, so there is one body.
    async fn write_chunks(
        &self,
        body: std::pin::Pin<&mut (dyn Stream<Item = Result<Bytes, String>> + Send)>,
        claimed: Option<u64>,
        observe: &mut (dyn FnMut(&[u8]) + Send),
    ) -> Result<Spooled, WriteError> {
        if claimed.is_some_and(|length| length > self.ceiling) {
            return Err(WriteError::TooLarge {
                ceiling: self.ceiling,
                claimed: true,
            });
        }
        let number = self.next.fetch_add(1, Ordering::Relaxed);
        let path = self
            .dir
            .join(format!("{PREFIX}{}-{number}", std::process::id()));
        let file = File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(WriteError::Io)?;
        debug!(file.path = %path.display(), "spooling an artifact");
        let mut spooled = Spooled { path, len: 0 };
        let mut file = tokio::fs::File::from_std(file);
        spooled.len = copy(body, &mut file, self.ceiling, observe).await?;
        Ok(spooled)
    }
}

/// Write `body` to `out`, passing each chunk to `observe` first, and give how many bytes it
/// held. Past `ceiling` bytes it stops with [`WriteError::TooLarge`].
async fn copy(
    mut body: std::pin::Pin<&mut (dyn Stream<Item = Result<Bytes, String>> + Send)>,
    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    ceiling: u64,
    observe: &mut (dyn FnMut(&[u8]) + Send),
) -> Result<u64, WriteError> {
    let mut len = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(WriteError::Upstream)?;
        len += chunk.len() as u64;
        if len > ceiling {
            return Err(WriteError::TooLarge {
                ceiling,
                claimed: false,
            });
        }
        observe(&chunk);
        out.write_all(&chunk).await.map_err(WriteError::Io)?;
    }
    out.flush().await.map_err(WriteError::Io)?;
    Ok(len)
}

/// What a lock that could not be taken means: another process holds it, or locking failed.
fn lock_error(dir: &Path, lock_path: &Path, e: TryLockError) -> OpenError {
    match e {
        TryLockError::WouldBlock => OpenError::Locked(dir.to_owned()),
        TryLockError::Error(error) => OpenError::Io {
            path: lock_path.to_owned(),
            error,
        },
    }
}

/// One artifact in the spool. The file is deleted when this is dropped.
#[derive(Debug)]
pub struct Spooled {
    path: PathBuf,
    len: u64,
}

impl Spooled {
    /// How many bytes were written.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The artifact, read from its first byte.
    pub fn reader(&self) -> io::Result<File> {
        File::open(&self.path)
    }
}

impl Drop for Spooled {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path) {
            tracing::warn!(file.path = %self.path.display(), error.message = %e, "a spool file was not deleted");
        }
    }
}

/// Remove every spool file in `dir`. Only regular files named with [`PREFIX`]: never the
/// lock, a directory, or a symlink, whatever it is named.
fn sweep(dir: &Path) -> io::Result<usize> {
    let mut swept = 0;
    for entry in fs::read_dir(dir)?.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_file())
            && entry.file_name().to_string_lossy().starts_with(PREFIX)
        {
            fs::remove_file(entry.path())?;
            swept += 1;
        }
    }
    Ok(swept)
}

fn at(path: &Path) -> impl FnOnce(io::Error) -> OpenError + '_ {
    move |error| OpenError::Io {
        path: path.to_owned(),
        error,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::util::test_support::tempdir;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    fn chunks(parts: &[&'static [u8]]) -> impl Stream<Item = Result<Bytes, String>> {
        futures_util::stream::iter(
            parts
                .iter()
                .map(|part| Ok(Bytes::from_static(part)))
                .collect::<Vec<_>>(),
        )
    }

    /// Every file in the directory but the lock, sorted.
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("reads")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| name != LOCK)
            .collect();
        names.sort();
        names
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("stats").permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn an_artifact_is_written_read_back_and_deleted_when_dropped() {
        let dir = tempdir("spool-write");
        let (spool, swept) = Spool::open(&dir, 1024).expect("opens");
        assert_eq!(swept, 0);
        assert_eq!(spool.dir(), dir);
        assert_eq!(spool.ceiling(), 1024);
        let mut seen = Vec::new();
        let spooled = spool
            .write(chunks(&[b"abc", b"", b"def"]), Some(6), |c| {
                seen.extend_from_slice(c)
            })
            .await
            .expect("writes");
        assert_eq!((spooled.len(), spooled.is_empty()), (6, false));
        assert_eq!(seen, b"abcdef");

        let name = listing(&dir).pop().expect("one file");
        assert!(name.starts_with(PREFIX), "{name}");
        assert_eq!(mode(&dir.join(&name)), 0o600);
        let mut read = String::new();
        spooled
            .reader()
            .expect("opens")
            .read_to_string(&mut read)
            .expect("reads");
        assert_eq!(read, "abcdef");

        drop(spooled);
        assert_eq!(listing(&dir), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn two_artifacts_at_once_are_two_files() {
        let dir = tempdir("spool-two");
        let (spool, _) = Spool::open(&dir, 1024).expect("opens");
        let first = spool.write(chunks(&[b"a"]), None, |_| {}).await;
        let second = spool.write(chunks(&[]), None, |_| {}).await;
        let (first, second) = (first.expect("writes"), second.expect("writes"));
        assert!(second.is_empty());
        assert_eq!(listing(&dir).len(), 2);
        drop((first, second));
        assert_eq!(listing(&dir), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_claimed_length_over_the_ceiling_writes_nothing() {
        let dir = tempdir("spool-claimed");
        let (spool, _) = Spool::open(&dir, 4).expect("opens");
        let mut observed = false;
        let e = spool
            .write(chunks(&[b"abcde"]), Some(5), |_| observed = true)
            .await
            .expect_err("over the ceiling");
        assert!(
            matches!(
                e,
                WriteError::TooLarge {
                    ceiling: 4,
                    claimed: true
                }
            ),
            "{e}"
        );
        assert_eq!(
            e.to_string(),
            format!(
                "the artifact's Content-Length is over the 4-byte ceiling set by {}",
                crate::env::MAX_ARTIFACT_BYTES
            )
        );
        assert!(!observed);
        assert_eq!(listing(&dir), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    /// `Content-Length` is a claim, so the bytes are counted as they arrive. An artifact
    /// exactly at the ceiling is written.
    #[tokio::test]
    async fn bytes_past_the_ceiling_are_refused_whatever_the_length_claimed() {
        let dir = tempdir("spool-actual");
        let (spool, _) = Spool::open(&dir, 4).expect("opens");
        let at_ceiling = spool.write(chunks(&[b"ab", b"cd"]), Some(4), |_| {}).await;
        assert_eq!(at_ceiling.expect("at the ceiling").len(), 4);

        let e = spool
            .write(chunks(&[b"ab", b"cde"]), Some(1), |_| {})
            .await
            .expect_err("over the ceiling");
        assert!(
            matches!(
                e,
                WriteError::TooLarge {
                    ceiling: 4,
                    claimed: false
                }
            ),
            "{e}"
        );
        assert_eq!(
            e.to_string(),
            format!(
                "the artifact is over the 4-byte ceiling set by {}",
                crate::env::MAX_ARTIFACT_BYTES
            )
        );
        assert_eq!(listing(&dir), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_body_that_fails_leaves_no_file() {
        let dir = tempdir("spool-upstream");
        let (spool, _) = Spool::open(&dir, 1024).expect("opens");
        let body = futures_util::stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Err("connection reset".to_owned()),
        ]);
        let e = spool
            .write(body, None, |_| {})
            .await
            .expect_err("the body failed");
        assert!(matches!(e, WriteError::Upstream(_)), "{e}");
        assert_eq!(e.to_string(), "the upstream body failed: connection reset");
        assert_eq!(listing(&dir), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    /// The directory removed under a running proxy: the file cannot be created, which the
    /// proxy answers as not ready.
    #[tokio::test]
    async fn a_file_that_cannot_be_created_is_an_io_error() {
        let dir = tempdir("spool-gone");
        let (spool, _) = Spool::open(&dir, 1024).expect("opens");
        fs::remove_dir_all(&dir).expect("removes");
        let e = spool
            .write(chunks(&[b"abc"]), None, |_| {})
            .await
            .expect_err("no directory");
        assert!(matches!(e, WriteError::Io(_)), "{e}");
        assert!(
            e.to_string()
                .starts_with("the spool could not be written: "),
            "{e}"
        );
    }

    /// Deleting a file that is already gone is logged, not a panic.
    #[tokio::test]
    async fn a_file_removed_before_its_guard_is_dropped_is_not_a_panic() {
        let dir = tempdir("spool-removed");
        let (spool, _) = Spool::open(&dir, 1024).expect("opens");
        let spooled = spool.write(chunks(&[b"a"]), None, |_| {}).await;
        let spooled = spooled.expect("writes");
        for name in listing(&dir) {
            fs::remove_file(dir.join(name)).expect("removes");
        }
        drop(spooled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_open_is_refused_until_the_first_is_dropped() {
        let dir = tempdir("spool-lock");
        let (first, _) = Spool::open(&dir, 1024).expect("opens");
        let e = Spool::open(&dir, 1024).expect_err("the first holds the lock");
        assert!(matches!(&e, OpenError::Locked(path) if path == &dir), "{e}");
        assert_eq!(
            e.to_string(),
            format!(
                "{} is locked by another process; two proxies cannot share a spool directory",
                dir.display()
            )
        );
        drop(first);
        Spool::open(&dir, 1024).expect("opens once the first is dropped");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A spool file left by a process that ended is removed. A symlink and a directory
    /// named like one are left alone.
    #[test]
    fn opening_removes_only_the_spool_files_left_behind() {
        let dir = tempdir("spool-sweep");
        fs::write(dir.join("artifact-1-0"), b"left").expect("writes");
        fs::write(dir.join("artifact-1-1"), b"left").expect("writes");
        fs::write(dir.join("notes.txt"), b"keep").expect("writes");
        let outside = tempdir("spool-sweep-target");
        fs::write(outside.join("kept"), b"keep").expect("writes");
        std::os::unix::fs::symlink(outside.join("kept"), dir.join("artifact-link")).expect("links");
        fs::create_dir(dir.join("artifact-dir")).expect("creates");

        let (_spool, swept) = Spool::open(&dir, 1024).expect("opens");
        assert_eq!(swept, 2);
        assert_eq!(
            listing(&dir),
            ["artifact-dir", "artifact-link", "notes.txt"]
        );
        assert!(outside.join("kept").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_lock_that_cannot_be_opened_is_an_error_naming_it() {
        let dir = tempdir("spool-lock-dir");
        fs::create_dir(dir.join(LOCK)).expect("creates");
        let e = Spool::open(&dir, 1024).expect_err("the lock is a directory");
        assert!(
            matches!(&e, OpenError::Io { path, .. } if path == &dir.join(LOCK)),
            "{e}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A leftover file the proxy cannot remove refuses the start, rather than leaving
    /// artifact bytes on disk nobody is told about.
    #[test]
    fn a_leftover_file_that_cannot_be_removed_refuses_the_open() {
        let dir = tempdir("spool-stuck");
        fs::write(dir.join(LOCK), b"").expect("writes");
        fs::write(dir.join("artifact-1-0"), b"left").expect("writes");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("chmods");
        let e = Spool::open(&dir, 1024).expect_err("the directory is read-only");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmods");
        assert!(
            matches!(&e, OpenError::Io { path, .. } if path == &dir),
            "{e}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_it_creates_is_readable_by_its_owner_only() {
        let parent = tempdir("spool-mode");
        let dir = parent.join("a").join("spool");
        let (_spool, _) = Spool::open(&dir, 1024).expect("opens");
        assert_eq!(mode(&dir), 0o700);
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_directory_that_cannot_be_created_is_an_error_naming_it() {
        let parent = tempdir("spool-blocked");
        let blocker = parent.join("file");
        fs::write(&blocker, b"").expect("writes");
        let dir = blocker.join("spool");
        let e = Spool::open(&dir, 1024).expect_err("a file is in the way");
        assert!(
            matches!(&e, OpenError::Io { path, .. } if path == &dir),
            "{e}"
        );
        assert!(e.to_string().starts_with(&dir.display().to_string()), "{e}");
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn the_default_is_a_directory_of_its_own_in_the_temporary_directory() {
        assert_eq!(default_dir(), std::env::temp_dir().join("byrle-spool"));
    }

    /// A writer that refuses its writes, or accepts them and refuses the flush.
    struct Refusing {
        at_flush: bool,
    }

    impl tokio::io::AsyncWrite for Refusing {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(if self.at_flush {
                Ok(bytes.len())
            } else {
                Err(io::Error::other("refused"))
            })
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Err(io::Error::other("refused")))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A write or a flush the disk refuses is an I/O error.
    #[tokio::test]
    async fn a_write_or_flush_that_fails_is_an_io_error() {
        for at_flush in [false, true] {
            let body = futures_util::stream::iter(vec![Ok(Bytes::from_static(b"abc"))]);
            let result = copy(
                std::pin::pin!(body),
                &mut Refusing { at_flush },
                1024,
                &mut |_| {},
            )
            .await;
            assert!(
                matches!(result, Err(WriteError::Io(_))),
                "at_flush {at_flush}"
            );
        }
    }

    /// Another holder of the lock, and a lock that failed, are told apart.
    #[test]
    fn a_lock_that_is_held_or_failed_says_which() {
        let dir = Path::new("/spool");
        let lock = dir.join(LOCK);
        assert!(matches!(
            lock_error(dir, &lock, TryLockError::WouldBlock),
            OpenError::Locked(_)
        ));
        assert!(matches!(
            lock_error(
                dir,
                &lock,
                TryLockError::Error(io::Error::other("no locks"))
            ),
            OpenError::Io { .. }
        ));
    }

    /// A spool directory whose lock cannot be created, or which cannot be listed, does not
    /// open.
    #[test]
    fn a_directory_that_cannot_be_locked_or_listed_does_not_open() {
        use crate::util::test_support::{Restricted, tempdir};
        for (label, mode) in [("spool-read-only", 0o555), ("spool-unlistable", 0o300)] {
            let dir = tempdir(label);
            let restricted = Restricted::new(&dir, mode);
            let opened = Spool::open(&dir, 1024);
            drop(restricted);
            assert!(matches!(opened, Err(OpenError::Io { .. })), "{label}");
        }
    }
}
