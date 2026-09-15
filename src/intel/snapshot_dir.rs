//! Snapshots kept as files, so one can be read after Postgres has replaced it.
//!
//! Postgres keeps the latest load only. `waharoa refresh` also writes each load to the
//! snapshot directory, and every file there is named by the digest of what it contains:
//!
//! | File | Contains | Named by |
//! |---|---|---|
//! | `<hex>.rows.gz` | one source's [`load::encode`] output, gzipped | its digest, `intel_source.digest` |
//! | `<hex>.snapshot` | [`load::manifest`]: one `source digest` line per source | its digest, the snapshot id |
//!
//! A source whose rows did not change between two snapshots is one rows file. Reading a file
//! checks what it contains against its name.
//!
//! [`SnapshotDir::open`] locks `.lock` in the directory until the value is dropped. `waharoa
//! refresh` holds it from before it writes rows until it has written the snapshot and pruned,
//! so a prune never removes rows another refresh has written and not yet named in a snapshot.
//!
//! See docs/engineering_decisions/snapshot-identity.md.

use super::load::{self, Decoder, Encoded, Row};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const ROWS: &str = ".rows.gz";
const SNAPSHOT: &str = ".snapshot";
/// A file being written, renamed to its real name once it is complete.
const PARTIAL: &str = ".partial";
const LOCK: &str = ".lock";

/// A snapshot directory, locked while this value lives.
#[derive(Debug)]
pub struct SnapshotDir {
    path: PathBuf,
    /// Held for its lock, which is released when the file is closed. `None` from
    /// [`SnapshotDir::open_to_read`].
    _lock: Option<File>,
}

/// What [`SnapshotDir::prune`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pruned {
    pub snapshots: usize,
    pub rows: usize,
}

/// Why the snapshot directory could not be used.
#[derive(Debug)]
pub enum KeptError {
    Io {
        path: PathBuf,
        error: io::Error,
    },
    /// What a file contains does not hash to the digest in its name.
    Mismatch {
        path: PathBuf,
        digest: String,
    },
    /// Not `sha256:` and 64 lowercase hex digits.
    NotADigest(String),
    /// A snapshot line that is not a source and a digest.
    NotALine {
        path: PathBuf,
        line: String,
    },
    /// A snapshot names rows that are not in the directory.
    Missing {
        source: String,
        digest: String,
    },
    /// A rows file whose contents match its name and are not rows of the source named.
    Undecodable {
        path: PathBuf,
        reason: String,
    },
    /// A stored range whose versions do not parse. The loader writes none.
    Range {
        digest: String,
        advisory_id: String,
    },
}

impl std::fmt::Display for KeptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Mismatch { path, digest } => write!(
                f,
                "{}: contents hash to {digest}, not the digest in its name",
                path.display()
            ),
            Self::NotADigest(value) => {
                write!(f, "`{value}` is not `sha256:` and 64 lowercase hex digits")
            }
            Self::NotALine { path, line } => write!(
                f,
                "{}: `{line}` is not a source and a digest",
                path.display()
            ),
            Self::Missing { source, digest } => write!(
                f,
                "the rows of source {source}, {digest}, are not in the snapshot directory; \
                 refresh {source} to write them"
            ),
            Self::Undecodable { path, reason } => write!(f, "{}: {reason}", path.display()),
            Self::Range {
                digest,
                advisory_id,
            } => write!(
                f,
                "the rows {digest} hold a range of {advisory_id} that does not parse"
            ),
        }
    }
}

impl std::error::Error for KeptError {}

impl SnapshotDir {
    /// Open `path`, creating it if it does not exist, and wait until no other process holds
    /// its lock.
    pub fn open(path: &Path) -> Result<Self, KeptError> {
        fs::create_dir_all(path).map_err(at(path))?;
        let lock_path = path.join(LOCK);
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(at(&lock_path))?;
        lock.lock().map_err(at(&lock_path))?;
        Ok(Self {
            path: path.to_owned(),
            _lock: Some(lock),
        })
    }

    /// `path`, for reading only, without the lock.
    ///
    /// A refresh never changes a file in place, and every read is checked against its digest,
    /// so a read cannot see a file half written. A prune can remove a file between two reads,
    /// which fails the second. Writing and pruning go through [`SnapshotDir::open`].
    pub fn open_to_read(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            _lock: None,
        }
    }

    /// Write one source's rows, unless a file with that digest is already there.
    pub fn write_rows(&self, encoded: &Encoded) -> Result<PathBuf, KeptError> {
        let path = self.file(&encoded.digest, ROWS)?;
        if !path.exists() {
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gzip.write_all(&encoded.bytes).map_err(at(&path))?;
            let bytes = gzip.finish().map_err(at(&path))?;
            replace(&path, &bytes)?;
        }
        Ok(path)
    }

    /// Write a snapshot's [`load::manifest`], once every rows file it names is here.
    ///
    /// Written again when it exists, so its modification time is that of the last refresh
    /// that loaded it. [`SnapshotDir::prune`] keeps by that time.
    pub fn write_snapshot(&self, manifest: &str) -> Result<PathBuf, KeptError> {
        let path = self.file(&load::snapshot_id(manifest), SNAPSHOT)?;
        for (source, digest) in lines(&path, manifest)? {
            if !self.file(digest, ROWS)?.exists() {
                return Err(KeptError::Missing {
                    source: source.to_owned(),
                    digest: digest.to_owned(),
                });
            }
        }
        replace(&path, manifest.as_bytes())?;
        Ok(path)
    }

    /// A snapshot's manifest, checked against `id`.
    pub fn read_snapshot(&self, id: &str) -> Result<String, KeptError> {
        let path = self.file(id, SNAPSHOT)?;
        let manifest = fs::read_to_string(&path).map_err(at(&path))?;
        check(&path, load::snapshot_id(&manifest), id)?;
        lines(&path, &manifest)?;
        Ok(manifest)
    }

    /// One source's encoded rows, checked against `digest`.
    pub fn read_rows(&self, digest: &str) -> Result<Vec<u8>, KeptError> {
        let path = self.file(digest, ROWS)?;
        let mut file = File::open(&path).map_err(at(&path))?;
        // A gzip file ends with the length of what it contains, modulo 2^32. It is read before
        // the contents are checked, so it is used only as a capacity, at most 16 times the
        // file: a wrong one costs a reallocation, and a right one saves growing to twice the
        // 35 MB npm's rows are, which gzip to 5.6 MB.
        let mut length = [0; 4];
        let capacity = file
            .seek(SeekFrom::End(-4))
            .and_then(|at_end| file.read_exact(&mut length).map(|_| at_end))
            .and_then(|at_end| file.rewind().map(|_| at_end))
            .map_or(0, |at_end| {
                u64::from(u32::from_le_bytes(length)).min((at_end + 4).saturating_mul(16))
            });
        let mut bytes = Vec::new();
        let _ = bytes.try_reserve_exact(usize::try_from(capacity).unwrap_or(0));
        flate2::read::GzDecoder::new(file)
            .read_to_end(&mut bytes)
            .map_err(at(&path))?;
        check(&path, load::digest(&bytes), digest)?;
        Ok(bytes)
    }

    /// Each source snapshot `id` names, with the digest of its rows.
    pub fn sources(&self, id: &str) -> Result<Vec<(String, String)>, KeptError> {
        let manifest = self.read_snapshot(id)?;
        let path = self.file(id, SNAPSHOT)?;
        Ok(lines(&path, &manifest)?
            .into_iter()
            .map(|(source, digest)| (source.to_owned(), digest.to_owned()))
            .collect())
    }

    /// One source's rows, checked against `digest` and against the source named, given to
    /// `each` one at a time as they are decoded.
    pub fn read_source(
        &self,
        source: &str,
        digest: &str,
        mut each: impl FnMut(Row) -> Result<(), KeptError>,
    ) -> Result<(), KeptError> {
        let bytes = self.read_rows(digest)?;
        let path = self.file(digest, ROWS)?;
        let undecodable = |reason: String| KeptError::Undecodable {
            path: path.clone(),
            reason,
        };
        let decoder = Decoder::new(&bytes).map_err(|e| undecodable(e.0))?;
        if decoder.source() != source {
            return Err(undecodable(format!(
                "holds source {}, where the snapshot names {source}",
                decoder.source()
            )));
        }
        for row in decoder {
            each(row.map_err(|e| undecodable(e.0))?)?;
        }
        Ok(())
    }

    /// When snapshot `id` was last written, which is when a refresh last loaded it. RFC 3339,
    /// UTC, to the second.
    pub fn written(&self, id: &str) -> Result<String, KeptError> {
        let path = self.file(id, SNAPSHOT)?;
        let modified = fs::metadata(&path)
            .and_then(|m| m.modified())
            .map_err(at(&path))?;
        jiff::Timestamp::try_from(modified)
            .and_then(|t| jiff::Timestamp::from_second(t.as_second()))
            .map(|t| t.to_string())
            .map_err(|e| at(&path)(io::Error::other(e)))
    }

    /// Keep the `limit` newest snapshots and the rows files they name. Remove every other
    /// snapshot and rows file, and any file a write left partial. Other files are left alone.
    pub fn prune(&self, limit: usize) -> Result<Pruned, KeptError> {
        let (mut snapshots, mut rows) = (Vec::new(), Vec::new());
        for entry in fs::read_dir(&self.path).map_err(at(&self.path))? {
            let path = entry.map_err(at(&self.path))?.path();
            let name = path.to_string_lossy();
            if name.ends_with(SNAPSHOT) {
                let modified = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map_err(at(&path))?;
                snapshots.push((modified, path));
            } else if name.ends_with(ROWS) {
                rows.push(path);
            } else if name.ends_with(PARTIAL) {
                fs::remove_file(&path).map_err(at(&path))?;
            }
        }
        // Newest first. The name breaks a tie, so two prunes of one directory agree.
        snapshots.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let removed = snapshots.split_off(limit.min(snapshots.len()));

        let mut named = HashSet::new();
        for (_, path) in &snapshots {
            let manifest = fs::read_to_string(path).map_err(at(path))?;
            for (_, digest) in lines(path, &manifest)? {
                named.insert(self.file(digest, ROWS)?);
            }
        }
        rows.retain(|path| !named.contains(path));
        for path in removed.iter().map(|(_, path)| path).chain(&rows) {
            fs::remove_file(path).map_err(at(path))?;
        }
        Ok(Pruned {
            snapshots: removed.len(),
            rows: rows.len(),
        })
    }

    /// `<hex><suffix>` in the directory. Only `sha256:` and 64 lowercase hex digits make a
    /// name, so no other value, such as one given on a command line, reaches a path.
    fn file(&self, digest: &str, suffix: &str) -> Result<PathBuf, KeptError> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or_else(|| KeptError::NotADigest(digest.to_owned()))?;
        Ok(self.path.join(format!("{hex}{suffix}")))
    }
}

fn at(path: &Path) -> impl FnOnce(io::Error) -> KeptError + '_ {
    move |error| KeptError::Io {
        path: path.to_owned(),
        error,
    }
}

/// Write `bytes` to `path` whole or not at all: to a partial file, flushed to disk, then
/// renamed over `path`.
fn replace(path: &Path, bytes: &[u8]) -> Result<(), KeptError> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(PARTIAL);
    let partial = PathBuf::from(partial);
    let mut file = File::create(&partial).map_err(at(&partial))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(at(&partial))?;
    fs::rename(&partial, path).map_err(at(path))
}

fn check(path: &Path, actual: String, expected: &str) -> Result<(), KeptError> {
    if actual == expected {
        Ok(())
    } else {
        Err(KeptError::Mismatch {
            path: path.to_owned(),
            digest: actual,
        })
    }
}

/// A manifest's lines, each a source and a digest.
fn lines<'a>(path: &Path, manifest: &'a str) -> Result<Vec<(&'a str, &'a str)>, KeptError> {
    manifest
        .lines()
        .map(|line| {
            line.split_once(' ').ok_or_else(|| KeptError::NotALine {
                path: path.to_owned(),
                line: line.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::osv::{Affected, Rows};
    use crate::test_support::tempdir;
    use std::time::{Duration, SystemTime};

    fn rows(id: &str) -> Rows {
        Rows {
            id: id.to_owned(),
            summary: None,
            modified: None,
            malware: true,
            cvss: None,
            band: None,
            unread_vectors: 0,
            aliases: Default::default(),
            affected: [Affected {
                ecosystem: "npm".to_owned(),
                name: id.to_lowercase(),
                version: None,
            }]
            .into(),
            ranges: Default::default(),
            unexpressed: 0,
        }
    }

    fn encoded(source: &str, ids: &[&str]) -> Encoded {
        let rows: Vec<Rows> = ids.iter().map(|id| rows(id)).collect();
        load::encode(source, &rows)
    }

    fn manifest_of(sources: &[&Encoded]) -> String {
        load::manifest(
            sources
                .iter()
                .map(|e| (e.source.as_str(), e.digest.as_str())),
        )
    }

    fn named(dir: &Path, digest: &str, suffix: &str) -> PathBuf {
        let hex = digest.strip_prefix("sha256:").expect("a digest");
        dir.join(format!("{hex}{suffix}"))
    }

    /// Set a file's modification time this many seconds in the past.
    fn age(path: &Path, seconds: u64) {
        File::options()
            .write(true)
            .open(path)
            .expect("should open")
            .set_modified(SystemTime::now() - Duration::from_secs(seconds))
            .expect("should set the time");
    }

    /// Every file in the directory but the lock, sorted.
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("should list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|name| name != LOCK)
            .collect();
        names.sort();
        names
    }

    fn file_name(path: &Path) -> String {
        path.file_name()
            .expect("a file")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn a_load_is_kept_as_rows_named_by_digest_and_a_snapshot_named_by_id() {
        let path = tempdir("kept-write");
        let dir = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1", "MAL-2"]);
        let manifest = manifest_of(&[&osv]);
        let id = load::snapshot_id(&manifest);

        let rows_path = dir.write_rows(&osv).expect("writes rows");
        let snapshot_path = dir.write_snapshot(&manifest).expect("writes the snapshot");

        assert_eq!(rows_path, named(&path, &osv.digest, ".rows.gz"));
        assert_eq!(snapshot_path, named(&path, &id, ".snapshot"));
        assert_eq!(
            &fs::read(&rows_path).expect("reads")[..2],
            [0x1f, 0x8b],
            "gzip"
        );
        assert_eq!(dir.read_rows(&osv.digest).expect("reads"), osv.bytes);
        assert_eq!(dir.read_snapshot(&id).expect("reads"), manifest);
    }

    #[test]
    fn rows_already_kept_are_not_written_again() {
        let path = tempdir("kept-rows-once");
        let dir = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1"]);
        let rows_path = dir.write_rows(&osv).expect("writes");
        age(&rows_path, 3600);
        let modified = || {
            fs::metadata(&rows_path)
                .and_then(|m| m.modified())
                .expect("time")
        };
        let before = modified();

        dir.write_rows(&osv).expect("writes");
        assert_eq!(modified(), before);
    }

    #[test]
    fn a_snapshot_naming_rows_not_kept_is_not_written() {
        let path = tempdir("kept-missing");
        let dir = SnapshotDir::open(&path).expect("opens");
        let (osv, other) = (encoded("osv", &["MAL-1"]), encoded("other", &["GHSA-1"]));
        let rows_path = dir.write_rows(&osv).expect("writes");

        let err = dir
            .write_snapshot(&manifest_of(&[&osv, &other]))
            .expect_err("the other source's rows are not kept");
        assert!(
            matches!(&err, KeptError::Missing { source, digest } if source == "other" && *digest == other.digest),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "the rows of source other, {}, are not in the snapshot directory; \
                 refresh other to write them",
                other.digest
            )
        );
        assert_eq!(listing(&path), [file_name(&rows_path)]);
    }

    #[test]
    fn a_rows_file_too_short_or_with_a_false_length_is_refused() {
        let path = tempdir("kept-short");
        let dir = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1"]);
        let rows_path = dir.write_rows(&osv).expect("writes");
        let mut false_length = fs::read(&rows_path).expect("reads");
        let end = false_length.len();
        false_length[end - 4..].copy_from_slice(&u32::MAX.to_le_bytes());

        for contents in [vec![0x1f, 0x8b], false_length] {
            fs::write(&rows_path, contents).expect("overwrites");
            let err = dir.read_rows(&osv.digest).expect_err("not the rows");
            assert!(matches!(err, KeptError::Io { .. }), "{err:?}");
        }
    }

    #[test]
    fn a_file_whose_contents_do_not_hash_to_its_name_is_refused() {
        let path = tempdir("kept-mismatch");
        let dir = SnapshotDir::open(&path).expect("opens");
        let (osv, other) = (encoded("osv", &["MAL-1"]), encoded("osv", &["MAL-2"]));
        let rows_path = dir.write_rows(&osv).expect("writes");
        let manifest = manifest_of(&[&osv]);
        let snapshot_path = dir.write_snapshot(&manifest).expect("writes");

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&other.bytes).expect("compresses");
        fs::write(&rows_path, gzip.finish().expect("compresses")).expect("overwrites");
        let err = dir
            .read_rows(&osv.digest)
            .expect_err("another source's rows");
        assert!(
            matches!(&err, KeptError::Mismatch { digest, .. } if *digest == other.digest),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "{}: contents hash to {}, not the digest in its name",
                rows_path.display(),
                other.digest
            )
        );

        fs::write(
            &snapshot_path,
            format!("{manifest}extra {}\n", other.digest),
        )
        .expect("overwrites");
        let id = load::snapshot_id(&manifest);
        assert!(matches!(
            dir.read_snapshot(&id),
            Err(KeptError::Mismatch { .. })
        ));
    }

    #[test]
    fn a_snapshot_line_that_is_not_a_source_and_a_digest_is_refused() {
        let path = tempdir("kept-line");
        let dir = SnapshotDir::open(&path).expect("opens");
        let manifest = "osv\n";
        let id = load::snapshot_id(manifest);
        fs::write(named(&path, &id, ".snapshot"), manifest).expect("writes");

        let err = dir.read_snapshot(&id).expect_err("no digest");
        assert!(
            err.to_string()
                .ends_with(": `osv` is not a source and a digest"),
            "{err}"
        );
        assert!(matches!(
            dir.write_snapshot(manifest),
            Err(KeptError::NotALine { .. })
        ));
    }

    #[test]
    fn a_value_that_is_not_a_digest_never_becomes_a_path() {
        let dir = SnapshotDir::open(&tempdir("kept-not-a-digest")).expect("opens");
        let hex = "a".repeat(64);
        for bad in [
            "../../etc/passwd".to_owned(),
            format!("sha256:../{}", &hex[3..]),
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha256:{}", &hex[1..]),
            format!("sha256:{hex}0"),
            format!("md5:{hex}"),
            hex.clone(),
        ] {
            let err = dir.read_snapshot(&bad).expect_err(&bad);
            assert_eq!(
                err.to_string(),
                format!("`{bad}` is not `sha256:` and 64 lowercase hex digits")
            );
            assert!(matches!(dir.read_rows(&bad), Err(KeptError::NotADigest(_))));
        }
    }

    #[test]
    fn prune_keeps_the_newest_snapshots_and_only_the_rows_they_name() {
        let path = tempdir("kept-prune");
        let dir = SnapshotDir::open(&path).expect("opens");
        let other = encoded("other", &["GHSA-1"]);
        let loads = [
            encoded("osv", &["MAL-1"]),
            encoded("osv", &["MAL-1", "MAL-2"]),
            encoded("osv", &["MAL-1", "MAL-2", "MAL-3"]),
        ];
        dir.write_rows(&other).expect("writes");
        let mut snapshots = Vec::new();
        for (osv, seconds) in loads.iter().zip([300, 200, 100]) {
            dir.write_rows(osv).expect("writes");
            let written = dir
                .write_snapshot(&manifest_of(&[osv, &other]))
                .expect("writes");
            age(&written, seconds);
            snapshots.push(written);
        }
        fs::write(path.join("notes.txt"), "an operator's").expect("writes");
        fs::write(path.join("abc.rows.gz.partial"), "").expect("writes");

        assert_eq!(
            dir.prune(2).expect("prunes"),
            Pruned {
                snapshots: 1,
                rows: 1
            }
        );
        let mut expected = vec![
            file_name(&snapshots[1]),
            file_name(&snapshots[2]),
            file_name(&named(&path, &loads[1].digest, ".rows.gz")),
            file_name(&named(&path, &loads[2].digest, ".rows.gz")),
            file_name(&named(&path, &other.digest, ".rows.gz")),
            "notes.txt".to_owned(),
        ];
        expected.sort();
        assert_eq!(listing(&path), expected);

        // Keeping more than there are removes nothing.
        assert_eq!(
            dir.prune(10).expect("prunes"),
            Pruned {
                snapshots: 0,
                rows: 0
            }
        );
    }

    #[test]
    fn a_snapshot_written_again_is_the_newest() {
        let path = tempdir("kept-rewrite");
        let dir = SnapshotDir::open(&path).expect("opens");
        let (a, b) = (encoded("osv", &["MAL-1"]), encoded("osv", &["MAL-2"]));
        let mut written = Vec::new();
        for (load, seconds) in [(&a, 200), (&b, 100)] {
            dir.write_rows(load).expect("writes");
            let snapshot = dir.write_snapshot(&manifest_of(&[load])).expect("writes");
            age(&snapshot, seconds);
            written.push(snapshot);
        }

        dir.write_snapshot(&manifest_of(&[&a]))
            .expect("writes again");
        dir.prune(1).expect("prunes");
        assert!(written[0].exists());
        assert!(!written[1].exists());
    }

    #[test]
    fn a_second_open_waits_until_the_first_is_dropped() {
        let path = tempdir("kept-lock");
        let first = SnapshotDir::open(&path).expect("opens");
        let (opened, told) = std::sync::mpsc::channel();
        let second = std::thread::spawn({
            let path = path.clone();
            move || {
                let dir = SnapshotDir::open(&path);
                opened.send(()).expect("the test is listening");
                dir.map(drop)
            }
        });

        assert!(
            told.recv_timeout(Duration::from_millis(300)).is_err(),
            "opened while the first held the lock"
        );
        drop(first);
        told.recv_timeout(Duration::from_secs(10))
            .expect("opens once the first is dropped");
        second.join().expect("joins").expect("opens");
    }

    #[test]
    fn a_reader_neither_waits_for_the_lock_nor_creates_the_directory() {
        let path = tempdir("kept-reader");
        let writer = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1"]);
        writer.write_rows(&osv).expect("writes");
        let manifest = manifest_of(&[&osv]);
        writer.write_snapshot(&manifest).expect("writes");

        let reader = SnapshotDir::open_to_read(&path);
        let id = load::snapshot_id(&manifest);
        assert_eq!(
            reader
                .sources(&id)
                .expect("reads while the writer holds the lock"),
            [("osv".to_owned(), osv.digest.clone())]
        );

        let absent = path.join("absent");
        let err = SnapshotDir::open_to_read(&absent)
            .read_snapshot(&id)
            .expect_err("no directory");
        assert!(matches!(err, KeptError::Io { .. }), "{err:?}");
        assert!(!absent.exists());
    }

    #[test]
    fn a_snapshot_reports_when_it_was_last_written_to_the_second() {
        let path = tempdir("kept-written");
        let dir = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1"]);
        dir.write_rows(&osv).expect("writes");
        let manifest = manifest_of(&[&osv]);
        let written = dir.write_snapshot(&manifest).expect("writes");
        let at: jiff::Timestamp = "2026-09-13T01:02:03.9Z".parse().expect("a time");
        File::options()
            .write(true)
            .open(&written)
            .expect("opens")
            .set_modified(SystemTime::from(at))
            .expect("sets the time");

        assert_eq!(
            dir.written(&load::snapshot_id(&manifest)).expect("reads"),
            "2026-09-13T01:02:03Z"
        );
    }

    #[test]
    fn rows_of_another_source_than_the_snapshot_names_are_refused() {
        let path = tempdir("kept-source");
        let dir = SnapshotDir::open(&path).expect("opens");
        let osv = encoded("osv", &["MAL-1"]);
        dir.write_rows(&osv).expect("writes");

        let mut read = Vec::new();
        let err = dir
            .read_source("other", &osv.digest, |row| {
                read.push(row);
                Ok(())
            })
            .expect_err("the rows are osv's");
        assert!(read.is_empty());
        assert_eq!(
            err.to_string(),
            format!(
                "{}: holds source osv, where the snapshot names other",
                named(&path, &osv.digest, ".rows.gz").display()
            )
        );
        dir.read_source("osv", &osv.digest, |row| {
            read.push(row);
            Ok(())
        })
        .expect("reads");
        assert_eq!(
            read,
            vec![
                Row::Advisory(Rows {
                    affected: Default::default(),
                    ..rows("MAL-1")
                }),
                Row::Affected(0, rows("MAL-1").affected.pop_first().expect("one")),
            ]
        );
    }

    #[test]
    fn a_directory_that_cannot_be_created_is_an_error_naming_it() {
        let file = tempdir("kept-unusable").join("a-file");
        fs::write(&file, "").expect("writes");
        let under = file.join("snapshots");
        let err = SnapshotDir::open(&under).expect_err("a file is in the way");
        assert!(
            err.to_string()
                .starts_with(&format!("{}: ", under.display())),
            "{err}"
        );
    }
}
