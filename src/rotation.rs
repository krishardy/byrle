//! A log file renamed with its date at UTC midnight. Files 3 days old and older are
//! compressed with bzip2, and files older than the retention period are deleted. See
//! docs/engineering_decisions/log-rotation.md.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;

use jiff::civil::Date;
use tracing::warn;

/// Days a file is kept uncompressed: today's, yesterday's and the day before's.
pub const UNCOMPRESSED_DAYS: i32 = 3;

/// Appended to a day's file name once it is compressed.
const BZ2: &str = ".bz2";

/// Appended to a day's file name while it is compressed. Removed by the next tidy.
const PART: &str = ".bz2.part";

/// A rotated log of lines that warns once, naming itself, when a line cannot be written.
#[derive(Debug)]
pub struct Lines {
    file: Rotating,
    /// Such as `audit log`, in the warning.
    name: &'static str,
    warned: std::sync::atomic::AtomicBool,
}

impl Lines {
    /// Open `path` as [`Rotating::open`] does, on `today`.
    pub fn open(
        path: &Path,
        retention_days: u32,
        name: &'static str,
        today: Date,
    ) -> io::Result<Self> {
        Ok(Self {
            file: Rotating::open(path, retention_days, today)?,
            name,
            warned: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Append `line` on `today`. A failure is warned about once and otherwise ignored.
    pub fn append(&self, line: &[u8], today: Date) {
        if self.file.append(line, today).is_err()
            && !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn!(
                byrle.reason = format!("{} could not be written", self.name),
                "the {} is incomplete from here on", self.name
            );
        }
    }
}

/// Today, in UTC.
pub fn today() -> Date {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
}

/// A file appended to, renamed `<path>.<YYYY-MM-DD>` on the first write of a later UTC day.
#[derive(Debug)]
pub struct Rotating {
    path: PathBuf,
    retention_days: u32,
    open: Mutex<Open>,
}

#[derive(Debug)]
struct Open {
    file: File,
    /// The UTC day `file` is written on.
    day: Date,
    /// The last tidy started, so a test can wait for it.
    tidying: Option<JoinHandle<()>>,
}

impl Rotating {
    /// Open `path` for appending, creating it if it is not there. A regular file last
    /// written before `today` is renamed with that day first. Then the rotated files are
    /// tidied, before this returns.
    pub fn open(path: &Path, retention_days: u32, today: Date) -> io::Result<Self> {
        if let Some(day) = written_on(path)
            && day < today
            && let Err(e) = dated(path, day)
        {
            not_rotated(path, &e);
        }
        let file = appending(path)?;
        tidy(path, retention_days, today);
        Ok(Self {
            path: path.to_owned(),
            retention_days,
            open: Mutex::new(Open {
                file,
                day: today,
                tidying: None,
            }),
        })
    }

    /// Append `bytes`, first renaming the file with its day when `today` is a later one.
    /// The rotated files are tidied on another thread. A rename that fails is warned about,
    /// and `bytes` are appended to the file as it is.
    pub fn append(&self, bytes: &[u8], today: Date) -> io::Result<()> {
        let mut open = self.lock();
        if today > open.day {
            if let Err(e) = self.rotate(&mut open, today) {
                not_rotated(&self.path, &e);
            }
            open.day = today;
        }
        open.file.write_all(bytes)
    }

    fn rotate(&self, open: &mut Open, today: Date) -> io::Result<()> {
        open.file = dated(&self.path, open.day).and_then(|()| appending(&self.path))?;
        let (path, retention_days) = (self.path.clone(), self.retention_days);
        open.tidying = Some(std::thread::spawn(move || {
            tidy(&path, retention_days, today);
        }));
        Ok(())
    }

    /// A writer that panicked holding the lock does not stop the next write.
    fn lock(&self) -> MutexGuard<'_, Open> {
        self.open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Wait for the last tidy started to finish.
    #[cfg(test)]
    pub fn tidied(&self) {
        if let Some(tidying) = self.lock().tidying.take() {
            tidying.join().expect("the tidy does not panic");
        }
    }
}

fn appending(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn not_rotated(path: &Path, e: &io::Error) {
    warn!(
        byrle.log.path = %path.display(),
        byrle.reason = %e,
        "the log was not renamed with its day, so it goes on in the same file"
    );
}

/// The UTC day a regular file at `path` was last written, if there is one.
fn written_on(path: &Path) -> Option<Date> {
    fs::metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .and_then(|m| m.modified().ok())
        .and_then(|modified| jiff::Timestamp::try_from(modified).ok())
        .map(|modified| modified.to_zoned(jiff::tz::TimeZone::UTC).date())
}

/// `<path>.<day>`, with `suffix` after it.
fn named(path: &Path, day: Date, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{day}{suffix}"));
    PathBuf::from(name)
}

/// Rename `path` to `<path>.<day>`. When that is there already, append to it instead.
fn dated(path: &Path, day: Date) -> io::Result<()> {
    let to = named(path, day, "");
    if !to.exists() {
        return fs::rename(path, to);
    }
    appending(&to)
        .and_then(|mut into| File::open(path).and_then(|mut from| io::copy(&mut from, &mut into)))
        .and_then(|_| fs::remove_file(path))
}

/// What a rotated file is.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Form {
    Plain,
    Compressed,
    /// A compression that has not finished.
    Part,
}

/// Each file rotated from `path`, with its day and form, in no order.
fn rotated(path: &Path) -> io::Result<Vec<(Date, Form, PathBuf)>> {
    let base = path.file_name().unwrap_or_default().to_string_lossy();
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut found = Vec::new();
    for entry in fs::read_dir(parent)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(&*base).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        let (Some(day), Some(suffix)) = (rest.get(..10), rest.get(10..)) else {
            continue;
        };
        let form = match suffix {
            "" => Form::Plain,
            BZ2 => Form::Compressed,
            PART => Form::Part,
            _ => continue,
        };
        if let Ok(day) = day.parse::<Date>() {
            found.push((day, form, entry.path()));
        }
    }
    Ok(found)
}

/// Compress each rotated file [`UNCOMPRESSED_DAYS`] old or older, delete each older than
/// `retention_days`, and remove what an interrupted compression left. A failure is warned
/// about, and the other files are still tidied.
fn tidy(path: &Path, retention_days: u32, today: Date) {
    let found = match rotated(path) {
        Ok(found) => found,
        Err(e) => return not_tidied(path, &e),
    };
    for (day, form, file) in found {
        let age = (today - day).get_days();
        let tidied =
            if form == Form::Part || age > i32::try_from(retention_days).unwrap_or(i32::MAX) {
                fs::remove_file(&file)
            } else if form == Form::Plain && age >= UNCOMPRESSED_DAYS {
                compress(&file, &named(path, day, BZ2), &named(path, day, PART))
            } else {
                Ok(())
            };
        if let Err(e) = tidied {
            not_tidied(&file, &e);
        }
    }
}

fn not_tidied(path: &Path, e: &io::Error) {
    warn!(
        byrle.log.path = %path.display(),
        byrle.reason = %e,
        "a rotated log was not compressed or deleted"
    );
}

/// Compress `plain` to `part`, rename that `done`, and remove `plain`. When `done` is there
/// already, a compression was interrupted after its rename, and only `plain` is removed.
fn compress(plain: &Path, done: &Path, part: &Path) -> io::Result<()> {
    if !done.exists() {
        File::create(part)
            .map(|file| bzip2::write::BzEncoder::new(file, bzip2::Compression::best()))
            .and_then(|mut to| {
                File::open(plain)
                    .and_then(|mut from| io::copy(&mut from, &mut to))
                    .map(|_| to)
            })
            .and_then(|to| to.finish())
            .and_then(|file| file.sync_all())
            .and_then(|()| fs::rename(part, done))?;
    }
    fs::remove_file(plain)
}

/// The files rotated from `path`, oldest first, then `path`. A day kept both uncompressed
/// and compressed, which an interrupted compression leaves, is listed once.
pub fn files(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut days = BTreeMap::new();
    for (day, form, file) in rotated(path)? {
        match form {
            Form::Plain => {
                days.insert(day, file);
            }
            Form::Compressed => {
                days.entry(day).or_insert(file);
            }
            Form::Part => {}
        }
    }
    let mut files: Vec<PathBuf> = days.into_values().collect();
    match fs::metadata(path) {
        Ok(_) => files.push(path.to_owned()),
        Err(e) if files.is_empty() => return Err(e),
        Err(_) => {}
    }
    Ok(files)
}

/// The text of `file`, decompressed when its name ends `.bz2`.
pub fn read(file: &Path) -> io::Result<String> {
    if !file.as_os_str().to_string_lossy().ends_with(BZ2) {
        return fs::read_to_string(file);
    }
    let mut text = String::new();
    File::open(file)
        .and_then(|from| bzip2::read::BzDecoder::new(from).read_to_string(&mut text))
        .map(|_| text)
}

/// Call `with` on the name and text of each of [`files`], one file at a time. `Err` is the
/// path that did not read, and why.
pub fn each(path: &Path, with: &mut dyn FnMut(&str, &str)) -> Result<(), String> {
    let failed = |file: &Path, e: io::Error| format!("{}: {e}", file.display());
    for file in files(path).map_err(|e| failed(path, e))? {
        let text = read(&file).map_err(|e| failed(&file, e))?;
        with(
            &file.file_name().unwrap_or_default().to_string_lossy(),
            &text,
        );
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::util::test_support::tempdir;
    use jiff::civil::date;

    const DAY: Date = date(2026, 10, 12);

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The file at `path`, last written on `day`.
    fn written(path: &Path, day: Date, text: &str) {
        fs::write(path, text).unwrap();
        let at = day.to_zoned(jiff::tz::TimeZone::UTC).unwrap().timestamp();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at.into())
            .unwrap();
    }

    fn texts(path: &Path) -> Vec<(String, String)> {
        let mut read = Vec::new();
        each(path, &mut |name, text| {
            read.push((name.to_owned(), text.to_owned()))
        })
        .unwrap();
        read
    }

    #[test]
    fn the_first_write_of_a_later_day_renames_the_file_with_its_day() {
        let dir = tempdir("rotation-midnight");
        let path = dir.join("audit.jsonl");
        let log = Rotating::open(&path, 365, DAY).unwrap();
        log.append(b"a\n", DAY).unwrap();
        log.append(b"b\n", DAY.tomorrow().unwrap()).unwrap();
        log.append(b"c\n", DAY.tomorrow().unwrap()).unwrap();
        log.tidied();
        assert_eq!(names(&dir), ["audit.jsonl", "audit.jsonl.2026-10-12"]);
        assert_eq!(
            texts(&path),
            [
                ("audit.jsonl.2026-10-12".to_owned(), "a\n".to_owned()),
                ("audit.jsonl".to_owned(), "b\nc\n".to_owned())
            ]
        );
    }

    /// A clock set back does not rename today's file with a later day.
    #[test]
    fn an_earlier_day_is_written_to_the_same_file() {
        let dir = tempdir("rotation-earlier");
        let path = dir.join("audit.jsonl");
        let log = Rotating::open(&path, 365, DAY).unwrap();
        log.append(b"a\n", DAY.yesterday().unwrap()).unwrap();
        log.append(b"b\n", DAY).unwrap();
        log.tidied();
        assert_eq!(names(&dir), ["audit.jsonl"]);
    }

    /// Files 0, 1 and 2 days old stay as they are; 3 days old and older are compressed;
    /// older than the retention period they are deleted.
    #[test]
    fn a_file_is_compressed_at_3_days_old_and_deleted_after_the_retention_period() {
        let dir = tempdir("rotation-ages");
        let path = dir.join("audit.jsonl");
        for age in [1, 2, 3, 10, 11] {
            let day = DAY.checked_sub(jiff::Span::new().days(age)).unwrap();
            fs::write(named(&path, day, ""), format!("{age}\n")).unwrap();
        }
        let log = Rotating::open(&path, 10, DAY).unwrap();
        assert_eq!(
            names(&dir),
            [
                "audit.jsonl",
                "audit.jsonl.2026-10-02.bz2",
                "audit.jsonl.2026-10-09.bz2",
                "audit.jsonl.2026-10-10",
                "audit.jsonl.2026-10-11",
            ]
        );
        log.append(b"0\n", DAY).unwrap();
        let read: Vec<String> = texts(&path).into_iter().map(|(_, t)| t).collect();
        assert_eq!(read, ["10\n", "3\n", "2\n", "1\n", "0\n"]);

        log.append(b"next\n", DAY.tomorrow().unwrap()).unwrap();
        log.tidied();
        assert_eq!(
            names(&dir),
            [
                "audit.jsonl",
                "audit.jsonl.2026-10-09.bz2",
                "audit.jsonl.2026-10-10.bz2",
                "audit.jsonl.2026-10-11",
                "audit.jsonl.2026-10-12",
            ]
        );
    }

    /// A proxy started after midnight renames the file it last wrote, with that day.
    #[test]
    fn a_file_last_written_on_an_earlier_day_is_renamed_on_open() {
        let dir = tempdir("rotation-startup");
        let path = dir.join("audit.jsonl");
        written(&path, DAY.yesterday().unwrap(), "old\n");
        Rotating::open(&path, 365, DAY).unwrap();
        assert_eq!(names(&dir), ["audit.jsonl", "audit.jsonl.2026-10-11"]);
        assert_eq!(
            fs::read_to_string(named(&path, DAY.yesterday().unwrap(), "")).unwrap(),
            "old\n"
        );

        fs::write(&path, "today\n").unwrap();
        Rotating::open(&path, 365, today()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "today\n");
    }

    /// A day's file already there is appended to rather than replaced.
    #[test]
    fn a_day_already_rotated_is_appended_to() {
        let dir = tempdir("rotation-twice");
        let path = dir.join("audit.jsonl");
        fs::write(named(&path, DAY.yesterday().unwrap(), ""), "first\n").unwrap();
        written(&path, DAY.yesterday().unwrap(), "second\n");
        Rotating::open(&path, 365, DAY).unwrap();
        assert_eq!(
            fs::read_to_string(named(&path, DAY.yesterday().unwrap(), "")).unwrap(),
            "first\nsecond\n"
        );
    }

    /// An interrupted compression leaves a part file, or both forms of one day. The next tidy
    /// finishes it, and a reader reads the day once.
    #[test]
    fn an_interrupted_compression_is_finished_and_read_once() {
        let dir = tempdir("rotation-interrupted");
        let path = dir.join("audit.jsonl");
        let old = DAY.checked_sub(jiff::Span::new().days(5)).unwrap();
        fs::write(named(&path, old, ""), "old\n").unwrap();
        fs::write(named(&path, old, PART), "torn").unwrap();
        let done = DAY.checked_sub(jiff::Span::new().days(4)).unwrap();
        fs::write(named(&path, done, ""), "done\n").unwrap();
        compress(
            &named(&path, done, ""),
            &named(&path, done, BZ2),
            &named(&path, done, PART),
        )
        .unwrap();
        fs::write(named(&path, done, ""), "done\n").unwrap();
        fs::write(named(&path, done, PART), "torn").unwrap();
        fs::write(&path, "").unwrap();

        let read: Vec<String> = texts(&path).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            read,
            [
                "audit.jsonl.2026-10-07",
                "audit.jsonl.2026-10-08",
                "audit.jsonl"
            ]
        );

        Rotating::open(&path, 365, DAY).unwrap();
        assert_eq!(
            names(&dir),
            [
                "audit.jsonl",
                "audit.jsonl.2026-10-07.bz2",
                "audit.jsonl.2026-10-08.bz2",
            ]
        );
        let read: Vec<String> = texts(&path).into_iter().map(|(_, t)| t).collect();
        assert_eq!(read, ["old\n", "done\n", ""]);
    }

    /// Only `<name>.<YYYY-MM-DD>`, with `.bz2` or `.bz2.part` or nothing after, is the log's.
    #[test]
    fn other_files_in_the_directory_are_left_alone() {
        let dir = tempdir("rotation-others");
        let path = dir.join("audit.jsonl");
        let others = [
            "audit.jsonl.bak",
            "audit.jsonl.2020-01-01.gz",
            "audit.jsonl.2020-13-01",
            "audit.jsonl.2020-01",
            "audit.jsonlx2020-01-01",
            "other.jsonl.2020-01-01",
        ];
        for other in others {
            fs::write(dir.join(other), "").unwrap();
        }
        Rotating::open(&path, 1, DAY).unwrap();
        let mut expected: Vec<&str> = others.to_vec();
        expected.push("audit.jsonl");
        expected.sort();
        assert_eq!(names(&dir), expected);
    }

    /// A bare file name, and no name, are looked for in the working directory.
    #[test]
    fn a_bare_file_name_is_looked_for_in_the_working_directory() {
        assert!(rotated(Path::new("no-such-byrle-log")).is_ok());
        assert!(rotated(Path::new("")).is_ok());
    }

    /// Rotated files alone are read without the live file. No file at all, or one that does
    /// not decompress, is an error naming it.
    #[test]
    fn a_log_with_no_file_is_an_error_naming_it() {
        let dir = tempdir("rotation-missing");
        let path = dir.join("audit.jsonl");
        let e = each(&path, &mut |_, _| {}).unwrap_err();
        assert!(e.starts_with(&path.display().to_string()), "{e}");
        assert!(each(&dir.join("no-dir").join("audit.jsonl"), &mut |_, _| {}).is_err());

        fs::write(named(&path, DAY, ""), "a\n").unwrap();
        assert_eq!(texts(&path).len(), 1);

        fs::write(named(&path, DAY, BZ2), "not bzip2").unwrap();
        fs::remove_file(named(&path, DAY, "")).unwrap();
        let e = each(&path, &mut |_, _| {}).unwrap_err();
        assert!(e.contains("2026-10-12.bz2"), "{e}");
    }

    /// A rename or a tidy that fails is warned about, and writing goes on.
    #[test]
    fn a_rotation_that_fails_is_warned_about_and_the_line_still_written() {
        use crate::util::test_support::{Restricted, capture, text};

        let dir = tempdir("rotation-fails");
        let path = dir.join("audit.jsonl");
        written(
            &path,
            DAY.checked_sub(jiff::Span::new().days(4)).unwrap(),
            "old\n",
        );
        fs::write(
            named(
                &path,
                DAY.checked_sub(jiff::Span::new().days(5)).unwrap(),
                "",
            ),
            "",
        )
        .unwrap();
        let (_guard, buf) = capture(tracing::Level::WARN);
        let log = {
            let _locked = Restricted::new(&dir, 0o555);
            let log = Rotating::open(&path, 365, DAY).unwrap();
            log.append(b"new\n", DAY.tomorrow().unwrap()).unwrap();
            log
        };
        let logged = text(&buf);
        assert_eq!(
            logged.matches("the log was not renamed").count(),
            2,
            "{logged}"
        );
        assert!(
            logged.contains("a rotated log was not compressed"),
            "{logged}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\nnew\n");
        drop(log);

        let unlisted = dir.join("unlisted");
        fs::create_dir(&unlisted).unwrap();
        let path = unlisted.join("audit.jsonl");
        fs::write(&path, "").unwrap();
        let (_guard, buf) = capture(tracing::Level::WARN);
        {
            let _locked = Restricted::new(&unlisted, 0o333);
            Rotating::open(&path, 365, DAY).unwrap();
        }
        assert!(text(&buf).contains("a rotated log was not compressed"));
    }

    /// A writer that panicked holding the lock does not stop the next write.
    #[test]
    fn a_lock_a_writer_panicked_holding_is_still_used() {
        let dir = tempdir("rotation-poisoned");
        let path = dir.join("audit.jsonl");
        let log = std::sync::Arc::new(Rotating::open(&path, 365, DAY).unwrap());
        let held = log.clone();
        let _ = std::thread::spawn(move || {
            let _open = held.open.lock().unwrap();
            panic!("poisons the lock");
        })
        .join();
        assert!(log.open.is_poisoned());
        log.append(b"a\n", DAY).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "a\n");
    }

    #[test]
    fn today_is_the_utc_date() {
        assert_eq!(
            today(),
            jiff::Timestamp::now()
                .to_zoned(jiff::tz::TimeZone::UTC)
                .date()
        );
    }
}
