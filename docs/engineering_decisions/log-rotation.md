# Logs are files, rotated daily, compressed after 3 days, kept 365 days

- **Status:** Decided 2026-10-11, by the user. Revised by the user 2026-10-12: bzip2 rather
  than gzip, and the 3 newest days uncompressed. Implemented 2026-10-12 for the audit log:
  `src/rotation.rs`. TODO Stage 4.9.
- **Related:** [audit-log](audit-log.md), [admin-plan](../admin-plan.md) §4.3

## Decision

The audit log and the account event log are files on disk. byrle rotates each itself. On
the first write of a new UTC day, the file is renamed `<path>.<YYYY-MM-DD>`, with the day
it was written, and a new file is opened at the path.

| Day | File |
|---|---|
| n, today | `<path>`, uncompressed |
| n-1 | `<path>.<n-1>`, uncompressed |
| n-2 | `<path>.<n-2>`, uncompressed |
| n-3 and earlier | `<path>.<day>.bz2` |
| older than `BYRLE_LOG_RETENTION_DAYS` (365) | deleted |

A file's age is today's date less the date in its name.

## When files are compressed and deleted

| When | What |
|---|---|
| at startup, before the proxy answers | a file last written on an earlier UTC day is renamed with that day, then the rotated files are tidied |
| at the first write of a new day | the file is renamed and reopened under the write lock, then the rotated files are tidied on another thread, so no request waits on bzip2 |

A tidy compresses each uncompressed file 3 days old or older, and deletes each file older
than the retention period. A day with no writes has no file. A proxy that writes nothing
for days compresses nothing until its next write or restart.

## Failures

| Failure | What happens |
|---|---|
| the rename fails | warned. Lines go on into the same file. The next day's rename names it with the later day, and it holds both days |
| a compression or a deletion fails | warned. The other files are still tidied |
| the process stops during a compression | the file is written to `<path>.<day>.bz2.part`, renamed `.bz2`, then the uncompressed file removed. The next tidy removes a `.part`, and removes the uncompressed file when its `.bz2` is there |
| a day's file is there when the live file is renamed to it | the live file is appended to it, so no line is lost. A clock set back causes it |

## What reads them

`policy diff` and `audit verify` read the files rotated from the path, oldest first, then
the path. A day kept both uncompressed and compressed is read once. A `.part` is not read.
`audit verify` names each line `<file>:<line>`.

The console will read them the same way. What it looks up rather than scans is indexed in
Postgres: `served_version` and `failure_count` ([admin-plan](../admin-plan.md) §4.3).

## Rejected

| Option | Why not |
|---|---|
| Every request as a row in Postgres | The user chose files on disk |
| Rotation by `logrotate` | It needs a configuration per install and a signal to reopen the file |
| gzip, compressed at rotation | Replaced by the user on 2026-10-12 with bzip2 after 3 days |
| A timer firing at midnight | A line written between midnight and the timer would go into the previous day's file. The day is checked on each write instead |

## Crate

`bzip2` 0.6.1, on `libbz2-rs-sys` 0.2.5: a Rust port of libbzip2, with no C to build.
`bzip2` is MIT or Apache-2.0. `libbz2-rs-sys` is under the bzip2-1.0.6 licence, a BSD-style
licence.
