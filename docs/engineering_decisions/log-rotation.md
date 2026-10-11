# Logs are files, rotated daily, compressed, kept 365 days

- **Status:** Decided 2026-10-11, by the user. Not yet implemented. TODO Stage 4.9.
- **Related:** [audit-log](audit-log.md), [admin-plan](../admin-plan.md) §4.3

## Decision

The audit log and the account event log are files on disk. byrle rotates each at UTC
midnight: the day's file is renamed with its date and compressed with gzip. Files older
than `BYRLE_LOG_RETENTION_DAYS`, 365 by default, are deleted.

## What follows

- `policy diff`, `audit verify` and the console read the current file and the compressed
  ones.
- What the console looks up rather than scans is indexed in Postgres: `served_version`
  and `failure_count` ([admin-plan](../admin-plan.md) §4.3).
- byrle rotates its own files, so no `logrotate` configuration is needed.

## Rejected

| Option | Why not |
|---|---|
| Every request as a row in Postgres | The user chose files on disk |
| Rotation by `logrotate` | It needs a configuration per install and a signal to reopen the file |
