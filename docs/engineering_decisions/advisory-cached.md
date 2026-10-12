# `advisory.cached`: when byrle first stored an advisory

- **Status:** Implemented 2026-10-12. `migrations/0016_advisory_cached.sql`,
  `write_source` in `src/intel/postgres.rs`, `Record::cached`, `explain::advisories`.
- **Related:** [explain-output](explain-output.md),
  [snapshot-identity](snapshot-identity.md)

## Decision

Each `advisory` row has `cached TIMESTAMPTZ NOT NULL`: the time of the refresh that first
stored its (source, publisher_id). Not every stream gives `modified`, so `modified` cannot
say how old every record is. `cached` can.

| Event | `cached` |
|---|---|
| the advisory appears in a refresh for the first time | that refresh's transaction time, `now()` |
| a later refresh holds it again, changed or not | kept |
| a refresh no longer holds it, and a later one does | the later refresh's time |
| row present before the migration | the time the migration ran |

`byrle explain <purl>` lists it per stream under the verdict:

```
  advisories:
    GHSA-35jh-r3h4-6jhm  osv/npm  cached 2026-10-12T09:10:03Z
```

## How a refresh keeps it

A refresh deletes a source's rows and copies them again. Before the delete, `write_source`
copies `(publisher_id, cached)` for that source into the temporary table `prior_cached`.
After the copy, it sets `cached` from that table on every row whose `publisher_id` matches,
and drops the table. Every source is written in one transaction, so the table is dropped
per source, not at commit. Those three statements use `sqlx::query`, because `query!`
checks a statement at build time, when `prior_cached` does not exist.

## What it is not part of

`cached` is not in the encoded rows, `load::FORMAT` or a source's digest. The same rows
loaded on two days are one snapshot, as before. A kept snapshot in `BYRLE_SNAPSHOT_DIR`,
which `policy diff --snapshot` reads, holds no `cached`, so its records have `None`.

The lookup query formats it in SQL as RFC 3339 UTC to the second,
`to_char(cached AT TIME ZONE 'UTC', ...)`, so it does not depend on the session's
`TimeZone` or `DateStyle`.

## Tested

`a_refresh_keeps_when_each_advisory_was_first_stored` in `tests/postgres.rs`: two
advisory sources per refresh, a backdated `cached` kept across a refresh in both, and a
removed advisory stored again with a new time. With the `UPDATE` changed to
`SET cached = a.cached`, the test fails:

```
  left: [("datadog/npm", Some("2026-10-12T09:19:38Z")), ("osv/npm", Some("2026-10-12T09:19:38Z"))]
```
