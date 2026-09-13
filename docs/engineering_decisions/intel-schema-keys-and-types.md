# Intel schema: surrogate keys and sized types

- **Status:** Implemented 2026-09-13. `migrations/0001_intel.sql` and
  `migrations/0002_ranges.sql` (rewritten), `src/intel/load.rs`, `PgIntel::replace_source` in
  `src/intel/postgres.rs`.
- **Related:** [storage-sqlx-postgres](storage-sqlx-postgres.md),
  [osv-malware-load](osv-malware-load.md), [osv-ranges-and-scores](osv-ranges-and-scores.md)

## Decision

Every intel table is keyed by `BIGINT GENERATED ALWAYS AS IDENTITY`, and tables join on it. A
publisher's id, such as `GHSA-2234-fmw7-43wr`, is `advisory.publisher_id`, a sized column with
a unique constraint. A snapshot's digest is `intel_snapshot.digest`, the same. Timestamps are
`TIMESTAMPTZ`. `advisory.summary` is the only `TEXT` column, because OSV does not bound it.

Strings are sized from the longest value in OSV's npm bundle of 2026-09-13, 228,951 records,
with headroom for other ecosystems:

| Column | Longest measured | Size |
|---|---|---|
| `publisher_id`, `alias` | 68, `SNYK-JS-NATIONALGEOGRAPHICSOCIETYNGSUIHEADERAUTHPROVIDERNEXT-9634209` | `VARCHAR(128)` |
| `ecosystem` | 14, `GitHub Actions` | `VARCHAR(64)` |
| `name` | 213 (npm allows 214) | `VARCHAR(512)` |
| `version`, `introduced`, `fixed`, `last_affected` | 74 | `VARCHAR(255)` |
| `source`, `cvss_source` | 3, `osv` | `VARCHAR(32)` |
| `digest` | 71, `sha256:` and 64 hex digits | `VARCHAR(71)`, no headroom |

`digest` is exact because `refresh::snapshot` produces one width, and
`the_snapshot_digest_depends_on_the_stream_digests_and_nothing_else` asserts it. Another hash
fails the snapshot insert and needs a migration.

A value longer than its column fails the refresh. The transaction rolls back, the previous
load stays, and the error names the table, line and column from Postgres's `where` field:

```
waharoa refresh: nothing loaded: intel store: error returned from database: value too long for type character varying(512) (COPY advisory_affected, line 1, column name: "xxxx...")
```

Postgres cuts the quoted value at 100 characters. The context was reproduced with `psql` against
the new migrations, a 513-character `name`:

```
ERROR:  value too long for type character varying(512)
CONTEXT:  COPY advisory_affected, line 1, column name: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..."
```

The limit is then raised in a migration. Skipping the record instead was rejected: the
refresh would succeed without an advisory that may be malware.

## Loading with keys the loader cannot know

`load.rs` builds CSV with no database, and an identity is assigned by Postgres. In one
transaction:

1. `DELETE FROM advisory WHERE source = $1`.
2. `COPY advisory`.
3. `SELECT publisher_id, id FROM advisory WHERE source = $1`.
4. `load::children` builds the alias, affected and range CSV carrying those keys, and each is
   copied into its own table.

`COPY` goes straight into the sized tables, so an over-long value is reported against the real
table and column.

Live, 2026-09-13, debug build, Postgres 17, the same bundle as
[osv-ranges-and-scores](osv-ranges-and-scores.md):

| | TEXT keys | Surrogate keys |
|---|---|---|
| advisories | 228,245 | 228,245 |
| aliases | 37,951 | 37,951 |
| affected rows | 233,239 | 233,239 |
| ranges | 10,326 | 10,326 |
| snapshot | `sha256:cf3822e6...3c392f` | `sha256:cf3822e6...3c392f` |
| `waharoa refresh` | 46.9s | 49.4s |

All 228,245 advisories have `modified`. The database is 106 MB. The lookup by package uses both
indexes:

```
Nested Loop  (actual time=0.023..0.024 rows=0 loops=1)
  ->  Index Scan using advisory_affected_lookup on advisory_affected m
        Index Cond: (((ecosystem)::text = 'npm'::text) AND ((name)::text = 'lodash'::text))
  ->  Index Scan using advisory_pkey on advisory a  (never executed)
        Index Cond: (id = m.advisory_id)
Execution Time: 0.117 ms
```

## Timestamps

`modified` and `taken_at` are written as RFC 3339 text and cast by Postgres:
`$2::text::timestamptz`, and `COPY` parses the text. Nothing reads a timestamp back into Rust,
so the codebase keeps one date library, jiff, which sqlx 0.8 has no mapping for. Postgres keeps
microseconds; OSV writes `modified` to the nanosecond, so it is rounded.

## Migrations rewritten, not added to

`0001_intel.sql` and `0002_ranges.sql` hold the new shape. No `0003` was added. sqlx records a
checksum of each applied migration, so a database that applied the old files fails to start:

```
migration 1 was previously applied but has been modified
```

Drop that database and run `waharoa refresh`. The store is a mirror of the advisory streams, so
nothing is lost that a refresh does not restore.

## Rejected

| Alternative | Why not |
|---|---|
| A new `0003` that drops and recreates the tables | The user chose rewriting: nothing is deployed, and the history would carry a schema the rule forbids |
| A new `0003` that alters in place | Longer and harder to read than the schema it produces, to keep rows a refresh restores |
| UUID keys assigned in Rust before `COPY` | A new crate and sqlx feature, and a 16-byte key where 8 does |
| `COPY` into temporary staging tables keyed by publisher id, then `INSERT ... SELECT` | Repeats every column size in the staging DDL, and an over-long value is reported against the staging table |

## Held by

- `every_table_is_keyed_by_an_identity_and_only_an_unbounded_column_is_text` in
  `tests/intel_postgres.rs` reads `information_schema`. It fails on a `TEXT` column other than
  `advisory.summary`, a `VARCHAR` with no length, a table whose primary key is not a `BIGINT`
  identity `id`, or an `advisory_id` that is not `BIGINT`. A new table is checked with no
  change to the test.
- `a_value_longer_than_its_column_fails_the_load_and_names_the_column`.
- `a_failed_refresh_leaves_the_previous_load_in_place` checks the duplicate is refused by
  `advisory_publisher_id_key`. Without that constraint the load still failed, later, on
  `advisory_affected_unique`, and a test that checked only for an error passed.
- `timestamps_written_as_rfc_3339_are_stored_as_timestamps`.
- `a_child_row_carries_its_advisory_key_rather_than_the_publisher_id` and
  `a_record_with_no_key_is_an_error_naming_it` in `src/intel/load.rs`.
