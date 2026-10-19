# Advisory rows are named by their unique index, and a refresh writes only what changed

- **Number:** 0121
- **Status:** Decided by the user 2026-10-19, as "Do all" of
  [postgres-review](../postgres-review.md). Implemented 2026-10-19:
  `migrations/0030_advisory_indexes.sql`, `write_source`, `replace_rows`, `write_advisories`
  and `PgIntel::package` in `src/intel/postgres.rs`, `read_dispositions` in
  `src/analysis/postgres.rs`.
- **Related:** [intel-schema-keys-and-types](0031-intel-schema-keys-and-types.md),
  [advisory-cached](0102-advisory-cached.md), [snapshot-identity](0036-snapshot-identity.md)

## Decision

| Change | Replaces |
|---|---|
| `advisory_affected` and `advisory_range` have no `id`. Each row is named by its unique index, led by `advisory_id`, which `ON DELETE CASCADE` reads by. `advisory_alias_by_alias` is dropped | 0031's "every intel table is keyed by `BIGINT GENERATED ALWAYS AS IDENTITY`", for these two tables |
| A source whose digest is the one `intel_source` holds is not written again. `byrle refresh` prints `sources unchanged` | a delete and copy of every source on every refresh |
| `advisory` is copied into the temporary table `advisory_load`, then inserted with `cached` from `prior_cached`, or `now()` | 0102's `UPDATE` of every row after the copy |
| `PgIntel::package` answers one row per advisory, its versions and ranges each `array_agg`ed | one row per `advisory_affected` and `advisory_range` row |
| A disposition by version filters `artifact_decision` before `DISTINCT ON (digest)` | the `artifact_disposition` view, filtered after it. The view still answers a digest |

## Why

Measured in [postgres-review](../postgres-review.md), sections 1 to 4: 86,581 ms to 0.55 ms
for a disposition by version over 1,000,000 decisions; 286 ms to 37 ms for jenkins-core's
intel; `advisory_affected` at 393 MB after one refresh and 1,353 MB after four of the same
feeds; 57 MB of index no query read.

No query, foreign key or `COPY` reads `advisory_affected.id` or `advisory_range.id`.

Measured after the change, 2026-10-19, the same feeds into a new database:

| | Before | After |
|---|---|---|
| `advisory_affected` after one refresh, total and indexes | 393 MB, 219 MB | 325 MB, 169 MB |
| a refresh of unchanged feeds | 35.1 to 37.2 s, every row rewritten | 6.7 to 7.7 s, `sources unchanged 8` |
| a refresh with one source changed, `datadog/pypi`'s 1,835 advisories | each inserted, then updated | 1,834 inserted, 0 updated |
| jenkins-core's intel, three runs | 298 to 303 ms | 38 to 41 ms |
| praisonai's | 287 to 372 ms | 33 to 39 ms |
| tensorflow's | 136 to 146 ms | 22 ms |

The unique index stays led by `advisory_id`. Led by `(ecosystem, name)`, as the review tried,
it was 241 MB after one refresh and 142 MB rebuilt: a copy writes rows in advisory order, so
an index in another order fills half its pages. `adv` in `PgIntel::package` is not
`MATERIALIZED`: with it the planner read all 325,073 advisories, 70 to 77 ms for
jenkins-core.

## What it costs

0031 rejected staging tables because the staging DDL repeats every column size and an
over-long value is reported against the staging table. `advisory_load` is
`CREATE TEMP TABLE ... AS SELECT <columns> FROM advisory WITH NO DATA`, so it takes
`advisory`'s sizes with no DDL of its own. An over-long `advisory` value is reported as
`COPY advisory_load`; the child tables are copied directly, as before.

A source loaded again with the same digest keeps its rows. A row changed in the database by
hand stays changed until the source's rows change.

## Held by

- `a_source_whose_rows_did_not_change_is_not_written_again` and
  `every_table_is_keyed_by_an_identity_and_only_an_unbounded_column_is_text`, with
  `KEYED_BY_THEIR_UNIQUE_INDEX`, in `tests/postgres.rs`.
- `the_advisory_copy_names_the_advisory_columns` in `src/intel/load.rs`.

`make mutants BASE=HEAD~1` over the change: 25 mutants, 9 missed, because
`tests/postgres.rs` skips with no database. Run again with `BYRLE_TEST_DATABASE_URL` set
to a local cluster and one job at a time, since the tests share database names: 12 caught,
13 unviable, 0 missed. Since then `make mutants` starts a Postgres itself and sets
`BYRLE_TEST_SCHEMA_PER_PROCESS=1`, so each job's tests use their own schemas. With 2 jobs:
14 caught, 13 unviable, 0 missed. With the default 4, the out-of-memory killer ended 6 of
the builds, which were reported unviable.
