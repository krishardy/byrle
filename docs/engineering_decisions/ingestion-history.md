# Ingestion history: a row per stream per refresh, appended

- **Status:** Implemented. `migrations/0004_ingestion.sql`, `src/intel/history.rs`,
  `PgIntel::replace`, `PgIntel::record_not_loaded`, `PgIntel::history`, `byrle refresh`,
  `byrle intel history`.
- **Related:** [snapshot-identity](snapshot-identity.md), [kev-stream](kev-stream.md),
  [datadog-stream](datadog-stream.md),
  [intel-schema-keys-and-types](intel-schema-keys-and-types.md)

## Decision

Every `byrle refresh` that fetches appends one `intel_ingestion` row per stream it loaded or
did not. No row is updated or deleted, and nothing prunes the table. `byrle intel history`
prints the newest rows first, 20 unless `--limit` says otherwise.

Before this, which feed was ingested when, and from which bundle, could not be read back:

| Record | Keeps |
|---|---|
| `intel_source` | each source's latest rows digest and streams |
| `intel_snapshot` | one row per distinct snapshot; loading the same rows again overwrites `taken_at` |
| kept snapshot files | the newest `BYRLE_SNAPSHOT_LIMIT` |

## Asked of the user, 2026-09-15

| Question | Chosen |
|---|---|
| Where the history is written | a Postgres table, beside the intel |
| How it is read back | `byrle intel history` |

## A row

| Column | Contains |
|---|---|
| `taken_at` | when the refresh recorded it; the same for every row of one refresh, and the snapshot's `taken_at` when it loaded |
| `source`, `stream` | `osv` and `osv/npm`, `cisa/kev` and `cisa/kev`, `datadog` and `datadog/npm` |
| `sha256`, `etag`, `last_modified` | the bundle and its response headers, when it was fetched |
| `rows_digest` | the rows loaded, as `intel_source.digest`; NULL when the stream did not load |
| `snapshot` | the snapshot the store contains after the refresh; NULL when the refresh loaded nothing |
| `error` | why the stream did not load; NULL when it loaded |
| `unconfigured` | the stream was not read because it is not configured, such as GitHub's with no token. Added 2026-09-29 by `0012_ingestion_unconfigured.sql`, which marks the earlier rows whose error is GitHub's missing-token message, so an upgraded proxy is ready without another refresh; the snapshot reports the streams whose latest row says so ([uncovered-ecosystem-fails-closed](uncovered-ecosystem-fails-closed.md)) |

Two `CHECK` constraints hold the shape: a row with no error has a bundle, rows digest and
snapshot, and a row with an error has no rows digest. `etag`, `last_modified` and `error` are
`TEXT`: the first two are the upstream's headers and the last is any error a refresh meets,
and none has a bound.

## When a row is written

| Refresh | Rows | Transaction |
|---|---|---|
| every stream loads | each stream, with its rows digest and the snapshot | the load's |
| KEV or Datadog is not fetched or read | the streams that loaded, and the one that did not with its error and the snapshot its last load stays in | the load's |
| OSV is not fetched or read | OSV, with its error | its own |
| a kept rows file is not written, or the load fails | every stream, with the error | its own |
| `BYRLE_DATABASE_URL` unset, Postgres unreachable, the snapshot directory or HTTP client fails | none | |

A stream that loaded is recorded in the load's transaction, so a load that rolls back leaves no
row saying it loaded. A refresh that loaded nothing records in a transaction of its own after
the failure; when that fails too, refresh prints `the ingestion history is not written` and
still exits 1.

`byrle refresh` now connects to Postgres and migrates before fetching. Before, it fetched and
read OSV's bundle first, so a refresh with Postgres down failed after downloading it.

Rows of one refresh share `taken_at`, and `intel history` orders by `id`, so they print
together. A refresh writes 3 rows while OSV, KEV and Datadog are the streams.

## Evidence

Into an empty Postgres 17, 2026-09-15: `intel history` before any refresh, then three
refreshes. The second had `HTTPS_PROXY` at a closed port with OSV's and CISA's hosts in
`NO_PROXY`, so only the Datadog fetch failed. The third had no `NO_PROXY`, so OSV's fetch
failed.

| Command | Exit | Snapshot |
|---|---|---|
| `intel history`, `BYRLE_DATABASE_URL` unset | 2, `set BYRLE_DATABASE_URL to the intel store's Postgres` | |
| `intel history` | 0, `no ingestion recorded` | |
| `refresh` | 0 | `sha256:83818356…c900` |
| `refresh`, Datadog fails | 1 | `sha256:83818356…c900` |
| `refresh`, OSV fails | 1 | none |

`intel history --limit 10` then printed 7 rows. The newest four, digests shortened here:

```text
2026-09-15T04:32:28Z osv/npm not loaded
  source        osv
  snapshot      none: the refresh loaded nothing
  error         fetching https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip: error sending request for url (...)

2026-09-15T04:32:16Z datadog/npm not loaded
  source        datadog
  snapshot      sha256:83818356…c900
  error         fetching https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json: error sending request for url (...)

2026-09-15T04:32:16Z cisa/kev loaded
  source        cisa/kev
  bundle sha256 9630fea2…fbfe
  etag          "1a49eb-65b760a9b62c0"
  last-modified Mon, 14 Sep 2026 19:00:02 GMT
  rows          sha256:74da28d9…eb5c
  snapshot      sha256:83818356…c900

2026-09-15T04:32:16Z osv/npm loaded
  source        osv
  bundle sha256 1b017e5f…22bc
  etag          "9a08e164c1ba74c58eab3aab87ee7c5a"
  last-modified Tue, 15 Sep 2026 04:25:50 GMT
  rows          sha256:51a7092f…983d
  snapshot      sha256:83818356…c900
```

The first refresh's three rows follow, all `loaded` with the same snapshot. Datadog's has no
`last-modified`: raw.githubusercontent.com sent none.

Those refreshes ran with no `BYRLE_SNAPSHOT_DIR`. `run_refresh` now writes kept rows files
after connecting, from the loads it builds, so a refresh with the directory set was run too: it
wrote the 3 rows files and `83818356…c900.snapshot`, the same set as before this change.

| Test | Covers |
|---|---|
| `every_stream_a_refresh_tried_is_appended_to_the_history` | loaded and not-loaded rows in the load's transaction, nothing from a failed load, a refresh that loaded nothing, the `CHECK` |
| `every_table_is_keyed_by_an_identity_and_only_an_unbounded_column_is_text` | `intel_ingestion`'s key and its 3 `TEXT` columns |
| `each_entry_prints_what_it_records_and_whether_it_loaded`, `no_entry_says_so` | `intel history`'s output |
| `each_command_parses_to_its_arguments`, `a_malformed_command_line_is_refused_with_the_reason` | `--limit` default, 1, 0 and `many` |

`make mutants` over the change: 19 mutants, 4 caught, 7 unviable, 8 missed. 5 are in `main.rs`,
which has no unit tests: `main`, `run_intel_history`, `run_refresh` and `nothing_loaded`
returning a default exit code, and `optional` returning `None`. The runs above exit 0, 1 and 2.
The other 3 are `record`, `record_not_loaded` and `history` in `postgres.rs`, which `make
mutants` tests without a database. With `BYRLE_TEST_DATABASE_URL` set, `cargo mutants --file
src/intel/postgres.rs` over those three gave 4 mutants, 3 caught and 1 unviable.
