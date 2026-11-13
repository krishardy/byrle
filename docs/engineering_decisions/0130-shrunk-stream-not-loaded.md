# A stream that parses to under half its stored rows is not loaded, unless forced

- **Number:** 0130
- **Status:** Implemented 2026-11-04, for finding 11 of the security review (TODO.md ad-hoc
  #50): `Read::refuse_shrunk` in `src/intel/fetch.rs`, `PgIntel::stored_rows` in
  `src/intel/postgres.rs`, `--force` on `byrle refresh` in `src/cli.rs`. The approach below
  was chosen while implementing it.
- **Related:** [stream-descriptor-table](0043-stream-descriptor-table.md),
  [snapshot-identity](0036-snapshot-identity.md)

## Decision

`byrle refresh` reads how many rows each source has (`advisory` rows, or `exploited_cve`
rows for `cisa/kev`) before it writes. A stream whose parse has fewer than half of them is
not loaded:

| Parsed | Stored | Loaded |
|---|---|---|
| 2 | 4 | yes |
| 2 | 5 | no |
| 0 | 1 | no |
| 0 | none | yes: nothing is erased |
| any | any, with `--force <stream>` | yes |

A stream not loaded is the same as one that did not parse: its last load stays, its
`intel_source` digest is kept, `intel history` records it with the error, and the refresh
exits 1. The error is `it parsed to N rows, under half the M stored; byrle refresh --force
<stream> loads it`.

`--force` is repeatable and takes a stream `stream::all` declares, so forcing one stream
that really shrank does not load another stream cut short in the same run.

## Why

Each load of a source runs `DELETE FROM advisory WHERE source = $1` and copies the new rows
(`replace_rows`). An OSV zip with no entries parsed, so an empty or truncated export, or a
mirror under `BYRLE_STREAM_URLS` serving a subset, erased the source's `MAL-` rows. KEV,
Datadog and GitHub refuse empty input, and no parser can tell a subset from the whole.

## Rejected

| Option | Why not |
|---|---|
| refuse an empty OSV zip in `read_bundle` only | a bundle cut to one record still erases the rest |
| a global `--force` | it would also load another stream cut short in the same run |
| compare in `write_source`, after the `LOCK` | a refused source would have to leave the transaction's `sources` and join its `not_loaded`; reading the counts before is one query, and only two refreshes at once see a different count |

## Cost

A source that really shrinks by half or more, such as OSV withdrawing most of an ecosystem's
records, is not loaded until an operator runs `byrle refresh --force <stream>`.
