# Snapshot identity

- **Status:** Implemented 2026-09-14: the id, the snapshot files `waharoa refresh` writes, and
  `policy diff --snapshot`, which reads them. Import is not built. `load::encode`,
  `load::Decoder`, `load::manifest` and `load::snapshot_id` in `src/intel/load.rs`,
  `PgIntel::replace_encoded` in `src/intel/postgres.rs`, `intel_source` in
  `migrations/0001_intel.sql` (rewritten), `SnapshotDir` in `src/intel/snapshot_dir.rs`,
  `SnapshotIntel` in `src/intel/snapshot_intel.rs`.
- **Related:** [osv-malware-load](osv-malware-load.md),
  [osv-ranges-and-scores](osv-ranges-and-scores.md),
  [intel-schema-keys-and-types](intel-schema-keys-and-types.md),
  [readiness-endpoint](readiness-endpoint.md)

## What the id is for

| Use | Where | What it needs from the id |
|---|---|---|
| Audit attribution | `intel_snapshot` on each audit line | same id, same rows read |
| Replica agreement | plan §3, `GET /-/waharoa/ready`, `waharoa doctor` | same id, same rows in the database |
| One `intel_snapshot` row per set of rows | `ON CONFLICT (digest)` in `replace_source` | same rows, same id |
| `policy diff --snapshot` | reads a kept snapshot | an older snapshot to select |
| Air-gapped export and import | plan §7, Stage 5 | a file an import can check |

## The defect

The id hashed the bundle bytes. The malware-only loader and the loader after it stored
different rows from one bundle, and both recorded
`sha256:cf3822e6036d97297ed303a25fd3330eab20d13671495aea49b5c435f0c3392f`. A snapshot row
also listed only the streams its own refresh fetched, so with two sources refreshed apart,
the newest id would not cover the other source's rows.

## Decision

The id is a hash over every source's stored rows.

`load::encode` writes one source's rows as below, and its sha256 is `intel_source.digest`:

```text
waharoa intel rows 1
source osv
advisory 23771415
(23,771,415 bytes of CSV)
advisory_alias 1149815
(1,149,815 bytes of CSV)
advisory_affected 9360804
(9,360,804 bytes of CSV)
advisory_range 437575
(437,575 bytes of CSV)
```

Each table's CSV is the `COPY` encoding, and the `advisory` CSV is the bytes `COPY` sends.
Records are sorted by publisher id. A child row carries its advisory's position in that
order, from 1.

`load::snapshot_id` hashes one `source digest` line per `intel_source` row, sorted, and that
is `intel_snapshot.digest`. `replace_source` computes both inside its transaction. It locks
`intel_source` first (`SHARE ROW EXCLUSIVE`, which a lookup's reads do not wait for), so a
refresh of another source waits and then reads the new digest.

The bundles' sha256, etag and `last-modified` are recorded in `streams` and hashed into
nothing. Two bundles that load the same rows are one snapshot.

The plan says `intel_snapshot_id` must be read from the database rather than computed
locally. That is still true: refresh computes it once and writes it, and every proxy reads it from
`intel_snapshot`.

The encoding has to equal what the database stores:

| Value | Encoded as | Why it matches the row | Test |
|---|---|---|---|
| `modified` | UTC, rounded to the microsecond | Postgres keeps microseconds, so the value sent is stored exactly. OSV writes nanoseconds | `modified_is_written_in_utc_to_the_microsecond`, `timestamps_written_as_rfc_3339_are_stored_as_timestamps` |
| `cvss` | `f64` `Display` | Postgres 17 prints a `DOUBLE PRECISION` as the shortest text that reads back, as Rust does | `a_stored_score_prints_as_the_encoding_wrote_it` |
| a child row's advisory | position by publisher id | the key Postgres assigns differs between databases | `an_encoding_numbers_advisories_by_publisher_id_and_gives_each_table_its_length` |

A `modified` that does not parse as RFC 3339 is sent as it is. All 228,245 stored on
2026-09-13 parsed.

## Where older snapshots are kept

Measured on `npm/all.zip` fetched 2026-09-13, 214,977,916 bytes, release build:

| Step | Result |
|---|---|
| `read_bundle` | 2.76 s |
| Encode the four CSVs | 67 ms |
| sha256 of them | 15 ms |
| The four CSVs | 34,719,609 bytes |
| gzip -6 | 5,816,758 bytes |
| zstd -19 | 4,447,405 bytes |
| `advisory`, `advisory_affected`, `advisory_alias`, `advisory_range` in Postgres, with indexes | 98 MB |

`npm/modified_id.csv` fetched 2026-09-13 lists 228,951 records. 1,581 (0.69%) were modified
in the 7 days before its newest entry, and 4,608 (2.01%) in 30 days.

| Option | Cost per kept snapshot | Lookups | Chosen |
|---|---|---|---|
| A full copy per snapshot in Postgres | 98 MB | every index gains a snapshot column | no |
| Advisory rows shared across snapshots, and a membership table | about 0.7% new rows a week, and 228,245 membership rows per snapshot (size not measured) | every lookup joins the membership table | no |
| Postgres keeps the latest load; each load is also written as files of the encoding | 5,577,231 bytes with `flate2` gzip, live | unchanged | yes |

gzip rather than zstd: `flate2` is already a dependency, and the `zip` features in
`Cargo.toml` leave zstd out on purpose. It costs 1.1 MB per snapshot against `zstd -19`.

## Snapshot directory

With `WAHAROA_SNAPSHOT_DIR` set, `waharoa refresh` keeps each snapshot there. Every file is
named by the sha256 of what it contains:

| File | Contains |
|---|---|
| `<hex>.rows.gz` | one source's `load::encode` output, gzipped. `<hex>` is `intel_source.digest` |
| `<hex>.snapshot` | `load::manifest`: one `source digest` line per source. `<hex>` is the snapshot id |

A snapshot is its manifest and the rows files it names, so a source whose rows did not change is
one file shared by every snapshot that has it. Reading a file checks its contents against its
name. An import will check a snapshot the same way.

| Step | When | If it fails |
|---|---|---|
| Lock `.lock` in the directory | before the fetch, held until exit | exit 1, nothing fetched |
| Write this source's rows file | after the bundle is read, before the load | exit 1, nothing loaded |
| Load into Postgres | as before | exit 1, previous load in place. The rows file stays until a prune |
| Write the manifest | after the load commits, once every rows file it names exists | exit 1, and Postgres has a snapshot the directory does not |
| Prune | after the manifest | exit 1 |

Rows are written before the load so a snapshot in Postgres never names rows the directory
lacks because of this refresh. A rows file from another source that was loaded before the
directory was set is reported by name, and refreshing that source writes it. Each file is
written to `<name>.partial`, flushed, and renamed, so a crash leaves no truncated file under a
real name; a prune removes `.partial` files.

The lock serializes refreshes into one directory. Without it, a prune could remove the rows
file another refresh had written and not yet named in a manifest.

## Reading a kept snapshot

`waharoa policy diff --snapshot <id>` reads snapshot `<id>` from `WAHAROA_SNAPSHOT_DIR` and
answers every package from it instead of Postgres. `WAHAROA_DATABASE_URL` is not needed.

| Step | What is checked |
|---|---|
| Read `<hex>.snapshot` | its contents hash to `<id>` |
| Read each `<hex>.rows.gz` it names | the decompressed contents hash to the digest in the name |
| `load::Decoder` reads the rows one at a time | the file contains the source the manifest lists; each row encodes back to the bytes it was read from and follows the row before it |
| `SnapshotIntel` keeps the records of the packages it is read for | every stored range of those packages parses as SemVer |

Encoding each row again and comparing it with its bytes is what makes a reader that differs
from the writer fail rather than answer. Requiring each row to follow the one before it, by
publisher id and then by position and row, refuses a row repeated or moved, which the
comparison of one row alone accepts.

One row is decoded at a time, and only the records of the packages asked for are kept.
`policy diff` reads its audit log before the snapshot and asks for the packages the log lists.
A package the snapshot was not read for is `IntelError::Unread`, not an empty answer.

The reader takes no lock. A refresh writes a new file under `.partial` and renames it, and
never changes a file in place, so a read cannot see half a file, and a file that does not hash
to its name is refused. A prune can remove a file while `policy diff` reads, which fails the
read. Taking the lock instead would make every refresh wait for every `policy diff`, which
fetches packuments and can run for minutes.

A kept snapshot records no streams, and its `taken_at` is when the manifest was last written.

`WAHAROA_SNAPSHOT_LIMIT`, default 30, is the most manifests the directory keeps. A prune
keeps the newest by modification time and removes the rest. A manifest loaded again is written again, so it counts as the newest.
Rows files that no kept manifest names are removed. Other files are left alone.

## Migration

`0001_intel.sql` is rewritten rather than followed by a `0003`, as `0002` was. Nothing is
deployed. A database migrated from the old `0001` fails sqlx's checksum check and has to be
recreated.

## Not done here

| Item | Where |
|---|---|
| Export and import | TODO.md Stage 5, offline and air-gapped mode |

## Evidence

`waharoa refresh` twice against Postgres 17, debug build, the same bundle (etag
`"b4c5724078934a1570170d39825325c2"`):

```
advisories written                 228245
aliases written                     37951
affected rows written              233239
ranges written                      10326
snapshot sha256:225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9
took 49.0s
```

The second run printed the same counts and snapshot and took 55.6s. The tables after it:

```
intel_snapshot  sha256:225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9
intel_source    osv  sha256:dad3f11d255aa4b00a3819d9c9631b101e7fa9a2daeb64d86879014210b16ee5
```

One row in each. The same load took 46.9s and 49.4s under the bundle-digest id
([intel-schema-keys-and-types](intel-schema-keys-and-types.md)).

With `WAHAROA_SNAPSHOT_DIR` set, the same bundle, debug build. The first run took 51.9s; later
runs shared the machine with a test run and are not timings.

```
snapshot sha256:225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9
snapshot file                    .../kept-live/225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9.snapshot
snapshot files removed                  0
rows files removed                      0
```

The directory after a second run, and each file's contents hashed:

```
      76  225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9.snapshot
 5577231  dad3f11d255aa4b00a3819d9c9631b101e7fa9a2daeb64d86879014210b16ee5.rows.gz
dad3f11d...b16ee5.rows.gz contents sha256 dad3f11d255aa4b00a3819d9c9631b101e7fa9a2daeb64d86879014210b16ee5
225131ad...c40b9.snapshot contents sha256 225131ada035512e110d0c18f027cb1832a200dfc231df294931e518d36c40b9
osv sha256:dad3f11d255aa4b00a3819d9c9631b101e7fa9a2daeb64d86879014210b16ee5
```

An older snapshot and its rows were then placed in the directory, dated a day earlier, and
the refresh run again with `WAHAROA_SNAPSHOT_LIMIT=1`. It printed `snapshot files removed 1`
and `rows files removed 1`, and left the two files above.

Reading that snapshot back, against Postgres holding the same load. A temporary example read
the kept snapshot in a release build, then asked both stores `package()` for every package
the rows name, lists compared sorted:

```
SnapshotIntel::read 626.387171ms, VmHWM:	  456992 kB
packages 224391
same 224391, differ 0, compared in 59.710736861s
```

`policy diff` over four audit-log packages (lodash 4.17.20 and 4.17.21, minimist 1.2.5,
left-pad 1.3.0), debug build:

| Store | Report | Exit | Time | Peak RSS |
|---|---|---|---|---|
| Postgres | `nothing moved` | 0 | 0.5s | 28 MB |
| `--snapshot`, `WAHAROA_DATABASE_URL` unset, every package read | `nothing moved`, identical | 0 | 3.8s | 468 MB |
| `--snapshot`, `WAHAROA_DATABASE_URL` unset, the 4 packages read | `nothing moved`, identical | 0 | 3.0s | 103 MB |

Both policies had an effective `max_cvss` under 7.9, so nothing moved. With `max_cvss: 7.0`
against `max_cvss: 9.0`, `--snapshot` gives:

```
pkg:npm/lodash@4.17.20  block -> allow
    max_cvss          FAIL block -> pass  (LOOSER)
pkg:npm/lodash@4.17.21  block -> allow
    max_cvss          FAIL block -> pass  (LOOSER)

waharoa policy diff: 2 loosened, 0 incomparable
```

and exits 1. With no store and no snapshot the same two policies give `nothing moved`.

Refused, each exit 2 when run, and 4 since
[policy-diff-dates-and-exit-bits](policy-diff-dates-and-exit-bits.md):

```
--snapshot sha256:2251...: WAHAROA_SNAPSHOT_DIR is not set, so there is no kept snapshot to read
--snapshot latest: `latest` is not `sha256:` and 64 lowercase hex digits
--snapshot sha256:0000...: .../0000...0000.snapshot: No such file or directory (os error 2)
```

Reading npm's snapshot, release build, one read per process. A temporary example measured
peak RSS and, with a counting allocator, the bytes allocated:

| Read | Peak RSS |
|---|---|
| Every record decoded to `Rows`, then encoded again whole | 462 MB |
| The same, not encoded again | 381 MB |
| One row at a time, every package kept | 304 MB, 195 MB of it the packages |
| One row at a time, the 4 packages kept | 98 MB |
| The same, the gunzipped buffer reserved at the length in the gzip trailer, at most 16 times the file | 84 MB |

The gunzipped rows, 34,681,127 bytes, are in memory while they are decoded. Without the
reservation, the buffer grows to 67 MB while holding 35 MB.

Each mutation below was caught:

| Mutation | Caught by |
|---|---|
| Records not sorted before encoding | `an_encoding_is_the_same_for_rows_in_any_order_and_changes_with_any_row` |
| No table lengths | `an_encoding_numbers_advisories_by_publisher_id_and_gives_each_table_its_length` |
| Positions from 0 | the same |
| Source left out of the encoding | the same |
| `modified` not rounded | `modified_is_written_in_utc_to_the_microsecond` |
| A `modified` that does not parse sent as empty | the same |
| Sources not sorted before hashing | `a_snapshot_id_is_the_same_for_sources_in_any_order_and_changes_with_any_digest` |
| No lock on `intel_source` | `a_refresh_waits_for_another_sources_uncommitted_digest` |
| Id from the loaded source's digest only | `the_snapshot_id_covers_every_source_in_the_store`, `a_refresh_waits_for_another_sources_uncommitted_digest` |

The snapshot directory, each caught:

| Mutation | Caught by |
|---|---|
| Rows rewritten when already kept | `rows_already_kept_are_not_written_again` |
| Manifest written with a rows file missing | `a_snapshot_naming_rows_not_kept_is_not_written` |
| Manifest not checked against its id | `a_file_whose_contents_do_not_hash_to_its_name_is_refused` |
| Rows not checked against their digest | the same |
| No lock | `a_second_open_waits_until_the_first_is_dropped` |
| Oldest kept instead of newest | `prune_keeps_the_newest_snapshots_and_only_the_rows_they_name`, `a_snapshot_written_again_is_the_newest` |
| Rows no kept manifest names left in place | `prune_keeps_the_newest_snapshots_and_only_the_rows_they_name` |
| `.partial` files left in place | the same |
| A digest longer than 64 digits, or with letters past `f`, made into a path | `a_value_that_is_not_a_digest_never_becomes_a_path` |
| `.partial` never renamed | 6 tests, `a_load_is_kept_as_rows_named_by_digest_and_a_snapshot_named_by_id` among them |
| `WAHAROA_SNAPSHOT_LIMIT=0` accepted | `a_value_that_does_not_parse_is_an_error_naming_the_variable_and_the_value` |

Reading a kept snapshot, when every record was decoded to `Rows` and every package kept, each
caught:

| Mutation | Caught by |
|---|---|
| Decoded rows not encoded again and compared | `bytes_that_are_not_an_encoding_are_refused_with_the_reason` |
| A doubled quote read as nothing | `decoding_an_encoding_gives_back_the_rows` |
| `fixed` and `last_affected` swapped | the same, and `a_kept_snapshot_answers_each_package_from_its_rows` |
| Position 0 read as position 1 | `bytes_that_are_not_an_encoding_are_refused_with_the_reason` |
| Bytes after `advisory_range` accepted | the same |
| Rows of another source accepted | `rows_of_another_source_than_the_snapshot_names_are_refused` |
| `taken_at` rounded rather than cut to the second | `a_snapshot_reports_when_it_was_last_written_to_the_second` |
| Every record given the source `osv` | `every_source_in_the_snapshot_answers` |
| Aliases dropped | `a_kept_snapshot_answers_each_package_from_its_rows` |
| Ranges dropped | the same |
| A listed version read as every version | the same |
| A package nothing is against given no snapshot id | `a_package_nothing_is_against_is_an_empty_answer_naming_the_snapshot` |

Reading one row at a time for the packages asked for, each caught:

| Mutation | Caught by |
|---|---|
| No row encoded again and compared with its bytes | `bytes_that_are_not_an_encoding_are_refused_with_the_reason` |
| No order check | the same |
| A repeated advisory accepted | the same |
| A repeated alias accepted | the same |
| Affected rows out of order accepted | the same |
| Ranges out of order accepted | the same |
| A repeated range accepted | the same |
| A table length `encode` does not write, such as `+0`, accepted | the same |
| Bytes after `advisory_range` accepted | the same |
| Position 0 read as position 1 | the same |
| Positions encoded again from 0 | 8 tests, `decoding_an_encoding_gives_back_the_rows` among them |
| Rows of another source accepted | `rows_of_another_source_than_the_snapshot_names_are_refused` |
| Every affected package kept | `a_package_the_snapshot_was_not_read_for_is_an_error_and_is_not_kept` |
| Every range parsed and kept | the same |
| A package not read answered as nothing known | the same |
| Aliases dropped | `a_kept_snapshot_answers_each_package_from_its_rows` |
| A range given the advisory at index 0 | the same |

`policy diff` builds the package set in `src/main.rs`, which no test runs. The live run above
reads the snapshot for the 4 packages and gives the report Postgres gives.
