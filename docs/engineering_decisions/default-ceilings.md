# Default ceilings

- **Status:** Implemented. The `DEFAULT_` constants in `src/env.rs`.
- **Related:** [environment-variables](environment-variables.md),
  [packument-body-inspection](packument-body-inspection.md),
  [no-metadata-cache](no-metadata-cache.md), [artifact-spool](artifact-spool.md),
  [snapshot-identity](snapshot-identity.md)

## Decision

| Default | Value | Why |
|---|---|---|
| `BYRLE_MAX_METADATA_BYTES` | 64 MiB | the largest packument measured is vite's full document, 38,950,704 bytes on 2026-09-26, so this is 1.7x headroom. It was 32 MiB, twice typescript's 15.7 MB, until vite outgrew it and a cooldown and the provenance check could not read its publish times. It bounds both the bytes buffered and the bytes decompression produces |
| `BYRLE_MAX_RECORDS` | 50,000 | about five installs of the size measured in `store`; 45 to 70 MB at 0.9 to 1.4 KB per record |
| `BYRLE_MAX_VERIFIED` | 50,000 | an entry is an algorithm and a digest, about 64 bytes. An artifact reaches `verified` only after a packument named it, so more than the record budget would be unused |
| `BYRLE_MAX_CONCURRENT_METADATA` | 8 | see below |
| `BYRLE_MAX_CONCURRENT_ANALYSES` | 8 | as for metadata. At the default artifact ceiling the spool holds at most 8 GiB |
| `BYRLE_MAX_TRAFFIC_CLIENTS` | 256 | a new client name past it is counted as `other`, so a user-agent made up per request cannot grow the map. A team's proxy sees a handful: npm, pnpm, yarn, bun, pip and uv |
| `BYRLE_MAX_ARTIFACT_BYTES` | 1 GiB | an order of magnitude above the largest artifact a detector reads, `opencv-python` 5.0.0.93 at 81,802,749 bytes, so it refuses an artifact whose length is a lie rather than one anybody publishes |
| `BYRLE_WATCH_INTERVAL` | 900 seconds | one metadata request per served package per pass, about one every 2 seconds for 500 packages. 0 turns the watcher off ([watcher](watcher.md)) |
| `BYRLE_SOURCE_ARCHIVES` | `https://codeload.github.com` | the host of GitHub's archives, which each artifact is compared with. 2 comparisons run at once, apart from the analyses, and the last 8 archives read are kept so one repository's packages fetch it once. `off` turns it off ([source-diff](source-diff.md)) |
| `BYRLE_DETECTORS` | none | a detector runs a program per version: 1.2 s median for GuardDog, 40 s the slowest measured. 2 run at once, each killed after 300 s or 16 MiB of output ([detectors](detectors.md)) |
| `BYRLE_EXPIRY_CEILING_DAYS` | 90 | long enough for a review cycle, and an entry nobody looks at again lapses within a quarter |
| `BYRLE_SNAPSHOT_LIMIT` | 30 | a month of daily refreshes. npm's rows were 5,577,231 bytes gzipped on 2026-09-13, and a source whose rows did not change is not written again |

Over the metadata ceiling the proxy forwards the response without normalising it: an
install does not fail because the proxy could not inspect the document.

## Concurrent metadata documents

Reading a packument costs more than its bytes on the wire: the decoded copy, the JSON value
tree the rewrite walks, the serialised output and the gzip buffer are live together.

| Load | Peak |
|---|---|
| 24 simultaneous requests for the largest full packuments (typescript, @types/node, react, next, @angular/core, eslint, webpack, aws-sdk), 27.6 MB encoded, no limit | 1,348 MB, about 56 MB per request |
| 8 simultaneous requests for vite's 38.9 MB full document, release build, 2026-09-26 | 916 MB, about 113 MB per request |
| a six-package install with 165 packuments | 141 MB, held down by npm's own request parallelism |

Eight kept the worst case near half a gigabyte when typescript's 15.7 MB was the largest
packument.

### As deployed, 2026-10-14

`make memory` (`scripts/make/memory.sh`) runs the proxy as `make bench` does: a token
required, Postgres intel, the default policy and usage recorded. Each load is on a fresh
process; RSS is sampled every 0.2 s, and idle is 30 s after the load ends. In MB:

| Load | peak | median while loaded | idle |
|---|---|---|---|
| `npm ci`, 207 packages, cold proxy | 376 | 319 | 352 |
| `uv pip install`, 18 packages, cold proxy | 133 | 120 | 125 |
| 8 at once: vite's full document | 918 | 173 | 69 |
| 24 at once: the 8 largest documents, 3 times each | 700 | 537 | 499 |

Before 2026-10-14 the same loads peaked at 586, 131, 923 and 1,181 MB. A cooldown refuses
recent versions of nearly every large package, and removing them parsed the document
into a `serde_json::Value` tree. The 24-document load without Postgres, one check on at a
time:

| Policy | peak | idle |
|---|---|---|
| none | 639 | 371 |
| the defaults | 1,425 | 1,224 |
| only `cooldown_days` | 1,446 | 1,233 |
| only `provenance` | 860 | 787 |
| only `install_scripts` | 874 | 699 |
| only `kev` | 495 | 348 |
| only `yanked` | 535 | 385 |
| the defaults, removal by slices | 778 | 418 |

`npm::rewrite::filter_unservable_versions` now reads the document as slices of itself
and points the kept URLs at the proxy with the same byte replacement as an unfiltered
document. PyPI's JSON index removal still builds the tree; its documents are small.

With `mimalloc` as the binary's allocator, 2026-10-14, chosen with the static musl
release ([release-provenance](release-provenance.md)), the same loads, in MB:

| Load | peak | median while loaded | idle |
|---|---|---|---|
| `npm ci`, 207 packages, cold proxy | 395 | 189 | 172 |
| `uv pip install`, 18 packages, cold proxy | 173 | 123 | 125 |
| 8 at once: vite's full document | 776 | 230 | 101 |
| 24 at once: the 8 largest documents, 3 times each | 597 | 298 | 196 |

`MALLOC_ARENA_MAX=2`, with glibc's allocator before the change, lowered idle RSS by about 40%: `npm ci` 586 to
349 MB, the 24 documents 1,093 to 689 MB. Peaks moved less: 586 to 448 and 1,181 to 809.

A request waits for a slot after its body is read, not before. The upstream connection is
then finished and waiting costs only time. With the wait placed before the read, the
response stalled until it timed out: 18 of 24 concurrent requests failed with "error
decoding response body".
