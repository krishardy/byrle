# Default ceilings

- **Status:** Implemented. The `DEFAULT_` constants in `src/env.rs`.
- **Related:** [environment-variables](environment-variables.md),
  [packument-body-inspection](packument-body-inspection.md),
  [no-metadata-cache](no-metadata-cache.md), [artifact-spool](artifact-spool.md),
  [snapshot-identity](snapshot-identity.md)

## Decision

| Default | Value | Why |
|---|---|---|
| `WAHAROA_MAX_METADATA_BYTES` | 64 MiB | the largest packument measured is vite's full document, 38,950,704 bytes on 2026-09-26, so this is 1.7x headroom. It was 32 MiB, twice typescript's 15.7 MB, until vite outgrew it and a cooldown and the provenance check could not read its publish times. It bounds both the bytes buffered and the bytes decompression produces |
| `WAHAROA_MAX_RECORDS` | 50,000 | about five installs of the size measured in `store`; 45 to 70 MB at 0.9 to 1.4 KB per record |
| `WAHAROA_MAX_VERIFIED` | 50,000 | an entry is an algorithm and a digest, about 64 bytes. An artifact reaches `verified` only after a packument named it, so more than the record budget would be unused |
| `WAHAROA_MAX_CONCURRENT_METADATA` | 8 | see below |
| `WAHAROA_MAX_CONCURRENT_ANALYSES` | 8 | as for metadata. At the default artifact ceiling the spool holds at most 8 GiB |
| `WAHAROA_MAX_TRAFFIC_CLIENTS` | 256 | a new client name past it is counted as `other`, so a user-agent made up per request cannot grow the map. A team's proxy sees a handful: npm, pnpm, yarn, bun, pip and uv |
| `WAHAROA_MAX_ARTIFACT_BYTES` | 1 GiB | an order of magnitude above the largest artifact a detector reads, `opencv-python` 5.0.0.93 at 81,802,749 bytes, so it refuses an artifact whose length is a lie rather than one anybody publishes |
| `WAHAROA_EXPIRY_CEILING_DAYS` | 90 | long enough for a review cycle, and an entry nobody looks at again lapses within a quarter |
| `WAHAROA_SNAPSHOT_LIMIT` | 30 | a month of daily refreshes. npm's rows were 5,577,231 bytes gzipped on 2026-09-13, and a source whose rows did not change is not written again |

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
