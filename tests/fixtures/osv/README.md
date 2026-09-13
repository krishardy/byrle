# OSV record fixtures

Real records from OSV's npm bundle,
`https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`, fetched 2026-09-13
(`last-modified: Sat, 12 Sep 2026 04:07:01 GMT`). Each file is one record, byte for byte
as it sits in the bundle. They are the input for `src/intel/osv.rs`.

Every record here is an OSSF Malicious Packages record, Apache-2.0. GHSA records are
CC-BY-4.0 and are not kept here; see `docs/engineering_decisions/advisory-stream-licences.md`.

Each record is here for the shape of its npm `affected` entry:

| Fixture | Shape | Stored as |
|---|---|---|
| `MAL-2021-1` | a range of `introduced: "0"` and no end, no `versions` | one row, every version |
| `MAL-2022-174` | a `versions` list of 4, no ranges | one row per listed version |
| `MAL-2022-1122` | `introduced: "0"` and a `versions` list of 1 | one row, every version |
| `MAL-2025-3605` | two ranges, `introduced: "99.2.2"` and `introduced: "0"`, and a `versions` list of 4 | one row, every version |
| `MAL-2025-3661` | `introduced: "99.9.1"` with no end, and a `versions` list of 2 | one row per listed version, and one range row |
| `MAL-2022-219` | `introduced: "1.2.2"` with no end, no `versions` | one range row |
| `MAL-2024-1398` | withdrawn | nothing |

`bundle.zip` holds the seven records above, deflate-compressed as OSV's bundle is, for
`src/intel/refresh.rs`. Rebuild it from them if one changes.

To refresh one, take the same file from a newer bundle. Do not hand-edit them: a record
OSV would never publish tests nothing.
