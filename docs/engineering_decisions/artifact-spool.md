# An artifact being analysed is spooled to disk, not held in memory

- **Status:** Decided 2026-09-22, not implemented.
- **Related:** [artifact-analysis-store](artifact-analysis-store.md),
  [fetch-path-branching](fetch-path-branching.md),
  [artifact-digest-verification](artifact-digest-verification.md),
  [deferral-status-codes](deferral-status-codes.md)

## Why the bytes have to be held at all

`proxy::VerifyingStream` forwards an artifact while hashing it, holding one chunk back. The
status and headers leave before the last byte arrives, so nothing decided from the bytes can
refuse the response once forwarding has begun (`src/proxy.rs:522`). A check that reads the
artifact therefore has to finish before the response starts, and that means the whole
artifact is in hand first.

The reader needs a prefix rather than the whole archive, because `analysis::member` returns
at the first `package.json`. That prefix is not small enough to bound: of 78 npm packages,
5 are not readable from 4 MiB, `next`, `selenium-webdriver`, `three`, `echarts` and
`aws-sdk`, because `package/package.json` is not always the first member.

## Why not memory

Measured in [artifact-analysis-store](artifact-analysis-store.md): the artifacts that are
read top out at 81,802,749 bytes, `opencv-python@5.0.0.93`, in a sample of 1,178 npm
artifacts and 199 PyPI sdists. Nothing bounds the tail. PyPI's per-file limit is 100 MB and
is raised on request, which `tensorflow` at 572,881,074 bytes is.

A memory ceiling is therefore a number with no evidence behind it, and the packages it
refuses are `torch` and `opencv-python`. A file has no such ceiling.

The median argues the same way from the other end: 9,078 bytes on npm and 238,888 on a PyPI
sdist. A spool file that size is written and read out of the page cache, so one path for
every artifact costs less than two paths and a threshold between them.

## What is spooled

Only an artifact a detector reads, and only on an analysis miss.

| Artifact | Spooled |
|---|---|
| npm tarball, no analysis stored for its digest | yes |
| PyPI sdist, no analysis stored for its digest | yes |
| PyPI wheel | no: a wheel runs nothing, so nothing reads it |
| any artifact whose digest already has an analysis | no: the verdict is read from the store |

A wheel never being spooled takes every artifact above 81,802,749 bytes out of the
population, because all 42 PyPI artifacts over 64 MiB are wheels.

## The bytes are not kept

The file holds one artifact for the duration of one request and is deleted when the request
ends. What outlives the request is the analysis, keyed by digest, in
[artifact-analysis-store](artifact-analysis-store.md).

This is the line that keeps the proxy from becoming an artifact store, which README.md
lists as a non-goal. A second request for the same bytes fetches them from upstream again
and skips the analysis, not the fetch.

## The file

| | |
|---|---|
| Directory | `WAHAROA_SPOOL_DIR`, defaulting to the OS temporary directory |
| Created | `O_CREAT` with `O_EXCL`, mode `0600` |
| Deleted | by a guard when the request ends, on every path: served, refused, or failed |
| Contents | never logged, and the path is logged at DEBUG only |

The proxy locks `.lock` in the directory at startup, as `SnapshotDir::open` does, and
refuses to start when another proxy holds it. Two proxies sharing a spool directory would
each sweep the other's files. Holding the lock is what makes the startup sweep safe: every
file in the directory at startup is an orphan from a process that crashed, so it is removed
and the count is logged.

Leaving them would accumulate artifact bytes on disk for as long as the machine lives, and
an operator who never looks in the directory would never find out.

## The ceiling, and what it is for

`Content-Length` is a claim. The write is bounded by `WAHAROA_MAX_ARTIFACT_BYTES`,
defaulting to 1 GiB, and an artifact past it is refused with the ceiling and the variable
named.

The number is a guard against an artifact that claims to be 100 GB, not a size policy. It
sits an order of magnitude above the largest artifact measured, so it should never fire for
a package anyone publishes, and a request that trips it is logged at WARN for that reason.
`analysis::MAX_MEMBER_BYTES`, 4 MiB, is the separate bound on one member inside the archive,
which is what a decompression bomb needs.

Disk is sized by the ceiling times the concurrency bound. `WAHAROA_MAX_CONCURRENT_ANALYSES`
defaults to 8, as `WAHAROA_MAX_CONCURRENT_METADATA` does, so a proxy at its bounds holds
8 GiB.

## A full disk is a 503

A spool the proxy cannot write is a proxy that cannot decide, which is the not-ready case,
not a refusal. [deferral-status-codes](deferral-status-codes.md) measured that five clients
of five retry a 503 and two stop on a 429, and its rule is that no not-ready state gets a
4xx that reads as a block. A failed spool answers 503 with `Retry-After: 1` and
`x-waharoa-not-ready` naming the case, as a cold intel store already does.

## Rejected

| Option | Why not |
|---|---|
| Stream the artifact and analyse afterwards | The status and headers have gone; a block is not expressible. `install_scripts: block` would be a silent pass, which is the failure the whole check exists to avoid |
| Buffer the whole artifact in memory, with a ceiling | The measurement: the ceiling refuses `torch` and `opencv-python`, and nothing bounds the tail |
| Buffer the prefix in memory up to the manifest | 5 of 78 npm packages need more than 4 MiB of prefix, so the bound is the artifact again |
| Memory below a threshold, spool above it | Two paths and a threshold to defend. The median artifact is 9,078 bytes and a file that size never reaches the disk |
| Keep the spooled artifact as a cache | README.md's non-goal, and the analysis is already the thing worth keeping |
