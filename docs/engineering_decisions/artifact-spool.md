# An artifact is analysed in the background, spooled to disk

- **Status:** Decided 2026-09-22, amended 2026-09-26: the analysis runs in the background
  and a request waits for it with a 503 only when the answer depends on it. Implemented: `src/spool.rs`,
  `src/analysis/run.rs`, and `proxy::analysed`.
- **Related:** [artifact-analysis-store](artifact-analysis-store.md),
  [fetch-path-branching](fetch-path-branching.md),
  [artifact-digest-verification](artifact-digest-verification.md),
  [deferral-status-codes](deferral-status-codes.md)

## No request waits for an analysis

The first fetch of an artifact that no analysis is stored for starts a job that fetches
the artifact from upstream, writes it to the spool, checks its digest, reads it, and stores
the analysis under the digest.

The request is answered 503 at once, with `Retry-After: 1` and `x-byrle-not-ready:
artifact-analysis`, under any policy and with none. Nothing is served until its analysis
has finished. Decided 2026-09-27, replacing a 503 only when the answer depended on the
analysis: an artifact the proxy has not assessed is never served. The retry is decided on
the analysis.

The same job verifies the attestations the provenance check needs, this version's and the
previous version's, each against the digest the packument published for it. See
[provenance-check](provenance-check.md).

| Policy, for this package | First fetch of an unanalysed artifact |
|---|---|
| any, when what is known already refuses it (a claimed script under `block`, a denial, the cooldown) | refused on what is known |
| any other, or none | 503; the retry is decided on the analysis and the verification |

The retry is fetched from upstream again through `proxy::VerifyingStream`.

The second fetch is checked against the same digest. That is what makes the stored
analysis apply to the bytes the client receives: a registry that serves different bytes
the second time fails the digest and the body never completes.

Before deferring, the policy is asked on the metadata's claim. A version that a denial, the
cooldown, an advisory, an unserved origin or a claimed install script refuses is refused at
once rather than deferred and then refused.

The decision as first written analysed inside the request: the response waited while the
artifact was spooled and read, because `VerifyingStream` sends the status before the last
byte arrives and nothing decided from the bytes can refuse after that. A deferred request
needs neither, and holds no connection open while the analysis runs.

### What the retry is decided on

| The artifact | `install_scripts` decides on |
|---|---|
| Analysed, and the archive was read | the metadata's claim, or what the archive declares when it declares a script the claim does not. The archive never removes a claim: an sdist with no `setup.py` still runs its PEP 517 backend, and npm runs `node-gyp rebuild` for a `binding.gyp` that `package.json` never names |
| Analysed, and the archive could not be read, or was over the ceiling | runs scripts: not knowing is not knowing there is none |
| Read by a detector, with no strong digest | runs scripts: there is no key to store an analysis under, and nothing ties the job's bytes to the served ones |
| Its last fetch did not match its digest | not decided: 502, naming the mismatch |
| A PyPI wheel | the metadata's claim, which for a wheel is none |

Each job ends with one INFO line, `analysis job timed`, giving milliseconds for each
phase under `byrle.analysis.`: `queued_ms` waiting for one of
`BYRLE_MAX_CONCURRENT_ANALYSES` slots, `fetch_ms` to the upstream's headers,
`download_ms` spooling and hashing the body, with `bytes`, `read_ms`, `store_ms`, and
`attest_ms` for its `attestations`, then `total_ms` and whether it `completed` before the
deadline. Each attestation's own line adds `byrle.attestation.fetch_ms` and
`byrle.attestation.verify_ms`.

A job that fails to fetch, cannot write the spool, or runs past its ten-minute deadline
stores nothing, and the next request starts another. That includes an upstream that
answers the artifact 404: nothing remembers the status, so every request for it is
answered 503. Decided 2026-09-28. The upstream client ends a
connection after 10s without connecting or 30s without a byte, `http::CONNECT_TIMEOUT` and
`http::READ_TIMEOUT`, since 2026-09-28. It sets no total timeout, so an upstream that
trickles would otherwise hold a job slot, and its digest would be answered 503 for as long
as it trickles. The deadline bounds that. A job whose bytes do not match the digest stores nothing and is remembered
in this process only, bounded by `BYRLE_MAX_VERIFIED`, because a mismatch is about one
upstream at one time rather than about the bytes.

### Why the reader needs the whole artifact

The reader needs a prefix rather than the whole archive, because `analysis::member` returns
at the first `package.json`. That prefix is not small enough to bound: of 78 npm packages,
5 are not readable from 4 MiB, `next`, `selenium-webdriver`, `three`, `echarts` and
`aws-sdk`, because `package/package.json` is not always the first member.

### Jobs

| Rule | Why |
|---|---|
| one job per digest at a time | a client retrying, and an install asking for one artifact from several places, start one job between them |
| at most `BYRLE_MAX_CONCURRENT_ANALYSES` jobs run; the rest wait for a slot | bounds how much of the spool is in use. A request never waits |
| a job ends after 10 minutes (`analysis::run::DEADLINE`), and its spool file is deleted | the upstream client ends a stall after `http::READ_TIMEOUT` with no bytes and sets no total timeout, so an upstream that trickles would hold a slot, and its digest would answer 503, for as long as it trickled. 10 minutes is a 1 GiB artifact at under 2 MB/s |
| a digest whose fetch did not match is remembered in this process only, bounded by count | a mismatch is about one upstream at one time, not about the bytes |
| an analysis store that cannot answer reads as not analysed | the artifact is analysed again |
| an archive nothing could read is stored as `Unreadable` | the retry is decided rather than deferred again, and `install_scripts: block` refuses it |

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

The file holds one artifact for the duration of one job and is deleted when the job ends. What outlives the request is the analysis, keyed by digest, in
[artifact-analysis-store](artifact-analysis-store.md).

This is the line that keeps the proxy from becoming an artifact store, which README.md
lists as a non-goal. A second request for the same bytes fetches them from upstream again
and skips the analysis, not the fetch.

## The file

| | |
|---|---|
| Directory | `BYRLE_SPOOL_DIR`, defaulting to `byrle-spool` in the OS temporary directory, created with mode `0700` |
| Name | `artifact-<pid>-<n>` |
| Created | `O_CREAT` with `O_EXCL`, mode `0600` |
| Deleted | by a guard when the request ends, on every path: served, refused, or failed |
| Contents | never logged, and the path is logged at DEBUG only |

The proxy locks `.lock` in the directory at startup and refuses to start when another
proxy holds it. `SnapshotDir::open` takes the same lock and waits for it instead. Two
proxies sharing a spool directory would each sweep the other's files. Holding the lock is
what makes the startup sweep safe: every spool file in the directory at startup is an
orphan from a process that crashed, so it is removed and the count is logged.

Leaving them would accumulate artifact bytes on disk for as long as the machine lives, and
an operator who never looks in the directory would never find out.

The sweep removes regular files whose names start with `artifact-`, and nothing else: not
`.lock`, not a directory, and not a symlink. The decision as first written defaulted to the
OS temporary directory itself and removed every file in it, which on a default start would
have emptied `/tmp`. A directory entry that cannot be read is left in place, and the spool
still opens.

## The ceiling, and what it is for

`Content-Length` is a claim. The write is bounded by `BYRLE_MAX_ARTIFACT_BYTES`,
defaulting to 1 GiB. An artifact past it is stored as unreadable, with the ceiling and the
variable named, so the retry is decided rather than deferred again.

The number is a guard against an artifact that claims to be 100 GB, not a size policy. It
sits an order of magnitude above the largest artifact measured, so it should never fire for
a package anyone publishes, and a job that trips it is logged at WARN for that reason.
`analysis::MAX_MEMBER_BYTES`, 4 MiB, is the separate bound on one member inside the archive,
which is what a decompression bomb needs.

Disk is sized by the ceiling times the concurrency bound. `BYRLE_MAX_CONCURRENT_ANALYSES`
defaults to 8, as `BYRLE_MAX_CONCURRENT_METADATA` does, so a proxy at its bounds holds
8 GiB.

## A full disk stores nothing

A job that cannot write the spool stores nothing and logs why. The client has already been
answered 503, and its retry starts another job. There is no 4xx for it:
[deferral-status-codes](deferral-status-codes.md)'s rule is that no not-ready state gets a
4xx that reads as a block.

## Rejected

| Option | Why not |
|---|---|
| Stream the artifact and analyse afterwards | The status and headers have gone; a block is not expressible. `install_scripts: block` would be a silent pass, which is the failure the whole check exists to avoid |
| Spool and analyse inside the request | The decision as first written. Replaced 2026-09-26: no request waits for an analysis |
| Wait a bounded time for the analysis before deferring | bun's total patience is 0.2s. Decided against 2026-09-26 |
| Defer only when the answer depends on the analysis | Built 2026-09-26 and replaced 2026-09-27. It served an artifact the proxy had not assessed whenever the policy would pass it at the worst the analysis could find. It saved a retry per novel artifact, and bun and yarn 1 their first fetch |
| Buffer the whole artifact in memory, with a ceiling | The measurement: the ceiling refuses `torch` and `opencv-python`, and nothing bounds the tail |
| Buffer the prefix in memory up to the manifest | 5 of 78 npm packages need more than 4 MiB of prefix, so the bound is the artifact again |
| Memory below a threshold, spool above it | Two paths and a threshold to defend. The median artifact is 9,078 bytes and a file that size never reaches the disk |
| Keep the spooled artifact as a cache | README.md's non-goal, and the analysis is already the thing worth keeping |
