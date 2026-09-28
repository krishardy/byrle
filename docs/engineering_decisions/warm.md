# `waharoa warm` asks a running proxy for what a lockfile locks

- **Status:** Implemented 2026-09-28. `src/warm.rs`, `lockfile::references`,
  `Clients::record`.
- **Related:** [artifact-spool](artifact-spool.md),
  [deferral-status-codes](deferral-status-codes.md),
  [policy-diff-lockfiles](policy-diff-lockfiles.md)

## Why

Every artifact the proxy has not analysed is answered 503 until its analysis has
finished. npm, pnpm, yarn 4, pip and uv retry. bun and yarn 1 do not, so their first
install of any new artifact fails. Measured 2026-09-28 with a lockfile of 8 npm packages
and a fresh proxy:

| | bun 1.4.2, first `bun install` |
|---|---|
| without warm | exit 1 |
| after `waharoa warm --lockfile package-lock.json` | exit 0 |

## Decision

`waharoa warm --lockfile <PATH>... [--proxy <URL>] [--deadline <SECONDS>]` reads each
lockfile `policy diff` reads, and asks the proxy for each locked version's metadata, then
for each artifact it lists. A 503 with `x-waharoa-not-ready: artifact-analysis` is asked
again each second, until the answer changes or `--deadline`, 900 s by default, passes
from the first 503.

It goes through a running proxy over HTTP, so it fills whichever analysis store the proxy
uses: the in-process one or Postgres.

| Answer | Reported as | Exit bit |
|---|---|---|
| 2xx or 304 | warmed | |
| 4xx | refused | |
| the proxy's document does not list the version | not listed | |
| 503 for anything but the analysis | not ready, with the reason | 1 |
| 503 for the analysis at the deadline | still being analysed | 2 |
| no answer, or another status | failed | 1 |
| a lockfile that does not read, or no proxy address | | 4, on its own |

The bits are `audit verify`'s and `policy diff`'s.

A refusal is the policy answering, which needs no analysis, so it is not a failure. A
version the proxy's document does not list was removed by the policy or is on an origin
the proxy does not serve.

## Details

- The body is never read. Warm drops each response at its status line. The proxy logged
  no error for it.
- An artifact URL is asked of `--proxy` with the path and query the proxy wrote. The proxy
  writes `WAHAROA_PUBLIC_URL` into its documents, which the machine running warm may not
  reach. Measured with `WAHAROA_PUBLIC_URL=http://waharoa.invalid`: 8 of 8 warmed.
- Sixteen metadata documents, then sixteen artifacts, are asked for at once. Every
  artifact is asked for once before any is asked again, so every analysis starts at
  once. On 207 npm packages it took 100.8 s:
  [latency-benchmarks](latency-benchmarks.md) says why.
- For PyPI, every file of a locked version is asked for, each platform's wheel included.
  A wheel is read by nothing, but its attestations are verified, and the served GET is
  its only full download.
- Warm's requests are decisions like any other: their pinned audit lines say `deferred`,
  then `served`. The audit line records no client. The proxy's log names it,
  `waharoa/<version>`.

## Rejected

| Option | Why |
|---|---|
| analyse in the warm process, writing the store directly | works only with the Postgres store, and duplicates the proxy's fetch and verification |
| HEAD requests | `handle` decides only a GET, so a HEAD starts no analysis |
| the upstream monitor alone | it covers new versions as they are published, not the versions a team already depends on. It stays in TODO |
