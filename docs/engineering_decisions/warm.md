# `byrle warm` asks a running proxy for what a lockfile locks

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
| after `byrle warm --lockfile package-lock.json` | exit 0 |

## Decision

`byrle warm --lockfile <PATH>... [--proxy <URL>] [--platform <PLATFORM>...]
[--all-platforms] [--deadline <SECONDS>]` reads each lockfile `policy diff` reads, and asks
the proxy for each locked artifact.

| Lockfile | Where warm asks | Platform |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | `resolved`'s path | `os`, `cpu`, `libc` |
| `yarn.lock` | `resolved`'s path | not recorded: every entry is asked for |
| `pnpm-lock.yaml`, `bun.lock` | `/<name>/-/<file>-<version>.tgz`, the registry's own path | `os`, `cpu`, `libc` |
| PyPI lockfiles | each file the proxy's index lists for the version | each wheel's platform tags; an sdist only when no wheel matches |

An npm artifact is asked for only when it installs on a target, by npm's rules: a listed
value is required, `!` excludes, and `libc` is read on Linux only. The target is the
machine warm runs on, or each `--platform`, such as `linux-x64` or `linux-x64-musl`, or
every platform with `--all-platforms`. A PyPI wheel is asked for when one of its platform
tags is the target's, such as `manylinux_2_17_x86_64` for `linux-x64` or `macosx_11_0_universal2`
for either Mac, or `any`, for every Python version. A version's sdist is asked for only
when none of its wheels is, which is when an installer builds from it. Added 2026-10-14,
asked for by the user: warm over the `make bench` PyPI set took 74.6 s against 11.0 s
for a cold install. The report counts what was skipped. A 503 with `x-byrle-not-ready: artifact-analysis` is asked
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
  writes `BYRLE_PROXY_URL` into its documents, which the machine running warm may not
  reach. Measured with `BYRLE_PROXY_URL=http://byrle.invalid`: 8 of 8 warmed.
- Sixteen artifacts are asked for at once. Every artifact is asked for once before any
  is asked again, so every analysis starts at once.
- Measured on the 207-package npm set of [latency-benchmarks](latency-benchmarks.md),
  one run each against a fresh proxy:

  | Warm | Artifacts | Skipped | Seconds |
  |---|---|---|---|
  | through the metadata, every platform, the first version | 207 | | 100.8 |
  | by lockfile path, this machine, `linux-x64-glibc` | 133 | 74 | 16.9 |
  | by lockfile path, `--all-platforms` | 207 | | 65.9 |

  `npm ci` run after the 16.9 s warm exited 0.
- For PyPI, every file of a locked version was asked for, each platform's wheel included,
  until 2026-10-14. A wheel is read by nothing, but its attestations are verified, and the
  served GET is its only full download.
- Warm's requests are decisions like any other: their pinned audit lines say `deferred`,
  then `served`. The audit line records no client. The proxy's log names it,
  `byrle/<version>`.

## Rejected

| Option | Why |
|---|---|
| analyse in the warm process, writing the store directly | works only with the Postgres store, and duplicates the proxy's fetch and verification |
| HEAD requests | `handle` decides only a GET, so a HEAD starts no analysis |
| the upstream monitor alone | it covers new versions as they are published, not the versions a team already depends on. It stays in TODO |
