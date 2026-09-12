# Deferral status codes: what a client does when the proxy says "not yet"

- **Status:** Measured Sept 2026, decision pending Stage 2
- **Plan reference:** §5 status codes, §5 client compatibility
- **Related:** [fetch-path-branching](fetch-path-branching.md),
  [enforcement-tiers](enforcement-tiers.md)

§5 defers rather than refuses when the proxy is not ready to answer: the intel mirror is
warming, or the artifact in hand is still being analysed. It assigns **503** to the first
and **429** to the second, and records a known risk: "npm may apply its own backoff and
fail the install rather than waiting politely. Needs testing against real clients in
Stage 1."

This is that test. `make retry-matrix` produces it, and
`scripts/make/retry-matrix.sh` is the harness.

## What was measured

The proxy can be told to answer a matching request with a deferral instead of fetching
(`WAHAROA_DEFER_TEST`, debug builds only; see `src/defer.rs`). Two runs per cell, because
they answer different questions:

- **Unbounded.** The deferral never lifts. Attempts and the gaps between them are the
  client's retry budget, which is what `Retry-After` has to land inside.
- **Bounded.** The deferral lifts after a few seconds, like a proxy finishing its
  warm-up. Whether the install then completes is what an operator will care about.

`Retry-After: 1` throughout, so a client that honours it shows gaps near 1 and a client
running its own backoff shows its own numbers.

Attempts are counted per path, not per request: npm asks for `/npm` as well as the
package on every round, so a raw count reports twice the retries it made.

Every client is pointed at a disposable cache. Two of them needed more than the obvious
flag:

- pnpm keeps packument metadata in a cache of its own, keyed by registry host and port,
  which `--store-dir` does not cover. Measured while building this: a second run at the
  same port resolved from `~/.cache/pnpm/metadata-v1.3/127.0.0.1+8733` and reported a
  retry budget it had never needed to spend. `npm_config_cache_dir` covers it.
- yarn 4 needs `globalFolder` and `enableMirror: false`, not just
  `enableGlobalCache: false`.

## The measurement

`Retry-After: 1` on every response. Attempts is how many times the client reissued one
request; gaps are the seconds between those attempts.

Deferral that never lifts:

| Client | 429 packument | 503 packument | 429 tarball | 503 tarball |
|---|---|---|---|---|
| npm 11.11.0 | 3 @ 10s, 60s | 3 @ 10s, 60s | 3 @ 10s, 60s | 3 @ 10s, 60s |
| pnpm 10.33.0 | 3 @ 10s, 60s | 3 @ 10s, 60s | 3 @ 10s, 60s | 3 @ 10s, 60s |
| yarn 1.22.22 | **1** | 5 @ 3s | **1** | **1** |
| yarn 4.9.1 | 4 @ 1s | 4 @ 1s | 4 @ 1s | 4 @ 1s |
| bun 1.3.14 | **1** | 6 @ 0s | **1** | 6 @ 0s |

Deferral lifting after 8 seconds, the shape of a proxy finishing its warm-up:

| Client | Attempts | Installed | Elapsed |
|---|---|---|---|
| npm 11.11.0 | 1 | yes | 10.5s |
| pnpm 10.33.0 | 1 | yes | 10.5s |
| yarn 1.22.22 | 3 @ 3s | yes | 9.6s |
| yarn 4.9.1 | 4 @ 1s | **no** | 3.2s |
| bun 1.3.14 | 6 @ 0s | **no** | 0.0s |

## What this changes

**429 is terminal for yarn 1 and bun; 503 is not.** Both stop after a single 429 and
report the code (`error: GET http://... - 429`, and yarn's `returned a 429`). Both retry a
503. npm, pnpm and yarn 4 make no distinction between the two codes at all. So on the only
axis where the codes differ in practice, 503 is retried by five clients out of five and
429 by three. This is the evidence for §5's "unknown user-agent falls back to 503", and it
argues against 429 for the per-artifact case unless the client is known to tolerate it.

**Only yarn 4 honours `Retry-After`**, at 1.0s gaps against the header's 1. npm and pnpm
back off 10s then 60s regardless. yarn 1 uses 3s. bun retries with no delay at all: six
attempts inside 0.2 seconds.

**The plan's mitigation was aimed at the wrong quantity.** §5 proposes "`Retry-After`
short enough to land inside npm's own retry window". npm ignores the header, so its value
does not matter to npm; what decides the outcome is the client's total patience, and there
the ordering is inverted. The client that honours `Retry-After` most faithfully has the
least patience overall:

| Client | Total patience before failing |
|---|---|
| npm, pnpm | 70s |
| yarn 1 | 12s on a packument, 0s on a tarball |
| yarn 4 | 3.2s |
| bun | 0.2s |

A deferral of more than about three seconds fails yarn 4. A 429 fails bun and yarn 1
immediately. The bounded run shows what that means end to end: an eight-second warm-up is
survived by npm, pnpm and yarn 1, and fails yarn 4 and bun.

**yarn 1 treats the two request kinds differently.** It retries a 503 packument five times
and gives up on a 503 tarball after one. No other client varies by target.

## What follows for Stage 2

- The per-client table §5 asks for is warranted: the clients differ by more than a
  constant, and one of them differs by request kind.
- It has to be keyed on what the proxy actually sees. yarn 4 identifies itself as
  `got (https://github.com/sindresorhus/got)`, so a rule written for `yarn` does not match
  it. This is the same trap already recorded for refusal statuses.
- §5's "bounded internal wait as a fallback for clients that give up" is not a fallback
  but the main mechanism for two of the five clients, since no code and no `Retry-After`
  buys any time from bun.
- The upstream issues §5 wants filed have their evidence here: four of five clients ignore
  `Retry-After`, and two treat 429 as terminal.

## Not decided here

Which code goes to which client. That is Stage 2, alongside the deferral it would answer;
nothing in Stage 1 produces one. This records what the clients do so the choice is made
against measurement rather than against protocol reading.
