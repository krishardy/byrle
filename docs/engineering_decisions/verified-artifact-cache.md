# The artifact cache does not skip verification

- **Status:** Implemented, Stage 1
- **Plan reference:** §5 fetch path table
- **Related:** [artifact-digest-verification](artifact-digest-verification.md),
  [fetch-path-branching](fetch-path-branching.md)

§5 branches the fetch path three ways, and the first row is "analyzed before (cache hit) →
stream through". The key is the artifact's content digest, which the packument publishes,
so the branch is decided before a byte is fetched. `src/verified.rs` is that cache.

## What a hit means, and what it does not

A hit means this digest was fetched and verified on an **earlier request**. It says nothing
about the bytes arriving on this one: those come from upstream now and could differ.

So a hit does not skip the hash. Skipping it would mean a registry that served correct
bytes once could serve anything afterwards and have it forwarded unchecked, which is the
failure `VerifyingStream` exists to catch. Every artifact is hashed every time.

This is not a compromise against §5. Its table says a hit **streams through**, and
streaming through a hashing wrapper is what the fetch path already does: there is no
buffering and no added latency, which is what that row is contrasting with the deferral
two rows below it. The saving a cache hit buys is the analysis, not the hash.

## What exists in Stage 1

Nothing analyses and nothing defers, so both arms of the branch behave identically. What
is real is the key, the branch, the counts and the log line:

```
artifact cache consulted  digest=sha512-v2kDEe57...  cache="miss"
artifact cache consulted  digest=sha512-v2kDEe57...  cache="hit"
```

Measured against registry.npmjs.org: two requests for lodash 4.17.21, miss then hit on the
same sha512, one entry held, `artifacts_verified: 1` at `/-/waharoa/health`.

Building it here rather than with the analysis is deliberate. The branch has to be decided
before the fetch, which is a constraint on the whole request path, and getting that wrong
is much cheaper to find now than alongside a queue and a verdict.

## A mismatch records nothing

A digest is recorded only after bytes have been hashed against it and matched. When they
do not, the registry served bytes its own packument does not describe: recording that
would be recording the attack, and the next request for the same digest would read as
already seen.

## Bounds

One entry per artifact version fetched, evicted by count, least recently used first, like
the record store. `WAHAROA_MAX_VERIFIED`, default 50,000. An entry is an algorithm and a
digest, on the order of 64 bytes, so the budget is a few megabytes.

Per-process, and it dies with the proxy. Stage 5 is where it acquires the analysis it
holds and whatever persistence that needs.
