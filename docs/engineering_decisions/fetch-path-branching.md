# Fetch path: branch before fetching

- **Status:** Staging
- **Plan reference:** decision #10

## Decision

Not a global stream-versus-buffer mode. Three branches, chosen before a byte is
fetched, using the artifact digest the packument already published (`dist.integrity` on
npm):

| Case | Behaviour |
|---|---|
| Analysed before (cache hit) | Stream through. Flat memory, no added latency. |
| Novel, cheap analysis | Buffer, analyse, forward. |
| Novel, expensive analysis | Defer with `429` plus `Retry-After`. |

## Rationale

Content-based verdicts are almost never needed at fetch time, because policy evaluates
on metadata, which is already resolved by then. The packument publishes the digest, so
whether this exact artifact has been analysed is knowable before fetching.

There is no mid-stream branch into buffering. The digest decides up front, so buffering
is its own path.

## Consequences

- The registry-supplied hash is a cache key, not a trust anchor. We verify the digest of
  what actually arrives; a mismatch is a finding.
- Analysis cost is part of the detector contract, declared per detector rather than
  guessed at runtime. Only expensive-tier detectors can produce a deferral, so the
  common path never retries.
- Status codes: 502 upstream unreachable or malformed, 503 we are not ready, 429 this
  artifact is under analysis. No 4xx that reads as a block for any not-ready state.
- **Known risk:** npm may apply its own backoff and fail the install rather than waiting.
  Untested as of Sept 2026. Mitigations are a `Retry-After` short enough to land inside
  npm's retry window, plus a bounded internal wait.

Status-code and client-compatibility detail remains in plan §5 ("Fetch path").
