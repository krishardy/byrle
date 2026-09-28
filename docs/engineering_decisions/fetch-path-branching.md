# Fetch path: branch before fetching

- **Status:** Staging
- **Plan reference:** decision #10

## Decision

Not a global stream-versus-buffer mode. Three branches, chosen before a byte is
fetched, using the artifact digest the packument already published (`dist.integrity` on
npm):

| Case | Behaviour |
|---|---|
| Analysed before (cache hit) | Decide on the analysis, then stream through. Flat memory, no added latency. |
| Novel | Answer `503` with `Retry-After: 1` and `x-waharoa-not-ready: artifact-analysis` at once, and analyse in the background. The client's retry is a cache hit. Refused at once instead when the metadata already refuses it. |
| No strong digest, or no metadata listing the version | Not served: refused, or 502 when the registry gave no metadata. Nothing can be assessed. |
| Read by no detector (a PyPI wheel) | Stream through, decided on the metadata. |

Amended 2026-09-26: a novel artifact was buffered and analysed inside the request when the
analysis was cheap, and deferred with `429` only when it was expensive. No request now
waits for an analysis, whatever it costs. See [artifact-spool](artifact-spool.md) and
[deferral-status-codes](deferral-status-codes.md). Amended 2026-09-27: a novel artifact is
deferred under any policy, and one with no strong digest or no metadata is not served.

## Rationale

Content-based verdicts are almost never needed at fetch time, because policy evaluates
on metadata, which is already resolved by then. The packument publishes the digest, so
whether this exact artifact has been analysed is knowable before fetching.

There is no mid-stream branch. The digest decides up front, before a byte is fetched.

## Consequences

- The registry-supplied hash is a cache key, not a trust anchor. We verify the digest of
  what actually arrives; a mismatch is a finding.
- Under `install_scripts: block`, the first fetch of a version that claims no script is
  deferred once, and under `provenance: block` so is the first fetch of a version whose
  attestations, or whose predecessor's, nothing has verified. bun, whose total patience is 0.2s, and yarn 1, which gives up on a 503
  tarball after one retry, fail that first install; the next install is served from the
  stored analysis ([deferral-status-codes](deferral-status-codes.md)).
- Status codes: 502 upstream unreachable or malformed, or serving bytes its metadata does
  not describe; 503 we are not ready, including this artifact is under analysis. No 4xx
  that reads as a block for any not-ready state.

Client-compatibility measurements are in [deferral-status-codes](deferral-status-codes.md).
