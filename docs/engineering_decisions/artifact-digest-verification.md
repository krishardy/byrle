# Verifying the artifact digest on the way past

- **Status:** Implemented, Stage 1
- **Code:** `src/integrity.rs`, `src/store.rs`, `proxy::VerifyingStream`

## Decision

A packument that goes past the proxy has its records stored, bounded by total record
count and evicted least recently used. The tarball request that follows looks up its own
record, so `dist.integrity` is known before a byte of the artifact is fetched.

The artifact is then streamed to the client while being hashed, with **one chunk held
back**. Each chunk is released when the next arrives; the last is released only after the
digest matches. On a mismatch the body ends in an error and the held chunk is dropped.

SHA-1 is not verifiable through this path.

## Rationale

**Why hold a chunk back.** Two separate problems, one fix.

The response status and headers leave before the first byte is hashed, so a mismatch can
only be reported by failing the body. Forwarding every chunk as it arrives means the
client already holds a complete, correct-length artifact by the time the check fails.

Worse, the check does not run at all. hyper stops polling a body once the declared
`Content-Length` has been written, so the end of the stream is never reached. Measured on
a real fetch of `lodash-4.17.21.tgz`: all 318,961 bytes forwarded, zero verifications
performed. Holding one chunk leaves the response short of its declared length, which
keeps hyper polling, and keeps the artifact incomplete until the digest passes.

**An empty chunk is not the next chunk.** reqwest ends a body with a zero-length chunk.
It displaced the held chunk and released the whole artifact before the comparison. Only a
byte-level trace found this; the response looked correct throughout.

**What npm does with a failed body.** Measured, not assumed. A tampered tarball served
through the proxy to a real `npm install` produced ECONNRESET, two retries with roughly
10 s then 60 s of backoff, and a failed install with nothing written to `node_modules`.
It fails closed, and takes about 70 seconds to do it.

**Why not SHA-1.** Two versions in 24,852 publish only `dist.shasum`. SHA-1 is
collision-broken, and a passing SHA-1 check logged beside a passing SHA-512 check invites
reading them as the same evidence. Those artifacts are forwarded unverified and said to
be unverified.

**Why the store is bounded by records, not entries.** A packument carries every version
ever published, not the one being installed. Measured over an
`express + @babel/code-frame + typescript + eslint` install: 167 packuments, 9,690
records, largest 3,822 (typescript). Counting entries would treat those as equal.

## Consequences

- The registry digest remains a cache key, not a trust anchor (see
  [fetch-path-branching.md](fetch-path-branching.md)). A match proves the bytes are the
  ones the packument described. A mismatch is a finding: the registry served bytes its
  own metadata does not describe.
- Verification depends on having seen the packument. A warm npm cache, a restarted proxy,
  or an evicted entry leaves the artifact unverified, and it is logged as such.
- A tarball filename that spells the version differently from the packument misses the
  lookup: 38 of 24,852 URLs, all pre-2013 prereleases. Reachable from a real
  `npm install express@3.0.0-rc1`.
- Extra memory while streaming is one chunk, not the artifact.
