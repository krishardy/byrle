# An artifact or manifest answered with any 2xx is verified as a 200 is

- **Number:** 0127
- **Status:** Implemented 2026-11-03 in `f0c4e2d`, for finding 10 of the security review
  (TODO.md ad-hoc #50): `Exchange::respond` and `Exchange::forward_artifact` in
  `src/proxy.rs`. The approach below was chosen while implementing it, and accepted by the
  user 2026-11-03.
- **Related:** [enforcement-tiers](0019-enforcement-tiers.md)

## Decision

| Upstream answer | Was | Is |
|---|---|---|
| 200, artifact with a digest | `VerifyingStream`: the body is cut off on a mismatch | the same |
| 203, 206 or another 2xx, artifact with a digest | forwarded unverified | the same as a 200 |
| 200, manifest with a claim | `forward_manifest`: read whole, 502 on a mismatch | the same |
| 203, 206 or another 2xx, manifest with a claim | forwarded unverified | the same as a 200 |
| 304 or a non-2xx | forwarded | forwarded |

`digest_mismatch` weighed under `risk_threshold` forwards a mismatch on any 2xx, as on a
200.

## Why

`Range` is not in `FORWARDED`, so only an upstream, a mirror or a redirect target answers
an artifact with a 2xx other than 200. mvn and Gradle check no digest by default, so the
proxy's check is the only one.

Sending each 2xx through the existing check keeps one rule and one tolerance for a
mismatch.

## Rejected

| Option | Why not |
|---|---|
| 502 for any 2xx other than 200 (the review's proposal) | a second refusal path beside `VerifyingStream`, with its own tolerance to keep in step |
| verify a 206 against the part of the digest it covers | a digest covers the whole file |

## Cost

A 206 to a request with no `Range` has part of the file, so it fails verification and
is cut off.
