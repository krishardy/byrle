# An undated file is dated by its first sighting, and `cooldown_unanswered` refuses one with none

- **Number:** 0129
- **Status:** Decided by the user 2026-11-03, for finding 7 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-11-03: `Deciding::dated`, `Deciding::first_seen`
  and `Deciding::own_signals` in `src/proxy.rs`, `Analyses::first_seen` in
  `src/analysis/store.rs` and `src/analysis/postgres.rs`, migration
  `0032_artifact_first_seen.sql`, `PROXY_RULES` in `src/policy/decide.rs`.
- **Related:** [every-refusal-a-signal](0116-every-refusal-a-signal.md),
  [pypi-file-publish-times](0124-pypi-file-publish-times.md),
  [policy-schema-v1-frozen](0030-policy-schema-v1-frozen.md)

## Decision

A pinned fetch under a cooldown is dated by the first of these that answers:

| Order | Source | Was |
|---|---|---|
| 1 | the record's `published_at` | the same |
| 2 | the full document's publish times | the same |
| 3 | the file host's `Last-Modified`, from a HEAD | asked only when step 2 gave no times at all. Now also asked when its times lack the version |
| 4 | the file's first sighting: the time the proxy first decided it, recorded in `artifact_first_seen` | not read |
| 5 | none: the proxy's rule `cooldown_unanswered` fires | `cooldown_days` removed as unanswerable, and the file served |

| What | Rule |
|---|---|
| when a first sighting is recorded | on a pinned fetch, after the metadata lists the version, while the policy uses a cooldown and steps 1 to 3 gave no date |
| its key | the version's purl and the file's name, so a file added to an old release starts its own wait |
| a later sighting | reads the first time back. The row is never updated |
| where it is kept | the analysis store: Postgres at `BYRLE_DATABASE_URL`, else in process, where a restart or an eviction past `BYRLE_MAX_VERIFIED` forgets it and the file is first seen again |
| when the store errors | step 5 |
| `cooldown_unanswered` | one of the proxy's own rules, weighing `risk_threshold` unless weighed. It answers with the refusal status and the audit value `undated` |
| a metadata document | unchanged: an undated version stays in it, and its pinned fetch is decided as above |

`signal_weights` in `version: 1` gains `cooldown_unanswered`.

## Why

Before, a version with no publish date had `cooldown_days` removed (`enforce.rs`
`unenforceable_given`) and was served. The registry or the network decides whether a date
is present, not the publisher, so a missing date made a cooldown pass.

The first sighting gives every listed file a date that only moves later: the proxy cannot
have seen a file before it was published. A request for a version the metadata does not
list is refused as not listed before the store is written, so asking for a version early
starts no wait.

## Rejected

| Option | Why not |
|---|---|
| 503 for an undated pinned fetch (the review's proposal) | a deferral that never lapses, and not a weighed signal as [every-refusal-a-signal](0116-every-refusal-a-signal.md) asks |
| keep serving, and list it as a bypass | the cooldown would still pass whenever a date is missing |
| key the first sighting by version | a wheel added to a seen release would take the release's time, as 0124 found |
| record first sightings for each undated version in a metadata document | a write per version per document, and a document keeps an undated version anyway |

## Cost

On the first day, every file with no registry date is first seen that day and refused for
`cooldown_days`. How many files are undated in each ecosystem was not measured.

With no `BYRLE_DATABASE_URL`, a restart starts every undated file's wait again.

While the analysis store errors, every undated file is refused, unless
`cooldown_unanswered` is weighed under the threshold.

`byrle explain` and `byrle policy diff` read no first sighting (TODO.md ad-hoc #53).
