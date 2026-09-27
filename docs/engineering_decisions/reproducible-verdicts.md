# A pinned verdict records its inputs, and `waharoa audit verify` decides it again

- **Status:** Implemented 2026-09-27. `audit::Inputs`, `audit::RecordedFacts`,
  `audit::replay`, `enforce::unenforceable_of`, `Policy::digest`, and
  `waharoa audit verify`.
- **Related:** [snapshot-identity](snapshot-identity.md),
  [intel-in-decisions](intel-in-decisions.md),
  [artifact-analysis-store](artifact-analysis-store.md),
  [policy-diff-dates-and-exit-bits](policy-diff-dates-and-exit-bits.md)

## Decision

The Stage 5 item reads "same policy + same intel snapshot = same result". It is built as
record and replay. Each pinned line of the audit log carries every input the engine read.
`waharoa audit verify <LOG> --policy <PATH>...` decides each pinned line again from those
inputs and reports any line that decides differently.

```
$ waharoa audit verify audit.jsonl --policy policy.yaml
line 1: not replayable: written before inputs were recorded
line 7: differs: pkg:npm/widget@2.0.0: action allow now block
5 reproduced, 1 differ, 1 not replayable
```

It exits 1 when a line differs and 2 when a policy or the log cannot be read. A line it
cannot replay does not change the exit code: a log whose every line names a policy not
given exits 0.

## What a pinned line records

Under `inputs`:

| Field | Holds |
|---|---|
| `as_of` | the date the engine decided on, `YYYY-MM-DD` UTC. A cooldown and an expiry are decided on this date, not on `at` |
| `policy_digest` | `sha256:` of the policy file's bytes, `Policy::digest` |
| `build` | `CARGO_PKG_VERSION` |
| `reader`, `verifier` | `analysis::READER` and `analysis::attestation::verifier_id()`, whose stored results the facts came from |
| `facts` | every field of `Facts`: publish date, `known_malware`, each advisory with its aliases, score, band, KEV flag and sources, whether intel was consulted and with exploitation loaded, install scripts, yanked, deprecated, and provenance |

The advisories are written out, not named by `intel_snapshot`. A kept snapshot is optional
and pruned, so a snapshot id alone cannot be read back. A line grows with the package's
advisories.

An unknown provenance is recorded as `unknown` with its reason, and read back with the
reason "recorded as unknown". No check reads the reason.

## What is compared

The action, `checks`, `exceptions_used` and `unenforceable`, as the line recorded them.
`unenforceable` is decided from the facts alone, `enforce::unenforceable_of`: the
cooldown is unenforced when no publish date was recorded. The proxy's
`enforce::unenforceable` gives the same names and differs only in the reason it gives.
Both read the date from `facts::published_date`.
`the_facts_alone_give_the_same_unenforced_checks_as_the_record` compares the two for a
record with a date, one without, one dated by fetched times and one the times do not date.

## Not replayable

| Line | Why |
|---|---|
| written before `inputs` existed | nothing to decide on. It still parses: `Event` is `#[serde(default)]` |
| a `policy_digest` no `--policy` file has | the policy is not given. Pass every file the log may have been decided under |
| an `as_of`, `published` or intel state that does not read | the recorded input is not one this build writes |
| not JSON | not an audit line |

Resolution lines are skipped. A resolution records the versions removed from a document,
not the facts of each, and replaying one would mean writing out every version's facts.

## What the replay shows

That the engine gives the same verdict from the same inputs, under this build. It does not
show that the recorded facts were what the registry, the intel store and the analysis
store held. `reader` and `verifier` say which analysis the facts were built from.

`build` is `0.1.0` on every commit until releases are versioned. A line another build wrote
is replayed, and counted in the summary, rather than refused.

## Defects found building it

Fixed in `fe6f430`:

| Defect | Fix |
|---|---|
| `decide_artifact` called `policy::today()` twice, so a request over midnight UTC could be decided on one date and audited on the next | one call, passed to both |
| a pinned request deferred for its analysis, or answered 502 after a digest mismatch, was audited as if served | `answered`: `served`, `refused`, `deferred` or `upstream-mismatch` |

## Tests

`audit::tests` replays lines built from `Facts` with `unenforceable_of`: one that
reproduces, one per compared field that differs, each reason a line is not replayable, a line from another
build, and each provenance and intel state read back. `the_order_of_the_advisories_does_not_change_the_verdict`
reverses the advisories and expects the same checks and exceptions.
`proxy::tests::the_audit_line_records_what_the_request_was_answered` sends a deferred, a
refused and a served request through the proxy, then replays its log: 3 reproduced.
`verify_exits_1_only_when_a_line_differs` and
`verify_exits_2_when_a_policy_or_the_log_does_not_read` cover the exit codes.

cargo-mutants over `replay`, `render`, `Inputs`, `RecordedFacts`, `unenforceable_of` and
`digest_of`: 33 mutants, 26 caught, 7 unviable, none missed. Over `verify`: 5, 2 caught, 3
unviable. `unenforceable_of`'s `is_none()` turned to `is_some()` by hand fails two tests.
