# Every refusal is a weighted signal, refused at one threshold

- **Number:** 0116
- **Status:** Decided by the user 2026-10-17 and 2026-10-18, as TODO.md ad-hoc #42 and
  [risk-score-plan](../risk-score-plan.md). Implemented 2026-10-18, `4ac8570` to
  `7175030`, as the plan's steps 2 to 7 record: `policy::decide`'s `Decision::action`,
  `check_weight` and `History`, `proxy::Deciding::refusal`, and `audit::Inputs`.
- **Related:** [policy-tier-resolution](0023-policy-tier-resolution.md), whose verdict
  this replaces, [policy-schema-v1-frozen](0030-policy-schema-v1-frozen.md),
  [detectors](0092-detectors.md), [reproducible-verdicts](0070-reproducible-verdicts.md)

## Decision

A version is refused when the weights of the signals present sum to the policy's
`risk_threshold` or more. Every reason the proxy refuses today is a signal:

| Group | Signals | Default weight |
|---|---|---|
| the policy's checks | `denied`, `known_malware`, `cooldown`, `kev`, `max_cvss`, `install_scripts`, `yanked`, `deprecated`, `provenance_unverified`, `provenance_dropped`, `provenance_identity_changed` | the threshold, or 0 where the policy sets the check to `allow` |
| the proxy's own | `no_strong_digest`, `unservable`, `digest_mismatch`, `signature_failed`, and since 2026-11-03 `cooldown_unanswered` ([0129](0129-undated-files-first-seen.md)) | the threshold, except `no_strong_digest`: 0, set by the user 2026-10-18. A version the metadata does not list is refused whatever is weighed, so it has no weight |
| reported today, refusing nothing | the advisory kinds, the detectors' rules, `trustpub_*`, `signing_key_*` | as today |

So an unedited policy refuses what it refuses today, except an artifact with no strong
digest, which is forwarded unverified and unanalysed. `version: 1` is changed, not a
`version: 2` opened: `install_scripts: block` is that signal weighing the threshold and
`allow` 0, and the same for `kev`, `yanked`, `deprecated` and `provenance`. A `packages`
entry's `set: { x: allow }` weighs that signal 0 for the versions it matches.

| Question | Answer |
|---|---|
| Thresholds | one, `risk_threshold`, not one per dimension |
| Known malware and `denials` | weigh the threshold by default and can be weighed lower; `policy diff` and `policy check` report that as a loosening, and nothing more |
| Observe mode | serves a version over the threshold only when the proxy's own signals alone weigh under it, so it never serves what cannot be assessed |
| A proxy signal weighed under the threshold | each serves what it can: a version on an origin the proxy does not serve is fetched by the client, as `BYRLE_REFUSE_UNSERVABLE=0` does today; one with no strong digest is served unanalysed; bytes not matching their digest have their last chunk released. A version the metadata does not list is refused whatever its weight, as there is no record to fetch it by |
| Replay | the signals present and their weights are in the audit line's `Inputs`, so `byrle audit verify` decides the verdict again |

## Why

The user, 2026-10-17: refusals should come from the sum of signals, not one rule each. A
rule that refuses alone cannot be outweighed by what else is known about the version, and
its false positives can only be answered by an exception per package.
`gradle-versions-plugin` 0.52.0 is refused today as `Dropped { previous: 0.11.1 }` after
44 unsigned versions; a score can say that 44 versions make a 45th unsigned unsurprising.

A dropped attestation is weighed on that history ([risk-score-plan](../risk-score-plan.md)
step 6). Decided by the user 2026-10-18: `provenance_dropped` weighs half the threshold,
and `provenance_surprise` sits beside it, a quarter of the threshold per bit of how
unexpected an unattested version is after its release line's earlier versions, at a
half-life the policy sets as `provenance_half_life`.

The proxy's own refusals were recommended to stay outside the score, as they refuse bytes
that cannot be checked rather than judging a package. The user chose to include them, and
observe mode still refuses them.

## Rejected

| Option | Why not |
|---|---|
| The proxy's refusals kept outside the score | chosen against by the user, 2026-10-18 |
| A threshold per dimension | one sum is one thing to explain and to measure |
| Known malware and `denials` kept as outright blocks, or fixed at the threshold | the user chose weights the policy can lower |
| `version: 2` | the user chose to change version 1, as for ad-hoc #37 |
