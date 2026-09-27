# Observe mode is one switch for the whole proxy, and enforce is the default

- **Status:** Decided 2026-09-27, not implemented. Replaces the plan's "warn mode is the
  default" (§6).
- **Related:** [policy-tier-resolution](policy-tier-resolution.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [reproducible-verdicts](reproducible-verdicts.md),
  [deferral-status-codes](deferral-status-codes.md)

## Decision

`WAHAROA_MODE` takes `enforce` or `observe`, and is `enforce` when unset. It applies to the
whole proxy.

| Mode | What the proxy decides and audits | What it answers |
|---|---|---|
| `enforce` | as now | as now |
| `observe` | as now | what the upstream sent. Each refusal it did not make is logged at WARN and audited with the action decided |

An ecosystem this build does not cover is refused in both modes, decided 2026-09-27. The
proxy has no way to read its metadata or its artifacts, so nothing about a dependency
from it can be decided or logged as a refusal not made
([uncovered-ecosystem-fails-closed](uncovered-ecosystem-fails-closed.md)).

The policy file does not change. `warn` stays out of the lattice
([policy-tier-resolution](policy-tier-resolution.md) §"`warn` is not in the lattice").

## Rejected

| Option | Why |
|---|---|
| a `warn` action per check | reverses the lattice decision. A check that delivers with a concern has no candidate: provenance was the only one, and it is now `block` or `allow` |
| no observe mode | `policy diff --lockfile` previews a policy over a lockfile. It does not show what live traffic would hit, such as a transitive dependency no lockfile in the repository names |
| observe as the shipped default | a proxy installed and left alone would refuse nothing. The plan's reason for it, "one blocked legitimate build and the tool is disabled", is met by making observe one variable away |

## To settle when it is built

| Case | Proposed |
|---|---|
| a quarantined or blocked version in a metadata document | left in. The removal is audited as a resolution line, as now |
| an artifact whose analysis has not finished, answered 503 now | served. The analysis still runs, and the audit line records `served` |
| an artifact whose bytes do not match the published digest, answered 502 now | still refused. It is an integrity failure of the transfer, not a policy verdict |
| how the audit line says the refusal was not made | open. `answered: served` with a `block` action already says it; a separate field may read more plainly |
| `/-/waharoa/health` and `waharoa status` | report the mode |
