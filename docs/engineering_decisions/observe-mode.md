# Observe mode is one switch for the whole proxy, and enforce is the default

- **Status:** Implemented 2026-09-28. `refusal::Mode`, `env::MODE`, `Deciding::answer` and
  `Deciding::observed`, `policy_refused_versions`, and `mode` in `/-/byrle/health`.
  Replaces the plan's "warn mode is the default" (§6).
- **Related:** [policy-tier-resolution](policy-tier-resolution.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [reproducible-verdicts](reproducible-verdicts.md),
  [deferral-status-codes](deferral-status-codes.md)

## Decision

`BYRLE_MODE` takes `enforce` or `observe`, and is `enforce` when unset. It applies to the
whole proxy.

| Mode | What the proxy decides and audits | What it answers |
|---|---|---|
| `enforce` | as now | as now |
| `observe` | as now | what the upstream sent. Each refusal it did not make is logged at WARN and audited with the action decided |

Observe mode serves what the policy refuses. It never serves what the proxy cannot
assess, decided 2026-09-27:

| Case | Both modes |
|---|---|
| an ecosystem no intel stream covers | 503 ([uncovered-ecosystem-fails-closed](uncovered-ecosystem-fails-closed.md)) |
| an artifact whose analysis has not finished | 503 until it has |
| an artifact with no strong digest | refused |
| an artifact whose metadata names neither its version nor its file | refused |
| an artifact whose metadata the registry did not give | 502 |

The policy file does not change. `warn` stays out of the lattice
([policy-tier-resolution](policy-tier-resolution.md) §"`warn` is not in the lattice").

## Rejected

| Option | Why |
|---|---|
| a `warn` action per check | reverses the lattice decision. A check that delivers with a concern has no candidate: provenance was the only one, and it is now `block` or `allow` |
| no observe mode | `policy diff --lockfile` previews a policy over a lockfile. It does not show what live traffic would hit, such as a transitive dependency no lockfile in the repository names |
| observe as the shipped default | a proxy installed and left alone would refuse nothing. The plan's reason for it, "one blocked legitimate build and the tool is disabled", is met by making observe one variable away |

## What observe mode changes

A metadata document:

| Step | Enforce | Observe |
|---|---|---|
| decide every version | yes | yes |
| resolution audit line | written | written, with `answered: served` |
| remove versions the policy refuses | yes | no, and WARN `observe: the policy refuses these versions; left in the document` |
| remove versions on an origin the proxy does not serve | yes | yes: left in, the client would fetch them without the proxy |
| `x-byrle-filtered-versions` and `x-byrle-filtered-checks` | sent when a version was removed | not sent |
| rewrite artifact URLs to the proxy | yes | yes |

An artifact request: the policy's refusal is logged at WARN, `observe: the policy refuses
this artifact; not refused`, and the request goes on to the checks after it. Its pinned
audit line keeps the action decided, `block` or `quarantine`, with `answered: served`. An
artifact whose analysis stored a digest mismatch is still a 502: that is the transfer
failing, not the policy.

`answered: served` beside a refusing action is how a line says the refusal was not made.
No separate field was added.

`/-/byrle/health` reports `mode`, and `byrle doctor` warns when it is `observe`.
`byrle status` reports what the build does, not how a proxy is configured, so it does
not.
