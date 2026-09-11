# Cooldown versus urgent fixes: manual waivers only

- **Status:** Decided
- **Plan reference:** decision #4b

## Decision

Manually reviewed version waivers only. No automatic advisory-based bypass of cooldown.

## Rationale

An automatic waiver triggered by an advisory is attacker-exploitable: publish a fake
advisory against the current version, and the cooldown on your malicious replacement
is waived. The mechanism that would let a security fix through quickly is the same one
that lets an attacker through quickly.

Manual waivers reduce to the §5.5 `packages` tier, which already exists and already
requires `reason` plus `expires`.

## Consequences

One path only. There is no emergency fast path, and deploy latency during an urgent fix
is accepted as the cost of having a single auditable route.

## See also

- [package-override-tier](package-override-tier.md).
