# Package-level overrides and denials

- **Status:** Decided
- **Plan reference:** decision #8. Full schema and semantics in plan §5.5.

## Decision

Three structurally separate blocks, evaluated most-authoritative first, first match
short-circuiting:

```
denials  ->  floor  ->  packages  ->  ecosystems  ->  defaults
```

- **`denials`**: permanent, absolute, always exact version, never overridable.
- **`floor`**: non-overridable minimum, per ecosystem, mandatory for every enabled
  ecosystem, operator-extensible, with `known_malware: block` pinned.
- **`packages`**: unified override tier, replacing the earlier `exceptions` block,
  handling both loosening and tightening.

## Rationale

Separation is structural rather than conventional. `denials` has no `expires` field and
no code path that consults precedence, so a denial with an expiry date is
unrepresentable. The merge function that handles `defaults` never receives floor rules,
so no code path exists by which a lower tier could override one. In Rust the floor is a
distinct type with no override constructor.

`ecosystem` is required on every selector. npm `requests` and PyPI `requests` are
unrelated projects, so a cross-ecosystem match is almost always a mistake. Requiring it
keeps tiers strictly linear and makes `{name: "*", cooldown: 0}` impossible to write by
accident.

Loosening in the `packages` tier requires `reason` plus `expires` (90 days maximum) or
`permanent: true`, and emits no warning. Warnings are correct at the ecosystem tier
where loosening is unexpected; here it is the tier's purpose, and per-entry warnings
would bury the ecosystem-tier warnings that matter. A required field cannot be ignored
the way a warning can.

Expiry inverts the default so an unexamined entry dies rather than persisting. A
justification is true when written and stops being true silently.

Specificity is strict subset containment, not a heuristic score. Incomparable overlaps
are a load-time error rather than a silent guess.

## Consequences

- A missing floor for an enabled ecosystem is a startup failure. Adding an adapter
  therefore breaks existing configs until a floor is declared, so shipped templates must
  include floors for every supported ecosystem. `examples/policy.yaml` does not yet, and
  that gap is tracked in TODO.md.
- The floor guards against careless overrides at lower tiers. It does not defend against
  someone with write access to the policy file, who can edit the floor directly. Plan §7
  states this rather than implying a stronger guarantee.
- Version ranges are resolved by the normalizer into a concrete match set before the
  policy engine sees them. Validate against the PyPI adapter before freezing.

## See also

- [policy-engine-hand-rolled](policy-engine-hand-rolled.md): containment is decidable
  only because the predicate vocabulary is closed.
- [cooldown-waivers-manual-only](cooldown-waivers-manual-only.md), which reduces to this
  tier.
