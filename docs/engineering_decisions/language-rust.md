# Language: Rust

- **Status:** Decided
- **Plan reference:** decision #1

## Decision

Rust.

## Rationale

Maintainer fluency. The type system encodes three things the policy engine needs as
structure rather than as runtime checks: the §5 action lattice, per-parameter
monotonicity, and the non-overridable floor. §5.5 makes this concrete: `denials` is a
distinct type with no `expires` field, so a denial with an expiry date is
unrepresentable rather than discouraged, and the floor has no override constructor.

## Consequences

Accepted costs, recorded when the decision was made:

- `sigstore-rs` is immature, which bears on provenance enforcement (Tier 1).
- No OSV client exists; the client is ours to write.
- `serde_yaml` is archived. Resolved separately, see
  [config-format-yaml-serde-saphyr](config-format-yaml-serde-saphyr.md).
- rustls is strict about certificates that other stacks accept.

## See also

- [policy-engine-hand-rolled](policy-engine-hand-rolled.md), which depends on the type
  system argument above.
