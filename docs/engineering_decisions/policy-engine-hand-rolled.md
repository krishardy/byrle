# Policy engine: hand-rolled

- **Status:** Decided
- **Plan reference:** decision #2

## Decision

Hand-rolled policy engine. Rego remains available later as an optional escape hatch.

## Rationale

The rule set is small and closed. Rego cannot natively express two things this design
requires: detection of policy *loosening*, and the non-overridable floor. `explain`,
which plan §6 makes a first-class command, is far harder to implement over Rego.

A closed predicate vocabulary also makes selector specificity decidable. §5.5 resolves
overlapping selectors by strict subset containment, which is only decidable because the
vocabulary is closed; an open expression language makes containment undecidable.

## Consequences

Rule expressiveness is bounded by what we implement. Organisations wanting arbitrary
logic get the Rego escape hatch later, not the core engine.

## See also

- [package-override-tier](package-override-tier.md) for the containment rules.
- [language-rust](language-rust.md).
