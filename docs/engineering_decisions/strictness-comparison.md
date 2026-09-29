# Whether one policy value is stricter than another

- **Status:** Implemented. `src/policy/strictness.rs`, used by `policy::merge::compare`,
  `policy check` and `policy diff`.
- **Related:** [policy-tier-resolution](policy-tier-resolution.md),
  [policy-diff-dates-and-exit-bits](policy-diff-dates-and-exit-bits.md)

## Decision

§5.5 warns when an exception loosens the settings above it. The answer is not always yes or
no, so a comparison is one of six results:

| `Strictness` | Means | Warns |
|---|---|---|
| `Stricter` | tighter than what it overrides | no |
| `Same` | compared, and did not move | no |
| `Looser` | looser | yes |
| `Incomparable` | tighter in one dimension and looser in another | yes: §5.5 fails loud when tightening cannot be proven |
| `NotApplicable` | the check has no meaning for this ecosystem | no, and it is reported |
| `Unset` | nothing above set a value, so nothing was loosened | no |

`Unset` is not `Same`, which would claim a comparison that never happened, and not
`NotApplicable`, which would claim the check has no meaning here.

## Combining dimensions

`Strictness::and` combines two dimensions of one setting:

- `Incomparable` with anything is `Incomparable`. Once undecided, no later dimension makes
  it provably stricter.
- `Same`, `NotApplicable` and `Unset` do not decide the result when the other side was
  compared: a dimension that did not move is `Same` over every compared dimension.
- `NotApplicable` with `Unset` is `NotApplicable`. They do not meet in practice, because
  applicability is decided for the whole check first.
- `Stricter` with `Looser` is `Incomparable`. This is why the combination is not a `min`.

Kani proofs in `strictness.rs` hold that `and` is commutative and associative, so a
setting's answer does not depend on field order, and that a conflict is never resolved by
picking one side, which commutativity and associativity alone would not catch.

## Direction

For an action the order is `allow < quarantine < block`. `Action::strength` states it
explicitly rather than taking it from the declaration order, and `ordering_is_the_lattice`
checks that the two agree. Two actions always compare, so an action alone is never
`Incomparable`.

For a number, nothing in the value says which way is stricter: a higher `cooldown_days` is
stricter and a higher `max_cvss` is looser. `merge::compare` names the direction for
`cooldown_days`, the one number an exception can set, and `the_two_directions_are_mirror_images` checks the two directions against each other. A
direction declared backwards would warn in exactly the wrong cases.
