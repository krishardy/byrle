# How the policy tiers resolve

- **Status:** Open question. Implementation stopped pending an answer.
- **Plan reference:** §5 (superseded shape), §5.5 (current shape)
- **Related:** [package-override-tier](package-override-tier.md),
  [policy-engine-hand-rolled](policy-engine-hand-rolled.md)

This records the tier structure exactly as the plan describes it, and isolates the one
place where two sentences in §5.5 give different answers.

## The stack, as §5.5 defines it

```
                 authority
                    ▲
  ┌─────────────┐   │   never overridable by any tier. Exact version only.
  │  denials    │   │   No `expires` field exists at all.
  └─────────────┘   │   Evaluated first, short-circuits everything.
         │          │
  ┌─────────────┐   │   per ecosystem, mandatory for every enabled one.
  │  floor      │   │   `known_malware: block` pinned, not removable.
  └─────────────┘   │   Operator-extensible: any rule may be promoted in.
         │          │
  ┌─────────────┐   │   one entry per selector, most-specific-wins.
  │  packages   │   │   Handles loosening AND tightening.
  └─────────────┘   │   Loosening requires reason + expires (or permanent).
         │          │
  ┌─────────────┐   │   per ecosystem. Overrides global.
  │  ecosystems │   │   Loosening warns unless acknowledged.
  └─────────────┘   │
         │          │
  ┌─────────────┐   │   the global baseline.
  │  defaults   │   │
  └─────────────┘   │
```

§5.5, verbatim: *"Evaluation order, most authoritative first. First match
short-circuits."*

## What each tier is allowed to do

| Tier | Scope | May loosen what is below | May tighten | Justification required |
|---|---|---|---|---|
| `denials` | one exact version | n/a, never overridden | always blocks | `reason` |
| `floor` | one ecosystem | no: it *is* the limit | yes, that is its purpose | none |
| `packages` | a selector | yes, the common case | yes (§5.5 names it) | `reason` + `expires`, or `permanent` |
| `ecosystems` | one ecosystem | yes, warns unless acknowledged | yes | `loosens_global` + `reason` + `expires` to silence |
| `defaults` | everything | n/a, nothing below it | n/a | none |

## What is settled, and is not in question

- **A denial cannot be undone by anything, the floor included.** Structurally separate,
  no `expires` field, no precedence code path.
- **Nothing below the floor may go below it.** §5.5: *"a floor rule can wedge every build
  with no escape hatch below it."*
- **`ecosystems` over `defaults` is a plain override**, already implemented in
  `src/policy/merge.rs`, with loosening reported.
- **`packages` sits above `ecosystems`**, and its baseline for loosening is the
  ecosystem/defaults merge, already implemented in `src/policy/packages.rs`.

## The one place two sentences disagree

Both of these are §5.5:

> **floor** — non-overridable **minimum**, per ecosystem.

> Evaluation order, most authoritative first. **First match short-circuits.**

They agree everywhere except when a `packages` entry is **stricter** than the floor for
the same rule.

```
  floor.npm:      install_scripts: warn
  packages[0]:    match {name: sketchy}   set {install_scripts: block}
  packages[1]:    match {name: reviewed}  set {install_scripts: allow}

                        minimum           first-match
                        (clamp)           (short-circuit)
  sketchy         ->    block             warn
  reviewed        ->    warn              warn
  anything else   ->    warn              warn
```

One row differs. Under *minimum*, the floor is a lower bound and a lower tier may still
tighten past it. Under *first match*, the floor settles the rule outright and `packages`
cannot move it in either direction.

### What points each way

**Toward minimum (clamp):**

- The heading itself says *minimum*.
- *"a security team can make `provenance_required: true` **unbypassable**"* — bypassing is
  going below, not above.
- §5.5 describes `packages` as handling *"both loosening (the common case) and tightening
  (e.g. raising cooldown on a package you distrust)"*. Under first-match, tightening is
  silently impossible for any rule the floor happens to mention, and since
  `known_malware` is pinned into every floor, at least one rule always is.
- *"`explain` renders the floor as its own section rather than folding it into effective
  policy"*. A tier that were simply first in a short-circuit chain would be folded in;
  rendering it separately is what a constraint applied alongside looks like.

**Toward first match (short-circuit):**

- The evaluation-order sentence says so directly, and lists the floor above `packages`.
- It is simpler: one value, one source, nothing to combine.

### What each costs

Under **minimum**, the floor's value has to be combined with the winning lower-tier value
rather than replacing it. The machinery for that already exists: the lattice for actions,
and `Direction` for `cooldown.days` and `provenance_required`, both in
`src/policy/strictness.rs`. Combining is per dimension, so a two-dimensional rule like
`cooldown` clamps `action` and `days` independently and the incomparable case never
arises here.

Under **first match**, the floor is a plain lookup and nothing is combined. The cost is
that promoting a rule into the floor silently removes the ability to tighten it per
package, which is a surprising consequence of an action described as making a rule
*stronger*.

## What is blocked on this

- Evaluation order with first-match short-circuit (`[!]`)
- Tests: a denial cannot be undone by any tier, including the floor
- Tests: the floor survives a hostile config file

Everything else in the package tier is done. Nothing already written depends on the
answer: `merge.rs` never receives floor rules, which is §5.5's own structural guarantee,
and `packages.rs` measures against the ecosystem merge, which sits below the floor either
way.
