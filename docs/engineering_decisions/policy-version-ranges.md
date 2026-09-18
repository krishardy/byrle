# Policy version ranges are VERS strings, in every ecosystem

- **Status:** Implemented 2026-09-19. `src/policy/vers.rs`, `Canonical::of` and
  `Canonical::of_denial` in `src/policy/selector.rs`, `Denial` in `src/policy.rs`,
  `Registry::canonical_name` in `src/ecosystem.rs`.
- **Related:** [policy-schema-v1-frozen](policy-schema-v1-frozen.md),
  [pep440-version-order](pep440-version-order.md),
  [policy-tier-resolution](policy-tier-resolution.md), [policy-check](policy-check.md)

## Decision

A policy writes a version range as a VERS string, the version range specifier from the
Package-URL project (`github.com/package-url/vers-spec`, Clause 5, read 2026-09-18 at
`f98c4c6`). One syntax covers every ecosystem. The VERS type names how the versions order,
and waharoa orders them by the ecosystem's `VersionOrder`.

```yaml
denials:
  - purl: "pkg:npm/chalk@5.6.1"                  # one version, as before
    reason: "compromised release, Sept 2025"
  - purl: "pkg:npm/lodash"
    version: "vers:npm/<4.17.21"                 # a range
    reason: "prototype pollution"

packages:
  - match: { ecosystem: pypi, name: requests, version: "vers:pypi/>=2.31|<3" }
    set: { cooldown_days: 0 }
    reason: "pinned by the platform team"
    expires: 2026-12-01
```

## The rules

| Key | Takes | Refused |
|---|---|---|
| `match.version` | one exact version, or a VERS string whose type is `match.ecosystem` | a VERS type other than `match.ecosystem` |
| `match.purl` | a purl, with or without `@version` | a purl with `@version` beside `match.version`. Today the purl's version wins and `match.version` is ignored without a word |
| `denials[].purl` | a purl with `@version`, or without one when `version` is set | neither `@version` nor `version`, as today (`DenialNeedsAVersion`); both |
| `denials[].version` | a VERS string whose type is the purl's type | a bare version. A single version is written in the purl |

A VERS string is read as Clause 5 and `how-to-parse.md` say, and invalid input is refused
rather than corrected:

| VERS rule | |
|---|---|
| form | `vers:<type>/<constraint>\|<constraint>...` |
| comparators | a bare version (equal), `!=`, `<`, `<=`, `>`, `>=`, and `*` alone |
| a leading `=` | refused |
| order | constraints sorted by version, each version once |
| sequence | ignoring `!=` and bare versions, `>`/`>=` and `<`/`<=` alternate |
| characters | no whitespace; `> < = ! * \| %` in a version are percent-encoded |
| type | an ecosystem with a row in `ecosystem::TABLE`, so `npm` or `pypi` today |

Every version in the string must read by the ecosystem's `VersionOrder`. A version that
does not is refused at load, naming the entry.

`^`, `~`, `~=`, `.*` and every other ecosystem's own range notation stay refused, with a
message naming VERS.

## Matching

An exact version matches a version equal to it in the ecosystem's order, so PyPI's `1.0`
matches `1.0.0` and `1.0-1` matches `1.0.post1`. A range matches a version inside it by the
containment procedure in `how-to-parse.md`.

The overlap check decides whether one `packages` selector contains another. A VERS string
is a finite union of intervals over a total order, so containment is decided by comparing
the intervals, not estimated.

## Why VERS

| Alternative | Why not |
|---|---|
| Exact versions only | The operator asked for ranges |
| Each ecosystem's own notation: `^1.2`, `~=1.4` | Two syntaxes, and more with each ecosystem. `^` and `~` have no PEP 440 meaning |
| Bare constraints, `>=1.0\|<2.0` | Not a string any other tool reads as VERS |
| GitHub's `>= 1.0, < 2.0` | One interval per entry, no `!=`, and no published specification |
| A second key, `versions` | Two keys for one question, and an entry could set both |

VERS is also what purl-based tools publish ranges in, and `denials` and `match.purl` are
purls already.

## Schema

Added to `version: 1` before deployment, as `advisory_scores` was on 2026-09-15: no
version 1 policy has been deployed. `policy-schema-v1-frozen.md` records the exception
when this is implemented. What changes in it:

| Key | Before | After |
|---|---|---|
| `match.version` | an exact version | an exact version or a VERS string |
| `denials[].version` | not a key | a VERS string |

## Settled while implementing

| Question | Answer |
|---|---|
| A lone `<2.0.0` or `!=1.0.0` | Every version below 2.0.0, and every version but 1.0.0: the segment Clause 5.3.3 describes. The containment procedure in `how-to-parse.md` walks pairs of constraints and, read literally, reaches neither |
| A version for an ecosystem with no row in `ecosystem::TABLE`, such as `match: { ecosystem: cargo, version: "1.0.0" }` | Refused: there is no order to read it by. A selector for such an ecosystem without a version still loads |
| A PyPI name | PEP 503 normalised in a selector, a denial, and every PyPI key, so `Django` is `django`. A prefix keeps a trailing separator as `-`, so `zope.*` covers `zope-interface` and not `zopefoo` |
| An npm name | Compared as written |
| Two VERS strings for one set | Cannot occur: two spans that touched would share a version, and VERS names each version once. An exact version and its one-version VERS string are equal |
| The kani proofs of containment | Proved over a 3-version bit set in place of `Versions`, which is more state than a proof unwinds in reasonable time. `Canonical` is generic over `VersionSet` for this |

## Known consequences

- A denial is absolute and has no `expires`. `vers:npm/*` or `vers:npm/>=1.0.0` refuses
  every future version as well.
- The registered `pypi` examples in the VERS repository break Clause 5.4's sorting rule,
  for example `vers:pypi/>=3.0.0|2.0.3`. They are refused here.
- `policy check`, `policy diff` and `explain --policy` print a range as it is written.
