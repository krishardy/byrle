# Policy version ranges are VERS strings, in every ecosystem

- **Status:** Decided 2026-09-19. Not yet implemented.
- **Related:** [policy-schema-v1-frozen](policy-schema-v1-frozen.md),
  [pep440-version-order](pep440-version-order.md),
  [policy-tier-resolution](policy-tier-resolution.md), [policy-check](policy-check.md)

## Decision

A policy writes a version range as a VERS string, the version range specifier from the
Package-URL project (`github.com/package-url/vers-spec`, Clause 5, read 2026-09-18 at
`f98c4c6`). One syntax covers every ecosystem. The VERS type names how the versions order,
and waharoa orders them by the ecosystem's `VersionOrder`.

A denial stays one exact version, written in its purl.

```yaml
denials:
  - purl: "pkg:npm/chalk@5.6.1"
    reason: "compromised release, Sept 2025"

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
| `denials[].purl` | a purl with `@version`, as today | a purl without one (`DenialNeedsAVersion`), as today |

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
| A range in a denial, in a `denials[].version` key | Redundant beside the purl, which already names the package and holds a version. A denial is absolute and has no `expires`, so a range such as `vers:npm/>=1.0.0` would also refuse every future version |

VERS is also what purl-based tools publish ranges in, and `denials` and `match.purl` are
purls already.

## Schema

Added to `version: 1` before deployment, as `advisory_scores` was on 2026-09-15: no
version 1 policy has been deployed. `policy-schema-v1-frozen.md` records the exception
when this is implemented. What changes in it:

| Key | Before | After |
|---|---|---|
| `match.version` | an exact version | an exact version or a VERS string |

No key is added.

## Known consequences

- The registered `pypi` examples in the VERS repository break Clause 5.4's sorting rule,
  for example `vers:pypi/>=3.0.0|2.0.3`. They are refused here.
- `policy check`, `policy diff` and `explain --policy` print a range as it is written.
