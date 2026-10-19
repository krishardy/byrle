# Every `packages` entry that matches a version applies, in file order

- **Number:** 0117
- **Status:** Decided by the user 2026-10-16 and 2026-10-18, as TODO.md ad-hoc #38.
  Implemented 2026-10-19: `policy::decide`'s `Applied` and `matching`, and
  `policy::check`'s `overridden` and `Reset`.
- **Related:** [policy-tier-resolution](0023-policy-tier-resolution.md), whose resolution of
  overlapping entries this replaces, [package-override-tier](0009-package-override-tier.md),
  [policy-check](0034-policy-check.md), [reproducible-verdicts](0070-reproducible-verdicts.md)

## Decision

When more than one live `packages` entry matches a version, the `set` blocks of all of them
apply, from entry 0 to entry n. Until now one entry applied whole, the narrowest by strict
subset containment (`decide::most_specific_match`), and two entries that overlap with
neither inside the other were refused at load (`PolicyError::Overlapping`).

| Key | Applied |
|---|---|
| `cooldown_days`, `install_scripts`, `kev`, `yanked`, `deprecated`, `provenance` | the value of the last matching entry that sets it |
| `ignored_vuln_advisory_ids` | every matching entry's ids, together |

| Question | Answer |
|---|---|
| Two entries setting one key | the later one's value. An entry may only loosen against the settings, so the values differ only for `cooldown_days`, or when a later entry sets a key back to the setting's own value |
| A later entry that sets a key back, undoing an earlier one for the versions both match | it applies, decided by the user 2026-10-18 over refusing it at load or keeping the loosest value. `byrle policy check` reports it as overriding the earlier entry |
| An entry past its `expires` | matches nothing, so the others still apply |
| Overlapping entries, or two with one selector | load |
| Which entry a check names as excusing it | the entry whose value decided it; for `max_cvss`, each entry naming an advisory it excused |
| An entry that never applies | `byrle policy check` reports one whose every key is set again by later entries that match every version it does: one entry whose selector contains it, or the two halves `has_install_scripts: true` and `false` |

## Why

The user, 2026-10-16: two exceptions written for one package, such as a cooldown waiver and
an advisory id, should both hold, rather than the narrower one silently dropping the wider
one's keys, or the pair being refused because neither selector contains the other.

## Rejected

| Option | Why not |
|---|---|
| The narrowest entry, whole, as before | the user asked for the union |
| The loosest value per key, whatever the order | the user chose file order |
| Refusing a later entry that undoes an earlier one | the user chose to apply it and report it |

## Consequences

An audit line written before this change records the entries that excused each check under
the old rule. `byrle audit verify` reports one whose version two entries matched as differing
in `exceptions_used`.
