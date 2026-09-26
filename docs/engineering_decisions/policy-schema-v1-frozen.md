# Policy schema version 1 is frozen

- **Status:** Decided 2026-09-13. Part of the Stage 2 exit criterion.
- **Related:** [policy-tier-resolution](policy-tier-resolution.md) (what the keys mean),
  [config-format-yaml-serde-saphyr](config-format-yaml-serde-saphyr.md) (the loader)

## Decision

`version: 1` is closed. No key is added, removed, renamed or retyped under it. A policy that
needs a new key says `version: 2`, and a build that understands only 1 refuses it by number
with `PolicyError::UnsupportedVersion`.

A default or the meaning of an existing key is part of what a written file says. Changing
either changes a file nobody edited, so that is a `version: 2` change too.

## The keys

| Level | Keys |
|---|---|
| top level | `version`, `cooldown_days`, `max_cvss`, `install_scripts`, `kev`, `deprecated`, `yanked`, `provenance`, `denials`, `packages`, `advisory_scores` |
| a `denials` entry | `purl`, `version`, `reason` |
| a `packages` entry | `match`, `set`, `reason`, `expires`, `permanent`, `added_by` |
| an `advisory_scores` entry | `advisory_id`, `cvss`, `reason`, `expires`, `permanent`, `added_by` |
| `match` | `ecosystem`, `name`, `purl`, `version`, `has_install_scripts` |
| `set` | `cooldown_days`, `kev`, `install_scripts`, `yanked`, `deprecated`, `provenance`, `vuln_advisory_ids` |

| Key | Value | Default |
|---|---|---|
| `version` | `1` | required |
| `cooldown_days` | whole days, 0 or more | 7 |
| `max_cvss` | a number. At or below is allowed | 6.9 |
| `install_scripts`, `kev`, `yanked`, `provenance` | `block` or `allow` | `block` |
| `deprecated` | `block` or `allow` | `allow` |
| `denials[].purl` | a purl, with `@version` unless `version` is set | required |
| `denials[].version` | a VERS range, when the purl has no `@version` | none |
| `reason` | text | required |
| `expires` | a date, `YYYY-MM-DD`, within the expiry ceiling | none |
| `permanent` | `true` or `false` | `false` |
| `added_by` | text | none |
| `match.ecosystem` | an ecosystem name | required |
| `match.name` | `*`, `prefix*` or a literal | none |
| `match.purl` | a purl | none |
| `match.version` | an exact version, or a VERS range whose type is `match.ecosystem` | none |
| `match.has_install_scripts` | `true` or `false` | none |
| `set.vuln_advisory_ids` | advisory ids, each matched against an advisory's id and its aliases | empty |
| `advisory_scores[].advisory_id` | an advisory id, matched against an advisory's id and its aliases | required |
| `advisory_scores[].cvss` | a number, 0.0 to 10.0 | required |

The rules the keys obey are fixed with them: every key refused when unknown, at every level;
a `packages` entry that loosens needs `expires` or `permanent: true`; an entry that tightens
is refused; overlapping entries that cannot be ordered by subset containment are refused;
every `advisory_scores` entry needs `expires` or `permanent: true`, and not both; two
`advisory_scores` entries with the same `advisory_id` are refused.

## What is not frozen

- Anything a policy file does not express: which intel streams are loaded, what `explain`
  prints, the audit log's fields.
- New warnings. A new refusal of a document version 1 accepts is a `version: 2` change.

## Held by

`the_version_1_key_set_is_closed` in `src/policy.rs`. Refusing an unknown key, serde names
every key the struct accepts, and the test pins those lists at all six levels. Adding,
removing or renaming a key fails it. `a_policy_that_says_nothing_blocks_every_on_off_check` pins
the defaults. `the_shipped_example_parses` loads `examples/policy.yaml`.

## Renamed before the freeze

`cve_ids` became `vuln_advisory_ids` on 2026-09-13. The list matches any advisory id or
alias, `GHSA-` and `MAL-` ids included, so version 1 never carried a name that says CVE.

## Added after the freeze, before deployment

`provenance` was added to `version: 1`, at the top level and in `set`, on 2026-09-26,
defaulting to `block`. No version 1 policy had been deployed. See
[provenance-check](provenance-check.md).

`yanked` was added to `version: 1`, at the top level and in `set`, on 2026-09-20, defaulting
to `block`, and `deprecated` the same day, defaulting to `allow`. No version 1 policy had
been deployed. See [yanked-files](yanked-files.md).

`denials[].version` was added to `version: 1` on 2026-09-19, and `match.version` took a VERS
range as well as an exact version. No version 1 policy had been deployed. See
[policy-version-ranges](policy-version-ranges.md).

`advisory_scores` was added to `version: 1` on 2026-09-15. The user chose this over opening
`version: 2`, as no version 1 policy had been deployed. `max_cvss` refuses a non-malware
advisory with no score, and an entry gives it one. See
[osv-ranges-and-scores](osv-ranges-and-scores.md#advisories-with-no-score-2026-09-15).
