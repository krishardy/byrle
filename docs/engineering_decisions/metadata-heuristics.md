# Metadata heuristics report signals and refuse nothing

- **Status:** Implemented 2026-09-29, report only. `src/heuristics.rs`,
  `RecordStore::signals` in `src/store.rs`, logged and audited by `decide_artifact` in
  `src/proxy.rs`, printed by `waharoa explain`.
- **Related:** [audit-log](audit-log.md), [explain-output](explain-output.md),
  [watcher](watcher.md)

## Decision

Each pinned artifact decision computes four signals from the metadata the proxy already
holds. No request is made for them. Decided with the user: report them, measure how often
they fire on packages that are not malicious, and only then consider a policy key.

| Signal | Fires when | Source |
|---|---|---|
| `new package` | the earliest version in the held document was published under 30 days ago | `published_at` of every held record |
| `new publisher` | this version's publisher published none of the earlier versions, and at least one earlier version names a publisher | npm `_npmUser.name`, full packument only |
| `no repository` | a full npm packument names no repository for this version | npm `repository` |
| `near name` | another package held in the same ecosystem is one insertion, deletion or substitution away, compared lowercased, or differs only in case. Names under 4 characters are not compared | the record store's package names |

Decided with the user: the maintainer signal is "new to this package", not the account's
age, which no registry document states. The near name compares with packages this proxy
has served, not a list of popular packages, so a typosquat is found when a client asks for
it next to the package it imitates.

## Where signals appear

| Place | Form |
|---|---|
| log | one WARN line per decision with any signal: `waharoa.signals`, the purl and the path |
| audit | `signals` on the pinned line, omitted when empty. `audit verify` and `policy diff` do not read it |
| `explain` | a `signals` block under the verdict, or `signals: none`. `explain` holds no served names, so it never reports `near name` |

## Consequences

- npm clients ask for the abbreviated packument, which has no `time`, `_npmUser` or
  `repository`. Behind npm, pnpm and bun only `near name` fires. `explain` fetches the
  abbreviated packument too, so for npm it prints `signals: none`.
- PyPI records carry upload times, so `new package` fires for PyPI. `new publisher` and
  `no repository` never do.
- The record store is bounded and in memory, so `near name` compares with the packages
  held now, not every package ever served.

## Measuring

Count the pinned audit lines per signal, and the packages among them that intel later
marked malicious:

```
jq -r 'select(.signals) | .signals[] | sub(":.*"; "")' audit.jsonl | sort | uniq -c
```

## Tests

`src/heuristics.rs` covers each signal firing and each case that suppresses it: 30 days old,
no earlier publisher, a version with no publish time, an abbreviated document, a PyPI
record, a name compared with itself, and names under 4 characters. A case-only difference
is near. `signals_compare_names_held_in_the_same_ecosystem` covers the store's ecosystem filter and its use of the held document.
`the_audit_line_records_what_the_request_was_answered` covers the audit field. 19 hand
mutants, each caught. The length check in `within_one_edit` survived because no input
reaches it, and was removed.
