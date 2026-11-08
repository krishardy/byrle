# A policy selector compares a crate name as crates.io does, `-` as `_`

- **Number:** 0136
- **Status:** Implemented 2026-11-08, for finding 33 of the security review:
  `Registry::selector_name`, `ecosystem::selector_name`, `cargo::paths::selector_name`.

## Context

A `packages` entry or a `denials` purl named a crate as its author wrote it, and the policy
compared it lowercased (`cargo::paths::canonical_name`). An entry for `foo_bar` matched
nothing when the crate is `foo-bar`, so a denial did not refuse it and a stricter entry did
not apply.

crates.io treats the two spellings as one crate. Its `canon_crate_name` is
`replace(lower($1), '-', '_')` (`migrations/20150319224700_dumped_migration_93/up.sql`), and
`index_crates_name` is a unique index on it (`migrations/20150319224701_dumped_migration_94`),
`main` on 2026-11-08. A name that reads as another's cannot be published.

`canonical_name` also names the rows intel stores (`intel::rows::Affected::new`), and the
proxy looks them up by the package key's name, which keeps the spelling. Folding it would
store `serde_json`'s advisories under one spelling and look them up under another whenever
the two differ.

## Decision

| Function | Used by | A crate name |
|---|---|---|
| `canonical_name` | intel rows, so a key's name finds them | lowercased |
| `selector_name` | `NamePattern::canonical` and `Selector::matches`: `packages`, `denials` | lowercased, `-` read as `_` |

Both sides of a policy comparison go through `selector_name`, so `Foo-Bar`, `foo_bar` and
`foo-*` all cover `foo-bar` and `foo_bar`. `policy check` and `explain` print a cargo
selector with `_`. The other ecosystems' `selector_name` is their `canonical_name`.

## Costs

A policy file written before this matches more crates under it: a denial or a `packages`
entry spelled with the other separator now applies. That includes a loosening entry.
`policy diff` compares both sides under the new rule, so it does not show the change.
