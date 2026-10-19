# `byrle policy check`

- **Number:** 0034
- **Status:** Implemented. `src/policy/check.rs`; the command in `src/main.rs`, and
  `startup::report_policy` for the proxy.
- **Plan reference:** §5.5, "`policy check` flags selectors that can never win" and
  "`permanent: true` ... reported separately by `policy check`"; §6, `policy check --strict`.

## Decision

`byrle policy check <path> [--as-of YYYY-MM-DD] [--strict] [--fetch]` loads a policy the
way the proxy does at startup: `Policy::load`, then `packages::check` with the expiry ceiling
from the environment and the date, UTC today by default. It prints six lists, each only when
it has an entry:

| Section | An entry is listed when |
|---|---|
| changes nothing | every value it sets equals the global setting (`packages::changes_nothing`), and it sets no key back over an earlier entry |
| never applies | later entries set every key it sets again, for every package it matches, and none of them expires |
| overridden until a later entry lapses | the same, and one of them expires. The line gives the last day |
| sets a key back over an earlier entry | it is after an entry it shares packages with, and sets a key stricter than that entry does, so undoes it for those packages |
| cooldown waivers no longer needed | `--fetch` only: it shortens `cooldown_days` for one version the global wait now admits anyway |
| permanent | it has `permanent: true` |

| Exit | When |
|---|---|
| 0 | the policy loads, and with `--strict`, no entry changes nothing, never applies, or has outlived its cooldown |
| 1 | load or the `packages` rules refuse it, or `--strict` and an entry changes nothing, never applies, or has outlived its cooldown |
| 2 | the file cannot be read, or the command line is malformed |

The proxy at startup and `byrle doctor` read the same `check::Report`. Startup warns for
each entry that changes nothing or never applies. `doctor` reports each as `WARN`, and a
refused policy as `PROBLEM`.

## `--fetch`

A cooldown waiver is a `packages` entry that shortens `cooldown_days` for one exact version.
It does something only while that version is younger than the global wait, and then sits in
the file loosening the policy for nothing until its `expires` date. Whether it still does
anything takes the version's publish date, which only the registry has, so the command asks
for it under a flag and is offline without one.

```
$ byrle policy check policy.yaml --fetch
2 package entries, as of 2026-09-20

cooldown waivers no longer needed
  packages[0] pkg:npm/lodash@4.17.21: published 2021-02-20, past cooldown_days 30 since 2021-03-22
```

An entry naming a range or a whole package is not a waiver here: it covers versions nobody
has published, so no publish date answers it. A version the registry does not publish, or a
fetch that fails, is a note on stderr rather than a finding: not knowing is not the same as
knowing the entry is unnecessary.

## Which entries never apply

Since 2026-10-18 every live entry matching a version applies, in file order, and each key
takes the last value set ([every-matching-entry-applies](0117-every-matching-entry-applies.md)).
Until then load refused overlapping entries that did not nest, and the narrowest match won
whole. An entry never applies when, for each key it sets, a later live entry sets it again
for every package it matches (`check::overridden`):

- a later entry whose selector contains it, or
- its two halves after it: entries with its ecosystem, name and version, one
  `has_install_scripts: true` and one `false`. Covering a name pattern or an absent version
  would take entries listing every name or version under it. That is not looked for.

Ids add up, so `ignored_vuln_advisory_ids` is set again only by an entry ignoring each id
it does. A lapsed entry matches nothing, so it neither covers another entry nor is reported. `tests/fixtures/policy-check/dead.yaml` has one entry in each section, and
`dead.txt` is its report.

## `--strict`

§6 has `--strict` exit nonzero on "any unacknowledged loosening". Schema version 1 refuses
at load a loosening entry with neither `expires` nor `permanent: true`, so no loosening can
be unacknowledged. `--strict` fails instead on entries that change nothing or never apply:
both load and neither has an effect. An entry that sets a key back is listed and does not
fail it: it has an effect, the one the user chose to allow.

| Rejected | Why |
|---|---|
| no `--strict` | a policy repository's CI could not reject a dead entry |
| `--strict` also fails on `permanent: true` | the plan asks for them to be listed. Failing them makes every internal-namespace entry a CI failure |
| `--strict` fails on an entry overridden until a date | it applies again the day after the later one lapses |

## Also changed

- `policy::today()` is the one UTC date. `report_policy` in `main.rs` checked the expiry
  ceiling against `jiff::Zoned::now().date()`, local time. The proxy, `explain` and
  `policy diff` used UTC.
- `packages::label(i)` names an entry in messages, replacing the `format!("packages[{i}]")`
  copies.
- `doctor` reads the policy and expiry ceiling variables when the policy one is set, and
  exits 2 on a ceiling that does not parse, as the proxy does. With no policy set it
  reports nothing about one: it runs on developer machines, which do not carry the
  proxy's environment.

## Not reported

- A lapsed entry, whose `expires` is before the date. It matches nothing, and the proxy
  does not warn about it either.
