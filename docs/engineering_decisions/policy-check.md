# `waharoa policy check`

- **Status:** Implemented. `src/policy/check.rs`; the command in `src/main.rs`, and
  `startup::report_policy` for the proxy.
- **Plan reference:** §5.5, "`policy check` flags selectors that can never win" and
  "`permanent: true` ... reported separately by `policy check`"; §6, `policy check --strict`.

## Decision

`waharoa policy check <path> [--as-of YYYY-MM-DD] [--strict]` loads a policy the way the
proxy does at startup: `Policy::load`, then `packages::check` with the expiry ceiling from
the environment and the date, UTC today by default. It prints four lists, each only when
it has an entry:

| Section | An entry is listed when |
|---|---|
| changes nothing | every value it sets equals the global setting (`packages::changes_nothing`) |
| never wins | two narrower entries match every package it does, and neither expires |
| shadowed until a narrower entry lapses | the same, and one of the two expires. The line gives the last day |
| permanent | it has `permanent: true` |

| Exit | When |
|---|---|
| 0 | the policy loads, and with `--strict`, nothing changes nothing or never wins |
| 1 | load or the `packages` rules refuse it, or `--strict` and an entry changes nothing or never wins |
| 2 | the file cannot be read, or the command line is malformed |

The proxy at startup and `waharoa doctor` read the same `check::Report`. Startup warns for
each entry that changes nothing or never wins. `doctor` reports each as `WARN`, and a
refused policy as `PROBLEM`.

## Which entries can never win

Load refuses duplicate selectors, and pairs that overlap with neither containing the
other. Overlapping entries that load form chains, and the narrowest live match wins
(`decide::most_specific_match`). A wider entry still wins every package its narrower
entries miss, so it never wins only when narrower entries cover it:

- Covering a name pattern (`*`, `prefix*`, a literal) or an absent version would take
  narrower entries listing every name or version under it. That is not looked for.
- `has_install_scripts` has two values. An entry that sets neither is covered by two
  entries with its ecosystem, name and version, one `true` and one `false`.

A lapsed entry matches nothing, so it neither covers another entry nor is reported as
shadowed. `tests/fixtures/policy-check/dead.yaml` has one entry in each section, and
`dead.txt` is its report.

## `--strict`

§6 has `--strict` exit nonzero on "any unacknowledged loosening". Schema version 1 refuses
at load a loosening entry with neither `expires` nor `permanent: true`, so no loosening can
be unacknowledged. `--strict` fails instead on entries that change nothing or never win:
both load and neither has an effect.

| Rejected | Why |
|---|---|
| no `--strict` | a policy repository's CI could not reject a dead entry |
| `--strict` also fails on `permanent: true` | the plan asks for them to be listed. Failing them makes every internal-namespace entry a CI failure |
| `--strict` fails on an entry shadowed until a date | the wide entry takes effect again the day after the narrower one lapses |

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
