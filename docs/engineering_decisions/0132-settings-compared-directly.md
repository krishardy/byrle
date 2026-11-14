# `policy diff` and `policy check` compare the top-level settings directly

- **Number:** 0132
- **Status:** Implemented 2026-11-04, for finding 13 of the security review (TODO.md ad-hoc
  #50): `settings::compared` in `src/policy/settings.rs`, `Report::settings` and
  `Report::exit_bits` in `src/policy/diff.rs`, `Report::looser` in `src/policy/check.rs`.
  The approach below was chosen while implementing it.
- **Related:** [policy-check](0034-policy-check.md),
  [policy-diff-dates-and-exit-bits](0038-policy-diff-dates-and-exit-bits.md),
  [every-refusal-a-signal](0116-every-refusal-a-signal.md)

## Decision

`settings::compared(from, to)` lists each setting `to` gives otherwise than `from`:

| Setting | Looser when |
|---|---|
| `cooldown_days`, `provenance_window_days`, `provenance_half_life` | lower |
| `max_cvss`, `risk_threshold` | higher |
| `install_scripts`, `kev`, `deprecated`, `yanked`, `provenance` | lower on allow, quarantine, block |
| `signal_weights.<key>`, for each key either policy sets | its weight is a smaller share of `risk_threshold` |

A weight is compared as `weight / risk_threshold`. A key neither policy sets is not listed,
so raising `risk_threshold` alone lists one line, not one per check weighing the threshold
by default.

| Command | Uses it as |
|---|---|
| `policy diff` | a `N settings moved` section before the packages. A looser setting sets exit bit 1 and a stricter one bit 2, whatever the packages did. The summary adds `settings: N loosened, M tightened` |
| `policy check` | a `looser than the default` section: each setting looser than in `version: 1` with nothing else. It sets no exit code, and `--strict` does not fail on it |

## Why

`policy diff` decided only the packages the audit log and the lockfiles list.
`signal_weights: { known_malware: 0 }`, over a log with no malware, moved no package and
printed no `LOOSER` line, though the threat model says a lower weight on `known_malware` is
reported as a loosening. `policy check` read no `signal_weights`, `risk_threshold` or
`max_cvss`.

## Not compared directly

`denials`, `packages` and `advisory_scores` are per package, and stay compared over the
listed packages. A detector's signals are not decided again per package (`decide_under` does
not call `with_signals`); a change to their weights is listed by the settings section.
