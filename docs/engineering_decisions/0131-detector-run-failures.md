# A detector command that exits non-zero is not run, and a rule that could not run fires `error`

- **Number:** 0131
- **Status:** Decided by the user 2026-11-04, for finding 12 of the security review (TODO.md
  ad-hoc #50). Implemented 2026-11-04: `Command::detect` in `src/analysis/detector.rs`,
  `of_detections` in `src/signal.rs`, `guarddog::WEIGHED` and `guarddog::error_rule` in
  `src/analysis/detector/guarddog.rs`.
- **Related:** [detectors](0092-detectors.md),
  [policy-schema-v1-frozen](0030-policy-schema-v1-frozen.md)

## Decision

| A command's run | Was | Is |
|---|---|---|
| exits non-zero, with JSON on stdout | stored as its result | not run: nothing stored, a WARN logged, and run again on the next decision, as output that is not JSON is |
| exits 0, and `errors` names a rule | stored, and the errors logged only | stored, and the signal `<detector>.error` fires once, its detail the rules named, comma-separated |
| GuardDog's, and `errors` names `potentially_compromised_email_domain` or `unclaimed_maintainer_email_domain` | the same | `guarddog.whois_error` fires for those two, in place of `guarddog.error` |
| exits 0, `errors` empty | stored | the same |

`<detector>.error` and `guarddog.whois_error` weigh 1 unless `signal_weights` weighs them,
as each other rule of a command does. Both are added to `signal_weights` in `version: 1`. The stored
result is not run again, so the rules that errored stay unrun for that detector version.

The audit line's signal is `guarddog: error`.

## Why

A detector's exit status was not read, so a run that failed after printing `{}` stored "no
findings" for that detector version. A rule in `errors` never ran, and its result was
stored. A semgrep failure in GuardDog's source rules, which a package's own code can cause,
then looked the same as a clean scan.

A signal keeps the 0092 rule that a failed detector fails open: at weight 1 it adds to the
risk score and refuses nothing alone.

## Rejected

| Option | Why not |
|---|---|
| a run with any error is not run (the review's proposal) | GuardDog's two WHOIS rules fail on every run without TCP port 43, so no result would be stored and GuardDog would run on every decision of every version |
| store, and run once more after a day | a rule a package makes fail fails again, and nothing reports it |

The two WHOIS rules look up maintainers' email domains on TCP port 43. A network that
blocks the port, as many allowing only 80 and 443 do, fails both on every run. Their own
signal lets a policy set `guarddog.whois_error: 0` and keep `guarddog.error` for the rules
that read the package. Added 2026-11-04, asked for by the user.

## Cost

Without port 43 or `SOCKS`, every version GuardDog scans gets `guarddog.whois_error`, +1 to
its risk score, until `signal_weights` sets `guarddog.whois_error: 0`.
