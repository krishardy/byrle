# Opengrep tried beside semgrep in `make sast`, and kept out of it

- **Number:** 0138
- **Status:** Trial 2026-11-12 to 2026-11-13, ended with opengrep removed from `make sast`, for TODO.md ad-hoc #54: `scripts/make/opengrep.sh`,
  `scripts/make/install-opengrep.sh`, `scripts/make/lib/opengrep.sh`,
  `scripts/make/lib/semgrep_scan.sh`.

## Context

Opengrep is a fork of semgrep's open-source engine, under LGPL-2.1. It reads semgrep rules
and `nosemgrep` comments. `make semgrep` requires a semgrep.dev login.

## Decision

`make sast` runs `make opengrep` after `make semgrep`. Both call `semgrep_scan` in
`scripts/make/lib/semgrep_scan.sh`, with the same packs (`p/rust`, `p/secrets`,
`p/security-audit`, `r/bash`), excludes and exceptions report. `SEMGREP_RULES` sets the
rules for both. Opengrep is not given `--metrics=off`: it has no metrics, and refuses the
flag.

Opengrep has no login. It fetches the packs from the semgrep registry as an anonymous
client.

`make install-opengrep` installs the pinned release binary, `opengrep_manylinux_x86` or
`_aarch64`, checked against its sha256. `make dev-setup` runs it where opengrep is missing,
and `make check-deps` reports a newer release.

## Measured

On `b35ccd5` plus this change, semgrep 1.185.0 anonymous against opengrep 1.33.1:

| | semgrep | opengrep |
|---|---|---|
| rules, files | 135, 559 | 135, 559 |
| findings | 11 | 12 |
| suppressed by `nosemgrep` | 18 | 18 |
| files the parser failed on | `scripts/make/lib/port.sh` | `scripts/make/lib/port.sh`, `src/startup.rs` |
| wall time, `make <engine>` | 18s | 53s |

The extra finding is `bash.lang.correctness.unquoted-expansion.unquoted-command-substitution-in-command`
at `scripts/make/commit-fixup.sh:160`, a `$(( $(...) - $(...) ))` arithmetic expansion.

`semgrep_exceptions.py` read suppressed findings from `extra.is_ignored` in a
`--disable-nosem` JSON pass. Semgrep 1.185.0 does not set that field with `--disable-nosem`,
so `make semgrep` listed none of the 18. It now reads them from the pass's SARIF
(`--sarif-output`), where both engines mark each one with `suppressions`.

## The rule set opengrep publishes

`opengrep/opengrep-rules` is a fork of semgrep-rules. Its last commit is `f1d2b56`, on
2025-01-26, and `main` is its only branch. Its licence is LGPL-2.1 with the Commons Clause.
It has no packs, so a scan names directories:

| | registry packs | `opengrep-rules` `rust/ bash/ generic/secrets/ python/` |
|---|---|---|
| rules | 135 | 609 |
| findings | 12 | 45 |
| `nosemgrep` comments matching | 18 | 0 |

Its rule IDs are the rule file's path, with `.` for `/`, plus the rule's
`id`: `<clone path>.rust.lang.security.args`. The registry's are
`rust.lang.security.args.args`, which all 19 `nosemgrep: <id>` comments in the repository
use. Its two `generic.secrets.gitleaks` findings are test fixtures: a fake PEM block at
`src/tls.rs:144` and a PGP fingerprint at `src/ecosystem/maven/signature.rs:342`.

## Result

`make sast` is `semgrep trufflehog trivy` again. With the registry's rules, opengrep found
one finding semgrep did not, a false positive. It parsed one fewer file and took 3 times as
long. Its rules still come from semgrep.dev under Semgrep's rules licence, and its own rule
set has not been committed to since 2025-01-26.

`make opengrep`, `make install-opengrep` and `semgrep_scan.sh` stay, so opengrep can replace
semgrep if semgrep's licence or login terms change. `make dev-setup` does not install it.
`make check-deps` reports a newer release than the pin.

Not measured: the rule count for a logged-in semgrep. `semgrep.sh` records 57 anonymous
against 103 logged in, from an earlier run; this trial's anonymous runs got 135.
