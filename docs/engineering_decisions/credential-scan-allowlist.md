# Trufflehog findings are allowed by exact value

- **Status:** Implemented 2026-10-12. `.trufflehog-allow`,
  `scripts/make/lib/trufflehog_allowed.py`, `scripts/make/trufflehog.sh`.
- **Related:** [ci-gates](ci-gates.md)

## Decision

`make trufflehog` fails on every finding whose raw value `.trufflehog-allow` does not list
whole. Both passes, the working tree and git history, write JSON, and the script judges
them together. It also lists allowlist lines that matched nothing.

## Why

On 2026-10-12 every finding was the URI detector, unverified, on test URLs such as
`https://user:secret@example.test` in `src/doctor.rs`, `src/http.rs` and four other files.
They are in git history from `5f7ec22` (2026-09-21), and `trufflehog git` has no path
exclusion that a change to the working tree could use.

| Option | What it would stop finding |
|---|---|
| exact values, chosen | only the listed strings |
| `--exclude-detectors=URI` | every credential in a URL, such as a database URL with a password |
| `--results=verified,unknown` | every result trufflehog cannot verify, for every detector |
| `trufflehog:ignore` comments | the comment rule allows only `// nosemgrep:`, and history keeps the old lines |

## Tested

29 findings, all allowed, on two runs. An untracked file holding a Postgres URL with a
user and password failed the run with the Postgres detector. The URL is not quoted here,
because this file is scanned too. trufflehog reported 26 to 29 findings across runs, and
`http://:s3cret@egress.example`, in `src/http.rs`'s tests, on some runs only.
