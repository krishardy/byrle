# Command line: clap, default features off

- **Status:** Implemented 2026-09-13. `src/cli.rs`, the dispatch in `src/main.rs`,
  `tests/fixtures/cli/`.
- **Related:** [http-stack-axum-reqwest](http-stack-axum-reqwest.md)

## Decision

The command line is parsed by clap 4.6.6 with `default-features = false` and
`features = ["std", "derive", "help", "usage", "error-context"]`. Parsing lives in the library as
`cli::Cli`, so it is unit-tested inside the coverage floor. The proxy stays configured through
the environment; the variables are listed after the generated help (`cli::environment`).

## The hand-written parser, measured

`main.rs` matched on `std::env::args().nth(1)` and read each subcommand's arguments by hand. Run
against `examples/policy.yaml` before the change:

| Command line | Before | After |
|---|---|---|
| `policy diff a b --as-of 2026-01-01`, the spelling its usage line showed | usage error, exit 2 | parsed |
| `policy diff a b --as-of=2026-01-01 --as-of=2026-01-02` | first taken, exit 0 | `cannot be used multiple times`, exit 2 |
| `policy diff a b --bogus` | ignored, exit 0 | `unexpected argument '--bogus' found`, exit 2 |
| `explain --policy extra` | `extra` ignored | `the argument '--policy' cannot be used with '[PURL]'`, exit 2 |
| `explain --help` | `` `--help` is not a package reference ``, exit 2 | help, exit 0 |
| `--version` | `unknown command`, exit 2 | `waharoa 0.1.0`, exit 0 |
| `doctr` | `unknown command`, exit 2 | `unrecognized subcommand 'doctr'`, exit 2 |

No test exercised the dispatch. `cli::tests` now covers each row.

## Candidates

Crates each adds to waharoa's tree of 226, by `cargo tree -e normal,build` against the current
`Cargo.lock`. `syn`, `quote`, `proc-macro2` and `anstyle` are already in it.

| Candidate | Crates added | Last release | Downloads, 90 days |
|---|---|---|---|
| clap, default features | 11: `anstream`, `anstyle-parse`, `anstyle-query`, `clap`, `clap_builder`, `clap_derive`, `clap_lex`, `colorchoice`, `is_terminal_polyfill`, `strsim`, `utf8parse` | 2026-08-06 | 228,500,341 |
| **clap, default features off, derive** | **4: `clap`, `clap_builder`, `clap_derive`, `clap_lex`** | 2026-08-06 | 228,500,341 |
| clap, default features off, builder | 3 | 2026-08-06 | 228,500,341 |
| bpaf, derive | 2 | 2026-07-29 | 1,652,259 |
| bpaf | 1 | 2026-07-29 | 1,652,259 |
| argh | 3 | 2026-03-16 | 2,620,639 |
| lexopt | 1 | 2026-02-28 | 2,646,919 |
| pico-args | 1 | 2022-06-04 | 17,433,173 |
| gumdrop | not measured | 2022-03-09 | 828,182 |

The choice was between clap with default features off, lexopt and bpaf. clap was chosen by the
user over lexopt, which was recommended for its single crate: help, usage errors, `--version`
and conflict checks are generated rather than written and maintained here, for three more crates
than lexopt, all from the clap-rs project.

## Rejected

| Alternative | Why not |
|---|---|
| clap with default features | Seven more crates for colour (`anstream` and its parsers), terminal detection and typo suggestions (`strsim`) |
| lexopt | One crate, but every refusal, the help and `--version` are written by hand, which is how the defects above arose |
| bpaf | One or two crates. Single maintainer, 1.7 million downloads in 90 days against clap's 228 million |
| argh | Three crates, BSD-3-Clause, and no `--version` flag |
| pico-args, gumdrop | No release since 2022 |
| Keeping the hand-written parser | The defects above |

## Consequences

- **No wrapping and no colour.** `wrap_help` and `color` are off, so each command's summary is
  kept to one short line, and the environment section is wrapped by hand.
- **`--snapshot` was hidden until 2026-09-14.** It was parsed so `policy diff` could refuse it
  with its own reason rather than clap's `unexpected argument`. It is listed now that
  [snapshot-identity](snapshot-identity.md) keeps snapshots it can read.
- **Help is pinned by golden files.** `tests/fixtures/cli/help.txt`, `explain.txt` and
  `policy-diff.txt`, rewritten with `WAHAROA_BLESS=1`. They are rendered by a debug build and show
  `WAHAROA_DEFER_TEST`, which a release build omits.
- **Two `nosemgrep: rust.lang.security.args.args` suppressions are gone** from `main.rs`: clap
  reads argv, and nothing in `main.rs` calls `std::env::args` any more.
- **Exit codes are unchanged:** 2 for a malformed command line, 0 for help and `--version`.
