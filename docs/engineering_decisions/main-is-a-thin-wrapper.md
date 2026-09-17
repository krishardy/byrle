# `main.rs` holds `main` and the runners, and nothing else

- **Status:** Implemented 2026-09-18. `src/main.rs`, `src/startup.rs`, `src/intel/fetch.rs`,
  `doctor::run`, `explain::run`, `policy::diff::run`, `intel::refresh::report`.
- **Related:** [cli-parser-clap](cli-parser-clap.md),
  [environment-variables](environment-variables.md),
  [stream-descriptor-table](stream-descriptor-table.md)

## Decision

`main.rs` parses the command line, dispatches, prints what a command returned and chooses
the exit code. Everything a command decides is in the library.

| In `main.rs` | In the library |
|---|---|
| `main`, the six runners | `startup::proxy`, `doctor::run`, `explain::run`, `diff::run`, `fetch::read_streams` |
| `tracing_subscriber` setup, `TcpListener`, `axum::serve` | the `Proxy` the environment describes |
| printing and exit codes | what to print, as a `String` and a list of lines |
| the Postgres transaction a refresh runs | the requests, the parses and the report |

It went from 1,292 lines to 344.

## Why

`scripts/make/coverage.sh` excludes `main.rs`: it is startup wiring, and a unit test of it
would need a process. Everything that moved into `main.rs` over time therefore left the
coverage floor and the mutation runs, and `make mutants` said so. Before this refactor 18
of 20 surviving mutants in one run were in `main.rs`: the byte ceilings on a stream's
bundle, the retry guard, the `report.unread` counters.

The same code in the library is reachable by a test. `test_support::scripted` serves a
status, a body, a body whose `Content-Length` lies, a chunked body with no length, or a
closed connection, and `env::testing::with` builds an environment from `Var` constants.
`explain::run` and `diff::run` are tested against a local registry; `fetch::bundle` against
each of those answers.

## What a command returns

Not a printed side effect. Each returns what to print, so a test reads it:

| Command | Type |
|---|---|
| `explain` | `Answered { notes, answer, code }` |
| `policy diff` | `diff::Run { notes, report, summary, code }` |
| `doctor` | `Checked { report, code }` |
| `refresh` | `fetch::Read`, then `refresh::report(...) -> String` |

`notes` and `summary` are stderr lines without the command's prefix, which `main` adds.
Ordering is preserved: notes, then the report, then the summary.

## What stayed in the binary

The tokio runtime, the logging subscriber, the listener and `axum::serve`. Exit codes: a
variable that does not parse is 2, as [environment-variables](environment-variables.md)
requires, and something the operator asked for that is not there refuses to start.
`startup::StartupError` carries which of the two it is.

The Postgres transaction in `run_refresh`, because `PgIntel` needs a database and
`coverage.sh` excludes the one file that speaks to it.

## What this cost

`Clients::from_env`, `postgres::from_env` and `startup::proxy` are generic over the
environment's lookup, so a test can pass its own. `doctor::run` is not: `CacheLocation`
holds a function pointer over the process environment, and a generic one cannot be a
function pointer. `doctor`'s pieces are tested individually instead.
