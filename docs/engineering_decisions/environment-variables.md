# Environment variables: one module

- **Status:** Implemented 2026-09-13. `src/env.rs`.
- **Related:** [cli-parser-clap](cli-parser-clap.md)

## Decision

Every environment variable waharoa's Rust code reads has its name, default, help text and
parsing in `src/env.rs`, and nowhere else. Other modules use its `Var` constants, as values
and inside messages, and read values through `env::process()`.

| Question | Decided |
|---|---|
| Which mentions count | Every one: reads, log and panic messages, `doctor` advice, `--help`, doc comments |
| A value that does not parse | Refused: `waharoa: WAHAROA_MAX_RECORDS: \`5O000\` is not a whole number`, exit 2 |
| Which variables | The binary's 20 (`RUST_LOG` and the debug-only `WAHAROA_DEFER_TEST` included), the four read by tests, and `HOME` and `BUN_INSTALL_CACHE_DIR` |
| Where defaults live | `src/env.rs`. `store`, `verified`, `proxy`, `npm`, `refusal` and `policy::packages` import them |

Shell scripts keep their own copies of the names they set. They cannot import Rust.

## Held by

`a_variable_name_appears_only_in_this_module` reads every `.rs` file under `src/`, `tests/`
and `examples/`. It fails on any variable name in `env::ALL`, or any `WAHAROA_` prefix, outside
`src/env.rs`, and on a `WAHAROA_` name inside `src/env.rs` that is not in `ALL`.

`--help` is rendered from the same constants the code reads, so
`tests/fixtures/cli/help.txt` is the check that a documented default is the real one. Before,
the help text wrote `(50,000)` and `(32 MiB)` by hand beside the constants.

## What changed in behaviour

| Before | After |
|---|---|
| `WAHAROA_MAX_PACKUMENT_BYTES`, `_MAX_RECORDS`, `_MAX_VERIFIED`, `_MAX_CONCURRENT_PACKUMENTS` and `_EXPIRY_CEILING_DAYS` fell back to the default on a value that did not parse | refused, exit 2 |
| `WAHAROA_CA_BUNDLE_EXCLUSIVE` was on only for `1`; `WAHAROA_REWRITE_ARTIFACTS` and `WAHAROA_REFUSE_UNSERVABLE` were off only for `0`. Anything else was silently the default | each accepts `0` or `1`, and refuses anything else |
| `WAHAROA_LISTEN=` and `WAHAROA_UPSTREAM=` were used as the empty string | an empty value is unset, for every variable |
| `RUST_LOG` that did not parse fell back to `waharoa=info` | refused, exit 2 |
| `RUST_LOG` was read by tracing and not listed in `--help` | listed, default `waharoa=info` |
| `WAHAROA_REFUSAL_STATUS` and `WAHAROA_DEFER_TEST` panicked on a bad value | exit 2 with the same reason |

`WAHAROA_CA_BUNDLE_EXCLUSIVE` is read only when `WAHAROA_CA_BUNDLE` is set, as before, so a bad
value is refused only then.

The log line `deferred (WAHAROA_DEFER_TEST)`, which `scripts/make/retry-matrix.sh` counts, is
unchanged: it is formatted from `env::DEFER_TEST`.

## Rejected

| Alternative | Why not |
|---|---|
| Only the reads go through the module | Names in advice and log text would stay as literals, and a rename would leave them stale |
| Keep silent fallback | An operator who set `WAHAROA_MAX_RECORDS=5O000` runs with 50,000 and nothing says so |
| Defaults stay in their modules, referenced from here | Each value defined once, but the item asked for them in the central module |
| A config struct parsed once at startup | Every command would fail on a bad proxy-only variable. `waharoa refresh` reads one variable and should not refuse over `WAHAROA_MAX_RECORDS` |
| Thousands separators in `--help` (`50,000`), by hand or with `num-format`, `thousands` or `icu_decimal` | Rust's `format!` has no grouping. `num-format` and `thousands` have had no release since 2022 and 2019; `icu_decimal` brings ICU4X locale data for one help line. Defaults print as `50000` |
| `npm::DEFAULT_REGISTRY` moves too | It is npm's registry, which the origin rules in `npm` name whether or not it is the upstream. `env::DEFAULT_UPSTREAM` is defined as it |
