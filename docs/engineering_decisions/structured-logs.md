# Every log value is a field, and the daemon can write JSON Lines

- **Status:** Implemented 2026-09-28. `src/logging.rs`, `env::LOG_FORMAT`.
- **Related:** [environment-variables](environment-variables.md)

## Decision

- `WAHAROA_LOG_FORMAT=json` writes one JSON object per line: `timestamp`, `level`,
  `message`, and each field as a key. `text`, the default, is the format the daemon wrote
  before, colour codes included.
- Every log message is a fixed string. A value goes in a field, so a search for a message
  finds every occurrence of that event, whatever its values. An environment variable a
  line is about is in the `variable` field.

Measured over `src/` on 2026-09-28, before the change: 19 of 114 log calls with a message
put a value into it, 11 of them in `startup.rs`. After: none.

## Messages that changed

The scripts that match log text were updated with them.

| Before | After |
|---|---|
| `not served: <why>` | `not served`, with `why` |
| `UNINSPECTED: <reason>` from `report_uninspected` | `UNINSPECTED`, with `reason` |
| `deferred (WAHAROA_DEFER_TEST)` | `deferred by the defer test`, with `variable` |
| `upstream traffic goes through a forward proxy: https via …` | `upstream traffic goes through a forward proxy`, with `https`, `http` and `direct` |
| `point npm at it with:  <command>` | `point a client at the proxy`, with `client` and `command` |

The other 14 are startup and snapshot-gap warnings, each with its value moved to a field.
