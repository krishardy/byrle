# Every log value is a field with an OpenTelemetry name, and the daemon can write OpenTelemetry log records

- **Status:** Implemented 2026-09-28. `src/logging.rs`, `env::LOG_FORMAT`.
- **Related:** [environment-variables](environment-variables.md)

## Decision

- `BYRLE_LOG_FORMAT=json` writes one JSON object per line in OpenTelemetry's log record
  shape: `timestamp`, `severity_text`, `severity_number`, `body`, and `attributes` holding
  every field. `text`, the default, is the format the daemon wrote before, colour codes
  included.
- A field is named by OpenTelemetry's semantic conventions where one fits, and under
  `byrle.` otherwise, as the conventions advise for an application's own attributes.
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
| `deferred (BYRLE_DEFER_TEST)` | `deferred by the defer test`, with `variable` |
| `upstream traffic goes through a forward proxy: https via …` | `upstream traffic goes through a forward proxy`, with `https`, `http` and `direct` |
| `point npm at it with:  <command>` | `point a client at the proxy`, with `client` and `command` |

The other 14 are startup and snapshot-gap warnings, each with its value moved to a field.

## Field names

Where a semantic convention fits:

| Before | After | Uses |
|---|---|---|
| `path`, a request target | `url.path`, and `url.query` when there is a query | 60 |
| `path`, a spool file | `file.path` | 2 |
| `error` | `error.message` | 28 |
| `url` | `url.full` | 15 |
| `client`, the user agent | `user_agent.original` | 13 |
| `method` | `http.request.method` | 10 |
| `status`, an HTTP status | `http.response.status_code` | 9 |
| `bytes` of a proxied answer | `http.response.body.size` | 2 |
| `accept_encoding`, `etag`, `retry_after` | `http.request.header.accept-encoding`, `http.response.header.etag`, `http.response.header.retry-after` | 3 |
| `listen` | `server.address` and `server.port` | 1 |

A request target is split by `http::url_path` and `http::url_query`. `url.query` is an
`Option`, and tracing records nothing for `None`, so a line for a request with no query has
no `url.query` at all.

Every other field is under `byrle.`, grouped by what it describes: `byrle.package.*`,
`byrle.artifact.*`, `byrle.analysis.*`, `byrle.attestation.*`, `byrle.policy.*`,
`byrle.deferral.*`, `byrle.intel.*`, `byrle.config.*` and a few others. 323 fields in
114 log calls were renamed. The scripts and tests that match log text use the full names.

`severity_number` is the first number of each level's OpenTelemetry range: TRACE 1, DEBUG
5, INFO 9, WARN 13, ERROR 17.
