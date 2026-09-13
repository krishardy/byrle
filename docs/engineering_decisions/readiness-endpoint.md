# Readiness endpoint

- **Status:** Implemented. `READY_PATH` and `Proxy::readiness` in `src/proxy.rs`;
  `Intel::snapshot` returns a `LoadedSnapshot` (`src/intel/store.rs`).
- **Plan reference:** §3, cold start.
- **Related:** [intel-in-decisions](intel-in-decisions.md)

## Decision

`GET /-/waharoa/ready` answers:

| Policy | Intel store | Status | `intel` |
|---|---|---|---|
| none | any | 200 | `not_consulted` |
| set | not configured | 200 | `not_consulted` |
| set | holds a snapshot | 200 | `loaded` |
| set | holds no snapshot | 503 | `empty` |
| set | cannot answer | 503 | `unavailable` |

The rows are the ones in [intel-in-decisions](intel-in-decisions.md): the proxy is ready
exactly when a package request would not be answered with the intel 503. One function,
`Proxy::consulted_intel`, decides for both.

The 200 body reports the snapshot that decisions use:

```json
{"ready":true,"intel":"loaded","snapshot":{"digest":"sha256:...","taken_at":"2026-09-13T01:02:03Z",
 "streams":[{"stream":"osv-npm","sha256":"...","etag":"...","last_modified":null}]}}
```

The response carries `Cache-Control: no-store`, as `/-/waharoa/health` does. A store error
is logged and not served, because a database error can carry the database's address.

## No percentage

Plan §3 asked for "the percentage complete" in the 503 body and per-stream progress at the
endpoint. `waharoa refresh` is a separate process, and `PgIntel::replace_source` deletes a
source's rows, copies the new ones in and records the snapshot in one transaction. A proxy
reads the previous snapshot or the new one, never part of one, so the store has no progress
to report. Per stream, the endpoint reports what is loaded: the sha256, etag and
`last-modified` refresh recorded.

| Rejected | Why |
|---|---|
| refresh writes rows loaded and rows expected to a progress table outside its transaction | a new migration, and a refresh that crashes leaves progress that never completes |

## Also changed

`Intel::snapshot` returns the digest, `taken_at` and streams instead of the digest alone.
It is one query, `jsonb_each` over the newest `intel_snapshot.streams`. `taken_at` is
reported in UTC to the second. A stream recorded with no `sha256` is left out; refresh
writes one for every stream.

## `waharoa doctor`

`doctor` reads the endpoint after the health request answers:

| `intel` | Finding |
|---|---|
| `loaded` | ok, with the snapshot digest and `taken_at` |
| `not_consulted` | WARN: `known_malware` and `max_cvss` are not enforced |
| `empty`, `unavailable` | PROBLEM: every package request is answered 503 |
| nothing readable | WARN: a proxy older than the endpoint |

## Not built

- The 503 on a package request still gives no cause and sends no `Retry-After`.
