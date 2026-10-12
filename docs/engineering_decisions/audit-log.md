# The audit log

- **Status:** Implemented. `src/audit.rs`, written where `BYRLE_AUDIT_LOG` points.
- **Related:** [reproducible-verdicts](reproducible-verdicts.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [policy-diff-dates-and-exit-bits](policy-diff-dates-and-exit-bits.md)

## Decision

One JSON line per policy decision, apart from the tracing log. Tracing output is diagnostic
and its shape may change. The audit log is a record an operator keeps and `policy diff` and
`audit verify` parse, so it has a schema and nothing else interleaved.

The unit is a request, not a version. typescript's packument has 3,823 versions, and a line
per refused version would put thousands of lines in the log for one request. A `resolution`
line names the versions it removed and the checks that removed them; `explain` gives the
reasoning per version. A version offered and not removed is not in the log.

| Field | Written as |
|---|---|
| `at` | RFC 3339 in UTC, so two proxies' logs can be concatenated |
| `path` | `resolution` (a filtered document, the client picks another version) or `pinned` (one version asked for by name) |
| `action` | on a `resolution` line, the strongest action taken against any version. Absent on a pinned line answered before anything was decided |
| `checks` | strongest first on a `pinned` line; sorted on a `resolution` line, which is the union over the versions removed |
| `unenforceable` | the checks that could not be answered, so an unenforced `cooldown_days` does not read as passed |
| `intel_snapshot` | absent when no store was asked, so a decision without intel does not read as one against an empty snapshot |
| `answered` | what the request got, below. On a pinned line always; on a resolution line in observe mode, and when the request failed. A deferral, a digest mismatch, an upstream failure and the proxy's own refusals answer requests the policy would have served |
| `signals` | pinned only: what the [metadata heuristics](metadata-heuristics.md) and the [source comparison](source-diff.md) reported. No verdict reads it |
| `risk_score` | pinned only, with any signal: the sum of the policy's `signal_weights` for the kinds present |
| `inputs` | pinned only: what the engine read, for [reproducible-verdicts](reproducible-verdicts.md). `as_of` is the date decided on, not read from `at`. `build` is `0.1.0` until releases are versioned, so a replay reports a difference rather than failing |
| `account` | the account whose token the request carried. Absent when tokens are not required |
| `upstream_status` | with `upstream-status`: the status the upstream answered |

| `answered` | The request got | Decided |
|---|---|---|
| `served` | the artifact | yes |
| `refused` | a refusal by the policy | yes |
| `unservable` | a refusal: its origin is one the proxy does not serve | yes |
| `no-strong-digest` | a refusal: its metadata publishes no strong digest | yes |
| `deferred` | 503 while it is analysed | yes |
| `upstream-mismatch` | 502: the upstream's bytes did not match their digest | yes |
| `not-listed` | a refusal: its metadata names neither its version nor its file | no |
| `no-metadata` | 502: the registry gave no metadata for it | no |
| `intel-store` | 503: the intel store errored or holds no snapshot | no |
| `no-stream-for-ecosystem` | 503: no stream in the snapshot covers the ecosystem | no |
| `upstream-unreachable` | 502: the upstream sent no answer, or a metadata body stopped part way | on an artifact, yes; on a metadata request, no |
| `upstream-status` | the upstream's status other than 2xx or 304, forwarded | on an artifact, yes; on a metadata request, no |
| `cut-short` | a served artifact's body ended early: its bytes did not match their digest, or the upstream stopped part way. Written after the `served` line for the same request | no |

A line with nothing decided has no `action` and no `inputs`. `audit verify` and `policy diff`
skip it.

An artifact's decision to serve is written once the upstream answers, so `served` means the
upstream answered 2xx or 304. A metadata request gets a line of its own only when the
policy removed a version, or when it failed: `intel-store`, `no-stream-for-ecosystem`,
`upstream-unreachable` or `upstream-status`, with no `version`. A request for neither
a package's metadata nor one of its artifacts, such as npm's `/-/v1/search`, gets none.

A 401 and a 503 `account-store` are not written. Until 2026-09-29 `unservable` and `no-strong-digest` were written as `refused`, and
the two undecided answers wrote no line.

Every field has a default, so a line an older build wrote without a field still reads. Empty
lists are left out rather than written as `[]`. An `answered` value a build does not know
makes the line unreadable to it: `audit verify` on that build reports it as not
replayable.

## Writing and reading

Writing never fails an install. A full disk or an unwritable path is warned about once, not
per line, because it is one problem. Reading skips a line that does not parse: a torn last
write is the ordinary case after a crash.
