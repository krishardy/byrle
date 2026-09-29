# The audit log

- **Status:** Implemented. `src/audit.rs`, written where `WAHAROA_AUDIT_LOG` points.
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
| `action` | on a `resolution` line, the strongest action taken against any version |
| `checks` | strongest first on a `pinned` line; sorted on a `resolution` line, which is the union over the versions removed |
| `unenforceable` | the checks that could not be answered, so an unenforced `cooldown_days` does not read as passed |
| `intel_snapshot` | absent when no store was asked, so a decision without intel does not read as one against an empty snapshot |
| `answered` | pinned only: `served`, `refused`, `deferred` or `upstream-mismatch`, since a deferral or a digest mismatch answers a request the policy would have served |
| `inputs` | pinned only: what the engine read, for [reproducible-verdicts](reproducible-verdicts.md). `as_of` is the date decided on, not read from `at`. `build` is `0.1.0` until releases are versioned, so a replay reports a difference rather than failing |

Every field has a default, so a line an older build wrote without a field still reads. Empty
lists are left out rather than written as `[]`.

## Writing and reading

Writing never fails an install. A full disk or an unwritable path is warned about once, not
per line, because it is one problem. Reading skips a line that does not parse: a torn last
write is the ordinary case after a crash.
