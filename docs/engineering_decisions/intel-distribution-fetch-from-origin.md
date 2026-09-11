# Intel distribution: fetch from origin

- **Status:** Decided
- **Plan reference:** decision #6

## Decision

We host and redistribute no advisory intel. Every stream fetches from its own origin.
Storage is SeaORM over SQLite and Postgres. Cold start fails closed with 503. The
query-on-clean live fallback is adopted, opt-in.

## Rationale

OSV publishes per-ecosystem bundles to a public GCS bucket, GitHub Advisory is queried
under the user's own token, and OSSF Malicious Packages is a git repository. All three
self-host, so there is nothing for us to distribute, and the artifact stays a single
binary.

## Consequences

- **Bulk refresh bypasses the ORM.** SeaORM serves the lookup path; the refresh path
  uses raw sqlx, because ORM inserts are too slow for hundreds of thousands of rows.
- **Refresh must be atomic.** Build into a temp table and swap. A failed refresh must
  never leave a half-populated advisory set that under-blocks silently.
- **Postgres implies multi-instance**, which brings refresh coordination (advisory-lock
  leader election, or a separate `waharoa refresh` run as a cron job with the proxies
  read-only) and means `intel_snapshot_id` must be read from the database rather than
  computed locally.
- **Cold start returns 503, never 403.** A 403 while warming looks like a policy
  violation for a package that is fine.
- **Query-on-clean leaks the clean subset of the dependency graph**, so it is opt-in
  with its own fail-open setting, defaulting to fail-open with a warning.

Detail on all five remains in plan §3 ("Intel storage and refresh"), which is
specification rather than decision rationale.

## See also

- [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md).
