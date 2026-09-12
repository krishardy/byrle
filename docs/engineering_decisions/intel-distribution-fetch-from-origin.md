# Intel distribution: fetch from origin

- **Status:** Decided
- **Plan reference:** decision #6

## Decision

We host and redistribute no advisory intel. Every stream fetches from its own origin.
Storage is **Postgres, and only Postgres**. Cold start fails closed with 503. The
query-on-clean live fallback is adopted, opt-in.

### Amended 2026-09-13: SQLite dropped

As originally decided, storage was SeaORM over SQLite and Postgres. SQLite is no longer a
target. Supporting two backends bought portability nobody asked for and constrained the
refresh path, which is the one place the storage layer has to be fast: `COPY FROM STDIN`
is Postgres-only and is what loading hundreds of thousands of advisory rows wants.

Development and tests use Postgres in a container rather than an embedded backend.

**Whether SeaORM is still the right choice is open.** Its justification in the plan was
one codebase for two backends, and there is now one backend. It already served the lookup
path only, since bulk refresh bypasses it for raw sqlx. Not decided here.

## Rationale

OSV publishes per-ecosystem bundles to a public GCS bucket, GitHub Advisory is queried
under the user's own token, and OSSF Malicious Packages is a git repository. All three
self-host, so there is nothing for us to distribute, and the artifact stays a single
binary.

## Consequences

- **Tests that need a database need a container.** `make test-integration` starts
  Postgres, runs them and tears it down. Tests that do not need a database must not
  require it.
- **The repository trait stays, for a different reason.** It was backend portability,
  which is moot. It remains because the 95% unit coverage floor excludes corpus and live
  tests, so the policy engine and everything above the storage seam has to be testable
  with no database at all. Reading "one backend" and deleting the trait would put the
  policy engine behind a container.
- **Bulk refresh does not go through an ORM.** It uses raw sqlx, because ORM inserts are
  too slow for hundreds of thousands of rows. Postgres-only makes `COPY FROM STDIN`
  available here, which two-backend support ruled out.
- **Refresh must be atomic.** Build into a temp table and swap. A failed refresh must
  never leave a half-populated advisory set that under-blocks silently. Postgres has
  transactional DDL, so the swap is an ordinary transaction.
- **Multi-instance concerns are production concerns**, not optional extras for large
  deployments: every deployment is Postgres. Refresh coordination needs advisory-lock
  leader election, or a separate `waharoa refresh` run as a cron job with the proxies
  read-only, and `intel_snapshot_id` must be read from the database rather than computed
  locally.
- **Cold start returns 503, never 403.** A 403 while warming looks like a policy
  violation for a package that is fine.
- **Query-on-clean leaks the clean subset of the dependency graph**, so it is opt-in
  with its own fail-open setting, defaulting to fail-open with a warning.

Detail on all five remains in plan §3 ("Intel storage and refresh"), which is
specification rather than decision rationale.

## See also

- [nvd-role-and-stream-capabilities](nvd-role-and-stream-capabilities.md).
