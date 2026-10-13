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

**SeaORM is not used.** Its justification was one codebase for two backends, and there is
now one backend. Storage is sqlx directly; see
[storage-sqlx-postgres](storage-sqlx-postgres.md), which supersedes the ORM half of this
document.

### Amended 2026-10-13: a mirror for any stream

`BYRLE_STREAM_URLS` names a URL to fetch a stream from instead of its origin, as
`stream=url` pairs: `osv/npm=https://mirror.example/npm/all.zip`. Each stream named is one
this build fetches, once; each URL is https, or http to loopback. A stream not named is
fetched from its origin. The mirror serves what the origin does: OSV's zip, KEV's JSON,
Datadog's manifest, GitHub's GraphQL. Asked for by the user for the console's exit test,
which loads a test `MAL-` record from a mirror on loopback. We still host nothing.

## Rationale

OSV publishes per-ecosystem bundles to a public GCS bucket, GitHub Advisory is queried
under the user's own token, and OSSF Malicious Packages is a git repository. All three
self-host, so there is nothing for us to distribute, and the artifact stays a single
binary.

## Consequences

- **Tests that need a database need a real Postgres.** `make test-integration` starts
  one in a docker container, or as a local cluster from `initdb` and `pg_ctl` when docker
  does not answer, runs them and tears it down. Tests that do not need a database must not
  require it.
- **The repository trait stays, for a different reason.** It was backend portability,
  which is moot. It remains because the 100% unit coverage floor excludes corpus and live
  tests, so the policy engine and everything above the storage seam has to be testable
  with no database at all. Reading "one backend" and deleting the trait would put the
  policy engine behind a container.
- **Bulk refresh uses `COPY FROM STDIN`**, which Postgres-only makes available and
  two-backend support ruled out. There is no ORM to bypass any more.
- **Refresh must be atomic.** A failed refresh must never leave a half-populated advisory
  set that under-blocks silently. A load deletes one stream's rows and copies the new ones
  in one transaction, rather than swapping tables; see
  [osv-malware-load](osv-malware-load.md).
- **Multi-instance concerns are production concerns**, not optional extras for large
  deployments: every deployment is Postgres. Refresh coordination needs advisory-lock
  leader election, or a separate `byrle refresh` run as a cron job with the proxies
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
