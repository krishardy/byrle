# Storage: sqlx over Postgres, no ORM

- **Status:** Implemented, lookup path only. `src/intel/store.rs` (trait),
  `src/intel/postgres.rs`, `migrations/0001_intel.sql`, `tests/intel_postgres.rs`. Refresh
  is not built.
- **Plan reference:** decision #14
- **Version:** sqlx 0.8. See [sqlx-0-8-and-rsa-advisory](sqlx-0-8-and-rsa-advisory.md)
- **Supersedes:** the ORM half of [intel-distribution-fetch-from-origin](intel-distribution-fetch-from-origin.md)

## Decision

Storage is **sqlx against Postgres, with no ORM**. SeaORM is not used.

Queries are written as SQL and checked at compile time with `sqlx::query_as!` against the
real schema. Migrations are plain `.sql` files under `sqlx::migrate!`.

## Rationale

SeaORM's justification in the plan was one sentence: "Async-native, one codebase for both
backends." SQLite was dropped, so there is one backend and the justification is gone.

What remained for it to do was small. Bulk refresh already bypassed the ORM for raw sqlx,
because ORM inserts are too slow for hundreds of thousands of advisory rows, so SeaORM
served the lookup path only: a fixed handful of queries keyed on ecosystem, name and
version.

Three things follow.

**It removes a dependency rather than swapping one.** SeaORM is built on sqlx. Dropping it
leaves the crate that was already going to be in the tree for the refresh path, and leaves
one query layer instead of two.

**`sqlx::query_as!` checks SQL against the live schema at compile time.** A renamed column
or a changed type is a compile error, not a runtime one. That is stronger than what SeaORM
offers, not weaker, and it matches how the rest of this codebase works: `Enrichment` cannot
become a `Finding` because the types say so, and the strictness lattice is proved rather
than tested.

**Postgres-only features stop being hidden.** `COPY FROM STDIN BINARY` via `PgCopyIn` is
what loading 221,548 malware records wants, and an ORM's portability layer is built to
abstract exactly that away.

## Consequences

- **The macros need a database at compile time.** This is the real cost, and the only one.
  Mitigated by `cargo sqlx prepare`, which writes an offline cache to `.sqlx/` that is
  checked into the repository, so a contributor can build with no database at all. CI runs
  `cargo sqlx prepare --check` so the cache cannot drift from the migrations.
- **`.sqlx/` is generated, and must be regenerated whenever a query or migration changes.**
  A `make sqlx-prepare` target wraps it. A stale cache is a CI failure rather than a
  runtime surprise.
- **Migrations are SQL, not a Rust DSL.** Postgres has transactional DDL, so a failed
  migration rolls back whole.
- **The repository trait stays**, unchanged by this. It was never about portability once
  SQLite was dropped: the 95% unit coverage floor excludes corpus and live tests, so the
  policy engine and everything above the storage seam has to be testable with no database.
- **No entity relations or lazy loading.** The data is advisories, aliases and packages,
  queried by exact key. Dynamic query building, if `explain` or `doctor` ever needs it,
  uses sqlx's `QueryBuilder`.

## Alternatives considered

**Keep SeaORM.** Rejected: its stated reason no longer exists, and it would mean two query
layers over one backend, with the slow path already written in the other one.

**sqlx without the checked macros** (`query_as` rather than `query_as!`). This avoids the
compile-time database entirely. Rejected: it trades the main reason to prefer sqlx here for
a workflow convenience that `.sqlx/` already solves.

**Diesel.** Not evaluated in depth. Synchronous by default, and the async story is less
settled than sqlx's; the codebase is async throughout.
