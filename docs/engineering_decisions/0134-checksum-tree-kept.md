# The checksum database's tree is kept past a restart, and a tile once its proof passes

- **Number:** 0134
- **Status:** Implemented 2026-11-05, for finding 30 of the security review:
  `go::sumdb::Client::kept` and `Proving`, `analysis::store::Trees`, and the
  `checksum_tree` table (`migrations/0033_checksum_tree.sql`).
- **Related:** [a-client-for-each-service](0133-a-client-for-each-service.md)

## Context

`go::sumdb::Client` believes a lookup only when its tree extends the largest tree it has
proved. That tree was held in memory, so after a restart the first tree the database
showed was believed whatever it was: a rolled-back or forked tree was accepted once per
process. The go command keeps its own in `$GOPATH/pkg/sumdb` for the same reason.

A full tile was kept in the tile cache as soon as it was fetched, before the inclusion and
consistency proofs that read it passed. A tile answered wrong once failed those proofs on
every later lookup, as 503, until the process restarted.

## Decision

| What | Kept where | When |
|---|---|---|
| the largest tree proved, per database key name | `checksum_tree`, through `analysis::store::Trees`, which the analyser's store implements | after a lookup proves a larger tree than the one kept; a smaller tree leaves it |
| a full tile | the client's tile cache | once both proofs of the lookup that fetched it pass |

On its first lookup a client reads the tree kept, and the database's tree must extend it,
or be extended by it, as one seen in this process must. A store that does not answer that
read fails the lookup, since a tree it kept cannot be ruled out. A store that does not
answer the write is logged at WARN, and the lookup is answered: the tree was proved.

The proxy hands its analyser's store to every registry client (`Fetch::keeping`); only Go's
uses it. Without Postgres, the store in this process keeps the tree for as long as the
process runs, as before.
