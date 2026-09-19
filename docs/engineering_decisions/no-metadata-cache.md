# Metadata is fetched from upstream on every request

- **Status:** Implemented 2026-09-19. `proxy::handle`, `publish_times_for`.
- **Related:** [adapter-interface](adapter-interface.md),
  [verified-artifact-cache](verified-artifact-cache.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md)

## Decision

The proxy answers every metadata request from a fresh upstream response, filtered by policy.
It keeps no copy of a metadata document to answer a later request from.

Under a policy with `cooldown_days`, an npm metadata request asks upstream for the full
packument (`Accept: application/json`) in place of the client's `Accept`. The full packument
has the `time` map, so every record carries `published_at`, and the cooldown is decided from
the same response the client receives. One upstream request per client request.

Without a cooldown, the client's `Accept` goes upstream unchanged.

## What was removed

`Proxy::publish_times` kept each package's publish times once fetched, up to 1,024 packages,
and cleared them all at the ceiling. A version published after the fetch had no time in it.
`can_answer_cooldown` returned `Missing` for that version, `enforce::unenforceable` dropped
`cooldown_days`, and the version was offered. The newest version of a package is the one a
cooldown exists to hold back.

Held by `a_version_published_after_an_earlier_request_is_held_back_by_the_cooldown`. The stub
registry publishes 2.0.0 between two client requests. On `6ca8e7d` the test fails with
`published today, inside the cooldown`.

## What is kept

| Store | Holds | Why it is not a cache of upstream state |
|---|---|---|
| `RecordStore` | the records of the last metadata document per package | Read only by the artifact request that follows, for the digest, whether installing runs scripts and the publish time. None of these changes after a version is published. It never answers a metadata request |
| `verified` | digests of artifacts already checked | An artifact's bytes are fetched from upstream every time; see [verified-artifact-cache](verified-artifact-cache.md) |

A version the registry withdraws is refused by upstream on the artifact request, because the
artifact is always fetched. A yanked PyPI file stays in its index with `yanked` set, and
policy does not read it: TODO.

## Record store size, measured

`examples/record_memory.rs` counts the heap bytes a normalised document holds after its
input is dropped.

| Document | Heap per record |
|---|---|
| npm `typescript` | 959 bytes |
| npm `lodash` | 906 bytes |
| PyPI `botocore` | 1,285 bytes |
| PyPI `boto3` | 1,397 bytes |
| PyPI `requests` | 1,115 bytes |
| PyPI `idna` | 1,153 bytes |

`DEFAULT_MAX_RECORDS` is 50,000, so the store is 45 to 70 MB at its budget.

## Cost

The full packument is larger than the abbreviated one, measured on eight packages: lodash
3.6x, express 2.4x, eslint 1.7x, debug 2.6x, ms 3.1x, @babel/traverse 1.9x, react 2.4x,
typescript 1.8x (8.7 MB to 15.7 MB). Before, a cooldown policy fetched both documents for a
package's first request.

## Rejected

| Option | Why not |
|---|---|
| Cache documents with a TTL, in memory or Postgres | A version published inside the TTL is not seen, and a cooldown or advisory decision is made on a stale document |
| Keep the publish-time cache and refetch when a version has no time | Two upstream requests where one does |
| Fetch the full packument on every npm request, cooldown or not | Up to 3.6x the bytes for a fact no check reads |
