# The watcher analyses new versions of served packages before a client asks

- **Status:** Implemented 2026-09-29. `Proxy::watch` in `src/proxy.rs`,
  `RecordStore::packages` and `RecordStore::refresh` in `src/store.rs`, started by
  `byrle daemon` every `BYRLE_WATCH_INTERVAL` seconds.
- **Related:** [artifact-spool](artifact-spool.md), [default-ceilings](default-ceilings.md),
  [warm](warm.md)

## Decision

Every novel artifact is deferred with a 503 until its analysis finishes, and some clients
give up first ([deferral-status-codes](deferral-status-codes.md)). The watcher analyses a
new version before anyone asks for it.

Each pass reads the metadata of every package the record store holds, which is the packages
this proxy has served. Decided with the user: not the registries' feeds of every publish,
which are thousands of versions an hour, most never installed here.

| Step | What it does |
|---|---|
| read | one metadata request per held package, through a metadata slot, so it never decodes more at once than client traffic may |
| new versions | the versions the fresh document lists and the held copy did not. The first pass does not analyse a package's history |
| refresh | the held copy is replaced, keeping the package's place in the eviction order. The watcher's reads never keep a package held; only client traffic does |
| analyse | each new version's preferred file, the one a resolver takes first, goes through the same path as a client's request: the upstream it would be fetched from, its publish times, and `analysed`, which starts the job |

A version starts nothing when its file is on an origin the proxy does not serve, when it
publishes no strong digest, or when its bytes are already analysed. The watcher is off when
there is no analyser, and when `BYRLE_WATCH_INTERVAL` is 0.

## Cost

One metadata request per held package per interval, 900 seconds by default, plus one
artifact download for each new version. A proxy holding 500 packages makes about one
request every 2 seconds. A pass runs one package at a time, and a pass that outlasts the
interval delays the next rather than overlapping it.

## Consequences

- The held packages are the in-memory record store, so after a restart the watcher has
  nothing to watch until client traffic arrives.
- With the in-process analysis store, analyses the watcher starts can evict ones for
  artifacts that were served. Postgres keeps them all.
- Under a cooldown, the watcher analyses versions nobody can install for `cooldown_days`.

## Tests

`the_watcher_analyses_a_new_version_before_a_client_asks` covers a new version started and
analysed, one already held, bytes already analysed, an origin not served, no digest, and no
analyser. `a_refresh_returns_new_versions_without_counting_as_a_use` covers the eviction
order. Mutation-tested: counting every listed version as new, and not skipping an origin
the proxy does not serve, each fail.
