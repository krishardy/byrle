# The adapter interface is a descriptor table and four shared modules

Stage 3's goal was to extract the adapter interface from two working implementations
rather than design one up front. npm was built first, PyPI second, and what they turned
out to share is smaller and more concrete than a trait.

## Decision

No `trait Adapter`. Four modules hold what both ecosystems answer the same way. Of those,
`ecosystem` holds a descriptor table: one `Registry` per ecosystem, with a field for each
question that is a plain function of a path or a header, or a declaration. Three questions
that are neither stay as `match` expressions on `Ecosystem`, listed below with the reason
each is still one.

Adding an ecosystem is a new row plus a compile error at each remaining `match` until it
is answered.

## What is shared

| Module | Answers | Built from |
|---|---|---|
| `route` | what a request path refers to: `Metadata`, `Artifact`, `Other`, and which ecosystem answers it | npm's `classify_path`, then PyPI's |
| `origin` | which hosts the proxy fronts, what happens to an artifact published elsewhere, and how to point a document's artifact URLs at the proxy | npm's `ReachableOrigins`, `OriginPolicy` and `rewrite_artifact_origins`, all three of which were npm's only by where they sat |
| `record` | `PackageMetadata` and `PackageRecord`: what a normaliser produces and the store holds | npm's `NormalizedPackument`, renamed once PyPI produced one |
| `ecosystem` | which registry answers a path, which ecosystems are served, and the per-ecosystem answers that are a function of a path or a header, or a declaration | the `match` arms that had accumulated in `route`, `proxy` and `origin` |

`RecordStore` holds both, keyed by `PackageKey`, which carries the ecosystem. The policy
engine reads `PackageRecord` and has never seen a packument or an index: nothing under
`src/policy/` changed in this stage.

## What each ecosystem directory holds

`src/ecosystem/npm/` and `src/ecosystem/pypi/` have the same files, so the same question is
in the same place for both:

| File | npm | PyPI |
|---|---|---|
| `paths.rs` | request paths, which packument a response is, and `upstream_url` | request paths, PEP 503 names, PEP 427 filenames, and `upstream_url` |
| `wire.rs` | the packument's serde targets | the index's serde targets, plus `Project`, the cleaned form |
| `normalize.rs` | packument to `PackageMetadata` | `Project` to `PackageMetadata` |
| `transport.rs` | `Client`, fetching a packument; `metadata` for the proxy's own fetch | `Client`, fetching an index; `metadata` for the proxy's own fetch |
| `inspect.rs` | `read_packument`: normalising a forwarded packument and keeping its records | `read_index`: the same for an index |
| `rewrite.rs` | `rewrite_packument`: removing refused versions from a packument and pointing the rest at the proxy | `rewrite_index`: the same for an index. See [pypi-index-filtering](pypi-index-filtering.md) |
| `error.rs` | `NormalizeError`, `FetchError` | `PypiError`, `FetchError` |

npm has two more files, and PyPI has no counterpart and no empty file standing in for
either:

| File | npm | Why PyPI has none |
|---|---|---|
| `clients.rs` | npm, pnpm, yarn and bun as `doctor` checks them | pip and uv are not checked yet |
| `lockfile.rs` | reading `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and `bun.lock` | `requirements.txt`, `uv.lock` and `poetry.lock` are not read yet, and `lockfile::read` refuses them by name |

`wire.rs` is the one file whose contents differ in kind. npm's holds serde targets only,
because a packument is already version-keyed. PyPI's also holds `Project`, because a simple
index is file-keyed and `PackageMetadata` is not: `requests` lists 244 files for 160
versions, and which file stands for a version is a question npm never asks.

`PackageMetadata::unserved_origins` and `bypassing_origins` were in npm's module and use
nothing of npm's. They are now in `src/origin.rs`. Their tests came with them and build
their input with npm's normaliser, which is a test dependency and not a production one.

## What the table answers

| Field | Question | npm | PyPI |
|---|---|---|---|
| `prefixes` | which paths does this registry claim | none: it answers what no other row claimed | `/simple/` and `/packages/` |
| `always_reachable` | which origins may the proxy fetch from whatever the operator configured | `registry.npmjs.org` | `pypi.org/simple` and `files.pythonhosted.org` |
| `classify_path` | what does this path refer to | `npm::classify_path` | `pypi::classify_path` |
| `read_media_type` | which document is this response | `npm::detail_from_content_type` | `pypi::SIMPLE_JSON` |
| `publish_times` | where a version's publish time comes from | `FullPackument`, fetched separately | `Record`, from each file's `upload-time` |
| `other_is_probe` | whether an unclassified request is a resolver probe, logged at DEBUG | no | yes: PEP 658 `.metadata` requests |
| `streams` | which package-keyed advisory streams cover it | `osv/npm`, `datadog/npm`, `github/npm` | none yet |
| `lockfiles` | which lockfile names `policy diff` reads, and with which reader | `npm::lockfile::LOCKFILES` | none yet |
| `unread_lockfiles` | which lockfile names are refused with a specific reason | `bun.lockb` | none |
| `clients` | which package managers `waharoa doctor` checks, how to ask each for its registry and cache, and how to fix each | npm, pnpm, yarn, bun | none yet |

npm's empty `prefixes` is the root fallback, and `ecosystem::ROOT` names it. Before the
table, `route::classify` was `if pypi::serves(path) { PyPI } else { Npm }`: a third
ecosystem's prefix would have lost to npm without a compile error. `serving` now walks the
table and falls back to `ROOT` only when no row claims the path.

Three tests hold the table's shape: every `Ecosystem::EXPRESSIBLE` variant has exactly one
row, exactly one row claims no prefix, and no prefix is claimed twice. The first is what
makes `ecosystem::of` safe to call on the request path.

`TABLE` is also the served set. `intel::served` reads it, so every row is an ecosystem
`LoadedSnapshot::gaps` checks, and a row with no `streams` is reported at startup and by
`waharoa doctor` as served with no stream providing `match` or `malware`. This replaced
`Ecosystem::ALL`, a hand-written list that held npm alone after the proxy served PyPI.

### Publish times

`ecosystem::Clients::publish_times` fetches only when the row says `FullPackument`, and
answers `Ok(None)` without a request when it says `Record`. The proxy asks it only when the
policy uses a cooldown. npm's abbreviated packument has no `time` map, so its times come
from a second request for the full one. A PyPI record already carries `published_at`,
which `facts::published_date` reads before any fetched times.

### Fetching without a document

`ecosystem::Clients` holds npm's and PyPI's clients, and `metadata` and `publish_times`
choose between them by the key's ecosystem. The proxy uses it for an artifact whose
metadata it has not seen. `waharoa explain` and `waharoa policy diff` use it for every
package they judge, so `explain pkg:pypi/requests@2.32.3` asks PyPI. Before, both commands
built an `npm::Client` whatever the purl said.

Before the field, `publish_times_for` called `npm::Client::publish_times` for every key.
Measured with `cooldown_days: 3650`, `pip install idna` logged
`purl=pkg:pypi/idna versions=1`: npm's `idna@0.0.1`. `FullPackument` is fetched with npm's
client, so `only_npm_reads_publish_times_from_a_full_packument` holds that no other row
declares it.

### Streams

A package-keyed stream's grant is `Scope::Listed`, which replaced `Scope::Only(ecosystem)`.
`capabilities_of` applies it to the rows whose `streams` list it.
`Scope::Served`, KEV's, still applies to every row. Two tests hold the two tables together:
every listed stream is in `intel::stream::ALL`, and a stream is listed by one row exactly
when a grant of its is `Listed`.

`intel::stream::ALL` stays hand-written. The refresh loads it in order, and a stream that
does not load leaves the others loading.

## What still matches on `Ecosystem`, and why

| Question | Where | Why not a field |
|---|---|---|
| where does this request go upstream | `proxy::upstream_url` | picks `Proxy`'s per-ecosystem upstream field; each arm is one call to `<ecosystem>::upstream_url` |
| what is fetched without a document | `ecosystem::Clients::metadata` | picks the ecosystem's client; each arm is one call to `Client::metadata`, which is `async` |
| how is that document read | `proxy::handle`'s `match document` | the arms need different things: PyPI's calls `pypi::read_index` and returns, npm's calls `npm::read_packument` and goes on to publish times, intel and `npm::rewrite_packument` |

All three are `match` expressions, not tests with a fall-through, so a third ecosystem is a
compile error at each. Two of them were not, and a third ecosystem would have been given
PyPI's two hosts by `upstream_url` and would have panicked in `handle` on an
`unreachable!`.

## Why not a trait

A missing table row and an enum match both fail to compile. A new `impl Adapter` says
nothing about the sites it missed, and the questions in the two tables above are exactly
the ones a new ecosystem must not be allowed to skip.

The repo's own precedent is `intel::stream::Stream`, a descriptor table of function
pointers for per-source behaviour, which is the same shape reached for the same reason.

The transport is the clearest case. `npm::Client::packument(key, detail)` and
`pypi::Client::project(name)` take different arguments because the documents differ:
`DocumentDetail` distinguishes npm's abbreviated document from its full one and has no
PyPI meaning, because a simple index withholds nothing it has. A trait would have to take
the union or the intersection, and both are wrong.

## Names outside the ecosystem directories

`record::DocumentDetail` was `PackumentDetail`, npm's word for a document PyPI also
produces. A PyPI record is `Full` and `may_be_incomplete()` is false. The record field is
`detail`, not `source`, which also names an advisory's source.

Code that serves both ecosystems says "metadata" where it said "packument": `Proxy`'s
`max_metadata_bytes` and `metadata_slots`, and the log lines on the shared request path,
such as `artifact requested, no metadata seen for it`. "Packument" stays where only npm is
meant: `DocumentKind::Packument`, the npm arm of `handle`, and `publish_times_for`'s
full-packument fetch.

`WAHAROA_MAX_METADATA_BYTES`, `WAHAROA_MAX_CONCURRENT_METADATA` and the health JSON's
`packages_held` were `..._PACKUMENT_BYTES`, `..._CONCURRENT_PACKUMENTS` and
`packuments_held` until 2026-09-19. No build had been deployed, so no configuration or reader
from another build held the old names.

## The resolver looking is not the client installing

A backtracking resolver fetches far more metadata than it installs. Measured 2026-09-16,
`pip install boto3 'botocore<1.34' s3transfer` through the proxy:

| | Count |
|---|---|
| project indexes read | 7 |
| versions held after them | 4,885 |
| PEP 658 `<file>.metadata` probes | 679 |
| artifacts fetched | 7 |
| packages installed | 8 |

Nothing treats a probe as install intent, and the log is the proof: 679 probes produced 7
record lookups and 7 policy decisions, one of each per artifact actually fetched. A probe
classifies as `RequestTarget::Other`, so it is forwarded to `pypi::FILES` with its path and
nothing else happens to it.

Two things did read as intent and no longer do:

- `versions_with_install_scripts` and `sdist_only_versions` are
  `install_script_versions_listed` and `sdist_only_versions_listed`. Both always counted
  the document; the comments said so, which meant the names were wrong.
- 679 INFO `proxied` lines buried the 7 an operator needs. A probe logs at DEBUG. The same
  install went from 731 log lines to 52, with every index and artifact line kept.

npm keeps INFO for its own unclassified traffic: `/-/v1/search` and `/-/whoami` are a
handful per install, and `scripts/make/retry-matrix.sh` counts those lines.

## What this did not settle

Range resolution. Nothing resolves a range in either ecosystem, so `pypi::normalize`
returns every version the index lists: `botocore` alone is 2,516 of the 4,885 above. That
is a separate piece of work, and `versions_listed` is the number it would reduce.
