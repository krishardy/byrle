# The adapter interface is a descriptor table and four shared modules

Stage 3's goal was to extract the adapter interface from two working implementations
rather than design one up front. npm was built first, PyPI second, and what they turned
out to share is smaller and more concrete than a trait.

## Decision

No `trait Adapter`. Four modules hold what both ecosystems answer the same way. Of those,
`ecosystem` holds a descriptor table: one `Registry` per ecosystem, with a field for each
question that is a plain function of a path or a header. Four questions that are not stay
as `match` expressions on `Ecosystem`, listed below with the reason each is still one.

Adding an ecosystem is a new row plus a compile error at each remaining `match` until it
is answered.

## What is shared

| Module | Answers | Built from |
|---|---|---|
| `route` | what a request path refers to: `Metadata`, `Artifact`, `Other`, and which ecosystem answers it | npm's `classify_path`, then PyPI's |
| `origin` | which hosts the proxy fronts, what happens to an artifact published elsewhere, and how to point a document's artifact URLs at the proxy | npm's `ReachableOrigins`, `OriginPolicy` and `rewrite_artifact_origins`, all three of which were npm's only by where they sat |
| `record` | `PackageMetadata` and `PackageRecord`: what a normaliser produces and the store holds | npm's `NormalizedPackument`, renamed once PyPI produced one |
| `ecosystem` | which registry answers a path, and the per-ecosystem answers that are a function of a path or a header | the `match` arms that had accumulated in `route`, `proxy` and `origin` |

`RecordStore` holds both, keyed by `PackageKey`, which carries the ecosystem. The policy
engine reads `PackageRecord` and has never seen a packument or an index: nothing under
`src/policy/` changed in this stage.

## What each ecosystem directory holds

`src/ecosystem/npm/` and `src/ecosystem/pypi/` have the same files, so the same question is
in the same place for both:

| File | npm | PyPI |
|---|---|---|
| `paths.rs` | request paths, and which packument a response is | request paths, PEP 503 names, PEP 427 filenames |
| `wire.rs` | the packument's serde targets | the index's serde targets, plus `Project`, the cleaned form |
| `normalize.rs` | packument to `PackageMetadata` | `Project` to `PackageMetadata` |
| `transport.rs` | `Client`, fetching a packument | `Client`, fetching an index |
| `error.rs` | `NormalizeError`, `FetchError` | `PypiError`, `FetchError` |

npm has a seventh, `rewrite.rs`: removing refused versions from a packument and pointing
the rest at the proxy. PyPI has no counterpart, and no empty file standing in for one.
`proxy::handle` returns before any filtering for a simple index, because filtering one is
range resolution rather than a refusal a client can act on.

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

npm's empty `prefixes` is the root fallback, and `ecosystem::ROOT` names it. Before the
table, `route::classify` was `if pypi::serves(path) { PyPI } else { Npm }`: a third
ecosystem's prefix would have lost to npm without a compile error. `serving` now walks the
table and falls back to `ROOT` only when no row claims the path.

Three tests hold the table's shape: every `Ecosystem::EXPRESSIBLE` variant has exactly one
row, exactly one row claims no prefix, and no prefix is claimed twice. The first is what
makes `ecosystem::of` safe to call on the request path.

## What still matches on `Ecosystem`, and why

| Question | Where | Why not a field |
|---|---|---|
| where does this request go upstream | `proxy::upstream_url` | reads `Proxy`'s per-ecosystem upstream fields |
| what does the proxy fetch on its own behalf | `proxy::fetch_and_store` | `async`, and reads `Proxy`'s clients |
| how is that document read | `proxy::handle`'s `match document` | npm's arm is written inline in `handle`, not as a function |
| when was each version published | `proxy::publish_times_for` | does not match at all: it asks npm for every ecosystem |

The first three are `match` expressions, not tests with a fall-through, so a third
ecosystem is a compile error at each. Two of them were not, and a third ecosystem would
have been given PyPI's two hosts by `upstream_url` and would have panicked in `handle` on
an `unreachable!`.

The fourth is a defect, recorded in TODO.md. `publish_times_for` calls
`proxy.registry.publish_times(key)` for every key, so a PyPI package's publish times are
read from npm. Confirmed live: `purl=pkg:pypi/idna versions=1`, which is npm's
`idna@0.0.1`. Moving it into the table is what fixes it, and the table is what makes the
omission visible.

## Why not a trait

A missing table row and an enum match both fail to compile. A new `impl Adapter` says
nothing about the sites it missed, and the questions in the two tables above are exactly
the ones a new ecosystem must not be allowed to skip.

The repo's own precedent is `intel::stream::Stream`, a descriptor table of function
pointers for per-source behaviour, which is the same shape reached for the same reason.

The transport is the clearest case. `npm::Client::packument(key, detail)` and
`pypi::Client::project(name)` take different arguments because the documents differ:
`PackumentDetail` distinguishes npm's abbreviated document from its full one and has no
PyPI meaning, because a simple index withholds nothing it has. A trait would have to take
the union or the intersection, and both are wrong.

## What npm's vocabulary still spells

`PackumentDetail::Abbreviated`/`Full` is npm's word for a document PyPI also produces, 88
uses. A PyPI record is `Full` and `may_be_incomplete()` is false, which is correct and
badly named. Renaming it is open.

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
