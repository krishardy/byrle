# The adapter interface is three shared modules and four exhaustive matches

Stage 3's goal was to extract the adapter interface from two working implementations
rather than design one up front. npm was built first, PyPI second, and what they turned
out to share is smaller and more concrete than a trait.

## Decision

No `trait Adapter`. Three modules hold what both ecosystems answer the same way, and four
`match` expressions hold what each answers differently. Adding an ecosystem is a compile
error at each of the four until it is answered.

## What is shared

| Module | Answers | Built from |
|---|---|---|
| `route` | what a request path refers to: `Metadata`, `Artifact`, `Other`, and which ecosystem answers it | npm's `classify_path`, then PyPI's |
| `origin` | which hosts the proxy fronts, what happens to an artifact published elsewhere, and how to point a document's artifact URLs at the proxy | npm's `ReachableOrigins`, `OriginPolicy` and `rewrite_artifact_origins`, all three of which were npm's only by where they sat |
| `record` | `PackageMetadata` and `PackageRecord`: what a normaliser produces and the store holds | npm's `NormalizedPackument`, renamed once PyPI produced one |

`RecordStore` holds both, keyed by `PackageKey`, which carries the ecosystem. The policy
engine reads `PackageRecord` and has never seen a packument or an index: nothing under
`src/policy/` changed in this stage.

## What is per-ecosystem, and where

| Question | Where | npm | PyPI |
|---|---|---|---|
| where does this request go upstream | `proxy::upstream_url` | the configured registry, path appended | the configured index with the proxy's `/simple` prefix removed, or `pypi::FILES` for a file |
| which document is this response | `proxy::document_from_content_type` | `npm::detail_from_content_type` | `pypi::SIMPLE_JSON` |
| how is that document read | `proxy::handle`'s `match document` | normalise, filter refused versions, rewrite | `read_index`: normalise, store, rewrite |
| what does the proxy fetch on its own behalf | `proxy::fetch_and_store` | the abbreviated packument | the simple index |

Each is a `match`, not a test with a fall-through. Two of them were not, and a third
ecosystem would have been given PyPI's two hosts by `upstream_url` and would have panicked
in `handle` on an `unreachable!`.

## Why not a trait

An enum match fails to compile at every site that must change. A new `impl Adapter` says
nothing about the sites it missed, and the four questions above are exactly the ones a new
ecosystem must not be allowed to skip.

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
