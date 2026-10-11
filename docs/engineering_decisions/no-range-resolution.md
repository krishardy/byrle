# byrle resolves no version ranges

- **Status:** Decided 2026-09-20. Stage 3, where the item was moved so the answer would be
  designed against two ecosystems rather than npm alone.
- **Related:** [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [adapter-interface](adapter-interface.md),
  [policy-version-ranges](policy-version-ranges.md)

## Decision

Nothing in byrle turns a range or a tag into a version. The client's resolver does that,
against the document this proxy filtered, and the proxy decides about versions and files
that are named to it.

## What asks for a version, and what names one already

| Caller | What it is given | Needs resolving |
|---|---|---|
| The metadata request | a document with every version | no: each record is decided, and refused ones are removed |
| The artifact request | a filename and a version | no: that is the version being installed |
| `byrle explain <purl>` | a purl with `@version` | no |
| `byrle policy diff` | lockfile entries and audit log versions | no: both are exact. An npm lockfile entry with `"version": "latest"` has no `resolved` URL and is dropped by the reader |
| `denials` and `match.version` | a VERS range | no: every version in the document is tested against the range ([policy-version-ranges](policy-version-ranges.md)) |

## Why resolving would be wrong, not merely unnecessary

Decision #4 filters on resolution and refuses on a pinned fetch, because substituting a
version breaks the integrity hash a lockfile records. A resolver in the proxy is that
substitution: it would pick a version the client did not ask for.

`dist-tags` follows from the same rule. A tag naming a refused version is dropped from the
rewritten packument rather than repointed at the newest surviving version, so the client's
resolver reports "no matching version" rather than installing something nobody chose. The
tag is kept as the string the registry published: the lodash fixture tags `latest` as
`4.18.1` while its `versions` map carries only `4.17.21`, so a tag can name a version the
document does not have.

## The count that was said to wait on it

`versions_with_install_scripts` in the packument log counted every version in the document,
not the one being installed, and the note said it could not answer for the installed version
until a range resolved to one. It can: the artifact request names a file, and its line
carries that file's own answer.

```
INFO artifact requested, digest known path=/packages/ef/01/26/x-3.0.tar.gz
     claimed_purl=pkg:pypi/x@3.0 has_install_scripts=true
INFO artifact requested, digest known path=/packages/ef/01/25/x-3.0-py3-none-any.whl
     claimed_purl=pkg:pypi/x@3.0 has_install_scripts=false
```

Held by `an_artifact_request_logs_the_answer_for_the_file_it_names`. The document's count is
`install_script_versions_listed`, which is what it counts; PyPI's equivalent was renamed with
the adapter interface and npm's was missed.

## When to revisit

A control that has to know what a client would resolve to, rather than what it did resolve
to. `byrle policy diff` over a manifest of ranges rather than a lockfile would be one, and
it would need a resolver per ecosystem, matching each client's own algorithm.
