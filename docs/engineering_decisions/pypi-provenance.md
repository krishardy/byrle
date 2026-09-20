# PyPI provenance: the index says where the bundle is

- **Status:** Implemented 2026-09-21, read only. `wire::File::provenance`,
  `html`'s `data-provenance`, `record::Provenance::attestation_url`.
- **Related:** [adapter-interface](adapter-interface.md),
  [pep-503-html-index](pep-503-html-index.md)

## What PyPI publishes

PEP 740. Each file in the index carries `provenance`: the URL of its attestation bundle, or
`null`. The HTML form writes the same thing as `data-provenance`. Both are in the document a
resolver already fetches, so reading it costs no request.

The bundle itself is a separate fetch. Its shape, read from `attrs` 26.1.0 on 2026-09-21:

```
{ "version": 1, "attestation_bundles": [ {
    "publisher": {"kind": "GitHub", "repository": "python-attrs/attrs",
                  "workflow": "pypi-package.yml", "environment": "release-pypi"},
    "attestations": [ {"version": 1, "verification_material": ..., "envelope": ...} ] } ] }
```

Its statement's predicate type is `https://docs.pypi.org/attestations/publish/v1`.

## Adoption, counted 2026-09-21

| Project | Files | With provenance |
|---|---|---|
| attrs | 72 | 12 |
| requests | 244 | 12 |
| sigstore | 132 | 38 |
| pydantic | 2,021 | 455 |
| cryptography | 3,683 | 1,150 |
| ruff | 7,134 | 0 |
| uv | 5,701 | 0 |

Where a project publishes attestations at all, its newest files carry them, so this is a
recent practice rather than a fading one. Two large projects publish none.

## Decision

The index's `provenance` URL is read into `record::Provenance::attestation_url`, the field
npm's `dist.attestations.url` already fills. Nothing is fetched and nothing is verified:
presence is the package's claim, and checking it is Stage 4's provenance item, which needs
sigstore.

The proxy counts them per document, `provenance_files_listed=12` for `attrs` on a real run,
so an operator can see which of their dependencies publish attestations before any check
exists to require them.

The record's value is the preferred file's, the file a resolver would take, because
`Provenance` describes a version. A pinned fetch of another file of the same version reads
that same field rather than its own.

## What is not read yet

| Field | Where it is | Why not |
|---|---|---|
| the publisher identity: repository, workflow, environment | inside the bundle | a fetch per file, and Stage 4 fetches it to verify rather than to report |
| the predicate type | inside the bundle's statement | the same |
| PyPI's own `_npmUser.trustedPublisher` equivalent | not in the index | PyPI puts the publisher in the bundle, so there is nothing cheaper to read |
