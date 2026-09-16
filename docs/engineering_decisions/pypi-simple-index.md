# PyPI's simple index is file-keyed, and a packument is not

- **Status:** Implemented, parse only. `src/pypi.rs`. Nothing fetches it yet.
- **Related:** [stage-structure](stage-structure.md),
  [purl-identity-rules](purl-identity-rules.md),
  [enforcement-tiers](enforcement-tiers.md),
  [packument-body-inspection](packument-body-inspection.md)

## Decision

`src/pypi.rs` reads PyPI's simple index as PEP 691 JSON and shares nothing with
`src/npm.rs`. Stage 3's goal says the adapter interface is an **output** of this stage,
extracted from two working implementations. An interface written before PyPI works would be
npm's shape with PyPI bent into it, which is the thing the stage exists to prevent.
`src/npm.rs` is 3,422 lines and is not touched.

## What the index really is, measured 2026-09-16

`Accept: application/vnd.pypi.simple.v1+json` against `pypi.org/simple/requests/` returns
`api-version: 1.4`, 123,104 bytes. Without that header the same URL serves HTML.

| | npm | PyPI |
|---|---|---|
| document | version-keyed, one entry per version | **file-keyed**: 244 files for 160 versions |
| publish time | only in the full packument, 1.7x to 3.6x larger | `upload-time` per file, in the document a resolver already fetches |
| artifact host | `registry.npmjs.org` serves both | `files.pythonhosted.org`, not the index host |
| install script | `hasInstallScript` on the version | nothing; an sdist runs `setup.py` and a wheel does not |
| name | used as written | PEP 503 normalised, and the index 301s to it |
| per-version document | the packument is the only one | none under `/simple/`; PEP 658 gives per-**file** metadata at `<url>.metadata` |

The first row is the finding. `NormalizedPackument` is version-keyed and a PyPI project is
not: several files carry one version and they are not interchangeable, because a wheel and
an sdist for the same version differ in whether installing runs code.

The second row is the one that saves work. Stage 2 spent an item on `npm::publish_times`,
fetching the full packument for its `time` map because the abbreviated one omits it. PyPI
writes `upload-time` on every file of the document pip already asks for, so `cooldown_days`
is answerable on the cheap path for this ecosystem.

## Name normalisation

PEP 503 lowercases and collapses every run of `-`, `_` and `.` to a single `-`. The index
enforces it with a redirect, measured:

| Asked | Answer |
|---|---|
| `Flask` | 301 to `/simple/flask/` |
| `zope.interface` | 301 to `/simple/zope-interface/` |
| `ruamel_yaml` | 301 to `/simple/ruamel-yaml/` |
| `ruamel.yaml` | 301 to `/simple/ruamel-yaml/` |
| `flask` | 200 |

`normalise` does it before the request, so one project is one identity rather than one per
spelling. A name that normalises to nothing is refused rather than turned into a path.

## Files a resolver would never fetch

A filename that names no version is skipped, and the document is still read. Over nine
projects, 12,164 files: 510 skipped, every one `.egg` (265), `.exe` (237) or `.src.rpm` (8).
pip installs none of those formats, so nothing a resolver would fetch is among them.

| Project | Files | Versions | Skipped | Wheels | Sdists | Yanked |
|---|---|---|---|---|---|---|
| requests | 244 | 160 | 1 | 83 | 160 | 4 |
| flask | 110 | 64 | 0 | 46 | 64 | 0 |
| django | 803 | 435 | 0 | 383 | 420 | 4 |
| numpy | 4,232 | 137 | 34 | 4,043 | 155 | 72 |
| urllib3 | 192 | 105 | 0 | 87 | 105 | 8 |
| setuptools | 1,530 | 626 | 79 | 580 | 871 | 20 |
| zope-interface | 2,298 | 89 | 396 | 1,815 | 87 | 203 |
| ruamel-yaml | 2,466 | 273 | 0 | 2,193 | 273 | 4 |
| pip | 289 | 159 | 0 | 130 | 159 | 6 |

Refusing a document because one 2006 egg sits in it would refuse `zope-interface` outright.
`examples/pypi_index.rs` is the run.

## Yanked is not a boolean

PEP 592 writes `yanked` as `false` or as a string giving the reason, so it is read as "not
`false`". `requests-2.32.0-py3-none-any.whl` carries
`"Yanked due to conflicts with CVE-2024-35195 mitigation"`, which a boolean read would take
as absent. The fixture keeps that entry for the case.

## Not decided here

The version is read from the filename, PEP 427 for a wheel and the last `-` for an sdist.
That is what the index gives: a file entry carries no version field. Whether a resolved
range picks a file or a version is the range-resolution item, and it is deliberately open.
