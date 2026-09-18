# A PyPI index is filtered by policy, with or without intel

- **Status:** Implemented 2026-09-18. `proxy::handle`, `ecosystem::pypi::rewrite`,
  `ecosystem::UncoveredMetadata`.
- **Related:** [quarantine-filter-metadata](quarantine-filter-metadata.md),
  [uncovered-ecosystem-fails-closed](uncovered-ecosystem-fails-closed.md),
  [pypi-simple-index](pypi-simple-index.md), [adapter-interface](adapter-interface.md)

## Decision

A simple index goes through the same path as a packument: `publish_times_for`,
`intel_for` and `policy_refused_versions`. `pypi::rewrite::rewrite_index` then removes every
file of a refused version and removes the version from the PEP 700 `versions` key. pip
resolves to a version the policy allows, as npm clients do.

When the intel snapshot has no stream for PyPI, the index is filtered by the checks that
need no intel and served. The file request answers 503, as before. npm's packument answers
503 in the same case. Each registry row says which with `uncovered_metadata`.

## Before

`proxy::handle` returned from the `SimpleIndex` arm after repointing file URLs. The index
reached neither intel nor the policy. Under `install_scripts: block`, pip saw a version
that offers only an sdist, picked it, and was refused 403 at the file. The same case on npm
resolves to an allowed version.

## Why a version and not a file

The policy decides on the version's record. `has_install_scripts` on that record is true
only when every file of the version is an sdist (`Project::only_sdist`). Every other check
reads the same value for every file of a version: publish time, intel, the package's name.
A version the record refuses is therefore one whose every file the artifact request refuses.
Removing the version removes nothing the file request would serve.

A version that offers a wheel and an sdist is kept whole. `pip install --no-binary :all:`
still asks for the sdist and is refused 403 at the file. `smoke-python` step 5 holds that.

## Why an uncovered index is served

pip does not report an index 503. Measured 2026-09-18 against a stub index, with pip 26.1.1
and uv 0.12.5:

| Stub answers | pip | uv |
|---|---|---|
| index 503 | 6 GETs in 7 s, then `No matching distribution found for demo (from versions: none)` | `Request failed after 3 retries in 5.3s ... 503 Service Unavailable` |
| index 200, file 503 | `Max retries exceeded ... (Caused by ResponseError('too many 503 error responses'))` | not measured |
| index 404 | `No matching distribution found for demo (from versions: none)` | `demo was not found in the package registry` |

An index 503 reads to a pip user as a package that does not exist. A file 503 names the
status. Serving the index moves no decision: every file is still refused.

## Rejected

| Alternative | Why not |
|---|---|
| Keep the index unfiltered | pip picks a version the policy refuses and the install fails where npm's succeeds |
| 503 the index when intel is uncovered, as npm does | pip reports it as `No matching distribution found` |
| Filter per file, keeping a version's wheel and removing its sdist | Every check but `install_scripts` has one answer per version, and a version's record answers `install_scripts` for the file a resolver takes. Removing an sdist would also change what `--no-binary` users are told from 403 to "no matching distribution" |
