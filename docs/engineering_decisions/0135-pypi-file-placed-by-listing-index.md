# A PyPI file whose name fits several projects belongs to the index that lists it

- **Number:** 0135
- **Status:** Implemented 2026-11-08, for finding 32 of the security review:
  `pypi::paths::version_in` and `filename_projects`, `Fetch::listing`, `proxy::placed`,
  `BYRLE_MAX_INDEXES_PER_FILE`.
- **Related:** [pypi-simple-index](0046-pypi-simple-index.md)

## Context

An sdist's filename is `<name>-<version>` plus an archive extension, and before PEP 625
both parts could hold a `-`. `foo-1.0-1.tar.gz` is `foo` at `1.0-1` (PEP 440's
`1.0.post1`) or `foo-1-0` at `1`. The proxy split at the last `-` everywhere:

| Where | What the last `-` did |
|---|---|
| reading foo's index | recorded the file as version `1`, so an advisory for `1.0.post1` did not match it |
| a pinned fetch by a hash path, `/packages/ab/cd/<hash>/foo-1.0-1.tar.gz` | keyed it `pkg:pypi/foo-1-0@1`, asked `/simple/foo-1-0/`, and answered 502 |

pip reads a file in a known project's index by the first `-` before which the name
normalises to that project (`_find_name_version_sep`), and skips a file that fits no
`-`. A hash path names no project.

PyPI never gives one filename to two files. Warehouse's `File.filename` is unique, the
`file_registry` table keeps every filename uploaded, deleted ones included, and an upload
whose filename does not normalise to the project's name is refused (`forklift/legacy.py`,
`main` on 2026-11-08). So the one index that lists a filename says which project it is.

## Decision

| Request | Project the file is read for |
|---|---|
| an index, JSON or HTML | the project the request path names, else the document's `name`, else the page URL's last segment. An sdist of another project is skipped, as pip skips it |
| `/simple/<project>/<file>` and `/packages/source/<l>/<project>/<file>` | the path's project, when the file fits it |
| a hash path, a filename with one reading | the filename's, as before |
| a hash path, a filename with several readings | the first candidate whose index lists the file |

The candidates are tried from the last `-` to the first, the key the path gave first. The
indexes the proxy holds are read first, then the others are asked one at a time, at most
`BYRLE_MAX_INDEXES_PER_FILE` (default 4). An index that answers 404, or lists other files,
is passed over. Any other failure ends the search. The index that lists the file is kept,
as a client's would be. Only a request that is decided is placed: a GET, and a HEAD where
the row decides one.

When no index lists the file, the request goes on with the last `-`'s key, and is answered
as before.

## Measured

PyPI's 1,000 most-downloaded projects (hugovk top-pypi-packages, 2026-11-01), simple
indexes fetched 2026-11-08:

| | Count |
|---|---|
| sdists | 91,068 |
| with more than one `-` in the stem | 12,470 |
| where pip's split and the last `-` differ | 126, in 36 projects |
| of those, a version pip installs | 38, the newest uploaded 2021-09-25 |
| an sdist of another project | 0 |

`celery-3.1.26-1.tar.gz`, `cffi-1.2.0-1.tar.gz`, `docutils-0.15.1-post1.tar.gz` and 12
`selenium-2.0-dev-NNNN.tar.gz` are among the 38. Most of the 12,470 are dashed names such
as `google-cloud-storage-2.0.tar.gz`, which the last `-` reads, so they cost the one index
fetch they cost before.

## Rejected

| Option | Why not |
|---|---|
| Split a hash path's file at its first `-` | wrong for every dashed project name |
| Read `Name:` from the sdist's `PKG-INFO` | the bytes arrive after the decision |
| Ask every candidate at once | a request for a crafted name would fan out to every `-` |

## Costs

A file on a hash path whose name fits several projects, and whose index the proxy does not
hold, costs up to `BYRLE_MAX_INDEXES_PER_FILE` index requests. pip and uv fetch the index
before its files, so a held index answers the common case with no request. When no index
lists the file, the last `-`'s index is asked again by the lookup that follows.
