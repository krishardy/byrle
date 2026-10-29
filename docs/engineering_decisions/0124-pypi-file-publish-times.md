# A PyPI file is dated by its own upload, and a version by its newest file

- **Number:** 0124
- **Status:** Decided by the user 2026-10-29, for finding 3 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-10-29: `record::Artifact::published_at`,
  `PackageRecord::narrowed_to` in `src/record.rs`, `published` and `newest` in
  `src/ecosystem/pypi/normalize.rs`.
- **Related:** [pypi-simple-index](0046-pypi-simple-index.md),
  [pypi-index-filtering](0050-pypi-index-filtering.md)

## Decision

| Date | Was | Is |
|---|---|---|
| a PyPI version's | the preferred file's `upload-time`: its first wheel's | its newest file's; none when any file has none |
| a pinned fetch's | the version's | the requested file's `upload-time`, else the version's |

`record::Artifact` carries `published_at`. Only PyPI sets it.

## Why

A file can be uploaded to a release long after the release. With the old rule, a
hijacked account uploads `pkg-1.0-py3-none-manylinux_2_17_x86_64.whl` to a 2024 release
whose `pkg-1.0-py3-none-any.whl` is listed first. pip on Linux prefers the new file.
Both the index and the pinned fetch dated it 2024, so it passed any cooldown.

A version with an undated file is undated, so the fallbacks date it: a HEAD's
`Last-Modified`. A file the index does not date may be the newest.

## Cost

[pypi-index-filtering](0050-pypi-index-filtering.md) removes a version with all its files.
A wheel added to an old release now removes that release from the index until the wheel
is `cooldown_days` old. pip resolves to another version meanwhile; a pin to that version
fails. Filtering by file instead would keep the older files listed.
