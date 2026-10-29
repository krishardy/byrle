# A PyPI file is dated by its own upload, and refused alone for it

- **Number:** 0124
- **Status:** Decided by the user 2026-10-29, for finding 3 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-10-29: `record::Artifact::published_at`,
  `PackageRecord::narrowed_to` in `src/record.rs`, `published` and `oldest` in
  `src/ecosystem/pypi/normalize.rs`, `policy_refused_versions` in `src/proxy.rs`,
  `rewrite_index` in `src/ecosystem/pypi/rewrite.rs`.
- **Related:** [pypi-simple-index](0046-pypi-simple-index.md),
  [pypi-index-filtering](0050-pypi-index-filtering.md)

## Decision

| What | Was | Is |
|---|---|---|
| a PyPI version's date | the preferred file's `upload-time`: its first wheel's | its oldest file's; none when any file has none |
| a pinned fetch's date | the version's | the requested file's `upload-time`, else the version's |
| the index | a version the policy refuses is removed with all its files | the same, and in a version it serves, a file the policy refuses under its own `upload-time` is removed alone |

`record::Artifact` carries `published_at`. Only PyPI sets it. A file is decided alone as
the version's record with the file's `upload-time` in place of the version's, so only a
check that reads the date can refuse it.

## Why

A file can be uploaded to a release long after the release. With the old rule, a
hijacked account uploads `pkg-1.0-py3-none-manylinux_2_17_x86_64.whl` to a 2024 release
whose `pkg-1.0-py3-none-any.whl` is listed first. pip on Linux prefers the new file.
Both the index and the pinned fetch dated it 2024, so it passed any cooldown.

Removing the whole release instead, by dating a version by its newest file, hides the
release's older files until the new one is `cooldown_days` old. A pin to that release
fails meanwhile. Removing the file alone leaves pip the older files of the same release.

A version with an undated file is undated, so the fallbacks date it: a HEAD's
`Last-Modified`. A file the index does not date may be the newest.

## Cost

A file refused alone is not written to the audit log's resolution event, which names
versions. Its pinned fetch, if a client asks for it, is refused and audited.
