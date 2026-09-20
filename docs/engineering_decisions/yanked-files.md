# A yanked file is refused, and the policy can allow it

- **Status:** Implemented 2026-09-20. `Artifact::yanked`, `PackageRecord::yanked`,
  `Check::Yanked`, `Rule::Yanked`, `Policy::yanked`.
- **Related:** [policy-schema-v1-frozen](policy-schema-v1-frozen.md),
  [policy-tier-resolution](policy-tier-resolution.md),
  [pypi-simple-index](pypi-simple-index.md)

## Decision

`yanked: block` is the default. A version whose every file is yanked is removed from the
index, and a pinned fetch of a yanked file answers 403. `yanked: allow` turns the check
off, and a `packages` entry can set it for one package.

npm has no yank, so the check reports not-applicable there, the way `install_scripts` does
for Go.

## What PyPI publishes

PEP 592. Each file in the PEP 691 index carries `yanked`, which is `false`, `true`, or a
string giving the reason. The PEP 503 HTML index writes the same thing as `data-yanked`.
Read from pypi.org on 2026-09-20, `requests` lists 244 files and 4 are yanked:

```json
{
 "filename": "requests-2.32.0-py3-none-any.whl",
 "hashes": {"sha256": "f2c3881dddb70d056c5bd7600a4fae312b2a300e39be6a118d30b90bd27262b5"},
 "size": 63695,
 "upload-time": "2024-05-20T16:08:19.530618Z",
 "yanked": "Yanked due to conflicts with CVE-2024-35195 mitigation"
}
```

A yanked file stays in the index and stays downloadable: that URL answers 200 with 63,695
bytes. pip skips a yanked file unless the requirement pins that version, which is what the
403 meets.

## Version and file

Both fields are `Option<String>`: `None` is not yanked, and `Some` carries the reason the
publisher gave, empty when the index said only `true`.

| Level | Yanked when | Read by |
|---|---|---|
| `Artifact::yanked` | that file's `yanked` is a reason or `true` | the pinned fetch, through `PackageRecord::narrowed_to` |
| `PackageRecord::yanked` | every file of the version is yanked, and it carries the first file's reason | the index filter |

A version with one file left is not yanked. PEP 592 is about which file a resolver takes,
and a version that still offers a wheel is a version to resolve to.

## Reading an absent key as a yank

`wire::Entry::yanked` is a `serde_json::Value` with `#[serde(default)]`, which is
`Value::Null` when the key is absent, and the test was `!matches!(value, Bool(false))`.
Null is not `Bool(false)`, so every file of every project parsed as yanked. Nothing read the
field until this change, so nothing failed. It is now
`matches!(value, Bool(true) | String(_))`, held by
`a_file_is_yanked_by_a_reason_or_by_true_and_by_nothing_else`, which reads an index with the
key absent and one with `true`.

## Rejected

| Option | Why not |
|---|---|
| Carry the flag and refuse nothing | A pinned install of a withdrawn version is the case an operator wants told about, and pip installs it without a word |
| Always filter, with no setting | A yank is the publisher's judgement about their own release, and an operator who needs that version has no way to say so |
| Open `version: 2` for the key | No version 1 policy has been deployed, so v1 was amended instead, as `denials[].version` and `advisory_scores` were |

## The reason is repeated back

The refusal the client reads and the proxy's log line both carry it:

```
waharoa: pkg:pypi/x@1.0 is blocked by policy
  - yanked: withdrawn, broken sdist
```

`waharoa explain` prints the same string beside the check, and a yank with no reason reads
`withdrawn by the registry`.

## npm's `deprecated` is logged, and refused only if asked

A deprecated npm version is served, and the message its publisher left is logged.
`PackageRecord::deprecated` carries it. An artifact request logs it as `deprecated=<message>`
beside the digest, and a packument logs `deprecated_versions_listed=<count>`.

`deprecated: block` in the policy refuses one, the way `yanked` does, and a `packages` entry
can set it for one package. It is `allow` by default: an operator turns it on. PyPI has no
deprecation marker, so the check reports not-applicable there.

`deprecated` is a per-version string in both the abbreviated and the full packument, so
reading it costs no extra request. It is not a yank. npm prints a warning during install and
installs the version, and no npm client skips a deprecated version the way pip skips a
yanked file. Measured against registry.npmjs.org on 2026-09-20:

| Package | Versions | Deprecated | An example value |
|---|---|---|---|
| `lodash` | 117 | 1 | "Bad release. Please use lodash@4.17.21 instead." |
| `eslint` | 430 | 405 | "This version is no longer supported. Please see https://eslint.org/version-support for other options." |
| `glob` | 168 | 160 | "Old versions of glob are not supported..." |
| `left-pad` | 15 | 15 | "use String.prototype.padStart()" |
| `request` | 126 | 126 | "request has been deprecated, see https://github.com/request/request/issues/3142" |

Filtering on it would remove 405 of eslint's 430 versions, and every version of `request`
and `left-pad`. What the string means is up to the publisher: `lodash@4.18.0` is a bad
release, eslint's are an end-of-support policy.
