# An artifact or manifest is served to GET and HEAD only

- **Number:** 0126
- **Status:** Implemented 2026-11-03 in `eb64955`, for finding 9 of the security review
  (TODO.md ad-hoc #50): `Exchange::method_not_allowed` in `src/proxy.rs`. The scope
  below was chosen while implementing it, and accepted by the user 2026-11-03.
- **Related:** [unrecognised-paths-refused](0119-unrecognised-paths-refused.md)

## Decision

| Request | Was | Is |
|---|---|---|
| an `Artifact` or `Manifest` path, GET | decided | decided |
| the same, HEAD | forwarded, decided for Maven only (`decides_head`) | the same |
| the same, any other method, enforce mode | forwarded with no decision | 405, `Allow: GET, HEAD`, logged at WARN |
| the same, any other method, observe mode | forwarded with no decision | forwarded, logged at WARN |
| a `Metadata` or `Other` path, any method | forwarded | forwarded |

## Why

proxy.golang.org answers POST, PUT, OPTIONS and PATCH to `@v/<version>.zip` with the zip.
npm, files.pythonhosted.org, Central and static.crates.io answered 400 to 405. No client
asks for a file with a method but GET or HEAD.

`npm audit` POSTs to `/-/npm/v1/security/advisories/bulk` and
`/-/npm/v1/security/audits/quick`, which are `Other` paths.

Observe mode forwards an unrecognised path with a WARN line
([unrecognised-paths-refused](0119-unrecognised-paths-refused.md)). A file asked with
another method is forwarded the same way.

## Rejected

| Option | Why not |
|---|---|
| 405 for any method but GET and HEAD, on every path (the review's proposal) | refuses `npm audit` |
| 405 in observe mode too | observe mode forwards an unrecognised path, which no check reads either |
| decide a POST as a GET | the upstream's answer to a POST is not the file the metadata describes |

## Cost

In enforce mode, a client that asks for a file with another method gets 405. Which
clients do that was not measured.
