# A request path the proxy does not recognise is refused

- **Number:** 0119
- **Status:** Decided by the user 2026-10-19, as TODO.md ad-hoc #45 and
  [unrecognised-paths-plan](../unrecognised-paths-plan.md). Implemented 2026-10-19:
  `RequestTarget::Unrecognised`, `proxy::unrecognised`, `scripts/make/lib/recognised.sh`.
- **Related:** [adapter-interface](0047-adapter-interface.md),
  [every-refusal-a-signal](0116-every-refusal-a-signal.md),
  [request-flow](../request-flow.md)

## Decision

Each adapter's `classify_path` returns `RequestTarget::Other` only for a path shape it
lists: npm's `/-/ping` and audit endpoints, PyPI's PEP 658 `.metadata`, Go's `.info` and
checksum database, Maven's digest and signature sidecars, and the rest of the plan's
inventory. Any other path under an ecosystem's prefix is `RequestTarget::Unrecognised`, and
`handle` refuses it after `admit`, `written` and `sidecar`, with the refusal status, logged
at WARN with its path. Under `BYRLE_MODE=observe` it is forwarded, logged the same. No
switch turns the refusal off.

## Why

`Other` was the default branch, and `handle` forwards it upstream unread. A path that
names an installable file but does not parse was served with no decision, digest check or
analysis: a PyPI `.tgz` or `.tar` sdist, which `filename_parts` does not read and pip
installs, or an npm tarball not named `<name>-<version>.tgz`. On PyPI, `other_is_probe`
logged each at DEBUG.

The refusal is not a weighted signal, as 0116 makes every other refusal. An unrecognised
path names no version to score. It writes no audit line, since `audit_refused` writes none
for a request that names no package.

## Rejected

| Option | Why not |
|---|---|
| Keep forwarding `Other`, and widen each parser | a parser misses the next file form as it missed `.tgz`; the miss is served |
| A second predicate listing forwarded paths beside `classify_path` | two parsers of one path can disagree |
| `BYRLE_REFUSE_UNRECOGNISED=0` | the user chose none: a missing shape is a bug fixed by listing it |
| 404 | a client reads it as missing rather than refused |
