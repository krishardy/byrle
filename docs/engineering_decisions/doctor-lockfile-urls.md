# Which lockfiles `doctor` checks for the proxy's address

**Status:** Implemented, the `pins` of each `LOCKFILES` entry in
`src/ecosystem/npm/lockfile.rs` and `src/ecosystem/pypi/lockfile.rs`, read by
`doctor::check_lockfile`.

## Decision

`doctor` reads the artifact URLs a lockfile records and reports any origin other than the
proxy. A lockfile that records no URLs passes, except `bun.lock`. The read is textual, not a parse of
each format: every format checked writes a URL as `<key>: <url>` or `<key> "<url>"` on one
line. A lockfile naming two origins installs from both, and only one is examined.

| Lockfile | Key `doctor` reads | What the file records |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | `resolved` | the absolute artifact URL |
| `yarn.lock` | `resolved` | the absolute artifact URL |
| `pnpm-lock.yaml` | `tarball` | `resolution.tarball` only when the URL differs from the configured registry; pnpm derives the rest at install time, so a file with none is normal |
| `bun.lock` | the second element of each package's array, after `": [` | the artifact URL for every registry but registry.npmjs.org, where it writes `""`. So a `bun.lock` that records no URL was resolved from npmjs.org, not through the proxy, and `doctor` warns |
| `uv.lock` | `url` | each file's URL |
| `poetry.lock` | not checked | each file's name and hash, no URL; poetry rebuilds it from the configured index |
| `requirements.txt` | not checked | no URL unless the exporter wrote one; uv's `--no-hashes` form writes none |
| `Pipfile.lock` | not checked | each file's hash and the index's name, no URL |

## bun, measured

bun 1.4.2, 2026-09-29, installing `ms@2.1.3` with a text lockfile:

| Registry | Given by | `bun.lock` entry |
|---|---|---|
| registry.npmjs.org | default | `"ms": ["ms@2.1.3", "", {}, "sha512-..."]` |
| the proxy at `http://127.0.0.1:48731/` | `--registry`, `.npmrc` or `bunfig.toml` | `"ms": ["ms@2.1.3", "http://127.0.0.1:48731/ms/-/ms-2.1.3.tgz", {}, "sha512-..."]` |

Until then `bun.lock` was not checked, on the belief that bun wrote `""` for whichever
registry was configured.
