# Which lockfiles `doctor` checks for the proxy's address

**Status:** Implemented, the `pins` of each `LOCKFILES` entry in
`src/ecosystem/npm/lockfile.rs` and `src/ecosystem/pypi/lockfile.rs`, read by
`doctor::check_lockfile`.

## Decision

`doctor` reads the artifact URLs a lockfile records and reports any origin other than the
proxy. A lockfile that records no URLs is not checked.

| Lockfile | Key `doctor` reads | What the file records |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | `resolved` | the absolute artifact URL |
| `yarn.lock` | `resolved` | the absolute artifact URL |
| `pnpm-lock.yaml` | `tarball` | `resolution.tarball` only when the URL differs from the configured registry; pnpm derives the rest at install time, so a file with none is normal |
| `bun.lock` | not checked | an empty string for an artifact from the configured registry, as written when this was decided. [break-glass](../break-glass.md) measured bun 1.4.2 recording the tarball URL on 2026-09-28 |
| `uv.lock` | `url` | each file's URL |
| `poetry.lock` | not checked | each file's name and hash, no URL; poetry rebuilds it from the configured index |
| `requirements.txt` | not checked | no URL unless the exporter wrote one; uv's `--no-hashes` form writes none |
| `Pipfile.lock` | not checked | each file's hash and the index's name, no URL |
