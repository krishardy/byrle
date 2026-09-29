# Where each npm client keeps its cache, and what a warm one skips

- **Status:** Implemented. `src/ecosystem/npm/clients.rs`, `doctor::probe`.
- **Related:** [doctor-python-clients](doctor-python-clients.md),
  [packument-tarball-url-rewriting](packument-tarball-url-rewriting.md)

## What a warm cache skips

Measured by installing the same package twice through the proxy with one cache and counting
what the proxy saw the second time. `waharoa doctor` reports each client's `CacheBypass`.

| Client | Second install | `CacheBypass` |
|---|---|---|
| npm 11, pnpm 10, bun 1.3 | nothing reached the proxy | `Complete` |
| yarn 1, yarn 4 | the packument did, the artifact did not | `ArtifactsOnly` |

## Where doctor looks

| Client | Registry | Cache |
|---|---|---|
| npm, pnpm, yarn | `config get registry`, which prints `undefined` for no value and reads a project `.npmrc`, then the user's, then the global one | the directory `config get cache` (npm), `store path` (pnpm) or `cache dir` (yarn) prints; npm's responses are one file each under `_cacache/index-v5` |
| bun | not checked | `BUN_INSTALL_CACHE_DIR`, else `~/.bun/install/cache`: `bun pm cache` needs a `package.json` in the working directory, which doctor cannot assume |

The cache is looked up from the directory doctor runs in, because it can differ per
directory: `pnpm store path` answers with a store on the project's own filesystem, so it is
`/tmp/.pnpm-store` under `/tmp` and the user's store elsewhere. Doctor reports whether a
cache is there and where, not a count: each client lays its cache out differently, and one
yarn cache is 12,983 entries or 749,073 files depending on which is counted.
