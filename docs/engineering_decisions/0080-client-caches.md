# Where each npm client keeps its cache, and what a warm one skips

- **Number:** 0080
- **Status:** Implemented. `src/ecosystem/npm/clients.rs`, `src/ecosystem/maven/clients.rs`,
  `doctor::probe`.
- **Related:** [doctor-python-clients](0053-doctor-python-clients.md),
  [packument-tarball-url-rewriting](0018-packument-tarball-url-rewriting.md)

## What a warm cache skips

Measured by installing the same package twice through the proxy with one cache and counting
what the proxy saw the second time. `byrle doctor` reports each client's `CacheBypass`.

| Client | Second install | `CacheBypass` |
|---|---|---|
| npm 11, pnpm 10, bun 1.3 | nothing reached the proxy | `Complete` |
| yarn 1, yarn 4 | the packument did, the artifact did not | `ArtifactsOnly` |
| cargo 1.99.0 | with crates.io replaced, `itoa` cached from crates.io was downloaded again through the replacement, 2026-10-14 | `PerRegistry` |
| go 1.27.2 | `rsc.io/quote@v1.5.2`, cached, was added though the proxy refused it by cooldown; the proxy saw no `.mod` or `.zip` request for it, 2026-10-16 | `Complete` |
| mvn 3.10.0 | under the same mirror id, 0 requests; under another id at the same URL, 498, 2026-10-17. mvn keys its cache by the mirror's id, not its URL | `Complete` |

## Where doctor looks

| Client | Registry | Cache |
|---|---|---|
| npm, pnpm, yarn | `config get registry`, which prints `undefined` for no value and reads a project `.npmrc`, then the user's, then the global one | the directory `config get cache` (npm), `store path` (pnpm) or `cache dir` (yarn) prints; npm's responses are one file each under `_cacache/index-v5` |
| bun | not checked | `BUN_INSTALL_CACHE_DIR`, else `~/.bun/install/cache`: `bun pm cache` needs a `package.json` in the working directory, which doctor cannot assume |
| cargo | `.cargo/config.toml` in the working directory and each above it, then `CARGO_HOME`'s, else `~/.cargo`'s: `[source.crates-io] replace-with` and that source's index | `CARGO_HOME/registry/cache`, else `~/.cargo/registry/cache`, a directory per registry, so reported and not warned about |
| go | `go env -json GOPROXY GONOPROXY GOFLAGS`: `GOPROXY`'s first entry, and as extra indexes the entries after a `\|` | `go env GOMODCACHE`'s `cache/download` |
| mvn | `-s` and `-gs` from `MAVEN_ARGS`, then `.mvn/maven.config`, else `~/.m2/settings.xml` and `conf/settings.xml` under the `Maven home:` `mvn --version` prints: the mirror for `central`, and as an extra index the mirror for an id no file names | `-Dmaven.repo.local` from the same arguments, else `<localRepository>`, else `~/.m2/repository` |

The cache is looked up from the directory doctor runs in, because it can differ per
directory: `pnpm store path` answers with a store on the project's own filesystem, so it is
`/tmp/.pnpm-store` under `/tmp` and the user's store elsewhere. Doctor reports whether a
cache is there and where, not a count: each client lays its cache out differently, and one
yarn cache is 12,983 entries or 749,073 files depending on which is counted.
