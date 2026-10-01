# `waharoa lockfile verify` checks a lockfile installs through the proxy

- **Status:** Implemented 2026-10-01. `src/lockfile/verify.rs`, the `urls` reader of each
  `LOCKFILES` entry.
- **Related:** [doctor-lockfile-urls](doctor-lockfile-urls.md),
  [policy-diff-lockfiles](policy-diff-lockfiles.md), [warm](warm.md)

## Decision

A CI job runs `waharoa lockfile verify --lockfile <path> --proxy <url>` to catch an install
that went around the proxy: a lockfile resolved against the public registry, committed, and
installed from there on every machine that uses it. `--proxy` defaults to
`WAHAROA_PUBLIC_URL`. A CI job has no listen address of its own to fall back on.

Each artifact the lockfile locks is parsed out, not matched as text, as `doctor` does, so
every entry is checked and not only the first origin.

| What the lockfile records | Route | Exit bit |
|---|---|---|
| a URL on the proxy's origin, under its path | through the proxy | |
| an HTTP URL elsewhere | from elsewhere, named by origin | 1 |
| a git, file or other non-HTTP spec | from elsewhere, named as written | 1 |
| no URL, in `bun.lock` | from elsewhere: bun writes `""` for registry.npmjs.org | 1 |
| no URL, in `pnpm-lock.yaml` or an old npm lockfile | not recorded | 2 |

An error stops the run with 4 on its own: a lockfile that does not read, a format that
records no URLs (`poetry.lock`, `requirements.txt`, `Pipfile.lock`), no proxy named, or one
that is not an HTTP URL. The exit code follows `warm` and `audit verify`.

| Lockfile | URLs read |
|---|---|
| `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` | `resolved` |
| `pnpm-lock.yaml` | `resolution.tarball`, written only for a URL that is not the configured registry's |
| `bun.lock` | each package's second element |
| `uv.lock` | the `url` of each registry package's sdist and every wheel |

- pnpm records no URL for the registry it was configured with, so a pnpm project that
  installs through the proxy sets bit 2 for every package. The registry is in its `.npmrc`,
  which a CI job can check, and the job can ignore bit 2 with `code & 1`.
- The pnpm and bun readers now record the URL a file gives, so `warm` asks for an artifact
  at that URL's path, not the registry's usual one.
- Git and file dependencies are not registry packages, and the readers leave them out. They
  bypass the proxy, and are named in `package.json`.
- `uv.lock` has a URL reader and no `artifacts` reader: `warm` still asks for a PyPI version
  through the proxy's metadata, not for every wheel the file lists.

## Run on real lockfiles

The [source-diff](source-diff.md) lockfiles, resolved straight from the public registries on
2026-09-30:

```
$ waharoa lockfile verify --lockfile express-eslint/package-lock.json --proxy https://registry.npmjs.org
express-eslint/package-lock.json: 143 artifacts, 143 through the proxy
$ waharoa lockfile verify --lockfile express-eslint/package-lock.json --proxy http://proxy.internal:8080
express-eslint/package-lock.json: 143 artifacts, 0 through the proxy, 143 from elsewhere
  @cacheable/memory@2.2.0	https://registry.npmjs.org
  ...
$ waharoa lockfile verify --lockfile requests-flask-django/uv.lock --proxy https://pypi.org/simple
requests-flask-django/uv.lock: 208 artifacts, 0 through the proxy, 208 from elsewhere
  asgiref@3.12.1	https://files.pythonhosted.org
  ...
```

The `uv.lock` run shows why the route is by origin: PyPI serves its index and its files
from different hosts. A `uv.lock` resolved through the proxy records the proxy for both
while artifact rewriting is on, the default, since the proxy rewrites each file's URL to its
own.

## Tests

`src/lockfile/verify.rs` covers each route, a proxy with a path prefix, every format's
report and exit bits, a package whose wheels share an origin listed once, the public URL as
the default, and each error. 9 hand mutants on the verifier and the readers, each caught
after the `bun.lock` case was made to check its whole report.
