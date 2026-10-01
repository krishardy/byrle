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
| a git, file or other non-HTTP spec, or a path outside the project | from elsewhere, named as written | 1 |
| a path inside the project: a workspace member, a directory or tarball committed with it | not an artifact | |
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
- Git and path dependencies are not registry packages. The `urls` readers report them, and
  the `read` and `artifacts` readers, for `policy diff` and `warm`, still leave them out. A
  path is inside the project when it does not leave the lockfile's directory, read lexically
  after `file:`, `link:` or `workspace:`. A path inside is source committed with the project,
  which nothing fetches.
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

A project with a git dependency, a directory and a tarball outside it, and a workspace
member, locked by npm 11.20.0, bun 1.4.2, pnpm 9.15.9, yarn 1.22 and uv 0.12.20 on
2026-10-01 (`tests/fixtures/lockfiles/unregistered/`):

```
$ waharoa lockfile verify --lockfile unregistered/package-lock.json --proxy https://registry.npmjs.org
unregistered/package-lock.json: 4 artifacts, 1 through the proxy, 3 from elsewhere
  is-number@7.0.0	git+ssh://git@github.com/jonschlinkert/is-number.git#98e8ff1da1a89f93d1397a24d7413ed15421c139
  localdir@1.0.0	../localdir
  tarpkg@2.0.0	file:../tarpkg-2.0.0.tgz
$ waharoa lockfile verify --lockfile unregistered/uv.lock --proxy https://files.pythonhosted.org
unregistered/uv.lock: 5 artifacts, 2 through the proxy, 3 from elsewhere
  localpy@1.0.0	../localpy
  six@1.16.0	git+https://github.com/benjaminp/six?rev=1.16.0#65486e4383f9f411da95937451205d3c7b61b9e1
  tarpy@2.0.0	../dist/tarpy-2.0.0.tar.gz
```

| Lockfile | Git dependency recorded as | Workspace member |
|---|---|---|
| `package-lock.json` | `resolved: git+ssh://...#<commit>` | a link to `packages/wsp` |
| `bun.lock` | `is-number@github:o/r#<short commit>` | `wsp@workspace:packages/wsp` |
| `pnpm-lock.yaml` | a codeload.github.com tarball URL in the key | `link:packages/wsp`, in `importers` only |
| `yarn.lock` | a codeload.github.com `resolved` under a `github:` range | not in the file |
| `uv.lock` | `source = { git = "https://...?rev=...#<commit>" }` | `source = { editable = "wspy" }` |

The `uv.lock` run shows why the route is by origin: PyPI serves its index and its files
from different hosts. A `uv.lock` resolved through the proxy records the proxy for both
while artifact rewriting is on, the default, since the proxy rewrites each file's URL to its
own.

## Tests

`src/lockfile/verify.rs` covers each route, a proxy with a path prefix, every format's
report and exit bits, a package whose wheels share an origin listed once, the public URL as
the default, and each error. 9 hand mutants on the verifier and the readers, each caught
after the `bun.lock` case was made to check its whole report.

Git and path dependencies: the report for each real lockfile above, each format's paths
inside the project, and `own_source`'s cases. 26 hand mutants on `own_source` and the
readers, each caught after three survivors were answered: `./../b` added to the cases, a
yarn `o/short` range added, and pnpm's `tarball` dropped as a source of the spec, since its
key records the same.
