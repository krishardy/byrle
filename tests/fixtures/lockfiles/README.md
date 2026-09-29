# Lockfile fixtures

Each directory contains the lockfile one package manager wrote for `package.json` here, on
2026-09-14, against `https://registry.npmjs.org/`:

| Directory | Command | Version |
|---|---|---|
| `npm` | `npm install --package-lock-only --ignore-scripts` | npm 9.9.4 |
| `yarn` | `yarn install --ignore-scripts` | yarn 1.22.22 |
| `pnpm` | `pnpm install --lockfile-only --ignore-scripts` | pnpm 10.33.0 |
| `bun` | `bun install --lockfile-only --ignore-scripts` | bun 1.3.14 |
| `bun-1.1` | `bun install --save-text-lockfile --ignore-scripts`, `lockfileVersion` 0 | bun 1.1.45 |
| `bun-1.4` | `bun install --save-text-lockfile`, `lockfileVersion` 2, on 2026-09-29 | bun 1.4.2 |
| `bun-1.4-overrides` | `bun install --lockfile-only --ignore-scripts` for its own `package.json`, which adds a scoped `overrides` rule pinning `chalk` to the 2.4.2 already resolved, `lockfileVersion` 3, on 2026-09-29 | bun 1.4.2 |

`my-lodash` is an alias for `lodash@4.17.21`, and `minimist` is a dev dependency. Every
lockfile locks the same 15 package versions.

`pypi/` holds what uv 0.12.5 and poetry 2.2.1 wrote on 2026-09-21 for a project depending
on `idna==3.10` and, from git, `packaging` at 23.2:

| File | Command |
|---|---|
| `pypi/uv.lock` | `uv lock` |
| `pypi/poetry.lock` | `poetry lock` |
| `pypi/requirements.txt` | `uv export`, for a project depending on `requests==2.32.3` and `idna==3.10` |
| `pypi/Pipfile.lock` | `pipenv lock`, pipenv 2024.4.1, with `requests` as a dev dependency |

Each lockfile carries one package a registry published, `idna`, beside one from git and,
in uv's, the project itself. `requirements.txt` pins `urllib3` twice, once per Python
version marker.
