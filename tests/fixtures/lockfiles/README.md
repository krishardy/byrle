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

`my-lodash` is an alias for `lodash@4.17.21`, and `minimist` is a dev dependency. Every
lockfile locks the same 15 package versions.
