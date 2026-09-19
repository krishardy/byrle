# How a request through the proxy is tied to an account

- **Status:** Decided 2026-09-19: a token per account. Not yet implemented. TODO Stage 8.
- **Related:** [doctor-python-clients](doctor-python-clients.md)

Stage 8 needs every request, metadata and artifact alike, to name the account that made it,
without a secret landing in a file that gets committed.

## Decision

Each account has a token. A client sends it the way it sends any registry credential, and the
proxy reads it from `Authorization`: `Bearer <token>`, or `Basic` with the token as the
password.

| Client | Where the token goes |
|---|---|
| npm, pnpm, yarn 1 | `//<proxy host>/:_authToken=<token>` in `.npmrc` |
| bun | `token` under `[install.registry]` in `bunfig.toml`, or `NPM_CONFIG_TOKEN` |
| pip, uv | `https://<account>:<token>@<proxy host>/simple/` as the index URL |

Every metadata and artifact request carries it, and no lockfile records it. `Authorization`
stops at the proxy.

## What each client sends, measured

A stub registry on 127.0.0.1 served one npm package and one wheel, logged each request's
path and `Authorization` header, and answered with URLs carrying the request's own path
prefix. Each client installed the package once per way of configuring a credential. npm
11.11.0, pnpm 10.33.0, yarn 1.22.22, bun 1.3.14, pip 26.1.1, uv 0.12.5.

| Client, configured with | Metadata request | Artifact request | Credential in the lockfile |
|---|---|---|---|
| npm, `user:pass@` in the registry URL | `Basic` | none | no |
| npm, `_authToken` | `Bearer` | `Bearer` | no |
| pnpm, `user:pass@` in the registry URL | `Basic` | none | no |
| pnpm, `_authToken` in `.npmrc` | `Bearer` | `Bearer` | no |
| yarn 1, `user:pass@` in the registry URL | `Basic` | none | no |
| yarn 1, `_authToken` in `.npmrc` | `Bearer` | `Bearer` | no |
| bun, `user:pass@` in the registry URL | none | not reached | no |
| bun, `token` in `bunfig.toml`, or `NPM_CONFIG_TOKEN` | `Bearer` | `Bearer` | no |
| pip, `user:pass@` in the index URL | `Basic` | `Basic` | no lockfile |
| uv, `user:pass@` in the index URL | `Basic` | `Basic` | no, `uv.lock` |
| every client, a token in the path, `/t/<token>/` | in the path | in the path | **yes** in `package-lock.json`, `yarn.lock`, `bun.lock` and `uv.lock`; not in `pnpm-lock.yaml`, which omits URLs |

pnpm ignored `_authToken` given as the `npm_config_//host/:_authToken` variable and read it
from `.npmrc`. yarn 4 was not measured.

## The proxy forwards `Authorization` upstream

`is_hop_by_hop` does not list `Authorization`, so `proxy::handle` copies it onto the
upstream request. A token a client sends the proxy reaches registry.npmjs.org or pypi.org
today.

## Options

| Option | Every request named | Secret in a committed file |
|---|---|---|
| A token per account: `_authToken` for npm, pnpm and yarn; `token` for bun; `user:token@` in the index URL for pip and uv. The proxy reads `Bearer`, or `Basic` with the token as the password | yes, for every client | no |
| `user:pass@` in the registry URL for every client | no: npm, pnpm and yarn send nothing on artifact requests, and bun sends nothing at all | no |
| A token in the path | yes | yes, four lockfiles |
| The client's network address | no: CI runners and developers behind one NAT share one | no |

Whichever is chosen, `Authorization` stops at the proxy, and a private upstream gets a
credential of its own from the proxy's configuration.
