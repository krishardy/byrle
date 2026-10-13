# How a request through the proxy is tied to an account

- **Status:** Decided 2026-09-19: a token per account. Accounts and tokens implemented
  2026-10-11 (`src/account.rs`, `byrle account`, `byrle token`), and required on each
  proxy request (`src/account/gate.rs`). The audit log does not record the account yet.
  TODO Stage 4.9.
- **Related:** [doctor-python-clients](doctor-python-clients.md)

Stage 4.9 and Stage 8 need every request, metadata and artifact alike, to name the account
that made it, without a secret landing in a file that gets committed.

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

## Through the proxy, under a path, measured

On 2026-10-11 a proxy at `http://127.0.0.1:8741/registry/` required a token, from a
Postgres account store. Each client installed one package from registry.npmjs.org or
pypi.org through it. The proxy logged, per request, whether it accepted the token or
answered 401. npm 11.21.0, bun 1.4.3, pip 25.1.1, uv 0.13.0. pnpm and yarn were not
installed.

| Client, configured with | Metadata requests with the token | Artifact requests with the token | 401s | Token in the lockfile |
|---|---|---|---|---|
| npm, `//127.0.0.1:8741/registry/:_auth=<base64 of account:token>` | 2 | 2 | 0 | no |
| npm, `//127.0.0.1:8741/registry/:_authToken=<token>` | 2 | 1 | 0 | no |
| bun, `token` in `[install.registry]` | 1 | 7 | 0 | not checked |
| pip, `http://<account>:<token>@127.0.0.1:8741/registry/simple/` | 1 | 2 | 0 | no lockfile |
| uv, the same index URL | 1 | 2 | 0 | not checked |

The artifact counts include the retries after a 503 `artifact-analysis`. With `_auth`, npm
sent the token on artifact requests, where `user:pass@` in the registry URL sent nothing.

## The proxy forwarded `Authorization` upstream

`is_hop_by_hop` does not list `Authorization`, so `proxy::handle` copied it onto the upstream
request, and a token a client sent the proxy reached registry.npmjs.org or pypi.org. Since
2026-09-19 `proxy::handle` drops it. Since 2026-10-13 the proxy sends only the client
headers in `proxy::FORWARDED`, asked for by the user, held by
`what_each_request_sends_upstream`. A private upstream that needs a
credential has none until the proxy's configuration gives it one: TODO Stage 8.

## Options

| Option | Every request named | Secret in a committed file |
|---|---|---|
| A token per account: `_authToken` for npm, pnpm and yarn; `token` for bun; `user:token@` in the index URL for pip and uv. The proxy reads `Bearer`, or `Basic` with the token as the password | yes, for every client | no |
| `user:pass@` in the registry URL for every client | no: npm, pnpm and yarn send nothing on artifact requests, and bun sends nothing at all | no |
| A token in the path | yes | yes, four lockfiles |
| The client's network address | no: CI runners and developers behind one NAT share one | no |

Whichever is chosen, `Authorization` stops at the proxy, and a private upstream gets a
credential of its own from the proxy's configuration.

## Required by default

Decided by the user 2026-10-11, for Stage 4.9. Every proxy request carries a token, and
each user has their own. The proxy accepts it in the forms JFrog Artifactory accepts:

| Form | Sent by |
|---|---|
| `Authorization: Bearer <token>` | npm, pnpm, yarn 1, bun |
| `Authorization: Basic`, the token as the password | pip, uv. The username has to be the token's account |
| `X-Byrle-Token: <token>` | a client that sets a custom header, such as Maven's `httpHeaders` |

A request with none of them, or a token that is unknown, revoked or of a disabled account,
is answered 401.
`/-/byrle/health` and `/-/byrle/ready` need no token. `BYRLE_REQUIRE_TOKEN=0` turns the
requirement off, and a request without a token is recorded as anonymous. See
[admin-plan](../admin-plan.md) §4.1.
