# Upstream traffic honours the forward proxy variables, as reqwest reads them

- **Status:** Implemented 2026-09-28. `env::HTTPS_PROXY`, `env::HTTP_PROXY`,
  `env::NO_PROXY`, `Env::upstream_proxy`, `http::UpstreamProxy::describe`, and
  `scripts/make/smoke-proxy.sh`.
- **Related:** [http-stack-axum-reqwest](http-stack-axum-reqwest.md),
  [environment-variables](environment-variables.md)

## Decision

reqwest reads `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, and their lowercase forms, when a
client is built, with default features off. Every client the proxy builds uses
`http::client_builder` and never calls `.no_proxy()`, so the forwarded request, the
analysis job and the intel refresh all go through the forward proxy. No proxy
configuration of waharoa's own was added.

What was added is visibility:

| Where | What |
|---|---|
| `waharoa --help` | the three variables, with a note that the lowercase names are read too |
| startup log | `upstream traffic goes through a forward proxy`, with fields `https`, `http` and `direct`, any user and password in a URL replaced by `***` |
| `make smoke-proxy` | the binary against a local registry and a local recording forward proxy |

## Measured

The daemon asked for `/lodash`, 2026-09-28, in a sandbox whose only route out is
`HTTPS_PROXY=http://egress-proxy:3128`:

| Setting | Answer |
|---|---|
| the sandbox's `HTTPS_PROXY` | 200 |
| `HTTPS_PROXY=http://127.0.0.1:1` | 502 |
| `NO_PROXY` including `registry.npmjs.org` | 502: sent direct, which the sandbox refuses |

`make smoke-proxy` repeats this over plain HTTP, which needs no network:

| Step | Setting | Expected |
|---|---|---|
| 1 | `HTTP_PROXY` | 200, carried by the forward proxy, named at startup |
| 2 | `HTTP_PROXY` at a closed port | 502 |
| 3 | `HTTP_PROXY` and `NO_PROXY=127.0.0.1` | 200, not carried |
| 4 | `HTTPS_PROXY` only | 200, not carried: it applies to https only |

With `.no_proxy()` added to `http::client_builder`, step 1 fails.

## Rejected

| Option | Why |
|---|---|
| waharoa's own proxy variable | a second name for what every tool on the machine already reads |
| parsing the variables and calling `.proxy()` | would restate reqwest's rules for lowercase names, `ALL_PROXY` and `NO_PROXY` matching, and could drift from them |
