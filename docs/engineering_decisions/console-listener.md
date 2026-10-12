# Where the console answers: its own URL, on the proxy's listener or its own

- **Status:** Decided 2026-10-11, by the user; revised the same day. Implemented:
  `src/mount.rs`, `src/console.rs`. TODO Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §4.8

## Decision

| Variable | Gives |
|---|---|
| `BYRLE_PROXY_URL` | the URL package managers use. Its path is where the proxy answers, and it is written into artifact URLs. Unset, each request's `Host`, at `/` |
| `BYRLE_CONSOLE_URL` | the URL of the console. Its path is where the console answers. Unset, there is no console |
| `BYRLE_LISTEN` | the address the proxy binds |
| `BYRLE_CONSOLE_LISTEN` | the address the console binds. Unset, or equal to `BYRLE_LISTEN`, it shares the proxy's |

The URLs say what clients and browsers use. The listen addresses say what byrle binds, which
behind a TLS front ([fronting-tls](../fronting-tls.md)) is not the same. The two URLs may
share a host and a port. They are never at the same path.

| | The two paths |
|---|---|
| on one listener | differ, and neither contains the other |
| on two listeners | differ |

On one listener a request is the console's when it is under the console's path, and the
proxy's otherwise. With the proxy at `/` and the console at `/admin/`, npm's package `admin`,
`/admin/-/admin-1.0.0.tgz`, would reach the console. Startup refuses such a pair, naming
both variables.

`BYRLE_PUBLIC_URL` was renamed `BYRLE_PROXY_URL` on 2026-10-11, so the proxy's and the
console's URLs are named alike. It is one variable: the URL written into artifact URLs is
the URL whose path the proxy answers under.

Configuration is through the environment, as every other setting of `byrle daemon` is.

## Why

One process keeps the in-memory counters of `proxy::Health` visible to the console. The
console's path, or a listener of its own, keeps it off the paths package managers use.

## Measured 2026-10-11

`BYRLE_PROXY_URL=http://127.0.0.1:18080/registry/`,
`BYRLE_CONSOLE_URL=http://127.0.0.1:18080/admin/`, one listener:

| Request | Answer |
|---|---|
| `/registry/-/byrle/health` | 200 |
| `/-/byrle/health` | 404 |
| `/admin/api/v1/health` | 200 `{"status":"up"}` |
| `/registry/admin`, npm's `admin` packument | 200 |
| `npm install is-number@7.0.0` | installed; `package-lock.json` records `http://127.0.0.1:18080/registry/is-number/-/is-number-7.0.0.tgz` |
| `pip install six==1.16.0`, index `.../registry/simple/` | installed |

## Rejected

| Option | Why not |
|---|---|
| The console always on a second listener | The user's deployments may give both one host and port |
| Routing the shared listener by `Host` | A front may rewrite `Host`; a path survives it |
| A separate `byrle console` process on the same database | It cannot read the proxy's in-memory counters |
| `--proxy-url` and `--console-url` flags on `byrle daemon` | Every other daemon setting is an environment variable |
