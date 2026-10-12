# The TLS front is nginx, not Caddy

- **Status:** Implemented 2026-10-12. Decided by the user the same day.
- **Related:** [tls-reverse-proxy-first](tls-reverse-proxy-first.md),
  [fronting-tls](../fronting-tls.md)

## Decision

nginx is the one documented and tested TLS front. Caddy will not be used as an
application reverse proxy, so it is not documented, configured or tested.

## Where

| File | Change |
|---|---|
| `docs/fronting-tls.md` | the nginx configuration only |
| `scripts/make/smoke-tls-front.sh` | runs nginx only, and fails when nginx is not on PATH |
| `scripts/make/dev-setup.sh` | does not install Caddy |

## Rejected

| Option | Why not |
|---|---|
| Keep Caddy beside nginx | It will not be used. `make smoke-tls-front` skipped it on a machine without it, so a run could pass without checking it |
