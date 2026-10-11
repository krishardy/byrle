# Refusal status

**Status:** Implemented, `src/refusal.rs`, set with `BYRLE_REFUSAL_STATUS`.

## Decision

Every refusal answers with one status, chosen per (ecosystem, client). A refusal by policy
and a refusal of an artifact the proxy cannot assess answer the same way.

```text
default=403,npm/pnpm=451,npm/yarn=404
```

| Rule | Reason |
|---|---|
| 403 by default | it means policy refused the request, and every client tested treats it as final |
| settable per (ecosystem, client) | package managers group status codes into buckets and do not agree on them; an operator whose client mishandles 403 can change it without a release |
| keyed by ecosystem as well as client | one client can behave differently per ecosystem, and `pip` settings do not move npm's clients |
| 400 to 599 only | a 2xx refusal is not a refusal, and a 3xx sends the client somewhere else |
| 5xx accepted, and reported at startup | §5 uses 5xx for "not ready", so a refusal answering one tells an operator their registry is broken when it is working |
| an unknown or absent user-agent gets the default | a refusal is final, so there is no retry to fall back to, unlike the not-ready codes in [deferral-status-codes](deferral-status-codes.md) |

## Identifying the client

The client is the first token of the user-agent, up to the first `/` or whitespace,
lowercased. It is never a substring match. Measured:

```text
npm/9.9.4 node/v16.20.1 linux x64 workspaces/false
pnpm/10.33.0 npm/? node/v20.11.1 linux x64
yarn/1.22.22 npm/? node/v16.20.1 linux x64
```

pnpm and yarn both contain `npm/` later in the string, so a search for `npm` matches all
three. The test `a_client_name_is_one_lowercase_token` checks that the name contains no
delimiter and is lowercase.
