# Console login: passwords, sessions and the limit on failures

- **Status:** Implemented 2026-10-13. The values below were proposed by Claude and
  confirmed by the user on 2026-10-13, who asked that each be an environment variable.
  Reading the client's address through `BYRLE_RP_KEY` was the user's decision. TODO
  Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §4.1 and §4.5,
  [console-login-crates](console-login-crates.md)
- **Code:** `src/account/password.rs`, `src/account/command.rs`, `src/console/login.rs`,
  `src/console/api.rs`, `migrations/0021_account_password.sql`,
  `migrations/0022_session.sql`

## Decision

| Value | Chosen | Source |
|---|---|---|
| Algorithm | Argon2id, version 0x13 | Q4, [console-login-crates](console-login-crates.md) |
| Memory, passes, lanes | 19 MiB, 2, 1 | the `argon2` crate's defaults, OWASP's Password Storage Cheat Sheet's first Argon2id line |
| Salt | 16 random bytes per hash, from `getrandom` 0.3 | |
| Fewest characters | 15 | NIST SP 800-63B-4: 15 for a password that is the only factor |
| Most bytes | 1,024 | bounds the work of hashing one |
| Stored as | the PHC string, `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>` | |

A hash is verified with the parameters its PHC string names, so raising the parameters
later leaves earlier hashes working.

`argon2` is built with `default-features = false` and `alloc` and `password-hash`. Its
default `getrandom` feature builds `getrandom` 0.4.3, which this crate does not use
elsewhere; the salt comes from `getrandom` 0.3, which issues proxy tokens too.

## Variables

| Variable | Default | Accepted |
|---|---|---|
| `BYRLE_PASSWORD_MIN_CHARS` | 15 | 1 to 1,024 |
| `BYRLE_ARGON2_MEMORY_KIB` | 19456 | 8 or more |
| `BYRLE_ARGON2_PASSES` | 2 | 1 or more |
| `BYRLE_SESSION_HOURS` | 8 | 1 to 8,760 |
| `BYRLE_LOGIN_WINDOW_MINUTES` | 15 | 1 to 525,600 |
| `BYRLE_LOGIN_FAILURES_PER_ACCOUNT` | 5 | 1 or more |
| `BYRLE_LOGIN_FAILURES_PER_ADDRESS` | 20 | 1 or more |

`byrle account password` reads the first three, so the command line and the console make
hashes alike. A value outside its range stops the proxy at startup, and the command with
exit 2. Changing the Argon2 cost leaves earlier hashes working; a password is rehashed only
when it is set again.

## Setting one

```
$ read -rs password; printf '%s\n' "$password" | byrle account password alice
password of account alice set
```

`byrle account password <name>` reads the first line of stdin and drops its line ending.
Nothing else is trimmed. A password on the command line would be in the shell history and
the process list, so it is not taken as an argument. With `BYRLE_ACCOUNT_EVENT_LOG` set, it
appends `password-set` without the password.

A disabled account's password is not read back, so it cannot log in.

## Logging in

| Request | Answers |
|---|---|
| `POST <console>/api/v1/login`, `{"account": ..., "password": ...}` | 200 with `account`, `roles`, `csrf` and `expires`, and the session cookie; 401 for a wrong account or password, alike; 429 with `Retry-After: 900`; 503 when the store does not answer |
| `POST <console>/api/v1/logout`, with the cookie and `X-Byrle-CSRF` | 204, the session deleted and the cookie cleared |
| `GET <console>/api/v1/session` | 200 with `account`, `roles`, and `by`: `session` or `token` |

A console request is from the session its cookie names, or else from a proxy token in any
form the proxy accepts ([admin-plan](../admin-plan.md) §4.1). A 401 has no
`WWW-Authenticate`, so a browser shows no dialog.

| Value | Chosen |
|---|---|
| Session | 8 hours from login, no idle limit. Its id is 32 random bytes; the `session` table keeps its SHA-256 |
| Cookie | `byrle_session=<id>; Path=<console path>; Max-Age=28800; HttpOnly; Secure; SameSite=Strict` |
| CSRF | a cookie request other than GET or HEAD carries `X-Byrle-CSRF`, the SHA-256 of `byrle-csrf\0` and the session id, which login returns. A token request needs none |
| Origin | a `POST` with an `Origin` other than `BYRLE_CONSOLE_URL`'s is 403, login included. A request with no `Origin`, such as curl's, is let through |
| Failures | 5 per account and 20 per address in 15 minutes; past either, a login is 429 without its password being checked. An IPv6 address counts by its /64. The counts are per process, so instances sharing a database each count their own |
| Hashing | 2 passwords at once, each on a blocking thread. An account that is unknown, has no password, or a name that is not a name is checked against a hash of a random string, so it takes as long |
| Address | the peer's, or the last `X-Forwarded-For` entry on a request carrying `BYRLE_RP_KEY` ([fronting-tls](../fronting-tls.md)) |

A disabled account's sessions stop at their next request. Each login, failed login and
logout is a line of `BYRLE_ACCOUNT_EVENT_LOG`, with the address as `source`. A failed
login names the account tried, cut to 256 bytes, and never the password.

The console does not start without `BYRLE_DATABASE_URL`, or with an `http://`
`BYRLE_CONSOLE_URL` to a host other than loopback, where a browser drops a `Secure` cookie.

## OIDC

Begun 2026-10-13: `src/console/oidc.rs` holds the parts that ask no one. The provider is
`BYRLE_OIDC_ISSUER`, with `BYRLE_OIDC_CLIENT_ID` and `BYRLE_OIDC_CLIENT_SECRET`; the three
are set together or not at all. Its redirect URI is `BYRLE_CONSOLE_URL` and
`oidc/callback`.

| Check | What is refused |
|---|---|
| issuer and endpoints | a URL other than `https`, or `http` to loopback; a discovery document naming another issuer |
| algorithm | one not in `BYRLE_OIDC_ALGORITHMS` (`RS256,ES256`), which may name no shared-secret algorithm such as `HS256`, since the client secret would then verify |
| key | a token naming no `kid`; a key of another type than the algorithm, or declaring another `alg`. A `kid` not held is told apart, for the keys to be fetched again |
| claims | `iss` not the issuer exactly; `aud` not naming the client id; several audiences without `azp` the client id; `exp` past by more than `BYRLE_OIDC_LEEWAY_SECONDS` (60); no `sub`; a `nonce` not this login's |
| PKCE | S256 only; the verifier is 32 random bytes, as the state and nonce are |

The flow, built 2026-10-13:

| Step | What happens |
|---|---|
| `GET <console>/oidc/login` | the discovery document and keys are fetched once and held; the browser is sent to the authorization endpoint, with a `__Host-byrle_oidc` cookie holding the state, nonce and PKCE verifier: `Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`. `Lax`, since the provider sends the browser back from another site |
| `GET <console>/oidc/callback` | refused unchecked past 20 failures from the address in 15 minutes; then the `state` must equal the cookie's, before the code is exchanged. The cookie is cleared |
| the code exchange | a `POST` to the token endpoint, the client id and secret form-urlencoded as Basic credentials (RFC 6749 §2.3.1), with the PKCE verifier. An answer is read up to 256 KiB |
| the ID token | checked as above. A `kid` not held fetches the keys again, at most once a minute |

Register `BYRLE_CONSOLE_URL` followed by `oidc/callback` as the redirect URI, such as
`https://byrle.example.com/admin/oidc/callback`. The provider is asked through the client
the registries are, which trusts `BYRLE_CA_BUNDLE` and uses the forward proxy variables. The
routes answer 404 without a provider. Each failure is a `login-failed` line, naming the
token's `sub` once it is verified.

A verified identity logs in as the account an admin linked it to, decided by the user
2026-10-13 ("start with A for now; we may change later"):

```
$ byrle account link alice --issuer https://idp.example.com/realms/corp --subject 8f1c…
OIDC identity 8f1c… at https://idp.example.com/realms/corp logs in as account alice
```

`account_oidc` holds each issuer and subject once (`migrations/0023_account_oidc.sql`); the
link is logged as `oidc-linked` with the issuer. An identity linked to no account, or to a
disabled one, is answered 403, "`<sub>` at `<issuer>` is not linked to an account", and
logged as `login-failed`. A linked one starts a session, logged as `login` with the account
as its actor. That answer is a 200 page that sets the session cookie and reloads home,
rather than a redirect: the browser comes from the provider's site, and a
`SameSite=Strict` cookie is not sent on a request another site began.

| Option | Not taken because |
|---|---|
| B. The `preferred_username` or `email` claim names the account | anyone who can set that claim at the provider would become that account |
| C. B the first time, then the link kept | B's risk, once per account |

## Rejected

| Option | Why not |
|---|---|
| The password as an argument | shell history, `ps` |
| A no-echo prompt with `rpassword` | a crate added for what `read -s` does |
| `argon2` default features | builds `getrandom` 0.4.3 beside 0.3.4 |
| A minimum of 8 | NIST's minimum when another factor is required; the console has none |
| A lockout after N failures | anyone could lock the admin out by failing as them; failures are throttled for 15 minutes instead |
| `X-Forwarded-For` from any peer | a client sets it; only nginx, holding `BYRLE_RP_KEY`, is believed |
| A `__Host-` cookie | needs `Path=/`; the console answers under its own path |
