# Admin console: plan for Stage 4.9

Admin, monitoring and configuration APIs, and a web interface over them. Written 2026-10-11.
`TODO.md` Stage 4.9 tracks the work.

## 1. Scope

| In Stage 4.9 | Later |
|---|---|
| Login by username and password, or by OIDC | Other identity protocols |
| A role model with permissions checked on every API call | Roles other than `admin` |
| The `admin` role | A user seeing only their own installs: Stage 8 |
| Viewing the proxy configuration | Changing the configuration from the console |
| Alerts shown in the console | Email: Stage 8's outbox |
| A token on every proxy request, required by default | |

The configuration stays in the environment and the policy file. The console reads it and
does not change it.

## 2. Requirements against what is recorded today

Read from `src/audit.rs`, `src/proxy.rs` and the decision files on 2026-10-11.

| # | As an admin, I want to | Data it needs | Today | Gap |
|---|---|---|---|---|
| R1 | log in by password or OIDC | accounts, password hashes, OIDC subjects, sessions | none | all of it |
| R2 | have access decided by role | roles, permissions | none | all of it |
| R3 | view every dependency retrieved, and its versions | each artifact served: purl, version, when, by whom | the audit log file, `answered: served` on `pinned` lines, when `BYRLE_AUDIT_LOG` is set | an index that lists versions without reading every log file (§4.3) |
| R4 | see alerts for dependencies retrieved and later flagged malicious | R3, matched against the current advisories | Stage 8's matching, decided and not built | the same matching, with results shown in the console |
| R5 | see requests blocked because a dependency is malicious | refusals with the check that fired | `pinned` lines with `answered: refused` and `known_malware` in `checks`; `resolution` lines naming versions removed by `known_malware` | the account on each line. A `resolution` line is reported as "removed from metadata", apart from a refused fetch |
| R6 | see request failures by case | every non-200 the proxy produces, by case | eight `answered` values; five cases not recorded at all (§3) | record the five; count by case and hour |
| R7 | view the proxy configuration | the settings as loaded, the policy as loaded | `/-/byrle/health` (`proxy::Health`), `byrle explain --policy`, `src/env.rs` | an API that returns both, with secrets removed |
| R8 | see what changes users have made | each change: who, what, when, from where | none | the account event log (§4.5). The configuration is read-only here, so the changes are to accounts, roles, tokens and sessions |
| R9 | get usage logs: dependencies requested, decisions made, users involved | every request, its decision and its account | the audit log file, with no account | the account on each line (§4.1); download of the log files |
| R10 | see whether the proxy and the management API are available | the proxy listener answering, its readiness, the API and its database answering | `/-/byrle/health` and `/-/byrle/ready` on the proxy port | a status page and endpoint that check each (§4.9) |

"Audit log" already means the decision log `src/audit.rs` writes, which `byrle audit verify`
and `byrle policy diff` read. This plan calls the R8 record the **account event log**.

## 3. Failure cases

From [request-flow](request-flow.md). R6 needs each one counted.

| Case | Status | Recorded today |
|---|---|---|
| refused by policy | refusal status, 403 by default | yes, `refused` |
| origin the proxy does not serve | refusal status | yes, `unservable` |
| no strong digest | refusal status | yes, `no-strong-digest` |
| metadata names neither the version nor the file | refusal status | yes, `not-listed` |
| registry gave no metadata for the package | 502 | yes, `no-metadata` |
| upstream bytes did not match their digest | 502 | yes, `upstream-mismatch` |
| artifact under analysis | 503 `artifact-analysis` | yes, `deferred` |
| intel store cannot answer | 503 `intel-store` | yes, `intel-store` |
| no stream covers the ecosystem | 503 `no-stream-for-ecosystem` | yes, `no-stream-for-ecosystem` |
| upstream unreachable, or stalled | 502 | yes, `upstream-unreachable` |
| upstream answered 404 ("not found") or another non-2xx | forwarded | yes, `upstream-status`, with the status |
| artifact streamed with 200, body cut short on a digest mismatch | 200, truncated | yes, `cut-short`, after its `served` line |
| no token, or one unknown, revoked or of a disabled account | 401 | yes, `unauthorized`, with no account |
| account store cannot answer | 503 `account-store` | yes, `account-store`, with no account |

Recorded 2026-10-12, with the account on each line
([audit-log](engineering_decisions/audit-log.md)). An older build cannot read a line with an
`answered` value it does not know, and `audit verify` on it reports that line as not
replayable.

## 4. Design

### 4.1 Accounts and credentials

Decided 2026-10-11 (Q1): every proxy request carries a token, by default. Each user has
their own. The proxy accepts it in the forms JFrog Artifactory accepts, since each
ecosystem's clients send at least one of them:

| Form | Sent by |
|---|---|
| `Authorization: Bearer <token>` | npm, pnpm, yarn 1 with `_authToken`; bun with `token` |
| `Authorization: Basic`, username and the token as the password | pip and uv with `user:token@` in the index URL. The username has to be the token's account |
| `X-Byrle-Token: <token>` | a client that sets a custom header, such as Maven's `httpHeaders` |

A request with none of these, or with a token that is unknown, revoked or of a disabled
account, is answered 401 with `WWW-Authenticate: Basic realm="byrle"`. `/-/byrle/health` and `/-/byrle/ready`
need no token. `BYRLE_REQUIRE_TOKEN=0` turns the requirement off, and a request without a
token is then recorded as anonymous.

Implemented 2026-10-11 in `src/account/gate.rs`. The proxy does not start with the
requirement on and no `BYRLE_DATABASE_URL`. Which form is read first, and the 503 when the
store cannot answer, are in [request-flow](request-flow.md#tokens).

[account-identification](engineering_decisions/account-identification.md) measured which
form each client sends on metadata and artifact requests, and on 2026-10-11 npm's `_auth`
(Basic, the form Artifactory documents for npm) through the proxy under a path: it sent
the token on every metadata and artifact request.

A console login and a proxy token belong to the same account, so the audit log names the
person behind each install:

| Credential | Used by | Stored as |
|---|---|---|
| password | a person logging in to the console | Argon2id hash |
| OIDC subject (`iss` + `sub`) | a person logging in through SSO | the pair, unique |
| proxy token | a package manager | SHA-256 of the token |

A CI runner is an account with a proxy token and no login.

This pulls forward Stage 8's first item, "Accounts: a user signs up and is identified on
the requests they make". Stage 8 keeps the user's own installs list and email.

### 4.2 Roles and permissions

Permissions are a closed enum in code. A role is a named set of them. An account has one
or more roles. Every API handler declares the permission it needs, and a test checks that
no handler is reachable without one.

| Permission | `admin` |
|---|---|
| `requests.read`: R3, R5, R6, R9 | yes |
| `alerts.read`: R4 | yes |
| `config.read`: R7 | yes |
| `status.read`: R10 | yes |
| `events.read`: R8 | yes |
| `accounts.read`, `accounts.write`: accounts, roles, tokens | yes |

Only `admin` exists in Stage 4.9. Accounts hold role names, so adding `viewer` or
`developer` later is a code change and no migration.

Built 2026-10-13: `src/account/role.rs`, and `account_role` in
`migrations/0020_account_role.sql`. `byrle account create alice --role admin` makes the
first admin, and `byrle account list` shows each account's roles. A role name a later build
added is skipped when an earlier one reads it.

### 4.3 Storage

Decided 2026-10-11 (Q5): logs are files on disk, rotated, compressed, and kept 365 days by
default.

| Log | File | Written by |
|---|---|---|
| audit log, gaining `account` and the §3 cases | `BYRLE_AUDIT_LOG` | the proxy, as today |
| account event log | `BYRLE_ACCOUNT_EVENT_LOG` | the console |

byrle rotates each log itself, at UTC midnight: the day's file is renamed with its date.
Files 3 days old and older are compressed with bzip2, and files older than
`BYRLE_LOG_RETENTION_DAYS` (365) are deleted
([log-rotation](engineering_decisions/log-rotation.md)). No `logrotate` configuration is
needed, and a rotation never loses a line written during it. `policy diff`, `audit
verify` and the console read the current file and the rotated ones.

Postgres, the database `BYRLE_DATABASE_URL` names, holds what is looked up rather than
scanned. The console requires it: with no database set, the console does not start.

| Table | One row per |
|---|---|
| `account` | account |
| `account_role` | account and role |
| `account_password` | account with a password |
| `account_oidc` | account and OIDC subject |
| `proxy_token` | token, hashed, with a name, created and last-used times |
| `session` | console session, hashed id, expiry |
| `served_version` | account, purl and version served: first and last time. Answers R3 and R4 |
| `failure_count` | hour, ecosystem and `answered` case: a count. Answers R6 |

`artifact_decision` (Ad-hoc #32, [artifact-decisions](engineering_decisions/artifact-decisions.md))
holds a row per pinned artifact decision, with its account, purl and version, and is deleted
after `BYRLE_DECISION_RETENTION_DAYS`. `served_version` is a table of its own, decided by the
user 2026-10-13, and is not deleted, so R3 and R4 keep a version served before that period.

The two index tables are written by the proxy beside each audit line, with a database, in
`migrations/0019_usage.sql` and `src/usage.rs`. The write never fails or delays an install:
rows go through a bounded queue of 4,096 and are written up to 256 at a time, with the
duplicates in a batch merged first. A full queue or a failed write counts the rows it drops
in `usage_unrecorded` on `/-/byrle/health`. The console shows the count. Built 2026-10-13.

| Audit line | Row |
|---|---|
| `answered: served`, with a version | `served_version`: the account, or NULL without a token, and the first and last `at` |
| any other `answered` | `failure_count`: 1 more for the line's hour (UTC), ecosystem and `answered` |
| a document filtered, with no `answered` or no version | none |

A line is written only with a policy, so a proxy without one counts nothing. Times are the
line's `at`, not when its batch was written.

R5 and R9 read the log files for the time range asked. A range of a year reads a year of
files; the console states how many files a query read.

Each proxy instance writes its own log files. A console reads the files of the instance it
runs in. Several instances on one database share the index tables, and each one's logs
stay on its own disk.

### 4.4 Alerts (R4)

After each refresh, and when the console asks, each row of `served_version` is looked up
with `Intel::lookup`, the lookup the proxy and `explain` use. A version with an advisory
where `malware` is set, first loaded after the version was served, is an alert. "First
loaded" comes from `intel_ingestion`. Stage 8 sends the same matches by email.

### 4.5 The account event log (R8)

Recorded actions in Stage 4.9:

| Action | Target |
|---|---|
| `login`, `login-failed`, `logout` | account |
| `account-created`, `account-disabled` | account |
| `role-granted`, `role-revoked` | account and role |
| `password-set` | account |
| `token-created`, `token-revoked` | token name |
| `oidc-linked` | account and issuer |

Each line has the time, the acting account, the action, the target and the source
address. A failed login names the username tried, not the password.

Built 2026-10-13, for the command line: `src/account/events.rs`. With
`BYRLE_ACCOUNT_EVENT_LOG` set, `byrle account` and `byrle token` check that they can open the
file before changing anything, then append a line per change, with `"source": "cli"` and no
actor. `byrle account create --role admin` writes `account-created`, then `role-granted`.
A change made and not appended exits 1 and says so.

```
{"at":"2026-10-13T09:00:00Z","action":"account-created","account":"alice","source":"cli"}
{"at":"2026-10-13T09:00:00Z","action":"role-granted","account":"alice","role":"admin","source":"cli"}
```

A command only appends. The proxy rotates the file and writes `login`, `login-failed` and
`logout` to it, with the client's address as `source`
([console-login](engineering_decisions/console-login.md)). A line a command appends after
midnight and before the proxy's first write of the day is filed with the day before.

### 4.6 API

JSON over HTTP, under `api/v1/` below the console's path: `https://h/admin/api/v1/` for
`BYRLE_CONSOLE_URL=https://h/admin/`. Every endpoint needs a session cookie or a token,
and a permission from §4.2. Lists are paged by cursor and filtered by time range,
ecosystem, purl, account and `answered`.

| Endpoint | Requirement |
|---|---|
| `GET dependencies` | R3 |
| `GET alerts` | R4 |
| `GET requests?answered=refused&check=known_malware` | R5 |
| `GET metrics/failures` | R6: counts by case and hour |
| `GET config` | R7 |
| `GET events` | R8 |
| `GET requests`, and `GET logs/<date>` for a day's file | R9 |
| `GET`, `POST`, `DELETE` under `accounts` | R1, R2 |
| `GET status` | R10 |
| `GET health`, with no session or token | R10, for an external monitor |
| `POST login`, `POST logout`, `GET session` | R1. Built 2026-10-13 ([console-login](engineering_decisions/console-login.md)) |

`GET config` returns `proxy::Health` and the policy as `explain --policy` loads it.
`BYRLE_GITHUB_TOKEN` is reported as set or unset. `BYRLE_DATABASE_URL` is reported without
its password.

### 4.7 Web interface

Pages for each row of §4.6, rendered in Rust with `maud` (Q3, §8). Filters are forms and
links; charts are SVG rendered on the server.

Every page sends `Content-Security-Policy: default-src 'self'`, and state-changing requests
need a CSRF token. The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`.

### 4.8 Where it listens

Decided 2026-10-11 (Q2), revised the same day:
[console-listener](engineering_decisions/console-listener.md). `BYRLE_CONSOLE_URL` turns
the console on, and its path is where the console answers. `BYRLE_PROXY_URL`'s path is
where the proxy answers. The two may share a host and port, and are never at the same path.
`BYRLE_CONSOLE_LISTEN` gives the console a listener of its own; unset, it shares the
proxy's, and neither path may contain the other.

### 4.9 Status (R10)

`GET status`, and a page over it, reports each component with `up`, `degraded` or `down`,
the reason, and when it was checked:

| Component | Checked by | `degraded` or `down` when |
|---|---|---|
| proxy listener | an HTTP request from the console to `-/byrle/health` under the proxy's path at `BYRLE_LISTEN`, on loopback when it listens on every address | `down`: no answer within 2 s |
| proxy readiness | `-/byrle/ready` under the same path: `proxy::Readiness` | `degraded`: `ready` false, with `intel` (`empty`, `unavailable`) and `gaps` as the reason |
| management API | the console answering the request at all | not reported: a console that cannot answer cannot report it |
| database | a `SELECT 1` on `BYRLE_DATABASE_URL` | `down`: an error or no answer within 2 s |
| index writes | `usage_unrecorded` on health, the queue's dropped-row count (§4.3) | `degraded`: rows dropped since the last check |

The page reloads every 15 s with `<meta http-equiv="refresh">`, so it needs no JavaScript.
When the process stops, the reload fails in the browser, and that failure is the report.
Since the proxy and the console share one process (§4.8), an outage of the process takes
both down.

`GET health` needs no session or token, and returns `200` with `{"status":"up"}`, or `503`
with the components that are not `up`, by name only. It is for a monitor outside the
process, which is the only way to report the process itself down. Since 2026-10-11 it
answers `{"status":"up"}` whenever the console answers; the component checks come with
`GET status`.

## 5. Threat model changes

[threat-model](threat-model.md) gains a section on the console and the tokens:

- The login endpoint, with a rate limit per username and per source address.
- Sessions and tokens, stored hashed.
- `GET health` answers without credentials. It names components, not addresses or errors.
- The OIDC flow: `state`, `nonce` and PKCE are checked; the issuer is fixed in the
  configuration.
- The audit log names who installed what. Whoever can read the log files or the database
  can read it.
- "Default exposure" today says the proxy has no authentication. With 4.9 it requires a
  token unless `BYRLE_REQUIRE_TOKEN=0`.
- The log files are not signed, as today. Whoever can write them can change them.

## 6. Moves from Stage 8

| Stage 8 item | Moves | Stays |
|---|---|---|
| Accounts, and requests naming them | yes, to 4.9 | |
| A list of each user's own installs | the data, as `served_version` | the per-user view |
| Email on malware | the matching, as alerts | the outbox and email |
| Email on critical or high vulnerabilities | | yes |

## 7. Build order

1. Accounts and proxy tokens. 401 without a token. Update `byrle doctor`, the smoke
   scripts and `docs/quickstart.md`, which all send requests without one.
2. The audit log gains `account` and the §3 cases. Rotation, compression and retention for
   it.
3. Migrations for §4.3, and the proxy's writes to the index tables.
4. Roles, permissions, password login, sessions, the account event log.
   `byrle account create --role admin` for the first admin.
5. The API, R3 to R10.
6. The web interface.
7. OIDC.
8. Threat model and docs.

## 8. Decisions

| # | Question | Decided |
|---|---|---|
| Q1 | Does the proxy require a token? | Yes, by default; one per user; Artifactory's forms (§4.1) |
| Q2 | Where does the console listen? | At `BYRLE_CONSOLE_URL`'s path, on the proxy's listener or `BYRLE_CONSOLE_LISTEN`; revised 2026-10-11 (§4.8) |
| Q3 | Is the web interface Rust or TypeScript? | Rust, HTML from `maud`, for now ([console-web-interface](engineering_decisions/console-web-interface.md)) |
| Q4 | Which crates for passwords and OIDC? | `argon2` 0.6.0; `jsonwebtoken` 11.1.0 on `aws_lc_rs`, with the OIDC flow written here ([console-login-crates](engineering_decisions/console-login-crates.md)) |
| Q5 | How long are logs kept? | Files on disk, rotated daily, bzip2 from 3 days old, 365 days by default |

### Q3: Rust or TypeScript

Measured 2026-10-11. Rust: each crate added to a copy of this crate's `Cargo.lock`, 360
packages today. npm: `npm install --package-lock-only --ignore-scripts`, npm 11.21.0, which
resolves the tree without downloading or running any package.

| Option | Packages added | Shipped to the browser | Tests and coverage |
|---|---|---|---|
| A. Rust, HTML from `maud` templates | 3 crates: `maud`, `maud_macros`, `proc-macro2-diagnostics` | none; HTML and forms | `cargo test`, counted by `make coverage` |
| A'. Rust, HTML from `askama` templates | 6 crates | none | the same |
| B. TypeScript, React and Vite | 214 npm packages, with Vitest and its coverage | `react`, `react-dom`, `scheduler` | Vitest, a second coverage floor |
| B'. TypeScript, Preact and Vite | 232 npm packages | `preact` | the same |
| C. TypeScript, no framework, compiled by `tsc` | 1 npm package, `typescript` | none beyond our own code | `node --test` on the compiled output; 206 packages if Vitest and jsdom are added for DOM tests |

| | Rust (A) | TypeScript (B) |
|---|---|---|
| Languages in the repository | one | two; node joins the release build |
| Supply chain | 3 crates, reviewed through `cargo audit` as today | 214 packages that run on every build machine. A dependency firewall would ship one |
| The 100% coverage floor | the console is inside it | a second tool and floor, or the console is outside it |
| Interaction | a page per view; filters are forms and links; charts as SVG rendered on the server | filtering, paging and charts without page loads |
| The API | the pages call the same query functions the API does; the API is tested separately | the UI is the API's first client, so a gap in the API shows in the UI |
| Release | one binary | one binary, with the built assets embedded |

Option C sits between them: TypeScript for the pieces that need to run in the browser, such
as a chart that updates, built with `tsc` alone, on pages Rust renders.

Decided 2026-10-11, by the user: A, for now. A view that has to update without a page load
is the reason to revisit, with C first.

## 9. Exit

An admin logs in by password and, separately, through an OIDC provider. After a real
`npm install` and `pip install` through the proxy, each with its own user's token, each of
R3 to R9 shows those requests with the account that made them. A request without a token
is answered 401. A package given a test `MAL-` advisory after it was installed appears as
an alert. The status page shows the proxy `down` while its listener is closed, and
`degraded` while the intel store holds no snapshot. An account without the `admin` role
gets 403 from every endpoint except `GET health`.
