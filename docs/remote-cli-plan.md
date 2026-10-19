# Plan: analysis commands run against a deployed byrle (TODO.md ad-hoc #41)

Today `byrle explain`, `artifact`, `intel history`, `status` and `policy check` and `diff`
read the policy file, the `BYRLE_*` environment, Postgres and the registries on the machine
that runs them, so only a machine set up as the proxy is can answer. After this plan, a user
with a token and the console's URL runs the same commands from their own machine, and the
deployment answers them. Written 2026-10-19 from the code at `d38ddab`.

## Decisions

Decided by the user 2026-10-19:

| Question | Answer |
|---|---|
| Commands | `explain` (a purl and `--policy`), `artifact show` and `export`, `intel history`, `status`, `policy check` and `diff` |
| Where they are answered | new routes under the console's `api/v1`, in `openapi.json`, authenticated as every console route is |
| Who may | a new permission, `packages.read`, held by `admin` and by a new role, `reader`, which holds every `*.read` permission and no `*.write` |
| How a user points the CLI | `BYRLE_REMOTE_URL`, the console's URL, and `BYRLE_TOKEN`. With the URL set, those commands ask the deployment; without it they run locally as today |

## Today

| Command | Reads locally |
|---|---|
| `explain <purl>` | `BYRLE_POLICY`, the registries (`BYRLE_UPSTREAM_*`), the intel store when `BYRLE_DATABASE_URL` is set |
| `explain --policy` | `BYRLE_POLICY`, the intel store |
| `artifact show`, `artifact export` | the analysis store, `BYRLE_DATABASE_URL` required |
| `intel history` | the intel store |
| `status` | the upstreams, the intel store's snapshot |
| `policy check <path>` | the file, the expiry ceiling; with `--fetch`, the registries |
| `policy diff <in-force> <candidate>` | both files, the registries, the audit log, the intel store; `--lockfile` a local lockfile |

The console already admits a proxy token as `Authorization: Bearer`, `Basic` or
`X-Byrle-Token` (`console/api.rs:224`, `account/gate.rs`), and refuses a caller whose roles
lack a route's permission with 403. `GET api/v1/config` returns the `explain --policy` report
among the configuration; no route decides a package.

## Design

- **The deployment runs the command and returns what it printed.** Each route answers
  `{"stdout": ..., "stderr": ..., "code": ...}`, from the same functions the local command
  calls, and the client prints them and exits with `code`. So the remote command prints
  what the local one would on the deployment, and there is one renderer. `artifact export`
  is the exception: its route streams the NDJSON, as `api/v1/logs/{day}` does.
- **Inputs the client sends.** A purl, a digest, dates and limits as query parameters. A
  candidate policy for `check` or `diff`, and a lockfile for `diff --lockfile`, as the body
  of a `POST`. Under `BYRLE_REMOTE_URL`, `policy diff` takes the candidate alone: the policy
  in force is the deployment's.
- **What the deployment uses.** Its policy in force, its intel store, its analysis store,
  its audit log and its upstreams: what the proxy itself decides on.
- **Nothing local is read** under `BYRLE_REMOTE_URL` but the files named on the command
  line. `BYRLE_POLICY` and `BYRLE_DATABASE_URL` set too are ignored, with a note on stderr.
- **Refusals.** No token: exit 2 naming `BYRLE_TOKEN`. 401 or 403: exit 2 with the
  console's `error`. A deployment that does not answer: exit 2.

## Steps

1. Decision `0118` for the four answers, and `docs/admin-plan.md` §4.2's roles amended.
2. `Permission::PackagesRead` and `Role::Reader`; `account create --role reader`. Done 2026-10-19.
3. The client: `BYRLE_REMOTE_URL` and `BYRLE_TOKEN` in `env.rs`, a `remote` module that asks
   a route and prints the answer, and `explain` (`GET api/v1/explain?purl=`, and `GET
   api/v1/explain` for `--policy`) on both sides. Done 2026-10-19: `remote::Remote` and `remote::Printed`,
   `console::commands::explain`, and `explain::run_on` on the proxy's policy, intel store and
   clients. `warm`'s token client moved to `http::token_client` for both.
4. `artifact show` (`GET api/v1/artifacts/{digest or purl}`) and `artifact export` (`GET
   api/v1/artifacts?since=&until=`, NDJSON).
5. `intel history` (`GET api/v1/intel/history?limit=`) and `status` (`GET
   api/v1/ecosystems`).
6. `policy check` (`POST api/v1/policy/check`) and `policy diff` (`POST api/v1/policy/diff`).
7. `make smoke-console` asks each route through the CLI with a `reader` token, and is
   refused with a token of an account with no role. Docs: `docs/console-api.md`,
   `docs/admin-plan.md`, the README, `docs/runbook.md`.
