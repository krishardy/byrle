# The analysis commands are answered by a deployed byrle, through the console API

- **Number:** 0118
- **Status:** Decided by the user 2026-10-19, as TODO.md ad-hoc #41 and
  [remote-cli-plan](../remote-cli-plan.md). Implemented 2026-10-19: `src/remote.rs`, the
  client; `console::commands`, the routes; `make smoke-console` step 9.
- **Related:** [admin-plan](../admin-plan.md) §4.2 and §5, [explain-output](0084-explain-output.md),
  [policy-check](0034-policy-check.md)

## Decision

With `BYRLE_REMOTE_URL` set to a deployment's console URL and `BYRLE_TOKEN` to an account's
token, `byrle explain`, `artifact show` and `export`, `intel history`, `status`, and `policy
check` and `diff` ask the deployment, which answers from its policy in force, intel store,
analysis store, audit log and upstreams. Without it they run locally, as before.

| Question | Answer |
|---|---|
| Where | routes under the console's `api/v1`, authenticated as every console route is: a session cookie, or a proxy token |
| Who | `packages.read`, a new permission, held by `admin` and by `reader`, a new role holding every `*.read` permission and no `*.write` |
| What a route returns | what the command printed on the deployment, `{"stdout", "stderr", "code"}`, which the client prints and exits with; `artifact export`'s JSON Lines in `stdout` too |
| What the client sends | the command's arguments; a candidate policy and a lockfile as a `POST` body. `policy diff` takes the candidate alone: the policy in force is the deployment's |

## Why

The user, 2026-10-17: an analysis question about a deployment should not need the
deployment's policy file, environment or intel store on the asker's machine. The console
already authenticates tokens and checks a permission on every route, so the commands are
routes on it rather than a second listener.

## Rejected

| Option | Why not |
|---|---|
| Routes under the proxy's `/-/byrle/` | the user chose the console, which has permissions and `openapi.json` |
| Any account with a token, or `admin` only | the user chose a read role |
| `--remote <url>` on each command, or a `byrle remote` tree | the user chose the environment, so the commands stay the same |
| The deployment returns structured data and the client renders it | two renderers to keep the same; the local command's text is the contract `explain-output` already fixes |
