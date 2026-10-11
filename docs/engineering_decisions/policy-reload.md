# The policy reloads on SIGHUP, and each request keeps the policy it started with

- **Status:** Implemented 2026-09-28. `Proxy::replace_policy`, `Proxy::current`,
  `startup::reload_policy` and `startup::reload_on_hangup`.
- **Related:** [reproducible-verdicts](reproducible-verdicts.md),
  [policy-check](policy-check.md), [observe-mode](observe-mode.md)

## Decision

`SIGHUP` loads `BYRLE_POLICY` again through the same `report_policy` startup uses: the
expiry ceiling, the package checks, and the same log lines. A file that loads replaces the
policy in force. One that does not, or an unset `BYRLE_POLICY`, leaves it in force, and
the log says which digest is kept and why.

`Proxy` holds the configuration it was built with and, after a reload, a replacement behind
a lock. `handle` takes one snapshot at the start of each request. The decision, the audit
line and the metadata filtering of one request therefore read one policy. The audit line's
policy digest names the policy the decision used.

Only the policy is reloaded. `BYRLE_MODE` and every other variable are read at startup.

## Rejected

| Option | Why |
|---|---|
| restart to change the policy | drops connections in flight and loses the in-process record store and deferral counts |
| watch the file for changes | an editor's partial write would be loaded. A signal is sent once the file is written and checked |
| a lock read at each use of the policy | a reload between the decision and the audit line would record a digest the decision did not use |
