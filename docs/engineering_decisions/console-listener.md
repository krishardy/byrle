# The console listens on a second address in `byrle daemon`

- **Status:** Decided 2026-10-11, by the user. Not yet implemented. TODO Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §4.8

## Decision

`byrle daemon` opens a second listener for the console and its API at
`BYRLE_CONSOLE_LISTEN`. Unset, there is no console.

## Why

One process keeps the in-memory counters of `proxy::Health` visible to the console. A
second address keeps the console off the port package managers use.

## Rejected

| Option | Why not |
|---|---|
| The console on the proxy's port | Anyone who can reach the proxy reaches the login page |
| A separate `byrle console` process on the same database | It cannot read the proxy's in-memory counters |
