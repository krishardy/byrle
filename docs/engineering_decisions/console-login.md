# Console login: passwords

- **Status:** Implemented 2026-10-13 for setting a password. The values below were chosen
  by Claude and are not yet confirmed by the user. Login, sessions and the rate limit are
  not built. TODO Stage 4.9.
- **Related:** [admin-plan](../admin-plan.md) §4.1 and §4.5,
  [console-login-crates](console-login-crates.md)
- **Code:** `src/account/password.rs`, `src/account/command.rs`,
  `migrations/0021_account_password.sql`

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

## Rejected

| Option | Why not |
|---|---|
| The password as an argument | shell history, `ps` |
| A no-echo prompt with `rpassword` | a crate added for what `read -s` does |
| `argon2` default features | builds `getrandom` 0.4.3 beside 0.3.4 |
| A minimum of 8 | NIST's minimum when another factor is required; the console has none |
