# `byrle explain` takes a purl with `--purl`, or npm's `name@version` with `--npm`

- **Number:** 0143
- **Status:** Implemented 2026-11-25. `src/cli.rs`, `src/explain.rs` (`purl_of`),
  `src/ecosystem/npm/paths.rs` (`printed_purl`), `src/main.rs`.
- **Related:** [explain-output](0084-explain-output.md),
  [remote-analysis-commands](0118-remote-analysis-commands.md)

## Decision

| Form | Takes | Asks about |
|---|---|---|
| `explain --policy` | nothing | the policy |
| `explain --purl <purl>` | a purl, as before | that purl, exactly |
| `explain --npm <name@version>` | the name and version npm prints in an error | the npm purl built from them |

Exactly one of the three is given. The purl is no longer a positional argument:
`byrle explain pkg:npm/a@1.0.0` exits 2 with clap's unknown-argument error.

npm prints a refused version as `@anthropic-ai/sdk@1.14.0`, for example in
`No matching version found for @anthropic-ai/sdk@1.14.0.` Its purl is
`pkg:npm/%40anthropic-ai/sdk@1.14.0`. `--npm` takes the first form and builds the second:

- The version starts at the last `@` past the first character, so a scope's `@` is part
  of the name.
- A trailing `.`, where npm ends its sentence, is dropped. No semver version ends in `.`.
- The version must parse as one semver version. A range such as `^4.17.0` exits 2, because
  a decision is about one version.
- The name is split into scope and name by `ecosystem::npm::paths::split_name`, as a name
  from the registry is.

`printed_purl` is in the npm adapter. `explain.rs` calls it, the one line outside an
adapter that names npm, and `only_the_adapters_name_an_ecosystem` allows that line.

The first line `explain` prints is the purl, so the result shows which purl `--npm` built.

A remote `explain` (`BYRLE_REMOTE_URL` set) builds the purl on the client and sends it as
the `purl` query parameter. `GET /api/v1/explain` is unchanged.

## Rejected

- **Keeping the positional purl beside the flags.** Two spellings for one argument. byrle
  is at 0.1.0, so the positional form is removed rather than kept.
- **Guessing the ecosystem from the argument.** `a@1.0.0` names a package in npm, and a
  version in no other ecosystem's syntax, but a later `--pypi` or `--cargo` would make the
  guess ambiguous. A flag per ecosystem names it.
- **Accepting the tarball URL from npm's 403 message**, such as
  `http://127.0.0.1:8080/npm/@babel/runtime/-/runtime-7.29.15.tgz`. Not done yet. The
  audit log names the package and version of each refused fetch.
