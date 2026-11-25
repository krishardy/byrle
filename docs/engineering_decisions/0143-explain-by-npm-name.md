# `byrle explain` and `artifact show` take a purl with `--purl`, or npm's `name@version` with `--npm`

- **Number:** 0143
- **Status:** Implemented 2026-11-25. `src/cli.rs` (`npm_purl`, `npm_artifact`),
  `src/ecosystem/npm/paths.rs` (`printed_purl`), `src/analysis/decision.rs`
  (`Artifact::digest`, `Artifact::version`), `src/main.rs`.
- **Related:** [explain-output](0084-explain-output.md),
  [remote-analysis-commands](0118-remote-analysis-commands.md)

## Decision

| Form | Takes | Asks about |
|---|---|---|
| `explain --policy` | nothing | the policy |
| `explain --purl <purl>` | a purl, as before | that purl, exactly |
| `explain --npm <name@version>` | the name and version npm prints in an error | the npm purl built from them |

| `artifact show --digest <digest>` | a Subresource Integrity digest | that artifact |
| `artifact show --purl <purl>` | a purl with a version | each artifact of that version |
| `artifact show --npm <name@version>` | as `explain --npm` | as `--purl`, with the npm purl |

Each command takes exactly one of its forms. Neither takes a positional argument any more:
`byrle explain pkg:npm/a@1.0.0` and `byrle artifact show pkg:npm/a@1.0.0` exit 2 with
clap's unknown-argument error. `--digest` refuses a purl and `--purl` a digest.

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

`--npm` is parsed by clap, with `printed_purl` from the npm adapter, so an argument that
is not a name@version exits 2 before anything runs. `cli.rs` calls it from `npm_purl`, the
one line outside an adapter that names npm, and `only_the_adapters_name_an_ecosystem`
allows that line.

The first line `explain` prints is the purl, so the result shows which purl `--npm` built.

A remote `explain` or `artifact show` (`BYRLE_REMOTE_URL` set) builds the purl on the
client and sends it as the `purl` or `artifact` query parameter. `GET /api/v1/explain` and
`GET /api/v1/artifact` are unchanged.

## Rejected

- **Keeping the positional purl beside the flags.** Two spellings for one argument. byrle
  is at 0.1.0, so the positional form is removed rather than kept.
- **Guessing the ecosystem from the argument.** `a@1.0.0` names a package in npm, and a
  version in no other ecosystem's syntax, but a later `--pypi` or `--cargo` would make the
  guess ambiguous. A flag per ecosystem names it.
- **Accepting the tarball URL from npm's 403 message**, such as
  `http://127.0.0.1:8080/npm/@babel/runtime/-/runtime-7.29.15.tgz`. Not done yet. The
  audit log names the package and version of each refused fetch.
