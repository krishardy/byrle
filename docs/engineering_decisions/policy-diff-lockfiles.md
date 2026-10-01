# `policy diff` reads lockfiles

- **Status:** Implemented. `src/lockfile.rs` and `src/ecosystem/npm/lockfile.rs`; the option in `src/cli.rs`; the package set in
  `run_policy_diff`, `src/main.rs`.
- **Plan reference:** §3, policy impact analysis: "Package set from lockfiles or the audit
  log. Lockfiles give the full resolved graph including transitives; the audit log gives
  actual observed traffic, including packages resolved but never locked. Support both."

## Decision

`waharoa policy diff <from> <to> --lockfile <path>`, repeatable. The package set is every
registry version each lockfile locks, plus every version the audit log lists when
`WAHAROA_AUDIT_LOG` is set. Each version is compared once. With neither, the command exits 4:

```
waharoa policy diff: set WAHAROA_AUDIT_LOG or pass --lockfile, for the packages to compare over
```

| Rejected | Why |
|---|---|
| `--against <dir>`, reading every lockfile found under a directory, as the plan's example shows | chosen by the user: a path per lockfile says which files are read |
| A lockfile replaces the audit log | the plan asks for both; the log has versions resolved and never locked |

## Formats

The file name chooses the reader. A lockfile under any other name is refused.

| File | Read as | Where the package and version are |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | JSON, `lockfileVersion` 2 or 3 | an entry's `name`, else its key after the last `node_modules/`, and `version` |
| `yarn.lock` | yarn 1's text, by hand | the first descriptor, or the package after `npm:` in an alias, and `version` |
| `pnpm-lock.yaml` | YAML with `serde-saphyr`, `lockfileVersion` 9 | each `packages` key, `name@version` |
| `bun.lock` | YAML with `serde-saphyr`, `lockfileVersion` 0 to 3 | the first element of each `packages` value, `name@version` |
| `uv.lock`, `poetry.lock` | TOML | each `[[package]]`'s `name` and `version` |
| `requirements.txt` | pip's requirement lines | a line pinned with `==`, its name normalised |
| `Pipfile.lock` | JSON | each entry of `default` and `develop` whose `version` is an `==` pin |

In npm, yarn and bun an entry's key can be an alias. The fixtures lock `my-lodash` as
`npm:lodash@4.17.21`:

| File | The alias as written |
|---|---|
| `package-lock.json` | key `node_modules/my-lodash`, `"name": "lodash"` |
| `yarn.lock` | `"my-lodash@npm:lodash@4.17.21":` |
| `pnpm-lock.yaml` | key `lodash@4.17.21` |
| `bun.lock` | key `my-lodash`, first element `lodash@4.17.21` |

Each reader takes the package from the entry, so an alias is judged as `lodash@4.17.21`.

bun 1.3.14 writes `bun.lock` at `lockfileVersion` 1. bun 1.1.45, run from npm's
`@oven/bun-linux-x64` package with `bun install --save-text-lockfile`, wrote 0 for the same
`package.json`. bun 1.4.2 writes 2, or 3 while `overrides` holds a scoped rule. Its own
source (`src/install/lockfile/bun.lock.rs` at `bun-v1.4.2`) says what each changed:

| Version | Change |
|---|---|
| 1 | a workspace package's entry no longer lists its dependencies |
| 2 | stricter parsing of the same content: a tarball outside the configured registry must carry an integrity hash, and a git tag must be a safe path |
| 3 | an `overrides` value may be an object of scoped rules |

None of them changes a `packages` entry, and the reader does not read `overrides`, so 0 to
3 are read alike. Measured on bun 1.4.2 for a project with a workspace, a git dependency, a
`file:` dependency, a tarball URL and `esbuild`'s platform packages: every entry has the
version 1 shape.

`bun.lock` is JSON with trailing commas, which `serde_json` refuses. A YAML flow mapping
accepts them, and `serde-saphyr` already reads the policy, so no dependency is added.

## Which versions are kept

A version from a registry is kept. The rest are not versions a packument lists.

| Format | Not kept |
|---|---|
| all | a version that does not start with a digit: `file:../x`, `link:`, `workspace:`, `github:o/r#abc`, a tarball URL, `latest` |
| npm | an entry outside `node_modules` (the project, a workspace), a `link`, one `resolved` from other than `http://` or `https://` |
| yarn 1 | an entry with no `resolved` or one from other than `http://` or `https://`. yarn 1 writes `resolved` for every registry entry. Also an entry whose range has a `:` or `/` and is not an `npm:` alias: yarn 1.22 resolves `github:o/r#7.0.0` to a codeload.github.com URL and the repository's `version`, which read as a registry's until 2026-10-01 |
| uv | a package whose `source` is not `{ registry = ... }`: `{ git = ... }`, a path, and `{ virtual = "." }`, which is the project itself |
| poetry | a package whose `[package.source]` has a `type` other than `legacy`, which is another index. `git`, `url` and `directory` are not |
| `requirements.txt` | a line that is not an `==` pin: a range, `name @ url`, `name @ git+...`, `-e .`, an option. A file with lines and no pin at all is refused, because reading it as no packages would say the project depends on nothing |
| pipenv | an entry with no `==` version: one carrying `git` and `ref`, or `path`, or `file`. An `index` naming another source is kept, because another index is still an index |

A `requirements.txt` pins a package once per environment marker, so a project resolving
`urllib3` differently before and after Python 3.10 locks both versions, and both are
judged: each is installed somewhere.

Dev dependencies are kept. npm marks them `dev`, pnpm lists them under `devDependencies`, and
yarn 1 and bun do not record the difference, so no format could filter them the same way.

Refused, each with the reason after the path:

| Refused | Reason |
|---|---|
| `package-lock.json` at a `lockfileVersion` other than 2 or 3 | `lockfileVersion 1 is not read; npm 7 and later write 2 or 3` |
| `package-lock.json` with no `packages` | ``` `packages` is missing ``` |
| yarn 2 and later | ``not a yarn 1 lockfile: `# yarn lockfile v1` is missing`` |
| `pnpm-lock.yaml` before 9 | `lockfileVersion 6.0 is not read; pnpm 9 and later write 9.0` |
| `bun.lockb` | ``bun.lockb is binary; `bun install --save-text-lockfile` writes bun.lock`` |
| any other name | `a lockfile is read only under one of these names: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock` |

## Evidence

`tests/fixtures/lockfiles/` has the lockfile npm 9.9.4, yarn 1.22.22, pnpm 10.33.0 and bun
1.3.14 each wrote for one `package.json`: three dependencies, one an alias, and one dev
dependency, the `lockfileVersion` 0 file bun 1.1.45 wrote, and the version 2 and 3 files
bun 1.4.2 wrote on 2026-09-29. Each gives the same 15
package versions
(`each_manager_locking_the_same_project_gives_the_same_packages`).

The Python shapes were measured 2026-09-21 against uv 0.12.5 and poetry 2.2.1, with the
files in the same directory.

`policy diff` from `max_cvss: 7.0` to `max_cvss: 9.0`, `WAHAROA_AUDIT_LOG` unset, over the
kept npm snapshot, debug build. Each of the four lockfiles alone gives this report, and all
four together give the same 15 packages:

```
15 packages evaluated
2 moved

      2  max_cvss LOOSER

pkg:npm/lodash@4.17.20  block -> allow
    max_cvss          FAIL block -> pass  (LOOSER)
pkg:npm/lodash@4.17.21  block -> allow
    max_cvss          FAIL block -> pass  (LOOSER)

waharoa policy diff: 2 loosened, 0 incomparable
```

Refused, each exit 2 when run, and 4 since
[policy-diff-dates-and-exit-bits](policy-diff-dates-and-exit-bits.md):

```
waharoa policy diff: set WAHAROA_AUDIT_LOG or pass --lockfile, for the packages to compare over
waharoa policy diff: tests/fixtures/lockfiles/package.json: a lockfile is read only under one of these names: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock
waharoa policy diff: .../nowhere/yarn.lock: No such file or directory (os error 2)
```

A larger project, `express`, `react`, `react-dom` and `@aws-sdk/client-s3` with `typescript`,
`eslint`, `webpack` and `jest` as dev dependencies, locked by `npm install` (268,644 bytes)
and carried to the other managers:

| Lockfile | Made by | Package versions | Not in npm's |
|---|---|---|---|
| `package-lock.json` | `npm install --ignore-scripts` | 545 | |
| `pnpm-lock.yaml` | `pnpm import` | 545 | 0 |
| `bun.lock` | `bun install --lockfile-only`, next to `package-lock.json` | 545 | 0 |
| `yarn.lock` | `yarn import --ignore-engines`, from `node_modules` | 547 | 2 |

`yarn import` refused `lockfileVersion` 3 as `source file(s) corrupted`, and refused
`node_modules` as `Found incompatible module` under Node 16 until `--ignore-engines`. Its 2
extra versions are in `yarn.lock`:

```
"@aws-sdk/types@^3.222.0":
  version "3.974.5"
"@smithy/types@^4.17.2":
  version "4.18.0"
```

npm resolved `@aws-sdk/types@^3.222.0` to the 3.370.0 it already had, and has no
`@smithy/types` 4.

Each mutation below was caught:

| Mutation | Caught by |
|---|---|
| A scope's `@` taken as the one before the version | `each_manager_locking_the_same_project_gives_the_same_packages`, and the pnpm and yarn tests |
| Any version text kept | `npm_keeps_only_registry_versions_under_node_modules`, and the pnpm and bun tests |
| Any `resolved` source kept | the same npm test, `yarn_reads_the_first_descriptor_and_keeps_only_registry_entries` |
| An `http://` registry dropped | `npm_keeps_only_registry_versions_under_node_modules` |
| npm's nested name read after the first `node_modules/` | the same |
| npm's alias judged under its alias | `each_manager_locking_the_same_project_gives_the_same_packages` |
| npm's `link` kept | `npm_keeps_only_registry_versions_under_node_modules` |
| npm at any `lockfileVersion` read | `npm_other_than_lockfile_version_2_or_3_and_json_that_does_not_parse_are_refused` |
| npm with no `packages` read as none | the same |
| yarn's `# yarn lockfile v1` not required | `a_yarn_file_that_is_not_a_yarn_1_lockfile_is_refused_with_the_line` |
| yarn's nested `version` read as the entry's | `yarn_reads_the_first_descriptor_and_keeps_only_registry_entries` |
| yarn's alias judged under its alias | the same, and the fixture test |
| yarn's alias with no range judged under its alias | the same yarn test |
| yarn's last entry dropped | the same, the fixture test and the refusal test |
| yarn's entry with no `resolved` kept | `yarn_reads_the_first_descriptor_and_keeps_only_registry_entries` |
| pnpm at any `lockfileVersion` read | `pnpm_before_lockfile_version_9_is_refused` |
| pnpm's keys that are not registry versions kept | `pnpm_keeps_only_registry_package_keys` |
| bun at `lockfileVersion` 2 read | `bun_keeps_only_registry_entries_and_refuses_what_it_cannot_read` |
| bun's entries that are not registry versions kept | the same |
| `bun.lockb` given no hint | `a_file_is_refused_by_its_name_and_by_what_it_contains` |

The first run had npm's version check as one match on version and `packages`, and the mutation
reading any `lockfileVersion` survived: no test gave a version above 3. The check is now two
refusals, each with a test.

The union and the once-each rule are in `src/main.rs`, which no test runs. The run with all
four lockfiles, 15 packages evaluated, is their evidence.
