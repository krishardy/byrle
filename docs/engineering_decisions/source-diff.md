# Registry tarball against its source, measured

- **Status:** Measured 2026-09-30, report only, not in the proxy. `src/analysis/source.rs`,
  measured by `examples/source_diff.rs`.
- **Related:** [tier-1-false-positives](tier-1-false-positives.md),
  [install-scripts-from-the-artifact](install-scripts-from-the-artifact.md),
  [metadata-heuristics](metadata-heuristics.md),
  [npm-packument-shapes](npm-packument-shapes.md)

## Decision

An npm version's published tarball is compared with the source it names. The source is
GitHub's archive (`codeload.github.com/{owner}/{repo}/tar.gz/{ref}`) at the version's
`gitHead`, the commit npm records at publish, else the first of the tags `v{version}`,
`{version}`, `{name}@{version}` and, for a scoped name, `{name without scope}@{version}`
that exists. No `git` binary or clone is needed.

The package is the directory of the source whose publishable `package.json` names it: the
`repository.directory` the metadata gives, then the root, then the shallowest other.
Publishable means a string `version` and not `"private": true`, as `npm publish` requires.

| Package | Without the rule, compared with |
|---|---|
| `@emnapi/runtime`, `@humanfs/core` | the repository root's `package.json`: they give no `repository.directory` |
| `cypress`, `tldts` | a private root `package.json` of the same name |
| `electron` | `default_app/package.json`, named `electron`, with no `version` |

Both archives are read into path and SHA-256 pairs, with every `\r` removed. The first path
component is dropped from each: `package/` and `{repo}-{commit}/`. A source archive whose
headers state more than 512 MiB is not read.

| Finding | What it compares |
|---|---|
| lifecycle scripts | `preinstall`, `install` and `postinstall` in the published `package.json` that the source's lacks or has with another body |
| dependencies | names in the published `dependencies` that the source's lacks |
| optional dependencies | the same for `optionalDependencies` |
| lifecycle files | files a lifecycle script names, as a word or the word plus `.js`, that the source lacks or has different |
| differing | paths in both whose content differs, `package.json` and Markdown aside |
| differing Markdown | the same for `.md` files |
| only in the package | paths the source lacks |

npm only. A PyPI record has no repository, and a wheel is built output.

## Results

Two sets, resolved on 2026-09-30, measured separately. They share one version, `qs` 6.16.0.

| Set | Packages asked for |
|---|---|
| tier 1 | the npm sets of [tier-1-false-positives](tier-1-false-positives.md): `express eslint`, `next react react-dom`, `vite typescript vitest` |
| install scripts | `esbuild sharp bufferutil utf-8-validate bcrypt sqlite3 core-js puppeteer protobufjs @swc/core better-sqlite3 node-sass cypress electron re2` |

| Outcome | Tier 1 | Install scripts |
|---|---|---|
| versions | 271 | 492 |
| compared by `gitHead` | 182 | 450 |
| compared by tag | 25 | 23 |
| of those by tag, with a `gitHead` GitHub does not have | 1 | 1 |
| no `package.json` in the source names it | 30 | 3 |
| source over 512 MiB | 21 | 0 |
| `gitHead` GitHub does not have, and no tag | 0 | 5 |
| no `gitHead`, and no tag | 12 | 11 |
| no repository | 1 | 0 |

| Not compared | Which |
|---|---|
| no `package.json` names it | 15 `@rolldown/binding-*` and 11 `lightningcss-*`, whose manifests are generated at build; `cypress` and `electron`, the same; `cacheable`, `@cacheable/memory`, `@cacheable/utils`, `natural-compare`, `undici-types` |
| over 512 MiB | `typescript` 7.0.2 and its 20 `@typescript/typescript-*` binaries, all from `microsoft/typescript-go` |
| `gitHead` GitHub does not have | `decamelize-keys`, `http-cache-semantics`, `lines-and-columns`, `performance-now`, `process` |
| no `gitHead`, no tag | 11 `@types/*` from DefinitelyTyped; `keyv`, `@keyv/bigmap`, `@keyv/serialize`, `file-entry-cache`, `flat-cache`, `@oxc-project/types`, `@swc/helpers`, `@swc/types`, `@swc/counter`, `concat-map`, `github-from-package`, `lodash.once` |

### Findings

A lifecycle file can only be found in a version whose install script names a file in the
package. The other findings can be found in any compared version.

| Finding | Tier 1 | Install scripts |
|---|---|---|
| compared | 207 | 473 |
| lifecycle scripts added or changed | 0 of 207 | 0 of 473 |
| dependencies added | 0 of 207 | 0 of 473 |
| optional dependencies added | 3 | 1 |
| install script names a file in the package | 0 | 5 |
| lifecycle files absent or different | 0 of 0 | 2 of 5 |
| differing | 6 | 3 |
| differing Markdown | 5 | 14 |
| only in the package | 98 | 150 |

| Package | Finding | Why |
|---|---|---|
| `next`, `lightningcss`, `rolldown`, `@swc/core` | optional dependencies | platform binaries added at publish |
| `esbuild` 0.28.2 | lifecycle file `install.js` absent | `npm/esbuild/install.js` is not in the source at `gitHead`: the build writes it |
| `@swc/core` 1.16.12 | lifecycle file `postinstall.js` differs | compared by tag `v1.16.12`, whose `postinstall.js` has an `SWC_SKIP_VALIDATION` check the published one lacks |
| `react` 19.3.0, `react-dom` 19.3.0, `scheduler` 0.28.0 | 7, 13, 4 differing entry files | each published `index.js` is the source's `packages/*/npm/index.js`, copied at build over the ES module entry of the same name |
| `qs` 6.16.0 | `dist/qs.js` differs | `prepack` runs `npm run dist`, and the rebuilt bundle orders its modules differently from the committed one |
| `nanoid` 3.3.19 | 13 differing | comments stripped at publish, in `async/index.js` |
| `js-base64` 2.6.4 | `base64.js` differs | the published file has the BSD 3-Clause header; the file at `gitHead` has the older MIT one |
| `range-parser` 1.3.0 | `index.js` differs | below |

`range-parser` 1.3.0 was published on 2026-06-25 at 20:55 UTC by `blakeembrey`. Its
`gitHead`, `855f5b1`, is not on GitHub, so it was compared by tag. Tag `v1.3.0` points at
`f4bf173`, committed 2 minutes before the publish. The published `index.js` has neither
`f4bf173`'s clamp of a suffix length (#66) nor `b49e00f`'s handling of mixed valid and
invalid ranges (#63, 2026-01-23): it returns `-2` where the tag's code skips an invalid range.
The version has no attestation. Its `scripts` are `lint`, `test`, `test-ci` and `test-cov`:
no build step.

## Consequences

- Lifecycle scripts and dependencies added at publish: 0 of 207 and 0 of 473. The
  corpus holds no known malicious version: npm removes them, so the tarballs of the 2025
  incidents cannot be fetched. `a_package_is_compared_with_its_source` shows a `postinstall`
  and its file added at publish are found. That is a test of the mechanism, not a detection
  rate.
- Lifecycle files: 2 of the 5 versions where one could be found, and both are a build step
  or a tag that is not the publish commit. A check on them would refuse `esbuild`.
- Differing files: 6 of 207 and 3 of 473. In tier 1, 5 are build steps and `range-parser`
  is not. In the install-script set, `qs` is a build step, `@swc/core` was compared with a
  tag, and `js-base64` is not explained. A check on them would need a list of known build
  patterns.
- In the proxy this would fetch from `codeload.github.com`, a host the proxy does not reach
  today.

## Found on the way

`react`, `react-dom` and `scheduler` write `"deprecated": false`, and `qs` writes
`"repository": {}`. Each made its whole full packument unreadable, so the proxy forwarded
those documents unfiltered. They now read as absent
([npm-packument-shapes](npm-packument-shapes.md)).

## Tests

`src/analysis/source.rs` covers every repository URL form npm accepts and hosts that are not
GitHub, the order of references, reading an archive, finding a monorepo package, the limit,
and each finding. 27 hand mutants on it, each caught after four cases were added: a
shorthand whose owner has a dot, an archive at the limit, a lifecycle script the package
drops, and a quoted script target. The five on the publishable-manifest rule, the unscoped
tag and the lifecycle target count were caught when written. `the_first_matching_member_is_read` holds the tar
walker's early stop, which survived a mutant before it.

To rerun, build the lockfiles as `examples/tier1_false_positives.py` does, one directory per
set, then:

```
cargo run --release --example source_diff -- */package-lock.json
```
