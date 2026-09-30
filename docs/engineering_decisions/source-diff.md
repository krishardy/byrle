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
`{version}` and `{name}@{version}` that exists. No `git` binary or clone is needed.

The package is the directory of the source whose `package.json` names it: the
`repository.directory` the metadata gives, then the root, then the shallowest other.
`@emnapi/runtime` and `@humanfs/core` are in monorepos and give no `repository.directory`.
Before this, each was compared with its repository's root `package.json`.

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

The npm sets of [tier-1-false-positives](tier-1-false-positives.md): `express eslint`,
`next react react-dom`, `vite typescript vitest`, resolved on 2026-09-30. 271 versions.

| Outcome | Versions | Which |
|---|---|---|
| compared by `gitHead` | 182 | |
| compared by tag | 24 | |
| no `package.json` in the source names it | 30 | 15 `@rolldown/binding-*` and 11 `lightningcss-*`, whose manifests are generated at build; `cacheable`, `@cacheable/memory`, `@cacheable/utils`, `natural-compare` |
| source over 512 MiB | 21 | `typescript` 7.0.2 and its 20 `@typescript/typescript-*` binaries, all from `microsoft/typescript-go` |
| no `gitHead` and no tag found | 13 | 5 `@types/*` from DefinitelyTyped, `keyv`, `@keyv/bigmap`, `@keyv/serialize`, `file-entry-cache`, `flat-cache`, `@oxc-project/types`, `@rolldown/pluginutils`, `@swc/helpers` |
| no repository | 1 | `client-only` |

Of the 206 compared:

| Finding | Versions | Which |
|---|---|---|
| lifecycle scripts | 0 | |
| lifecycle files | 0 | |
| dependencies | 0 | |
| optional dependencies | 3 (1.5%) | `next`, `lightningcss`, `rolldown`: platform binaries added at publish |
| differing | 6 (2.9%) | below |
| differing Markdown | 5 | |
| only in the package | 97 (47%) | build output, such as `dist/` |

| Package | Differing files | Why |
|---|---|---|
| `react` 19.3.0, `react-dom` 19.3.0, `scheduler` 0.28.0 | 7, 13, 4 entry files | each published `index.js` is the source's `packages/*/npm/index.js`, copied at build over the ES module entry of the same name |
| `qs` 6.16.0 | `dist/qs.js` | `prepack` runs `npm run dist`, and the rebuilt bundle orders its modules differently from the committed one |
| `nanoid` 3.3.19 | 13 | comments stripped at publish, in `async/index.js` |
| `range-parser` 1.3.0 | `index.js` | not explained by a build. Below |

`range-parser` 1.3.0 was published on 2026-06-25 at 20:55 UTC by `blakeembrey`. Its
`gitHead`, `855f5b1`, is not on GitHub. Tag `v1.3.0` points at `f4bf173`, committed 2 minutes
before the publish. The published `index.js` has neither `f4bf173`'s clamp of a suffix
length (#66) nor `b49e00f`'s handling of mixed valid and invalid ranges (#63, 2026-01-23): it
returns `-2` where the tag's code skips an invalid range. The version has no attestation.

## Consequences

- The lifecycle and dependency findings fired on nothing in 206 versions. The corpus holds
  no known malicious version: npm removes them, so the tarballs of the 2025 incidents
  cannot be fetched. `a_package_is_compared_with_its_source` shows a `postinstall` and its
  file added at publish are found. That is a test of the mechanism, not a detection rate.
- Differing files are 2.9% here, and 5 of the 6 are build steps. A check on them would
  need a list of known build patterns.
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
and each finding. 22 hand mutants on it, each caught after four cases were added: a
shorthand whose owner has a dot, an archive at the limit, a lifecycle script the package
drops, and a quoted script target. `the_first_matching_member_is_read` holds the tar
walker's early stop, which survived a mutant before it.

To rerun, build the lockfiles as `examples/tier1_false_positives.py` does, then:

```
cargo run --release --example source_diff -- */package-lock.json
```
