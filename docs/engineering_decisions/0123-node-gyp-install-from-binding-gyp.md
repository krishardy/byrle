# An npm tarball with a `binding.gyp` runs `node-gyp rebuild` on install, as npm runs it

- **Number:** 0123
- **Status:** Decided by the user 2026-10-29, for finding 2 of the security review
  (TODO.md ad-hoc #50). Implemented 2026-10-29: `npm_install_scripts` and
  `npm_runs_node_gyp` in `src/analysis.rs`. `READER` is `install-scripts 6`.
- **Related:** [install-scripts-from-the-artifact](0062-install-scripts-from-the-artifact.md),
  [tarballs-read-as-the-widest-extractor](0122-tarballs-read-as-the-widest-extractor.md)

## Decision

The npm reader adds `install: node-gyp rebuild` when the tarball has an entry other than a
directory at `binding.gyp`, as npm extracts it, and some `package.json` in it has:

| Key | Value |
|---|---|
| `scripts.install` | absent, or one JavaScript reads as false: `""`, `0`, `null`, `false` |
| `scripts.preinstall` | the same |
| `gypfile` | anything but `false` |

A `package.json` that already declares a non-empty `install` keeps its own.

## Why

npm 11.21.1 runs it. `@npmcli/arborist` `lib/arborist/rebuild.js` `#addToBuildSet`:

```js
const isGyp = gypfile !== false &&
  !install &&
  !preinstall &&
  await isNodeGypPackage(node.path)
```

`isNodeGypPackage` is a `stat` of `<package>/binding.gyp` that is a file.
`@npmcli/run-script` `run-script-pkg.js` then runs `node-gyp rebuild`, and node-gyp runs
the `<!(...)` commands in `binding.gyp`.

`npm publish` writes this `install` into the registry's manifest, so `hasInstallScript`
is true. A manifest put to the registry directly can omit it. Before this change, the
metadata and the tarball then both said the version runs nothing.

## Cost

Every npm tarball is read again once, under the new `READER`. A package that builds with
node-gyp and declares no `install` was already counted through `hasInstallScript`, so no
version that served before is refused for this alone unless its metadata omitted it.
