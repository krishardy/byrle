# Real packages that are safe to test against

- **Status:** Decided 2026-09-29. For tests and smoke runs against the real registries.
- **Related:** [install-scripts-from-the-artifact](install-scripts-from-the-artifact.md),
  [osv-malware-load](osv-malware-load.md)

## Decision

Each package below was read before being listed: its metadata and every file it installs.

| Ecosystem | Package | Exercises | Why it is safe |
|---|---|---|---|
| npm | `clinstestpackage@0.0.1-security` | `known_malware`: MAL-2022-1929 covers every version (`introduced: 0`) | npm replaced the package with its security placeholder: no scripts, no dependencies, no code |
| npm | `kottestpackage`, `testpackagehere`, both `0.0.1-security` | the same, as MAL-2022-4217 and MAL-2022-6528 | the same |
| npm | `core-js@3.39.0` | `install_scripts`: `postinstall` runs `postinstall.js` | the script prints a funding banner, skipped in CI or with `ADBLOCK` set, and writes a list of banners shown to `core-js-banners` in the OS temp directory. No dependencies |
| npm | `eicar@1.0.0` | an antivirus scanner on the path. No byrle check refuses it | two files; `README.md` holds the EICAR string. Published 2018 by Adam Baldwin |
| PyPI | `docopt==0.6.2` | `install_scripts`: the version offers only an sdist, so installing runs `setup.py` | `setup.py` is a plain `setup()` call that imports only `docopt.__version__` |
| PyPI | `test-eicar==0.1.0` | an antivirus scanner on the path | one wheel: `test_eicar.txt` holds the EICAR string, `main.py` prints `Hello World!`. A wheel runs no code on install. Uploaded 2025-09-03, no author given |

## No PyPI package tests `known_malware`

PyPI deletes a malicious project rather than leaving a placeholder. Of 600 sampled PyPI
`MAL-` records covering every version, all 600 projects answered 404 on 2026-09-29. Of the
289 whose names suggest a test or proof of concept, one still exists, `hack-test`, and its
versions are not the ones MAL-2024-12281 lists. `known_malware` on PyPI is tested against a
stub index.

## Rejected

| Package | Why not |
|---|---|
| npm `eicar-test@0.0.1` | published 2026-06-23 by an unknown account and not read |
| npm `esbuild@0.20.2` | its `postinstall` checks its platform binary, and it pulls 23 platform packages |
| npm `bufferutil@4.1.0`, `fsevents@2.3.3` | `install` may build native code; `fsevents` is macOS only |
| PyPI `eicar==0.0.0` | a held name: no EICAR string, README "Hogging this space for future use" |
| PyPI `hack-test` | unknown author, versions no MAL record covers |
