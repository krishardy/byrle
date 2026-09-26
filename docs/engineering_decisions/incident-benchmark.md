# The Tier 1 controls against the 2025 npm incidents

- **Status:** Measured 2026-09-26. The Stage 4 benchmark against known incidents. Pairs with
  [tier-1-false-positives](tier-1-false-positives.md), which measured what the same controls
  refuse in packages nobody reported.
- **Related:** [provenance-check](provenance-check.md),
  [install-scripts-from-the-artifact](install-scripts-from-the-artifact.md),
  [quarantine-filter-metadata](quarantine-filter-metadata.md)

## Method

The malicious versions come from GitHub's malware advisories and the maintainers' own
statements. Publish times and the provenance of the versions before them come from the npm
registry: a removed version keeps its entry in the packument's `time`, and loses its
manifest. Whether a malicious version ran an install script, whether it carried provenance,
and when it was removed come from published reports, each with its source below. The
registry cannot say: npm's attestations endpoint answers 404 for every removed version,
attested or not.

Each control is judged on its own, with `known_malware` left out. That check refuses
anything an advisory stream has reported, from the moment the stream loads it.

## Results

| Incident | Malicious versions | `cooldown_days: 7` | `install_scripts: block` | `provenance: block` |
|---|---|---|---|---|
| chalk/debug, 2025-09-08 | 19 | all, removed within 7 h | none: the payload runs on import | none: no earlier version attested |
| DuckDB, 2025-09-09 | 4 | all if removed within 7 days; removal time not sourced | all, as every legitimate `duckdb` version is refused too: it declares `node-pre-gyp install` | none: no earlier version attested |
| Shai-Hulud, 2025-09 | 187+ packages | all if removed within 7 days; removal time not sourced | all: `postinstall: node bundle.js` | 15 of 173 packages had an attested version just before |
| Sha1-Hulud 2.0, 2025-11-24 | 1,091 versions, 795 packages | as above | all: `preinstall: node setup_bun.js` | 3 of 741 packages |
| Nx s1ngularity, 2025-08-26 | 19 | all, removed 4 to 12 h after publish | `nx`: every version, legitimate `nx` already runs a postinstall; `@nx/*`: not sourced | 6 of 19 |
| eslint-config-prettier and 4 others, 2025-07-18 | 9, plus `got-fetch` | all if removed within 7 days; deprecation began 2 h after publish | `install.js` per the advisory; which versions carried it is not sourced | 5 of 9 |
| xrpl.js, 2025-04-21 | 5 | all if removed within 7 days; the fix was published 16 h later | none: the payload runs on import | none: no earlier version attested |

### What each control stands on

- **Cooldown.** Every incident's malicious versions were live for hours, and a 7-day
  cooldown keeps a version out of resolution and refuses a pinned fetch of it for 7 days.
  Removal times are sourced for two incidents: npm reported the chalk versions down by
  19:59Z, under 7 hours after publish, and the Nx advisory gives 02:44Z and 10:20Z the next
  day. For the rest, the replacement or deprecation came within a day, and the removal time
  is not published.
- **Install scripts.** Both Shai-Hulud waves run on install, and so did Nx and
  eslint-config-prettier. chalk, DuckDB and xrpl ran on import, which no install-script
  policy sees. Where the legitimate package already runs an install script, as `nx` and
  `duckdb` do, `block` refuses the malicious version only by refusing the package, and an
  exception that releases the package releases the malicious version too.
- **Provenance.** It can only fire where the package published attested versions before
  the attack. For Nx and eslint-config-prettier the malicious versions are confirmed
  unattested and the versions before them attested. For the other incidents no source
  says whether the malicious versions carried provenance. Each was published with a stolen
  token outside CI, which leaves nothing to attest with.

## A burst of versions escapes the provenance check as built

The check compares a version with the one published immediately before it. An attacker
who publishes several versions in a burst makes each one after the first the predecessor
of the next, and an unattested version after an unattested one passes. Nx published 19
malicious versions over two hours: the first `21.5.0` of each package follows an attested
canary and is refused. Of the other 13, 11 follow a malicious version, and `@nx/key` and
`@nx/enterprise-cloud` never published an attested version.

Refusing an unattested version when any earlier version of the package was attested closes
it:

| Incident | Versions checked | Previous version by publish time (as built) | Any earlier version attested |
|---|---|---|---|
| Shai-Hulud, the `@ctrl/tinycolor`, `ngx-bootstrap`, `ngx-toastr` sample | 11 | 1 | 2 |
| Nx s1ngularity | 19 | 6 | 17 |
| eslint-config-prettier and eslint-plugin-prettier | 6 | 2 | 6 |

On the 271 npm versions of [tier-1-false-positives](tier-1-false-positives.md), both rules
refuse the same one, `why-is-node-running` 3.2.2.

Decided 2026-09-26: the version just before, and every version in a window,
`provenance_window_days`, 7 by default. It catches the burst as well as any earlier version
does, 17 of 19 for Nx, and misses 4 of the 6 eslint-config-prettier versions, whose last
attested release was more than 7 days earlier and was not the one just before. On the 271
benign npm versions it refuses the same single one.

## Sources

| Fact | Source |
|---|---|
| chalk/debug version list, 2FA-reset phishing | https://github.com/debug-js/debug/issues/1005#issuecomment-3266868187 |
| chalk payload in `index.js`; `error-ex` 1.3.3 | https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/ |
| chalk browser interceptor | https://github.com/advisories/GHSA-2v46-p5h4-248w |
| Shai-Hulud `postinstall` `bundle.js`, 187 packages | https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/ |
| Sha1-Hulud 2.0 `preinstall` `setup_bun.js`, stolen tokens | https://semgrep.dev/blog/2025/digging-for-secrets-sha1-hulud-the-second-coming-of-the-npm-worm/ |
| Sha1-Hulud 2.0, 795 packages and 1,091 versions | https://github.com/DataDog/indicators-of-compromise/blob/main/shai-hulud-2.0/consolidated_iocs.csv |
| Nx versions, `postinstall`, removal times, token exfiltrated through `publish.yml` | https://github.com/advisories/GHSA-cxm3-wv7p-598c |
| Nx malicious versions unattested | https://github.com/nrwl/nx/issues/32522#issuecomment-3226581918 |
| eslint-config-prettier versions, `install.js` | https://github.com/advisories/GHSA-f29h-pxvx-f335 |
| eslint-config-prettier malicious versions unattested | https://github.com/prettier/eslint-config-prettier/issues/339#issuecomment-3090250555 |
| DuckDB versions, added API token | https://github.com/duckdb/duckdb-node/security/advisories/GHSA-w62p-hx95-gf2c |
| xrpl.js versions | https://github.com/advisories/GHSA-33qr-m49q-rxfx |

## Not sourced

- npm's removal times for every incident but chalk and Nx.
- Which `@nx/*` and eslint-config-prettier versions carried the install hook.
- Whether the chalk, Shai-Hulud, DuckDB and xrpl malicious versions carried provenance.
- The xrpl payload running on import, and the Shai-Hulud wave 1 count of 500+, come from
  search-result summaries rather than a page read in full.
