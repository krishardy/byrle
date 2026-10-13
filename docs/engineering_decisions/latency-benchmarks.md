# Install latency through the proxy, measured

- **Status:** Measured 2026-09-28, and as deployed 2026-10-13, with `make bench` (`scripts/make/bench.sh`); first at `ca96897`
  plus warm's two-pass change. The latency budget is not set.
- **Related:** [warm](warm.md), [deferral-status-codes](deferral-status-codes.md),
  [artifact-spool](artifact-spool.md)

## As deployed, 2026-10-13

`make bench` now runs the proxy as a team deploys it: a token required, intel from a
`byrle refresh` into Postgres, the default policy, and each request's usage recorded. The
sets are resolved as of 8 days ago, past the default 7-day cooldown. A discovery pass
installs through the proxy first and adds an exception for each version refused, so the
installs finish with every check still run. Median of 3 runs, in seconds; npm 11.21.0,
uv 0.13.0.

| Set | direct, cold | direct, warm cache | proxy, cold | `byrle warm` | proxy, analysed | proxy, warm cache |
|---|---|---|---|---|---|---|
| npm: 207 packages | 9.6 | 2.8 | 15.7 | 4.9 | 12.0 | 2.8 |
| pypi: 18 packages | 8.5 | 0.1 | 12.3 | 74.6, one run | 11.7 | 0.1 |

| Set | cold over direct | analysed over direct |
|---|---|---|
| npm | +6.1 s, +64% | +2.4 s, +25% |
| pypi | +3.8 s, +45% | +3.2 s, +38% |

Analysed npm was +0.3 s on 2026-09-28, with no token, policy, intel store or usage.

Refused under the defaults and released for the measurement:

| Version | Reason |
|---|---|
| npm `@rolldown/pluginutils@1.0.1` | provenance: built by `rolldown/plugins/.github/workflows/publish.yml`; 1.0.0 by `rolldown/rolldown/.github/workflows/publish-to-npm.yml` |
| pypi `scikit-learn@1.9.1` | provenance: built by `scikit-learn/scikit-learn-release/.github/workflows/wheels.yml`; 1.9.0 by `scikit-learn/scikit-learn/.github/workflows/publish_pypi.yml` |

`byrle warm` over the PyPI set asks for every file of each version: 655 files. In one of
three runs 16 wheels were answered 502, and the run failed; 18 sdists were refused by
`install_scripts`, which no install here fetches.

## Method

Two dependency sets, each installed from a lockfile five ways, three times each; the
median is shown, in seconds. The proxy is a release build on the same machine, with no
policy and no intel store. Every request to a registry, direct or from the proxy, went
through the machine's forward proxy, `HTTPS_PROXY`.

- npm: `next react react-dom eslint typescript vite vitest`, 207 lockfile entries, with
  `npm ci`. npm 11.20.0.
- PyPI: `pandas scikit-learn matplotlib`, 18 pinned requirements, with `uv pip install`.
  uv 0.12.19.

## Results

| Set | direct, cold | direct, warm cache | proxy, cold | `byrle warm` | proxy, analysed | proxy, warm cache |
|---|---|---|---|---|---|---|
| npm: 207 packages | 9.4 | 2.7 | 20.1 | 100.8 | 9.7 | 2.7 |
| pypi: 18 packages | 9.0 | 0.1 | 13.9 | 52.8 | 11.6 | 0.1 |

| Column | Client cache | Proxy |
|---|---|---|
| direct, cold | empty | none |
| direct, warm cache | filled by the run before | none |
| proxy, cold | empty | started fresh: nothing analysed |
| `byrle warm` | | started fresh, warmed from the lockfile |
| proxy, analysed | empty | after `byrle warm` |
| proxy, warm cache | filled by the run before | analysed |

## What the numbers say

- **Analysed:** npm is 0.3 s over direct, and PyPI 2.6 s.
- **Cold:** npm is 10.7 s over direct. The proxy log of one run shows every artifact
  deferred within 2.2 s and every one asked again 10 s later: npm waits 10 s after a 503.
  PyPI is 4.9 s over.
- **Warm client cache:** the same as direct. The client revalidates and the proxy
  forwards the 304.

## `byrle warm` takes longer than a cold install

`byrle warm` took 100.8 s for the npm set, against 20.1 s for `npm ci` against a cold
proxy, measured in one run each from the proxy's log:

| | `npm ci`, cold proxy | `byrle warm` |
|---|---|---|
| artifacts asked for | 131: npm skips optional packages for other platforms | 207: every lockfile entry, every platform's binaries included |
| metadata | 128 documents fetched by the proxy on its own behalf, all within 2.2 s | 207 documents served to warm as a client's, over 40 s. `next`'s, 4.4 MB, took 21 s |
| analyses | every artifact returned about 10 s after its deferral | returns spread over 57 s |

The `analysis job timed` lines of one warm run over the npm set, 206 jobs, in
milliseconds:

| Phase | Median | p90 | Max | Sum |
|---|---|---|---|---|
| queued for one of 8 slots | 63,754 | 70,915 | 71,285 | |
| fetch, to the headers | 57 | 238 | 546 | 24,266 |
| download | 109 | 6,365 | 24,725 | 498,316 |
| read | 0 | 2,707 | 7,394 | 122,107 |
| store | 0 | 0 | 6,703 | 20,109 |
| total, from the slot | 175 | 11,395 | 26,134 | 665,008 |

The jobs downloaded 721,192,626 bytes. The largest were `next`'s platform binaries,
33 to 35 MB and 23 to 25 s each. 665 s of work over 8 slots is most of warm's run: its
cost is the analysis of every platform's binaries, which `npm ci` does not fetch.

Since then warm asks for npm artifacts by the lockfile's path, for the platforms it is
given, and took 16.9 s for this machine's 133 of the 207: see [warm](warm.md).

Warm was first measured at 194.5 s, fetching each version's metadata in turn. Fetching
them 16 at a time brought it to 102.2 s. Asking for every artifact once before asking any
again, which starts every analysis at once as npm does, left it at 105.6 s.
