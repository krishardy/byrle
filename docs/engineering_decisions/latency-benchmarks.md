# Install latency through the proxy, measured

- **Status:** Measured 2026-09-28 with `make bench` (`scripts/make/bench.sh`), at `ca96897`
  plus warm's two-pass change. The latency budget is not set.
- **Related:** [warm](warm.md), [deferral-status-codes](deferral-status-codes.md),
  [artifact-spool](artifact-spool.md)

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

| Set | direct, cold | direct, warm cache | proxy, cold | `waharoa warm` | proxy, analysed | proxy, warm cache |
|---|---|---|---|---|---|---|
| npm: 207 packages | 9.4 | 2.7 | 20.1 | 100.8 | 9.7 | 2.7 |
| pypi: 18 packages | 9.0 | 0.1 | 13.9 | 52.8 | 11.6 | 0.1 |

| Column | Client cache | Proxy |
|---|---|---|
| direct, cold | empty | none |
| direct, warm cache | filled by the run before | none |
| proxy, cold | empty | started fresh: nothing analysed |
| `waharoa warm` | | started fresh, warmed from the lockfile |
| proxy, analysed | empty | after `waharoa warm` |
| proxy, warm cache | filled by the run before | analysed |

## What the numbers say

- **Analysed:** npm is 0.3 s over direct, and PyPI 2.6 s.
- **Cold:** npm is 10.7 s over direct. The proxy log of one run shows every artifact
  deferred within 2.2 s and every one asked again 10 s later: npm waits 10 s after a 503.
  PyPI is 4.9 s over.
- **Warm client cache:** the same as direct. The client revalidates and the proxy
  forwards the 304.

## `waharoa warm` takes longer than a cold install

`waharoa warm` took 100.8 s for the npm set, against 20.1 s for `npm ci` against a cold
proxy, measured in one run each from the proxy's log:

| | `npm ci`, cold proxy | `waharoa warm` |
|---|---|---|
| artifacts asked for | 131: npm skips optional packages for other platforms | 207: every lockfile entry, every platform's binaries included |
| metadata | 128 documents fetched by the proxy on its own behalf, all within 2.2 s | 207 documents served to warm as a client's, over 40 s. `next`'s, 4.4 MB, took 21 s |
| analyses | every artifact returned about 10 s after its deferral | returns spread over 57 s |

Warm was first measured at 194.5 s, fetching each version's metadata in turn. Fetching
them 16 at a time brought it to 102.2 s. Asking for every artifact once before asking any
again, which starts every analysis at once as npm does, left it at 105.6 s.
