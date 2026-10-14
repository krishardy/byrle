# Install latency through the proxy, measured

- **Status:** Measured 2026-09-28, and as deployed 2026-10-13, with `make bench` (`scripts/make/bench.sh`); first at `ca96897`
  plus warm's two-pass change. The latency budget was set by the user 2026-10-13.
- **Related:** [warm](warm.md), [deferral-status-codes](deferral-status-codes.md),
  [artifact-spool](artifact-spool.md)

## Budget

Set by the user 2026-10-13. `make bench` exits 1 when a median is over it, or a case fails.

| Case | Budget | Variable |
|---|---|---|
| proxy, analysed | at most 1.5 times direct, cold, or 3 s over it, whichever is larger | `BYRLE_BENCH_ANALYSED_RATIO`, `BYRLE_BENCH_ALLOWANCE_SECONDS` |
| proxy, cold | at most 2 times direct, cold, or 3 s over it, whichever is larger | `BYRLE_BENCH_COLD_RATIO`, `BYRLE_BENCH_ALLOWANCE_SECONDS` |
| proxy, warm cache | at most 1 s over direct, warm cache | `BYRLE_BENCH_WARM_CACHE_SECONDS` |

A ratio, so it scales with the size of the set. The 3 s allowance was added by the user
2026-10-14: that day direct PyPI took 1.6 s, and the proxy's 4.2 s was over 1.5 times it. The cold npm median moved by about 3 s
between runs (12.9 s and 15.7 s), which the cold budget leaves room for.

## With mimalloc, 2026-10-14

After the three fixes below, with `mimalloc` as the allocator. Median of 3 runs, in
seconds; within the budget.

| Set | direct, cold | direct, warm cache | proxy, cold | `byrle warm` | proxy, analysed | proxy, warm cache |
|---|---|---|---|---|---|---|
| npm: 207 packages | 3.6 | 2.9 | 4.0 | 3.4 | 3.7 | 3.1 |
| pypi: 18 packages | 2.5 | 0.1 | 2.3 | 0.4 | 1.6 | 0.1 |

## Where an analysed PyPI install's time went, 2026-10-14

uv installing the 18-package set through an analysed proxy took 4.4 s against 1.2 s
direct. Three causes, each measured on its own:

| Cause | Measured | Fix | After |
|---|---|---|---|
| Repointing a document's URLs searched for every served origin from each URL, so an origin the document never names was read to the end each time | pillow's index, 2,986 URLs in 2.3 MB: 2.19 s with no policy | `origin::Candidates` keeps each prefix's next position | 0.051 s |
| The intel query worked out each advisory's `exploited` and aliases once per row, and pillow's 153 advisories, listing their versions, are 9,441 rows; each was a sequential scan of `exploited_cve` | 1,261 ms to execute | once per advisory, in a materialised CTE, with an indexed EXISTS for each of the two ways to be exploited | 66 ms |
| HTTP/2 to the file host at hyper's default window, through the forward proxy | scipy's 35 MB wheel in 1.20 s through the proxy, 0.41 to 0.72 s by curl; the proxy used 15% of a core | `http2_adaptive_window` on every upstream client | 0.52 to 0.94 s |

`http1_only` left the wheel at 1.14 to 1.20 s. npm was not slowed by the default window,
measured the same day through an analysed proxy:

| | `@next/swc-linux-x64-gnu-16.4.0.tgz`, three downloads | `npm ci`, 207 packages |
|---|---|---|
| default window | 0.51, 0.51, 0.51 s | 4.32, 4.42, 4.80 s |
| adaptive window | 0.48, 0.48, 0.50 s | 4.45, 4.64, 4.74 s |
| direct | 0.34, 0.33, 0.33 s | 4.31, 4.45, 4.51 s |

With all three the install took 1.57 to
2.30 s through the proxy, and 1.59 to 2.99 s direct in the same run.

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
