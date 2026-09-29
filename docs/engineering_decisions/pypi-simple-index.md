# PyPI's simple index is file-keyed, and a packument is not

- **Status:** Implemented and served. `src/ecosystem/pypi/`.
- **Related:** [stage-structure](stage-structure.md),
  [purl-identity-rules](purl-identity-rules.md),
  [enforcement-tiers](enforcement-tiers.md),
  [packument-body-inspection](packument-body-inspection.md)

## Decision

`src/ecosystem/pypi/` reads PyPI's simple index as PEP 691 JSON. What it shares with
`src/ecosystem/npm/` is what `ecosystem::Registry` names and nothing else. Stage 3's goal
says the adapter interface is an **output** of this stage, extracted from two working
implementations. An interface written before PyPI works would be npm's shape with PyPI bent
into it, which is the thing the stage exists to prevent.

## What the index really is, measured 2026-09-16

`Accept: application/vnd.pypi.simple.v1+json` against `pypi.org/simple/requests/` returns
`api-version: 1.4`, 123,104 bytes. Without that header the same URL serves HTML.

| | npm | PyPI |
|---|---|---|
| document | version-keyed, one entry per version | **file-keyed**: 244 files for 160 versions |
| publish time | only in the full packument, 1.7x to 3.6x larger | `upload-time` per file, in the document a resolver already fetches |
| artifact host | `registry.npmjs.org` serves both | `files.pythonhosted.org`, not the index host |
| install script | `hasInstallScript` on the version | nothing; an sdist runs `setup.py` and a wheel does not |
| name | used as written | PEP 503 normalised, and the index 301s to it |
| per-version document | the packument is the only one | none under `/simple/`; PEP 658 gives per-**file** metadata at `<url>.metadata` |

The first row is the finding. `NormalizedPackument` is version-keyed and a PyPI project is
not: several files carry one version and they are not interchangeable, because a wheel and
an sdist for the same version differ in whether installing runs code.

The second row is the one that saves work. Stage 2 spent an item on `npm::publish_times`,
fetching the full packument for its `time` map because the abbreviated one omits it. PyPI
writes `upload-time` on every file of the document pip already asks for, so `cooldown_days`
is answerable on the cheap path for this ecosystem.

## Name normalisation

PEP 503 lowercases and collapses every run of `-`, `_` and `.` to a single `-`. The index
enforces it with a redirect, measured:

| Asked | Answer |
|---|---|
| `Flask` | 301 to `/simple/flask/` |
| `zope.interface` | 301 to `/simple/zope-interface/` |
| `ruamel_yaml` | 301 to `/simple/ruamel-yaml/` |
| `ruamel.yaml` | 301 to `/simple/ruamel-yaml/` |
| `flask` | 200 |

`normalise` does it before the request, so one project is one identity rather than one per
spelling. A name that normalises to nothing is refused rather than turned into a path.
A wheel writes `-` in a project name as `_`, so `zope_interface-...whl` is normalised to
`zope-interface` too. A wheel's name and version are the first two of at least five fields;
an sdist's name may contain `-`, so its version follows the last one.

## Files a resolver would never fetch

A filename that names no version is skipped, and the document is still read. Over nine
projects, 12,164 files: 510 skipped, every one `.egg` (265), `.exe` (237) or `.src.rpm` (8).
pip installs none of those formats, so nothing a resolver would fetch is among them.

| Project | Files | Versions | Skipped | Wheels | Sdists | Yanked |
|---|---|---|---|---|---|---|
| requests | 244 | 160 | 1 | 83 | 160 | 4 |
| flask | 110 | 64 | 0 | 46 | 64 | 0 |
| django | 803 | 435 | 0 | 383 | 420 | 4 |
| numpy | 4,232 | 137 | 34 | 4,043 | 155 | 72 |
| urllib3 | 192 | 105 | 0 | 87 | 105 | 8 |
| setuptools | 1,530 | 626 | 79 | 580 | 871 | 20 |
| zope-interface | 2,298 | 89 | 396 | 1,815 | 87 | 203 |
| ruamel-yaml | 2,466 | 273 | 0 | 2,193 | 273 | 4 |
| pip | 289 | 159 | 0 | 130 | 159 | 6 |

Refusing a document because one 2006 egg sits in it would refuse `zope-interface` outright.
`examples/pypi_index.rs` is the run.

## Yanked is not a boolean

PEP 592 writes `yanked` as `false` or as a string giving the reason, so it is read as "not
`false`". `requests-2.32.0-py3-none-any.whl` carries
`"Yanked due to conflicts with CVE-2024-35195 mitigation"`, which a boolean read would take
as absent. The fixture keeps that entry for the case.

## What PyPI forced on the core, and what it did not

The stage exists to find these. Five candidates; two are real changes and three are not.

| Candidate | Outcome |
|---|---|
| sha256 hex against npm's SRI | **converted, no core change.** `integrity::Algorithm` already has `Sha256`, so `pypi::sri` turns the index's hex into `sha256-<base64>` and the existing verifier reads it |
| `DocumentDetail::Abbreviated`/`Full` | **naming only.** The simple index withholds nothing it has, which is what `Full` means, so a PyPI record is `Full` and `may_be_incomplete()` is false. The type was `PackumentDetail`, npm's vocabulary, and is now `DocumentDetail` |
| yanked files | **no core change.** PEP 592 makes a yank an upstream signal a resolver acts on, not a decision this proxy makes, so a yanked version is still a version |
| **one record, several files** | **a real divergence, now closed.** See below |
| **one upstream host** | **a real divergence, still open.** See below |

### A record is about a version; an artifact request is about a file

`PackageRecord` holds one `Artifact`, because an npm version resolves to one tarball. A PyPI
version does not: `requests` 2.34.2 offers a wheel and an sdist, and they differ in whether
installing runs the package's own code.

`PackageRecord::artifact` is now `artifacts: Vec<Artifact>`. npm pushes one, PyPI pushes
every file for the version, wheels first. `Artifact` gained two fields:

| Field | npm | PyPI |
|---|---|---|
| `filename` | the last segment of `dist.tarball` | the index's own `filename` |
| `runs_install_scripts` | equal to `PackageRecord::has_install_scripts` | `kind == Sdist` |

`has_install_scripts` stays the version-level answer: true only when every file for that
version is an sdist, because a resolver that can take a wheel will. For the same reason a
version's publish time is its wheel's `upload-time` when it offers one. The version list is
read from the files, not the PEP 700 `versions` key, which an index may omit. A wheel
filename may carry a PEP 427 build tag between the version and the Python tag.

### Why the per-file answer had to exist

`requests` 2.32.3 offers a wheel and an sdist, so `has_install_scripts` is false and a
policy with `install_scripts: block` clears the version. A client then asks for
`/packages/.../requests-2.32.3.tar.gz`, which `pip --no-binary :all:` does, and so does any
platform with no matching wheel. Those bytes run `setup.py`. Deciding from the version's
record serves them.

`PackageRecord::narrowed_to(filename)` is the answer: a copy holding that file alone, with
`has_install_scripts` set from it. `proxy::handle` narrows before it builds `Facts`, writes
the audit event or calls `enforce::artifact`, so the pinned decision is about the bytes the
client asked for. On npm the narrowed record equals the original, held by
`narrowing_an_npm_record_to_its_only_file_changes_nothing`.

Nothing under `src/policy/` reads `artifact`. The change stops at the normalisers, the
store and the proxy's artifact path.

### A registry is one host to npm and two to PyPI

`Proxy` held one `upstream: String` and one `registry: npm::Client`, because
`registry.npmjs.org` serves both the packument and the tarball. PyPI serves the index from
`pypi.org/simple/` and the files from `files.pythonhosted.org/packages/`, and the index
gives each file's URL in full.

| | metadata | artifacts |
|---|---|---|
| npm | `registry.npmjs.org/<name>` | `registry.npmjs.org/<name>/-/<file>.tgz` |
| PyPI | `pypi.org/simple/<name>/` | `files.pythonhosted.org/packages/<hash>/<hash>/<hash>/<file>` |

Two consequences the extraction step has to answer, neither of them settled here:

- `WAHAROA_UPSTREAM` became `WAHAROA_UPSTREAM_NPM` and `WAHAROA_UPSTREAM_PYPI`, one per
  ecosystem. See `environment-variables.md`.
- The proxy already reads artifact origins from the packument, in `OriginPolicy` and
  `ReachableOrigins`, because npm packages can name a host other than the registry. PyPI's
  second host is the same question arriving as the normal case rather than the exception.

### Which origins the proxy fronts

`ReachableOrigins` and `OriginPolicy` were in npm's module and `ReachableOrigins::new`
always added `npm::DEFAULT_REGISTRY`. They are now `src/origin.rs`, `new` takes the set of
configured upstreams, and each ecosystem names the origins it always reaches:

| Ecosystem | Always reachable |
|---|---|
| npm | `https://registry.npmjs.org` |
| PyPI | `https://pypi.org/simple`, `https://files.pythonhosted.org` |

Without that, `files.pythonhosted.org` is on no reachable origin, `OriginPolicy::disposition`
returns `Refused`, and with `WAHAROA_REFUSE_UNSERVABLE` at its default the proxy answers
every PyPI artifact request with a refusal. Held by
`a_pypi_file_is_served_rather_than_refused`.

The set reads every row of `ecosystem::TABLE`, whatever advisory streams cover it. Which
hosts the proxy can fetch through and which ecosystems it routes are different questions,
and a document can publish an artifact on any host.

## Classifying a path

`route::RequestTarget` is what `proxy::handle` reads, and each ecosystem's `classify_path`
produces it. The variants are the two things every registry serves, plus everything else:

| Variant | npm | PyPI |
|---|---|---|
| `Metadata(PackageKey)` | `/lodash`, `/@babel%2fcore` | `/simple/requests/` |
| `Artifact { key, claimed_version, filename }` | `/lodash/-/lodash-4.17.21.tgz` | `/packages/<hash>/<hash>/<hash>/requests-2.32.3-py3-none-any.whl` |
| `Other` | `/-/v1/search`, `/` | `/simple/`, `/pypi/requests/json` |

`route::RequestTarget::Artifact` carries `filename` because `claimed_version` does not reach
a file on PyPI:
`requests-2.32.3-py3-none-any.whl` and `requests-2.32.3.tar.gz` are one version and two
digests. On npm the filename is the same fact said twice, except for the 38 measured
tarballs whose filename spells the version differently from the packument.

The names are `Metadata` and `Artifact` rather than `Packument` and `Tarball`, which are
npm's words. `WAHAROA_DEFER_TEST`'s scope strings followed on 2026-09-19, to `metadata` and
`artifact`, when `make retry-matrix` added pip and uv.

`proxy::handle` still calls `npm::classify_path` alone. Routing between the two is the next
commit; this one is the type they both produce.

## Routing

`proxy::handle` reads `route::classify`, which picks the ecosystem from the path and then
that ecosystem's `classify_path`:

| Path | Answered as |
|---|---|
| `/simple/...`, `/packages/...` | PyPI |
| everything else | npm |

npm keeps the root because that is where a client configured with
`registry=http://proxy/` looks, and pip takes its index URL with the `/simple/` in it. A
path under a PyPI prefix is PyPI's whatever it turns out to be, `/simple/` and
`/packages/nonsense` included: answering pip with an npm registry's 404 says nothing
useful. `/simple` and `/packages` without the trailing slash stay npm packages by those
names.

`upstream_url` sends each request where it belongs. npm's rule is unchanged. PyPI needs
two hosts:

| Request | Upstream |
|---|---|
| `/simple/requests/` | `{WAHAROA_UPSTREAM_PYPI}/requests/` |
| `/packages/f9/9b/335f/requests-2.32.3-py3-none-any.whl` | `pypi::FILES` with the path kept |

The configured base already ends in `/simple`, so the proxy's own prefix comes off rather
than being sent twice. A file needs no lookup: the hash segments that locate it upstream
are in the request path, because the client followed the URL the index published.

### Rewriting the index, and what pip does without it

The simple index gives each file's URL in full on `files.pythonhosted.org` and pip uses it
as written. Forwarded unchanged, every file is fetched around the proxy: measured
2026-09-16 with pip 26.1.1 installing `requests`, five `/simple/` pages arrived and no
`/packages/` request did.

That is the PyPI shape of `packument-tarball-url-rewriting.md`, where npm is the only one
of five npm clients that rewrites an artifact URL to the configured registry. pip does not
rewrite either, so the proxy does.

`rewrite_index` parses the index, collects every file's `url`, and hands them to
`origin::rewrite_artifact_origins`, the same textual rewrite npm's packument uses. Only the
origin changes; the path is kept, which is what makes the request that comes back one
`pypi::classify_path` reads as an artifact and `upstream_url` sends to the host it came
from. Held by `a_rewritten_url_round_trips_to_where_it_came_from`.

The same run with the rewrite in place, pip 26.1.1, `requests` into an empty venv:

```text
INFO simple index rewritten path=/simple/requests/            files=243  rewritten=243  left_alone=0
INFO simple index rewritten path=/simple/charset-normalizer/  files=2289 rewritten=2289 left_alone=0
INFO simple index rewritten path=/simple/idna/                files=73   rewritten=73   left_alone=0
INFO simple index rewritten path=/simple/urllib3/             files=192  rewritten=192  left_alone=0
INFO simple index rewritten path=/simple/certifi/             files=140  rewritten=140  left_alone=0
```

2,937 file URLs rewritten, none left alone, and ten `/packages/` requests reached the
proxy: five wheels and five PEP 658 `.metadata` files.

The run needs `PIP_CONFIG_FILE=/dev/null`. A configured `extra-index-url` is queried
alongside this proxy and serves its own file URLs, so without that the measurement counts
what the other index answered.

### From the index to a verified file

`pypi::normalize` gives the index the same shape npm's packument reaches, and `read_index`
stores it before the rewrite, built from the bytes that arrived rather than the ones the
proxy is about to send. Records built from the rewritten document would name the proxy's
own origin as every artifact's upstream, which is the wrong thing to hold as the index's
claim.

pip 26.1.1, `requests` into an empty venv:

```text
INFO simple index normalized path=/simple/requests/ files=243 versions=160 artifacts=243 skipped=0 sdist_only_versions_listed=77 held_packages=1 held_records=160
INFO artifact requested, digest known path=/packages/.../requests-2.34.2-py3-none-any.whl integrity="sha256-Kg1gwXL4OsarMeRVSQbA87NYjTe1y5ObHAYfSQfieOA=" has_install_scripts=false
INFO artifact cache consulted ... cache="miss"
INFO artifact digest verified path=/packages/.../requests-2.34.2-py3-none-any.whl purl=pkg:pypi/requests@2.34.2 bytes=73075
```

All five wheels verified. 243 files became 160 versions with 243 artifacts and nothing
skipped, and 77 of those versions offer only an sdist.

`fetch_and_store` asks each ecosystem its own registry, chosen from `key.ecosystem()`: npm
the abbreviated packument, PyPI the simple index. `Proxy` holds a `pypi::Client` beside its
`npm::Client` for it.

### The wheel and the sdist of one version get different answers

With `install_scripts: block` and pip asked for the sdist:

```text
INFO artifact requested, digest known path=/packages/.../idna-3.19.tar.gz
     claimed_purl=pkg:pypi/idna@3.19 has_install_scripts=true
INFO refused by policy method=GET path=/packages/.../idna-3.19.tar.gz status=403
     claimed_purl=pkg:pypi/idna@3.19 action="block" reasons=["install_scripts: block"]
```

```text
ERROR: HTTP error 403 while getting .../idna-3.19.tar.gz (from .../simple/idna/)
```

The same proxy, the same policy, the same version, asked for the wheel:

```text
INFO artifact requested, digest known path=/packages/.../idna-3.19-py3-none-any.whl
     claimed_purl=pkg:pypi/idna@3.19 has_install_scripts=false
INFO proxied method=GET path=/packages/.../idna-3.19-py3-none-any.whl status=200 bytes=68550
```

`idna` 3.19's record says `has_install_scripts: false`, because a wheel is on offer. The
sdist's own answer is true, and `narrowed_to` is what puts it in front of the policy. This
is the bypass named above, refused live.

PEP 658's `<file>.metadata` classifies as `Other`: `filename_parts` reads no distribution
from it, which is right, because it is not installable bytes. It forwards to the files host
like any other path under the prefix.

## Verified against real bytes

`requests-0.2.0.tar.gz`, 5,533 bytes, fetched from `files.pythonhosted.org` 2026-09-16:

```text
sha256 of the bytes  813202ace4d9301a3c00740c700e012fb9f3f8c73ddcfe02ab558a8df6f175fd
the index claims     813202ace4d9301a3c00740c700e012fb9f3f8c73ddcfe02ab558a8df6f175fd
pypi::sri gives      sha256-gTICrOTZMBo8AHQMcA4BL7nz+Mc93P4Cq1WKjfbxdf0=
```

The last line round-trips through `integrity::Sri::parse` as `Algorithm::Sha256`, so the
conversion reaches the verifier npm's digests already use.

## Transport, and what it does not share with npm

`pypi::Client` is deliberately the same shape as `npm::Client`, an `http`, a base and a
byte ceiling, and deliberately shares no code with it. Two concrete implementations side by
side are what the extraction step reads.

| | `npm::Client` | `pypi::Client` |
|---|---|---|
| content negotiation | `Accept` picks abbreviated or full | `Accept` picks JSON over HTML, and an index may refuse |
| a name it does not serve as given | the registry serves it | PEP 503 301s to the normalised name, so `normalise` runs before the request |
| a wrong content type | the body is JSON either way | HTML is an error, not an empty project |
| encoding | asks gzip, decodes through `http::decode_for_parsing` | the same, for the same reason |

The third row is the one worth keeping. An index that answers HTML would parse as zero
files, which reads as "this project has no versions" and fails open. It is
`FetchError::NotJson` instead.

Verified live against nine projects on 2026-09-16, one record per version for every one:

| Project | Versions | Records | Sdist-only versions |
|---|---|---|---|
| requests | 160 | 160 | 77 |
| flask | 64 | 64 | 18 |
| django | 435 | 435 | 52 |
| numpy | 137 | 137 | 4 |
| urllib3 | 105 | 105 | 18 |
| setuptools | 626 | 626 | 47 |
| zope-interface | 89 | 89 | 31 |
| ruamel-yaml | 273 | 273 | 18 |
| pip | 159 | 159 | 29 |

The last column is the `install_scripts` question for this ecosystem: 48% of `requests`
versions offer no wheel, so installing one runs `setup.py`. They are the old ones, from
before wheels existed.

## Identity before the proxy routes it

Expressing an identity and serving an ecosystem are separate questions.
`Ecosystem::EXPRESSIBLE` is the first. The second was `Ecosystem::ALL`, which held npm alone
until after the proxy served `/simple/`. It is now the rows of `ecosystem::TABLE`, which
`intel::served` reads, so `doctor` and the startup log report PyPI as served with no stream
providing `match` or `malware`.

`pkg:pypi/requests@2.34.2` parses, held by `a_pypi_identity_is_a_pypi_purl`.

## Not decided here

The version is read from the filename, PEP 427 for a wheel and the last `-` for an sdist.
That is what the index gives: a file entry carries no version field. Whether a resolved
range picks a file or a version is the range-resolution item, and it is deliberately open.
