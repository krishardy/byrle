# Break-glass

What to do when the proxy stands between a team and an install that has to happen now.
There are two cases: the proxy is down, or it is up and refusing something.

## The proxy is down

Installs fail. Clients point at the proxy and nothing answers, so nothing is installed
unchecked. To install anyway, point one install at the public registry. Nothing is checked
for that install: no policy, no intel, no analysis, no digest verification beyond the
client's own.

A lockfile written through the proxy records the proxy's address, and some clients fetch
from what the lockfile records rather than from the registry they are given.

Measured 2026-09-28 with `ms@2.1.3` or `six==1.17.0` locked through the proxy, the proxy
then stopped, and each command run with an empty cache:

| Client | Lockfile records the proxy's URL | Command | Result |
|---|---|---|---|
| npm 11.20.0 | yes, `resolved` | `npm ci --registry=https://registry.npmjs.org/ --replace-registry-host=always` | installed. Without `--replace-registry-host=always` it fetched the proxy URL and failed `ECONNREFUSED` |
| pnpm 10.34.5 | no | `pnpm install --frozen-lockfile --registry=https://registry.npmjs.org/` | installed |
| yarn 1.22.22 | yes, `resolved` | rewrite the address in `yarn.lock` (below), then `yarn install --frozen-lockfile` | installed. `--registry` alone fetched the proxy URL and failed `ECONNREFUSED`, with or without `--frozen-lockfile` |
| yarn 4.9.1 | no | `YARN_NPM_REGISTRY_SERVER=https://registry.npmjs.org yarn install --immutable` | installed |
| bun 1.4.2 | yes, the tarball URL | rewrite the address in `bun.lock` (below), then `bun install --frozen-lockfile` | installed. `--registry` alone failed `ConnectionRefused downloading tarball`, with or without `--frozen-lockfile` |
| pip 26.2.1 | no, in a `pip freeze` requirements file | `pip install --index-url https://pypi.org/simple -r requirements.txt` | installed |
| uv 0.12.19 | yes, `source` and each file's `url` | `uv sync --default-index https://pypi.org/simple` | installed, and rewrote `uv.lock` to name `https://pypi.org/simple`. `uv sync --frozen` with the same flag fetched the proxy URLs and failed |

Rewriting the lockfile, for yarn 1 and bun, with the proxy's address as the lockfile
records it:

```
sed -i 's#https://byrle.example.com/#https://registry.npmjs.org/#g' yarn.lock
```

The lockfile's integrity hash still checks the bytes: yarn 1's `#sha1` fragment and bun's
`sha512` are unchanged by the rewrite.

Do not commit a lockfile the bypass changed, by hand or by uv. It records the public
registry, and every later install from it goes around the proxy while the proxy is up.
`git checkout` the lockfile once the proxy is back.

## The proxy refuses something needed now

Add an exception to the policy file and reload it. No restart is needed, and connections
in flight are not dropped.

1. Add a `packages` entry for the package, with a `reason` and an `expires` date, or
   `permanent: true`. Its `set` names the check to release, such as
   `install_scripts: allow`. A `denials` entry is removed instead.
2. Check the file: `byrle policy check <file>`. It exits 1 if the proxy would refuse it.
3. Send the proxy `SIGHUP`: `kill -HUP <pid>`.

The proxy loads the file as it does at startup, and logs one of:

```
INFO policy reloaded from=sha256:2dc2… to=sha256:a797…
ERROR policy not reloaded keeping=sha256:a797… why=BYRLE_POLICY: policy version 9 is not supported; this build understands version 1
```

A file that does not load leaves the policy in force as it was. A request already being
decided finishes on the policy it started with.

Each pinned audit line names the digest of the policy it was decided under. To replay a
log that spans a reload, pass both files: `byrle audit verify <log> --policy old.yaml
--policy new.yaml`.

`BYRLE_MODE=observe` serves everything the policy refuses, for the whole proxy. It is
read at startup, so switching to it needs a restart. It never serves what the proxy cannot
assess: see [request-flow](request-flow.md).
