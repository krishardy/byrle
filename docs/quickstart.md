# Quickstart

From a checkout to installs through byrle in enforcing mode, for npm and PyPI. Every
command here was run on 2026-09-29, and each excerpt below is that run's output, except
for tokens: §3, the token table in §6 and `BYRLE_TOKEN` in §8 were run on 2026-10-11.

The order is: run the proxy in observe mode, point clients at it, check with `doctor`,
warm the lockfiles, then enforce.

## 1. Build

```
cargo build --release
```

The binary is `target/release/byrle`. There is no published release yet.

## 2. An intel store

`known_malware`, `max_cvss` and `kev` are decided from a Postgres store that `byrle
refresh` fills. Without one, those checks are unenforceable, and `byrle status` says so.

```
export BYRLE_DATABASE_URL=postgres://user:password@localhost/byrle
byrle refresh
```

It loads OSV, Datadog's malicious-packages dataset and CISA KEV, and the GitHub Advisory
Database when `BYRLE_GITHUB_TOKEN` is set. The run above took 48 s. Run it on a schedule;
each run is a new snapshot, and the proxy decides with the latest.

## 3. Accounts and tokens

The proxy answers 401 to a request without a token, unless `BYRLE_REQUIRE_TOKEN=0`. The
accounts and tokens are kept in the same Postgres. Make one account per person or CI
runner, and a token for each machine:

```
$ byrle account create alice
account alice created
$ byrle token create alice laptop
token laptop of account alice created. It is shown once; byrle keeps only its SHA-256
byrle_HTh6…
$ byrle token list alice
ACCOUNT  TOKEN   CREATED               REVOKED
alice    laptop  2026-10-11T19:03:29Z  -
```

The token is printed once, on stdout; the line above is cut short here. byrle keeps its
SHA-256. `byrle token revoke alice laptop` or `byrle account disable alice` stops it from
the next request.

## 4. A policy

Start from the defaults:

```yaml
version: 1
```

That refuses known malware, a version published in the last 7 days, install scripts, an
advisory scored above 6.9, a known-exploited vulnerability, a yanked PyPI file, and
contradicted provenance. [policy-reference](policy-reference.md) lists every key.
`byrle policy check policy.yaml` loads it as the proxy does.

## 5. Run the proxy in observe mode

```
export BYRLE_POLICY=/etc/byrle/policy.yaml
export BYRLE_AUDIT_LOG=/var/log/byrle/audit.jsonl
export BYRLE_PROXY_URL=https://byrle.example.com
export BYRLE_MODE=observe
byrle daemon
```

- **`BYRLE_PROXY_URL`** is the address written into lockfiles. Set it to a name every
  machine that installs from a lockfile can reach: see the README's deployment note.
- **`BYRLE_LISTEN`** is where it listens, `127.0.0.1:8080` by default. Put TLS in
  front of it for a proxy reached by name: [fronting-tls](fronting-tls.md) has a tested
  nginx configuration.
- **`BYRLE_MODE=observe`** serves what the policy refuses and logs it at WARN, so
  nothing breaks while you learn what it would refuse.

Startup names each check that can fire, and prints the command to point each client at
it:

```
WARN observe mode: what the policy refuses is served and logged, not refused byrle.config.variable=BYRLE_MODE
WARN ENFORCED: known_malware and max_cvss, from the intel store, and kev once the store has loaded the KEV catalogue. ...
INFO point a client at the proxy byrle.client.name="npm" byrle.client.command=npm config set registry http://127.0.0.1:18990/
INFO point a client at the proxy byrle.client.name="pip" byrle.client.command=pip config set global.index-url http://127.0.0.1:18990/simple/
```

`GET /-/byrle/ready` answers 200 once the store holds a snapshot. Point a readiness probe
at it.

## 6. Point each client at it

With the proxy at `https://byrle.example.com`:

| Client | Configuration |
|---|---|
| npm | `npm config set registry https://byrle.example.com/` |
| pnpm | `pnpm config set registry https://byrle.example.com/` |
| yarn 1 | `yarn config set registry https://byrle.example.com/` |
| yarn 4 | `npmRegistryServer: "https://byrle.example.com"` in `.yarnrc.yml` |
| bun | `registry = "https://byrle.example.com/"` under `[install]` in `bunfig.toml` |
| pip | `pip config set global.index-url https://byrle.example.com/simple/` |
| uv | `UV_DEFAULT_INDEX=https://byrle.example.com/simple`, or `index-url` in `uv.toml` |

Each line was run on 2026-09-29, in a home directory of its own and against a fresh proxy
at `http://127.0.0.1:18995`, then used to install one package:

| Client | Version | Registry the client reported | Install |
|---|---|---|---|
| npm | 11.20.0 | `http://127.0.0.1:18995/` | served and verified |
| pnpm | 10.34.5 | `http://127.0.0.1:18995/` | served and verified |
| yarn 1 | 1.22.22 | `http://127.0.0.1:18995/` | failed on the first request's 503, served on the second install |
| yarn 4 | 4.9.1 | `http://127.0.0.1:18995` | served and verified |
| bun | 1.4.2 | `registry = "http://127.0.0.1:18995/"` | failed on the first request's 503, served on the second install |
| pip | 26.2.1 | `http://127.0.0.1:18995/simple/` | served and verified |
| uv | 0.12.19 | `UV_DEFAULT_INDEX` | served and verified |

Each client also sends the token. `<token>` is the output of `byrle token create`:

| Client | Token |
|---|---|
| npm, pnpm, yarn 1 | `//byrle.example.com/:_authToken=<token>` in `~/.npmrc` |
| bun | `registry = { url = "https://byrle.example.com/", token = "<token>" }` under `[install]` in `bunfig.toml`, in place of the `registry` line above |
| pip | `https://alice:<token>@byrle.example.com/simple/` as the index URL |
| uv | `https://alice:<token>@byrle.example.com/simple` as the index URL |
| `byrle warm` | `BYRLE_TOKEN=<token>` |

The username in pip's and uv's URL is the account name, not `__token__`: any other name is
answered 401. `make smoke-npm` and `make smoke-python` installed with npm's `_authToken`,
and pip and uv with `<account>:<token>@`, on 2026-10-11, and bun installed with the line
above. The forms for pnpm and yarn 1 were measured on a stub registry
([account-identification](engineering_decisions/account-identification.md)). No lockfile
checked records the token.

yarn 4 refuses a registry on plain HTTP unless its host is listed, as it was for this
run: `unsafeHttpWhitelist: ["127.0.0.1"]` in `.yarnrc.yml`. Behind `https://` it needs
nothing more.

Then empty each client's cache once. An install supplied from the cache never asks the
proxy: `npm cache clean --force`, `uv cache clean`, `bun pm cache rm`,
`yarn cache clean`.

## 7. Check with `doctor`

```
BYRLE_PROXY_URL=https://byrle.example.com byrle doctor
```

It checks the proxy, its readiness and policy, what each installed client points at, and
which caches would skip it. It exits 1 while any install would go around the proxy. From
the run, before uv and the caches were set up:

```
     ok  proxy readiness: ready, using intel snapshot sha256:918d1ac1…, taken 2026-09-29T00:15:33Z
     ok  npm registry: http://127.0.0.1:18990/
     ok  pip registry: http://127.0.0.1:18990/simple/
PROBLEM  uv registry: points at https://pypi.org/simple, not the proxy at http://127.0.0.1:18990
         fix: set UV_DEFAULT_INDEX to http://127.0.0.1:18990/simple, or `index-url` in uv.toml
   WARN  npm cache: /home/portacot/.npm/_cacache/index-v5 holds cached packages. A warm cache supplies the whole install, so those packages never reach the proxy
         fix: npm cache clean --force
```

When nothing answers at the proxy URL, `doctor` says whether its host resolves on this
machine, and to which addresses. An IP address is not looked up:

```
PROBLEM  proxy: nothing answered at https://byrle.invalid: byrle.invalid does not resolve on this machine: failed to lookup address information: Name or service not known
         fix: check the host in BYRLE_PROXY_URL, and the DNS this machine uses
PROBLEM  proxy: nothing answered at http://127.0.0.1:1/-/byrle/health: the request failed: error sending request for url (http://127.0.0.1:1/-/byrle/health): client error (Connect): tcp connect error: Connection refused (os error 111)
         fix: start the proxy, or point this at the address clients actually use
```

## 8. Install, and warm the lockfiles

The first request for any artifact is answered 503 until the proxy has analysed it. npm,
pnpm, yarn 4, pip and uv retry and succeed. bun and yarn 1 give up. `byrle warm` asks
the proxy for everything a lockfile locks, ahead of the first install:

```
BYRLE_TOKEN=<token> byrle warm --lockfile package-lock.json --proxy https://byrle.example.com
66 warmed, 0 refused, 0 not listed, 0 not ready, 0 still being analysed, 0 failed; 0 skipped for other platforms
```

It warms the platform it runs on. Pass `--platform linux-x64` for each other platform
installs run on, or `--all-platforms`. Run it in CI when a lockfile changes.

In the same job, `byrle lockfile verify` fails when a committed lockfile fetches anything
from elsewhere, such as one resolved against the public registry:

```
byrle lockfile verify --lockfile package-lock.json --proxy https://byrle.example.com
package-lock.json: 66 artifacts, 66 through the proxy
```

It exits 1 for an artifact from elsewhere, and 2 for one the lockfile records no URL for,
as pnpm does for its configured registry ([lockfile-verify](engineering_decisions/lockfile-verify.md)).

## 9. Read what it would refuse

In observe mode, each refusal is a WARN line starting `observe:`, and the audit log holds
one line per decision. `byrle explain` answers for one package:

```
byrle explain pkg:npm/express@4.21.2

  denials          pass
  known_malware    pass
  cooldown_days    pass
  kev              pass
  max_cvss         pass
  install_scripts  pass
  yanked           n/a               no meaning for npm
  deprecated       pass
  provenance       pass

  verdict: allow
```

`byrle explain --policy` shows the policy in force. A package you need that the policy
refuses gets a `packages` exception, with a reason and an expiry:
[policy-reference](policy-reference.md).

## 10. Enforce

Unset `BYRLE_MODE` and restart the proxy. After that, a changed policy file takes
effect on `kill -HUP <pid>`, without a restart.

`byrle audit verify` decides each logged pinned request again from what it recorded,
and reports any that come out differently. From the run, after installs in both modes:

```
byrle audit verify /var/log/byrle/audit.jsonl --policy /etc/byrle/policy.yaml
281 reproduced, 0 differ, 0 not replayable
```

## When it is in the way

[break-glass](break-glass.md) says how to install while the proxy is down, and how to
release a refused package without a restart.
