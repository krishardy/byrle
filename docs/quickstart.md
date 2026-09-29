# Quickstart

From a checkout to installs through waharoa in enforcing mode, for npm and PyPI. Every
command here was run on 2026-09-29, and each excerpt below is that run's output.

The order is: run the proxy in observe mode, point clients at it, check with `doctor`,
warm the lockfiles, then enforce.

## 1. Build

```
cargo build --release
```

The binary is `target/release/waharoa`. There is no published release yet.

## 2. An intel store

`known_malware`, `max_cvss` and `kev` are decided from a Postgres store that `waharoa
refresh` fills. Without one, those checks are unenforceable, and `waharoa status` says so.

```
export WAHAROA_DATABASE_URL=postgres://user:password@localhost/waharoa
waharoa refresh
```

It loads OSV, Datadog's malicious-packages dataset and CISA KEV, and the GitHub Advisory
Database when `WAHAROA_GITHUB_TOKEN` is set. The run above took 48 s. Run it on a schedule;
each run is a new snapshot, and the proxy decides with the latest.

## 3. A policy

Start from the defaults:

```yaml
version: 1
```

That refuses known malware, a version published in the last 7 days, install scripts, an
advisory scored above 6.9, a known-exploited vulnerability, a yanked PyPI file, and
contradicted provenance. [policy-reference](policy-reference.md) lists every key.
`waharoa policy check policy.yaml` loads it as the proxy does.

## 4. Run the proxy in observe mode

```
export WAHAROA_POLICY=/etc/waharoa/policy.yaml
export WAHAROA_AUDIT_LOG=/var/log/waharoa/audit.jsonl
export WAHAROA_PUBLIC_URL=https://waharoa.example.com
export WAHAROA_MODE=observe
waharoa daemon
```

- **`WAHAROA_PUBLIC_URL`** is the address written into lockfiles. Set it to a name every
  machine that installs from a lockfile can reach: see the README's deployment note.
- **`WAHAROA_LISTEN`** is where it listens, `127.0.0.1:8080` by default. Put TLS in
  front of it for a proxy reached by name.
- **`WAHAROA_MODE=observe`** serves what the policy refuses and logs it at WARN, so
  nothing breaks while you learn what it would refuse.

Startup names each check that can fire, and prints the command to point each client at
it:

```
WARN observe mode: what the policy refuses is served and logged, not refused waharoa.config.variable=WAHAROA_MODE
WARN ENFORCED: known_malware and max_cvss, from the intel store, and kev once the store has loaded the KEV catalogue. ...
INFO point a client at the proxy waharoa.client.name="npm" waharoa.client.command=npm config set registry http://127.0.0.1:18990/
INFO point a client at the proxy waharoa.client.name="pip" waharoa.client.command=pip config set global.index-url http://127.0.0.1:18990/simple/
```

`GET /-/waharoa/ready` answers 200 once the store holds a snapshot. Point a readiness probe
at it.

## 5. Point each client at it

With the proxy at `https://waharoa.example.com`:

| Client | Configuration |
|---|---|
| npm | `npm config set registry https://waharoa.example.com/` |
| pnpm | `pnpm config set registry https://waharoa.example.com/` |
| yarn 1 | `yarn config set registry https://waharoa.example.com/` |
| yarn 4 | `npmRegistryServer: "https://waharoa.example.com"` in `.yarnrc.yml` |
| bun | `registry = "https://waharoa.example.com/"` under `[install]` in `bunfig.toml` |
| pip | `pip config set global.index-url https://waharoa.example.com/simple/` |
| uv | `UV_DEFAULT_INDEX=https://waharoa.example.com/simple`, or `index-url` in `uv.toml` |

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

yarn 4 refuses a registry on plain HTTP unless its host is listed, as it was for this
run: `unsafeHttpWhitelist: ["127.0.0.1"]` in `.yarnrc.yml`. Behind `https://` it needs
nothing more.

Then empty each client's cache once. An install supplied from the cache never asks the
proxy: `npm cache clean --force`, `uv cache clean`, `bun pm cache rm`,
`yarn cache clean`.

## 6. Check with `doctor`

```
WAHAROA_PUBLIC_URL=https://waharoa.example.com waharoa doctor
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

## 7. Install, and warm the lockfiles

The first request for any artifact is answered 503 until the proxy has analysed it. npm,
pnpm, yarn 4, pip and uv retry and succeed. bun and yarn 1 give up. `waharoa warm` asks
the proxy for everything a lockfile locks, ahead of the first install:

```
waharoa warm --lockfile package-lock.json --proxy https://waharoa.example.com
66 warmed, 0 refused, 0 not listed, 0 not ready, 0 still being analysed, 0 failed; 0 skipped for other platforms
```

It warms the platform it runs on. Pass `--platform linux-x64` for each other platform
installs run on, or `--all-platforms`. Run it in CI when a lockfile changes.

## 8. Read what it would refuse

In observe mode, each refusal is a WARN line starting `observe:`, and the audit log holds
one line per decision. `waharoa explain` answers for one package:

```
waharoa explain pkg:npm/express@4.21.2

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

`waharoa explain --policy` shows the policy in force. A package you need that the policy
refuses gets a `packages` exception, with a reason and an expiry:
[policy-reference](policy-reference.md).

## 9. Enforce

Unset `WAHAROA_MODE` and restart the proxy. After that, a changed policy file takes
effect on `kill -HUP <pid>`, without a restart.

`waharoa audit verify` decides each logged pinned request again from what it recorded,
and reports any that come out differently. From the run, after installs in both modes:

```
waharoa audit verify /var/log/waharoa/audit.jsonl --policy /etc/waharoa/policy.yaml
281 reproduced, 0 differ, 0 not replayable
```

## When it is in the way

[break-glass](break-glass.md) says how to install while the proxy is down, and how to
release a refused package without a restart.
