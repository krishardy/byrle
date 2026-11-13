# Runbook: a team running byrle in blocking mode

For the first team to run byrle in front of its npm and PyPI installs, from v0.1.0. The
order is: install and verify, configure, observe for a week, settle what it would refuse,
then enforce. [quickstart](quickstart.md) has each command with its output; this says
what to run, in what order, and what to send back. Written 2026-10-14.

## What you run

| Piece | From | Sizing, measured 2026-10-14 |
|---|---|---|
| `byrle daemon` | the v0.1.0 binary or image, below | 1 GiB of memory: 597 MB peak with 24 of the largest npm documents at once, 776 MB with 8 of vite's 38.9 MB document, 395 MB for a 207-package `npm ci` ([default-ceilings](engineering_decisions/0085-default-ceilings.md)). Spool disk: up to 8 GiB, 8 analyses at the 1 GiB artifact ceiling |
| Postgres 18 | your own | intel is about 98 MB ([snapshot-identity](engineering_decisions/0036-snapshot-identity.md)); accounts, usage and analyses grow with use, decisions kept 365 days |
| `byrle refresh` | the same binary or image, on a schedule | about a minute; once a day at least |
| TLS in front | nginx, as [fronting-tls](fronting-tls.md) | |

## 1. Install and verify

The binaries are static, for Linux x86_64 and aarch64. The image is distroless, with no
shell.

```
curl -sSLO https://github.com/krishardy/byrle/releases/download/v0.1.0/byrle-0.1.0-x86_64-unknown-linux-musl.tar.gz
gh attestation verify byrle-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo krishardy/byrle
tar -xzf byrle-0.1.0-x86_64-unknown-linux-musl.tar.gz

gh attestation verify oci://ghcr.io/krishardy/byrle:0.1.0 --repo krishardy/byrle
docker run --rm ghcr.io/krishardy/byrle:0.1.0 --version
```

Each attestation names `.github/workflows/release.yml` and the commit it built
([release-provenance](engineering_decisions/0108-release-provenance.md)).

## 2. Configure

All configuration is environment variables; `byrle --help` lists each with its default.
The ones a team sets:

| Variable | Set to |
|---|---|
| `BYRLE_DATABASE_URL` | the Postgres URL |
| `BYRLE_PROXY_URL` | the name every installing machine reaches, such as `https://byrle.example.com/`: lockfiles record it |
| `BYRLE_LISTEN` | where nginx reaches it, `127.0.0.1:8080` by default |
| `BYRLE_POLICY` | a file holding `version: 1`, the defaults ([policy-reference](policy-reference.md)) |
| `BYRLE_AUDIT_LOG` | a path; one line per decision, rotated daily |
| `BYRLE_SPOOL_DIR` | a directory with the disk above |
| `BYRLE_MODE` | `observe` for the first week |
| `BYRLE_RP_KEY` | with the console behind nginx: a random key nginx sends, so failed logins are counted by the client's address |
| `BYRLE_GITHUB_TOKEN` | optional: `byrle refresh` loads GitHub's advisories with it |

Make one account per person and per CI runner, and a token per machine (quickstart §3).
Point each client at the proxy (quickstart §6), and run `byrle doctor` on a developer
machine and a CI runner (quickstart §7).

## 3. Observe for a week

With `BYRLE_MODE=observe`, everything is served, and what the policy refuses is logged
at WARN as `observe:` and in the audit log. Run `byrle warm` in CI when a lockfile
changes, and `byrle lockfile verify` beside it (quickstart §8).

For each refusal, decide one of:

| Decision | How |
|---|---|
| it is right | nothing |
| the package is needed and the refusal is a false positive | a `packages` exception with a reason and an expiry ([policy-reference](policy-reference.md)) |
| the version is needed and another one will do | change the lockfile |

`byrle explain pkg:npm/<name>@<version>` says why one version is refused. From another
machine, set `BYRLE_REMOTE_URL` to the console's URL and `BYRLE_TOKEN` to a token of an
account with the `reader` or `admin` role: `explain`, `artifact show` and `export`, `intel
history`, `status`, and `policy check` and `policy diff <candidate>` are then answered by
the deployment, from its policy, stores and audit log
([remote-analysis-commands](engineering_decisions/0118-remote-analysis-commands.md)).
`byrle account create <name> --role reader` makes such an account.

## 4. What the defaults are known to refuse

Measured on 2026-10-13 and 2026-10-14, on the `make bench` sets (next, react, eslint,
typescript, vite, vitest; pandas, scikit-learn, matplotlib):

| Check | Refuses | Seen |
|---|---|---|
| `cooldown_days: 7` | a version published in the last 7 days. A resolver picks an older one; a lockfile pinned to the new one fails | `vitest@5.0.4`, published 2026-10-12 |
| `provenance` | a version built by a repository or workflow no version from 7 or more days before it used: a project moving its release, until 7 days after | `scikit-learn@1.9.1` (to `scikit-learn-release`), `@rolldown/pluginutils@1.0.1` (to `rolldown/plugins`); 382 of 30,261 npm versions across whole histories ([provenance-check](engineering_decisions/0066-provenance-check.md)) |
| `install_scripts` | a PyPI sdist, which runs code to build. An install that has a wheel for its platform does not fetch the sdist | 18 sdists of the PyPI set, none fetched by `uv pip install` |

bun and yarn 1 give up on the 503 a not-yet-analysed artifact answers; `byrle warm`
first, or a second install, serves them.

## 5. Enforce

Unset `BYRLE_MODE` and restart the proxy. A changed policy file then takes effect on
`kill -HUP <pid>`. To go back to observing, set it again and restart.

## 6. Run it

| Watch | How |
|---|---|
| health | `GET /-/byrle/health`; `GET /-/byrle/ready` answers 200 once intel is loaded, for a readiness probe |
| the intel | `byrle refresh` exits 0, or 1 when a stream did not load and its last load stays; anything else failed. A stream that parsed to under half its stored rows is one: check its bundle, then `byrle refresh --force <stream>` loads it |
| what was refused and served | the audit log, or the console (quickstart §11) |
| an install that must go ahead now | [break-glass](break-glass.md) |
| a new release | verify its attestations as in §1 before running it |

## 7. What to send back

Each of these, with the audit line or the command and its output:

- a refusal that was wrong, and the exception you wrote for it
- an install that failed or hung, with the client and its version
- install times through the proxy against direct; `make bench` measured npm 3.7 s
  against 3.6 s and PyPI 1.6 s against 2.5 s, analysed, on 2026-10-14
  ([latency-benchmarks](engineering_decisions/0075-latency-benchmarks.md))
- the proxy's peak memory, and anything you had to change to keep it up
