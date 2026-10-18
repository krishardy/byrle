# Quickstart

From a checkout to installs through byrle in enforcing mode, for npm, PyPI, cargo, Go and
Maven. Every command here was run on 2026-09-29, and each excerpt below is that run's
output, except for tokens: §3, the token table in §6 and `BYRLE_TOKEN` in §8 were run on
2026-10-11, cargo's lines on 2026-10-14, Go's on 2026-10-16, and mvn's and Gradle's on
2026-10-17 and 2026-10-18.

The order is: run the proxy in observe mode, point clients at it, check with `doctor`,
warm the lockfiles, then enforce.

## 1. Build

```
cargo build --release
```

The binary is `target/release/byrle`. A release's static binaries and image, and how to
verify them, are in [runbook](runbook.md) §1.

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

That refuses known malware, a version published in the last 7 days, install scripts (for a
crate, a build script or a proc-macro, which `serde` and `rustls` have; for a jar, an
annotation processor javac runs, which `lombok` and `log4j-core` declare), an advisory
scored above 6.9, a known-exploited vulnerability, a yanked PyPI file, and
contradicted provenance (for Maven, a version unsigned after a signed one, as
`gradle-versions-plugin` 0.52.0 is after 0.11.1). [policy-reference](policy-reference.md) lists every key.
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
INFO point a client at the proxy byrle.client.name="npm" byrle.client.command=npm config set registry http://127.0.0.1:18990/npm/
INFO point a client at the proxy byrle.client.name="pip" byrle.client.command=pip config set global.index-url http://127.0.0.1:18990/pypi/simple/
```

and cargo's, from a run on 2026-10-14, go's, on 2026-10-16, and mvn's, on 2026-10-18:

```
INFO point a client at the proxy byrle.client.name="cargo" byrle.client.command=in ~/.cargo/config.toml: [registries.byrle] index = "sparse+http://127.0.0.1:18081/cargo/" and credential-provider = "cargo:token", [source.crates-io] replace-with = "byrle", and [net] retry = 30
INFO point a client at the proxy byrle.client.name="go" byrle.client.command=go env -w GOPROXY=http://127.0.0.1:18471/go, or with a token GOPROXY=http://<account>:<token>@127.0.0.1:18471/go
INFO point a client at the proxy byrle.client.name="mvn" byrle.client.command=in ~/.m2/settings.xml: <mirror><id>byrle</id><mirrorOf>*</mirrorOf><url>https://localhost:8741/maven</url></mirror>, and a <server><id>byrle</id> with the account and token
```

`GET /-/byrle/ready` answers 200 once the store holds a snapshot. Point a readiness probe
at it.

## 6. Point each client at it

With the proxy at `https://byrle.example.com`:

| Client | Configuration |
|---|---|
| npm | `npm config set registry https://byrle.example.com/npm/` |
| pnpm | `pnpm config set registry https://byrle.example.com/npm/` |
| yarn 1 | `yarn config set registry https://byrle.example.com/npm/` |
| yarn 4 | `npmRegistryServer: "https://byrle.example.com"` in `.yarnrc.yml` |
| bun | `registry = "https://byrle.example.com/npm/"` under `[install]` in `bunfig.toml` |
| pip | `pip config set global.index-url https://byrle.example.com/pypi/simple/` |
| uv | `UV_DEFAULT_INDEX=https://byrle.example.com/pypi/simple`, or `index-url` in `uv.toml` |
| cargo | in `~/.cargo/config.toml`, below |
| go | `go env -w GOPROXY=https://byrle.example.com/go`, with nothing after it |
| mvn | a mirror in `~/.m2/settings.xml`, below |
| Gradle | an init script in `~/.gradle/init.d/`, below |
| `./mvnw` | `MVNW_REPOURL=https://byrle.example.com/maven` |

```toml
[source.crates-io]
replace-with = "byrle"

[registries.byrle]
index = "sparse+https://byrle.example.com/cargo/"
credential-provider = "cargo:token"

[net]
retry = 30
```

cargo reads the replacement only from a file: cargo 1.99.0 ignored
`CARGO_SOURCE_CRATES_IO_REPLACE_WITH` and fetched from crates.io. Without
`credential-provider`, it refused a registry asking for a token: "authenticated registries
require a credential-provider to be configured".

A download answers 503 until crates.io's API says who published the version, one crate a
second ([cargo-provenance](engineering_decisions/0110-cargo-provenance.md)). cargo 1.99.0 waited
at most 10 s for each retry, whatever `Retry-After` asked, and retries 3 times by default.
A cold `cargo fetch` of 161 crates through the proxy failed after 23 s with the default,
and completed in 164 s with `retry = 20`. `retry = 30` covers about 300 crates.

```xml
<settings>
  <mirrors>
    <mirror>
      <id>byrle</id>
      <mirrorOf>*</mirrorOf>
      <url>https://byrle.example.com/maven</url>
    </mirror>
  </mirrors>
  <servers>
    <server>
      <id>byrle</id>
      <username>alice</username>
      <password>TOKEN</password>
    </server>
  </servers>
</settings>
```

```groovy
// ~/.gradle/init.d/byrle.gradle: every repository replaced with the proxy's.
def central = 'https://byrle.example.com/maven/'
def portal = 'https://byrle.example.com/gradle-plugins/'
def only = { RepositoryHandler repos, String mirror ->
    repos.all { ArtifactRepository repo ->
        if (!(repo instanceof MavenArtifactRepository) || !repo.url.toString().startsWith(mirror)) {
            repos.remove(repo)
        }
    }
    repos.maven {
        url = mirror
        credentials { username = 'alice'; password = 'TOKEN' }
    }
}
beforeSettings { settings ->
    settings.pluginManagement.repositories { only(delegate, portal) }
}
allprojects {
    buildscript { only(repositories, portal) }
    only(repositories, central)
}
```

mvn 3.10.0 chose a mirror whose `<mirrorOf>` is the repository's id before any pattern,
in the user's file or the global one: a `<mirrorOf>central</mirrorOf>` elsewhere beats the
`*` above. mvn keeps its cache by the mirror's id, so a mirror renamed `byrle` fetches
again what an earlier mirror cached, and one repointed under its old id does not. Write
the `<url>` without a trailing `/`: `wrapper:wrapper` writes `distributionUrl` from it,
and a `/maven//org/...` is answered 404. mvn retried a 503 itself, 4 times
`Retry-After` apart, and `make smoke-maven` resolved through the proxy in one run.

mvn's own plugins are decided as any jar. With advisories loaded on 2026-10-18,
`dependency:resolve` failed under the default `max_cvss`: maven-dependency-plugin 3.11.0
depends on commons-beanutils 1.9.4, refused for GHSA-wxr5-93ph-8wr9. A `packages`
exception releases it ([policy-reference](policy-reference.md)).

Gradle does not read `settings.xml`. The init script replaces the repositories each build
and plugin block declares, and sends plugins to `/gradle-plugins/`, the Gradle plugin
portal. Gradle 9.8.1 tried a 503 3 times in 3 s, ignoring `Retry-After`, so a cold build
can fail on a jar still being checked and pass when run again: a cold Spring Boot build
did, on 2026-10-17. `./gradlew` downloads Gradle itself from `services.gradle.org`, not through the
proxy: pin `distributionSha256Sum` in `gradle/wrapper/gradle-wrapper.properties`, which
`doctor` checks. `./mvnw` downloads mvn from a Central path, which the proxy serves under
`MVNW_REPOURL`.

go 1.27.2 asks the module's origin after a proxy entry followed by `|`, on any error, a
refusal included; after `,` only on a 404 or 410. A `GOPROXY` ending `,direct`, go's
default, did not reach the origin after any refusal measured. `GONOPROXY`, which
`GOPRIVATE` sets, sends the modules it matches to their origin. sum.golang.org is asked
through the proxy: `GOSUMDB` can stay as it is
([go-plan](go-plan.md) step 5).

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
| npm, pnpm, yarn 1 | `//byrle.example.com/npm/:_authToken=<token>` in `~/.npmrc` |
| bun | `registry = { url = "https://byrle.example.com/npm/", token = "<token>" }` under `[install]` in `bunfig.toml`, in place of the `registry` line above |
| pip | `https://alice:<token>@byrle.example.com/pypi/simple/` as the index URL |
| uv | `https://alice:<token>@byrle.example.com/pypi/simple` as the index URL |
| cargo | `CARGO_REGISTRIES_BYRLE_TOKEN=<token>`, or `cargo login --registry byrle`. cargo sends it alone in `Authorization` |
| go | `GOPROXY=https://alice:<token>@byrle.example.com/go`. go sends it over https only: over http it refused, "refusing to pass credentials to insecure URL", to 127.0.0.1 too |
| mvn | a `<server>` with the mirror's id, the account as `<username>` and the token as `<password>`, as above. Or `Authorization: Bearer <token>` in its `<configuration><httpHeaders>` |
| Gradle | `credentials { username = 'alice'; password = '<token>' }` in the init script, as above. Or `credentials(HttpHeaderCredentials)` with `Authorization: Bearer <token>` |
| `./mvnw` | `MVNW_USERNAME=alice` and `MVNW_PASSWORD=<token>` |
| `byrle warm` | `BYRLE_TOKEN=<token>` |

The username in pip's and uv's URL is the account name, not `__token__`: any other name is
answered 401. `make smoke-npm` and `make smoke-python` installed with npm's `_authToken`,
and pip and uv with `<account>:<token>@`, on 2026-10-11, and bun installed with the line
above. `make smoke-maven` resolved with mvn's `<server>`, Gradle's `credentials { }` and
`./mvnw`'s two variables on 2026-10-18. mvn and Gradle sent Basic after the first 401, and
on every request after it. The Bearer forms are Artifactory's and were not run. The forms
for pnpm and yarn 1 were measured on a stub registry
([account-identification](engineering_decisions/0054-account-identification.md)). No lockfile
checked records the token.

yarn 4 refuses a registry on plain HTTP unless its host is listed, as it was for this
run: `unsafeHttpWhitelist: ["127.0.0.1"]` in `.yarnrc.yml`. Behind `https://` it needs
nothing more.

Then empty each client's cache once. An install supplied from the cache never asks the
proxy: `npm cache clean --force`, `uv cache clean`, `bun pm cache rm`,
`yarn cache clean`, `go clean -modcache`, and for mvn and Gradle remove `~/.m2/repository`
and `~/.gradle/caches/modules-2`, or build once with `--refresh-dependencies`.

## 7. Check with `doctor`

```
BYRLE_PROXY_URL=https://byrle.example.com byrle doctor
```

It checks the proxy, its readiness and policy, what each installed client points at, and
which caches would skip it. It exits 1 while any install would go around the proxy. From
the run, before uv and the caches were set up:

```
     ok  proxy readiness: ready, using intel snapshot sha256:918d1ac1…, taken 2026-09-29T00:15:33Z
     ok  npm registry: http://127.0.0.1:18990/npm/
     ok  pip registry: http://127.0.0.1:18990/pypi/simple/
PROBLEM  uv registry: points at https://pypi.org/simple, not the proxy at http://127.0.0.1:18990
         fix: set UV_DEFAULT_INDEX to http://127.0.0.1:18990/pypi/simple/, or `index-url` in uv.toml
   WARN  npm cache: /home/portacot/.npm/_cacache/index-v5 holds cached packages. A warm cache supplies the whole install, so those packages never reach the proxy
         fix: npm cache clean --force
```

For mvn it reads the `settings.xml` files mvn reads, and for Gradle the init scripts and
the wrapper, which it checks against `services.gradle.org/versions/all`. From runs on
2026-10-18:

```
     ok  mvn registry: http://127.0.0.1:8080/maven/
PROBLEM  mvn extra indexes: also asks each repository a pom declares, at its own URL, whose files never reach the proxy
     ok  gradle wrapper jar: Gradle 9.8.1's, by its sha256
   WARN  gradle distribution: no distributionSha256Sum, so ./gradlew does not check gradle-9.8.1-bin.zip
         fix: set distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties to dce76f55f8e251a3a1f130eb120f30b3d271de2b76c9b0729d316b5a1b6dc01f
```

The first two are a mirror of `central` alone; `*` covers every repository.

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
as pnpm does for its configured registry ([lockfile-verify](engineering_decisions/0093-lockfile-verify.md)).
`Cargo.lock` records none for any crates.io crate, so it exits 2 for each.

cargo retries a 503 three times, a second apart, so it waits about 3 seconds for an
analysis. Reading `rustls` 0.23.45's `.crate` took 79 ms. `byrle warm --lockfile
Cargo.lock` asks for each crate first.

go does not retry a 503: each zip's first fetch fails the go command until it is run
again. `make smoke-go` built `rsc.io/quote` v1.5.2, 3 zips, in 6 runs, and downloaded the
go1.26.0 toolchain in 8. `byrle warm --lockfile go.sum` asks for each zip first.
`go.sum` records no URL, so `lockfile verify` exits 2 for each module.

mvn writes no lockfile. Gradle's `dependencies --write-locks` writes `gradle.lockfile`,
read from Central, and `buildscript-gradle.lockfile` and `settings-gradle.lockfile`, read
from the plugin portal. `byrle warm` asks for each locked jar: over the three files of a
project with a BOM, lombok and a portal plugin, on 2026-10-17, it warmed 32 and reported
3 refused, lombok and two BOMs that publish no jar. Gradle's lockfiles record no URL, so
`lockfile verify` exits 2 for each.

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

## 11. The console

The console shows what was installed, refused and failed, and by whom. It needs the
database, and logs in with an account's password:

```
$ byrle account create alice --role admin
account alice created
$ read -rs password; printf '%s\n' "$password" | byrle account password alice
password of account alice set
```

Then give it a path beside the proxy's, and start the proxy again:

```
BYRLE_PROXY_URL=https://byrle.example.com/registry/
BYRLE_CONSOLE_URL=https://byrle.example.com/admin/
BYRLE_ACCOUNT_EVENT_LOG=/var/log/byrle/events.jsonl
```

`https://byrle.example.com/admin/` is the login form. Behind nginx, set `BYRLE_RP_KEY` and
the two headers in [fronting-tls](fronting-tls.md), so failed logins are counted by the
client's address rather than nginx's. The API under `admin/api/v1/` takes the same
session, or a proxy token; [console-api](console-api.md) lists each endpoint.

## When it is in the way

[break-glass](break-glass.md) says how to install while the proxy is down, and how to
release a refused package without a restart.
