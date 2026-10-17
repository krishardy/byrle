# Stage 6 plan: Maven

Maven is the fifth row of the adapter table, after cargo ([cargo-plan](cargo-plan.md)) and
Go ([go-plan](go-plan.md)). Written 2026-10-16. Every measurement below was made that day,
with Maven 3.10.0 and Gradle 9.8.1 on Temurin 21.0.12.1 against `repo1.maven.org` and
`plugins.gradle.org`, and a stub relaying to them that logged each request and answered
what a scenario set.

## What Central serves

| | Measured |
|---|---|
| Artifact metadata | `org/apache/commons/commons-lang3/maven-metadata.xml`: XML, `<latest>`, `<release>`, 27 `<version>`s, one `<lastUpdated>` for the artifact. No time per version |
| Group metadata | `org/apache/maven/plugins/maven-metadata.xml`, `org/codehaus/mojo/maven-metadata.xml`: plugin prefixes, read to resolve `dependency:resolve` |
| Files | `.pom`, `.jar`, `-sources.jar`, `-javadoc.jar`, `.module`, SBOMs, each beside `.md5`, `.sha1` and `.asc` |
| Headers | `last-modified`, `etag`, `x-checksum-md5`, `x-checksum-sha1`. No sha256 header |
| Strong digests | a `.sha256` or `.sha512` beside 21 of the 94 jars and 50 of the 242 poms mvn fetched for a Spring Boot 3.5.6 build, and beside 11 of the 34 jars Gradle fetched for it. By group: jackson, tomcat-embed and micrometer have them; Spring's 15 jars, commons-lang3, slf4j, logback and log4j do not |
| Gradle module metadata | a `.module` beside 36 of the 107 poms Gradle fetched. It lists each file of each variant with its size, sha1, md5, sha256 and sha512. It gives the sha256 of 21 of the 34 jars, 15 of them Spring's, and all 21 matched the jar. Spring's 22 `.module`s have only a `.sha1` and `.md5` beside them |
| Signatures | a PGP `.asc` beside 93 of the 94 jars; a `.sigstore.json` beside none |
| Publish time | each file's `Last-Modified`. search.maven.org's `timestamp` agreed with it to 0.4 s for the 3 versions it answered, and timed out after 30 s for 5 others |

## What mvn does, measured against the stub

`<mirror><mirrorOf>*</mirrorOf><url>http://127.0.0.1:18891/maven2</url></mirror>` in
`settings.xml`, a fresh local repository, and `dependency:resolve` of `commons-lang3`
3.17.0 unless the row says otherwise:

| Stub | mvn |
|---|---|
| relaying, Spring Boot 3.5.6 starter-web | 678 requests in 22 s: 242 `.pom`, 94 `.jar`, 339 `.sha1`, 3 `maven-metadata.xml`. A plain-http mirror was used without a warning |
| relaying | `.pom`, `.pom.sha1`, `.jar`, `.jar.sha1` for the pinned version; `maven-metadata.xml` only for a range or a version-less plugin |
| the jar 503, `Retry-After: 1`, once | fetched it 1 s later, and built |
| the jar 503, `Retry-After: 1`, always | 4 requests 1 s apart, then failed: "HTTP Status: 503" |
| the jar 503, `Retry-After: 5`, always | 4 requests 5 s apart, then failed |
| the jar 403 | failed at once, no retry: "HTTP Status: 403" |
| the jar's `.sha1` 404 | asked `.md5` instead, and built |
| the jar's `.sha1` wrong | `WARNING Checksum validation failed`, and built |
| the jar's body short of its `Content-Length` | failed: "Premature end of Content-Length delimited message body", no jar stored |
| a range, `[3.0,3.18)` | read the artifact's `maven-metadata.xml` and fetched 3.17.0 |
| that, 3.17.0 removed from the metadata | fetched 3.16.0, warning that the metadata's `.sha1` did not match; the metadata was fetched twice |
| 401 with `WWW-Authenticate: Basic` | failed without credentials. With `<server><id>` matching the mirror's id, sent Basic after the first 401 and on every request after it: 2 answered 401, 14 Basic |

So a refusal is a 403 on the pinned fetch, and the build fails: a pinned version reads no
metadata, so removing a refused version from it changes only a range. With the checksum
policy at its default, `warn`, mvn builds through a wrong sidecar, and only a body that
ends short stops it.

## What Gradle does, measured against the stub

`repositories { maven { url = 'http://127.0.0.1:18892/maven2'; allowInsecureProtocol = true } }`,
a fresh Gradle home, `--no-daemon`, and a task reading `runtimeClasspath`'s files, with
`commons-lang3` 3.17.0 unless the row says otherwise:

| Stub | Gradle |
|---|---|
| relaying, Spring Boot 3.5.6 starter-web | 177 requests in 11 s: 107 `.pom`, 36 `.module`, 34 `.jar`. No `.sha1` |
| relaying, plain http to 10.89.8.5 without `allowInsecureProtocol` | failed: "Using insecure protocols with repositories, without explicit opt-in, is unsupported". To 127.0.0.1 it was allowed |
| the jar 503, `Retry-After: 1`, once | fetched it 1 s later, and built |
| the jar 503, `Retry-After: 5`, always | 3 requests, at +0, +1 and +3 s, then failed: "Received status code 503 from server: Service Unavailable" |
| the jar 403 | failed at once, no retry: "Received status code 403 from server: Forbidden" |
| the `.pom` 403 | failed at once: "Could not resolve org.apache.commons:commons-lang3:3.17.0" |
| the jar's body short of its `Content-Length` | 3 requests, at +0, +1 and +3 s, then failed: "Premature end of Content-Length delimited message body" |
| a range, `[3.0,3.18)` | read the artifact's `maven-metadata.xml` and fetched 3.17.0 |
| that, 3.17.0 removed from the metadata | fetched 3.16.0. No `.sha1` of the metadata asked |
| that, the metadata 404 | failed: "no versions of org.apache.commons:commons-lang3 are available" |
| 401 with `WWW-Authenticate: Basic`, `credentials { }` set | sent Basic after the first 401 and on every request after it: 1 answered 401, 6 Basic |
| a jar cached from another repository URL | `HEAD` of the `.pom` and the `.jar`, `GET` of each one's `.sha1`, and no `GET` of the jar. A 403 on the jar's `HEAD` failed the build |

An init script in `$GRADLE_USER_HOME/init.d/` that removes every repository but the
mirror, in `pluginManagement` and in each project, sent all 177 requests of an unedited
build declaring `mavenCentral()` to the Central relay, and all 34 of an unedited plugin
lookup to the portal relay, with the JVM given no proxy. Gradle does not read
`settings.xml`.

With `--write-verification-metadata pgp,sha256`, Gradle fetched an `.asc` beside every
file. Its default key servers were `pgp.mit.edu` and `ha.pool.sks-keyservers.net`, and it
recorded 3 of 3 keys as "couldn't be downloaded from any key server". With
`keys.openpgp.org` and `keyserver.ubuntu.com` configured, it trusted 22 keys and ignored
none. The Spring Boot build then verified, 34 of 34 jars with a `.asc`; with
`slf4j-api-2.0.17.jar` answered with 2.0.16's bytes, it failed: "One artifact failed
verification: slf4j-api-2.0.17.jar".

## The Gradle plugin portal

A plugin is found through its marker, `<id>/<id>.gradle.plugin/<version>/<id>.gradle.plugin-<version>.pom`,
whose dependency is the plugin's jar. `org.springframework.boot` 3.5.6's marker is on
Central; `com.github.ben-manes.versions` 0.52.0's is only on the portal. Of the 34 files
the portal answered for that plugin:

| Portal's answer | Files |
|---|---|
| 200, itself | 1 `.pom`, the marker |
| 303 to `plugins-artifacts.gradle.org/<group>/<artifact>/<version>/<sha256>/<file>` | 1 `.pom`, 1 `.jar`, 1 `.module`. The sha256 in the path matched each body |
| 303 to `repo.maven.apache.org` | 13 `.pom`, 9 `.jar`, 7 `.module` |

The portal answers a `.sha256`, `.sha512` or `.asc` it does not hold with a 303 to
Central, which answered 404 for the plugin's `.pom.sha256`.

## The Gradle wrapper

`gradle wrapper` writes `distributionUrl=https\://services.gradle.org/distributions/gradle-9.8.1-bin.zip`
and no `distributionSha256Sum`. That URL answers a 302 to
`release-assets.githubusercontent.com`. The wrapper fetches the distribution itself, not
through a repository, so a mirror does not see it.

## Code run at build

javac runs an annotation processor it finds on the classpath, declared in a jar's
`META-INF/services/javax.annotation.processing.Processor`, unless told otherwise.
`lombok` 1.18.40 as a plain dependency, maven-compiler-plugin 3.16.0:

| JDK | Lombok's processor |
|---|---|
| Temurin 21.0.12.1 | ran: `getX()`, which only it generates, compiled, with no warning |
| Temurin 25.0.4.1 | did not run: "cannot find symbol: method getX()" |

Gradle 9.8.1 on Temurin 21.0.12.1 did not run Lombok's processor from `implementation`:
"cannot find symbol". From `annotationProcessor` it ran.

None of the 94 jars in the Spring Boot build declares a processor. A plugin's jar is code
run at build by definition, and is fetched through the same mirror.

## Signatures, measured over the 94 jars

| | |
|---|---|
| `.asc` present | 93 |
| key found on keys.openpgp.org and keyserver.ubuntu.com | 81 |
| key found only on keyserver.ubuntu.com | 12 |
| signature good, with keys.openpgp.org's copy | 61 |
| signature good, only with keyserver.ubuntu.com's copy | 27 |
| signed by a key since expired | 4 |
| signed by a key since revoked | 1 |
| hash in the signature: SHA-512, SHA-256, SHA-1 | 55, 33, 5 |

The signatures are by 31 keys. Of the 27 good only with keyserver.ubuntu.com's copy, 12 are
by a key keys.openpgp.org does not hold, and 15 by one whose copy there did not verify with
gpg 2.4.8.

## Advisories, OSV's `Maven/all.zip`

10,406,912 bytes, 7,191 records: 7,189 `GHSA-` and 2 `MAL-`; 113 withdrawn. Of the 7,078
not withdrawn, 6,620 carry a severity. Ranges are `ECOSYSTEM` (13,370) and `SEMVER` (121),
so they are compared in Maven's own version order. Every `Maven` package name is
`groupId:artifactId`.

## The adapter, checked against today's `Registry`

| Need | Hook it uses |
|---|---|
| `/maven/` paths: metadata, `.pom`, `.jar` and sidecars | `classify_path`, `upstream_url` |
| `maven-metadata.xml` filtered: `<version>`s, `<latest>` and `<release>` | `read` |
| the filtered metadata's `.sha1` and `.md5`, written by the proxy | none: `write` answers from the path alone, without fetching, as for Go's `supported`. A sidecar of a filtered document is a new hook |
| a refusal on `HEAD` as on `GET`, and the `.sha1` of a refused file refused with it | `classify_path`, as today's `HEAD` |
| a version's time from its `.pom`'s `Last-Modified` | `Fetch::version`, as Go's `.info` |
| a list dated newest first under a cooldown | `Fetch::dated`, as Go's |
| a jar's digest from its sidecar, checked against its bytes in a job, served against their sha256 | `Fetch::claim` and the claim job, as Go's `h1:` |
| annotation processors read from the jar | `reader`, as a `.crate`'s build script |
| Maven's version order | a `VersionOrder` arm, as Go's |
| `settings.xml`'s mirror and server, for `byrle doctor` | `clients` |
| `osv/maven` | `streams` |

One new hook, for the filtered metadata's sidecars.

## Publish times against version order

Every version in `maven-metadata.xml`, each `.pom`'s `Last-Modified`, sorted by Maven
3.10.0's `ComparableVersion`:

| Artifact | Versions | No `Last-Modified` | Published after a higher version | First two |
|---|---|---|---|---|
| `org.springframework:spring-core` | 336 | 0 | 130 | 1.2.7 on 2006-05-10, after 2.0-m1; 1.2.8 on 2006-08-24, after 2.0-m1 |
| `com.fasterxml.jackson.core:jackson-databind` | 235 | 0 | 86 | 2.1.5 on 2013-05-03, after 2.2.0-rc1; 2.2.4 on 2014-06-11, after 2.3.0-rc1 |
| `org.apache.logging.log4j:log4j-core` | 78 | 0 | 23 | 2.3.1 on 2021-12-21, after 2.4; 2.3.2 on 2021-12-29, after 2.4 |
| `com.google.guava:guava` | 160 | 0 | 13 | 12.0.1 on 2012-07-10, after 13.0-rc1; 22.0-rc1 on 2017-05-02, after 22.0-rc1-android |
| `org.apache.commons:commons-lang3` | 27 | 0 | 0 | |

spring-core 6.2.19 and 7.0.8 were both published 2026-06-08. A range `[6.2,7)` picks the
highest version in it, 6.2.19, whatever 7.x holds. Under a cooldown covering 2026-06-08 and
not 7.0.7's date, a list dated newest first until one version is older than the cooldown,
as Go's is, stops at 7.0.7 and leaves 6.2.19 undated. The range then picks 6.2.19, whose
jar is refused. HEAD of all 336 spring-core `.pom`s, 16 at
a time, took 1.9 s.

## Decisions

Answered by the user 2026-10-16. Q1, Q3, Q4, Q5, Q6, Q8 and Q10 as recommended;
Q2, Q7 and Q9 otherwise.

| | Question | Decided |
|---|---|---|
| Q1 | Where Maven is served | `/maven/` |
| Q2 | Where a jar's strong digest comes from | Both. The `.sha256` or `.sha512` when published, otherwise the `.sha1`, checked against the bytes in the claim job and served against their sha256, in a decision superseding 0017 for Maven. The `.asc` is decided by `provenance`, extended to PGP: see step 2.2 |
| Q3 | Whether a `.pom` is refused by policy | No. A `.pom` is checked against its sidecar and signature, and not refused by policy |
| Q4 | Annotation processors | `install_scripts`, read from the jar's `META-INF/services/javax.annotation.processing.Processor` |
| Q5 | Plugins | Decided as any artifact. A plugin jar holds `META-INF/maven/plugin.xml` or `META-INF/gradle-plugins/<id>.properties`; 9 of the 94 jars mvn fetched were plugins from Maven 3.10.0's default lifecycle, which the probe's `pom.xml` did not declare |
| Q6 | Publish times | The `.pom`'s `Last-Modified` |
| Q7 | Tokens | The proxy reads Basic and Bearer already ([request-flow](request-flow.md), forms 2 and 3). The quickstart shows Basic first, from `settings.xml`'s `<server>` and the init script's `credentials { }`, and Bearer second, from `<httpHeaders>` and `HttpHeaderCredentials`, as Artifactory documents both |
| Q8 | Where the plugin portal is served | `/gradle-plugins/` |
| Q9 | Whether the proxy serves wrapper distributions | Not served: `./gradlew` fetches the distribution from `services.gradle.org` itself. `byrle doctor` reads the version from `gradle-wrapper.properties`'s `distributionUrl` and reports a missing `distributionSha256Sum`, one that differs from `services.gradle.org/versions/all`'s `checksum`, a `gradle-wrapper.jar` whose sha256 differs from its `wrapperChecksum`, and a version whose `buildTime` is inside the cooldown |
| Q10 | Whether `make dev-setup` installs Gradle | Yes: Gradle 9.8.1 pinned beside `scripts/make/lib/java.sh`, checked against its sha256, watched by `check-deps` |

## Steps

1. `make install-gradle`: Gradle 9.8.1 pinned in `scripts/make/lib/gradle.sh` beside
   `java.sh`, checked against `services.gradle.org`'s sha256, wired into `dev-setup` and
   watched by `check-deps` (Q10). Done 2026-10-16: `make install-gradle` installs it under
   `~/.local/share/byrle` beside the JDK and links `gradle` in `~/.local/bin`.
2. Three engineering decisions, written before the code they govern. Done 2026-10-16 and
   2026-10-17:
   1. [maven-digests](engineering_decisions/0112-maven-digests.md): the strongest of a
      file's `.sha512`, `.sha256` and `.sha1`, a jar checked in the claim job and served
      against its sha256. It supersedes 0017's refusal of SHA-1 for Maven only.
   2. [maven-signatures](engineering_decisions/0113-maven-signatures.md): 0066's three
      cases, with the signing primary key as the identity, under `provenance`. A
      signature by a key since expired verifies when made before the expiry; a revocation
      is read as RFC 9580 reads it; a key no key server holds fails verification.
   3. [maven-files-unchanged](engineering_decisions/0114-maven-files-unchanged.md),
      raised 2026-10-17: byrle passes every Maven file and sidecar through
      byte for byte, except a `maven-metadata.xml` it filters and that file's `.sha1`
      and `.md5`. A client checking a jar against a digest or a PGP signature from
      outside byrle then catches byrle itself changing it. mvn and Gradle ask for a
      sidecar from the repository that served its file, so the outside check is a PGP
      key fetched from a key server, or a digest recorded before, as Gradle's committed
      `verification-metadata.xml` records one.
3. `VersionOrder::Maven`, Maven's `ComparableVersion` order, checked against Maven
   3.10.0's own comparison over every version in OSV's `Maven` ranges. Done 2026-10-16:
   `intel::comparable_version`, ported from `maven-artifact` 3.10.0's `ComparableVersion.java`. OSV's
   `Maven/all.zip` names 40,883 distinct versions. Over 1,000,529 pairs of them, each
   with its neighbour by text and the rest drawn at random, byrle and Maven gave the same
   answer for every pair. Maven's order is not total. In Maven 3.10.0 and in byrle,
   `1.0-dev-2.20021231.045254` < `1.0.0.beta.2` < `1.0.0` < `1.0-dev-2.20021231.045254`.
   So the sorted lists differ by sort algorithm, and Rust's sort of the 40,492 versions
   that start with a digit panicked: "user-provided comparison function does not
   correctly implement a total order". A range's events are now sorted by insertion,
   which ends whatever the order, and no Maven version is given to a std sort. Step
   4.4's dating needs no sort; `<latest>` and `<release>` are a maximum.
   `make mutants`: 88 mutants, 67 caught, 21 unviable.
4. The Maven adapter, with the hooks of "The adapter, checked against today's
   `Registry`". npm, PyPI, cargo and Go unchanged. In six parts, each refusing what it
   cannot yet check:
   1. The row, `/maven/` paths, `maven-metadata.xml` filtered (`<version>`s, `<latest>`,
      `<release>`), `osv/maven`, and `BYRLE_UPSTREAM_MAVEN`. A `HEAD` is decided as a
      `GET`, as Gradle reuses a cached jar after a `HEAD` alone. Every jar is refused as
      publishing no strong digest. Done 2026-10-16: `ecosystem::maven`. A key's name is
      `groupId/artifactId`, read from `groupId:artifactId` as OSV and a selector write it.
      `maven-metadata.xml` is read with quick-xml 0.42.0, MIT, and a refused version's
      line is removed with every other byte kept; `<latest>` and `<release>` naming one
      name the highest left. A `maven-metadata.xml` whose `<groupId>` and `<artifactId>`
      are not its path's, as a group's plugin prefixes are not, is forwarded unread. Any
      file in a version's directory but a sidecar, a `.pom` and a `.module` is decided as
      that version's: a `.war` or a `-sources.jar` as a jar is. `Registry::decides_head`
      is true for Maven alone, so npm's `HEAD` stays undecided. Each of the 96 jars mvn
      and Gradle fetched for the Spring Boot build is listed in its artifact's
      `maven-metadata.xml`, so a pinned jar's record comes from that document, fetched by
      the proxy. smoke-cargo 8/8, ready after `osv/maven` loaded live.
      `make mutants`: 148 mutants, 104 caught, 39 unviable, 1 timed out, 4 missed; the
      4 were caught by two tests added after, which `wire.rs`'s 68 mutants ran against:
      54 caught, 13 unviable, 1 timed out. The timeout is the `Eof` arm deleted, which
      reads `Eof` without end.
   2. The new hook: the `.sha1` and `.md5` of a filtered `maven-metadata.xml`, written by
      the proxy from the filtered body. mvn warned on the unfiltered `.sha1`; Gradle asked
      none. Done 2026-10-17: `Registry::sidecar`, and `proxy::sidecar`, which fetches the
      document, filters it as its own request would, without writing its refusals to the
      audit log again, and answers the digest of the body served. A document served as
      it came, or one that cannot be fetched or read, has the repository's sidecar
      forwarded. Measured with mvn 3.10.0 through the proxy, `[3.0,3.18)` with 3.17.0
      denied: the first run warned "Checksum validation failed, expected
      '6e9bad07...' (REMOTE_INCLUDED)" before mvn asked for any `.sha1`. Central sends
      `x-checksum-sha1` and `x-checksum-md5` with the file, and mvn checks a body against
      them first. A rewritten document of any ecosystem now goes without the upstream's
      digest headers (`proxy::UPSTREAM_DIGESTS`), as its length and entity tag were
      already its own. The second run resolved 3.16.0 with no warning, its `.sha1`
      written by the proxy; the 3.16.0 jar was 403, as every jar is until part 3.
      `make mutants`: 28 mutants, 20 caught, 8 unviable.
   3. The claim (0112). A `.pom` and a `.module` are checked in the request against their
      sidecar and never refused by policy (Q3); a jar's first fetch is 503 while the claim
      job checks it. mvn retried a 503 4 times at `Retry-After`; Gradle 3 times in 3 s,
      ignoring it, so a claim job longer than that fails a Gradle build until it is run
      again.
      Done 2026-10-17. `Fetch::claim` is asked of a file, and `RequestTarget::Manifest`
      names one: a version's jar, `-sources.jar`, `.pom` and `.module` each have their own
      sidecar. `maven::digest` reads the first of `.sha512`, `.sha256` and `.sha1` beside
      the file as `<algorithm>:<hex>`, its first word of hex the algorithm's length; a
      404 asks the next, one holding no such word is passed over, and none is
      `Claimed::Unknown`, refused as no strong digest. A claim is kept per file. A `HEAD`
      of a `.pom` is forwarded unchecked: it has no body. Measured 2026-10-17 through the
      proxy, an in-process claim store:

      | Build | Result |
      |---|---|
      | mvn 3.10.0, `commons-lang3` 3.17.0 | BUILD SUCCESS. The `.pom` verified in the request; the jar 503, its `sha1:b17d2136...` checked against its bytes, the retry served verified |
      | mvn 3.10.0, Spring Boot 3.5.6 starter-web, cold | BUILD SUCCESS in 93 s, 22 s straight from Central. 94 jars checked, 247 poms verified; claims 419 `sha1` and 114 `sha512` |
      | Gradle 9.8.1, the same build, cold | failed: `spring-web-6.2.11.jar` was still being checked after Gradle's third try |
      | Gradle 9.8.1, run again | succeeded in 4 s, 34 jars |

      From each jar's first 503 to its claim checked, cold: 3 of 34 over 3 s,
      `spring-boot-3.5.6.jar` 3.1 s, `spring-web-6.2.11.jar` and
      `spring-boot-autoconfigure-3.5.6.jar` 3.3 s. Gradle's tries came at +0, +1 and +3 s.
      Holding the download open while its claim is checked, which a 2 s hold would have
      covered for all 34, was asked of the user 2026-10-17 and declined, as for Go: each
      request held open keeps a connection and a task on the proxy for as long as its
      claim job runs, so a client asking many unchecked files at once could exhaust them.
      A 503 releases both at once. A cold Gradle build can fail and pass when run again,
      which step 9's quickstart says.
      `make mutants`: 65 mutants, 49 caught, 16 unviable.
   4. Cooldown from the `.pom`'s `Last-Modified` (Q6): every version in the list dated,
      by a `HEAD` per version, and each time kept, as a file on Central is never replaced.
      Not newest first until one is older, as Go's: "Publish times against version order"
      has 130 of spring-core's 336 versions published after a higher one. A pinned
      version is dated by its own `.pom`.
      Done 2026-10-17: `maven::Client::dated` asks a `HEAD` of every version's `.pom`, 16
      at a time, whatever the cooldown, and keeps each time read; a version with no `.pom`
      is left undated. `Fetch::version` reads a pinned version's record from its own
      `.pom`, so its jar is decided on that time, and a version whose `.pom` is 404 falls
      back to the document's record. Measured with mvn 3.10.0 through the proxy,
      `cooldown_days: 30`: `[3.18,)` resolved 3.20.0, published 2025-11-12, with 3.21.0,
      published 2026-09-25, removed; all 27 versions dated.
      `make mutants`: 25 mutants, 5 caught, 20 unviable.
   5. Signatures (0113), under `provenance`, as amended 2026-10-17. In three parts:
      1. A jar's signature, cases 1 and 2. Done 2026-10-17. `pgp` 0.21.0, with `rsa`
         accepted for verification ([sqlx-0-8-and-rsa-advisory](engineering_decisions/0028-sqlx-0-8-and-rsa-advisory.md)).
         `Claim::signer`, a `Signer` the adapter makes, is handed to the claim job: the
         `.asc` and its key are fetched as the jar spools, both key servers at once,
         and the result is stored in `artifact_signature`, migration 0026, by the jar's
         sha256 and the verifier, before the claim. Its provenance fact: verified or
         unsigned is consistent, failed is unverified, and no `.asc` after an earlier
         version's is dropped, the earlier versions asked newest first by their `.pom`
         times. A key server that does not answer stores nothing, so the next request
         checks again. Migration 0026 also widens `artifact_claim.claim` to 160: a
         `sha512:` claim is 135 characters, which Postgres refused at 128.
         Measured through the proxy, cold:

         | Build | Result |
         |---|---|
         | mvn 3.10.0, Spring Boot 3.5.6 | BUILD SUCCESS in 95 s, 93 s before signatures. 93 jars verified, 1 unsigned with no signed version before it |
         | Gradle 9.8.1, the same build | failed once, then succeeded, as before signatures. 4 of 34 jars checked more than 3 s after their first 503, against 3 before; with the key servers asked one after the other, 15 |

         `make mutants`: 140 mutants, 50 caught, 82 unviable, 8 missed. Two were caught by
         tests added after, each checked by applying the mutant by hand. Six are the
         Postgres store's signature read and write, which only `make test-integration`
         runs; two of them applied by hand failed its round trip.

      2. A `.pom`'s and a `.module`'s signature, the first fetch 503 until checked. Done
         2026-10-17: a manifest with a signer goes through the claim job as a jar does,
         then is served against the sha256 of its bytes; a signature that fails is 502.
         A file checked against a digest is now asked of the upstream as `identity`:
         Central gzips a `.pom` a client accepts gzipped, and the digest names the
         uncompressed bytes, which first answered every `.pom`'s retry with a body cut
         short. A key expired when it signed no longer fails verification (0113,
         amended): `rsocket-bom-1.1.5.pom`'s did, and with it every Gradle build of a
         Spring Boot project. `BYRLE_CLAIM_RETRY_AFTER`, 2 by default, is the deferral's
         `Retry-After`. Measured through the proxy:

         | Build | Result |
         |---|---|
         | mvn 3.10.0, Spring Boot 3.5.6, cold | BUILD SUCCESS in 295 s; at `Retry-After: 1` it failed |
         | mvn, the same proxy, an empty local repository | 16 s |
         | Gradle 9.8.1, after the mvn runs | succeeded in 130 s, the BOMs it imports new to the proxy; again, 3 s |

         A `.pom` on Central whose signature does not verify, gpg agreeing:
         `maven-dependency-plugin-2.0-alpha-1.pom`, 2007, is 502.
         `make mutants`: 37 mutants, 7 caught, 28 unviable, 2 missed, each the `purl`
         a manifest is fetched with, which tests added after assert.
      3. Case 3 as the signal `signing_key_new`, weight 1, from the earlier versions'
         `.asc`.
   6. Annotation processors (Q4): a jar holding
      `META-INF/services/javax.annotation.processing.Processor` has install scripts.
      A plugin jar is decided as any other (Q5).
5. The plugin portal under `/gradle-plugins/` (Q8): a second upstream of the Maven row,
   relaying `plugins.gradle.org/m2` and following its 303s. A 303 to
   `plugins-artifacts.gradle.org` carries the file's sha256 in its path, which is the
   claim; one to Central is decided as `/maven/` decides it. `BYRLE_UPSTREAM_GRADLE_PLUGINS`.
6. `gradle.lockfile` for `warm`, `policy diff` and `lockfile verify`. mvn writes no
   lockfile.
7. `byrle doctor` for mvn and Gradle:

   | Reads | Reports |
   |---|---|
   | `settings.xml` | a `<mirror>` not `mirrorOf` `*` or not the proxy, and no `<server>` with the mirror's id when tokens are required |
   | `$GRADLE_USER_HOME/init.d/` | no init script sending repositories and `pluginManagement` to the proxy |
   | `gradle-wrapper.properties` and `gradle-wrapper.jar` | Q9's four checks, against `services.gradle.org/versions/all` |
   | `~/.m2/repository` and Gradle's `caches/modules-2` | a cached refused version, as Go's module cache |
   | `gradle/verification-metadata.xml` | none, or one with `<verify-signatures>` false: no check of byrle from outside it, per step 2.3 |

8. `make smoke-maven`: mvn and Gradle builds of a real project through the proxy over
   https, with a token, a refused version, a cooldown, an advisory, an annotation
   processor, a portal plugin, and the wrapper checks. Gradle run as `./gradlew` with the
   init script, a case not measured in this plan. A first fetch answered 503 is run
   again.
9. Docs: quickstart (Basic first, Bearer second, per Q7), policy-reference,
   threat-model (the wrapper download as a bypass, and byrle checked from outside by
   PGP signatures whose keys come from key servers, per step 2.3), request-flow, and the
   README.

## Exit

An mvn build and a Gradle build of a real project through the proxy with a token,
enforcing the defaults: a refused version is not chosen by a range, a pinned one answers
403, and an advisory from `osv/maven` refuses what it names. npm, PyPI, cargo and Go pass
their smoke tests unchanged.
