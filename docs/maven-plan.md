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

One new hook, for the filtered metadata's sidecars. Q2's answer decides whether the claim
is the sidecar, the signature, or both.

## Questions

Answered 2026-10-16.

| | Question | Recommended |
|---|---|---|
| Q1 | Where Maven is served | Under `/maven/`, as `/go/`: `<mirror><url>https://byrle.example.com/maven</url>` for mvn, and an init script in `$GRADLE_USER_HOME/init.d/` for Gradle |
| Q2 | Where a jar's strong digest comes from. 73 of the 94 jars mvn fetched have only `.sha1` and `.md5`; [artifact-digest-verification](engineering_decisions/0017-artifact-digest-verification.md) refuses SHA-1, which would refuse 78% of them. A `.module`'s sha256 covers Spring's 15, but each of those `.module`s has only a `.sha1` | `.sha256` or `.sha512` when published; otherwise the `.sha1`, checked against the bytes in the claim job and served against their sha256. The check is against a body changed on the way, which needs a second preimage of SHA-1, not a collision. A decision superseding 0017 for Maven. The other two: verify the `.asc`, 88 of 93 good with gpg and 34 of 34 with Gradle, which needs an OpenPGP crate and a key trusted per group on first use; or the sha256 of the first fetch, which no one else claims. A portal file at `plugins-artifacts.gradle.org` has its sha256 in its path |
| Q3 | Whether a `.pom` is refused by policy | No, as Go's `go.mod`: 242 poms against 94 jars, most of them parents and BOMs no build compiles. A `.pom` is checked against its sidecar |
| Q4 | Annotation processors | `install_scripts`, read from the jar's `META-INF/services/javax.annotation.processing.Processor`. 0 of 94 in the Spring Boot build. mvn on JDK 21 ran one unasked; on JDK 25 it did not; Gradle ran one only from `annotationProcessor` |
| Q5 | Plugins | Decided as any artifact: refusing every plugin under `install_scripts` would refuse every build |
| Q6 | Publish times | The `.pom`'s `Last-Modified`, a `HEAD` per version, newest first under a cooldown, as Go's `.info`. search.maven.org timed out on 5 of 8 versions |
| Q7 | Tokens | `Basic`, after the 401's challenge: from `settings.xml`'s `<server>` with the mirror's id for mvn, and `credentials { }` in the init script for Gradle |
| Q8 | Where the plugin portal is served | Under `/gradle-plugins/`, relaying `plugins.gradle.org/m2` and following its 303s, a separate upstream from `/maven/` |
| Q9 | Whether the proxy serves wrapper distributions | No: `services.gradle.org` is not a repository. `byrle doctor` warns when `gradle-wrapper.properties` has no `distributionSha256Sum` |
| Q10 | Whether `make dev-setup` installs Gradle | Yes, pinned in a script beside `scripts/make/lib/java.sh`, with its sha256 from `services.gradle.org` |

| | Answer |
|---|---|
| Q1 | `/maven/` |
| Q2 | Both. The `.sha256` or `.sha512` when published, otherwise the `.sha1`, checked against the bytes in the claim job and served against their sha256, in a decision superseding 0017 for Maven. The `.asc` is also verified when its key is found: a bad signature refuses the file. A file with no `.asc`, or with a key not found, expired or revoked, is decided by a new policy key, off by default |
| Q3 | No. A `.pom` is checked against its sidecar and signature, and not refused by policy |
| Q4 | `install_scripts`, read from the jar's `META-INF/services/javax.annotation.processing.Processor` |
| Q5 | Decided as any artifact. A plugin jar holds `META-INF/maven/plugin.xml` or `META-INF/gradle-plugins/<id>.properties`; 9 of the 94 jars mvn fetched were plugins from Maven 3.10.0's default lifecycle, which the probe's `pom.xml` did not declare |
| Q6 | The `.pom`'s `Last-Modified` |
| Q7 | The proxy reads Basic and Bearer already ([request-flow](request-flow.md), forms 2 and 3). The quickstart shows Basic first, from `settings.xml`'s `<server>` and the init script's `credentials { }`, and Bearer second, from `<httpHeaders>` and `HttpHeaderCredentials`, as Artifactory documents both |
| Q8 | `/gradle-plugins/` |
| Q9 | Not served: `./gradlew` fetches the distribution from `services.gradle.org` itself. `byrle doctor` reads the version from `gradle-wrapper.properties`'s `distributionUrl` and reports a missing `distributionSha256Sum`, one that differs from `services.gradle.org/versions/all`'s `checksum`, a `gradle-wrapper.jar` whose sha256 differs from its `wrapperChecksum`, and a version whose `buildTime` is inside the cooldown |
| Q10 | Yes: Gradle 9.8.1 pinned beside `scripts/make/lib/java.sh`, checked against its sha256, watched by `check-deps` |

## Steps

To be written once the questions are answered.
