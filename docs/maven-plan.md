# Stage 6 plan: Maven

Maven is the fifth row of the adapter table, after cargo ([cargo-plan](cargo-plan.md)) and
Go ([go-plan](go-plan.md)). Written 2026-10-16. Every measurement below was made that day,
with Maven 3.10.0 on Temurin 21.0.12.1 against `repo1.maven.org`, and a stub relaying to
it that logged each request and answered what a scenario set.

## What Central serves

| | Measured |
|---|---|
| Artifact metadata | `org/apache/commons/commons-lang3/maven-metadata.xml`: XML, `<latest>`, `<release>`, 27 `<version>`s, one `<lastUpdated>` for the artifact. No time per version |
| Group metadata | `org/apache/maven/plugins/maven-metadata.xml`, `org/codehaus/mojo/maven-metadata.xml`: plugin prefixes, read to resolve `dependency:resolve` |
| Files | `.pom`, `.jar`, `-sources.jar`, `-javadoc.jar`, `.module`, SBOMs, each beside `.md5`, `.sha1` and `.asc` |
| Headers | `last-modified`, `etag`, `x-checksum-md5`, `x-checksum-sha1`. No sha256 header |
| Strong digests | a `.sha256` or `.sha512` beside 21 of the 94 jars and 50 of the 242 poms a Spring Boot 3.5.6 build fetched. By group: jackson, tomcat-embed and micrometer have them; Spring's 15 jars, commons-lang3, slf4j, logback and log4j do not |
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

## Code run at build

javac runs an annotation processor it finds on the classpath, declared in a jar's
`META-INF/services/javax.annotation.processing.Processor`, unless told otherwise.
`lombok` 1.18.40 as a plain dependency, maven-compiler-plugin 3.16.0:

| JDK | Lombok's processor |
|---|---|
| Temurin 21.0.12.1 | ran: `getX()`, which only it generates, compiled, with no warning |
| Temurin 25.0.4.1 | did not run: "cannot find symbol: method getX()" |

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

| | Question | Recommended |
|---|---|---|
| Q1 | Where Maven is served | Under `/maven/`, as `/go/`: `<mirror><url>https://byrle.example.com/maven</url>` |
| Q2 | Where a jar's strong digest comes from. 73 of the 94 jars have only `.sha1` and `.md5`; [artifact-digest-verification](engineering_decisions/0017-artifact-digest-verification.md) refuses SHA-1, which would refuse 78% of a Spring Boot build | `.sha256` or `.sha512` when published; otherwise the `.sha1`, checked against the bytes in the claim job and served against their sha256. The check is against a body changed on the way, which needs a second preimage of SHA-1, not a collision. A decision superseding 0017 for Maven. The other two: verify the `.asc`, 88 of 93 good, which needs an OpenPGP crate and a key trusted per group on first use; or the sha256 of the first fetch, which no one else claims |
| Q3 | Whether a `.pom` is refused by policy | No, as Go's `go.mod`: 242 poms against 94 jars, most of them parents and BOMs no build compiles. A `.pom` is checked against its sidecar |
| Q4 | Annotation processors | `install_scripts`, read from the jar's `META-INF/services/javax.annotation.processing.Processor`. 0 of 94 in the Spring Boot build. JDK 21 ran one unasked; JDK 25 did not |
| Q5 | Plugins | Decided as any artifact: refusing every plugin under `install_scripts` would refuse every build |
| Q6 | Publish times | The `.pom`'s `Last-Modified`, a `HEAD` per version, newest first under a cooldown, as Go's `.info`. search.maven.org timed out on 5 of 8 versions |
| Q7 | Tokens | `Basic`, after the 401's challenge, from `settings.xml`'s `<server>` with the mirror's id |

Gradle is not measured: `services.gradle.org` is refused by this machine's forward proxy,
so no Gradle could be downloaded.

## Steps

To be written once the questions are answered.
