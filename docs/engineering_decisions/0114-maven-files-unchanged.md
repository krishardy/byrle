# Maven: byrle passes every file through unchanged, so a client can check byrle

- **Number:** 0114
- **Status:** Decided by the user 2026-10-17, as step 2.3 of
  [maven-plan](../maven-plan.md). Implemented 2026-10-18: the proxy changes only a
  `maven-metadata.xml` it filters (`src/ecosystem/maven/wire.rs`), and that file's
  `.sha1` and `.md5`, written from the filtered body (`digest.rs`). `byrle doctor` reports
  a Gradle build without `<verify-signatures>` (`gradle.rs`).
- **Related:** [maven-digests](0112-maven-digests.md),
  [maven-signatures](0113-maven-signatures.md),
  [artifact-digest-verification](0017-artifact-digest-verification.md)

## Decision

Under `/maven/` and `/gradle-plugins/`, the proxy answers a file it serves with the body
and the `Content-Encoding` the repository sent. A `maven-metadata.xml` it filters is
encoded as the client asked, as any rewritten document is (`proxy::finish`):

| File | Answered with |
|---|---|
| a jar or any other artifact, a `.pom`, a `.module` | the repository's bytes, or a refusal |
| a `.sha1`, `.md5`, `.sha256`, `.sha512` or `.asc` beside one of those | the repository's bytes |
| a `maven-metadata.xml` the policy filters | the repository's bytes less each refused version's element, with `<latest>` and `<release>` moved down ([maven-plan](../maven-plan.md) step 4.1) |
| that file's `.sha1` and `.md5` | written by the proxy from the filtered body (step 4.2). Its `x-checksum-*` headers, which describe Central's body, are removed |
| a `maven-metadata.xml` nothing is filtered from, and its sidecars | the repository's bytes |

No other Maven file is written or rewritten by the proxy. A change to this list is a
decision that supersedes this one.

## Why

byrle is one place every build's files come through. A proxy that changed a jar, through a
compromise or a bug, and the sidecar beside it would pass the client's own check, since mvn
and Gradle check a file against the sidecar from the repository that served it. A check
whose source is outside byrle catches it, and works only if byrle's bytes are the
repository's:

| Check outside byrle | Where its trust comes from | Measured 2026-10-16 |
|---|---|---|
| a PGP signature, the `.asc` served through byrle | the key, fetched from a key server, not through byrle | Gradle 9.8.1 verified 34 of 34 jars of a Spring Boot build, and failed `slf4j-api-2.0.17.jar` answered with 2.0.16's bytes: "One artifact failed verification" |
| a digest recorded before, as Gradle's committed `gradle/verification-metadata.xml` | the commit that recorded it | the same run: the file held both the sha256 and the key, and which of the two failed was not read |
| a digest written from Central directly | the machine that fetched it | not measured |

byrle cannot make a PGP signature without the publisher's key, so a changed jar fails the
signature whatever the proxy serves beside it.

## Rejected

| Option | Why not |
|---|---|
| sidecars served from Central directly, jars from byrle | no setting in mvn or Gradle was found that asks a second repository for a checksum; not measured. Central serves jars and sidecars from one host, `repo1.maven.org`, so a network that lets the sidecars through lets the jars through |
| the proxy writing its own sidecars for every file | a client's check would then be against byrle's word, which is what an outside check is for |

## Consequences

- The filtered `maven-metadata.xml` cannot be checked from outside byrle: it differs from
  Central's on purpose. A refused version left out of it changes what a range resolves to,
  and the jar of that version is refused whatever the client reads.
- Step 4.3's claim job checks a jar against Central's sidecar and keeps the sha256 of the
  same bytes. The jar served is those bytes.
- `byrle doctor` warns, in step 7, when a Gradle build has no
  `gradle/verification-metadata.xml`, or has one with `<verify-signatures>` false.
- `make smoke-maven`, in step 8, compares the sha256 of each file in the client's local
  repository with the sha256 of the same file fetched from Central directly.
- The threat model, in step 9, names PGP keys fetched from key servers as the check of
  byrle from outside it. mvn verifies no signature without a plugin, which is not measured.
