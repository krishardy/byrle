# Maven: a jar's digest is its strongest sidecar, SHA-1 included

- **Number:** 0112
- **Status:** Decided by the user 2026-10-16, as Q2 of [maven-plan](../maven-plan.md). Not
  yet implemented: step 4.3 of the plan.
- **Related:** [artifact-digest-verification](0017-artifact-digest-verification.md),
  [maven-signatures](0113-maven-signatures.md), [go-plan](../go-plan.md)

## Decision

A file under `/maven/` is checked against the strongest digest Central publishes beside
it:

| Beside the file | Checked against |
|---|---|
| `.sha512` | its SHA-512 |
| `.sha256`, and no `.sha512` | its SHA-256 |
| `.sha1` only | its SHA-1 |
| none of the three | nothing: refused, as an artifact with no digest is |

`.md5` is never read.

A `.pom` and a `.module` are checked in the request: each is small, and mvn and Gradle
read both for versions whose jars they never fetch. A jar's first fetch is 503 while the
claim job fetches it, spools it, and checks it against its sidecar. A match is kept in
`artifact_claim` as the sha256 of the same bytes, and the retry is served checked against
that sha256, as a Go zip's `h1:` is. A jar that does not match is 502.

This replaces, for Maven only, 0017's refusal of an artifact whose only digest is SHA-1.
npm, PyPI, cargo and Go are unchanged.

## Measured 2026-10-16

| Build | Jars | With a `.sha256` or `.sha512` | With only `.sha1` |
|---|---|---|---|
| mvn, Spring Boot 3.5.6 starter-web, with its plugins | 94 | 21 | 73 |
| Gradle, the same dependencies | 34 | 11 | 23 |

Spring's 15 jars, commons-lang3, slf4j, logback and log4j publish no strong sidecar.
Under 0017's rule the proxy would refuse 73 of mvn's 94 jars.

A `.module` lists the sha256 of each file of each variant, and gives it for 21 of
Gradle's 34 jars, all 21 matching. Spring's 22 `.module`s have only a `.sha1` beside
them, so the chain still starts at SHA-1: they are checked as any file is, and their
contents are not used as a claim.

## Why SHA-1 is accepted here

0017 refuses SHA-1 because it is collision-broken. A collision needs one party to make
both files. Here the sidecar and the jar come from Central, and the check is against a
jar changed after Central published it: on the way, or in a cache between. Making a jar
that matches a `.sha1` already published needs a second preimage of SHA-1, which no
published attack achieves. A publisher who makes a colliding pair can already publish
any jar it likes, which the policy checks decide as any other.

## Rejected

| Option | Why not |
|---|---|
| 0017 unchanged: refuse SHA-1 | refuses 73 of 94 jars of a Spring Boot build |
| The sha256 of the first fetch | nothing upstream claims it; it proves only that later fetches match the first |
| A `.module`'s sha256 as the claim | it covers Spring's 15 jars, but each `.module` has only a `.sha1` beside it |

PGP signatures are decided by [maven-signatures](0113-maven-signatures.md), as well as
this digest, not in place of it.

## Consequences

- mvn retried a 503 4 times at its `Retry-After`; Gradle 3 times in 3 s, ignoring it. A
  claim job longer than 3 s fails a Gradle build until it is run again.
- The proxy writes the `.sha1` and `.md5` of a `maven-metadata.xml` it filtered, from the
  filtered body. mvn warned on the unfiltered `.sha1`; Gradle asked none.
- A jar cached by Gradle from another repository URL is reused after a `HEAD` of the jar
  and a `GET` of its `.sha1`, with no `GET` of the jar. The `.sha1` served is Central's,
  and a refused jar's `HEAD` is refused as its `GET` is.
