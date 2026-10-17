# Maven: the Gradle plugin portal is a second repository of the Maven row

- **Number:** 0115
- **Status:** Decided by the user 2026-10-17: the repository carried through the request,
  with a `Repository` type in each store's key and a `repository` field in each record.
  Implemented 2026-10-17, step 5 of [maven-plan](../maven-plan.md), but for the console's
  usage tables.
- **Related:** [ecosystem-path-prefixes](0111-ecosystem-path-prefixes.md),
  [maven-digests](0112-maven-digests.md), [maven-signatures](0113-maven-signatures.md)

## What the portal answers

Asked of `plugins.gradle.org/m2` 2026-10-17:

| File | Portal's answer |
|---|---|
| a marker's and a plugin's `maven-metadata.xml` | 200, its own |
| `com.github.ben-manes.versions.gradle.plugin-0.52.0.pom`, the marker, and its `.sha1` | 200, its own |
| `gradle-versions-plugin-0.52.0` `.pom`, `.jar`, `.module` | 303 to `plugins-artifacts.gradle.org/<group>/<artifact>/<version>/<sha256>/<file>`. The jar's sha256 matched its path |
| `gradle-versions-plugin-0.52.0.jar.sha1` | 200, its own, matching the jar |
| a `.sha256` or `.sha512` | 303 to `repo.maven.apache.org`, which answered 404 |
| `gradle-versions-plugin-0.52.0.jar.asc` | 303 to `repo.maven.apache.org`, 404 |
| `spring-boot-gradle-plugin-3.5.6.jar` and its `.asc` | 303 to `plugins-artifacts.gradle.org`. The jar's bytes are Central's |

Central and the portal answer differently for the same coordinates.
`com.github.ben-manes:gradle-versions-plugin`'s `maven-metadata.xml` lists 6 versions on
Central, 0.1 to 0.11.1, and 58 on the portal. Central answers 404 for the 0.52.0 jar the
portal serves.

## Constraints

A file from the portal is `pkg:maven`. Policy selectors, OSV, GHSA and KEV name it by its
Maven coordinates, as they name a file from Central.

What is read from a repository is that repository's. As the proxy is written, this state is
keyed by `Ecosystem` or `PackageKey` alone:

| State | Key |
|---|---|
| `route::classify`, `Exchange`, `Negotiation`, `ArtifactRequest` | `Ecosystem` |
| `Upstreams`, `Clients`, `Health.upstreams` | `Ecosystem` |
| `RecordStore`, holding each document's records and artifact URLs | `PackageKey` |
| `DetectionKey`, the signing detector's history | detector, ecosystem, name, version |
| `put_signature`: `Unsigned` and `Dropped` read from one repository's history | sha256 |
| `classify_path`, `upstream_url`, `inspect::read`, `metadata_sidecar` | `maven::PREFIX`, `/maven/` |

A second `TABLE` row for Maven sends `/gradle-plugins/` to Central without an error:
`ecosystem::of` takes the first row, and `Clients` and `Upstreams` keep the last.

## The two designs

| | Repository in the key | Repository carried through the request |
|---|---|---|
| How | `PackageKey` gains purl's `repository_url` qualifier, set for the portal | `Exchange`, `Negotiation` and `ArtifactRequest` carry the repository; `Upstreams`, `Clients`, `RecordStore` and `DetectionKey` are keyed by repository and key |
| Intel and policy | `PackageKey` is the advisory lookup key, so each lookup and selector strips the qualifier | unchanged |
| `identity.rs` | changed, with its kani proofs | unchanged |
| A store added later | split by repository with no change | keyed by repository, or shared across both by mistake |

The second is decided: intel and policy stay as they are, and `identity.rs` is unchanged.

Its costs, and what is done for each:

| Cost | Done |
|---|---|
| A store keyed by `PackageKey` alone shares the two repositories, and nothing stops one being added | each store on the request path is keyed by a `Repository`, a type of its own, so a store built without one does not compile |
| The audit log, `Decided` and the console name a purl, the same from either repository | each record gains `repository` |
| `explain`, `policy check --fetch`, `policy diff` and `warm` start from a `PackageKey` | they ask Central unless told the portal |
| A `packages:` rule for a name applies to it from either repository | unchanged: a selector names no repository |
| The analysis store's detections and signatures are keyed without a repository | a migration adds it |

## Either way

- The portal's `Client` sends with redirects off and reads `Location`. reqwest follows
  redirects by default, and nothing reads the final URL. A 303 to a path ending
  `<group>/<artifact>/<version>/<64 hex>/<file>`, the request's own coordinates, is a claim
  of `sha256:<hex>`. Any other answer is claimed from the portal's sidecars, the strongest
  first, as 0112 claims one from Central's.
- A 303 to `repo.maven.apache.org` is fetched from `BYRLE_UPSTREAM_MAVEN` at the same path
  and decided as `/maven/` decides it, so an operator's mirror of Central is not bypassed.
  The portal answers so for a Central artifact's `maven-metadata.xml` too, so where each
  path is is asked with a `HEAD` before it is decided, and kept once read.
- A signature's result is stored by repository and sha256. `spring-boot-gradle-plugin-3.5.6.jar`
  is the same bytes on both, and each repository's history of `.asc`s is its own.
- `BYRLE_UPSTREAM_GRADLE_PLUGINS`, default `https://plugins.gradle.org/m2`.
