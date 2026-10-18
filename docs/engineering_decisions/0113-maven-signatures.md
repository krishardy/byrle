# Maven: PGP signatures are decided by `provenance`, a key as the identity

- **Number:** 0113
- **Status:** Decided by the user 2026-10-16, as Q2 of [maven-plan](../maven-plan.md) and
  the three cases below. Implemented 2026-10-17, step 4.5 of the plan:
  `src/ecosystem/maven/signature.rs`, `signer.rs`, `signing.rs` and `keys.rs`.
- **Related:** [provenance-check](0066-provenance-check.md),
  [maven-digests](0112-maven-digests.md)

## Decision

0066's three cases apply to a Maven artifact, with the fingerprint of the primary key
that made a jar's `.asc` in place of a repository and workflow file. `provenance: block`,
the default, refuses a version when:

| Case | 0066's | Maven's |
|---|---|---|
| 1 | an attestation that fails verification | a jar's `.asc` that fails verification |
| 2 | none, after a version with one | no `.asc`, after a version with one |
| 3 | a repository and workflow file no attested version from `provenance_window_days` before used | not refused: a signal, `signing_key_new`, weight 1, when no version of the artifact published 7 or more days before was signed by the primary key |

The artifact is `groupId:artifactId`. Its earlier versions are looked through as 0066
looks, most recent first, up to `BYRLE_PROVENANCE_HISTORY`, and each version's key is kept
once read. `set: { provenance: allow }` releases all three, as for npm and PyPI.

A signature verifies when all of these hold:

| Check | Decided |
|---|---|
| The key | fetched by fingerprint from keys.openpgp.org, then keyserver.ubuntu.com, and kept per fingerprint. A key neither holds fails verification. A key server that does not answer is 503, as an unreachable sum.golang.org is |
| The signature | made over the jar's bytes by the key or one of its signing subkeys |
| Expiry | not checked since 2026-10-17: a key, or the subkey, that had expired when it signed is a risk signal, as below. The first answer, that it fails verification, refused rsocket-bom 1.1.5's `.pom` |
| Revocation | as RFC 9580: a revocation with reason `0x01`, superseded, or `0x03`, retired, invalidates only signatures made after it; any other reason, `0x02` compromised included, invalidates every signature by the key |

A `.pom` and a `.module` whose `.asc` fails verification are refused as a file changed
on the way, 502, as one whose digest differs is ([maven-digests](0112-maven-digests.md)).
They are not decided by cases 2 and 3, as a `.pom` is never refused by policy. Its first
fetch is 503 while a job reads its `.asc` and key, as a jar's is, so no key server is
asked while a client waits; decided by the user 2026-10-17.

## Amended 2026-10-17: case 3 a signal, and earlier versions read unverified

Measured over the 92 artifacts of mvn's Spring Boot 3.5.6 build, 9,773 versions, each
version's signer read from its `.asc` and its time from its `.pom`, window 7 days:

| Case 3 as | Versions the build fetched refused | All versions refused |
|---|---|---|
| per artifact, by key id as the signature writes it | 14 of 92 | 480 of 9,773 |
| per artifact, by primary key | 13 of 92 | |
| pooled by `groupId`, by key id, this build's artifacts only | 8 of 92 | 366 of 9,773 |

Of the 13, 11 are Apache Maven's own plugins and libraries, each release signed by its
release manager's key: `maven-jar-plugin` had 11 primary keys before 3.5.1. Case 2 refused
0 of the 92 fetched, and 21 of the 9,773 versions in 9 artifacts, 13 of them `asm`'s.

Decided by the user 2026-10-17: case 3 is a signal, `signing_key_new`, weight 1, as
cargo's `trustpub_repository_changed` is; cases 1 and 2 refuse under `provenance: block`.

An earlier version's `.asc` is read for whether it is there and which key it names, not
verified against its jar, which would mean fetching every earlier jar. Central does not
replace a published file, so an attacker publishing a new version cannot change an earlier
one's `.asc`.

## Measured 2026-10-16, over the 94 jars of mvn's Spring Boot 3.5.6 build

| | Jars |
|---|---|
| `.asc` present | 93 |
| key on keys.openpgp.org and keyserver.ubuntu.com | 81 |
| key only on keyserver.ubuntu.com | 12 |
| key on neither | 0 |
| good with gpg 2.4.8 and keys.openpgp.org's copy | 61 |
| good only with keyserver.ubuntu.com's copy | 27 |
| signed by a key since expired | 4 |
| signed by a key since revoked | 1 |

The 4 and the 1, dated:

| Jar | Signed | Key | Under this decision |
|---|---|---|---|
| `json-simple-3.0.2.jar` | 2018-01-24 | expired 2019-01-25 | verifies |
| `maven-artifact-transfer-0.13.1.jar` | 2020-12-22 | expired 2026-06-05 | verifies |
| `velocity-engine-core-2.4.1.jar` | 2024-10-14 | expired 2025-09-10 | verifies |
| `plexus-component-annotations-2.0.0.jar` | 2019-01-28 | primary key, which signed it, expired 2026-08-15 | verifies |
| `plexus-build-api-0.0.7.jar` | 2011-02-11 | revoked 2024-01-04, reason `0x01` | verifies |

Corrected 2026-10-17: `plexus-component-annotations-2.0.0.jar` was read on 2026-10-16 as
signed by a subkey after it expired. Its signature names the primary key,
`BF1518E0160788A2`; the subkey that expired 2017-03-03 is an encryption subkey and signed
nothing. So each of the 4 was signed before its key expired. With `pgp` 0.21.0 and this
decision's rules, 93 of 93 signatures verify: 81 with keys.openpgp.org's copy of the key,
12 with keyserver.ubuntu.com's.

Of the 27 good only with keyserver.ubuntu.com's copy, 12 are by a key keys.openpgp.org
does not hold, and 15 by one whose copy there did not verify. So the second server is
asked when the first's copy does not verify, not only when it holds none.

Gradle 9.8.1, with keys.openpgp.org and keyserver.ubuntu.com configured, verified 34 of
34 jars of the same dependencies. Its default key servers, pgp.mit.edu and
`ha.pool.sks-keyservers.net`, gave it none of 3 keys.

## Why a key is an identity, and not proof

Anyone who publishes a version can sign it with a key of their own and upload that key
to a key server. A signature that verifies proves only that its key's holder signed the
jar. Case 3 is what makes the key mean something: a key the artifact's earlier versions
were signed with is trusted, and a new one waits out `provenance_window_days`, as a new
repository or workflow does under 0066.

A signature's creation time is written by the signer. A holder of an expired key can
date a new signature before the expiry; the expiry check stops only a signature dated
after it. A compromised key is caught by its revocation, whatever the date.

## Rejected

| Option | Why not |
|---|---|
| A new policy key, off by default | the user's first answer; replaced once case 3 was seen to need 0066's window |
| Any expired key refuses | refuses 4 of 93, each signed while its key was valid |
| Any revocation refuses | refuses `plexus-build-api-0.0.7.jar`, signed 13 years before its key was superseded |
| A missing key as no signature | lets a version signed by a key no server holds pass case 2 |

## The crate

| Crate | Version | Licence |
|---|---|---|
| `pgp` (rPGP) | 0.21.0 | MIT OR Apache-2.0 |
| `sequoia-openpgp` | 2.4.2 | LGPL-2.0-or-later |

`pgp` 0.21.0 is chosen. With it and this decision's rules, 93 of 93 signatures verified;
byrle is Apache-2.0 and ships one static binary. It builds `rsa`, accepted for verification
in [sqlx-0-8-and-rsa-advisory](0028-sqlx-0-8-and-rsa-advisory.md).

## Amended 2026-10-17: a key expired when it signed is a signal

`rsocket-bom-1.1.5.pom`, which Spring Boot 3.5.6's BOM imports, was signed 2025-02-03 by
key `21871D2A9AB66A31`, which keyserver.ubuntu.com's copy says expired 2023-06-09;
keys.openpgp.org holds no copy. gpg 2.4.8 said "Good signature ... [expired]". Under the
first answer it failed verification, and every `.pom` refused so is 502: Gradle 9.8.1
failed every run of a Spring Boot build. Decided by the user 2026-10-17: it is a score
for the risk vector, [TODO](../../TODO.md) ad-hoc #42. The signature verifies; the
expiry is the `signing` detector's signal, in step 4.5 part 3 of
[maven-plan](../maven-plan.md). Revocation is still checked.

A `.pom` and a `.module` are checked as a jar is, in the claim job, their first fetch
503: decided by the user 2026-10-17. The 503's `Retry-After` is
`BYRLE_CLAIM_RETRY_AFTER`, 2 by default, for a jar too: mvn 3.10.0 waits it between 4
tries, and at 1 a cold Spring Boot build failed on `tomcat-embed-core-10.1.46.pom`,
checked 3.4 s after its first 503.

## Amended 2026-10-17: the `signing` detector

Case 3 and a key expired when it signed are the rules of `signing`, a detector built in
that reads Maven versions. It is not awaited: a download does not wait for it.

| Rule | Fires when | Detail, for example |
|---|---|---|
| `signing_key_new` | no version published 7 or more days before was signed by its `.pom`'s primary key, and one was signed | `signed by <fingerprint>; 1.2 was signed by <fingerprint>` |
| `signing_key_expired` | its `.pom`'s key, or subkey, had expired when it signed | `the key expired before it signed` |

| Choice | Why |
|---|---|
| The `.pom`'s `.asc`, not the jar's | every version has a `.pom`; a BOM has no jar |
| A signer read from its `.asc` and key copies, unverified | no earlier file is fetched, as above |
| 7 days, not `provenance_window_days` | a detection is stored once per version and read under every policy; 7 is that key's default |
| Versions read newest first, until one 7 days older was signed by the same key, or 64 such were read | 64 is `BYRLE_PROVENANCE_HISTORY`'s default |
| A version with no `.asc`, or whose key no server holds, fires nothing | it has no key to compare |

A repository or key server that cannot be asked stores nothing, and the detector runs
again on the next request for the version.

## Amended 2026-10-17: a signature in a compressed packet

`mapstruct-processor-1.6.3.pom.asc`, written by BouncyCastle 1.77, is armored as
`PGP MESSAGE`: one stored compressed packet holding one signature packet. gpg 2.4.8
cannot read it ("indeterminate length packet of type 8 in detached signature"); Central,
which checks signatures on upload, published it. byrle refused the `.pom` 502 until this
change. An `.asc` of exactly that form is now read as the signature it holds; any other
`PGP MESSAGE` is still no signature. Through the proxy, its `.pom`, `mapstruct-parent`'s
and the jar verify, by key `97CB58ABBA8F94D9358E5968F0B5C3E6BE36BC75`.

