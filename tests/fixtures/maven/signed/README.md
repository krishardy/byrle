# Signed Maven files

Four jars of mvn's Spring Boot 3.5.6 build, each with its `.asc`, as repo1.maven.org
served them, and the key it names, as keys.openpgp.org (`.openpgp.key`) and
keyserver.ubuntu.com (`.ubuntu.key`) answered for it, fetched 2026-10-16:

| Jar | Licence | Its signature |
|---|---|---|
| `jakarta.annotation-api-2.1.1.jar` | EPL-2.0 OR GPL-2.0 with Classpath exception | good |
| `json-simple-3.0.2.jar` | Apache-2.0 | by a key that expired after it signed |
| `plexus-build-api-0.0.7.jar` | Apache-2.0 | by a key revoked as superseded after it signed, named by key id alone |
| `plexus-component-annotations-2.0.0.jar` | Apache-2.0 | by a primary key that expired after it signed, beside an encryption subkey that expired before |
| `rsocket-bom-1.1.5.pom`, fetched 2026-10-17 | Apache-2.0 | made 2025-02-03 by a key that expired 2023-06-09, named by key id alone; keys.openpgp.org holds no copy. Spring Boot 3.5.6's BOM imports it |

See docs/engineering_decisions/0113-maven-signatures.md.
