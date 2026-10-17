//! The `signing` detector for Maven: each version's `.pom.asc` read for the key that signed
//! it, newest first, until an established version signed with the same key. No version's
//! file is fetched: a signer is read from its signature and key alone.

use std::sync::Arc;

use crate::analysis::detector::signing::{NAME, Signed, VERSION, detection};
use crate::analysis::detector::{Detecting, Detector, Target};
use crate::ecosystem::Repository;
use crate::identity::{Ecosystem, PackageKey};

use super::signature::{issuer, signer};
use super::transport::Client;

/// The detector for `repository`, at `upstream`. Always made: its signatures are on the
/// repository itself, and each is read once.
pub fn made(
    http: &reqwest::Client,
    repository: Repository,
    upstream: &str,
    _: &crate::env::ApiSetting,
    _: std::time::Duration,
) -> Option<Arc<dyn Detector>> {
    let client = Client::new(
        http.clone(),
        upstream,
        crate::env::DEFAULT_MAX_METADATA_BYTES,
    );
    Some(Arc::new(Signing { client, repository }))
}

/// Reads each version's signer from the repository and key servers `client` asks.
pub struct Signing {
    pub client: Client,
    /// The repository whose versions it reads.
    pub repository: Repository,
}

impl Signing {
    /// What signed `version` of `key`, published at `at`. `None` when it has no `.asc` or no
    /// key there made it. Errors when the repository or a key server cannot be asked.
    async fn signed(
        &self,
        key: &PackageKey,
        version: &str,
        at: jiff::Timestamp,
    ) -> Result<Signed, String> {
        let pom = format!("{}-{version}.pom", key.name());
        let url = self.client.file_url(key, version, &pom);
        let mut found = Signed {
            version: version.to_owned(),
            published: at,
            key: None,
            expired: None,
        };
        let Some(signature) = self.client.signature(&url).await? else {
            return Ok(found);
        };
        let Ok(named) = issuer(&signature) else {
            return Ok(found);
        };
        for copy in self.client.keys().copies(&named).await? {
            if let Some((primary, expired)) = signer(&signature, &copy) {
                (found.key, found.expired) = (Some(primary), expired);
                break;
            }
        }
        Ok(found)
    }

    /// The signers of `target` and the versions before it, newest first, until one
    /// established before the window was signed with its key, or [`HISTORY`] such were read.
    /// An unsigned version is read alone: no rule compares it.
    async fn history(&self, target: &Target) -> Result<Vec<Signed>, String> {
        let key = PackageKey::from_registry_name(Ecosystem::Maven, &target.name)
            .map_err(|e| e.to_string())?;
        let metadata = crate::ecosystem::fetched(self.client.metadata(&key).await)?;
        let times = self.client.dated(&metadata).await?;
        let Some(at) = times.get(&target.version).copied() else {
            return Err(format!("{} lists no version {}", key, target.version));
        };
        let this = self.signed(&key, &target.version, at).await?;
        if this.key.is_none() {
            return Ok(vec![this]);
        }
        let opens = at - window();
        let mut before: Vec<(jiff::Timestamp, String)> = times
            .into_iter()
            .filter(|(_, t)| *t < at)
            .map(|(v, t)| (t, v))
            .collect();
        before.sort();
        let (mut read, mut established) = (vec![this.clone()], 0);
        for (t, version) in before.into_iter().rev() {
            let signed = self.signed(&key, &version, t).await?;
            let counted = t <= opens && signed.key.is_some();
            let matched = counted && signed.key == this.key;
            established += usize::from(counted);
            read.push(signed);
            if matched || established == HISTORY {
                break;
            }
        }
        Ok(read)
    }
}

/// Established versions read at most, [`crate::env::PROVENANCE_HISTORY`]'s default.
const HISTORY: usize = crate::analysis::attestation::DEFAULT_HISTORY;

/// When a key is established: [`crate::policy::DEFAULT_PROVENANCE_WINDOW_DAYS`] before.
fn window() -> jiff::SignedDuration {
    crate::policy::window_of(crate::policy::DEFAULT_PROVENANCE_WINDOW_DAYS)
}

impl Detector for Signing {
    fn name(&self) -> &str {
        NAME
    }

    fn version(&self) -> &str {
        VERSION
    }

    fn reads(&self, at: Repository) -> bool {
        at == self.repository
    }

    fn detect<'a>(&'a self, target: &'a Target) -> Detecting<'a> {
        Box::pin(async move {
            let read = self.history(target).await?;
            Ok(detection(&read, &target.version, window()).unwrap_or_default())
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const DIR: &str = "/org/example/lib";

    /// What the repository answers for a version's `.pom.asc`.
    #[derive(Clone, Copy)]
    enum Asc {
        /// This fixture.
        File(&'static str),
        /// These bytes.
        Bytes(&'static [u8]),
        /// 500.
        Broken,
        /// No `.asc`: 404.
        None,
        /// No `.pom` either: 500 for it, so it cannot be dated.
        Undated,
    }

    fn signed(name: &str) -> Vec<u8> {
        super::super::fixture(&format!("signed/{name}"))
    }

    /// A repository on loopback listing `versions`, each `(version, day, asc)` published `day`
    /// days into 2026 with the fixture `asc` beside its `.pom`, and a key server holding
    /// the keys of jakarta.annotation-api, json-simple and rsocket-bom. Their bases.
    async fn repository(versions: &[(String, i64, Asc)]) -> (String, String) {
        let listed: String = versions
            .iter()
            .map(|(v, _, _)| format!("<version>{v}</version>"))
            .collect();
        let metadata = format!(
            "<metadata><groupId>org.example</groupId><artifactId>lib</artifactId>\
             <versioning><versions>{listed}</versions></versioning></metadata>"
        );
        let mut router = axum::Router::new().route(
            &format!("{DIR}/maven-metadata.xml"),
            axum::routing::get(move || {
                let metadata = metadata.clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "text/xml")], metadata) }
            }),
        );
        for (version, day, asc) in versions {
            let start: jiff::Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
            let at = start + jiff::SignedDuration::from_hours(24 * day);
            let modified =
                jiff::fmt::rfc2822::to_string(&at.to_zoned(jiff::tz::TimeZone::UTC)).unwrap();
            let pom = format!("{DIR}/{version}/lib-{version}.pom");
            let asc = *asc;
            if let Asc::Undated = asc {
                router = router.route(
                    &pom,
                    axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
                );
                continue;
            }
            router = router.route(
                &pom,
                axum::routing::get(move || {
                    let modified = modified.clone();
                    async move {
                        (
                            [(axum::http::header::LAST_MODIFIED, modified)],
                            "<project/>",
                        )
                    }
                }),
            );
            let answer = move || async move {
                use axum::response::IntoResponse;
                match asc {
                    Asc::File(name) => signed(name).into_response(),
                    Asc::Bytes(bytes) => bytes.into_response(),
                    _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            };
            if !matches!(asc, Asc::None) {
                router = router.route(&format!("{pom}.asc"), axum::routing::get(answer));
            }
        }
        let held: HashMap<String, Vec<u8>> = [
            (
                "jakarta.annotation-api-2.1.1.jar",
                "jakarta.annotation-api-2.1.1.jar",
            ),
            ("json-simple-3.0.2.jar", "json-simple-3.0.2.jar"),
            ("rsocket-bom-1.1.5.pom", "rsocket-bom-1.1.5.pom"),
            (
                "plexus-component-annotations-2.0.0.jar",
                "json-simple-3.0.2.jar",
            ),
        ]
        .iter()
        .map(|(file, copy)| {
            let named = issuer(&signed(&format!("{file}.asc"))).unwrap();
            (format!("0x{named}"), signed(&format!("{copy}.ubuntu.key")))
        })
        .collect();
        let keys = axum::Router::new().route(
            "/pks/lookup",
            axum::routing::get(
                move |axum::extract::Query(query): axum::extract::Query<
                    HashMap<String, String>,
                >| {
                    let found = held.get(&query["search"]).cloned();
                    async move {
                        found.map_or_else(
                            || {
                                axum::response::IntoResponse::into_response(
                                    axum::http::StatusCode::NOT_FOUND,
                                )
                            },
                            axum::response::IntoResponse::into_response,
                        )
                    }
                },
            ),
        );
        (
            crate::proxy::testing::serve(router).await,
            crate::proxy::testing::serve(keys).await,
        )
    }

    fn detector(base: &str, keys: &str) -> Signing {
        let client = Client::new(reqwest::Client::new(), base, 1 << 20).with_key_servers(
            super::super::keys::KeyServers::at(reqwest::Client::new(), &[keys]),
        );
        Signing {
            client,
            repository: Repository::of(Ecosystem::Maven),
        }
    }

    fn target(version: &str) -> Target {
        Target {
            repository: crate::ecosystem::Repository::of(crate::identity::Ecosystem::Maven),
            name: "org.example:lib".to_owned(),
            version: version.to_owned(),
        }
    }

    const JAKARTA: Asc = Asc::File("jakarta.annotation-api-2.1.1.jar.asc");
    const JSON: Asc = Asc::File("json-simple-3.0.2.jar.asc");
    const RSOCKET: Asc = Asc::File("rsocket-bom-1.1.5.pom.asc");
    const UNHELD: Asc = Asc::File("plexus-build-api-0.0.7.jar.asc");
    /// Its key server answers with another key's copy.
    const MISCOPIED: Asc = Asc::File("plexus-component-annotations-2.0.0.jar.asc");

    fn rules(detection: &crate::analysis::detector::Detection) -> Vec<&str> {
        detection.findings.iter().map(|f| f.rule.as_str()).collect()
    }

    /// 1.2's key signed 1.0; 1.3's signed nothing before it, after its key expired; 1.4 is
    /// unsigned, no key server holds 1.5's key, 1.6's is another's, 1.7's is no signature.
    #[tokio::test]
    async fn a_version_signed_by_a_key_no_established_version_used_fires() {
        let versions: Vec<(String, i64, Asc)> = [
            ("1.0", 0, JAKARTA),
            ("1.1", 30, JSON),
            ("1.2", 60, JAKARTA),
            ("1.2.5", 83, JSON),
            ("1.3", 90, RSOCKET),
            ("1.4", 91, Asc::None),
            ("1.5", 92, UNHELD),
            ("1.6", 93, MISCOPIED),
            ("1.7", 94, Asc::Bytes(b"not armor")),
        ]
        .into_iter()
        .map(|(v, d, a)| (v.to_owned(), d, a))
        .collect();
        let (base, keys) = repository(&versions).await;
        let signing = detector(&base, &keys);
        assert!(rules(&signing.detect(&target("1.2")).await.unwrap()).is_empty());
        assert_eq!(signing.history(&target("1.2")).await.unwrap().len(), 3);
        let found = signing.detect(&target("1.3")).await.unwrap();
        assert_eq!(rules(&found), ["signing_key_new", "signing_key_expired"]);
        let json = issuer(&signed("json-simple-3.0.2.jar.asc")).unwrap();
        assert!(
            found.findings[0].detail.contains("; 1.2.5 was signed by ")
                && found.findings[0].detail.contains(&json[json.len() - 16..]),
            "{}",
            found.findings[0].detail
        );
        assert_eq!(
            signing.history(&target("1.3")).await.unwrap().len(),
            5,
            "no established version used its key: every one is read"
        );
        for quiet in ["1.4", "1.5", "1.6", "1.7"] {
            assert!(rules(&signing.detect(&target(quiet)).await.unwrap()).is_empty());
            assert_eq!(signing.history(&target(quiet)).await.unwrap().len(), 1);
        }
        let missing = signing.detect(&target("9.9")).await.unwrap_err();
        assert_eq!(missing, "pkg:maven/org.example/lib lists no version 9.9");
        assert_eq!((signing.name(), signing.version()), (NAME, VERSION));
        assert!(signing.reads(Repository::of(Ecosystem::Maven)));
        assert!(!signing.reads(Repository::of(Ecosystem::Cargo)));
        let portal = Repository::named("gradle-plugins").unwrap();
        assert!(
            !signing.reads(portal),
            "the portal's versions are read by its own"
        );
    }

    /// A version inside the window signed with the same key establishes nothing: the
    /// versions read go on to one 7 days older.
    #[tokio::test]
    async fn a_version_inside_the_window_does_not_end_the_versions_read() {
        let versions: Vec<(String, i64, Asc)> = [
            ("1.0", 0, JAKARTA),
            ("1.1", 10, JSON),
            ("1.2", 12, JAKARTA),
            ("1.3", 13, JAKARTA),
        ]
        .into_iter()
        .map(|(v, d, a)| (v.to_owned(), d, a))
        .collect();
        let (base, keys) = repository(&versions).await;
        let read = detector(&base, &keys)
            .history(&target("1.3"))
            .await
            .unwrap();
        let read: Vec<&str> = read.iter().map(|s| s.version.as_str()).collect();
        assert_eq!(read, ["1.3", "1.2", "1.1", "1.0"]);
    }

    /// At most [`HISTORY`] established versions are read for a key none of them used.
    #[tokio::test]
    async fn the_versions_read_stop_at_the_history() {
        let mut versions: Vec<(String, i64, Asc)> = (0..HISTORY as i64 + 2)
            .map(|day| (format!("1.{day}"), day, JAKARTA))
            .collect();
        versions.push(("2.0".to_owned(), 200, RSOCKET));
        let (base, keys) = repository(&versions).await;
        let read = detector(&base, &keys)
            .history(&target("2.0"))
            .await
            .unwrap();
        assert_eq!(read.len(), 1 + HISTORY);
    }

    /// A repository or key server that cannot be asked is an error, and nothing is stored.
    #[tokio::test]
    async fn a_lookup_that_fails_is_an_error() {
        let versions = vec![
            ("1.0".to_owned(), 0, JAKARTA),
            ("1.1".to_owned(), 30, Asc::Broken),
            ("2.0".to_owned(), 60, RSOCKET),
        ];
        let (base, keys) = repository(&versions).await;
        let failing = detector(&base, &keys);
        assert!(
            failing.detect(&target("1.1")).await.is_err(),
            "its own .asc"
        );
        assert!(
            failing.detect(&target("2.0")).await.is_err(),
            "an earlier .asc"
        );
        let (undated, _) = repository(&[("1.0".to_owned(), 0, Asc::Undated)]).await;
        assert!(
            detector(&undated, &keys)
                .detect(&target("1.0"))
                .await
                .is_err()
        );
        let down = crate::proxy::testing::serve(axum::Router::new().route(
            "/pks/lookup",
            axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        ))
        .await;
        assert!(detector(&base, &down).detect(&target("1.0")).await.is_err());
        let gone = detector("http://127.0.0.1:9", &down);
        assert!(gone.detect(&target("1.0")).await.is_err());
        let mut unnamed = target("1.0");
        unnamed.name = "no-group".to_owned();
        assert!(detector(&base, &down).detect(&unnamed).await.is_err());
        let made = made(
            &reqwest::Client::new(),
            Repository::of(Ecosystem::Maven),
            &base,
            &crate::env::ApiSetting::Unset,
            std::time::Duration::ZERO,
        );
        assert_eq!(made.expect("always made").name(), NAME);
    }
}
