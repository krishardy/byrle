//! A Maven file's `.asc`, fetched and checked for the claim job, and, for a file with none,
//! whether a version before it had one: cases 1 and 2 of
//! [maven-signatures](../../../docs/engineering_decisions/0113-maven-signatures.md).

use futures_util::future::BoxFuture;
use futures_util::{StreamExt, TryStreamExt};

use crate::analysis::attestation::LINE_HISTORY;
use crate::intel::range::VersionOrder;
use crate::policy::decide::History;

use crate::ecosystem::{Material, Signature, Signer, Source};
use crate::identity::PackageKey;

use super::signature::{Signed, issuer, verify};
use super::transport::Client;

/// One file's signature, asked of the repository and key servers `client` reads.
#[derive(Debug, Clone)]
pub struct FileSigner {
    pub client: Client,
    pub key: PackageKey,
    pub version: String,
    /// The file's name, which an earlier version's file is named as with its version.
    pub file: String,
    /// Earlier versions asked for a signature at most, newest first: none for a `.pom`.
    pub history: usize,
}

impl FileSigner {
    /// The URL of version `version`'s file: this file's name with its version replaced,
    /// after the artifact's name, as Maven names a version's files.
    fn url(&self, version: &str) -> String {
        let named = format!("{}-{}", self.key.name(), self.version);
        let renamed = match self.file.strip_prefix(&named) {
            Some(rest) => format!("{}-{version}{rest}", self.key.name()),
            None => self.file.clone(),
        };
        self.client.file_url(&self.key, version, &renamed)
    }
}

impl Signer for FileSigner {
    fn verifier(&self) -> &'static str {
        super::signature::VERIFIER
    }

    fn material(&self) -> BoxFuture<'_, Result<Option<Material>, String>> {
        Box::pin(async move {
            let Some(signature) = self.client.signature(&self.url(&self.version)).await? else {
                return Ok(None);
            };
            let keys = match issuer(&signature) {
                Ok(issuer) => self.client.keys().copies(&issuer).await?,
                Err(_) => Vec::new(),
            };
            Ok(Some(Material { signature, keys }))
        })
    }

    /// The newest of the earlier versions signed, and once one is, whether each of those in
    /// this one's line was, at most [`LINE_HISTORY`], asked eight at a time.
    fn signed_before(&self) -> BoxFuture<'_, Result<Option<(String, History)>, String>> {
        Box::pin(async move {
            if self.history == 0 {
                return Ok(None);
            }
            let earlier = self
                .client
                .earlier(&self.key, &self.version, self.history)
                .await?;
            let mut previous = None;
            for version in &earlier {
                if self.client.signature(&self.url(version)).await?.is_some() {
                    previous = Some(version.clone());
                    break;
                }
            }
            let Some(previous) = previous else {
                return Ok(None);
            };
            let line = VersionOrder::Maven.line(&self.version);
            let in_line = earlier
                .into_iter()
                .filter(|version| line.is_some() && VersionOrder::Maven.line(version) == line)
                .take(LINE_HISTORY);
            let signed: Vec<bool> = futures_util::stream::iter(in_line)
                .map(|version| async move {
                    self.client
                        .signature(&self.url(&version))
                        .await
                        .map(|asc| asc.is_some())
                })
                .buffered(8)
                .try_collect()
                .await?;
            Ok(Some((previous, History(signed))))
        })
    }

    /// keys.openpgp.org's copy first, then the next server's when it does not verify.
    fn verify(&self, material: &Material, file: &mut dyn Source) -> std::io::Result<Signature> {
        let mut why = "no key server holds the key it names".to_owned();
        for copy in &material.keys {
            match verify(&material.signature, copy, file)? {
                Signed::Verified { key, expired } => {
                    if let Some(expired) = expired {
                        tracing::info!(byrle.signature.key = %key, byrle.reason = %expired, "a signature verified whose key had expired when it signed");
                    }
                    return Ok(Signature::Verified { key });
                }
                Signed::Failed { why: failed } => why = failed,
            }
        }
        if let Err(unread) = issuer(&material.signature) {
            why = unread;
        }
        Ok(Signature::Failed { why })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::identity::Ecosystem;

    const JAR: &str = "jakarta.annotation-api-2.1.1.jar";

    fn signed(name: &str) -> Vec<u8> {
        super::super::fixture(&format!("signed/{name}"))
    }

    /// A repository on loopback holding jakarta.annotation-api's 2.1.1 jar and its `.sha1`,
    /// the fixture `.asc` named `asc` beside it, `older` versions dated by their `.pom`s
    /// with an `.asc` beside each of `signed_older`, and a key server holding its key. Its
    /// base, and the key server's.
    pub(crate) async fn repository(
        asc: Option<&'static str>,
        older: &[&str],
        signed_older: &[&str],
    ) -> (String, String) {
        let dir = "/jakarta/annotation/jakarta.annotation-api";
        let mut versions = older.to_vec();
        versions.push("2.1.1");
        let listed: String = versions
            .iter()
            .map(|v| format!("<version>{v}</version>"))
            .collect();
        let metadata = format!(
            "<metadata><groupId>jakarta.annotation</groupId><artifactId>jakarta.annotation-api\
             </artifactId><versioning><versions>{listed}</versions></versioning></metadata>"
        );
        let mut router = axum::Router::new()
            .route(
                &format!("{dir}/maven-metadata.xml"),
                axum::routing::get(move || {
                    let metadata = metadata.clone();
                    async move { ([(axum::http::header::CONTENT_TYPE, "text/xml")], metadata) }
                }),
            )
            .route(
                &format!("{dir}/2.1.1/{JAR}"),
                axum::routing::get(|| async { signed(JAR) }),
            )
            .route(
                &format!("{dir}/2.1.1/{JAR}.sha1"),
                axum::routing::get(|| async { super::super::digest::sha1(&signed(JAR)) }),
            );
        router = dated(router, dir, &versions);
        for version in signed_older {
            router = router.route(
                &format!("{dir}/{version}/jakarta.annotation-api-{version}.jar.asc"),
                axum::routing::get(|| async { signed(&format!("{JAR}.asc")) }),
            );
        }
        if let Some(asc) = asc {
            router = router.route(
                &format!("{dir}/2.1.1/{JAR}.asc"),
                axum::routing::get(move || async move { signed(asc) }),
            );
        }
        let keys = axum::Router::new().route(
            "/pks/lookup",
            axum::routing::get(|| async { signed(&format!("{JAR}.ubuntu.key")) }),
        );
        (
            crate::proxy::testing::serve(router).await,
            crate::proxy::testing::serve(keys).await,
        )
    }

    pub(crate) fn signer(base: &str, keys: &str) -> FileSigner {
        let client = Client::new(reqwest::Client::new(), base, 1 << 20).with_key_servers(
            super::super::keys::KeyServers::at(reqwest::Client::new(), &[keys]),
        );
        FileSigner {
            client,
            key: PackageKey::from_registry_name(
                Ecosystem::Maven,
                "jakarta.annotation:jakarta.annotation-api",
            )
            .unwrap(),
            version: "2.1.1".to_owned(),
            file: JAR.to_owned(),
            history: 64,
        }
    }

    /// A signed jar's material is its `.asc` and the key server's copy of its key, and
    /// they verify against its bytes.
    #[tokio::test]
    async fn a_signed_file_s_material_verifies() {
        let (base, keys) = repository(Some("jakarta.annotation-api-2.1.1.jar.asc"), &[], &[]).await;
        let jar = signer(&base, &keys);
        let material = jar.material().await.unwrap().expect("signed");
        assert_eq!(material.keys.len(), 1);
        let dir = std::env::temp_dir().join(format!("byrle-signer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(JAR);
        std::fs::write(&path, signed(JAR)).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            jar.verify(&material, &mut file).unwrap(),
            Signature::Verified { .. }
        ));
        let none = Material {
            signature: material.signature.clone(),
            keys: Vec::new(),
        };
        assert_eq!(
            jar.verify(&none, &mut file).unwrap(),
            Signature::Failed {
                why: "no key server holds the key it names".to_owned()
            }
        );
        let unreadable = Material {
            signature: b"not armor".to_vec(),
            keys: Vec::new(),
        };
        let Signature::Failed { why } = jar.verify(&unreadable, &mut file).unwrap() else {
            panic!("failed");
        };
        assert!(why.starts_with("it is no signature"), "{why}");
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(jar.verifier(), super::super::signature::VERIFIER);
    }

    /// An `.asc` that names no key reads as material with no key; a repository that cannot
    /// be asked is an error, in each lookup.
    #[tokio::test]
    async fn what_cannot_be_read_or_asked_says_so() {
        let (base, keys) = repository(Some("README.md"), &[], &[]).await;
        let material = signer(&base, &keys)
            .material()
            .await
            .unwrap()
            .expect("an .asc");
        assert!(material.keys.is_empty());
        let addr =
            crate::util::test_support::scripted(vec![crate::util::test_support::Answer::Status(
                500,
            )])
            .await;
        let failing = signer(&format!("http://{addr}"), &format!("http://{addr}"));
        assert!(failing.material().await.is_err());
        assert!(failing.signed_before().await.is_err());
        let (base, _) = repository(None, &["2.0"], &[]).await;
        let addr =
            crate::util::test_support::scripted(vec![crate::util::test_support::Answer::Status(
                500,
            )])
            .await;
        let keys_down = signer(&base, &format!("http://{addr}"));
        let (signed_base, _) =
            repository(Some("jakarta.annotation-api-2.1.1.jar.asc"), &[], &[]).await;
        let keyless = FileSigner {
            client: Client::new(reqwest::Client::new(), &signed_base, 1 << 20).with_key_servers(
                super::super::keys::KeyServers::at(
                    reqwest::Client::new(),
                    &[&format!("http://{addr}")],
                ),
            ),
            ..keys_down
        };
        assert!(keyless.material().await.is_err());
    }

    /// A file that cannot be read is an error; an earlier version's `.asc` that cannot be
    /// asked is one too.
    #[tokio::test]
    async fn a_read_or_a_lookup_that_fails_is_an_error() {
        struct Unseekable;
        impl std::io::Read for Unseekable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl std::io::Seek for Unseekable {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("unseekable"))
            }
        }
        let (base, keys) = repository(Some("jakarta.annotation-api-2.1.1.jar.asc"), &[], &[]).await;
        let jar = signer(&base, &keys);
        let material = jar.material().await.unwrap().unwrap();
        assert!(jar.verify(&material, &mut Unseekable).is_err());
        for signed_since in [None, Some("2.0.5")] {
            let base = crate::proxy::testing::serve(unaskable(signed_since)).await;
            assert!(
                signer(&base, &keys).signed_before().await.is_err(),
                "{signed_since:?}"
            );
        }
    }

    /// `router` with a `.pom` for each of `versions` under `dir`, a day apart from 2025-06-01.
    fn dated(mut router: axum::Router, dir: &str, versions: &[&str]) -> axum::Router {
        for (day, version) in versions.iter().enumerate() {
            let at: jiff::Timestamp = "2025-06-01T00:00:00Z".parse().unwrap();
            let at = at + jiff::SignedDuration::from_hours(24 * day as i64);
            let modified =
                jiff::fmt::rfc2822::to_string(&at.to_zoned(jiff::tz::TimeZone::UTC)).unwrap();
            router = router.route(
                &format!("{dir}/{version}/jakarta.annotation-api-{version}.pom"),
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
        }
        router
    }

    /// A repository whose 2.0 `.asc` answers 500, before 2.1.1 and after `signed_since`, a
    /// version signed, when given: asked first, or as part of 2.1.1's line.
    fn unaskable(signed_since: Option<&'static str>) -> axum::Router {
        let dir = "/jakarta/annotation/jakarta.annotation-api";
        let mut versions = vec!["2.0"];
        versions.extend(signed_since);
        versions.push("2.1.1");
        let listed: String = versions
            .iter()
            .map(|v| format!("<version>{v}</version>"))
            .collect();
        let metadata = format!(
            "<metadata><groupId>jakarta.annotation</groupId><artifactId>jakarta.annotation-api\
             </artifactId><versioning><versions>{listed}</versions></versioning></metadata>"
        );
        let mut router = axum::Router::new()
            .route(
                &format!("{dir}/maven-metadata.xml"),
                axum::routing::get(move || {
                    let metadata = metadata.clone();
                    async move { ([(axum::http::header::CONTENT_TYPE, "text/xml")], metadata) }
                }),
            )
            .route(
                &format!("{dir}/2.0/jakarta.annotation-api-2.0.jar.asc"),
                axum::routing::get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
            );
        router = dated(router, dir, &versions);
        if let Some(version) = signed_since {
            router = router.route(
                &format!("{dir}/{version}/jakarta.annotation-api-{version}.jar.asc"),
                axum::routing::get(|| async { signed(&format!("{JAR}.asc")) }),
            );
        }
        router
    }

    /// A signature made after its key expired verifies: the expiry is a signal, not a failure.
    #[test]
    fn a_signature_by_a_key_expired_since_verifies() {
        let pom = "rsocket-bom-1.1.5.pom";
        let material = Material {
            signature: signed(&format!("{pom}.asc")),
            keys: vec![String::from_utf8(signed(&format!("{pom}.ubuntu.key"))).unwrap()],
        };
        let jar = signer("http://unused", "http://unused");
        let mut file = std::io::Cursor::new(signed(pom));
        assert!(matches!(
            jar.verify(&material, &mut file).unwrap(),
            Signature::Verified { .. }
        ));
    }

    /// An unsigned file has no material; the newest version before it that is signed is
    /// found with its line's history, and none is `None`.
    #[tokio::test]
    async fn an_unsigned_file_is_compared_with_the_versions_before_it() {
        let (base, keys) = repository(None, &["1.0", "2.0", "2.1.0"], &["1.0", "2.0"]).await;
        let unsigned = signer(&base, &keys);
        assert_eq!(
            unsigned
                .client
                .earlier(&unsigned.key, "2.1.1", 64)
                .await
                .unwrap(),
            ["2.1.0", "2.0", "1.0"],
            "newest first, without the version itself"
        );
        assert!(unsigned.material().await.unwrap().is_none());
        assert_eq!(
            unsigned.signed_before().await.unwrap(),
            Some(("2.0".to_owned(), History(vec![false, true])))
        );
        let (base, keys) = repository(
            None,
            &["1.0", "2.0-M1", "2.0", "2.0.1", "2.1.0"],
            &["2.0-M1", "2.0", "2.0.1", "2.1.0"],
        )
        .await;
        assert_eq!(
            signer(&base, &keys).signed_before().await.unwrap(),
            Some(("2.1.0".to_owned(), History(vec![true, true, true]))),
            "its line's stable versions"
        );
        let short = FileSigner {
            history: 2,
            ..signer(&base, &keys)
        };
        assert_eq!(
            short.signed_before().await.unwrap(),
            Some(("2.1.0".to_owned(), History(vec![true, true]))),
            "of the versions its history reaches"
        );
        let (base, keys) = repository(None, &["1.0", "nightly"], &["1.0"]).await;
        let lineless = FileSigner {
            version: "nightly".to_owned(),
            file: "jakarta.annotation-api-nightly.jar".to_owned(),
            ..signer(&base, &keys)
        };
        assert_eq!(
            lineless.signed_before().await.unwrap(),
            Some(("1.0".to_owned(), History(Vec::new()))),
            "in no line"
        );
        let (base, keys) = repository(None, &["1.0"], &[]).await;
        assert_eq!(signer(&base, &keys).signed_before().await.unwrap(), None);
        let renamed = FileSigner {
            file: "other.jar".to_owned(),
            ..signer(&base, &keys)
        };
        assert!(renamed.url("1.0").ends_with("/1.0/other.jar"));
    }
}
