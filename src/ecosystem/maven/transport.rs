//! Fetching an artifact's `maven-metadata.xml` on the proxy's own behalf, for a pinned jar,
//! whose metadata mvn and Gradle never ask for, and a file's claim from its sidecars.

use std::sync::{Arc, Mutex};

use crate::ecosystem::{Claim, Claimed, Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;
use crate::util::lru::Lru;

use super::digest::{CLAIMED, Sidecar};
use super::paths::{METADATA, directory};
use super::wire::parse;

/// Claims kept, one per file: a file published to Central is never replaced.
pub const MAX_CLAIMS: usize = 8192;

/// Fetches metadata and sidecars from one Maven repository.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    repository: String,
    max_bytes: usize,
    /// Each file's claim, by its URL.
    claims: Arc<Mutex<Lru<String, Claim>>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// `repository` is a base URL such as `https://repo1.maven.org/maven2`. A trailing
    /// slash is trimmed.
    pub fn new(http: reqwest::Client, repository: &str, max_bytes: usize) -> Self {
        Self {
            http,
            repository: repository.trim_end_matches('/').to_owned(),
            max_bytes,
            claims: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
        }
    }

    /// The strongest digest the repository publishes beside `version`'s `file`: its
    /// `.sha512`, else its `.sha256`, else its `.sha1`. [`Claimed::Unknown`] when it publishes
    /// none. Errors when a sidecar cannot be fetched, or answers other than 200 or 404.
    pub async fn claim(
        &self,
        key: &PackageKey,
        version: &str,
        file: &str,
    ) -> Result<Claimed, String> {
        let url = format!("{}/{}/{version}/{file}", self.repository, directory(key));
        let kept = self.claims.lock().expect("claims lock").get(&url).cloned();
        if let Some(claim) = kept {
            return Ok(Claimed::Known(claim));
        }
        for sidecar in &CLAIMED {
            let Some(text) = self.sidecar(&url, sidecar).await? else {
                continue;
            };
            let Some(digest) = sidecar.claim(&text) else {
                tracing::warn!(url.full = %format!("{url}{}", sidecar.suffix), "the sidecar holds no digest; asking the next");
                continue;
            };
            let claim = Claim {
                artifact: digest.clone(),
                artifact_digest: sidecar.file,
                manifest: digest,
                manifest_digest: sidecar.bytes,
            };
            self.claims
                .lock()
                .expect("claims lock")
                .insert(url, claim.clone());
            return Ok(Claimed::Known(claim));
        }
        Ok(Claimed::Unknown)
    }

    /// The text of `sidecar` beside the file at `url`, `None` when the repository has none.
    /// Errors when it cannot be fetched, or answers other than 200 or 404.
    async fn sidecar(&self, url: &str, sidecar: &Sidecar) -> Result<Option<String>, String> {
        let asked = format!("{url}{}", sidecar.suffix);
        let response = self
            .http
            .get(&asked)
            .send()
            .await
            .map_err(|e| format!("{} request failed: {e}", sidecar.suffix))?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => return Ok(None),
            status if !status.is_success() => {
                return Err(format!("{} answered {status}", sidecar.suffix));
            }
            _ => {}
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("{} request failed: {e}", sidecar.suffix))?;
        Ok(Some(String::from_utf8_lossy(&body).into_owned()))
    }

    /// One artifact's `maven-metadata.xml` as records.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        let versions = format!("{}/{}/", self.repository, directory(key));
        let url = format!("{versions}{METADATA}");
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("maven-metadata.xml request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("maven-metadata.xml answered {}", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("maven-metadata.xml request failed: {e}"))?;
        let body = crate::http::decode_for_parsing(&body, None, self.max_bytes)
            .map_err(|e| format!("maven-metadata.xml body could not be decoded: {e}"))?;
        Ok(match parse(&body) {
            Ok(read) if read.is_of(key) => Ok(read.records(key, &versions)),
            Ok(_) => Err(format!("{url} names no versions of {key}")),
            Err(e) => Err(e),
        })
    }
}

impl Fetch for Client {
    fn metadata<'a>(&'a self, key: &'a PackageKey) -> futures_util::future::BoxFuture<'a, Fetched> {
        Box::pin(Client::metadata(self, key))
    }

    fn claim<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
        file: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Claimed, String>> {
        Box::pin(Client::claim(self, key, version, file))
    }

    /// The metadata carries no times, and is not asked again for them.
    fn full<'a>(
        &'a self,
        _: &'a PackageKey,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<FullDocument>, String>> {
        Box::pin(async { Ok(None) })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;
    use crate::util::test_support::{Answer, recorded, scripted};

    fn lang3() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Maven, "org.apache.commons:commons-lang3")
            .unwrap()
    }

    /// The metadata is asked for at the group's dots written as `/`.
    #[tokio::test]
    async fn an_artifact_s_metadata_is_fetched_at_its_group_path() {
        let fixture = String::from_utf8(super::super::fixture("commons-lang3.xml")).unwrap();
        let (addr, requests) = recorded(vec![Answer::body(fixture)]).await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}/"), 1 << 20);
        let metadata = Fetch::metadata(&client, &lang3()).await.expect("fetched");
        let metadata = metadata.expect("read");
        assert_eq!(metadata.records.len(), 27);
        assert_eq!(
            metadata.records[0].artifacts[0].url,
            format!("http://{addr}/org/apache/commons/commons-lang3/3.0/commons-lang3-3.0.jar")
        );
        let request = String::from_utf8(requests.lock().unwrap()[0].clone()).unwrap();
        assert!(
            request
                .starts_with("GET /org/apache/commons/commons-lang3/maven-metadata.xml HTTP/1.1"),
            "{request}"
        );
        assert!(Fetch::full(&client, &lang3()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_document_that_is_not_the_artifact_s_does_not_read() {
        let plugins = String::from_utf8(super::super::fixture("plugins.xml")).unwrap();
        for (body, said) in [(plugins, "names no versions"), ("<a>".to_owned(), "")] {
            let addr = scripted(vec![Answer::body(body)]).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
            let error = client
                .metadata(&lang3())
                .await
                .expect("fetched")
                .expect_err("not read");
            assert!(error.contains(said), "{error}");
        }
    }

    const SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /// The claim is the strongest sidecar the repository publishes, asked strongest first,
    /// and kept: a second claim of the file asks nothing.
    #[tokio::test]
    async fn a_claim_is_the_strongest_sidecar_published() {
        let (addr, requests) = recorded(vec![
            Answer::Status(404),
            Answer::Status(404),
            Answer::body(format!("{SHA1}  commons-lang3-3.17.0.jar\n")),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        for _ in 0..2 {
            let Claimed::Known(claim) =
                Fetch::claim(&client, &lang3(), "3.17.0", "commons-lang3-3.17.0.jar")
                    .await
                    .unwrap()
            else {
                panic!("claimed");
            };
            assert_eq!(claim.artifact, format!("sha1:{SHA1}"));
            assert_eq!(claim.manifest, claim.artifact);
            assert_eq!((claim.manifest_digest)(b"abc"), claim.manifest);
        }
        let asked: Vec<String> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                String::from_utf8_lossy(r)
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        let jar = "/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar";
        assert_eq!(
            asked,
            [
                format!("GET {jar}.sha512 HTTP/1.1"),
                format!("GET {jar}.sha256 HTTP/1.1"),
                format!("GET {jar}.sha1 HTTP/1.1"),
            ]
        );
    }

    /// A sidecar holding no digest is passed over for the next; none published is no claim.
    #[tokio::test]
    async fn a_file_with_no_digest_published_has_no_claim() {
        for (answers, expected) in [
            (
                vec![Answer::body("<html>not found</html>"), Answer::body(SHA256)],
                Some(format!("sha256:{SHA256}")),
            ),
            (vec![Answer::Status(404)], None),
        ] {
            let addr = scripted(answers).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
            let claimed = client.claim(&lang3(), "3.17.0", "x.jar").await.unwrap();
            let found = match claimed {
                Claimed::Known(claim) => Some(claim.artifact),
                Claimed::Unknown => None,
                Claimed::NotAsked => panic!("asked"),
            };
            assert_eq!(found, expected);
        }
    }

    /// A repository that cannot be asked gives no answer, which the proxy answers 503.
    #[tokio::test]
    async fn a_sidecar_that_cannot_be_read_is_no_answer() {
        for (answer, expected) in [
            (Answer::Status(500), ".sha512 answered 500"),
            (Answer::Close, ".sha512 request failed"),
            (Answer::cut_short(), ".sha512 request failed"),
        ] {
            let addr = scripted(vec![answer]).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
            let error = client.claim(&lang3(), "3.17.0", "x.jar").await.unwrap_err();
            assert!(error.starts_with(expected), "{error}");
        }
        let client = Client::new(reqwest::Client::new(), "http://r.example", 1);
        assert!(format!("{client:?}").contains("http://r.example"));
    }

    #[tokio::test]
    async fn each_way_a_fetch_fails_says_which() {
        for (answer, max_bytes, expected) in [
            (
                Answer::Status(404),
                1 << 20,
                "maven-metadata.xml answered 404",
            ),
            (Answer::Close, 1 << 20, "maven-metadata.xml request failed"),
            (
                Answer::cut_short(),
                1 << 20,
                "maven-metadata.xml request failed",
            ),
            (
                Answer::body("<metadata/>".repeat(8)),
                8,
                "maven-metadata.xml body could not be decoded",
            ),
        ] {
            let addr = scripted(vec![answer]).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), max_bytes);
            let error = client.metadata(&lang3()).await.expect_err("fails");
            assert!(error.starts_with(expected), "{error}");
        }
    }
}
