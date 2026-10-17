//! Fetching an artifact's `maven-metadata.xml` on the proxy's own behalf, for a pinned jar,
//! whose metadata mvn and Gradle never ask for, and a file's claim from its sidecars.

use std::sync::{Arc, Mutex};

use futures_util::stream::{self, StreamExt};

use crate::ecosystem::{Claim, Claimed, Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;
use crate::policy::facts::PublishTimes;
use crate::record::{PackageMetadata, PackageRecord};
use crate::util::lru::Lru;

use super::digest::{CLAIMED, Sidecar};
use super::keys::KeyServers;
use super::paths::{METADATA, directory};
use super::signer::FileSigner;
use super::wire::{parse, record};

/// Claims kept, one per file: a file published to Central is never replaced.
pub const MAX_CLAIMS: usize = 8192;

/// Publish times kept, one per version, for the same reason.
pub const MAX_TIMES: usize = 65_536;

/// The `.pom`s asked for their `Last-Modified` at once, when a document's versions are dated.
pub const DATING: usize = 16;

/// What a `HEAD` of a version's `.pom` found.
enum Pom {
    /// 404: the repository has no such version.
    Missing,
    /// The `.pom`, and its `Last-Modified` when it sent one.
    Published(Option<jiff::Timestamp>),
}

/// Fetches metadata and sidecars from one Maven repository.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    repository: String,
    max_bytes: usize,
    /// Each file's claim, by its URL.
    claims: Arc<Mutex<Lru<String, Claim>>>,
    /// Each version's publish time, by its `.pom`'s URL.
    times: Arc<Mutex<Lru<String, jiff::Timestamp>>>,
    /// Where the keys signatures name are asked for.
    keys: KeyServers,
    /// Each `.asc` read, `None` for one the repository has not, by its file's URL.
    signatures: Arc<Mutex<Lru<String, Option<Vec<u8>>>>>,
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
            repository: repository.trim_end_matches('/').to_owned(),
            max_bytes,
            claims: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
            times: Arc::new(Mutex::new(Lru::new(MAX_TIMES))),
            keys: KeyServers::new(http.clone()),
            signatures: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
            http,
        }
    }

    /// The same, asking `keys` for the keys signatures name.
    pub fn with_key_servers(mut self, keys: KeyServers) -> Self {
        self.keys = keys;
        self
    }

    /// Where the keys signatures name are asked for.
    pub fn keys(&self) -> &KeyServers {
        &self.keys
    }

    /// The URL of `version`'s `file` on the repository.
    pub fn file_url(&self, key: &PackageKey, version: &str, file: &str) -> String {
        format!("{}/{}/{version}/{file}", self.repository, directory(key))
    }

    /// The `.asc` beside the file at `url`, `None` when the repository has none, kept once
    /// read: a file published to Central is never replaced. Errors when it cannot be asked,
    /// or answers other than 200 or 404.
    pub async fn signature(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        let kept = self
            .signatures
            .lock()
            .expect("signatures lock")
            .get(&url.to_owned())
            .cloned();
        if let Some(kept) = kept {
            return Ok(kept);
        }
        let asked = format!("{url}.asc");
        let response = self
            .http
            .get(&asked)
            .send()
            .await
            .map_err(|e| format!(".asc request failed: {e}"))?;
        let signature = match response.status() {
            reqwest::StatusCode::NOT_FOUND => None,
            status if !status.is_success() => return Err(format!(".asc answered {status}")),
            _ => Some(
                response
                    .bytes()
                    .await
                    .map_err(|e| format!(".asc request failed: {e}"))?
                    .to_vec(),
            ),
        };
        self.signatures
            .lock()
            .expect("signatures lock")
            .insert(url.to_owned(), signature.clone());
        Ok(signature)
    }

    /// The versions of `key` published before `version`, newest first, at most `limit`, by
    /// their `.pom`s' times. Errors when the metadata or a time cannot be read.
    pub async fn earlier(
        &self,
        key: &PackageKey,
        version: &str,
        limit: usize,
    ) -> Result<Vec<String>, String> {
        let metadata = crate::ecosystem::fetched(self.metadata(key).await)?;
        let times = self.dated(&metadata).await?;
        let Some(at) = times.get(version).copied() else {
            return Ok(Vec::new());
        };
        let mut before: Vec<(jiff::Timestamp, String)> = times
            .into_iter()
            .filter(|(_, t)| *t < at)
            .map(|(v, t)| (t, v))
            .collect();
        before.sort();
        Ok(before
            .into_iter()
            .rev()
            .take(limit)
            .map(|(_, v)| v)
            .collect())
    }

    /// Whether `version` of `key` has a `.pom`, and its `Last-Modified` when it does,
    /// kept once read. Errors when it cannot be asked, or answers other than 200 or 404.
    async fn pom(&self, key: &PackageKey, version: &str) -> Result<Pom, String> {
        let pom = format!(
            "{}/{}/{version}/{}-{version}.pom",
            self.repository,
            directory(key),
            key.name()
        );
        if let Some(at) = self.times.lock().expect("times lock").get(&pom).copied() {
            return Ok(Pom::Published(Some(at)));
        }
        let response = self
            .http
            .head(&pom)
            .send()
            .await
            .map_err(|e| format!(".pom request failed: {e}"))?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => return Ok(Pom::Missing),
            status if !status.is_success() => return Err(format!(".pom answered {status}")),
            _ => {}
        }
        let published = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::http::http_date);
        if let Some(at) = published {
            self.times.lock().expect("times lock").insert(pom, at);
        }
        Ok(Pom::Published(published))
    }

    /// The record of `version` read on its own, its time its `.pom`'s `Last-Modified`.
    /// `None` when the repository has no `.pom` for it. Errors as the `.pom`'s `HEAD` does.
    pub async fn version(
        &self,
        key: &PackageKey,
        version: &str,
    ) -> Result<Option<PackageRecord>, String> {
        let Pom::Published(published_at) = self.pom(key, version).await? else {
            return Ok(None);
        };
        let versions = format!("{}/{}/", self.repository, directory(key));
        Ok(Some(record(key, version, published_at, &versions)))
    }

    /// A time for every version of `metadata`, [`DATING`] at a time: Maven picks the highest
    /// version a range allows, which may be published after a higher one outside it.
    /// Errors when one cannot be asked.
    pub async fn dated(&self, metadata: &PackageMetadata) -> Result<PublishTimes, String> {
        let versions: Vec<String> = metadata
            .records
            .iter()
            .map(|r| r.package.version().to_owned())
            .collect();
        let key = &metadata.key;
        let asked = stream::iter(versions)
            .map(move |version: String| async move {
                let at = match self.pom(key, &version).await? {
                    Pom::Published(at) => at,
                    Pom::Missing => None,
                };
                Ok::<_, String>(at.map(|at| (version, at)))
            })
            .buffer_unordered(DATING)
            .collect::<Vec<_>>()
            .await;
        let mut times = PublishTimes::new();
        for dated in asked {
            if let Some((version, at)) = dated? {
                times.insert(version, at);
            }
        }
        Ok(times)
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
                signer: Some(Arc::new(FileSigner {
                    client: self.clone(),
                    key: key.clone(),
                    version: version.to_owned(),
                    file: file.to_owned(),
                    history: if super::paths::is_descriptor(file) {
                        0
                    } else {
                        crate::analysis::attestation::DEFAULT_HISTORY
                    },
                })),
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

    fn version<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<PackageRecord>, String>> {
        Box::pin(Client::version(self, key, version))
    }

    /// Every version is dated, whatever `before` is: see [`Client::dated`].
    fn dated<'a>(
        &'a self,
        metadata: &'a PackageMetadata,
        _before: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<PublishTimes>, String>> {
        Box::pin(async move { Client::dated(self, metadata).await.map(Some) })
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
pub(crate) mod tests {
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

    /// A repository on loopback serving `poms`, each version's `.pom` with its
    /// `Last-Modified`, and 404 for every other path.
    pub(crate) async fn poms(poms: &[(&str, &str)]) -> String {
        let mut router = axum::Router::new();
        for (version, modified) in poms {
            let path =
                format!("/org/apache/commons/commons-lang3/{version}/commons-lang3-{version}.pom");
            let modified = (*modified).to_owned();
            router = router.route(
                &path,
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
        crate::proxy::testing::serve(router).await
    }

    /// A version is dated by its `.pom`'s `Last-Modified`, kept once read; one with no
    /// `.pom` is no version.
    #[tokio::test]
    async fn a_version_is_dated_by_its_pom() {
        let base = poms(&[("3.17.0", "Wed, 21 Aug 2024 14:04:19 GMT")]).await;
        let client = Client::new(reqwest::Client::new(), &base, 1 << 20);
        let record = Fetch::version(&client, &lang3(), "3.17.0")
            .await
            .unwrap()
            .expect("published");
        let at: jiff::Timestamp = "2024-08-21T14:04:19Z".parse().unwrap();
        assert_eq!(record.published_at, Some(at));
        assert_eq!(record.artifacts[0].filename, "commons-lang3-3.17.0.jar");
        assert!(client.version(&lang3(), "9.9.9").await.unwrap().is_none());
        let undated = Client::new(
            reqwest::Client::new(),
            &poms(&[("1", "not a date")]).await,
            1,
        );
        let record = undated.version(&lang3(), "1").await.unwrap().unwrap();
        assert_eq!(record.published_at, None);
    }

    /// Every version of a document is dated, whatever the cooldown, and one with no `.pom`
    /// left undated. A time read once is not asked again.
    #[tokio::test]
    async fn every_version_of_a_document_is_dated() {
        let base = poms(&[
            ("3.0", "Mon, 18 Jul 2011 00:00:00 GMT"),
            ("3.1", "Sun, 13 Nov 2011 00:00:00 GMT"),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &base, 1 << 20);
        let read = parse(
            b"<metadata><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
              <versioning><versions><version>3.0</version><version>3.1</version>\
              <version>3.2</version></versions></versioning></metadata>",
        )
        .unwrap();
        let metadata = read.records(&lang3(), "https://r.example/");
        let before: jiff::Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
        let times = Fetch::dated(&client, &metadata, before)
            .await
            .unwrap()
            .expect("dated");
        assert_eq!(times.len(), 2);
        assert_eq!(times["3.1"], "2011-11-13T00:00:00Z".parse().unwrap());
        assert!(!times.contains_key("3.2"));
        let addr = scripted(vec![Answer::Status(404)]).await;
        let missing = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        assert!(missing.dated(&metadata).await.unwrap().is_empty());
        let error = Client::new(reqwest::Client::new(), "http://127.0.0.1:9", 1)
            .dated(&metadata)
            .await
            .unwrap_err();
        assert!(error.starts_with(".pom request failed"), "{error}");
        let addr = scripted(vec![Answer::Status(500)]).await;
        let error = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1)
            .version(&lang3(), "3.0")
            .await
            .unwrap_err();
        assert_eq!(error, ".pom answered 500 Internal Server Error");
        let times = Arc::clone(&client.times);
        assert_eq!(times.lock().unwrap().len(), 2, "both times kept");
    }

    /// A `.asc` is read once, present or not; one that cannot be read is an error.
    #[tokio::test]
    async fn a_signature_is_read_once_and_a_failure_says_which() {
        let (addr, requests) = recorded(vec![Answer::Status(404)]).await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        let url = client.file_url(&lang3(), "3.17.0", "commons-lang3-3.17.0.jar");
        for _ in 0..2 {
            assert_eq!(client.signature(&url).await.unwrap(), None);
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
        for (answer, said) in [
            (Answer::Status(500), ".asc answered 500"),
            (Answer::Close, ".asc request failed"),
            (Answer::cut_short(), ".asc request failed"),
        ] {
            let addr = scripted(vec![answer]).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
            let error = client
                .signature(&format!("http://{addr}/x.jar"))
                .await
                .unwrap_err();
            assert!(error.starts_with(said), "{error}");
        }
    }

    /// A version the repository dates nothing for has nothing before it; metadata that
    /// cannot be read is an error.
    #[tokio::test]
    async fn the_versions_before_one_need_its_time_and_the_metadata() {
        let fixture = String::from_utf8(super::super::fixture("commons-lang3.xml")).unwrap();
        let addr = scripted(vec![
            Answer::Typed("text/xml", fixture.into_bytes()),
            Answer::Status(404),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        assert!(
            client
                .earlier(&lang3(), "3.17.0", 64)
                .await
                .unwrap()
                .is_empty()
        );
        let addr = scripted(vec![Answer::Status(404)]).await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        assert!(client.earlier(&lang3(), "3.17.0", 64).await.is_err());
        let addr = scripted(vec![
            Answer::Typed("text/xml", super::super::fixture("commons-lang3.xml")),
            Answer::Status(500),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        assert!(client.earlier(&lang3(), "3.17.0", 64).await.is_err());
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
