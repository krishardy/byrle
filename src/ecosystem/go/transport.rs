//! Fetching a module's `@v/list` on the proxy's own behalf, for a zip whose list go read
//! from its own cache, and asking sum.golang.org what a version's files are.

use std::sync::{Arc, Mutex};

use crate::ecosystem::{Claim, Claimed, Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;
use crate::policy::facts::PublishTimes;
use crate::record::{PackageMetadata, PackageRecord};
use crate::util::lru::Lru;

use super::paths::{LIST, escape};
use super::sumdb::{self, Answer};
use super::wire::{Info, list, preferred, published, record};

/// Claims kept, one per module version: a version sum.golang.org knows never changes.
pub const MAX_CLAIMS: usize = 8192;

/// Fetches version lists from one module proxy, and claims from sum.golang.org.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    proxy: String,
    max_bytes: usize,
    sumdb: Arc<sumdb::Client>,
    /// Each module version's claim, by module path and version.
    claims: Arc<Mutex<Lru<(String, String), Claim>>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// `proxy` is a base URL such as `https://proxy.golang.org`. A trailing slash is trimmed.
    pub fn new(http: reqwest::Client, proxy: &str, max_bytes: usize) -> Self {
        let sumdb = sumdb::Client::new(http.clone(), sumdb::DEFAULT, super::note::SUM_GOLANG_ORG)
            .expect("the go command's key parses");
        Self {
            http,
            proxy: proxy.trim_end_matches('/').to_owned(),
            max_bytes,
            sumdb: Arc::new(sumdb),
            claims: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
        }
    }

    /// The same, asking `sumdb` for claims.
    pub fn with_sumdb(mut self, sumdb: sumdb::Client) -> Self {
        self.sumdb = Arc::new(sumdb);
        self
    }

    /// The URL of `key`'s files.
    fn files(&self, key: &PackageKey) -> String {
        format!("{}/{}/@v/", self.proxy, escape(&key.registry_name()))
    }

    /// `version`'s `.info`. `None` for 404 or 410: the proxy does not have it.
    async fn info(&self, key: &PackageKey, version: &str) -> Result<Option<Info>, String> {
        let url = format!("{}{}.info", self.files(key), escape(version));
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        match response.status().as_u16() {
            404 | 410 => return Ok(None),
            status if !(200..300).contains(&status) => {
                return Err(format!("{url} answered {status}"));
            }
            _ => {}
        }
        let body = response.bytes().await.map_err(|e| format!("{url}: {e}"))?;
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| format!("{url}: {e}"))
    }

    /// `version`'s record from its own `.info`, with its time: go fetches versions its list
    /// leaves out, pseudo-versions among them. `None` when the proxy does not have it.
    pub async fn version(
        &self,
        key: &PackageKey,
        version: &str,
    ) -> Result<Option<PackageRecord>, String> {
        let Some(info) = self.info(key, version).await? else {
            return Ok(None);
        };
        let published_at = published(&info)?;
        Ok(Some(record(key, version, published_at, &self.files(key))))
    }

    /// A time for each of `metadata`'s versions: each `.info` in the go command's order of
    /// preference, until one is older than `before`. Every version after that one is given
    /// its time: go chooses one only when it is named, and then asks its own `.info`.
    pub async fn dated(
        &self,
        metadata: &PackageMetadata,
        before: jiff::Timestamp,
    ) -> Result<PublishTimes, String> {
        let versions = preferred(metadata.records.iter().map(|r| r.package.version()));
        let mut times = PublishTimes::new();
        let mut cutoff = None;
        for version in versions {
            if let Some(at) = cutoff {
                times.insert(version.to_owned(), at);
                continue;
            }
            let info = self.info(&metadata.key, version).await?;
            let Some(at) = info.as_ref().map(published).transpose()?.flatten() else {
                continue;
            };
            times.insert(version.to_owned(), at);
            cutoff = (at < before).then_some(at);
        }
        Ok(times)
    }

    /// What sum.golang.org says of `key` at `version`: its zip's and its `go.mod`'s `h1:`.
    /// A known version's claim is kept; an unknown one is asked again, as it may be
    /// published since. Errors when sum.golang.org does not answer or prove its answer.
    pub async fn claim(&self, key: &PackageKey, version: &str) -> Result<Claimed, String> {
        let asked = (key.registry_name(), version.to_owned());
        let kept = self
            .claims
            .lock()
            .expect("claims lock")
            .get(&asked)
            .cloned();
        if let Some(claim) = kept {
            return Ok(Claimed::Known(claim));
        }
        let Answer::Known { zip, go_mod } = self.sumdb.lookup(&asked.0, version).await? else {
            return Ok(Claimed::Unknown);
        };
        let claim = Claim {
            artifact: zip,
            artifact_digest: super::dirhash::zip_h1::<std::fs::File>,
            manifest: go_mod,
            manifest_digest: super::dirhash::go_mod_h1,
        };
        self.claims
            .lock()
            .expect("claims lock")
            .insert(asked, claim.clone());
        Ok(Claimed::Known(claim))
    }

    /// One module's `@v/list` as records.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        let url = format!("{}/{}{LIST}", self.proxy, escape(&key.registry_name()));
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("version list request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("version list answered {}", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("version list request failed: {e}"))?;
        let body = crate::http::decode_for_parsing(&body, None, self.max_bytes)
            .map_err(|e| format!("version list body could not be decoded: {e}"))?;
        Ok(Ok(list(key, &body, &self.files(key))))
    }
}

impl Fetch for Client {
    fn metadata<'a>(&'a self, key: &'a PackageKey) -> futures_util::future::BoxFuture<'a, Fetched> {
        Box::pin(Client::metadata(self, key))
    }

    /// The list carries no times, and is not asked again for them.
    fn full<'a>(
        &'a self,
        _: &'a PackageKey,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<FullDocument>, String>> {
        Box::pin(async { Ok(None) })
    }

    fn claim<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Claimed, String>> {
        Box::pin(Client::claim(self, key, version))
    }

    fn version<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<PackageRecord>, String>> {
        Box::pin(Client::version(self, key, version))
    }

    fn dated<'a>(
        &'a self,
        metadata: &'a PackageMetadata,
        before: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<PublishTimes>, String>> {
        Box::pin(async move { Client::dated(self, metadata, before).await.map(Some) })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::identity::Ecosystem;
    use crate::util::test_support::{Answer, recorded, scripted};

    fn toml() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Go, "github.com/BurntSushi/toml").unwrap()
    }

    /// The list is asked for at the module's escaped path.
    #[tokio::test]
    async fn a_module_s_list_is_fetched_at_its_escaped_path() {
        let (addr, requests) = recorded(vec![Answer::body("v1.0.0\nv1.1.0\n")]).await;
        let client = Client::new(reqwest::Client::new(), &format!("http://{addr}/"), 1 << 20);
        let metadata = Fetch::metadata(&client, &toml()).await.expect("fetched");
        let metadata = metadata.expect("read");
        assert_eq!(metadata.records.len(), 2);
        assert_eq!(
            metadata.records[0].artifacts[0].url,
            format!("http://{addr}/github.com/!burnt!sushi/toml/@v/v1.0.0.zip")
        );
        let request = String::from_utf8(requests.lock().unwrap()[0].clone()).unwrap();
        assert!(
            request.starts_with("GET /github.com/!burnt!sushi/toml/@v/list HTTP/1.1"),
            "{request}"
        );
        assert!(Fetch::full(&client, &toml()).await.unwrap().is_none());
    }

    /// rsc.io/quote v1.5.2's lines, as sum.golang.org answered them on 2026-10-15.
    pub(crate) fn quote_record() -> String {
        "rsc.io/quote v1.5.2 h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=\n\
         rsc.io/quote v1.5.2/go.mod h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=\n"
            .to_owned()
    }

    /// A known version's claim is asked once and kept; an unknown one is asked each time.
    #[tokio::test]
    async fn a_claim_is_asked_of_the_checksum_database_once() {
        use super::super::sumdb::testing::{Database, client};
        let db = Database::new(vec![
            quote_record(),
            "other.example/m v1.0.0 h1:x=\n".into(),
        ]);
        let go = Client::new(reqwest::Client::new(), "http://127.0.0.1:9", 1 << 20)
            .with_sumdb(client(db.clone()).await);
        let quote = PackageKey::from_registry_name(Ecosystem::Go, "rsc.io/quote").unwrap();
        let Claimed::Known(claim) = Fetch::claim(&go, &quote, "v1.5.2").await.unwrap() else {
            panic!("sum.golang.org knows it");
        };
        assert_eq!(
            claim.artifact,
            "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="
        );
        let go_mod = super::super::fixture("rsc.io-quote-v1.5.2.mod");
        assert_eq!(claim.check_manifest(&go_mod), Ok(()));
        let error = claim.check_manifest(b"module rsc.io/quote\n").unwrap_err();
        assert!(error.contains("and the claim is h1:LzX7"), "{error}");

        let asked = db.log.asked.lock().unwrap().len();
        assert!(asked > 0, "the lookup read the log's tiles");
        assert!(matches!(
            go.claim(&quote, "v1.5.2").await,
            Ok(Claimed::Known(_))
        ));
        assert_eq!(
            db.log.asked.lock().unwrap().len(),
            asked,
            "kept, not asked again"
        );
        for _ in 0..2 {
            assert!(matches!(
                go.claim(&quote, "v9.0.0").await,
                Ok(Claimed::Unknown)
            ));
        }
        let broken = PackageKey::from_registry_name(Ecosystem::Go, "other.example/m").unwrap();
        let error = go.claim(&broken, "v1.0.0").await.unwrap_err();
        assert!(error.contains("go.mod"), "{error}");
        assert!(format!("{go:?}").contains("127.0.0.1:9"));
    }

    /// A module proxy answering `.info` for each of `infos`, by version, and 404 otherwise.
    async fn infos(infos: Vec<(&'static str, &'static str)>) -> String {
        let router = axum::Router::new().route(
            "/github.com/!burnt!sushi/toml/@v/{file}",
            axum::routing::get(
                move |axum::extract::Path(file): axum::extract::Path<String>| {
                    let infos = infos.clone();
                    async move {
                        let version = file.strip_suffix(".info").unwrap_or_default();
                        match infos.iter().find(|(v, _)| *v == version) {
                            Some((_, "500")) => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
                            Some((_, body)) => Ok(body.to_string()),
                            None => Err(axum::http::StatusCode::NOT_FOUND),
                        }
                    }
                },
            ),
        );
        crate::proxy::testing::serve(router).await
    }

    /// A version is read from its own `.info`, its `Time` its record's publish time.
    #[tokio::test]
    async fn a_version_is_read_from_its_own_info() {
        let base = infos(vec![
            (
                "v1.0.0",
                r#"{"Version":"v1.0.0","Time":"2020-01-02T03:04:05Z"}"#,
            ),
            ("v2.0.0", r#"{"Version":"v2.0.0","Time":"then"}"#),
            ("v3.0.0", "not json"),
            ("v4.0.0", "500"),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &base, 1 << 20);
        let record = Fetch::version(&client, &toml(), "v1.0.0")
            .await
            .unwrap()
            .expect("found");
        assert_eq!(
            record.published_at,
            Some("2020-01-02T03:04:05Z".parse().unwrap())
        );
        assert_eq!(
            record.artifacts[0].url,
            format!("{base}/github.com/!burnt!sushi/toml/@v/v1.0.0.zip")
        );
        assert_eq!(client.version(&toml(), "v9.0.0").await, Ok(None));
        for (version, error) in [
            ("v2.0.0", "Time `then`"),
            ("v3.0.0", "expected"),
            ("v4.0.0", "answered 500"),
        ] {
            let found = client.version(&toml(), version).await.unwrap_err();
            assert!(found.contains(error), "{version}: {found}");
        }
        let addr = scripted(vec![Answer::cut_short()]).await;
        let cut = Client::new(reqwest::Client::new(), &format!("http://{addr}"), 1 << 20);
        assert!(cut.version(&toml(), "v1.0.0").await.is_err());
        let closed = crate::util::test_support::closing_server().await;
        let closed = Client::new(reqwest::Client::new(), &format!("http://{closed}"), 1 << 20);
        assert!(closed.version(&toml(), "v1.0.0").await.is_err());
    }

    /// Versions are dated newest first until one is older than the cutoff; each after it is
    /// given its time, and one whose `.info` has no time stays undated.
    #[tokio::test]
    async fn versions_are_dated_newest_first_until_one_is_old_enough() {
        let base = infos(vec![
            (
                "v1.2.0",
                r#"{"Version":"v1.2.0","Time":"2026-10-14T00:00:00Z"}"#,
            ),
            ("v1.1.0", r#"{"Version":"v1.1.0"}"#),
            (
                "v1.0.1",
                r#"{"Version":"v1.0.1","Time":"2020-01-01T00:00:00Z"}"#,
            ),
            ("v1.0.0", "500"),
            ("v0.9.0", r#"{"Version":"v0.9.0","Time":"then"}"#),
        ])
        .await;
        let client = Client::new(reqwest::Client::new(), &base, 1 << 20);
        let metadata = list(&toml(), b"v1.0.0\nv1.2.0\nv1.0.1\nv1.1.0\nv1.3.0\n", "x");
        let before: jiff::Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let times = Fetch::dated(&client, &metadata, before)
            .await
            .unwrap()
            .expect("dated");
        let old: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            times,
            PublishTimes::from([
                ("v1.2.0".to_owned(), "2026-10-14T00:00:00Z".parse().unwrap()),
                ("v1.0.1".to_owned(), old),
                ("v1.0.0".to_owned(), old),
            ]),
            "v1.3.0 has no .info and v1.1.0 no time; v1.0.0's is never asked"
        );
        for failing in ["v1.0.0", "v0.9.0"] {
            let failing = list(&toml(), failing.as_bytes(), "x");
            assert!(client.dated(&failing, before).await.is_err());
        }
    }

    #[tokio::test]
    async fn each_way_a_fetch_fails_says_which() {
        for (answer, max_bytes, expected) in [
            (Answer::Status(404), 1 << 20, "version list answered 404"),
            (Answer::Close, 1 << 20, "version list request failed"),
            (Answer::cut_short(), 1 << 20, "version list request failed"),
            (
                Answer::body("v1.0.0\n".repeat(8)),
                8,
                "version list body could not be decoded",
            ),
        ] {
            let addr = scripted(vec![answer]).await;
            let client = Client::new(reqwest::Client::new(), &format!("http://{addr}"), max_bytes);
            let error = client.metadata(&toml()).await.expect_err("fails");
            assert!(error.starts_with(expected), "{error}");
        }
    }
}
