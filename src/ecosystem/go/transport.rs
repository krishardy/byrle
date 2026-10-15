//! Fetching a module's `@v/list` on the proxy's own behalf, for a zip whose list go read
//! from its own cache, and asking sum.golang.org what a version's files are.

use std::sync::{Arc, Mutex};

use crate::ecosystem::{Claim, Claimed, Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;
use crate::util::lru::Lru;

use super::paths::{LIST, escape};
use super::sumdb::{self, Answer};
use super::wire::list;

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
        let module = format!("{}/{}", self.proxy, escape(&key.registry_name()));
        let url = format!("{module}{LIST}");
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
        Ok(Ok(list(key, &body, &format!("{module}/@v/"))))
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
