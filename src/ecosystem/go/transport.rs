//! Fetching a module's `@v/list` on the proxy's own behalf, for a zip whose list go read
//! from its own cache.

use crate::ecosystem::{Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;

use super::paths::{LIST, escape};
use super::wire::list;

/// Fetches version lists from one module proxy.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    proxy: String,
    max_bytes: usize,
}

impl Client {
    /// `proxy` is a base URL such as `https://proxy.golang.org`. A trailing slash is trimmed.
    pub fn new(http: reqwest::Client, proxy: &str, max_bytes: usize) -> Self {
        Self {
            http,
            proxy: proxy.trim_end_matches('/').to_owned(),
            max_bytes,
        }
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
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
