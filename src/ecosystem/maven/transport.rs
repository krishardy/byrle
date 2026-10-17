//! Fetching an artifact's `maven-metadata.xml` on the proxy's own behalf, for a pinned jar,
//! whose metadata mvn and Gradle never ask for.

use crate::ecosystem::{Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;

use super::paths::{METADATA, directory};
use super::wire::parse;

/// Fetches metadata from one Maven repository.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    repository: String,
    max_bytes: usize,
}

impl Client {
    /// `repository` is a base URL such as `https://repo1.maven.org/maven2`. A trailing
    /// slash is trimmed.
    pub fn new(http: reqwest::Client, repository: &str, max_bytes: usize) -> Self {
        Self {
            http,
            repository: repository.trim_end_matches('/').to_owned(),
            max_bytes,
        }
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
