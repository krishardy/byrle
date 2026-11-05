//! Fetching an index file on the proxy's own behalf, for a download whose index file cargo
//! read from its own cache.

use crate::ecosystem::{Fetch, Fetched, FullDocument};
use crate::identity::PackageKey;

use super::paths::index_path;
use super::wire::normalize;

/// The headers the cargo index is sent.
pub const SERVICE: crate::service::Declared = crate::service::Declared {
    name: "the cargo index",
    headers: &["accept-encoding"],
};

/// Fetches index files from one sparse index.
#[derive(Debug, Clone)]
pub struct Client {
    http: crate::service::Service,
    index: String,
    max_bytes: usize,
}

impl Client {
    /// `index` is a base URL such as `https://index.crates.io`. A trailing slash is trimmed.
    pub fn new(connection: crate::service::Connection, index: &str, max_bytes: usize) -> Self {
        Self {
            http: crate::service::Service::new(SERVICE, &connection),
            index: index.trim_end_matches('/').to_owned(),
            max_bytes,
        }
    }

    /// One crate's index file as records.
    pub async fn metadata(&self, key: &PackageKey) -> Fetched {
        let url = format!("{}/{}", self.index, index_path(key.name()));
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT_ENCODING, "gzip")
            .send()
            .await
            .map_err(|e| format!("index request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("index answered {}", response.status()));
        }
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = crate::http::capped_body(response, self.max_bytes)
            .await
            .map_err(|e| format!("index request failed: {e}"))?;
        let decoded = crate::http::decode_for_parsing(&body, encoding.as_deref(), self.max_bytes)
            .map_err(|e| format!("index body could not be decoded: {e}"))?;
        Ok(normalize(&decoded))
    }
}

impl Fetch for Client {
    fn metadata<'a>(&'a self, key: &'a PackageKey) -> futures_util::future::BoxFuture<'a, Fetched> {
        Box::pin(Client::metadata(self, key))
    }

    /// Each line carries `pubtime`: nothing more is asked.
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

    fn itoa() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Cargo, "itoa").unwrap()
    }

    async fn client(answers: Vec<Answer>, max_bytes: usize) -> Client {
        let addr = scripted(answers).await;
        Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}/"),
            max_bytes,
        )
    }

    /// The file is asked for at its index path, and read as the forwarded one is.
    #[tokio::test]
    async fn a_crate_s_index_file_is_fetched_from_its_index_path() {
        let (addr, requests) = recorded(vec![Answer::body(super::super::fixture())]).await;
        let client = Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}"),
            1 << 20,
        );
        let metadata = Fetch::metadata(&client, &itoa()).await.expect("fetched");
        assert_eq!(metadata.expect("read").records.len(), 37);
        let request = String::from_utf8(requests.lock().unwrap()[0].clone()).unwrap();
        assert!(request.starts_with("GET /it/oa/itoa HTTP/1.1"), "{request}");
        assert!(Fetch::full(&client, &itoa()).await.unwrap().is_none());
    }

    /// An index answering gzip, as index.crates.io does when asked, is read decoded.
    #[tokio::test]
    async fn a_gzipped_index_file_is_decoded() {
        use std::io::Write as _;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&super::super::fixture()).unwrap();
        let body = gzip.finish().unwrap();
        let sent = body.len();
        let app = axum::Router::new().fallback(move || {
            let body = body.clone();
            async move { ([(axum::http::header::CONTENT_ENCODING, "gzip")], body) }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let client = Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}"),
            1 << 20,
        );
        let metadata = client.metadata(&itoa()).await.expect("fetched");
        assert_eq!(metadata.expect("read").records.len(), 37);
        let small = Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}"),
            sent,
        );
        let error = small
            .metadata(&itoa())
            .await
            .expect_err("decodes past the limit");
        assert!(
            error.starts_with("index body could not be decoded"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn each_way_a_fetch_fails_says_which() {
        for (answer, max_bytes, expected) in [
            (Answer::Status(404), 1 << 20, "index answered 404"),
            (Answer::Close, 1 << 20, "index request failed"),
            (Answer::cut_short(), 1 << 20, "index request failed"),
            (
                Answer::body("x".repeat(64)),
                8,
                "index request failed: the body is over 8 bytes",
            ),
        ] {
            let error = client(vec![answer], max_bytes)
                .await
                .metadata(&itoa())
                .await
                .expect_err("fails");
            assert!(error.starts_with(expected), "{error}");
        }
    }
}
