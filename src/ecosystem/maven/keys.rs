//! Fetching the key a PGP signature names from key servers, as
//! [maven-signatures](../../../docs/engineering_decisions/0113-maven-signatures.md) decides:
//! each server in [`SERVERS`] in turn, by HKP, every copy found kept for its fingerprint.

use std::sync::{Arc, Mutex};

use crate::util::lru::Lru;

/// The key servers asked, in order; keyserver.ubuntu.com held 12 of 93 keys the first lacked.
pub const SERVERS: [&str; 2] = ["https://keys.openpgp.org", "https://keyserver.ubuntu.com"];

/// Keys kept, by the fingerprint or key id a signature named them by.
pub const MAX_KEYS: usize = 4096;

/// Asks key servers for keys, keeping what each answered.
#[derive(Clone)]
pub struct KeyServers {
    http: reqwest::Client,
    servers: Vec<String>,
    held: Arc<Mutex<Lru<String, Vec<String>>>>,
}

impl std::fmt::Debug for KeyServers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyServers")
            .field("servers", &self.servers)
            .finish_non_exhaustive()
    }
}

impl KeyServers {
    /// The servers in [`SERVERS`].
    pub fn new(http: reqwest::Client) -> Self {
        Self::at(http, &SERVERS)
    }

    /// The servers at `servers`, base URLs, asked in that order.
    pub fn at(http: reqwest::Client, servers: &[&str]) -> Self {
        Self {
            http,
            servers: servers
                .iter()
                .map(|s| s.trim_end_matches('/').to_owned())
                .collect(),
            held: Arc::new(Mutex::new(Lru::new(MAX_KEYS))),
        }
    }

    /// Each server's copy of the key `issuer` names, a fingerprint or key id in hex, every
    /// server asked at once, in server order; empty when none holds it. Kept once found.
    /// Errors when a server cannot be asked, or answers other than 200 or 404.
    pub async fn copies(&self, issuer: &str) -> Result<Vec<String>, String> {
        if let Some(held) = self.held.lock().expect("keys lock").get(&issuer.to_owned()) {
            return Ok(held.clone());
        }
        let asked = self.servers.iter().map(|server| self.copy(server, issuer));
        let mut copies = Vec::new();
        for answer in futures_util::future::join_all(asked).await {
            copies.extend(answer?);
        }
        if !copies.is_empty() {
            self.held
                .lock()
                .expect("keys lock")
                .insert(issuer.to_owned(), copies.clone());
        }
        Ok(copies)
    }
}

impl KeyServers {
    /// `server`'s copy of the key `issuer` names, `None` when it holds none. Errors when it
    /// cannot be asked, or answers other than 200 or 404.
    async fn copy(&self, server: &str, issuer: &str) -> Result<Option<String>, String> {
        let url = format!("{server}/pks/lookup?op=get&options=mr&search=0x{issuer}");
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("{server} could not be asked: {e}"))?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            status if !status.is_success() => Err(format!("{server} answered {status}")),
            _ => response
                .text()
                .await
                .map(Some)
                .map_err(|e| format!("{server} could not be read: {e}")),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::util::test_support::{Answer, recorded, scripted};

    /// Every server is asked, by HKP, and a key found is not asked for again.
    #[tokio::test]
    async fn each_server_s_copy_is_kept() {
        let (first, asked) = recorded(vec![Answer::Status(404)]).await;
        let (second, _) = recorded(vec![Answer::body("KEY")]).await;
        let servers = KeyServers::at(
            reqwest::Client::new(),
            &[&format!("http://{first}/"), &format!("http://{second}")],
        );
        for _ in 0..2 {
            assert_eq!(servers.copies("ABCD").await.unwrap(), ["KEY"]);
        }
        let request = String::from_utf8(asked.lock().unwrap()[0].clone()).unwrap();
        assert!(
            request.starts_with("GET /pks/lookup?op=get&options=mr&search=0xABCD HTTP/1.1"),
            "{request}"
        );
        assert_eq!(asked.lock().unwrap().len(), 1);
        assert!(format!("{servers:?}").contains(&first.to_string()));
    }

    /// A key no server holds is no copy, and is asked again; a server that cannot answer
    /// is an error.
    #[tokio::test]
    async fn a_key_no_server_holds_is_none_and_a_server_that_fails_is_an_error() {
        let addr = scripted(vec![Answer::Status(404)]).await;
        let none = KeyServers::at(reqwest::Client::new(), &[&format!("http://{addr}")]);
        assert!(none.copies("AB").await.unwrap().is_empty());
        for (answer, said) in [
            (Answer::Status(500), "answered 500"),
            (Answer::Close, "could not be asked"),
            (Answer::cut_short(), "could not be read"),
        ] {
            let addr = scripted(vec![answer]).await;
            let failing = KeyServers::at(reqwest::Client::new(), &[&format!("http://{addr}")]);
            let error = failing.copies("AB").await.unwrap_err();
            assert!(error.contains(said), "{error}");
        }
        assert_eq!(KeyServers::new(reqwest::Client::new()).servers, SERVERS);
    }
}
