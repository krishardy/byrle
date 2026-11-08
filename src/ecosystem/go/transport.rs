//! Fetching a module's `@v/list` on the proxy's own behalf, for a zip whose list go read
//! from its own cache, and asking sum.golang.org what a version's files are.

use std::sync::{Arc, Mutex};

use tracing::warn;

use crate::dating::{Read, RecordDates, Source};
use crate::ecosystem::{Claim, Claimed, Fetch, Fetched, FullDocument, Versioned};
use crate::identity::PackageKey;
use crate::policy::facts::PublishTimes;
use crate::record::PackageMetadata;
use crate::util::lru::Lru;

use super::heads::{self, Heads, Placed};
use super::paths::{LIST, escape};
use super::sumdb::{self, Answer};
use super::wire::{Info, list, preferred, published, record};

/// The headers the Go module proxy is sent.
pub const SERVICE: crate::service::Declared = crate::service::Declared {
    name: "the Go module proxy",
    headers: &[],
};

/// Claims kept, one per module version: a version sum.golang.org knows never changes.
pub const MAX_CLAIMS: usize = 8192;

/// Fetches version lists from one module proxy, and claims from sum.golang.org.
#[derive(Clone)]
pub struct Client {
    http: crate::service::Service,
    proxy: String,
    max_bytes: usize,
    sumdb: Arc<sumdb::Client>,
    /// Each module version's claim, by module path and version.
    claims: Arc<Mutex<Lru<(String, String), Claim>>>,
    /// Each module version's record number in the checksum database, which never changes.
    records: Arc<Mutex<Lru<(String, String), u64>>>,
    /// The checksum database's trees, which date a version by its record.
    heads: Arc<Heads>,
    /// How the index's client connects, for [`Client::with_index`].
    connection: crate::service::Connection,
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
    pub fn new(connection: crate::service::Connection, proxy: &str, max_bytes: usize) -> Self {
        let sumdb = sumdb::Client::new(
            connection.clone(),
            sumdb::DEFAULT,
            super::note::SUM_GOLANG_ORG,
        )
        .expect("the go command's key parses");
        Self {
            heads: Arc::new(Heads::new(connection.clone(), heads::INDEX)),
            http: crate::service::Service::new(SERVICE, &connection),
            proxy: proxy.trim_end_matches('/').to_owned(),
            max_bytes,
            sumdb: Arc::new(sumdb),
            claims: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
            records: Arc::new(Mutex::new(Lru::new(MAX_CLAIMS))),
            connection,
        }
    }

    /// The same, asking `sumdb` for claims and records.
    pub fn with_sumdb(mut self, sumdb: sumdb::Client) -> Self {
        self.sumdb = Arc::new(sumdb);
        self
    }

    /// The same, reading rows from the module index at `index`.
    pub fn with_index(mut self, index: &str) -> Self {
        self.heads = Arc::new(Heads::new(self.connection.clone(), index));
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
        let body = crate::http::capped_body(response, crate::http::MAX_SIDECAR_BYTES)
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|e| format!("{url}: {e}"))
    }

    /// `version`'s record from its own `.info`, dated for a cooldown starting `before`: go
    /// fetches versions its list leaves out, pseudo-versions among them. `None` when the
    /// proxy does not have it.
    pub async fn version(
        &self,
        key: &PackageKey,
        version: &str,
        before: Option<jiff::Timestamp>,
    ) -> Result<Option<Versioned>, String> {
        let Some(info) = self.info(key, version).await? else {
            return Ok(None);
        };
        let time = published(&info)?;
        let dates = match before {
            Some(before) => self.date(key, version, time, before).await,
            None => dates(
                time,
                Read::nothing(
                    checksum_database(None),
                    "not asked: the policy has no cooldown",
                ),
                time.map(|_| 0),
            ),
        };
        Ok(Some(Versioned {
            record: record(key, version, dates.time(), &self.files(key)),
            dates,
        }))
    }

    /// When `version` of `key` became public, for a cooldown starting `before`: by its
    /// record in the checksum database, [`Heads::placed`]. Its `.info` `time` when the
    /// database does not answer or has no record of it, which is logged.
    async fn date(
        &self,
        key: &PackageKey,
        version: &str,
        time: Option<jiff::Timestamp>,
        before: jiff::Timestamp,
    ) -> RecordDates {
        let record = match self.record(key, version).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                warn!(byrle.package.purl = %key, byrle.package.version = version, "a go version is dated by its .info Time: the checksum database has no record of it");
                let none = Read::nothing(checksum_database(None), "no record of this version");
                return dates(time, none, time.map(|_| 0));
            }
            Err(e) => {
                warn!(byrle.package.purl = %key, byrle.package.version = version, error.message = %e, "a go version is dated by its .info Time: the checksum database did not answer");
                let none = Read::nothing(checksum_database(None), format!("did not answer: {e}"));
                return dates(time, none, time.map(|_| 0));
            }
        };
        let placed = self.heads.placed(&self.sumdb, record, Some(before)).await;
        let source = checksum_database(Some(record));
        let (read, used) = match placed {
            Placed::Held(at) => (Read::at(source, at), Some(1)),
            Placed::BelowEvery(oldest) => {
                let info_first = matches!(time, Some(time) if time < oldest);
                (
                    Read::at(source, oldest),
                    Some(if info_first { 0 } else { 1 }),
                )
            }
            Placed::Unheld => (
                Read::nothing(source, "no tree head kept holds the record"),
                time.map(|_| 0),
            ),
        };
        dates(time, read, used)
    }

    /// `version` of `key`'s record number, kept once known. `None` when the database has no
    /// record of it. Errors when the database does not answer or prove its answer.
    async fn record(&self, key: &PackageKey, version: &str) -> Result<Option<u64>, String> {
        let asked = (key.registry_name(), version.to_owned());
        let kept = self
            .records
            .lock()
            .expect("records lock")
            .get(&asked)
            .copied();
        if kept.is_some() {
            return Ok(kept);
        }
        Ok(self.lookup(asked).await?.map(|(_, record)| record))
    }

    /// What the database says of `asked`, a module path and version: its claim and record
    /// number, both kept, and its tree, seen now. `None` when it has no record of it.
    async fn lookup(&self, asked: (String, String)) -> Result<Option<(Claim, u64)>, String> {
        let Answer::Known {
            zip,
            go_mod,
            record,
            tree,
        } = self.sumdb.lookup(&asked.0, &asked.1).await?
        else {
            return Ok(None);
        };
        self.heads.saw(tree, jiff::Timestamp::now());
        let claim = Claim {
            artifact: zip,
            artifact_digest: super::dirhash::zip_h1::<std::fs::File>,
            manifest: go_mod,
            manifest_digest: super::dirhash::go_mod_h1,
            signer: None,
        };
        self.records
            .lock()
            .expect("records lock")
            .insert(asked.clone(), record);
        self.claims
            .lock()
            .expect("claims lock")
            .insert(asked, claim.clone());
        Ok(Some((claim, record)))
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
            let Some(info) = self.info(&metadata.key, version).await? else {
                continue;
            };
            let time = published(&info)?;
            let Some(at) = self.date(&metadata.key, version, time, before).await.time() else {
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
        Ok(match self.lookup(asked).await? {
            Some((claim, _)) => Claimed::Known(claim),
            None => Claimed::Unknown,
        })
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
        let body = crate::http::capped_body(response, self.max_bytes)
            .await
            .map_err(|e| format!("version list request failed: {e}"))?;
        Ok(Ok(list(key, &body, &self.files(key))))
    }
}

impl Fetch for Client {
    fn metadata<'a>(&'a self, key: &'a PackageKey) -> futures_util::future::BoxFuture<'a, Fetched> {
        Box::pin(Client::metadata(self, key))
    }

    fn keeping(&self, store: &Arc<dyn crate::analysis::store::Trees>) {
        self.sumdb.keeping_trees(store.clone());
    }

    /// The list carries no times, and is not asked again for them.
    fn full<'a>(
        &'a self,
        _: &'a PackageKey,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<FullDocument>, String>> {
        Box::pin(async { Ok(None) })
    }

    /// One lookup holds a version's zip and `go.mod`, so `file` is not asked.
    fn claim<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
        _file: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Claimed, String>> {
        Box::pin(Client::claim(self, key, version))
    }

    fn version<'a>(
        &'a self,
        key: &'a PackageKey,
        version: &'a str,
        before: Option<jiff::Timestamp>,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<Versioned>, String>> {
        Box::pin(Client::version(self, key, version, before))
    }

    fn dated<'a>(
        &'a self,
        metadata: &'a PackageMetadata,
        before: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<'a, Result<Option<PublishTimes>, String>> {
        Box::pin(async move { Client::dated(self, metadata, before).await.map(Some) })
    }
}

/// The checksum database as a source of a version's date, naming `record` when known.
fn checksum_database(record: Option<u64>) -> Source {
    Source::Record(match record {
        Some(record) => format!("the checksum database, record {record}"),
        None => "the checksum database".to_owned(),
    })
}

/// The `.info` `time` and the checksum database's `read`, `used` the one that dates it.
fn dates(time: Option<jiff::Timestamp>, read: Read, used: Option<usize>) -> RecordDates {
    let source = Source::Record("the .info Time".to_owned());
    let info = match time {
        Some(time) => Read::at(source, time),
        None => Read::nothing(source, "the .info has no Time"),
    };
    RecordDates {
        reads: vec![info, read],
        used,
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
        let client = Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}/"),
            1 << 20,
        );
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
        let go = Client::new(
            crate::service::Connection::default(),
            "http://127.0.0.1:9",
            1 << 20,
        )
        .with_sumdb(client(db.clone()).await);
        let quote = PackageKey::from_registry_name(Ecosystem::Go, "rsc.io/quote").unwrap();
        let Claimed::Known(claim) = Fetch::claim(&go, &quote, "v1.5.2", "v1.5.2.zip")
            .await
            .unwrap()
        else {
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
        let client = Client::new(crate::service::Connection::default(), &base, 1 << 20);
        let record = Fetch::version(&client, &toml(), "v1.0.0", None)
            .await
            .unwrap()
            .expect("found")
            .record;
        assert_eq!(
            record.published_at,
            Some("2020-01-02T03:04:05Z".parse().unwrap())
        );
        assert_eq!(
            record.artifacts[0].url,
            format!("{base}/github.com/!burnt!sushi/toml/@v/v1.0.0.zip")
        );
        assert_eq!(client.version(&toml(), "v9.0.0", None).await, Ok(None));
        for (version, error) in [
            ("v2.0.0", "Time `then`"),
            ("v3.0.0", "expected"),
            ("v4.0.0", "answered 500"),
        ] {
            let found = client.version(&toml(), version, None).await.unwrap_err();
            assert!(found.contains(error), "{version}: {found}");
        }
        let addr = scripted(vec![Answer::cut_short()]).await;
        let cut = Client::new(
            crate::service::Connection::default(),
            &format!("http://{addr}"),
            1 << 20,
        );
        assert!(cut.version(&toml(), "v1.0.0", None).await.is_err());
        let closed = crate::util::test_support::closing_server().await;
        let closed = Client::new(
            crate::service::Connection::default(),
            &format!("http://{closed}"),
            1 << 20,
        );
        assert!(closed.version(&toml(), "v1.0.0", None).await.is_err());
    }

    /// Clients whose Go client is `client`.
    pub(crate) fn holding(client: Client) -> crate::ecosystem::Clients {
        crate::ecosystem::Clients::new(
            crate::service::Connection::default(),
            &crate::ecosystem::Upstreams::defaults(),
            1 << 20,
        )
        .with(
            crate::ecosystem::Repository::of(Ecosystem::Go),
            Arc::new(client),
        )
    }

    /// Clients asking a Go module proxy at `base`, whose checksum database is `sumdb`.
    pub(crate) fn clients(base: &str, sumdb: sumdb::Client) -> crate::ecosystem::Clients {
        holding(Client::new(crate::service::Connection::default(), base, 1 << 20).with_sumdb(sumdb))
    }

    /// A checksum database holding only rsc.io/quote, so no other module has a record.
    pub(crate) async fn sumdb_of_quote() -> sumdb::Client {
        use super::super::sumdb::testing::{Database, client};
        client(Database::new(vec![quote_record()])).await
    }

    /// Records of `example.com/m` at `v0` to `v1999`, one every 10 minutes, each claiming
    /// a 2020 `.info` `Time`, with an index of them. Returns the client and when each was
    /// published.
    pub(crate) async fn backdated() -> (
        Client,
        Vec<jiff::Timestamp>,
        Arc<super::super::sumdb::testing::Database>,
    ) {
        use super::super::heads::testing::{every_ten_minutes, serve};
        let published = every_ten_minutes(2000);
        let (_index, index, db, sumdb) = serve(published.clone()).await;
        let router = axum::Router::new().route(
            "/example.com/m/@v/{file}",
            axum::routing::get(|| async { r#"{"Version":"v0","Time":"2020-01-01T00:00:00Z"}"# }),
        );
        let base = crate::proxy::testing::serve(router).await;
        let client = Client::new(crate::service::Connection::default(), &base, 1 << 20)
            .with_sumdb(sumdb)
            .with_index(&index);
        (client, published, db)
    }

    /// A record no tree head kept holds is dated by its `.info` `Time`, and one below every
    /// row by the oldest row when that is earlier.
    #[tokio::test]
    async fn a_record_no_tree_holds_is_dated_by_its_info() {
        let (client, _, _) = backdated().await;
        let m = PackageKey::from_registry_name(Ecosystem::Go, "example.com/m").unwrap();
        client
            .records
            .lock()
            .unwrap()
            .insert(("example.com/m".to_owned(), "v9".to_owned()), 1 << 40);
        let claimed: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        let before = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(7 * 24);
        let dates = client.date(&m, "v9", Some(claimed), before).await;
        assert_eq!(dates.time(), Some(claimed));
        assert_eq!(
            dates.reads[1].said,
            crate::dating::Said::Nothing("no tree head kept holds the record".to_owned())
        );

        let now = jiff::Timestamp::now();
        let below = client.date(&m, "v500", Some(now), before).await;
        assert_eq!(
            below.used,
            Some(1),
            "the oldest row is earlier than its Time"
        );
        assert!(below.time().unwrap() < now);
    }

    /// v500, older than the seed, keeps its 2020 `Time`; v1950 is dated by its record, which
    /// and whose claim are kept. With no cooldown, no record is asked.
    #[tokio::test]
    async fn a_version_is_dated_by_its_record_not_its_commit() {
        let (client, published, db) = backdated().await;
        let m = PackageKey::from_registry_name(Ecosystem::Go, "example.com/m").unwrap();
        let before = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(7 * 24);
        let claimed: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        let dated = |version: &'static str, before| {
            let client = client.clone();
            let m = m.clone();
            async move {
                client
                    .version(&m, version, before)
                    .await
                    .unwrap()
                    .unwrap()
                    .record
                    .published_at
                    .unwrap()
            }
        };
        assert_eq!(dated("v500", Some(before)).await, claimed);
        let new = dated("v1950", Some(before)).await;
        let late = new.duration_since(published[1950]);
        assert!(
            late > jiff::SignedDuration::ZERO
                && late <= super::super::heads::GRAIN + super::super::heads::MARGIN,
            "{late:?}"
        );
        let asked = db.log.asked.lock().unwrap().len();
        assert_eq!(dated("v1950", Some(before)).await, new);
        assert!(matches!(
            client.claim(&m, "v1950").await,
            Ok(Claimed::Known(_))
        ));
        assert_eq!(db.log.asked.lock().unwrap().len(), asked, "kept");
        assert_eq!(dated("v1951", None).await, claimed, "no cooldown");

        let metadata = list(&m, b"v500\nv1950\n", "x");
        let times = client.dated(&metadata, before).await.unwrap();
        assert_eq!(times["v1950"], new);
        assert_eq!(times["v500"], claimed);
    }

    /// A database that does not answer leaves the `.info` `Time`, logged.
    #[tokio::test]
    async fn a_database_that_does_not_answer_leaves_the_info_time() {
        let base = infos(vec![(
            "v1.0.0",
            r#"{"Version":"v1.0.0","Time":"2020-01-02T03:04:05Z"}"#,
        )])
        .await;
        let closed = crate::util::test_support::closing_server().await;
        let sumdb = sumdb::Client::new(
            crate::service::Connection::default(),
            &format!("http://{closed}"),
            super::super::note::SUM_GOLANG_ORG,
        )
        .unwrap();
        let client =
            Client::new(crate::service::Connection::default(), &base, 1 << 20).with_sumdb(sumdb);
        let (guard, log) = crate::util::test_support::capture(tracing::Level::WARN);
        let record = client
            .version(&toml(), "v1.0.0", Some(jiff::Timestamp::now()))
            .await
            .unwrap()
            .unwrap()
            .record;
        drop(guard);
        assert_eq!(
            record.published_at,
            Some("2020-01-02T03:04:05Z".parse().unwrap())
        );
        let log = crate::util::test_support::text(&log);
        assert!(
            log.contains("the checksum database did not answer"),
            "{log}"
        );
    }

    /// Versions are dated newest first until one is older than the cutoff, each after it
    /// given its time. A version with no record keeps its `.info` `Time`, logged.
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
        let client = Client::new(crate::service::Connection::default(), &base, 1 << 20)
            .with_sumdb(sumdb_of_quote().await);
        let metadata = list(&toml(), b"v1.0.0\nv1.2.0\nv1.0.1\nv1.1.0\nv1.3.0\n", "x");
        let before: jiff::Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let (guard, log) = crate::util::test_support::capture(tracing::Level::WARN);
        let times = Fetch::dated(&client, &metadata, before)
            .await
            .unwrap()
            .expect("dated");
        drop(guard);
        let log = crate::util::test_support::text(&log);
        assert!(
            log.contains("the checksum database has no record of it"),
            "{log}"
        );
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
        let at_the_cutoff = list(&toml(), b"v1.0.1\nv0.9.5\n", "x");
        let cutoff: jiff::Timestamp = "2020-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            client.dated(&at_the_cutoff, cutoff).await.unwrap(),
            PublishTimes::from([("v1.0.1".to_owned(), cutoff)]),
            "a version published at the cutoff is not older than it, so v0.9.5 is asked"
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
                "version list request failed: the body is over 8 bytes",
            ),
        ] {
            let addr = scripted(vec![answer]).await;
            let client = Client::new(
                crate::service::Connection::default(),
                &format!("http://{addr}"),
                max_bytes,
            );
            let error = client.metadata(&toml()).await.expect_err("fails");
            assert!(error.starts_with(expected), "{error}");
        }
    }
}
