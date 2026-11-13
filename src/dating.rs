//! Where a file's publish time is read from, what each place gave, and which one dated it,
//! for a cooldown. The proxy, `byrle explain` and `byrle policy diff` read them in one order.
//! See docs/engineering_decisions/0129-undated-files-first-seen.md and
//! docs/engineering_decisions/0137-dates-reported.md.

use futures_util::future::BoxFuture;

use crate::ecosystem::FullDocument;
use crate::policy::facts::PublishTimes;
use crate::record::{PackageMetadata, PackageRecord};

/// One place a publish time is read from, in the order the proxy reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The record's own time, as the ecosystem's client names where it read it.
    Record(String),
    /// The full document's time for the version.
    Document,
    /// The file host's `Last-Modified`, from a HEAD.
    FileHost,
    /// When the proxy first decided the file.
    FirstSighting,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(what) => f.write_str(what),
            Self::Document => f.write_str("the full document's time"),
            Self::FileHost => f.write_str("the file host's Last-Modified"),
            Self::FirstSighting => f.write_str("the file's first sighting"),
        }
    }
}

/// What one source gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Said {
    At(jiff::Timestamp),
    /// No time, and why.
    Nothing(String),
}

impl Said {
    pub fn time(&self) -> Option<jiff::Timestamp> {
        match self {
            Self::At(at) => Some(*at),
            Self::Nothing(_) => None,
        }
    }
}

/// One source, and what it gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    pub source: Source,
    pub said: Said,
}

impl Read {
    pub fn at(source: Source, at: jiff::Timestamp) -> Self {
        Self {
            source,
            said: Said::At(at),
        }
    }

    pub fn nothing(source: Source, why: impl Into<String>) -> Self {
        Self {
            source,
            said: Said::Nothing(why.into()),
        }
    }
}

/// The reads an ecosystem's client made for a record's own time, and the one it used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordDates {
    pub reads: Vec<Read>,
    pub used: Option<usize>,
}

impl RecordDates {
    /// The time of the read used.
    pub fn time(&self) -> Option<jiff::Timestamp> {
        self.reads[self.used?].said.time()
    }

    /// The record's time as its document gave it, for a client that read nothing else.
    pub fn of(record: &PackageRecord) -> Self {
        Self::named(record, "the metadata's publish time")
    }

    /// The record's time, read from `what`.
    pub fn named(record: &PackageRecord, what: &str) -> Self {
        let source = Source::Record(what.to_owned());
        match record.published_at {
            Some(at) => Self {
                reads: vec![Read::at(source, at)],
                used: Some(0),
            },
            None => Self {
                reads: vec![Read::nothing(source, "the metadata carries none")],
                used: None,
            },
        }
    }
}

/// Every source read for one file, and the one that dated it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dating {
    /// The file dated.
    pub file: Option<String>,
    pub reads: Vec<Read>,
    /// The position in `reads` of the one used.
    pub used: Option<usize>,
}

impl Dating {
    /// The source used, and its time.
    pub fn dated(&self) -> Option<(&Source, jiff::Timestamp)> {
        let read = &self.reads[self.used?];
        read.said.time().map(|at| (&read.source, at))
    }

    /// One line per source, `*` on the one used, each indented by `indent`.
    pub fn lines(&self, indent: &str) -> String {
        let width = self
            .reads
            .iter()
            .map(|read| read.source.to_string().len())
            .max()
            .unwrap_or(0);
        let mut out = String::new();
        for (i, read) in self.reads.iter().enumerate() {
            let mark = if Some(i) == self.used { '*' } else { ' ' };
            let said = match &read.said {
                Said::At(at) => at.to_string(),
                Said::Nothing(why) => why.clone(),
            };
            out.push_str(&format!(
                "{indent}{mark} {:width$}  {said}\n",
                read.source.to_string()
            ));
        }
        out
    }

    /// Add `read`, used when nothing before it was.
    fn push(&mut self, read: Read) {
        if self.used.is_none() && read.said.time().is_some() {
            self.used = Some(self.reads.len());
        }
        self.reads.push(read);
    }
}

/// Where the sources past the record's own are read from.
pub trait Sources: Send + Sync {
    /// The full document. `Ok(None)` for an ecosystem whose records carry publish times.
    fn full(&self) -> BoxFuture<'_, Result<Option<FullDocument>, String>>;

    /// The `Last-Modified` the host of the file at `url` answers a HEAD with. Errors with
    /// why there is none, or why it was not asked.
    fn last_modified<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<jiff::Timestamp, String>>;

    /// When the file `filename` of `purl` was first decided. `Ok(None)` for none.
    fn first_seen<'a>(
        &'a self,
        purl: &'a str,
        filename: &'a str,
    ) -> BoxFuture<'a, Result<Option<jiff::Timestamp>, String>>;
}

/// How far to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Read the file host and the first sighting, which only a cooldown needs.
    pub cooldown: bool,
    /// Read every source, past the first that answers.
    pub every: bool,
}

/// What [`date`] found.
#[derive(Debug, Default)]
pub struct Found {
    pub dating: Dating,
    /// The full document's times, with this version's from the file host or the sighting.
    pub times: Option<PublishTimes>,
    /// The full document's records, for the heuristics.
    pub full: Option<PackageMetadata>,
    /// Why the full document could not be read.
    pub unread: Option<String>,
}

/// Date `record`'s file, as `purl`: the record's own time, the full document's, the file
/// host's `Last-Modified` and the file's first sighting, in that order, the first that
/// answers used. `own` is what the record's client read. Unless `reading.every`, reading
/// stops at the first that answers. The file host is asked only when none before it did.
pub async fn date(
    record: &PackageRecord,
    purl: &str,
    own: RecordDates,
    sources: &dyn Sources,
    reading: Reading,
) -> Found {
    let mut found = Found {
        dating: Dating {
            file: record.artifact().map(|a| a.filename.clone()),
            reads: own.reads,
            used: own.used,
        },
        ..Found::default()
    };
    read(record, purl, sources, reading, &mut found).await;
    if record.published_at.is_none()
        && let Some((_, at)) = found.dating.dated()
    {
        found
            .times
            .get_or_insert_default()
            .entry(record.package.version().to_owned())
            .or_insert(at);
    }
    found
}

/// The sources past the record's own, into `found`, as [`date`] reads them.
async fn read(
    record: &PackageRecord,
    purl: &str,
    sources: &dyn Sources,
    reading: Reading,
    found: &mut Found,
) {
    let answered = |found: &Found| found.dating.used.is_some() && !reading.every;
    if answered(found) {
        return;
    }
    let document = match sources.full().await {
        Ok(Some(full)) => {
            let read = match full.times.get(record.package.version()) {
                Some(at) => Read::at(Source::Document, *at),
                None => Read::nothing(Source::Document, "its times do not list this version"),
            };
            found.times = Some(full.times);
            found.full = full.metadata.ok();
            read
        }
        Ok(None) => Read::nothing(Source::Document, "the ecosystem has no fuller document"),
        Err(e) => {
            let read = Read::nothing(Source::Document, format!("not read: {e}"));
            found.unread = Some(e);
            read
        }
    };
    found.dating.push(document);
    let Some(artifact) = record.artifact() else {
        return;
    };
    if answered(found) || !reading.cooldown {
        return;
    }
    let host = if found.dating.used.is_some() {
        Read::nothing(Source::FileHost, "not asked: an earlier source dates it")
    } else {
        match sources.last_modified(&artifact.url).await {
            Ok(at) => Read::at(Source::FileHost, at),
            Err(why) => Read::nothing(Source::FileHost, why),
        }
    };
    found.dating.push(host);
    if answered(found) {
        return;
    }
    let seen = match sources.first_seen(purl, &artifact.filename).await {
        Ok(Some(at)) => Read::at(Source::FirstSighting, at),
        Ok(None) => Read::nothing(Source::FirstSighting, "none stored"),
        Err(why) => Read::nothing(Source::FirstSighting, why),
    };
    found.dating.push(seen);
}

/// The `Last-Modified` the host of the file at `url` answers a HEAD from `service` with.
/// Errors with why there is none: the host refused the HEAD, could not be asked, or sent
/// no date.
pub async fn last_modified(
    service: &crate::service::Service,
    url: &str,
) -> Result<jiff::Timestamp, String> {
    let response = service
        .head(url)
        .send()
        .await
        .map_err(|e| format!("the file host could not be asked: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "the file host answered {} to a HEAD",
            response.status().as_u16()
        ));
    }
    response
        .headers()
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::http::http_date)
        .ok_or_else(|| "the file host sent no Last-Modified".to_owned())
}

/// What `explain` and `policy diff` read dates from. It records no first sighting.
#[derive(Clone)]
pub struct Reader {
    pub clients: crate::ecosystem::Clients,
    hosts: crate::service::Service,
    origins: crate::origin::OriginPolicy,
    sightings: Option<std::sync::Arc<dyn crate::analysis::store::Analyses>>,
}

impl Reader {
    pub fn new(
        clients: crate::ecosystem::Clients,
        hosts: crate::service::Service,
        origins: crate::origin::OriginPolicy,
        sightings: Option<std::sync::Arc<dyn crate::analysis::store::Analyses>>,
    ) -> Self {
        Self {
            clients,
            hosts,
            origins,
            sightings,
        }
    }

    /// The reader the environment describes, connecting as the proxy does, with the first
    /// sightings at [`crate::env::DATABASE_URL`] when it is set.
    pub async fn from_env<L: Fn(&str) -> Option<std::ffi::OsString>>(
        environment: &crate::env::Env<L>,
    ) -> Result<Self, String> {
        let connection = crate::startup::connection(environment).map_err(|e| e.to_string())?;
        let upstreams = environment.upstreams().map_err(|e| e.to_string())?;
        let served = environment.artifact_origins().map_err(|e| e.to_string())?;
        let allowed = environment
            .allow_direct_origins()
            .map_err(|e| e.to_string())?;
        let origins = crate::proxy::origin_policy(&upstreams, &served, &allowed)
            .map_err(|e| e.to_string())?;
        let sightings = crate::analysis::postgres::from_env(environment)
            .await
            .map_err(|e| format!("{}: {e}", crate::env::DATABASE_URL))?;
        Ok(Self::new(
            crate::ecosystem::Clients::new(
                connection.clone(),
                &upstreams,
                environment
                    .max_metadata_bytes()
                    .map_err(|e| e.to_string())?,
            ),
            crate::service::Service::new(crate::proxy::UPSTREAM, &connection),
            origins,
            sightings,
        ))
    }

    /// Date `versioned`, `key`'s record from `at`, as [`date`] does.
    pub async fn date(
        &self,
        at: crate::ecosystem::Repository,
        key: &crate::identity::PackageKey,
        versioned: &crate::ecosystem::Versioned,
        reading: Reading,
    ) -> Found {
        let record = &versioned.record;
        let purl = crate::proxy::purl_of(key, record.package.version());
        let asking = Asking {
            reader: self,
            at,
            key,
        };
        date(record, &purl, versioned.dates.clone(), &asking, reading).await
    }
}

/// A [`Reader`] asking about one package.
struct Asking<'r> {
    reader: &'r Reader,
    at: crate::ecosystem::Repository,
    key: &'r crate::identity::PackageKey,
}

impl Sources for Asking<'_> {
    fn full(&self) -> BoxFuture<'_, Result<Option<FullDocument>, String>> {
        Box::pin(self.reader.clients.full_document(self.at, self.key))
    }

    fn last_modified<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<jiff::Timestamp, String>> {
        Box::pin(async move {
            if let crate::origin::Disposition::Refused(origin) =
                self.reader.origins.disposition(url)
            {
                return Err(format!(
                    "not asked: the file is on {origin}, which the proxy does not serve"
                ));
            }
            last_modified(&self.reader.hosts, url).await
        })
    }

    fn first_seen<'a>(
        &'a self,
        purl: &'a str,
        filename: &'a str,
    ) -> BoxFuture<'a, Result<Option<jiff::Timestamp>, String>> {
        Box::pin(async move {
            let Some(sightings) = &self.reader.sightings else {
                return Err(format!("not read: {} is not set", crate::env::DATABASE_URL));
            };
            sightings
                .sighted(purl, filename)
                .await
                .map_err(|e| format!("not read: {e}"))
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use super::*;

    /// A reader asking `clients`, the file hosts of the default registries and `served`, and
    /// `sightings` for first sightings.
    pub(crate) fn reader(
        clients: crate::ecosystem::Clients,
        served: &[String],
        sightings: Option<std::sync::Arc<dyn crate::analysis::store::Analyses>>,
    ) -> Reader {
        let connection = crate::service::Connection::default();
        Reader::new(
            clients,
            crate::service::Service::new(crate::proxy::UPSTREAM, &connection),
            crate::proxy::origin_policy(&crate::ecosystem::Upstreams::defaults(), served, &[])
                .expect("valid origins"),
            sightings,
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn at(text: &str) -> jiff::Timestamp {
        text.parse().expect("a timestamp")
    }

    /// `widget` 1.0.0 as an abbreviated packument, whose file is at `tarball`, dated at
    /// `published` when given.
    fn widget(tarball: &str, published: Option<&str>) -> PackageRecord {
        let doc = serde_json::json!({"name": "widget", "versions": {"1.0.0": {
            "name": "widget", "version": "1.0.0",
            "dist": {"tarball": tarball, "integrity": "sha512-AAAA"}}}});
        let mut record = crate::ecosystem::npm::normalize_packument(
            doc.to_string().as_bytes(),
            crate::record::DocumentDetail::Abbreviated,
        )
        .expect("normalizes")
        .records
        .remove(0);
        record.published_at = published.map(at);
        record
    }

    /// Sources answering as set, keeping which were asked.
    struct Fake {
        full: Result<Option<FullDocument>, String>,
        host: Result<jiff::Timestamp, String>,
        seen: Result<Option<jiff::Timestamp>, String>,
        asked: Mutex<Vec<&'static str>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                full: Ok(None),
                host: Err("the file host sent no Last-Modified".to_owned()),
                seen: Ok(None),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn listing(mut self, version: &str, time: &str) -> Self {
            self.full = Ok(Some(FullDocument {
                times: [(version.to_owned(), at(time))].into_iter().collect(),
                metadata: Err("not read".to_owned()),
            }));
            self
        }

        fn asked(&self) -> Vec<&'static str> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Sources for Fake {
        fn full(&self) -> BoxFuture<'_, Result<Option<FullDocument>, String>> {
            self.asked.lock().unwrap().push("full");
            let full = self.full.clone();
            Box::pin(async move { full })
        }

        fn last_modified<'a>(
            &'a self,
            _: &'a str,
        ) -> BoxFuture<'a, Result<jiff::Timestamp, String>> {
            self.asked.lock().unwrap().push("host");
            let host = self.host.clone();
            Box::pin(async move { host })
        }

        fn first_seen<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> BoxFuture<'a, Result<Option<jiff::Timestamp>, String>> {
            self.asked.lock().unwrap().push("seen");
            let seen = self.seen.clone();
            Box::pin(async move { seen })
        }
    }

    const TARBALL: &str = "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz";

    /// A file host answering every HEAD with a `Last-Modified` of 2026-09-17.
    async fn dated_host() -> String {
        let router = axum::Router::new().route(
            "/{file}",
            axum::routing::get(|| async {
                (
                    [(
                        axum::http::header::LAST_MODIFIED,
                        "Thu, 17 Sep 2026 00:00:00 GMT",
                    )],
                    "x",
                )
            }),
        );
        crate::proxy::testing::serve(router).await
    }
    const PURL: &str = "pkg:npm/widget@1.0.0";

    async fn dated(record: &PackageRecord, sources: &Fake, cooldown: bool, every: bool) -> Found {
        date(
            record,
            PURL,
            RecordDates::of(record),
            sources,
            Reading { cooldown, every },
        )
        .await
    }

    /// Each source is read only until one answers, and the first that answers is used.
    #[tokio::test]
    async fn the_first_source_that_answers_dates_the_file() {
        let record = widget(TARBALL, Some("2026-01-01T00:00:00Z"));
        let fake = Fake::new();
        let found = dated(&record, &fake, true, false).await;
        assert_eq!(fake.asked(), Vec::<&str>::new());
        assert_eq!(found.dating.used, Some(0));
        assert_eq!(found.times, None);

        let undated = widget(TARBALL, None);
        let fake = Fake::new().listing("1.0.0", "2026-02-01T00:00:00Z");
        let found = dated(&undated, &fake, true, false).await;
        assert_eq!(fake.asked(), ["full"]);
        assert_eq!(
            found.dating.dated(),
            Some((&Source::Document, at("2026-02-01T00:00:00Z")))
        );

        let fake = Fake {
            host: Ok(at("2026-03-01T00:00:00Z")),
            ..Fake::new().listing("0.9.0", "2025-01-01T00:00:00Z")
        };
        let found = dated(&undated, &fake, true, false).await;
        assert_eq!(fake.asked(), ["full", "host"]);
        assert_eq!(found.dating.used, Some(2));
        let times = found.times.expect("times");
        assert_eq!(times["1.0.0"], at("2026-03-01T00:00:00Z"));
        assert_eq!(times["0.9.0"], at("2025-01-01T00:00:00Z"));

        let fake = Fake {
            seen: Ok(Some(at("2026-04-01T00:00:00Z"))),
            ..Fake::new()
        };
        let found = dated(&undated, &fake, true, false).await;
        assert_eq!(fake.asked(), ["full", "host", "seen"]);
        assert_eq!(
            found.dating.dated(),
            Some((&Source::FirstSighting, at("2026-04-01T00:00:00Z")))
        );
        assert_eq!(
            found.times.expect("times")["1.0.0"],
            at("2026-04-01T00:00:00Z")
        );

        let fake = Fake::new();
        let found = dated(&undated, &fake, true, false).await;
        assert_eq!(found.dating.used, None);
        assert_eq!(found.dating.reads.len(), 4);
        assert_eq!(found.times, None);
    }

    /// With no cooldown the file host and the first sighting are not read, and a full
    /// document that fails is kept as why.
    #[tokio::test]
    async fn without_a_cooldown_only_the_documents_are_read() {
        let undated = widget(TARBALL, None);
        let fake = Fake {
            full: Err("metadata could not be fetched".to_owned()),
            ..Fake::new()
        };
        let found = dated(&undated, &fake, false, true).await;
        assert_eq!(fake.asked(), ["full"]);
        assert_eq!(
            found.unread.as_deref(),
            Some("metadata could not be fetched")
        );
        assert_eq!(
            found.dating.reads[1].said,
            Said::Nothing("not read: metadata could not be fetched".to_owned())
        );

        let mut fileless = undated.clone();
        fileless.artifacts.clear();
        let fake = Fake::new();
        let found = dated(&fileless, &fake, true, true).await;
        assert_eq!(fake.asked(), ["full"]);
        assert_eq!(found.dating.file, None);
    }

    /// Reading every source reads past the one used, but asks the file host only when
    /// nothing before it answered.
    #[tokio::test]
    async fn every_source_is_read_but_the_file_host_only_when_needed() {
        let record = widget(TARBALL, Some("2026-01-01T00:00:00Z"));
        let fake = Fake {
            seen: Ok(Some(at("2026-04-01T00:00:00Z"))),
            ..Fake::new().listing("1.0.0", "2026-02-01T00:00:00Z")
        };
        let found = dated(&record, &fake, true, true).await;
        assert_eq!(fake.asked(), ["full", "seen"]);
        assert_eq!(found.dating.used, Some(0));
        assert_eq!(
            found.dating.reads[2],
            Read::nothing(Source::FileHost, "not asked: an earlier source dates it")
        );
        assert_eq!(
            found.dating.reads[3],
            Read::at(Source::FirstSighting, at("2026-04-01T00:00:00Z"))
        );
        assert_eq!(
            found.times.expect("times")["1.0.0"],
            at("2026-02-01T00:00:00Z")
        );
        assert_eq!(
            found.dating.lines("  "),
            "  * the metadata's publish time    2026-01-01T00:00:00Z\n\
             \x20   the full document's time       2026-02-01T00:00:00Z\n\
             \x20   the file host's Last-Modified  not asked: an earlier source dates it\n\
             \x20   the file's first sighting      2026-04-01T00:00:00Z\n"
        );
        assert_eq!(
            RecordDates::of(&widget(TARBALL, None)),
            RecordDates {
                reads: vec![Read::nothing(
                    Source::Record("the metadata's publish time".to_owned()),
                    "the metadata carries none"
                )],
                used: None,
            }
        );
        assert_eq!(RecordDates::default().time(), None);
    }

    /// A HEAD's `Last-Modified`, and each way there is none.
    #[tokio::test]
    async fn the_file_host_s_last_modified_and_each_way_it_has_none() {
        use crate::util::test_support::{Answer, scripted};
        let service = crate::service::Service::new(
            crate::proxy::UPSTREAM,
            &crate::service::Connection::default(),
        );
        let dated = dated_host().await;
        assert_eq!(
            last_modified(&service, &format!("{dated}/x.tgz")).await,
            Ok(at("2026-09-17T00:00:00Z"))
        );
        let missing = scripted(vec![Answer::Status(404)]).await;
        assert_eq!(
            last_modified(&service, &format!("http://{missing}/x.tgz")).await,
            Err("the file host answered 404 to a HEAD".to_owned())
        );
        let undated = scripted(vec![Answer::Chunked(b"x".to_vec())]).await;
        assert_eq!(
            last_modified(&service, &format!("http://{undated}/x.tgz")).await,
            Err("the file host sent no Last-Modified".to_owned())
        );
        let closed = crate::util::test_support::closing_server().await;
        let error = last_modified(&service, &format!("http://{closed}/x.tgz"))
            .await
            .unwrap_err();
        assert!(
            error.starts_with("the file host could not be asked"),
            "{error}"
        );
    }

    /// A reader asks no file host the proxy does not serve, reads first sightings without
    /// recording one, and says when it has none to read.
    #[tokio::test]
    async fn a_reader_asks_only_what_the_proxy_would_and_records_nothing() {
        use crate::analysis::store::{Analyses, InProcess};
        let origin = dated_host().await;
        let store = std::sync::Arc::new(InProcess::new(4));
        let clients = crate::ecosystem::Clients::new(
            crate::service::Connection::default(),
            &crate::ecosystem::Upstreams::defaults(),
            1 << 20,
        );
        let reader = testing::reader(
            clients.clone(),
            std::slice::from_ref(&origin),
            Some(store.clone()),
        );
        let key = crate::identity::PackageKey::from_registry_name(
            crate::identity::Ecosystem::Npm,
            "widget",
        )
        .unwrap();
        let asking = Asking {
            reader: &reader,
            at: crate::ecosystem::Repository::of(crate::identity::Ecosystem::Npm),
            key: &key,
        };
        assert_eq!(
            asking.last_modified(&format!("{origin}/x.tgz")).await,
            Ok(at("2026-09-17T00:00:00Z"))
        );
        assert_eq!(
            asking.last_modified("https://elsewhere.example/x.tgz").await,
            Err("not asked: the file is on https://elsewhere.example, which the proxy does not serve".to_owned())
        );
        assert_eq!(asking.first_seen(PURL, "widget-1.0.0.tgz").await, Ok(None));
        let first = store.first_seen(PURL, "widget-1.0.0.tgz").await.unwrap();
        assert_eq!(
            asking.first_seen(PURL, "widget-1.0.0.tgz").await,
            Ok(Some(first))
        );

        let broken = testing::reader(
            clients.clone(),
            &[],
            Some(std::sync::Arc::new(crate::analysis::store::tests::Broken)),
        );
        let asking = Asking {
            reader: &broken,
            ..asking
        };
        let error = asking
            .first_seen(PURL, "widget-1.0.0.tgz")
            .await
            .unwrap_err();
        assert!(error.starts_with("not read: "), "{error}");
        let none = testing::reader(clients, &[], None);
        let asking = Asking {
            reader: &none,
            ..asking
        };
        assert_eq!(
            asking.first_seen(PURL, "widget-1.0.0.tgz").await,
            Err(format!("not read: {} is not set", crate::env::DATABASE_URL))
        );
    }

    /// The environment's reader, and each setting that stops one being built.
    #[tokio::test]
    async fn a_reader_is_built_from_the_environment() {
        use crate::env::testing::{empty, with};
        assert!(Reader::from_env(&empty()).await.is_ok());
        for (var, value) in [
            (crate::env::CA_BUNDLE, "/nonexistent/byrle-ca.pem"),
            (crate::env::DATABASE_URL, "not a url"),
            (crate::env::ARTIFACT_ORIGINS, "not an origin"),
            (crate::env::MAX_METADATA_BYTES, "lots"),
            (crate::env::UPSTREAM_NPM, "not a url"),
        ] {
            let Err(error) = Reader::from_env(&with(&[(var, value)])).await else {
                panic!("{} {value} builds a reader", var.name);
            };
            assert!(!error.is_empty(), "{}", var.name);
        }
        for var in [
            crate::env::ARTIFACT_ORIGINS,
            crate::env::ALLOW_DIRECT_ORIGINS,
        ] {
            let unreadable = crate::env::testing::with_unreadable(&[], var);
            assert!(Reader::from_env(&unreadable).await.is_err(), "{}", var.name);
        }
    }
}
