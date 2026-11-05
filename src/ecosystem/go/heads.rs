//! When a Go module version became public, read from where its record falls in Go's checksum
//! database. Its log only appends, so a tree of `size` records seen at a time held every
//! record numbered below `size` by then. A publisher cannot set that time, as it can a
//! commit's. See docs/engineering_decisions/0125-go-versions-dated-by-the-checksum-database.md.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jiff::{SignedDuration, Timestamp};
use tracing::warn;

use super::sumdb::{self, Answer};

/// The headers the Go module index is sent.
pub const SERVICE: crate::service::Declared = crate::service::Declared {
    name: "the Go module index",
    headers: &[],
};

/// The feed of every module version proxy.golang.org fetched, with when it first did.
pub const INDEX: &str = "https://index.golang.org";

/// How long after its index `Timestamp` a record is taken to be in a signed tree (120 s seen).
pub const MARGIN: SignedDuration = SignedDuration::from_hours(1);

/// Rows this close around a record are not split: a version is dated up to this late.
pub const GRAIN: SignedDuration = SignedDuration::from_hours(1);

/// A tree seen this soon after the newest row replaces it.
const THIN: SignedDuration = SignedDuration::from_mins(1);

/// Rows kept. Past it the oldest is dropped, and read again when a seed needs it.
pub const MAX_ROWS: usize = 65_536;

/// Splits for one record, at most: 2^20 hours is past the longest cooldown.
const MAX_SPLITS: usize = 20;

/// After a row fails to be read, none is asked for this long: each would wait its timeout.
const REST: Duration = Duration::from_secs(300);

/// The index's answer is read this far, at most, for its first line.
const MAX_ENTRY_BYTES: usize = 64 << 10;

/// Every record below a size, by size, was in a signed tree by its time.
type Rows = BTreeMap<u64, Timestamp>;

/// The checksum database's trees as this process saw them, and index entries as trees.
pub struct Heads {
    http: crate::service::Service,
    index: String,
    /// Times rise as sizes do: the first row past a record is the earliest that holds it.
    rows: Mutex<Rows>,
    /// Held while a seed is read, so concurrent requests read one.
    seeding: tokio::sync::Mutex<()>,
    /// When a row last failed to be read.
    failed: Mutex<Option<Instant>>,
}

/// One line of the index.
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    path: String,
    version: String,
    timestamp: String,
}

impl Heads {
    /// Rows read from the index at `index`, such as [`INDEX`]. A trailing slash is trimmed.
    pub fn new(connection: crate::service::Connection, index: &str) -> Self {
        Self {
            http: crate::service::Service::new(SERVICE, &connection),
            index: index.trim_end_matches('/').to_owned(),
            rows: Mutex::new(Rows::new()),
            seeding: tokio::sync::Mutex::new(()),
            failed: Mutex::new(None),
        }
    }

    /// Note a tree of `size` records proved at `at`. A larger one within a minute of the
    /// newest row replaces it.
    pub fn saw(&self, size: u64, at: Timestamp) {
        let mut rows = self.rows.lock().expect("rows lock");
        if let Some((&newest, &seen)) = rows.last_key_value()
            && newest < size
            && at.duration_since(seen) < THIN
        {
            rows.remove(&newest);
        }
        insert(&mut rows, size, at);
    }

    /// When `record` was public, given the `time` its `.info` claims: the earliest row that
    /// holds it, split from the index until the rows around it are [`GRAIN`] apart. A record
    /// below every row is dated by the earlier of `time` and the oldest row. With `before`,
    /// a row at or before it is read first, so only a record older than `before` is.
    pub async fn dated(
        &self,
        sumdb: &sumdb::Client,
        record: u64,
        time: Option<Timestamp>,
        before: Option<Timestamp>,
    ) -> Option<Timestamp> {
        if let Some(before) = before {
            self.seed(sumdb, before).await;
        }
        let mut last = None;
        let mut splits = 0;
        loop {
            let (below, above) = self.around(record);
            let Some(held) = above else {
                return time;
            };
            let Some(below) = below else {
                return Some(time.map_or(held, |time| time.min(held)));
            };
            let span = held.duration_since(below);
            if span <= GRAIN || last == Some((below, held)) || splits == MAX_SPLITS {
                return Some(held);
            }
            last = Some((below, held));
            splits += 1;
            if self.resting() {
                return Some(held);
            }
            if let Err(e) = self.point(sumdb, below + span / 2).await {
                warn!(error.message = %e, "a go version is dated by the checksum tree after it: the index could not be read between");
                return Some(held);
            }
        }
    }

    /// Read a row from the index [`MARGIN`] before `before`, unless one at or before `before`
    /// is kept, or a read failed within [`REST`]. A failed read is logged: a record below every
    /// row is then dated by its `.info` `Time`, the earlier of it and the oldest row.
    async fn seed(&self, sumdb: &sumdb::Client, before: Timestamp) {
        let seeded = || {
            self.rows
                .lock()
                .expect("rows lock")
                .first_key_value()
                .is_some_and(|(_, at)| *at <= before)
        };
        if seeded() {
            return;
        }
        let _one = self.seeding.lock().await;
        if seeded() || self.resting() {
            return;
        }
        if let Err(e) = self.point(sumdb, before - MARGIN).await {
            warn!(error.message = %e, "go versions older than every checksum tree seen are dated by their .info Time: the index could not be read");
        }
    }

    /// [`Heads::read_point`], noting when it fails.
    async fn point(&self, sumdb: &sumdb::Client, at: Timestamp) -> Result<(), String> {
        let read = self.read_point(sumdb, at).await;
        *self.failed.lock().expect("failed lock") = read.as_ref().err().map(|_| Instant::now());
        read
    }

    /// Whether a row failed to be read within [`REST`].
    fn resting(&self) -> bool {
        self.failed
            .lock()
            .expect("failed lock")
            .is_some_and(|at| at.elapsed() < REST)
    }

    /// Add the row the index's first entry from [`MARGIN`] before `at` makes: its record,
    /// held [`MARGIN`] after its `Timestamp`, so no earlier than `at`. Errors when the index
    /// or the database does not answer, or the database has no record of the entry.
    async fn read_point(&self, sumdb: &sumdb::Client, at: Timestamp) -> Result<(), String> {
        let since = (at - MARGIN).strftime("%Y-%m-%dT%H:%M:%SZ");
        let url = format!("{}/index?since={since}&limit=1", self.index);
        let line = self.first_line(&url).await?;
        let entry: Entry = serde_json::from_str(&line).map_err(|e| format!("{url}: {e}"))?;
        let published: Timestamp = entry
            .timestamp
            .parse()
            .map_err(|e| format!("{url}: Timestamp `{}`: {e}", entry.timestamp))?;
        let Answer::Known { record, tree, .. } = sumdb.lookup(&entry.path, &entry.version).await?
        else {
            return Err(format!(
                "{url}: the checksum database has no record of {}@{}",
                entry.path, entry.version
            ));
        };
        self.saw(tree, Timestamp::now());
        insert(
            &mut self.rows.lock().expect("rows lock"),
            record,
            published + MARGIN,
        );
        Ok(())
    }

    /// The first line `url` answers, read no further than [`MAX_ENTRY_BYTES`]. Errors when it
    /// does not answer 2xx, or answers no line.
    async fn first_line(&self, url: &str) -> Result<String, String> {
        let mut response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("{url} answered {}", response.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| format!("{url}: {e}"))? {
            body.extend_from_slice(&chunk);
            if body.contains(&b'\n') || body.len() >= MAX_ENTRY_BYTES {
                break;
            }
        }
        let line = body.split(|b| *b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line).trim().to_owned();
        if line.is_empty() {
            return Err(format!("{url}: no entry"));
        }
        Ok(line)
    }

    /// The times of the last row at or below `record`, and of the first above it.
    fn around(&self, record: u64) -> (Option<Timestamp>, Option<Timestamp>) {
        let rows = self.rows.lock().expect("rows lock");
        let below = rows.range(..=record).next_back().map(|(_, at)| *at);
        let above = rows
            .range((Bound::Excluded(record), Bound::Unbounded))
            .next()
            .map(|(_, at)| *at);
        (below, above)
    }
}

/// Add the row `size` at `at` to `rows`, unless a row as large is no later, and drop the rows
/// it holds sooner. Past [`MAX_ROWS`], the oldest is dropped.
fn insert(rows: &mut Rows, size: u64, at: Timestamp) {
    if rows
        .range(size..)
        .next()
        .is_some_and(|(_, seen)| *seen <= at)
    {
        return;
    }
    let later: Vec<u64> = rows
        .range(..=size)
        .rev()
        .take_while(|(_, seen)| **seen >= at)
        .map(|(size, _)| *size)
        .collect();
    for size in later {
        rows.remove(&size);
    }
    rows.insert(size, at);
    if rows.len() > MAX_ROWS {
        rows.pop_first();
    }
}

/// An index and a checksum database on loopback, with a record for each index entry.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use super::*;
    use crate::ecosystem::go::sumdb::testing::{Database, client};
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Each entry's `Timestamp`, by record, and whether the index answers 500.
    pub(crate) struct Index {
        pub(crate) published: Vec<Timestamp>,
        pub(crate) broken: Mutex<bool>,
        pub(crate) asked: Mutex<usize>,
    }

    async fn index(
        State(index): State<Arc<Index>>,
        Query(query): Query<HashMap<String, String>>,
    ) -> Result<String, StatusCode> {
        *index.asked.lock().unwrap() += 1;
        if *index.broken.lock().unwrap() {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let since: Timestamp = query["since"].parse().unwrap();
        Ok(index
            .published
            .iter()
            .position(|at| *at >= since)
            .map(|i| {
                format!(
                    "{{\"Path\":\"example.com/m\",\"Version\":\"v{i}\",\"Timestamp\":\"{}\"}}\n",
                    index.published[i]
                )
            })
            .unwrap_or_default())
    }

    /// Record `i` of `example.com/m`.
    pub(crate) fn record(i: usize) -> String {
        format!("example.com/m v{i} h1:zip{i}=\nexample.com/m v{i}/go.mod h1:mod{i}=\n")
    }

    /// A record for each of `published`, which the index answers with, and a client of each.
    pub(crate) async fn serve(
        published: Vec<Timestamp>,
    ) -> (Arc<Index>, String, Arc<Database>, sumdb::Client) {
        let db = Database::new((0..published.len()).map(record).collect());
        let sumdb = client(db.clone()).await;
        let index = Arc::new(Index {
            published,
            broken: Mutex::new(false),
            asked: Mutex::new(0),
        });
        let router = axum::Router::new()
            .route("/index", axum::routing::get(self::index))
            .with_state(index.clone());
        let base = crate::proxy::testing::serve(router).await;
        (index, base, db, sumdb)
    }

    /// `n` records, one every 10 minutes, the last one now.
    pub(crate) fn every_ten_minutes(n: usize) -> Vec<Timestamp> {
        let now = Timestamp::now();
        (0..n)
            .map(|i| now - SignedDuration::from_mins(10 * (n - 1 - i) as i64))
            .collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::testing::{every_ten_minutes, serve};
    use super::*;
    use crate::util::test_support::{capture, text};

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn rows(heads: &Heads) -> Vec<(u64, Timestamp)> {
        heads
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|(size, at)| (*size, *at))
            .collect()
    }

    /// A row a larger, earlier one holds is not added, and a row drops those it holds sooner.
    #[test]
    fn rows_keep_times_rising_with_sizes() {
        let mut rows = Rows::new();
        insert(&mut rows, 100, at("2026-10-29T10:00:00Z"));
        insert(&mut rows, 200, at("2026-10-29T12:00:00Z"));
        insert(&mut rows, 300, at("2026-10-29T14:00:00Z"));
        insert(&mut rows, 150, at("2026-10-29T13:00:00Z"));
        insert(&mut rows, 200, at("2026-10-29T12:00:00Z"));
        assert_eq!(rows.len(), 3, "200 by noon holds 150 by 13:00");
        insert(&mut rows, 250, at("2026-10-29T11:00:00Z"));
        assert_eq!(
            rows.into_iter().collect::<Vec<_>>(),
            [
                (100, at("2026-10-29T10:00:00Z")),
                (250, at("2026-10-29T11:00:00Z")),
                (300, at("2026-10-29T14:00:00Z")),
            ],
            "250 by 11:00 holds 200 by noon"
        );
    }

    /// Past [`MAX_ROWS`] the oldest row is dropped.
    #[test]
    fn the_oldest_row_goes_first() {
        let mut rows = Rows::new();
        let start = at("2026-01-01T00:00:00Z");
        for i in 0..=MAX_ROWS as u64 {
            insert(&mut rows, i, start + SignedDuration::from_secs(i as i64));
        }
        assert_eq!(rows.len(), MAX_ROWS);
        assert_eq!(rows.first_key_value().map(|(size, _)| *size), Some(1));
    }

    /// A tree seen within a minute of the newest row replaces it; one later is added.
    #[test]
    fn trees_seen_close_together_are_one_row() {
        let heads = Heads::new(crate::service::Connection::default(), INDEX);
        heads.saw(100, at("2026-10-29T10:00:00Z"));
        heads.saw(110, at("2026-10-29T10:00:30Z"));
        heads.saw(120, at("2026-10-29T10:02:00Z"));
        heads.saw(90, at("2026-10-29T10:02:10Z"));
        heads.saw(120, at("2026-10-29T10:02:20Z"));
        assert_eq!(
            rows(&heads),
            [
                (110, at("2026-10-29T10:00:30Z")),
                (120, at("2026-10-29T10:02:00Z")),
            ]
        );
    }

    /// Under a 7-day cooldown, record 500, older than the seed, keeps its claimed time, and
    /// record 1,000, 6.9 days old, is dated by split rows up to two hours after it.
    #[tokio::test]
    async fn a_record_is_dated_by_the_rows_around_it() {
        let published = every_ten_minutes(2000);
        let (index, base, db, sumdb) = serve(published.clone()).await;
        let heads = Heads::new(crate::service::Connection::default(), &format!("{base}/"));
        heads.saw(2000, Timestamp::now());
        let before = Timestamp::now() - SignedDuration::from_hours(7 * 24);
        let claimed = Some(at("2020-01-01T00:00:00Z"));

        assert_eq!(
            heads.dated(&sumdb, 500, claimed, Some(before)).await,
            claimed
        );
        let seed = rows(&heads)[0];
        assert!(seed.1 <= before && seed.1 > before - MARGIN * 2, "{seed:?}");
        assert_eq!(*index.asked.lock().unwrap(), 1);
        assert_eq!(
            heads.dated(&sumdb, 500, None, Some(before)).await,
            Some(seed.1),
            "undated, the seed's time"
        );
        assert_eq!(*index.asked.lock().unwrap(), 1, "the seed is kept");

        let dated = heads
            .dated(&sumdb, 1000, claimed, Some(before))
            .await
            .unwrap();
        let late = dated.duration_since(published[1000]);
        assert!(
            late > SignedDuration::ZERO && late <= GRAIN + MARGIN,
            "{late:?}"
        );
        assert!(dated > before, "refused by the cooldown");
        assert!(*db.size.lock().unwrap() == 2000);
    }

    /// An index answering 500: a record below every row keeps its claimed time, nothing is
    /// asked for [`REST`], and a failed split dates a record by the row after it. Logged.
    #[tokio::test]
    async fn an_index_that_does_not_answer_dates_by_what_is_kept() {
        let (index, base, _db, sumdb) = serve(every_ten_minutes(200)).await;
        *index.broken.lock().unwrap() = true;
        let now = Timestamp::now();
        let claimed = Some(at("2020-01-01T00:00:00Z"));
        let before = now - SignedDuration::from_hours(24);
        let (guard, log) = capture(tracing::Level::WARN);
        let heads = Heads::new(crate::service::Connection::default(), &base);
        heads.saw(200, now);
        assert_eq!(
            heads.dated(&sumdb, 10, claimed, Some(before)).await,
            claimed
        );
        heads.saw(100, now - SignedDuration::from_hours(30));
        assert_eq!(
            heads.dated(&sumdb, 150, claimed, Some(before)).await,
            Some(now)
        );
        assert_eq!(*index.asked.lock().unwrap(), 1, "resting");

        let heads = Heads::new(crate::service::Connection::default(), &base);
        heads.saw(100, now - SignedDuration::from_hours(30));
        heads.saw(200, now);
        assert_eq!(heads.dated(&sumdb, 150, claimed, None).await, Some(now));
        drop(guard);
        let log = text(&log);
        assert_eq!(
            log.matches("dated by their .info Time: the index could not be read")
                .count(),
            1,
            "{log}"
        );
        assert!(
            log.contains(
                "dated by the checksum tree after it: the index could not be read between"
            ),
            "{log}"
        );
    }

    /// An index that takes connections and never answers: one read waits its timeout, and
    /// the requests behind it date at once.
    #[tokio::test]
    async fn an_index_that_hangs_is_waited_on_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::Relaxed);
                held.push(socket);
            }
        });
        let (_index, _base, _db, sumdb) = serve(every_ten_minutes(20)).await;
        let http = crate::service::Connection::timing_out(std::time::Duration::from_millis(100));
        let heads = Heads::new(http, &format!("http://{addr}"));
        let now = Timestamp::now();
        heads.saw(20, now);
        let before = Some(now - SignedDuration::from_hours(24));
        let claimed = Some(at("2020-01-01T00:00:00Z"));
        let started = Instant::now();
        let dated =
            futures_util::future::join_all((0..4).map(|_| heads.dated(&sumdb, 5, claimed, before)))
                .await;
        assert_eq!(dated, vec![claimed; 4]);
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    /// With no row above a record, its claimed time. A split whose entry adds no row, as
    /// a larger row holds it sooner, stops at the row after the record.
    #[tokio::test]
    async fn a_record_past_every_row_or_a_split_that_adds_none() {
        let now = Timestamp::now();
        let days = |n: i64| SignedDuration::from_hours(24 * n);
        let mut published = vec![now - days(30); 20];
        published[5] = now - days(6) - SignedDuration::from_mins(30);
        let (index, base, _db, sumdb) = serve(published).await;
        let heads = Heads::new(crate::service::Connection::default(), &base);
        let claimed = Some(at("2020-01-01T00:00:00Z"));
        assert_eq!(heads.dated(&sumdb, 15, claimed, None).await, claimed);
        heads.saw(10, now - days(10));
        heads.saw(20, now - days(2));
        assert_eq!(
            heads.dated(&sumdb, 15, claimed, None).await,
            Some(now - days(2))
        );
        assert_eq!(
            *index.asked.lock().unwrap(),
            1,
            "one split, which added no row"
        );
        assert_eq!(rows(&heads).len(), 2);
    }

    /// An entry the database has no record of, or that does not read, is an error, and so
    /// is an index that does not answer, or answers no entry.
    #[tokio::test]
    async fn an_entry_that_does_not_make_a_row_is_an_error() {
        let (_index, base, db, sumdb) = serve(every_ten_minutes(20)).await;
        *db.size.lock().unwrap() = 10;
        let heads = Heads::new(crate::service::Connection::default(), &base);
        let error = heads.point(&sumdb, Timestamp::now()).await.unwrap_err();
        assert!(error.contains("no record of example.com/m@v1"), "{error}");

        for body in [
            "not json\n",
            "{\"Path\":\"a\",\"Version\":\"v1\",\"Timestamp\":\"then\"}\n",
        ] {
            let base = crate::proxy::testing::serve(
                axum::Router::new()
                    .route("/index", axum::routing::get(move || async move { body })),
            )
            .await;
            let heads = Heads::new(crate::service::Connection::default(), &base);
            assert!(
                heads.point(&sumdb, Timestamp::now()).await.is_err(),
                "{body}"
            );
        }
        let closed = crate::util::test_support::closing_server().await;
        let heads = Heads::new(
            crate::service::Connection::default(),
            &format!("http://{closed}"),
        );
        assert!(heads.point(&sumdb, Timestamp::now()).await.is_err());
        let heads = Heads::new(crate::service::Connection::default(), &base);
        let error = heads
            .point(&sumdb, Timestamp::now() + SignedDuration::from_hours(2))
            .await
            .unwrap_err();
        assert!(error.ends_with("no entry"), "{error}");
    }

    /// Requests that need a seed at once read one: the second waits, then finds it kept.
    #[tokio::test]
    async fn a_seed_is_read_once_for_requests_at_once() {
        let (index, base, _db, sumdb) = serve(every_ten_minutes(2000)).await;
        let heads = Heads::new(crate::service::Connection::default(), &base);
        let before = Timestamp::now() - SignedDuration::from_hours(24);
        tokio::join!(heads.seed(&sumdb, before), heads.seed(&sumdb, before));
        assert_eq!(*index.asked.lock().unwrap(), 1);
    }

    /// Rows 2^21 hours apart, and an index whose entry at any time is a record below the
    /// one dated: each split halves the gap, and after [`MAX_SPLITS`] it is still 2 hours.
    #[tokio::test]
    async fn splitting_stops_after_so_many() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let db = crate::ecosystem::go::sumdb::testing::Database::new(
            (0..100).map(testing::record).collect(),
        );
        let sumdb = crate::ecosystem::go::sumdb::testing::client(db).await;
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        let router = axum::Router::new().route(
            "/index",
            axum::routing::get(
                move |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let i = counted.fetch_add(1, Ordering::Relaxed) + 1;
                    async move {
                        format!(
                            "{{\"Path\":\"example.com/m\",\"Version\":\"v{i}\",\"Timestamp\":\"{}\"}}\n",
                            query["since"]
                        )
                    }
                },
            ),
        );
        let base = crate::proxy::testing::serve(router).await;
        let heads = Heads::new(crate::service::Connection::default(), &base);
        let now = Timestamp::from_second(Timestamp::now().as_second()).unwrap();
        heads.saw(0, now - SignedDuration::from_hours(1 << 21));
        heads.saw(100, now);
        assert_eq!(heads.dated(&sumdb, 50, None, None).await, Some(now));
        assert_eq!(asked.load(Ordering::Relaxed), MAX_SPLITS);
        let (_, below) = rows(&heads)[MAX_SPLITS];
        assert_eq!(now.duration_since(below), SignedDuration::from_hours(2));
    }

    /// An index line past [`MAX_ENTRY_BYTES`] or a body cut short is not read whole, and a
    /// database that does not answer fails the row.
    #[tokio::test]
    async fn a_long_or_cut_answer_or_a_silent_database_is_an_error() {
        let (_index, base, _db, _sumdb) = serve(every_ten_minutes(20)).await;
        let closed = crate::util::test_support::closing_server().await;
        let silent = sumdb::Client::new(
            crate::service::Connection::default(),
            &format!("http://{closed}"),
            crate::ecosystem::go::note::SUM_GOLANG_ORG,
        )
        .unwrap();
        let heads = Heads::new(crate::service::Connection::default(), &base);
        assert!(heads.point(&silent, Timestamp::now()).await.is_err());

        let (_index, _base, _db, sumdb) = serve(every_ten_minutes(20)).await;
        let long = "x".repeat(MAX_ENTRY_BYTES * 2);
        let base = crate::proxy::testing::serve(
            axum::Router::new().route("/index", axum::routing::get(move || async move { long })),
        )
        .await;
        let error = Heads::new(crate::service::Connection::default(), &base)
            .point(&sumdb, Timestamp::now())
            .await
            .unwrap_err();
        assert!(error.contains("expected"), "{error}");
        let addr = crate::util::test_support::scripted(vec![
            crate::util::test_support::Answer::cut_short(),
        ])
        .await;
        let heads = Heads::new(
            crate::service::Connection::default(),
            &format!("http://{addr}"),
        );
        assert!(heads.point(&sumdb, Timestamp::now()).await.is_err());
    }

    /// Against index.golang.org and sum.golang.org: a seed a week back holds records only
    /// from before it. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "asks index.golang.org and sum.golang.org"]
    async fn index_golang_org_seeds_a_row_a_week_back() {
        let sumdb = sumdb::Client::new(
            crate::service::Connection::default(),
            sumdb::DEFAULT,
            crate::ecosystem::go::note::SUM_GOLANG_ORG,
        )
        .unwrap();
        let heads = Heads::new(crate::service::Connection::default(), INDEX);
        let before = Timestamp::now() - SignedDuration::from_hours(7 * 24);
        heads.seed(&sumdb, before).await;
        let (size, seen) = rows(&heads)[0];
        assert!(seen <= before, "{seen}");
        let Ok(Answer::Known { record, .. }) = sumdb.lookup("golang.org/x/text", "v0.20.0").await
        else {
            panic!("known");
        };
        assert!(record < size, "2024's record is below the seed of {size}");
    }
}
