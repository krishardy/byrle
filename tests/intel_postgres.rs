//! The repository trait against a real Postgres.
//!
//! Not unit tests. They need a database, which `make test-integration` starts in a
//! container and points at with `waharoa::env::TEST_DATABASE_URL`. Without that variable every
//! test here is skipped, so `cargo test` stays runnable with nothing installed.
//!
//! These exist because SQLite was dropped and Postgres is the only backend. A suite left
//! to itself covers whatever needs no service, which would have been the backend nobody
//! deploys. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

#![cfg(not(coverage))]

use sqlx::PgPool;
use waharoa::intel::load::{self, Fetch};
use waharoa::intel::osv::{self, Parsed, Rows};
use waharoa::intel::postgres::{Loaded, PgIntel};
use waharoa::intel::refresh::StreamDigest;
use waharoa::intel::store::{Intel, IntelError, LoadedSnapshot};

/// The database to test against, or nothing, in which case the test is skipped.
fn url() -> Option<String> {
    waharoa::env::process()
        .test_database_url()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A schema of its own per test, so tests cannot see each other's rows.
///
/// A schema name is an identifier and cannot be a bind parameter, so it is formatted into
/// the SQL. That is safe because `name` is a `'static` literal from
/// `skip_without_database!` and the assert below admits only `[a-z0-9_]`.
async fn fresh(name: &'static str) -> Option<PgIntel> {
    assert!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "schema name {name:?} must be [a-z0-9_]"
    );
    let pool = PgPool::connect(&url()?).await.expect("should connect");
    sqlx::query(&format!("DROP SCHEMA IF EXISTS {name} CASCADE"))
        .execute(&pool)
        .await
        .expect("should drop");
    sqlx::query(&format!("CREATE SCHEMA {name}"))
        .execute(&pool)
        .await
        .expect("should create");
    sqlx::query(&format!("SET search_path TO {name}"))
        .execute(&pool)
        .await
        .expect("should set");

    let intel = PgIntel::new(connect(name).await?);
    intel.migrate().await.expect("migrations should apply");
    Some(intel)
}

/// A pool whose connection uses schema `name`, which `fresh` has created.
async fn connect(name: &'static str) -> Option<PgPool> {
    // One connection, so `search_path` holds for everything the test does.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let name = name.to_owned();
            Box::pin(async move {
                sqlx::query(&format!("SET search_path TO {name}"))
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url()?)
        .await
        .expect("should connect");
    Some(pool)
}

/// `raw_sql`, not `query`: a prepared statement takes one command, and these fixtures are
/// several. `'static` because sqlx 0.9 accepts unaudited SQL only as a literal, and every
/// fixture is one.
///
/// A store with no snapshot has loaded nothing and answers no lookup, so a snapshot older
/// than any a test names is recorded first.
async fn insert(intel: &PgIntel, sql: &'static str) {
    sqlx::raw_sql(
        "INSERT INTO intel_snapshot (digest, taken_at, streams) \
         VALUES ('fixture', '2000-01-01T00:00:00Z', '{}') ON CONFLICT (digest) DO NOTHING",
    )
    .execute(intel.pool())
    .await
    .expect("fixture snapshot should insert");
    sqlx::raw_sql(sql)
        .execute(intel.pool())
        .await
        .expect("fixture should insert");
}

macro_rules! skip_without_database {
    ($name:expr) => {
        match fresh($name).await {
            Some(intel) => intel,
            None => return,
        }
    };
}

#[tokio::test]
async fn the_migrations_apply_to_an_empty_database() {
    let intel = skip_without_database!("t_migrate");

    // Applying twice is what a restart does, and it must not fail.
    intel
        .migrate()
        .await
        .expect("re-running migrations is safe");
    assert_eq!(intel.snapshot().await.expect("should query"), None);
}

#[tokio::test]
async fn nothing_known_is_an_empty_answer_rather_than_an_error() {
    let intel = skip_without_database!("t_empty");

    assert!(
        intel
            .lookup("npm", "lodash", "4.17.21")
            .await
            .expect("a lookup with nothing to find still succeeds")
            .is_empty()
    );
}

#[tokio::test]
async fn an_advisory_against_one_version_is_found_for_that_version_only() {
    let intel = skip_without_database!("t_one_version");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source, cvss, cvss_source) \
         VALUES ('GHSA-x', 'ghsa', 9.8, 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'lodash', '4.17.20' FROM advisory WHERE publisher_id = 'GHSA-x'",
    )
    .await;

    let hit = intel
        .lookup("npm", "lodash", "4.17.20")
        .await
        .expect("query");
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].advisory_id, "GHSA-x");
    assert_eq!(hit[0].cvss, Some(9.8));
    assert!(!hit[0].malware);

    assert!(
        intel
            .lookup("npm", "lodash", "4.17.21")
            .await
            .expect("query")
            .is_empty(),
        "a different version must not match"
    );
}

/// A malware report is usually against the package rather than one version, which is what
/// a NULL version means.
#[tokio::test]
async fn a_null_version_matches_every_version_of_the_package() {
    let intel = skip_without_database!("t_null_version");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source, malware) VALUES ('MAL-1', 'ossf', TRUE); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'evil-pkg', NULL FROM advisory WHERE publisher_id = 'MAL-1'",
    )
    .await;

    for version in ["0.0.1", "1.0.0", "99.99.99"] {
        let hit = intel
            .lookup("npm", "evil-pkg", version)
            .await
            .expect("query");
        assert_eq!(hit.len(), 1, "{version}");
        assert!(hit[0].malware, "{version}");
    }
}

#[tokio::test]
async fn an_advisory_for_another_ecosystem_is_not_returned() {
    let intel = skip_without_database!("t_ecosystem");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('GHSA-y', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'pypi', 'lodash', '1.0.0' FROM advisory WHERE publisher_id = 'GHSA-y'",
    )
    .await;

    assert!(
        intel
            .lookup("npm", "lodash", "1.0.0")
            .await
            .expect("query")
            .is_empty()
    );
}

/// An advisory recorded against both the package and this exact version is one answer, not
/// two. The checks above count advisories.
#[tokio::test]
async fn an_advisory_matching_twice_is_returned_once() {
    let intel = skip_without_database!("t_dedupe");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('GHSA-z', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT a.id, 'npm', 'lodash', v.version \
         FROM advisory a, (VALUES (NULL), ('4.17.21')) v (version) \
         WHERE a.publisher_id = 'GHSA-z'",
    )
    .await;

    assert_eq!(
        intel
            .lookup("npm", "lodash", "4.17.21")
            .await
            .expect("query")
            .len(),
        1
    );
}

/// NULL cvss is "no stream scored it" and 0.0 is a real score. The column is nullable so
/// the two stay distinguishable.
#[tokio::test]
async fn an_unscored_advisory_is_null_rather_than_zero() {
    let intel = skip_without_database!("t_unscored");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('MAL-2', 'ossf'); \
         INSERT INTO advisory (publisher_id, source, cvss) VALUES ('GHSA-0', 'ghsa', 0.0); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'p', '1.0.0' FROM advisory WHERE publisher_id IN ('MAL-2', 'GHSA-0')",
    )
    .await;

    let hits = intel.lookup("npm", "p", "1.0.0").await.expect("query");
    let scored: Vec<Option<f64>> = hits.iter().map(|r| r.cvss).collect();
    assert!(scored.contains(&None), "{scored:?}");
    assert!(scored.contains(&Some(0.0)), "{scored:?}");
}

/// `insert` also records its `fixture` snapshot, dated 2000, so `older` has to be later than
/// that for this test to say anything.
#[tokio::test]
async fn the_newest_snapshot_is_the_one_reported() {
    let intel = skip_without_database!("t_snapshot");
    insert(
        &intel,
        r#"INSERT INTO intel_snapshot (digest, taken_at, streams) VALUES
         ('older', '2026-01-01T00:00:00Z', '{}'),
         ('newer', '2026-09-13T01:02:03.456Z',
          '{"osv-npm": {"sha256": "ab", "etag": "e1", "last_modified": null},
            "cisa-kev": {"sha256": "cd", "etag": null, "last_modified": "Sun, 13 Sep 2026 00:00:00 GMT"},
            "unhashed": {"etag": "e2"}}')"#,
    )
    .await;

    assert_eq!(
        intel.snapshot().await.expect("query"),
        Some(LoadedSnapshot {
            digest: "newer".to_owned(),
            taken_at: "2026-09-13T01:02:03Z".to_owned(),
            streams: vec![
                StreamDigest {
                    stream: "cisa-kev".to_owned(),
                    sha256: "cd".to_owned(),
                    etag: None,
                    last_modified: Some("Sun, 13 Sep 2026 00:00:00 GMT".to_owned()),
                },
                StreamDigest {
                    stream: "osv-npm".to_owned(),
                    sha256: "ab".to_owned(),
                    etag: Some("e1".to_owned()),
                    last_modified: None,
                },
            ],
        }),
        "sorted by stream, to the second in UTC, and a stream with no sha256 left out"
    );
}

/// A stored row names a package, so it can become a finding. It cannot become an
/// enrichment, which is what `src/intel.rs` enforces in the types.
#[tokio::test]
async fn a_row_becomes_a_finding_carrying_its_source_and_score() {
    let intel = skip_without_database!("t_finding");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source, cvss, cvss_source, exploited) \
         VALUES ('CVE-1', 'osv', 7.5, 'nvd', TRUE); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'q', '1.0.0' FROM advisory WHERE publisher_id = 'CVE-1'",
    )
    .await;

    let hit = &intel.lookup("npm", "q", "1.0.0").await.expect("query")[0];
    let finding = hit.finding();
    assert_eq!(finding.advisory_id, "CVE-1");
    assert_eq!(finding.source, "osv");
    assert!(finding.exploited(), "an exploited row carries it through");
    assert_eq!(hit.score().expect("a score").source, "nvd");
}

fn osv_fixture(id: &str) -> Rows {
    let path = format!(
        "{}/tests/fixtures/osv/{id}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    match osv::parse(&std::fs::read(path).expect("fixture is missing")).expect("fixture parses") {
        Parsed::Rows(rows) => rows,
        other => panic!("{id}: {other:?}"),
    }
}

/// `taken_at` differs per tag, because `snapshot()` reports the latest and equal times tie.
/// The tag is also the stream's name and sha256, so a test can tell fetches apart.
fn fetch(tag: &str) -> Fetch {
    let seconds = tag.bytes().map(u32::from).sum::<u32>() % 60;
    Fetch {
        taken_at: format!("2026-09-13T00:00:{seconds:02}Z"),
        streams: vec![StreamDigest {
            stream: tag.to_owned(),
            sha256: tag.to_owned(),
            etag: None,
            last_modified: None,
        }],
    }
}

/// The snapshot id of a store holding exactly these sources' rows.
fn id_of(sources: &[(&str, &[Rows])]) -> String {
    let digests: Vec<(&str, String)> = sources
        .iter()
        .map(|(source, rows)| (*source, load::encode(source, rows).digest))
        .collect();
    load::snapshot_id(digests.iter().map(|(s, d)| (*s, d.as_str())))
}

async fn snapshots(intel: &PgIntel) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM intel_snapshot")
        .fetch_one(intel.pool())
        .await
        .expect("query")
}

/// The package a fixture is against, and one version it lists if it lists any.
fn target(rows: &Rows) -> (String, Option<String>) {
    let first = rows.affected.first().expect("fixture has an affected row");
    (first.name.clone(), first.version.clone())
}

#[tokio::test]
async fn a_loaded_malware_record_is_found_for_every_version() {
    let intel = skip_without_database!("t_load_every");
    let rows = osv_fixture("MAL-2021-1");
    let (name, _) = target(&rows);

    let loaded = intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &fetch("s1"))
        .await
        .expect("load");
    assert_eq!(
        loaded,
        Loaded {
            advisories: 1,
            aliases: 0,
            affected: 1,
            ranges: 0,
            snapshot: id_of(&[(osv::SOURCE, std::slice::from_ref(&rows))]),
        }
    );

    for version in ["0.0.1", "9.9.9"] {
        let hit = intel.lookup("npm", &name, version).await.expect("query");
        assert_eq!(hit.len(), 1, "{version}");
        assert!(hit[0].malware, "{version}");
        assert_eq!(hit[0].source, "osv");
    }
    assert_eq!(
        intel.snapshot().await.expect("query").map(|s| s.digest),
        Some(loaded.snapshot)
    );
}

#[tokio::test]
async fn a_record_listing_versions_matches_only_those() {
    let intel = skip_without_database!("t_load_listed");
    let rows = osv_fixture("MAL-2022-174");
    let (name, version) = target(&rows);
    let version = version.expect("this fixture lists versions");

    let loaded = intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &fetch("s1"))
        .await
        .expect("load");
    assert_eq!((loaded.aliases, loaded.affected), (1, 4));

    assert_eq!(
        intel
            .lookup("npm", &name, &version)
            .await
            .expect("query")
            .len(),
        1
    );
    assert!(
        intel
            .lookup("npm", &name, "0.0.0-not-listed")
            .await
            .expect("query")
            .is_empty()
    );
}

/// A record that leaves the feed, withdrawn or deleted, leaves the store on the next load.
#[tokio::test]
async fn a_refresh_replaces_what_the_source_held() {
    let intel = skip_without_database!("t_load_replace");
    let (gone, kept) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));

    intel
        .replace_source(osv::SOURCE, &[gone.clone(), kept.clone()], &fetch("s1"))
        .await
        .expect("first load");
    intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&kept), &fetch("s2"))
        .await
        .expect("second load");

    let (gone_name, _) = target(&gone);
    let (kept_name, kept_version) = target(&kept);
    assert!(
        intel
            .lookup("npm", &gone_name, "1.0.0")
            .await
            .expect("query")
            .is_empty()
    );
    assert_eq!(
        intel
            .lookup("npm", &kept_name, &kept_version.expect("listed"))
            .await
            .expect("query")
            .len(),
        1
    );
    assert_eq!(
        intel.snapshot().await.expect("query").map(|s| s.digest),
        Some(id_of(&[(osv::SOURCE, std::slice::from_ref(&kept))]))
    );
}

/// Two records with one id fail the advisory `COPY`, which runs after the delete.
#[tokio::test]
async fn a_failed_refresh_leaves_the_previous_load_in_place() {
    let intel = skip_without_database!("t_load_atomic");
    let (first, second) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));

    intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&first), &fetch("s1"))
        .await
        .expect("first load");
    let error = intel
        .replace_source(osv::SOURCE, &[second.clone(), second.clone()], &fetch("s2"))
        .await
        .expect_err("a duplicate advisory id should fail the load")
        .to_string();
    assert!(error.contains("advisory_publisher_id_key"), "{error}");

    let (first_name, _) = target(&first);
    let (second_name, second_version) = target(&second);
    assert_eq!(
        intel
            .lookup("npm", &first_name, "1.0.0")
            .await
            .expect("query")
            .len(),
        1
    );
    assert!(
        intel
            .lookup("npm", &second_name, &second_version.expect("listed"))
            .await
            .expect("query")
            .is_empty()
    );
    assert_eq!(
        intel.snapshot().await.expect("query").map(|s| s.digest),
        Some(id_of(&[(osv::SOURCE, std::slice::from_ref(&first))]))
    );
}

/// The same rows from two bundles have one snapshot id. The second load succeeds, and the
/// snapshot takes its `taken_at` and streams.
#[tokio::test]
async fn the_same_rows_loaded_twice_are_one_snapshot() {
    let intel = skip_without_database!("t_load_twice");
    let rows = osv_fixture("MAL-2021-1");

    for tag in ["s1", "s2"] {
        intel
            .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &fetch(tag))
            .await
            .expect("load");
    }

    assert_eq!(snapshots(&intel).await, 1);
    let reported = intel
        .snapshot()
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(
        reported.digest,
        id_of(&[(osv::SOURCE, std::slice::from_ref(&rows))])
    );
    assert_eq!(reported.taken_at, fetch("s2").taken_at);
    assert_eq!(reported.streams, fetch("s2").streams);
}

/// When the id hashed the bundle, the malware-only loader and the one after it stored
/// different rows from one bundle under one id.
#[tokio::test]
async fn different_rows_from_one_bundle_are_different_snapshots() {
    let intel = skip_without_database!("t_load_differ");
    let (a, b) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));

    let both = intel
        .replace_source(osv::SOURCE, &[a.clone(), b], &fetch("s1"))
        .await
        .expect("load");
    let one = intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&a), &fetch("s1"))
        .await
        .expect("load");

    assert_ne!(both.snapshot, one.snapshot);
    assert_eq!(snapshots(&intel).await, 2);
}

#[tokio::test]
async fn the_snapshot_id_covers_every_source_in_the_store() {
    let intel = skip_without_database!("t_load_sources");
    let (ours, theirs) = ([osv_fixture("MAL-2021-1")], [osv_fixture("MAL-2022-174")]);
    let both = id_of(&[(osv::SOURCE, &ours[..]), ("other", &theirs[..])]);

    let first = intel
        .replace_source(osv::SOURCE, &ours, &fetch("s1"))
        .await
        .expect("load");
    assert_eq!(first.snapshot, id_of(&[(osv::SOURCE, &ours[..])]));

    let second = intel
        .replace_source("other", &theirs, &fetch("s2"))
        .await
        .expect("load");
    assert_eq!(second.snapshot, both);
    let reported = intel
        .snapshot()
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(reported.digest, both);
    let streams: Vec<&str> = reported.streams.iter().map(|s| s.stream.as_str()).collect();
    assert_eq!(streams, ["s1", "s2"]);

    // One source reloaded with the same rows: still both.
    let third = intel
        .replace_source(osv::SOURCE, &ours, &fetch("s3"))
        .await
        .expect("load");
    assert_eq!(third.snapshot, both);
}

/// Two refreshes of different sources at once would each hash the other's previous digest.
/// The other refresh here is a transaction holding an uncommitted `intel_source` row.
#[tokio::test]
async fn a_refresh_waits_for_another_sources_uncommitted_digest() {
    let intel = skip_without_database!("t_load_lock");
    let other = connect("t_load_lock")
        .await
        .expect("connected a moment ago");
    let mut tx = other.begin().await.expect("begin");
    sqlx::query(
        "INSERT INTO intel_source (source, digest, streams) \
         VALUES ('other', 'sha256:other', '{}')",
    )
    .execute(&mut *tx)
    .await
    .expect("insert");

    let rows = [osv_fixture("MAL-2021-1")];
    let refresh = {
        let (intel, rows) = (intel.clone(), rows.clone());
        tokio::spawn(async move { intel.replace_source(osv::SOURCE, &rows, &fetch("s1")).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !refresh.is_finished(),
        "the refresh committed before the other source's digest did"
    );

    tx.commit().await.expect("commit");
    let loaded = refresh.await.expect("joined").expect("load");
    let ours = load::encode(osv::SOURCE, &rows).digest;
    assert_eq!(
        loaded.snapshot,
        load::snapshot_id([(osv::SOURCE, ours.as_str()), ("other", "sha256:other")])
    );
}

#[tokio::test]
async fn a_refresh_leaves_other_sources_alone() {
    let intel = skip_without_database!("t_load_other_source");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('GHSA-keep', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'kept', '1.0.0' FROM advisory WHERE publisher_id = 'GHSA-keep'",
    )
    .await;

    intel
        .replace_source(osv::SOURCE, &[], &fetch("s1"))
        .await
        .expect("empty load");

    assert_eq!(
        intel
            .lookup("npm", "kept", "1.0.0")
            .await
            .expect("query")
            .len(),
        1
    );
}

/// A quote, a newline, and `\.` alone on a line, which ends unquoted CSV data early.
#[tokio::test]
async fn text_copy_treats_specially_round_trips() {
    let intel = skip_without_database!("t_load_escaping");
    let tricky = "say \"hi\"\n\\.\nafter";
    let rows = [
        Rows {
            summary: Some(tricky.to_owned()),
            ..osv_fixture("MAL-2021-1")
        },
        Rows {
            summary: None,
            ..osv_fixture("MAL-2022-174")
        },
    ];

    intel
        .replace_source(osv::SOURCE, &rows, &fetch("s1"))
        .await
        .expect("load");

    let summaries: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT publisher_id, summary FROM advisory ORDER BY publisher_id")
            .fetch_all(intel.pool())
            .await
            .expect("query");
    assert_eq!(
        summaries,
        vec![
            ("MAL-2021-1".to_owned(), Some(tricky.to_owned())),
            ("MAL-2022-174".to_owned(), None),
        ]
    );
}

/// More than one 1 MiB `COPY_CHUNK` of CSV, so rows are split across `CopyData` messages.
#[tokio::test]
async fn a_load_larger_than_one_copy_chunk_arrives_whole() {
    let intel = skip_without_database!("t_load_chunks");
    let base = osv_fixture("MAL-2021-1");
    let rows: Vec<Rows> = (0..3000)
        .map(|i| Rows {
            id: format!("MAL-bulk-{i}"),
            summary: Some("x".repeat(1000)),
            aliases: Default::default(),
            affected: [osv::Affected {
                ecosystem: "npm".to_owned(),
                name: format!("bulk-{i}"),
                version: None,
            }]
            .into(),
            ..base.clone()
        })
        .collect();

    let loaded = intel
        .replace_source(osv::SOURCE, &rows, &fetch("s1"))
        .await
        .expect("load");
    assert_eq!((loaded.advisories, loaded.affected), (3000, 3000));
    for name in ["bulk-0", "bulk-1500", "bulk-2999"] {
        assert_eq!(
            intel
                .lookup("npm", name, "1.0.0")
                .await
                .expect("query")
                .len(),
            1,
            "{name}"
        );
    }
}

#[tokio::test]
async fn an_empty_store_answers_no_package_intel_at_all() {
    let intel = skip_without_database!("t_package_empty");
    assert_eq!(intel.package("npm", "lodash").await.expect("query"), None);
}

#[tokio::test]
async fn a_loaded_store_answers_every_version_row_for_a_package() {
    let intel = skip_without_database!("t_package_loaded");
    let (every, listed) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));
    let loaded = intel
        .replace_source(osv::SOURCE, &[every.clone(), listed.clone()], &fetch("s1"))
        .await
        .expect("load");

    let (every_name, _) = target(&every);
    let found = intel
        .package("npm", &every_name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(found.snapshot, loaded.snapshot);
    assert_eq!(found.records.len(), 1);
    assert_eq!(found.records[0].0, None);
    assert!(found.records[0].1.malware);

    let (listed_name, listed_version) = target(&listed);
    let found = intel
        .package("npm", &listed_name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(found.records.len(), 4, "one row per listed version");
    assert_eq!(found.for_version(&listed_version.expect("listed")).len(), 1);
    assert!(found.for_version("0.0.0-not-listed").is_empty());
}

/// Loaded, and nothing is known against this package: consulted, not cold.
#[tokio::test]
async fn a_package_nothing_is_known_against_still_names_the_snapshot() {
    let intel = skip_without_database!("t_package_unknown");
    let loaded = intel
        .replace_source(osv::SOURCE, &[osv_fixture("MAL-2021-1")], &fetch("s1"))
        .await
        .expect("load");

    let found = intel
        .package("npm", "lodash")
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(found.snapshot, loaded.snapshot);
    assert!(found.records.is_empty());
}

/// Rows from two sources against one package come back together, each under its own id.
#[tokio::test]
async fn a_package_named_by_two_sources_answers_both() {
    let intel = skip_without_database!("t_package_two_sources");
    let malware = osv_fixture("MAL-2021-1");
    let (name, _) = target(&malware);
    assert_eq!(
        name, "cxp-jquery",
        "the fixture this test is written against"
    );
    intel
        .replace_source(osv::SOURCE, &[malware], &fetch("s1"))
        .await
        .expect("load");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source, cvss) VALUES ('GHSA-both', 'ghsa', 7.5); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'cxp-jquery', '1.0.0' FROM advisory WHERE publisher_id = 'GHSA-both'",
    )
    .await;

    let found = intel
        .package("npm", &name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    let ids: Vec<&str> = found
        .for_version("1.0.0")
        .iter()
        .map(|r| r.advisory_id.as_str())
        .collect();
    assert_eq!(ids, ["GHSA-both", "MAL-2021-1"]);
    assert_eq!(found.for_version("2.0.0").len(), 1);
}

/// `MAL-2022-219` is `introduced: "1.2.2"` with no end and no list.
#[tokio::test]
async fn a_loaded_range_is_found_for_the_versions_inside_it() {
    let intel = skip_without_database!("t_range_open");
    let rows = osv_fixture("MAL-2022-219");
    let loaded = intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &fetch("s1"))
        .await
        .expect("load");
    assert_eq!((loaded.affected, loaded.ranges), (0, 1));

    let name = "@dydxprotocol/perpetual";
    for (version, hits) in [("1.2.1", 0), ("1.2.2", 1), ("1.2.2+b", 1), ("40.0.0", 1)] {
        assert_eq!(
            intel
                .lookup("npm", name, version)
                .await
                .expect("query")
                .len(),
            hits,
            "{version}"
        );
    }
    let found = intel
        .package("npm", name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert!(found.records.is_empty());
    assert_eq!(found.ranges.len(), 1);
}

/// `MAL-2025-3661` lists 99.9.0 and 99.9.1 beside `introduced: "99.9.1"`.
#[tokio::test]
async fn a_version_published_into_a_range_after_the_list_was_written_is_found() {
    let intel = skip_without_database!("t_range_and_list");
    intel
        .replace_source(osv::SOURCE, &[osv_fixture("MAL-2025-3661")], &fetch("s1"))
        .await
        .expect("load");

    let name = "@ebay-business-components/marko-rum";
    for version in ["99.9.0", "99.9.1", "99.9.5"] {
        let hit = intel.lookup("npm", name, version).await.expect("query");
        assert_eq!(hit.len(), 1, "{version}");
        assert!(hit[0].malware);
    }
    assert!(
        intel
            .lookup("npm", name, "1.0.0")
            .await
            .expect("query")
            .is_empty()
    );
}

/// Synthetic id and no summary: GHSA text is CC-BY-4.0 and none is committed.
#[tokio::test]
async fn a_vulnerability_record_loads_with_its_score_and_aliases() {
    let intel = skip_without_database!("t_ghsa");
    let record = br#"{
        "id": "GHSA-0000-0000-0000",
        "aliases": ["CVE-2099-2", "CVE-2099-1"],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
        ],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "vulnerable"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "1.0.1"},
                {"introduced": "2.0.0"}, {"last_affected": "2.3.0"}
            ]}]
        }]
    }"#;
    let Parsed::Rows(rows) = osv::parse(record).expect("parses") else {
        panic!("should be stored");
    };
    let loaded = intel
        .replace_source(osv::SOURCE, &[rows], &fetch("s1"))
        .await
        .expect("load");
    assert_eq!((loaded.aliases, loaded.ranges), (2, 2));

    for (version, hits) in [("1.0.0", 1), ("1.0.1", 0), ("2.3.0", 1), ("2.3.1", 0)] {
        let hit = intel
            .lookup("npm", "vulnerable", version)
            .await
            .expect("query");
        assert_eq!(hit.len(), hits, "{version}");
        if let [hit] = hit.as_slice() {
            assert_eq!(hit.cvss, Some(6.9));
            assert!(!hit.malware);
            assert_eq!(hit.aliases, ["CVE-2099-1", "CVE-2099-2"]);
        }
    }
}

/// The loader writes only strict SemVer, so a row that is not came from somewhere else.
#[tokio::test]
async fn a_stored_range_that_does_not_parse_is_an_error_not_an_empty_answer() {
    let intel = skip_without_database!("t_range_corrupt");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('GHSA-bad', 'ghsa'); \
         INSERT INTO advisory_range (advisory_id, ecosystem, name, introduced) \
         SELECT id, 'npm', 'p', '13.0' FROM advisory WHERE publisher_id = 'GHSA-bad'",
    )
    .await;

    match intel.package("npm", "p").await {
        Err(IntelError::Range { advisory_id }) => assert_eq!(advisory_id, "GHSA-bad"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_range_row_with_both_ends_or_neither_is_refused_by_the_schema() {
    let intel = skip_without_database!("t_range_check");
    insert(
        &intel,
        "INSERT INTO advisory (publisher_id, source) VALUES ('GHSA-c', 'ghsa')",
    )
    .await;
    for values in ["'1.0.0', '2.0.0', '2.0.0'", "NULL, NULL, NULL"] {
        let sql = format!(
            "INSERT INTO advisory_range \
             (advisory_id, ecosystem, name, introduced, fixed, last_affected) \
             SELECT id, 'npm', 'p', {values} FROM advisory WHERE publisher_id = 'GHSA-c'"
        );
        assert!(
            sqlx::raw_sql(&sql).execute(intel.pool()).await.is_err(),
            "{values}"
        );
    }
}

/// Every table is keyed by a `BIGINT` identity and joins on it. A string column is sized, and
/// `TEXT` only where a value has no bound. See
/// docs/engineering_decisions/intel-schema-keys-and-types.md.
#[tokio::test]
async fn every_table_is_keyed_by_an_identity_and_only_an_unbounded_column_is_text() {
    let intel = skip_without_database!("t_schema_types");
    // `_sqlx_migrations` is sqlx's own.
    let columns: Vec<(String, String, String, String, Option<i32>)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text, is_identity::text, \
                character_maximum_length::int4 \
         FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name <> '_sqlx_migrations' \
         ORDER BY table_name, ordinal_position",
    )
    .fetch_all(intel.pool())
    .await
    .expect("query");
    let named = |c: &(String, String, String, String, Option<i32>)| format!("{}.{}", c.0, c.1);

    let text: Vec<String> = columns
        .iter()
        .filter(|c| c.2 == "text")
        .map(named)
        .collect();
    assert_eq!(text, ["advisory.summary"]);

    let unsized_strings: Vec<String> = columns
        .iter()
        .filter(|c| c.2 == "character varying" && c.4.is_none())
        .map(named)
        .collect();
    assert!(unsized_strings.is_empty(), "{unsized_strings:?}");

    let keys: Vec<(String, String, String)> = columns
        .iter()
        .filter(|c| c.1 == "id" || c.1 == "advisory_id")
        .map(|c| (named(c), c.2.clone(), c.3.clone()))
        .collect();
    let tables = [
        "advisory",
        "advisory_affected",
        "advisory_alias",
        "advisory_range",
        "intel_snapshot",
        "intel_source",
    ];
    for table in tables {
        assert!(
            keys.contains(&(format!("{table}.id"), "bigint".to_owned(), "YES".to_owned())),
            "{table}: {keys:?}"
        );
    }
    for (column, data_type, _) in keys.iter().filter(|k| k.0.ends_with(".advisory_id")) {
        assert_eq!(data_type, "bigint", "{column}");
    }

    let primary: Vec<(String, String)> = sqlx::query_as(
        "SELECT tc.table_name::text, string_agg(k.column_name::text, ',') \
         FROM information_schema.table_constraints tc \
         JOIN information_schema.key_column_usage k \
           ON k.constraint_schema = tc.constraint_schema \
          AND k.constraint_name = tc.constraint_name \
         WHERE tc.table_schema = current_schema() AND tc.constraint_type = 'PRIMARY KEY' \
           AND tc.table_name <> '_sqlx_migrations' \
         GROUP BY tc.table_name ORDER BY 1",
    )
    .fetch_all(intel.pool())
    .await
    .expect("query");
    assert_eq!(
        primary,
        tables.map(|t| (t.to_owned(), "id".to_owned())).to_vec()
    );
}

/// The refresh fails rather than dropping the record, and the previous load stays.
#[tokio::test]
async fn a_value_longer_than_its_column_fails_the_load_and_names_the_column() {
    let intel = skip_without_database!("t_too_long");
    let first = osv_fixture("MAL-2021-1");
    intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&first), &fetch("s1"))
        .await
        .expect("first load");

    let long = Rows {
        affected: [osv::Affected {
            ecosystem: "npm".to_owned(),
            name: "x".repeat(513),
            version: None,
        }]
        .into(),
        ..osv_fixture("MAL-2022-174")
    };
    let error = intel
        .replace_source(osv::SOURCE, &[long], &fetch("s2"))
        .await
        .expect_err("a 513-character name should fail the load")
        .to_string();
    assert!(
        error.contains("character varying(512)") && error.contains("COPY advisory_affected"),
        "{error}"
    );
    assert!(error.contains("column name"), "{error}");

    let (first_name, _) = target(&first);
    assert_eq!(
        intel
            .lookup("npm", &first_name, "1.0.0")
            .await
            .expect("query")
            .len(),
        1
    );
    assert_eq!(
        intel.snapshot().await.expect("query").map(|s| s.digest),
        Some(id_of(&[(osv::SOURCE, std::slice::from_ref(&first))]))
    );
}

/// OSV writes `modified` to the nanosecond. Postgres keeps microseconds.
#[tokio::test]
async fn timestamps_written_as_rfc_3339_are_stored_as_timestamps() {
    let intel = skip_without_database!("t_timestamps");
    let rows = Rows {
        modified: Some("2026-09-08T03:45:02.886710134Z".to_owned()),
        ..osv_fixture("MAL-2021-1")
    };
    intel
        .replace_source(osv::SOURCE, &[rows], &fetch("s1"))
        .await
        .expect("load");

    let (modified, taken_at): (bool, bool) = sqlx::query_as(
        "SELECT (SELECT modified = '2026-09-08T03:45:02.886710Z'::timestamptz FROM advisory), \
                (SELECT taken_at = $1::text::timestamptz FROM intel_snapshot)",
    )
    .bind(fetch("s1").taken_at)
    .fetch_one(intel.pool())
    .await
    .expect("query");
    assert!(modified);
    assert!(taken_at);
}

/// Postgres prints a `DOUBLE PRECISION` as the shortest text that reads back as the same
/// number, as Rust does, so a stored score is the text the encoding hashed.
#[tokio::test]
async fn a_stored_score_prints_as_the_encoding_wrote_it() {
    let intel = skip_without_database!("t_score_text");
    let rows: Vec<Rows> = [6.9, 0.1 + 0.2, 9.3]
        .into_iter()
        .enumerate()
        .map(|(i, cvss)| Rows {
            id: format!("GHSA-{i}"),
            cvss: Some(cvss),
            ..osv_fixture("MAL-2021-1")
        })
        .collect();
    intel
        .replace_source(osv::SOURCE, &rows, &fetch("s1"))
        .await
        .expect("load");

    let stored: Vec<String> =
        sqlx::query_scalar("SELECT cvss::text FROM advisory ORDER BY publisher_id")
            .fetch_all(intel.pool())
            .await
            .expect("query");
    assert_eq!(stored, ["6.9", "0.30000000000000004", "9.3"]);
}
