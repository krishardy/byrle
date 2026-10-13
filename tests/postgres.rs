//! The repository traits against a real Postgres: the advisory mirror and the analyses.
//!
//! `make test-integration` sets `byrle::env::TEST_DATABASE_URL`; without it each test is
//! skipped. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

#![cfg(not(coverage))]

use byrle::analysis::InstallScripts;
use byrle::analysis::postgres::PgAnalyses;
use byrle::analysis::store::{Analyses, Analysis, Scripts};
use byrle::integrity::Sri;
use byrle::intel::history::{Ingestion, NotLoaded};
use byrle::intel::load::{self, Fetch};
use byrle::intel::postgres::{Loaded, PgIntel, Replacement};
use byrle::intel::providers::osv::{self, Parsed};
use byrle::intel::providers::{datadog, kev};
use byrle::intel::refresh::StreamDigest;
use byrle::intel::rows::{self, Rows};
use byrle::intel::snapshot_dir::SnapshotDir;
use byrle::intel::snapshot_intel::SnapshotIntel;
use byrle::intel::store::{Intel, IntelError, LoadedSnapshot, PackageIntel};
use sqlx::PgPool;
use std::collections::BTreeSet;

/// The database to test against, or nothing, in which case the test is skipped.
fn url() -> Option<String> {
    byrle::env::process()
        .test_database_url()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A schema of its own per test, so tests cannot see each other's rows.
/// `name` is formatted into the SQL, so it is a `'static` literal of `[a-z0-9_]` only.
/// Returns the migrated store, or `None` without a database.
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

/// Run fixture SQL, several commands, after recording a snapshot older than any a test
/// names, so the store answers lookups. `sql` is a literal: sqlx accepts unaudited SQL
/// only as one.
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

/// `postgres::from_env` reads the variable, connects and migrates. Its `Ok(None)` is a
/// proxy with no store, which is a different state from a store that cannot answer.
#[tokio::test]
async fn a_store_is_built_from_the_environment_or_is_absent() {
    use byrle::env::{DATABASE_URL, Env};

    let unset = Env::from_lookup(|_| None);
    assert!(
        byrle::intel::postgres::from_env(&unset)
            .await
            .expect("an unset variable is not an error")
            .is_none()
    );

    let Some(url) = url() else { return };
    let set = Env::from_lookup(move |name| {
        (name == DATABASE_URL.name).then(|| std::ffi::OsString::from(url.clone()))
    });
    let intel = byrle::intel::postgres::from_env(&set)
        .await
        .expect("the database is there")
        .expect("the variable is set");
    assert!(
        intel.snapshot().await.is_ok(),
        "migrated, so a query against the schema answers"
    );
}

/// A command that cannot run without the store says which variable to set, and exits 2 as
/// any other missing configuration does.
#[tokio::test]
async fn a_command_without_a_store_is_refused_with_the_variable_to_set() {
    use byrle::env::{DATABASE_URL, Env};

    let unset = Env::from_lookup(|_| None);
    let refused = match byrle::intel::postgres::required(&unset).await {
        Err(refused) => refused,
        Ok(_) => panic!("an unset variable is no store"),
    };
    assert_eq!(refused.code, 2);
    assert_eq!(
        refused.to_string(),
        format!("set {} to the intel store's Postgres", DATABASE_URL)
    );

    let Some(url) = url() else { return };
    let set = Env::from_lookup(move |name| {
        (name == DATABASE_URL.name).then(|| std::ffi::OsString::from(url.clone()))
    });
    assert!(
        byrle::intel::postgres::required(&set).await.is_ok(),
        "the database is there"
    );
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
            sources: Vec::new(),
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
            unconfigured: Vec::new(),
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
         VALUES ('CVE-1', 'osv/npm', 7.5, 'nvd', TRUE); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         SELECT id, 'npm', 'q', '1.0.0' FROM advisory WHERE publisher_id = 'CVE-1'",
    )
    .await;

    let hit = &intel.lookup("npm", "q", "1.0.0").await.expect("query")[0];
    let finding = hit.finding();
    assert_eq!(finding.advisory_id, "CVE-1");
    assert_eq!(finding.source, "osv/npm");
    assert!(finding.exploited(), "an exploited row carries it through");
    assert_eq!(hit.score().expect("a score").source, "nvd");
}

fn osv_fixture(id: &str) -> Rows {
    let path = format!(
        "{}/tests/fixtures/osv/{id}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    match osv::parse(
        byrle::identity::Ecosystem::Npm,
        &std::fs::read(path).expect("fixture is missing"),
    )
    .expect("fixture parses")
    {
        Parsed::Rows(rows) => *rows,
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
    load::snapshot_id(&load::manifest(
        digests.iter().map(|(s, d)| (*s, d.as_str())),
    ))
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
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&rows),
            &fetch("s1"),
        )
        .await
        .expect("load");
    assert_eq!(
        loaded,
        Loaded {
            advisories: 1,
            aliases: 0,
            affected: 1,
            ranges: 0,
            exploited: 0,
            snapshot: id_of(&[(osv::bundle::NPM_STREAM, std::slice::from_ref(&rows))]),
            manifest: load::manifest([(
                osv::bundle::NPM_STREAM,
                load::encode(osv::bundle::NPM_STREAM, std::slice::from_ref(&rows))
                    .digest
                    .as_str()
            )]),
        }
    );

    for version in ["0.0.1", "9.9.9"] {
        let hit = intel.lookup("npm", &name, version).await.expect("query");
        assert_eq!(hit.len(), 1, "{version}");
        assert!(hit[0].malware, "{version}");
        assert_eq!(hit[0].source, "osv/npm");
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
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&rows),
            &fetch("s1"),
        )
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
        .replace_source(
            osv::bundle::NPM_STREAM,
            &[gone.clone(), kept.clone()],
            &fetch("s1"),
        )
        .await
        .expect("first load");
    intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&kept),
            &fetch("s2"),
        )
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
        Some(id_of(&[(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&kept)
        )]))
    );
}

/// Two records with one id fail the advisory `COPY`, which runs after the delete.
#[tokio::test]
async fn a_failed_refresh_leaves_the_previous_load_in_place() {
    let intel = skip_without_database!("t_load_atomic");
    let (first, second) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));

    intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&first),
            &fetch("s1"),
        )
        .await
        .expect("first load");
    let error = intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            &[second.clone(), second.clone()],
            &fetch("s2"),
        )
        .await
        .expect_err("a duplicate advisory id should fail the load")
        .to_string();
    assert!(
        error.contains("advisory_source_publisher_id_key"),
        "{error}"
    );

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
        Some(id_of(&[(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&first)
        )]))
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
            .replace_source(
                osv::bundle::NPM_STREAM,
                std::slice::from_ref(&rows),
                &fetch(tag),
            )
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
        id_of(&[(osv::bundle::NPM_STREAM, std::slice::from_ref(&rows))])
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
        .replace_source(osv::bundle::NPM_STREAM, &[a.clone(), b], &fetch("s1"))
        .await
        .expect("load");
    let one = intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&a),
            &fetch("s1"),
        )
        .await
        .expect("load");

    assert_ne!(both.snapshot, one.snapshot);
    assert_eq!(snapshots(&intel).await, 2);
}

#[tokio::test]
async fn the_snapshot_id_covers_every_source_in_the_store() {
    let intel = skip_without_database!("t_load_sources");
    let (ours, theirs) = ([osv_fixture("MAL-2021-1")], [osv_fixture("MAL-2022-174")]);
    let both = id_of(&[(osv::bundle::NPM_STREAM, &ours[..]), ("other", &theirs[..])]);

    let first = intel
        .replace_source(osv::bundle::NPM_STREAM, &ours, &fetch("s1"))
        .await
        .expect("load");
    assert_eq!(
        first.snapshot,
        id_of(&[(osv::bundle::NPM_STREAM, &ours[..])])
    );

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

    let third = intel
        .replace_source(osv::bundle::NPM_STREAM, &ours, &fetch("s3"))
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
        tokio::spawn(async move {
            intel
                .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s1"))
                .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !refresh.is_finished(),
        "the refresh committed before the other source's digest did"
    );

    tx.commit().await.expect("commit");
    let loaded = refresh.await.expect("joined").expect("load");
    let ours = load::encode(osv::bundle::NPM_STREAM, &rows).digest;
    assert_eq!(
        loaded.snapshot,
        load::snapshot_id(&load::manifest([
            (osv::bundle::NPM_STREAM, ours.as_str()),
            ("other", "sha256:other")
        ]))
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
        .replace_source(osv::bundle::NPM_STREAM, &[], &fetch("s1"))
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
        .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s1"))
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
            affected: [rows::Affected {
                ecosystem: "npm".to_owned(),
                name: format!("bulk-{i}"),
                version: None,
            }]
            .into(),
            ..base.clone()
        })
        .collect();

    let loaded = intel
        .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s1"))
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
        .replace_source(
            osv::bundle::NPM_STREAM,
            &[every.clone(), listed.clone()],
            &fetch("s1"),
        )
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
    assert_eq!(
        found
            .for_version("npm", &listed_version.expect("listed"))
            .len(),
        1
    );
    assert!(found.for_version("npm", "0.0.0-not-listed").is_empty());
}

/// Loaded, and nothing is known against this package: consulted, not cold.
#[tokio::test]
async fn a_package_nothing_is_known_against_still_names_the_snapshot() {
    let intel = skip_without_database!("t_package_unknown");
    let loaded = intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            &[osv_fixture("MAL-2021-1")],
            &fetch("s1"),
        )
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
        .replace_source(osv::bundle::NPM_STREAM, &[malware], &fetch("s1"))
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
        .for_version("npm", "1.0.0")
        .iter()
        .map(|r| r.advisory_id.as_str())
        .collect();
    assert_eq!(ids, ["GHSA-both", "MAL-2021-1"]);
    assert_eq!(found.for_version("npm", "2.0.0").len(), 1);
}

/// `MAL-2022-219` is `introduced: "1.2.2"` with no end and no list.
#[tokio::test]
async fn a_loaded_range_is_found_for_the_versions_inside_it() {
    let intel = skip_without_database!("t_range_open");
    let rows = osv_fixture("MAL-2022-219");
    let loaded = intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&rows),
            &fetch("s1"),
        )
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
        .replace_source(
            osv::bundle::NPM_STREAM,
            &[osv_fixture("MAL-2025-3661")],
            &fetch("s1"),
        )
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
    let Parsed::Rows(rows) = osv::parse(byrle::identity::Ecosystem::Npm, record).expect("parses")
    else {
        panic!("should be stored");
    };
    let loaded = intel
        .replace_source(osv::bundle::NPM_STREAM, &[*rows], &fetch("s1"))
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

/// Every table is keyed by a `BIGINT` identity, and a string column is `TEXT` only where
/// a value has no bound. See docs/engineering_decisions/intel-schema-keys-and-types.md.
#[tokio::test]
async fn every_table_is_keyed_by_an_identity_and_only_an_unbounded_column_is_text() {
    let intel = skip_without_database!("t_schema_types");
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
    assert_eq!(
        text,
        [
            "advisory.summary",
            "artifact_analysis.unreadable",
            "artifact_attestation.failure",
            "artifact_install_script.body",
            "artifact_source.result",
            "intel_ingestion.etag",
            "intel_ingestion.last_modified",
            "intel_ingestion.error",
            "version_detection.result"
        ]
    );

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
        "account",
        "account_oidc",
        "account_password",
        "account_role",
        "advisory",
        "advisory_affected",
        "advisory_alias",
        "advisory_range",
        "artifact_analysis",
        "artifact_attestation",
        "artifact_decision",
        "artifact_install_script",
        "artifact_source",
        "artifact_virustotal",
        "exploited_cve",
        "failure_count",
        "intel_ingestion",
        "intel_snapshot",
        "intel_source",
        "proxy_token",
        "served_version",
        "session",
        "version_detection",
        "virustotal_request",
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

/// A stream a refresh did not read because it is not configured is recorded so, and the
/// snapshot reports it until a later refresh records the stream otherwise.
#[tokio::test]
async fn a_stream_left_unconfigured_is_reported_until_a_refresh_records_it_otherwise() {
    let intel = skip_without_database!("t_unconfigured");
    let rows = [osv_fixture("MAL-2021-1")];
    let encoded = load::encode(osv::bundle::NPM_STREAM, &rows);
    let github = |unconfigured| NotLoaded {
        source: "github/npm".to_owned(),
        stream: "github/npm".to_owned(),
        bundle: None,
        error: format!(
            "{} is unset, so this stream is not read",
            byrle::env::GITHUB_TOKEN
        ),
        unconfigured,
    };
    let load = |tag: &'static str, not_loaded: NotLoaded| {
        let intel = &intel;
        let encoded = &encoded;
        let rows = &rows;
        async move {
            let f = fetch(tag);
            intel
                .replace(
                    &[Replacement {
                        encoded,
                        rows,
                        streams: &f.streams,
                    }],
                    std::slice::from_ref(&not_loaded),
                    &f.taken_at,
                )
                .await
                .expect("load");
        }
    };
    load("u1", github(true)).await;
    let snapshot = intel.snapshot().await.expect("answers").expect("loaded");
    assert_eq!(snapshot.unconfigured, ["github/npm"]);
    assert!(
        intel.history(1).await.expect("reads")[0].unconfigured,
        "the history row says so"
    );

    load("u2", github(false)).await;
    let snapshot = intel.snapshot().await.expect("answers").expect("loaded");
    assert!(
        snapshot.unconfigured.is_empty(),
        "the latest row says it was configured and failed"
    );
}

/// A load appends a row per stream it tried, with the snapshot; a failed load appends
/// nothing; a refresh that loaded nothing appends its streams with no snapshot.
#[tokio::test]
async fn every_stream_a_refresh_tried_is_appended_to_the_history() {
    let intel = skip_without_database!("t_history");
    assert!(intel.history(10).await.expect("reads").is_empty());

    let rows = [osv_fixture("MAL-2021-1")];
    let encoded = load::encode(osv::bundle::NPM_STREAM, &rows);
    let s1 = fetch("s1");
    let refused = NotLoaded {
        source: kev::STREAM.to_owned(),
        stream: kev::STREAM.to_owned(),
        bundle: None,
        error: "fetching: refused".to_owned(),
        unconfigured: false,
    };
    let loaded = intel
        .replace(
            &[Replacement {
                encoded: &encoded,
                rows: &rows,
                streams: &s1.streams,
            }],
            std::slice::from_ref(&refused),
            &s1.taken_at,
        )
        .await
        .expect("load");
    let first = [
        Ingestion::not_loaded(&s1.taken_at, &refused, Some(&loaded.snapshot)),
        Ingestion::loaded(
            &s1.taken_at,
            osv::bundle::NPM_STREAM,
            &s1.streams[0],
            &encoded.digest,
            &loaded.snapshot,
        ),
    ];
    assert_eq!(intel.history(10).await.expect("reads"), first);

    let long = Rows {
        id: "x".repeat(129),
        ..rows[0].clone()
    };
    intel
        .replace_source(osv::bundle::NPM_STREAM, &[long], &fetch("s2"))
        .await
        .expect_err("a value longer than its column");
    assert_eq!(intel.history(10).await.expect("reads"), first);

    let s3 = fetch("s3");
    let unread = NotLoaded {
        source: osv::bundle::NPM_STREAM.to_owned(),
        stream: s3.streams[0].stream.clone(),
        bundle: Some(s3.streams[0].clone()),
        error: "a record did not read".to_owned(),
        unconfigured: false,
    };
    intel
        .record_not_loaded(std::slice::from_ref(&unread), &s3.taken_at)
        .await
        .expect("records");
    let history = intel.history(2).await.expect("reads");
    assert_eq!(
        history,
        [
            Ingestion::not_loaded(&s3.taken_at, &unread, None),
            first[0].clone()
        ]
    );

    let unexplained = sqlx::raw_sql(
        "INSERT INTO intel_ingestion (taken_at, source, stream) VALUES (now(), 'osv', 'osv/npm')",
    )
    .execute(intel.pool())
    .await;
    assert!(
        unexplained.is_err(),
        "a row with no error must carry its bundle, rows and snapshot"
    );
}

/// The refresh fails rather than dropping the record, and the previous load stays.
#[tokio::test]
async fn a_value_longer_than_its_column_fails_the_load_and_names_the_column() {
    let intel = skip_without_database!("t_too_long");
    let first = osv_fixture("MAL-2021-1");
    intel
        .replace_source(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&first),
            &fetch("s1"),
        )
        .await
        .expect("first load");

    let long = Rows {
        affected: [rows::Affected {
            ecosystem: "npm".to_owned(),
            name: "x".repeat(513),
            version: None,
        }]
        .into(),
        ..osv_fixture("MAL-2022-174")
    };
    let error = intel
        .replace_source(osv::bundle::NPM_STREAM, &[long], &fetch("s2"))
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
        Some(id_of(&[(
            osv::bundle::NPM_STREAM,
            std::slice::from_ref(&first)
        )]))
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
        .replace_source(osv::bundle::NPM_STREAM, &[rows], &fetch("s1"))
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
        .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s1"))
        .await
        .expect("load");

    let stored: Vec<String> =
        sqlx::query_scalar("SELECT cvss::text FROM advisory ORDER BY publisher_id")
            .fetch_all(intel.pool())
            .await
            .expect("query");
    assert_eq!(stored, ["6.9", "0.30000000000000004", "9.3"]);
}

/// One snapshot answers the same from its kept files as from Postgres.
#[tokio::test]
async fn a_kept_snapshot_answers_as_postgres_does() {
    let intel = skip_without_database!("t_kept_answers");
    let rows = [
        osv_fixture("MAL-2021-1"),
        osv_fixture("MAL-2022-174"),
        osv_fixture("MAL-2022-219"),
        osv_fixture("MAL-2025-3661"),
        Rows {
            id: "GHSA-0000-0000-0000".to_owned(),
            malware: false,
            cvss: Some(6.9),
            band: Some("MODERATE".to_owned()),
            aliases: ["CVE-2099-1".to_owned()].into(),
            ..osv_fixture("MAL-2022-174")
        },
    ];
    let encoded = load::encode(osv::bundle::NPM_STREAM, &rows);
    let exploited = load::encode_exploited(kev::STREAM, &["CVE-2099-1".to_owned()].into());
    let (every, _) = target(&rows[0]);
    let (listed, _) = target(&rows[1]);
    let manifest = datadog::parse(
        byrle::identity::Ecosystem::Npm,
        format!(r#"{{"{every}": null, "{listed}": ["1.0"]}}"#).as_bytes(),
    )
    .expect("parses");
    let flagged = load::encode(datadog::NPM_STREAM, &manifest);
    let s1 = fetch("s1");
    let loaded = intel
        .replace(
            &[
                Replacement {
                    encoded: &encoded,
                    rows: &rows,
                    streams: &s1.streams,
                },
                Replacement {
                    encoded: &exploited,
                    rows: &[],
                    streams: &[],
                },
                Replacement {
                    encoded: &flagged,
                    rows: &manifest,
                    streams: &[],
                },
            ],
            &[],
            &s1.taken_at,
        )
        .await
        .expect("load");

    let path = std::env::temp_dir().join(format!("byrle-it-kept-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let dir = SnapshotDir::open(&path).expect("opens");
    for rows in [&encoded, &exploited, &flagged] {
        dir.write_rows(rows).expect("writes rows");
    }
    dir.write_snapshot(&loaded.manifest)
        .expect("writes the snapshot");
    let names: std::collections::BTreeSet<&str> = rows
        .iter()
        .flat_map(|r| {
            r.affected
                .iter()
                .map(|a| a.name.as_str())
                .chain(r.ranges.iter().map(|x| x.name.as_str()))
        })
        .chain(["lodash"])
        .collect();
    assert_eq!(names.len(), 5, "{names:?}");
    let packages = names
        .iter()
        .map(|name| ("npm".to_owned(), name.to_string()))
        .collect();
    let kept = SnapshotIntel::read(&dir, &loaded.snapshot, packages).expect("reads");
    let (mut exploited_records, mut datadog_records, mut banded_records) = (0, 0, 0);
    for name in names {
        let from_postgres = intel.package("npm", name).await.expect("query");
        banded_records += from_postgres
            .iter()
            .flat_map(|p| &p.records)
            .filter(|(_, r)| r.band.as_deref() == Some("MODERATE"))
            .count();
        exploited_records += from_postgres
            .iter()
            .flat_map(|p| &p.records)
            .filter(|(_, r)| r.exploited)
            .count();
        datadog_records += from_postgres
            .iter()
            .flat_map(|p| &p.records)
            .filter(|(_, r)| r.source == datadog::NPM_STREAM && r.malware)
            .count();
        assert!(
            from_postgres
                .iter()
                .flat_map(|p| p.records.iter().map(|(_, r)| r))
                .chain(
                    from_postgres
                        .iter()
                        .flat_map(|p| p.ranges.iter().map(|(_, r)| r))
                )
                .all(|r| r.cached.is_some()),
            "every Postgres record has when it was stored: {name}"
        );
        let from_files = kept.package("npm", name).await.expect("answers");
        assert_eq!(
            from_files.map(sorted),
            from_postgres.map(uncached).map(sorted),
            "{name}"
        );
    }
    assert!(
        banded_records > 0,
        "GHSA-0000-0000-0000's band is stored and read back"
    );
    assert!(
        exploited_records > 0,
        "the catalogue marks GHSA-0000-0000-0000"
    );
    assert_eq!(datadog_records, 2, "one row each for {every} and {listed}");
    let kept_snapshot = kept.snapshot().await.expect("answers").expect("kept");
    assert_eq!(kept_snapshot.digest, loaded.snapshot);
    let stored = intel.snapshot().await.expect("query").expect("loaded");
    assert_eq!(kept_snapshot.sources, stored.sources);
    assert!(kept_snapshot.exploitation_loaded() && stored.exploitation_loaded());
}

/// A package's answer with its rows in one order. Postgres orders text by collation, and the
/// files by byte.
/// `intel` without `cached`, which a kept snapshot does not hold: it is when Postgres
/// stored a row, not part of the rows a snapshot is made of.
fn uncached(mut intel: PackageIntel) -> PackageIntel {
    for (_, r) in &mut intel.records {
        r.cached = None;
    }
    for (_, r) in &mut intel.ranges {
        r.cached = None;
    }
    intel
}

fn sorted(intel: PackageIntel) -> (String, bool, Vec<String>, Vec<String>) {
    let mut records: Vec<String> = intel.records.iter().map(|r| format!("{r:?}")).collect();
    let mut ranges: Vec<String> = intel.ranges.iter().map(|r| format!("{r:?}")).collect();
    records.sort();
    ranges.sort();
    (intel.snapshot, intel.exploitation_loaded, records, ranges)
}

/// Each advisory affecting `name` once, with whether it is exploited, and whether the snapshot
/// includes the catalogue.
async fn exploitation(intel: &PgIntel, name: &str) -> (bool, Vec<(String, bool)>) {
    let found = intel
        .package("npm", name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    let mut marked: Vec<(String, bool)> = found
        .records
        .iter()
        .map(|(_, r)| (r.advisory_id.clone(), r.exploited))
        .collect();
    marked.sort();
    marked.dedup();
    (found.exploitation_loaded, marked)
}

/// A catalogue marks an advisory whose id or alias it lists. Reloading OSV or the
/// catalogue alone leaves the other loaded.
#[tokio::test]
async fn a_catalogue_marks_the_advisories_it_lists_and_is_replaced_apart_from_osv() {
    let intel = skip_without_database!("t_kev");
    let advisory = |id: &str, alias: &str| Rows {
        id: id.to_owned(),
        malware: false,
        cvss: Some(6.9),
        aliases: [alias.to_owned()].into(),
        ..osv_fixture("MAL-2022-174")
    };
    let rows = [
        advisory("CVE-2099-2", "GHSA-0000-0000-0002"),
        advisory("GHSA-0000-0000-0001", "CVE-2099-1"),
        advisory("GHSA-0000-0000-0003", "CVE-2099-3"),
    ];
    let (name, _) = target(&rows[0]);
    let marked = |flags: [bool; 3]| -> Vec<(String, bool)> {
        rows.iter().map(|r| r.id.clone()).zip(flags).collect()
    };

    intel
        .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s1"))
        .await
        .expect("load");
    assert_eq!(
        exploitation(&intel, &name).await,
        (false, marked([false, false, false]))
    );

    let catalogue: BTreeSet<String> = ["CVE-2099-1", "CVE-2099-2", "CVE-2099-9"]
        .map(str::to_owned)
        .into();
    let (osv_rows, exploited) = (
        load::encode(osv::bundle::NPM_STREAM, &rows),
        load::encode_exploited(kev::STREAM, &catalogue),
    );
    let kev_streams = [StreamDigest {
        stream: kev::STREAM.to_owned(),
        sha256: "kev".to_owned(),
        etag: None,
        last_modified: None,
    }];
    let kev_only = |encoded| {
        [Replacement {
            encoded,
            rows: &[],
            streams: &kev_streams,
        }]
    };
    let before = snapshots(&intel).await;
    let s2 = fetch("s2");
    let loaded = intel
        .replace(
            &[
                Replacement {
                    encoded: &osv_rows,
                    rows: &rows,
                    streams: &s2.streams,
                },
                kev_only(&exploited)[0],
            ],
            &[],
            &s2.taken_at,
        )
        .await
        .expect("load");
    assert_eq!((loaded.advisories, loaded.exploited), (3, 3));
    assert_eq!(snapshots(&intel).await, before + 1);
    assert_eq!(
        loaded.manifest,
        load::manifest([
            (osv::bundle::NPM_STREAM, osv_rows.digest.as_str()),
            (kev::STREAM, exploited.digest.as_str()),
        ])
    );
    assert_eq!(
        exploitation(&intel, &name).await,
        (true, marked([true, true, false]))
    );
    let snapshot = intel.snapshot().await.expect("query").expect("loaded");
    assert_eq!(snapshot.sources, [kev::STREAM, osv::bundle::NPM_STREAM]);
    assert!(snapshot.exploitation_loaded());
    assert!(
        snapshot.streams.iter().any(|s| s.stream == kev::STREAM),
        "{:?}",
        snapshot.streams
    );

    let reloaded = intel
        .replace_source(osv::bundle::NPM_STREAM, &rows, &fetch("s3"))
        .await
        .expect("load");
    assert_eq!(reloaded.exploited, 0);
    assert_eq!(reloaded.manifest, loaded.manifest);
    assert_eq!(
        exploitation(&intel, &name).await,
        (true, marked([true, true, false]))
    );

    let smaller = load::encode_exploited(kev::STREAM, &["CVE-2099-3".to_owned()].into());
    let replaced = intel
        .replace(&kev_only(&smaller), &[], &fetch("s4").taken_at)
        .await
        .expect("load");
    assert_eq!((replaced.advisories, replaced.exploited), (0, 1));
    assert_eq!(
        exploitation(&intel, &name).await,
        (true, marked([false, false, true]))
    );
}

/// The analysis store shares the intel pool, so it answers on the schema `fresh` made.
fn analyses(intel: &PgIntel) -> PgAnalyses {
    PgAnalyses::new(intel.pool().clone())
}

fn sri(seed: u8) -> Sri {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(vec![seed; 64]);
    Sri::parse(&format!("sha512-{encoded}")).expect("the digest parses")
}

fn analysis(scripts: Scripts) -> Analysis {
    Analysis {
        ecosystem: "npm".to_owned(),
        name: "bufferutil".to_owned(),
        version: "4.1.0".to_owned(),
        scripts,
    }
}

#[tokio::test]
async fn an_artifact_nothing_has_analysed_has_no_row() {
    let intel = skip_without_database!("t_analysis_absent");
    assert_eq!(
        analyses(&intel)
            .get(&sri(1))
            .await
            .expect("the store answers"),
        None
    );
}

/// npm runs them in this order, and the reader found them in it.
#[tokio::test]
async fn the_scripts_come_back_in_the_order_they_were_written() {
    let intel = skip_without_database!("t_analysis_order");
    let store = analyses(&intel);
    let written = analysis(Scripts::Declared(InstallScripts {
        names: vec![
            "preinstall".to_owned(),
            "install".to_owned(),
            "postinstall".to_owned(),
        ],
        bodies: vec![
            ("preinstall".to_owned(), "echo one".to_owned()),
            ("install".to_owned(), "node-gyp-build".to_owned()),
            ("postinstall".to_owned(), "node install.js".to_owned()),
        ],
    }));

    store.put(&sri(1), &written).await.expect("it writes");
    assert_eq!(
        store.get(&sri(1)).await.expect("the store answers"),
        Some(written)
    );
}

/// A second read of the same bytes writes the same answer. The row is replaced, and a
/// script the later answer does not carry is gone rather than merged into it.
#[tokio::test]
async fn re_analysing_an_artifact_replaces_its_scripts() {
    let intel = skip_without_database!("t_analysis_replace");
    let store = analyses(&intel);
    let first = analysis(Scripts::Declared(InstallScripts {
        names: vec!["preinstall".to_owned(), "postinstall".to_owned()],
        bodies: vec![
            ("preinstall".to_owned(), "echo one".to_owned()),
            ("postinstall".to_owned(), "echo two".to_owned()),
        ],
    }));
    let second = analysis(Scripts::Declared(InstallScripts {
        names: vec!["postinstall".to_owned()],
        bodies: vec![("postinstall".to_owned(), "echo two".to_owned())],
    }));

    store.put(&sri(1), &first).await.expect("it writes");
    store.put(&sri(1), &second).await.expect("it writes again");

    assert_eq!(
        store.get(&sri(1)).await.expect("the store answers"),
        Some(second)
    );
}

/// A verified identity and a failure each come back as written, a later answer replaces
/// an earlier one, and a digest nothing verified is `None` rather than either.
#[tokio::test]
async fn an_attestation_result_is_kept_under_its_digest() {
    use byrle::analysis::attestation::Attested;
    let intel = skip_without_database!("t_attestation");
    let store = analyses(&intel);
    let verified = Attested::Verified {
        identity: "github.com/o/r/.github/workflows/release.yml".to_owned(),
    };
    let failed = Attested::Failed {
        why: "artifact hash does not match any subject in attestation".to_owned(),
    };
    assert_eq!(store.attested(&sri(1)).await.expect("answers"), None);

    store
        .put_attested(&sri(1), &verified)
        .await
        .expect("writes");
    store.put_attested(&sri(2), &failed).await.expect("writes");
    assert_eq!(
        store.attested(&sri(1)).await.expect("answers"),
        Some(verified.clone())
    );
    assert_eq!(
        store.attested(&sri(2)).await.expect("answers"),
        Some(failed.clone())
    );

    store
        .put_attested(&sri(1), &failed)
        .await
        .expect("replaces");
    assert_eq!(
        store.attested(&sri(1)).await.expect("answers"),
        Some(failed)
    );
}

/// A detector's result is kept under its version's name, replaced by a later run, and read
/// back only for the detector version that wrote it.
#[tokio::test]
async fn a_detection_is_kept_under_its_version() {
    use byrle::analysis::detector::{Detection, Finding};
    use byrle::analysis::store::DetectionKey;
    let intel = skip_without_database!("t_detection");
    let store = analyses(&intel);
    let key = DetectionKey {
        detector: "guarddog".to_owned(),
        detector_version: "3.2.0".to_owned(),
        ecosystem: "npm".to_owned(),
        name: "widget".to_owned(),
        version: "1.0.0".to_owned(),
    };
    let fired = Detection {
        findings: vec![Finding {
            rule: "threat-process-hooks".to_owned(),
            detail: "found".to_owned(),
        }],
        errors: Vec::new(),
    };
    assert_eq!(store.detected(&key).await.expect("answers"), None);
    store.put_detected(&key, &fired).await.expect("writes");
    assert_eq!(store.detected(&key).await.expect("answers"), Some(fired));
    let newer = DetectionKey {
        detector_version: "3.3.0".to_owned(),
        ..key.clone()
    };
    assert_eq!(store.detected(&newer).await.expect("answers"), None);
    store
        .put_detected(&newer, &Detection::default())
        .await
        .expect("replaces");
    assert_eq!(
        store.detected(&key).await.expect("answers"),
        None,
        "replaced"
    );
    assert_eq!(
        store.detected(&newer).await.expect("answers"),
        Some(Detection::default())
    );
    sqlx::query("UPDATE version_detection SET result = 'not json'")
        .execute(intel.pool())
        .await
        .expect("updates");
    assert_eq!(store.detected(&newer).await.expect("answers"), None);
}

/// A source comparison is kept under its digest until replaced. One another comparer wrote,
/// or one that no longer reads, is not read back.
#[tokio::test]
async fn a_source_comparison_is_kept_under_its_digest() {
    use byrle::analysis::source::{Comparison, Sourced};
    let intel = skip_without_database!("t_source");
    let store = analyses(&intel);
    let compared = Sourced::Compared {
        repository: "o/r".to_owned(),
        reference: "v1.0.0".to_owned(),
        comparison: Box::new(Comparison {
            differing: vec!["x.js".to_owned()],
            same: 2,
            ..Comparison::default()
        }),
    };
    let not = Sourced::NotCompared("no package.json in the source names the package".to_owned());
    assert_eq!(store.sourced(&sri(1)).await.expect("answers"), None);
    store.put_sourced(&sri(1), &compared).await.expect("writes");
    store.put_sourced(&sri(2), &not).await.expect("writes");
    assert_eq!(
        store.sourced(&sri(1)).await.expect("answers"),
        Some(compared.clone())
    );
    assert_eq!(
        store.sourced(&sri(2)).await.expect("answers"),
        Some(not.clone())
    );
    store.put_sourced(&sri(1), &not).await.expect("replaces");
    assert_eq!(store.sourced(&sri(1)).await.expect("answers"), Some(not));

    for (column, value) in [("comparer", "source 0"), ("result", "not json")] {
        store.put_sourced(&sri(3), &compared).await.expect("writes");
        sqlx::query(&format!("UPDATE artifact_source SET {column} = $1 WHERE id = (SELECT max(id) FROM artifact_source)"))
            .bind(value)
            .execute(intel.pool())
            .await
            .expect("updates");
        assert_eq!(
            store.sourced(&sri(3)).await.expect("answers"),
            None,
            "{column}"
        );
    }
}

/// What VirusTotal said is kept under the artifact's digest, each state round-trips, and a
/// request older than two days is deleted as a new one is recorded.
#[tokio::test]
async fn what_virustotal_said_is_kept_under_its_digest() {
    use byrle::analysis::virustotal::{Counts, Scanned, Verdict};
    let intel = skip_without_database!("t_virustotal");
    let store = analyses(&intel);
    let scanned = |verdict, asked| Scanned {
        sha256: "a".repeat(64),
        verdict,
        asked,
    };
    let known = scanned(
        Verdict::Known(Counts {
            malicious: 3,
            suspicious: 1,
            engines: 70,
        }),
        1_760_000_000,
    );
    assert_eq!(store.scanned(&sri(1)).await.expect("answers"), None);
    store.put_scanned(&sri(1), &known).await.expect("writes");
    assert_eq!(store.scanned(&sri(1)).await.expect("answers"), Some(known));
    for verdict in [Verdict::Unknown, Verdict::Queued("an-1".to_owned())] {
        let replaced = scanned(verdict, 1_760_000_100);
        store
            .put_scanned(&sri(1), &replaced)
            .await
            .expect("replaces");
        assert_eq!(
            store.scanned(&sri(1)).await.expect("answers"),
            Some(replaced)
        );
    }

    let now = 1_760_000_000_i64;
    store
        .put_virustotal_asked(now - 3 * 86_400)
        .await
        .expect("writes");
    store.put_virustotal_asked(now - 30).await.expect("writes");
    store.put_virustotal_asked(now).await.expect("writes");
    assert_eq!(
        store.virustotal_asked(now - 86_400).await.expect("answers"),
        [now - 30, now]
    );
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM virustotal_request")
        .fetch_one(intel.pool())
        .await
        .expect("counts");
    assert_eq!(held, 2, "the request three days old was deleted");
}

/// A decision as the proxy records it: `name`@1.0.0 with `digest`, decided at `at`.
fn decision(name: &str, digest: Option<&str>, at: &str) -> byrle::analysis::decision::Decided {
    let json = serde_json::json!({
        "at": at,
        "digest": digest,
        "ecosystem": "npm",
        "name": name,
        "version": "1.0.0",
        "account": "alice",
        "features": {
            "facts": {
                "published": "2026-10-01", "known_malware": false, "advisories": [],
                "intel": "not-consulted", "has_install_scripts": true, "yanked": null,
                "deprecated": null, "provenance": {"state": "consistent"}
            },
            "detectors": [{"detector": "guarddog", "findings": [
                {"rule": "threat-process-hooks", "detail": ""}], "errors": []}],
            "virustotal": {"state": "known", "malicious": 3, "suspicious": 0, "engines": 63}
        },
        "disposition": {
            "action": "allow", "answered": "served", "mode": "enforce", "checks": [],
            "unenforceable": [], "exceptions_used": [], "risk_score": 1,
            "upstream_status": null, "policy_digest": "sha256:p", "intel_snapshot": null,
            "as_of": "2026-10-12", "build": "0.1.0", "reader": "r", "verifier": "v"
        }
    });
    byrle::analysis::decision::Decided::from_json(&json.to_string()).expect("a decision")
}

/// Decisions keep their order and JSON columns; the view answers the latest per artifact;
/// a page is bounded by id and UTC day; and those before a UTC day are deleted.
#[tokio::test]
async fn each_decision_is_kept_and_the_latest_on_each_artifact_is_its_disposition() {
    use byrle::analysis::decision::{Artifact, Page};
    let intel = skip_without_database!("t_decisions");
    let store = analyses(&intel);
    let mut refused = decision("a", Some("sha512-1"), "2026-10-10T23:59:59Z");
    refused.disposition.action = "block".to_owned();
    refused.disposition.answered = byrle::audit::Answered::Refused;
    let rows = [
        refused,
        decision("a", Some("sha512-2"), "2026-10-11T00:00:00Z"),
        decision("a", None, "2026-10-11T12:00:00Z"),
        decision("a", Some("sha512-1"), "2026-10-12T00:00:00+13:00"),
    ];
    store.put_decisions(&rows[..1]).await.expect("writes");
    store.put_decisions(&rows[1..]).await.expect("writes");

    type Columns = (Option<String>, String, Option<String>, String, String);
    let columns: Vec<Columns> = sqlx::query_as(
        "SELECT digest, name, account, action, answered FROM artifact_decision ORDER BY id",
    )
    .fetch_all(intel.pool())
    .await
    .expect("reads");
    assert_eq!(
        columns[0],
        (
            Some("sha512-1".to_owned()),
            "a".to_owned(),
            Some("alice".to_owned()),
            "block".to_owned(),
            "refused".to_owned()
        )
    );
    assert_eq!(columns[2].0, None);

    let version = Artifact::Version {
        ecosystem: "npm".to_owned(),
        name: "a".to_owned(),
        version: "1.0.0".to_owned(),
    };
    let latest = store.dispositions(&version).await.expect("answers");
    assert_eq!(latest, [rows[1].clone(), rows[3].clone()]);
    let one = Artifact::Digest("sha512-1".to_owned());
    assert_eq!(
        store.dispositions(&one).await.expect("answers"),
        [rows[3].clone()]
    );
    let other = Artifact::Digest("sha512-9".to_owned());
    assert!(
        store
            .dispositions(&other)
            .await
            .expect("answers")
            .is_empty()
    );

    let page = |after, since: Option<&str>, until: Option<&str>, limit| Page {
        after,
        since: since.map(str::to_owned),
        until: until.map(str::to_owned),
        limit,
    };
    let all = store
        .decisions(&page(0, None, None, 10))
        .await
        .expect("answers");
    assert_eq!(
        all.iter().map(|(_, d)| d.clone()).collect::<Vec<_>>(),
        rows.to_vec()
    );
    let first = all[0].0;
    let next = store
        .decisions(&page(first, None, None, 2))
        .await
        .expect("answers");
    assert_eq!(next, all[1..3]);
    let day = store
        .decisions(&page(0, Some("2026-10-11"), Some("2026-10-11"), 10))
        .await
        .expect("answers");
    assert_eq!(
        day.iter().map(|(_, d)| d.at.as_str()).collect::<Vec<_>>(),
        [
            "2026-10-11T00:00:00Z",
            "2026-10-11T12:00:00Z",
            "2026-10-12T00:00:00+13:00"
        ],
        "the last was decided at 11:00 UTC on the 11th"
    );

    assert_eq!(
        store.forget_decisions("2026-10-11").await.expect("deletes"),
        1
    );
    let left = store
        .decisions(&page(0, None, None, 10))
        .await
        .expect("answers");
    assert_eq!(left, all[1..]);
}

/// An analysis another reader wrote, or one written before readers were recorded, is not
/// read back: the artifact is read again by the reader this build has.
#[tokio::test]
async fn an_analysis_from_another_reader_is_not_read() {
    let intel = skip_without_database!("t_analysis_reader");
    let store = analyses(&intel);
    let found = analysis(Scripts::Declared(InstallScripts {
        names: vec!["install".to_owned()],
        bodies: vec![("install".to_owned(), "node-gyp rebuild".to_owned())],
    }));
    store.put(&sri(1), &found).await.expect("writes");
    assert_eq!(
        store.get(&sri(1)).await.expect("answers"),
        Some(found.clone())
    );

    for older in ["", "install-scripts 0"] {
        sqlx::query("UPDATE artifact_analysis SET reader = $1")
            .bind(older)
            .execute(intel.pool())
            .await
            .expect("updates");
        assert_eq!(
            store.get(&sri(1)).await.expect("answers"),
            None,
            "{older:?}"
        );
    }

    store.put(&sri(1), &found).await.expect("replaces");
    assert_eq!(store.get(&sri(1)).await.expect("answers"), Some(found));
}

/// A result another verifier wrote is not read back: a failure from an older root or a
/// verifier bug does not outlive the upgrade that fixes it.
#[tokio::test]
async fn an_attestation_result_from_another_verifier_is_not_read() {
    use byrle::analysis::attestation::Attested;
    let intel = skip_without_database!("t_attestation_verifier");
    let store = analyses(&intel);
    sqlx::query(
        "INSERT INTO artifact_attestation (digest, failure, verifier) \
         VALUES ($1, 'bad root', 'sigstore-verify 0.12.0; root sha256:0000000000000000')",
    )
    .bind(sri(1).to_string())
    .execute(intel.pool())
    .await
    .expect("inserts");
    assert_eq!(store.attested(&sri(1)).await.expect("answers"), None);

    let verified = Attested::Verified {
        identity: "github.com/o/r/.github/workflows/release.yml".to_owned(),
    };
    store
        .put_attested(&sri(1), &verified)
        .await
        .expect("replaces");
    assert_eq!(
        store.attested(&sri(1)).await.expect("answers"),
        Some(verified)
    );
}

/// The two answers a bool would collapse. An archive nobody could read is not an archive
/// that declares no script.
#[tokio::test]
async fn an_unreadable_archive_is_stored_apart_from_one_that_declares_nothing() {
    let intel = skip_without_database!("t_analysis_unreadable");
    let store = analyses(&intel);
    let unreadable = analysis(Scripts::Unreadable(
        "the archive holds no manifest to read".to_owned(),
    ));
    let nothing = analysis(Scripts::Declared(InstallScripts::default()));

    store.put(&sri(1), &unreadable).await.expect("it writes");
    store.put(&sri(2), &nothing).await.expect("it writes");

    assert_eq!(
        store.get(&sri(1)).await.expect("the store answers"),
        Some(unreadable)
    );
    let held = store
        .get(&sri(2))
        .await
        .expect("the store answers")
        .expect("the row is there");
    assert_eq!(held.scripts.names(), Some(&[][..]));
}

/// pip runs a `setup.py` to build an sdist. The reader names the file and has no command
/// to report, so the body is NULL and the name still comes back.
#[tokio::test]
async fn a_script_with_no_command_keeps_its_name() {
    let intel = skip_without_database!("t_analysis_no_body");
    let store = analyses(&intel);
    let written = Analysis {
        ecosystem: "pypi".to_owned(),
        name: "six".to_owned(),
        version: "1.17.0".to_owned(),
        scripts: Scripts::Declared(InstallScripts {
            names: vec!["setup.py".to_owned()],
            bodies: Vec::new(),
        }),
    };

    store.put(&sri(1), &written).await.expect("it writes");
    assert_eq!(
        store.get(&sri(1)).await.expect("the store answers"),
        Some(written)
    );
}

/// The key is the bytes. A registry that repoints a version at different bytes gets a
/// different row, and the first one is untouched.
#[tokio::test]
async fn two_digests_of_one_package_are_two_analyses() {
    let intel = skip_without_database!("t_analysis_by_digest");
    let store = analyses(&intel);
    let runs = analysis(Scripts::Declared(InstallScripts {
        names: vec!["postinstall".to_owned()],
        bodies: vec![("postinstall".to_owned(), "node install.js".to_owned())],
    }));
    let nothing = analysis(Scripts::Declared(InstallScripts::default()));

    store.put(&sri(1), &runs).await.expect("it writes");
    store.put(&sri(2), &nothing).await.expect("it writes");

    assert_eq!(store.get(&sri(1)).await.expect("it answers"), Some(runs));
    assert_eq!(store.get(&sri(2)).await.expect("it answers"), Some(nothing));
}

fn name(s: &str) -> byrle::account::Name {
    byrle::account::Name::parse(s).expect("a valid name")
}

/// A token names its holder until it is revoked or its account disabled, as the in-memory
/// store does, and the store keeps the digest, never the token.
#[tokio::test]
async fn accounts_and_tokens_round_trip_through_postgres() {
    use byrle::account::{AccountError, Accounts, TokenDigest, postgres::PgAccounts};
    let intel = skip_without_database!("t_accounts");
    let store = PgAccounts::new(intel.pool().clone());
    let (ci, alice, laptop, nobody) = (name("ci"), name("alice"), name("laptop"), name("nobody"));

    use byrle::account::Role;
    store.ping().await.expect("the store answers");
    store.create_account(&ci, &[]).await.unwrap();
    store
        .create_account(&alice, &[Role::Admin, Role::Admin])
        .await
        .unwrap();
    assert_eq!(
        store.create_account(&ci, &[Role::Admin]).await,
        Err(AccountError::Exists("account ci".into()))
    );
    sqlx::query("INSERT INTO account_role (account_id, role) SELECT id, 'auditor' FROM account WHERE name = 'alice'")
        .execute(intel.pool())
        .await
        .unwrap();
    let roles: Vec<(String, Vec<Role>)> = store
        .accounts()
        .await
        .unwrap()
        .into_iter()
        .map(|a| (a.name.to_string(), a.roles))
        .collect();
    assert_eq!(
        roles,
        [("alice".into(), vec![Role::Admin]), ("ci".into(), vec![])],
        "a role this build does not know is skipped"
    );

    assert_eq!(store.password(&alice).await, Ok(None));
    store.set_password(&alice, "$argon2id$first").await.unwrap();
    store
        .set_password(&alice, "$argon2id$second")
        .await
        .unwrap();
    assert_eq!(
        store.password(&alice).await,
        Ok(Some("$argon2id$second".into()))
    );
    assert_eq!(
        store.set_password(&nobody, "$x").await,
        Err(AccountError::NotFound("account nobody".into()))
    );
    assert_eq!(store.password(&nobody).await, Ok(None));

    let issuer = "https://idp.example";
    assert_eq!(store.oidc_account(issuer, "u-1").await, Ok(None));
    store.link_oidc(&alice, issuer, "u-1").await.unwrap();
    assert_eq!(
        store.oidc_account(issuer, "u-1").await,
        Ok(Some(alice.clone()))
    );
    assert!(matches!(
        store.link_oidc(&ci, issuer, "u-1").await,
        Err(AccountError::Exists(_))
    ));
    assert!(matches!(
        store.link_oidc(&nobody, issuer, "u-2").await,
        Err(AccountError::NotFound(_))
    ));

    let token = byrle::account::issue();
    let digest = TokenDigest::of(&token);
    store.create_token(&ci, &laptop, &digest).await.unwrap();
    store
        .create_token(&alice, &laptop, &TokenDigest::of("other"))
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_token(&ci, &laptop, &TokenDigest::of("again"))
            .await,
        Err(AccountError::Exists(_))
    ));
    assert!(matches!(
        store
            .create_token(&nobody, &laptop, &TokenDigest::of("x"))
            .await,
        Err(AccountError::NotFound(_))
    ));

    let stored: Vec<String> = sqlx::query_scalar("SELECT digest FROM proxy_token")
        .fetch_all(intel.pool())
        .await
        .unwrap();
    assert!(stored.contains(&digest.as_str().to_owned()));
    assert!(!stored.contains(&token));

    let holder = store.holder(&digest).await.unwrap().expect("held");
    assert_eq!((holder.account, holder.token), (ci.clone(), laptop.clone()));
    assert_eq!(store.holder(&TokenDigest::of("none")).await.unwrap(), None);

    let accounts = store.accounts().await.unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].name, alice);
    assert!(
        accounts[0].created.ends_with('Z'),
        "{}",
        accounts[0].created
    );
    assert_eq!(store.tokens(None).await.unwrap().len(), 2);
    assert_eq!(store.tokens(Some(&ci)).await.unwrap().len(), 1);
    assert!(matches!(
        store.tokens(Some(&nobody)).await,
        Err(AccountError::NotFound(_))
    ));

    store.revoke_token(&ci, &laptop).await.unwrap();
    store.revoke_token(&ci, &laptop).await.unwrap();
    assert_eq!(store.holder(&digest).await.unwrap(), None);
    assert!(store.tokens(Some(&ci)).await.unwrap()[0].revoked.is_some());
    assert!(matches!(
        store.revoke_token(&ci, &nobody).await,
        Err(AccountError::NotFound(_))
    ));

    use byrle::account::Caller;
    let (live, old) = (TokenDigest::of("live"), TokenDigest::of("old"));
    store
        .create_session(&alice, &old, "2000-01-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(store.session(&old).await, Ok(None), "expired");
    store
        .create_session(&alice, &live, "2999-01-01T00:00:00Z")
        .await
        .unwrap();
    let left: Vec<String> = sqlx::query_scalar("SELECT digest FROM session")
        .fetch_all(intel.pool())
        .await
        .unwrap();
    assert_eq!(left, [live.as_str()], "the expired session is deleted");
    assert_eq!(
        store.session(&live).await,
        Ok(Some(Caller {
            account: alice.clone(),
            roles: vec![Role::Admin],
        }))
    );
    assert_eq!(store.roles(&alice).await, Ok(vec![Role::Admin]));
    assert_eq!(store.roles(&nobody).await, Ok(vec![]));
    assert!(matches!(
        store
            .create_session(&nobody, &old, "2999-01-01T00:00:00Z")
            .await,
        Err(AccountError::NotFound(_))
    ));

    store.disable_account(&alice).await.unwrap();
    store.disable_account(&alice).await.unwrap();
    assert_eq!(store.session(&live).await, Ok(None), "disabled");
    assert_eq!(
        store.oidc_account(issuer, "u-1").await,
        Ok(None),
        "disabled"
    );
    assert_eq!(store.roles(&alice).await, Ok(vec![]));
    store.end_session(&live).await.unwrap();
    let ended: i64 = sqlx::query_scalar("SELECT count(*) FROM session")
        .fetch_one(intel.pool())
        .await
        .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(
        store.password(&alice).await,
        Ok(None),
        "a disabled account has no password to log in with"
    );
    assert_eq!(store.holder(&TokenDigest::of("other")).await.unwrap(), None);
    assert!(store.accounts().await.unwrap()[0].disabled.is_some());
    assert!(matches!(
        store.disable_account(&nobody).await,
        Err(AccountError::NotFound(_))
    ));
}

/// Load `osv` rows and a Datadog manifest naming `flagged` in one transaction, as one
/// refresh does with several streams.
async fn refresh_two(intel: &PgIntel, osv: &[Rows], flagged: &str, tag: &str) {
    let encoded = load::encode(osv::bundle::NPM_STREAM, osv);
    let manifest = datadog::parse(
        byrle::identity::Ecosystem::Npm,
        format!(r#"{{"{flagged}": null}}"#).as_bytes(),
    )
    .expect("parses");
    let listed = load::encode(datadog::NPM_STREAM, &manifest);
    let f = fetch(tag);
    intel
        .replace(
            &[
                Replacement {
                    encoded: &encoded,
                    rows: osv,
                    streams: &f.streams,
                },
                Replacement {
                    encoded: &listed,
                    rows: &manifest,
                    streams: &[],
                },
            ],
            &[],
            &f.taken_at,
        )
        .await
        .expect("load");
}

/// Each stream's record of `name`, as (source, cached).
async fn cached_of(intel: &PgIntel, name: &str) -> Vec<(String, Option<String>)> {
    let mut found: Vec<(String, Option<String>)> = intel
        .package("npm", name)
        .await
        .expect("query")
        .expect("a snapshot is loaded")
        .records
        .into_iter()
        .map(|(_, r)| (r.source, r.cached))
        .collect();
    found.sort();
    found.dedup();
    found
}

/// `cached` is kept across a refresh in each source of the transaction, and an advisory that
/// left and came back gets the time it came back.
#[tokio::test]
async fn a_refresh_keeps_when_each_advisory_was_first_stored() {
    let intel = skip_without_database!("t_cached");
    let (kept, left) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));
    let (kept_name, _) = target(&kept);
    let (left_name, _) = target(&left);
    const OLD: &str = "2001-02-03T04:05:06Z";

    refresh_two(&intel, &[kept.clone(), left.clone()], &kept_name, "s1").await;
    sqlx::query("UPDATE advisory SET cached = $1::timestamptz")
        .bind(OLD)
        .execute(intel.pool())
        .await
        .expect("backdate");

    refresh_two(&intel, std::slice::from_ref(&kept), &kept_name, "s2").await;
    assert_eq!(
        cached_of(&intel, &kept_name).await,
        [
            (datadog::NPM_STREAM.to_owned(), Some(OLD.to_owned())),
            (osv::bundle::NPM_STREAM.to_owned(), Some(OLD.to_owned())),
        ]
    );

    refresh_two(&intel, &[kept.clone(), left.clone()], &kept_name, "s3").await;
    let back = cached_of(&intel, &left_name).await;
    assert_eq!(back.len(), 1, "{back:?}");
    let stored = back[0].1.as_deref().expect("a Postgres row has a time");
    assert!(stored > OLD, "stored again at {stored}");
    assert_eq!(
        stored.len(),
        OLD.len(),
        "RFC 3339 UTC to the second: {stored}"
    );
    assert!(stored.ends_with('Z'), "{stored}");
}

/// A batch with a key twice is merged before the statement, and later batches widen each
/// version's first and last time and add to each hour's count. No account shares one row.
#[tokio::test]
async fn each_served_version_and_hourly_failure_count_is_merged() {
    use byrle::audit::Answered;
    use byrle::usage::Use;
    let intel = skip_without_database!("t_usage");
    let store = byrle::usage::postgres::PgUsage::new(intel.pool().clone());
    let served = |account: Option<&str>, at: &str| Use::Served {
        account: account.map(str::to_owned),
        ecosystem: "npm".into(),
        name: "@scope/a".into(),
        version: "1.0.0".into(),
        at: at.parse().unwrap(),
    };
    let failed = |answered| Use::Failed {
        hour: "2026-10-13T09:00:00Z".parse().unwrap(),
        ecosystem: "pypi".into(),
        answered,
    };
    store
        .write(&[
            served(Some("alice"), "2026-10-13T09:00:00Z"),
            served(Some("alice"), "2026-10-13T08:00:00Z"),
            served(None, "2026-10-13T09:00:00Z"),
            failed(Answered::Unauthorized),
            failed(Answered::Unauthorized),
        ])
        .await
        .expect("writes");
    store
        .write(&[
            served(Some("alice"), "2026-10-13T10:00:00Z"),
            served(None, "2026-10-13T07:00:00Z"),
            failed(Answered::Unauthorized),
            failed(Answered::UpstreamStatus),
        ])
        .await
        .expect("writes");

    let versions: Vec<(Option<String>, String, String)> = sqlx::query_as(
        "SELECT account, to_char(first_served AT TIME ZONE 'UTC', 'HH24'), \
         to_char(last_served AT TIME ZONE 'UTC', 'HH24') \
         FROM served_version ORDER BY account NULLS FIRST",
    )
    .fetch_all(intel.pool())
    .await
    .expect("reads");
    assert_eq!(
        versions,
        [
            (None, "07".into(), "09".into()),
            (Some("alice".into()), "08".into(), "10".into()),
        ]
    );
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT answered, count FROM failure_count ORDER BY answered")
            .fetch_all(intel.pool())
            .await
            .expect("reads");
    assert_eq!(
        counts,
        [("unauthorized".into(), 3), ("upstream-status".into(), 1)]
    );

    use byrle::usage::{FailureQuery, ServedQuery, Usage};
    let page = |after, limit| ServedQuery {
        after,
        limit,
        ..ServedQuery::default()
    };
    let first = store.served(&page(0, 1)).await.expect("reads");
    assert_eq!(first.len(), 1);
    assert_eq!(
        (first[0].account.as_deref(), first[0].name.as_str()),
        (None, "@scope/a"),
        "a batch is written in key order, and no account sorts first"
    );
    assert_eq!(first[0].first_served, "2026-10-13T07:00:00Z");
    assert_eq!(first[0].last_served, "2026-10-13T09:00:00Z");
    let rest = store.served(&page(first[0].id, 10)).await.expect("reads");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].account.as_deref(), Some("alice"));
    assert_eq!(rest[0].last_served, "2026-10-13T10:00:00Z");
    let filtered = |query: ServedQuery| {
        let store = &store;
        async move { store.served(&query).await.expect("reads").len() }
    };
    let at = |s: &str| Some(s.parse().unwrap());
    assert_eq!(
        filtered(ServedQuery {
            account: Some("alice".into()),
            ..page(0, 10)
        })
        .await,
        1
    );
    assert_eq!(
        filtered(ServedQuery {
            ecosystem: Some("pypi".into()),
            ..page(0, 10)
        })
        .await,
        0
    );
    assert_eq!(
        filtered(ServedQuery {
            name: Some("@scope/a".into()),
            ..page(0, 10)
        })
        .await,
        2
    );
    assert_eq!(
        filtered(ServedQuery {
            since: at("2026-10-13T09:30:00Z"),
            ..page(0, 10)
        })
        .await,
        1
    );
    assert_eq!(
        filtered(ServedQuery {
            until: at("2026-10-13T07:30:00Z"),
            ..page(0, 10)
        })
        .await,
        1
    );

    let hours = |since: &str, until: &str, answered: Option<&str>| FailureQuery {
        since: since.parse().unwrap(),
        until: until.parse().unwrap(),
        ecosystem: Some("pypi".into()),
        answered: answered.map(str::to_owned),
    };
    let read = store
        .failures(&hours("2026-10-13T09:00:00Z", "2026-10-13T10:00:00Z", None))
        .await
        .expect("reads");
    let read: Vec<(&str, &str, i64)> = read
        .iter()
        .map(|row| (row.hour.as_str(), row.answered.as_str(), row.count))
        .collect();
    assert_eq!(
        read,
        [
            ("2026-10-13T09:00:00Z", "unauthorized", 3),
            ("2026-10-13T09:00:00Z", "upstream-status", 1),
        ]
    );
    let unauthorized = hours(
        "2026-10-13T09:00:00Z",
        "2026-10-13T10:00:00Z",
        Some("unauthorized"),
    );
    assert_eq!(store.failures(&unauthorized).await.expect("reads").len(), 1);
    let before = hours("2026-10-13T08:00:00Z", "2026-10-13T09:00:00Z", None);
    assert!(
        store.failures(&before).await.expect("reads").is_empty(),
        "until is exclusive"
    );
}
