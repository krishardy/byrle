//! The repository trait against a real Postgres.
//!
//! Not unit tests. They need a database, which `make test-integration` starts in a
//! container and points at with `WAHAROA_TEST_DATABASE_URL`. Without that variable every
//! test here is skipped, so `cargo test` stays runnable with nothing installed.
//!
//! These exist because SQLite was dropped and Postgres is the only backend. A suite left
//! to itself covers whatever needs no service, which would have been the backend nobody
//! deploys. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

#![cfg(not(coverage))]

use sqlx::PgPool;
use waharoa::intel::load::Snapshot;
use waharoa::intel::osv::{self, Parsed, Rows};
use waharoa::intel::postgres::{Loaded, PgIntel};
use waharoa::intel::store::Intel;

/// The database to test against, or nothing, in which case the test is skipped.
fn url() -> Option<String> {
    std::env::var("WAHAROA_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
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

    let intel = PgIntel::new(pool);
    intel.migrate().await.expect("migrations should apply");
    Some(intel)
}

/// `raw_sql`, not `query`: a prepared statement takes one command, and these fixtures are
/// several. `'static` because sqlx 0.9 accepts unaudited SQL only as a literal, and every
/// fixture is one.
async fn insert(intel: &PgIntel, sql: &'static str) {
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
        "INSERT INTO advisory (id, source, cvss, cvss_source) \
         VALUES ('GHSA-x', 'ghsa', 9.8, 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('GHSA-x', 'npm', 'lodash', '4.17.20')",
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
        "INSERT INTO advisory (id, source, malware) VALUES ('MAL-1', 'ossf', TRUE); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('MAL-1', 'npm', 'evil-pkg', NULL)",
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
        "INSERT INTO advisory (id, source) VALUES ('GHSA-y', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('GHSA-y', 'pypi', 'lodash', '1.0.0')",
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
        "INSERT INTO advisory (id, source) VALUES ('GHSA-z', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('GHSA-z', 'npm', 'lodash', NULL), ('GHSA-z', 'npm', 'lodash', '4.17.21')",
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
        "INSERT INTO advisory (id, source) VALUES ('MAL-2', 'ossf'); \
         INSERT INTO advisory (id, source, cvss) VALUES ('GHSA-0', 'ghsa', 0.0); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('MAL-2', 'npm', 'p', '1.0.0'), ('GHSA-0', 'npm', 'p', '1.0.0')",
    )
    .await;

    let hits = intel.lookup("npm", "p", "1.0.0").await.expect("query");
    let scored: Vec<Option<f64>> = hits.iter().map(|r| r.cvss).collect();
    assert!(scored.contains(&None), "{scored:?}");
    assert!(scored.contains(&Some(0.0)), "{scored:?}");
}

#[tokio::test]
async fn the_newest_snapshot_is_the_one_reported() {
    let intel = skip_without_database!("t_snapshot");
    insert(
        &intel,
        "INSERT INTO intel_snapshot (id, taken_at, streams) VALUES \
         ('older', '2026-01-01T00:00:00Z', '{}'), \
         ('newer', '2026-09-13T00:00:00Z', '{}')",
    )
    .await;

    assert_eq!(
        intel.snapshot().await.expect("query"),
        Some("newer".to_owned())
    );
}

/// A stored row names a package, so it can become a finding. It cannot become an
/// enrichment, which is what `src/intel.rs` enforces in the types.
#[tokio::test]
async fn a_row_becomes_a_finding_carrying_its_source_and_score() {
    let intel = skip_without_database!("t_finding");
    insert(
        &intel,
        "INSERT INTO advisory (id, source, cvss, cvss_source, exploited) \
         VALUES ('CVE-1', 'osv', 7.5, 'nvd', TRUE); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('CVE-1', 'npm', 'q', '1.0.0')",
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

/// `taken_at` differs per id, because `snapshot()` reports the latest and equal times tie.
fn snapshot(id: &str) -> Snapshot {
    let seconds = id.bytes().map(u32::from).sum::<u32>() % 60;
    Snapshot {
        id: id.to_owned(),
        taken_at: format!("2026-09-13T00:00:{seconds:02}Z"),
        streams: r#"{"osv": "etag"}"#.to_owned(),
    }
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
        .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &snapshot("s1"))
        .await
        .expect("load");
    assert_eq!(
        loaded,
        Loaded {
            advisories: 1,
            aliases: 0,
            affected: 1
        }
    );

    for version in ["0.0.1", "9.9.9"] {
        let hit = intel.lookup("npm", &name, version).await.expect("query");
        assert_eq!(hit.len(), 1, "{version}");
        assert!(hit[0].malware, "{version}");
        assert_eq!(hit[0].source, "osv");
    }
    assert_eq!(
        intel.snapshot().await.expect("query"),
        Some("s1".to_owned())
    );
}

#[tokio::test]
async fn a_record_listing_versions_matches_only_those() {
    let intel = skip_without_database!("t_load_listed");
    let rows = osv_fixture("MAL-2022-174");
    let (name, version) = target(&rows);
    let version = version.expect("this fixture lists versions");

    let loaded = intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &snapshot("s1"))
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
        .replace_source(osv::SOURCE, &[gone.clone(), kept.clone()], &snapshot("s1"))
        .await
        .expect("first load");
    intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&kept), &snapshot("s2"))
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
        intel.snapshot().await.expect("query"),
        Some("s2".to_owned())
    );
}

/// Two records with one id fail the advisory `COPY`, which runs after the delete.
#[tokio::test]
async fn a_failed_refresh_leaves_the_previous_load_in_place() {
    let intel = skip_without_database!("t_load_atomic");
    let (first, second) = (osv_fixture("MAL-2021-1"), osv_fixture("MAL-2022-174"));

    intel
        .replace_source(osv::SOURCE, std::slice::from_ref(&first), &snapshot("s1"))
        .await
        .expect("first load");
    assert!(
        intel
            .replace_source(
                osv::SOURCE,
                &[second.clone(), second.clone()],
                &snapshot("s2")
            )
            .await
            .is_err(),
        "a duplicate advisory id should fail the load"
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
        intel.snapshot().await.expect("query"),
        Some("s1".to_owned())
    );
}

/// The same bundle fetched twice has the same snapshot id. The second load succeeds.
#[tokio::test]
async fn the_same_bundle_loaded_twice_is_one_snapshot() {
    let intel = skip_without_database!("t_load_twice");
    let rows = osv_fixture("MAL-2021-1");

    for _ in 0..2 {
        intel
            .replace_source(osv::SOURCE, std::slice::from_ref(&rows), &snapshot("s1"))
            .await
            .expect("load");
    }

    let snapshots: i64 = sqlx::query_scalar("SELECT count(*) FROM intel_snapshot")
        .fetch_one(intel.pool())
        .await
        .expect("query");
    assert_eq!(snapshots, 1);
    assert_eq!(
        intel.snapshot().await.expect("query"),
        Some("s1".to_owned())
    );
}

#[tokio::test]
async fn a_refresh_leaves_other_sources_alone() {
    let intel = skip_without_database!("t_load_other_source");
    insert(
        &intel,
        "INSERT INTO advisory (id, source) VALUES ('GHSA-keep', 'ghsa'); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('GHSA-keep', 'npm', 'kept', '1.0.0')",
    )
    .await;

    intel
        .replace_source(osv::SOURCE, &[], &snapshot("s1"))
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
        .replace_source(osv::SOURCE, &rows, &snapshot("s1"))
        .await
        .expect("load");

    let summaries: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id, summary FROM advisory ORDER BY id")
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
        .replace_source(osv::SOURCE, &rows, &snapshot("s1"))
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
    intel
        .replace_source(
            osv::SOURCE,
            &[every.clone(), listed.clone()],
            &snapshot("s1"),
        )
        .await
        .expect("load");

    let (every_name, _) = target(&every);
    let found = intel
        .package("npm", &every_name)
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(found.snapshot, "s1");
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
    intel
        .replace_source(osv::SOURCE, &[osv_fixture("MAL-2021-1")], &snapshot("s1"))
        .await
        .expect("load");

    let found = intel
        .package("npm", "lodash")
        .await
        .expect("query")
        .expect("a snapshot is loaded");
    assert_eq!(found.snapshot, "s1");
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
        .replace_source(osv::SOURCE, &[malware], &snapshot("s1"))
        .await
        .expect("load");
    insert(
        &intel,
        "INSERT INTO advisory (id, source, cvss) VALUES ('GHSA-both', 'ghsa', 7.5); \
         INSERT INTO advisory_affected (advisory_id, ecosystem, name, version) \
         VALUES ('GHSA-both', 'npm', 'cxp-jquery', '1.0.0')",
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
