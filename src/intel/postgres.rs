//! The Postgres implementation of [`Intel`], with queries checked against the schema at
//! compile time by `sqlx::query_as!`.
//!
//! See `docs/engineering_decisions/storage-sqlx-postgres.md`.

use super::history::{Ingestion, NotLoaded};
use super::load::{self, Encoded, Fetch, Kind};
use super::providers::kev;
use super::range::{Interval, VersionOrder};
use super::refresh::StreamDigest;
use super::rows::Rows;
use super::store::{Intel, IntelError, LoadedSnapshot, Lookup, PackageIntel, Record};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;

/// Bytes per `CopyData` message, which bounds what one send holds in flight.
const COPY_CHUNK: usize = 1 << 20;

/// Rows written by [`PgIntel::replace`], and the snapshot the store contains after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub advisories: u64,
    pub aliases: u64,
    pub affected: u64,
    pub ranges: u64,
    pub exploited: u64,
    /// The snapshot id. See [`load::snapshot_id`].
    pub snapshot: String,
    /// What the snapshot id is the digest of. See [`load::manifest`].
    pub manifest: String,
}

/// One source a load replaces.
#[derive(Debug, Clone, Copy)]
pub struct Replacement<'a> {
    pub encoded: &'a Encoded,
    /// The rows `encoded` encodes, for the tables built once Postgres has keyed them.
    pub rows: &'a [Rows],
    /// The bundles the rows were read from. Recorded, and part of no digest.
    pub streams: &'a [StreamDigest],
}

/// The advisory mirror.
#[derive(Debug, Clone)]
pub struct PgIntel {
    pool: PgPool,
}

/// The store at [`crate::env::DATABASE_URL`], connected and migrated. `Ok(None)` when the
/// variable is unset, which is a proxy that enforces no advisory check.
pub async fn from_env<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &crate::env::Env<L>,
) -> Result<Option<PgIntel>, String> {
    let Some(url) = environment.database_url().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let pool = PgPool::connect(&url)
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    let intel = PgIntel::new(pool);
    intel.migrate().await.map_err(|e| e.to_string())?;
    Ok(Some(intel))
}

/// [`from_env`] as any [`Intel`], for `explain` and `policy diff`, which read a kept
/// snapshot the same way. The error names [`crate::env::DATABASE_URL`].
pub async fn intel_from_env<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &crate::env::Env<L>,
) -> Result<Option<Box<dyn Intel>>, String> {
    from_env(environment)
        .await
        .map(|store| store.map(|store| Box::new(store) as Box<dyn Intel>))
        .map_err(|e| format!("{}: {e}", crate::env::DATABASE_URL))
}

/// `e`, and where Postgres says it stopped: a failed `COPY` names the table, line and column,
/// such as a value longer than its column.
pub(crate) fn described(e: &sqlx::Error) -> String {
    match e
        .as_database_error()
        .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .and_then(|d| d.r#where())
    {
        Some(context) => format!("{e} ({context})"),
        None => e.to_string(),
    }
}

/// Why a command that cannot run without the store did not get one.
#[derive(Debug)]
pub struct Refused {
    pub why: String,
    /// 2 when the variable is unset, and 1 when the store cannot be reached or migrated.
    pub code: u8,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

/// The store a command cannot run without.
pub async fn required<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &crate::env::Env<L>,
) -> Result<PgIntel, Refused> {
    match from_env(environment).await {
        Ok(Some(intel)) => Ok(intel),
        Ok(None) => Err(Refused {
            why: format!(
                "set {} to the intel store's Postgres",
                crate::env::DATABASE_URL
            ),
            code: 2,
        }),
        Err(e) => Err(Refused {
            why: format!("{}: {e}", crate::env::DATABASE_URL),
            code: 1,
        }),
    }
}

impl PgIntel {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, which the artifact analyses share and tests insert fixtures through.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply any migrations this build carries that the database does not have.
    ///
    /// Postgres has transactional DDL, so a migration that fails rolls back whole and the
    /// database is never left half-migrated.
    pub async fn migrate(&self) -> Result<(), IntelError> {
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(|e| IntelError::Backend(sqlx::Error::Migrate(Box::new(e))))
    }

    /// Replace everything `source` supplied with `rows`, and record the snapshot the store
    /// contains after it. [`PgIntel::replace`] for one source of advisories.
    pub async fn replace_source(
        &self,
        source: &str,
        rows: &[Rows],
        fetch: &Fetch,
    ) -> Result<Loaded, IntelError> {
        let encoded = load::encode(source, rows);
        self.replace(
            &[Replacement {
                encoded: &encoded,
                rows,
                streams: &fetch.streams,
            }],
            &[],
            &fetch.taken_at,
        )
        .await
    }

    /// Replace everything each source supplied with its rows, in one transaction, and record
    /// the snapshot the store then holds. See docs/engineering_decisions/snapshot-identity.md.
    pub async fn replace(
        &self,
        sources: &[Replacement<'_>],
        not_loaded: &[NotLoaded],
        taken_at: &str,
    ) -> Result<Loaded, IntelError> {
        let mut tx = self.pool.begin().await.map_err(IntelError::Backend)?;

        sqlx::query!("LOCK TABLE intel_source IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        let mut written = Written::default();
        for replacement in sources {
            write_source(&mut tx, replacement, &mut written).await?;
        }
        let (manifest, snapshot) = record_snapshot(&mut tx, taken_at).await?;
        record_ingestions(&mut tx, sources, not_loaded, taken_at, &snapshot).await?;

        tx.commit().await.map_err(IntelError::Backend)?;
        Ok(Loaded {
            advisories: written.advisories,
            aliases: written.aliases,
            affected: written.affected,
            ranges: written.ranges,
            exploited: written.exploited,
            snapshot,
            manifest,
        })
    }

    /// Append `not_loaded` to `intel_ingestion` for a refresh that loaded nothing, in one
    /// transaction. `taken_at` is RFC 3339 UTC.
    pub async fn record_not_loaded(
        &self,
        not_loaded: &[NotLoaded],
        taken_at: &str,
    ) -> Result<(), IntelError> {
        let mut tx = self.pool.begin().await.map_err(IntelError::Backend)?;
        for stream in not_loaded {
            record(&mut tx, &Ingestion::not_loaded(taken_at, stream, None)).await?;
        }
        tx.commit().await.map_err(IntelError::Backend)
    }

    /// The newest `limit` rows of `intel_ingestion`, newest first.
    pub async fn history(&self, limit: u32) -> Result<Vec<Ingestion>, IntelError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                to_char(taken_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "taken_at!",
                source, stream, sha256, etag, last_modified, rows_digest, snapshot, error,
                unconfigured
            FROM intel_ingestion
            ORDER BY id DESC
            LIMIT $1
            "#,
            i64::from(limit)
        )
        .fetch_all(&self.pool)
        .await
        .map_err(IntelError::Backend)?;
        Ok(rows
            .into_iter()
            .map(|row| Ingestion {
                taken_at: row.taken_at,
                source: row.source,
                stream: row.stream,
                sha256: row.sha256,
                etag: row.etag,
                last_modified: row.last_modified,
                rows: row.rows_digest,
                snapshot: row.snapshot,
                error: row.error,
                unconfigured: row.unconfigured,
            })
            .collect())
    }
}

/// Rows [`PgIntel::replace`] has copied so far, per table.
#[derive(Default)]
struct Written {
    advisories: u64,
    aliases: u64,
    affected: u64,
    ranges: u64,
    exploited: u64,
}

/// Delete the rows `replacement`'s source supplied before, copy its new rows, and store its
/// digest and streams in `intel_source`. Keeps each advisory's `cached`: see advisory-cached.md.
async fn write_source(
    conn: &mut PgConnection,
    replacement: &Replacement<'_>,
    written: &mut Written,
) -> Result<(), IntelError> {
    let encoded = replacement.encoded;
    let source = encoded.source.as_str();
    sqlx::query(
        "CREATE TEMP TABLE prior_cached ON COMMIT DROP AS \
         SELECT publisher_id, cached FROM advisory WHERE source = $1",
    )
    .bind(source)
    .execute(&mut *conn)
    .await
    .map_err(IntelError::Backend)?;
    sqlx::query!("DELETE FROM advisory WHERE source = $1", source)
        .execute(&mut *conn)
        .await
        .map_err(IntelError::Backend)?;
    sqlx::query!("DELETE FROM exploited_cve WHERE source = $1", source)
        .execute(&mut *conn)
        .await
        .map_err(IntelError::Backend)?;
    match encoded.kind {
        Kind::Exploited => {
            written.exploited += copy(conn, load::EXPLOITED, &encoded.first_table).await?;
        }
        Kind::Advisories => write_advisories(conn, replacement, written).await?,
    }
    sqlx::query(
        "UPDATE advisory a SET cached = p.cached FROM prior_cached p \
         WHERE a.source = $1 AND a.publisher_id = p.publisher_id",
    )
    .bind(source)
    .execute(&mut *conn)
    .await
    .map_err(IntelError::Backend)?;
    sqlx::query("DROP TABLE prior_cached")
        .execute(&mut *conn)
        .await
        .map_err(IntelError::Backend)?;

    sqlx::query!(
        "INSERT INTO intel_source (source, digest, streams) \
         VALUES ($1, $2, $3::text::jsonb) \
         ON CONFLICT (source) DO UPDATE \
         SET digest = EXCLUDED.digest, streams = EXCLUDED.streams",
        source,
        encoded.digest,
        load::streams_json(replacement.streams)
    )
    .execute(conn)
    .await
    .map_err(IntelError::Backend)?;
    Ok(())
}

/// Copy `advisory`, read back the keys Postgres assigned, and copy the alias, affected and
/// range rows carrying them.
async fn write_advisories(
    conn: &mut PgConnection,
    replacement: &Replacement<'_>,
    written: &mut Written,
) -> Result<(), IntelError> {
    let encoded = replacement.encoded;
    written.advisories += copy(conn, load::ADVISORY, &encoded.first_table).await?;
    let keys: HashMap<String, i64> = sqlx::query!(
        "SELECT publisher_id, id FROM advisory WHERE source = $1",
        encoded.source
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(IntelError::Backend)?
    .into_iter()
    .map(|row| (row.publisher_id, row.id))
    .collect();
    let children = load::children(replacement.rows, &keys)
        .map_err(|load::Unkeyed(advisory_id)| IntelError::Unkeyed { advisory_id })?;
    written.aliases += copy(conn, load::ALIAS, &children.alias).await?;
    written.affected += copy(conn, load::AFFECTED, &children.affected).await?;
    written.ranges += copy(conn, load::RANGE, &children.range).await?;
    Ok(())
}

/// Hash every source's digest into the snapshot id and upsert its `intel_snapshot` row.
/// Returns the manifest and the snapshot id.
async fn record_snapshot(
    conn: &mut PgConnection,
    taken_at: &str,
) -> Result<(String, String), IntelError> {
    let stored = sqlx::query!("SELECT source, digest FROM intel_source")
        .fetch_all(&mut *conn)
        .await
        .map_err(IntelError::Backend)?;
    let manifest = load::manifest(
        stored
            .iter()
            .map(|s| (s.source.as_str(), s.digest.as_str())),
    );
    let snapshot = load::snapshot_id(&manifest);
    sqlx::query!(
        "INSERT INTO intel_snapshot (digest, taken_at, streams) \
         SELECT $1, $2::text::timestamptz, COALESCE(jsonb_object_agg(e.key, e.value), '{}') \
         FROM intel_source s CROSS JOIN LATERAL jsonb_each(s.streams) e \
         ON CONFLICT (digest) DO UPDATE \
         SET taken_at = EXCLUDED.taken_at, streams = EXCLUDED.streams",
        snapshot,
        taken_at
    )
    .execute(conn)
    .await
    .map_err(IntelError::Backend)?;
    Ok((manifest, snapshot))
}

/// Append each stream in `sources` to `intel_ingestion` as loaded, and each in `not_loaded`
/// as not, both with `snapshot`.
async fn record_ingestions(
    conn: &mut PgConnection,
    sources: &[Replacement<'_>],
    not_loaded: &[NotLoaded],
    taken_at: &str,
    snapshot: &str,
) -> Result<(), IntelError> {
    for replacement in sources {
        for bundle in replacement.streams {
            let entry = Ingestion::loaded(
                taken_at,
                &replacement.encoded.source,
                bundle,
                &replacement.encoded.digest,
                snapshot,
            );
            record(conn, &entry).await?;
        }
    }
    for stream in not_loaded {
        record(
            conn,
            &Ingestion::not_loaded(taken_at, stream, Some(snapshot)),
        )
        .await?;
    }
    Ok(())
}

/// Append one row to `intel_ingestion`.
async fn record(conn: &mut PgConnection, entry: &Ingestion) -> Result<(), IntelError> {
    sqlx::query!(
        "INSERT INTO intel_ingestion \
         (taken_at, source, stream, sha256, etag, last_modified, rows_digest, snapshot, error, \
          unconfigured) \
         VALUES ($1::text::timestamptz, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        entry.taken_at,
        entry.source,
        entry.stream,
        entry.sha256.as_deref(),
        entry.etag.as_deref(),
        entry.last_modified.as_deref(),
        entry.rows.as_deref(),
        entry.snapshot.as_deref(),
        entry.error.as_deref(),
        entry.unconfigured
    )
    .execute(conn)
    .await
    .map_err(IntelError::Backend)?;
    Ok(())
}

/// Send `data` through one `COPY ... FROM STDIN`, returning the rows Postgres wrote.
///
/// A failed send aborts the copy. Without that the connection stays in copy mode and the
/// rollback that follows fails too.
async fn copy(conn: &mut PgConnection, statement: &str, data: &[u8]) -> Result<u64, IntelError> {
    let mut copy = conn
        .copy_in_raw(statement)
        .await
        .map_err(IntelError::Backend)?;
    for chunk in data.chunks(COPY_CHUNK) {
        if let Err(e) = copy.send(chunk).await {
            let _ = copy.abort(e.to_string()).await;
            return Err(IntelError::Backend(e));
        }
    }
    copy.finish().await.map_err(IntelError::Backend)
}

impl Intel for PgIntel {
    fn lookup<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
        version: &'a str,
    ) -> Lookup<'a, Vec<Record>> {
        Box::pin(async move {
            Ok(self
                .package(ecosystem, name)
                .await?
                .map(|p| {
                    p.for_version(ecosystem, version)
                        .into_iter()
                        .cloned()
                        .collect()
                })
                .unwrap_or_default())
        })
    }

    fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
        Box::pin(async move {
            let rows = sqlx::query!(
                r#"
                SELECT
                    s.digest AS "digest!",
                    to_char(s.taken_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                        AS "taken_at!",
                    ARRAY(SELECT source::text FROM intel_source ORDER BY source) AS "sources!",
                    ARRAY(
                        SELECT latest.stream::text
                        FROM (
                            SELECT DISTINCT ON (stream) stream, unconfigured
                            FROM intel_ingestion
                            ORDER BY stream, id DESC
                        ) latest
                        WHERE latest.unconfigured
                        ORDER BY latest.stream
                    ) AS "unconfigured!",
                    e.key AS "stream?",
                    e.value ->> 'sha256' AS "sha256?",
                    e.value ->> 'etag' AS "etag?",
                    e.value ->> 'last_modified' AS "last_modified?"
                FROM (
                    SELECT digest, taken_at, streams
                    FROM intel_snapshot
                    ORDER BY taken_at DESC
                    LIMIT 1
                ) s
                LEFT JOIN LATERAL jsonb_each(s.streams) e ON TRUE
                ORDER BY e.key
                "#
            )
            .fetch_all(&self.pool)
            .await
            .map_err(IntelError::Backend)?;

            let Some(first) = rows.first() else {
                return Ok(None);
            };
            Ok(Some(LoadedSnapshot {
                digest: first.digest.clone(),
                taken_at: first.taken_at.clone(),
                sources: first.sources.clone(),
                unconfigured: first.unconfigured.clone(),
                streams: rows
                    .iter()
                    .filter_map(|row| {
                        Some(StreamDigest {
                            stream: row.stream.clone()?,
                            sha256: row.sha256.clone()?,
                            etag: row.etag.clone(),
                            last_modified: row.last_modified.clone(),
                        })
                    })
                    .collect(),
            }))
        })
    }

    fn package<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
    ) -> Lookup<'a, Option<PackageIntel>> {
        Box::pin(async move {
            let rows = sqlx::query!(
                r#"
                WITH m AS (
                    SELECT advisory_id, FALSE AS is_range, version,
                           NULL::varchar AS introduced, NULL::boolean AS introduced_excluded,
                           NULL::varchar AS fixed, NULL::varchar AS last_affected
                    FROM advisory_affected WHERE ecosystem = $1 AND name = $2
                    UNION ALL
                    SELECT advisory_id, TRUE, NULL, introduced, introduced_excluded,
                           fixed, last_affected
                    FROM advisory_range WHERE ecosystem = $1 AND name = $2
                ),
                adv AS MATERIALIZED (
                    SELECT a.id, a.publisher_id, a.source, a.cvss, a.cvss_source,
                        a.severity_band, a.malware, a.cached,
                        (a.exploited
                            OR EXISTS (SELECT 1 FROM exploited_cve k WHERE k.cve_id = a.publisher_id)
                            OR EXISTS (SELECT 1 FROM advisory_alias al JOIN exploited_cve k
                                ON k.cve_id = al.alias WHERE al.advisory_id = a.id)) AS exploited,
                        ARRAY(SELECT al.alias FROM advisory_alias al
                            WHERE al.advisory_id = a.id ORDER BY al.alias) AS aliases
                    FROM advisory a
                    WHERE a.id IN (SELECT advisory_id FROM m)
                )
                SELECT
                    s.digest        AS "snapshot!",
                    EXISTS (SELECT 1 FROM intel_source WHERE source = $3)
                                    AS "exploitation_loaded!",
                    m.is_range AS "is_range?", m.version AS "version?",
                    m.introduced AS "introduced?", m.introduced_excluded AS "introduced_excluded?",
                    m.fixed AS "fixed?", m.last_affected AS "last_affected?",
                    adv.publisher_id AS "advisory_id?", adv.source AS "source?",
                    adv.cvss AS "cvss?", adv.cvss_source AS "cvss_source?",
                    adv.severity_band AS "severity_band?", adv.exploited AS "exploited?",
                    adv.malware AS "malware?",
                    to_char(adv.cached AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "cached?",
                    COALESCE(adv.aliases, ARRAY[]::varchar[]) AS "aliases!"
                FROM (SELECT digest FROM intel_snapshot ORDER BY taken_at DESC LIMIT 1) s
                LEFT JOIN m ON TRUE
                LEFT JOIN adv ON adv.id = m.advisory_id
                ORDER BY adv.publisher_id, m.is_range, m.version, m.introduced,
                         m.introduced_excluded, m.fixed, m.last_affected
                "#,
                ecosystem,
                name,
                kev::STREAM
            )
            .fetch_all(&self.pool)
            .await
            .map_err(IntelError::Backend)?;

            let Some(first) = rows.first() else {
                return Ok(None);
            };
            let mut intel = PackageIntel {
                snapshot: first.snapshot.clone(),
                records: Vec::new(),
                ranges: Vec::new(),
                exploitation_loaded: first.exploitation_loaded,
            };
            for row in rows {
                let (Some(advisory_id), Some(source), Some(exploited), Some(malware)) =
                    (row.advisory_id, row.source, row.exploited, row.malware)
                else {
                    continue;
                };
                let record = Record {
                    advisory_id,
                    aliases: row.aliases,
                    source,
                    cvss: row.cvss,
                    cvss_source: row.cvss_source,
                    band: row.severity_band,
                    exploited,
                    malware,
                    cached: row.cached,
                };
                if row.is_range == Some(true) {
                    let interval = VersionOrder::of(ecosystem)
                        .and_then(|order| {
                            Interval::from_columns(
                                order,
                                row.introduced.as_deref(),
                                row.introduced_excluded.unwrap_or(false),
                                row.fixed.as_deref(),
                                row.last_affected.as_deref(),
                            )
                        })
                        .ok_or_else(|| IntelError::Range {
                            advisory_id: record.advisory_id.clone(),
                        })?;
                    intel.ranges.push((interval, record));
                } else {
                    intel.records.push((row.version, record));
                }
            }
            Ok(Some(intel))
        })
    }
}
