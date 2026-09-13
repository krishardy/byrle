//! The Postgres implementation of [`Intel`].
//!
//! Queries are written as SQL and checked against the real schema at compile time by
//! `sqlx::query_as!`. A renamed column or a changed type is a compile error rather than a
//! runtime one. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

use super::load::{self, Snapshot};
use super::osv::Rows;
use super::range::Interval;
use super::store::{Intel, IntelError, Lookup, PackageIntel, Record};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;

/// Bytes per `CopyData` message. Postgres accepts far larger; this bounds what one send
/// holds in flight.
const COPY_CHUNK: usize = 1 << 20;

/// Rows written by [`PgIntel::replace_source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    pub advisories: u64,
    pub aliases: u64,
    pub affected: u64,
    pub ranges: u64,
}

/// The advisory mirror.
#[derive(Debug, Clone)]
pub struct PgIntel {
    pool: PgPool,
}

impl PgIntel {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for tests that insert fixtures directly.
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

    /// Replace everything `source` supplied with `rows`, and record `snapshot`.
    ///
    /// One transaction. A lookup during the load reads the previous rows, because Postgres
    /// shows a transaction's writes to nobody else until it commits, and a load that fails
    /// at any step leaves them in place. Deleting by `source` rather than swapping whole
    /// tables leaves other streams' rows alone. The alias, affected and range rows go with
    /// their advisory through `ON DELETE CASCADE`.
    ///
    /// `advisory` is copied first. The keys Postgres assigned are read back in the same
    /// transaction, and the other tables are copied carrying them.
    ///
    /// A snapshot digest already recorded, which is the same bundle loaded again, keeps its
    /// row and takes the new `taken_at`.
    pub async fn replace_source(
        &self,
        source: &str,
        rows: &[Rows],
        snapshot: &Snapshot,
    ) -> Result<Loaded, IntelError> {
        let mut tx = self.pool.begin().await.map_err(IntelError::Backend)?;

        sqlx::query!("DELETE FROM advisory WHERE source = $1", source)
            .execute(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        let advisories = copy(&mut tx, load::ADVISORY, &load::advisories(source, rows)).await?;
        let keys: HashMap<String, i64> = sqlx::query!(
            "SELECT publisher_id, id FROM advisory WHERE source = $1",
            source
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(IntelError::Backend)?
        .into_iter()
        .map(|row| (row.publisher_id, row.id))
        .collect();
        let children = load::children(rows, &keys)
            .map_err(|load::Unkeyed(advisory_id)| IntelError::Unkeyed { advisory_id })?;
        let loaded = Loaded {
            advisories,
            aliases: copy(&mut tx, load::ALIAS, &children.alias).await?,
            affected: copy(&mut tx, load::AFFECTED, &children.affected).await?,
            ranges: copy(&mut tx, load::RANGE, &children.range).await?,
        };
        // `::text` first, so the parameters are text and sqlx needs no date or JSON type.
        sqlx::query!(
            "INSERT INTO intel_snapshot (digest, taken_at, streams) \
             VALUES ($1, $2::text::timestamptz, $3::text::jsonb) \
             ON CONFLICT (digest) DO UPDATE \
             SET taken_at = EXCLUDED.taken_at, streams = EXCLUDED.streams",
            snapshot.digest,
            snapshot.taken_at,
            snapshot.streams
        )
        .execute(&mut *tx)
        .await
        .map_err(IntelError::Backend)?;

        tx.commit().await.map_err(IntelError::Backend)?;
        Ok(loaded)
    }
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
        // Ranges compare as SemVer, which SQL does not, so one version is answered the way
        // the proxy answers every version: read the package, evaluate here.
        Box::pin(async move {
            Ok(self
                .package(ecosystem, name)
                .await?
                .map(|p| p.for_version(version).into_iter().cloned().collect())
                .unwrap_or_default())
        })
    }

    fn snapshot(&self) -> Lookup<'_, Option<String>> {
        Box::pin(async move {
            sqlx::query_scalar!("SELECT digest FROM intel_snapshot ORDER BY taken_at DESC LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(IntelError::Backend)
        })
    }

    fn package<'a>(
        &'a self,
        ecosystem: &'a str,
        name: &'a str,
    ) -> Lookup<'a, Option<PackageIntel>> {
        Box::pin(async move {
            // One statement, so the snapshot id and the rows are read from the same
            // committed state. A refresh replaces both in one transaction, and a second
            // query could see the other side of it.
            //
            // `m` is every version-shaped row for the package: listed versions and every
            // version from `advisory_affected`, intervals from `advisory_range`.
            let rows = sqlx::query!(
                r#"
                SELECT
                    s.digest        AS "snapshot!",
                    m.is_range      AS "is_range?",
                    m.version       AS "version?",
                    m.introduced    AS "introduced?",
                    m.fixed         AS "fixed?",
                    m.last_affected AS "last_affected?",
                    a.publisher_id  AS "advisory_id?",
                    a.source        AS "source?",
                    a.cvss          AS "cvss?",
                    a.cvss_source   AS "cvss_source?",
                    a.exploited     AS "exploited?",
                    a.malware       AS "malware?",
                    ARRAY(
                        SELECT al.alias FROM advisory_alias al
                        WHERE al.advisory_id = a.id ORDER BY al.alias
                    )               AS "aliases!"
                FROM (SELECT digest FROM intel_snapshot ORDER BY taken_at DESC LIMIT 1) s
                LEFT JOIN (
                    SELECT advisory_id, FALSE AS is_range, version,
                           NULL::varchar AS introduced, NULL::varchar AS fixed,
                           NULL::varchar AS last_affected
                    FROM advisory_affected WHERE ecosystem = $1 AND name = $2
                    UNION ALL
                    SELECT advisory_id, TRUE, NULL, introduced, fixed, last_affected
                    FROM advisory_range WHERE ecosystem = $1 AND name = $2
                ) m ON TRUE
                LEFT JOIN advisory a ON a.id = m.advisory_id
                ORDER BY a.publisher_id, m.is_range, m.version, m.introduced, m.fixed, m.last_affected
                "#,
                ecosystem,
                name
            )
            .fetch_all(&self.pool)
            .await
            .map_err(IntelError::Backend)?;

            let Some(snapshot) = rows.first().map(|row| row.snapshot.clone()) else {
                return Ok(None);
            };
            let mut intel = PackageIntel {
                snapshot,
                records: Vec::new(),
                ranges: Vec::new(),
            };
            for row in rows {
                // No advisory is the one row a snapshot with nothing against the package
                // gives.
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
                    exploited,
                    malware,
                };
                if row.is_range == Some(true) {
                    let interval = Interval::from_columns(
                        row.introduced.as_deref(),
                        row.fixed.as_deref(),
                        row.last_affected.as_deref(),
                    )
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
