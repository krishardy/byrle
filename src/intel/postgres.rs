//! The Postgres implementation of [`Intel`].
//!
//! Queries are written as SQL and checked against the real schema at compile time by
//! `sqlx::query_as!`. A renamed column or a changed type is a compile error rather than a
//! runtime one. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

use super::load::{self, Snapshot};
use super::osv::Rows;
use super::store::{Intel, IntelError, Lookup, PackageIntel, Record};
use sqlx::{PgConnection, PgPool};

/// Bytes per `CopyData` message. Postgres accepts far larger; this bounds what one send
/// holds in flight.
const COPY_CHUNK: usize = 1 << 20;

/// Rows written by [`PgIntel::replace_source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    pub advisories: u64,
    pub aliases: u64,
    pub affected: u64,
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
    /// tables leaves other streams' rows alone. The aliases and affected rows go with their
    /// advisory through `ON DELETE CASCADE`.
    ///
    /// A snapshot id already recorded, which is the same bundle loaded again, keeps its row and
    /// takes the new `taken_at`.
    pub async fn replace_source(
        &self,
        source: &str,
        rows: &[Rows],
        snapshot: &Snapshot,
    ) -> Result<Loaded, IntelError> {
        let tables = load::tables(source, rows);
        let mut tx = self.pool.begin().await.map_err(IntelError::Backend)?;

        sqlx::query!("DELETE FROM advisory WHERE source = $1", source)
            .execute(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        let loaded = Loaded {
            advisories: copy(&mut tx, load::ADVISORY, &tables.advisory).await?,
            aliases: copy(&mut tx, load::ALIAS, &tables.alias).await?,
            affected: copy(&mut tx, load::AFFECTED, &tables.affected).await?,
        };
        sqlx::query!(
            "INSERT INTO intel_snapshot (id, taken_at, streams) VALUES ($1, $2, $3::text::jsonb) \
             ON CONFLICT (id) DO UPDATE SET taken_at = EXCLUDED.taken_at, streams = EXCLUDED.streams",
            snapshot.id,
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
        Box::pin(async move {
            // `version IS NULL` is "every version of this package", which is how a malware
            // report usually reads. Both arms are one query, because two queries could
            // answer from two different snapshots if a refresh landed between them.
            sqlx::query_as!(
                Record,
                r#"
                SELECT DISTINCT
                    a.id          AS "advisory_id!",
                    a.source      AS "source!",
                    a.cvss,
                    a.cvss_source,
                    a.exploited   AS "exploited!",
                    a.malware     AS "malware!"
                FROM advisory a
                JOIN advisory_affected f ON f.advisory_id = a.id
                WHERE f.ecosystem = $1
                  AND f.name = $2
                  AND (f.version IS NULL OR f.version = $3)
                ORDER BY a.id
                "#,
                ecosystem,
                name,
                version
            )
            .fetch_all(&self.pool)
            .await
            .map_err(IntelError::Backend)
        })
    }

    fn snapshot(&self) -> Lookup<'_, Option<String>> {
        Box::pin(async move {
            sqlx::query_scalar!("SELECT id FROM intel_snapshot ORDER BY taken_at DESC LIMIT 1")
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
            let rows = sqlx::query!(
                r#"
                SELECT
                    s.id          AS "snapshot!",
                    f.version     AS "version?",
                    a.id          AS "advisory_id?",
                    a.source      AS "source?",
                    a.cvss        AS "cvss?",
                    a.cvss_source AS "cvss_source?",
                    a.exploited   AS "exploited?",
                    a.malware     AS "malware?"
                FROM (SELECT id FROM intel_snapshot ORDER BY taken_at DESC LIMIT 1) s
                LEFT JOIN advisory_affected f ON f.ecosystem = $1 AND f.name = $2
                LEFT JOIN advisory a ON a.id = f.advisory_id
                ORDER BY a.id, f.version
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
            let records = rows
                .into_iter()
                .filter_map(|row| {
                    Some((
                        row.version,
                        Record {
                            advisory_id: row.advisory_id?,
                            source: row.source?,
                            cvss: row.cvss,
                            cvss_source: row.cvss_source,
                            exploited: row.exploited?,
                            malware: row.malware?,
                        },
                    ))
                })
                .collect();
            Ok(Some(PackageIntel { snapshot, records }))
        })
    }
}
