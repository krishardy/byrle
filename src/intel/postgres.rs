//! The Postgres implementation of [`Intel`].
//!
//! Queries are written as SQL and checked against the real schema at compile time by
//! `sqlx::query_as!`. A renamed column or a changed type is a compile error rather than a
//! runtime one. See `docs/engineering_decisions/storage-sqlx-postgres.md`.

use super::kev;
use super::load::{self, Encoded, Fetch, Kind};
use super::osv::Rows;
use super::range::Interval;
use super::refresh::StreamDigest;
use super::store::{Intel, IntelError, LoadedSnapshot, Lookup, PackageIntel, Record};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;

/// Bytes per `CopyData` message. Postgres accepts far larger; this bounds what one send
/// holds in flight.
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
    /// The rows `encoded` encodes when it contains advisories, which the other tables are built
    /// from once Postgres has keyed them. Empty for exploited ids.
    pub rows: &'a [Rows],
    /// The bundles the rows were read from. Recorded, and part of no digest.
    pub streams: &'a [StreamDigest],
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
            &fetch.taken_at,
        )
        .await
    }

    /// Replace everything each source supplied with its rows, and record the snapshot the store
    /// contains after it. `taken_at` is RFC 3339 UTC.
    ///
    /// One transaction, so one refresh records one snapshot. A lookup during the load reads the
    /// previous rows, because Postgres shows a transaction's writes to nobody else until it
    /// commits, and a load that fails at any step leaves them in place. Deleting by source
    /// rather than swapping whole tables leaves other sources' rows alone. The alias, affected
    /// and range rows go with their advisory by `ON DELETE CASCADE`.
    ///
    /// For advisories, `advisory` is copied first. The keys Postgres assigned are read back in
    /// the same transaction, and the other tables are copied carrying them. Exploited ids are
    /// one table, copied as encoded.
    ///
    /// The snapshot id is hashed from every source's `intel_source.digest`. The transaction
    /// locks `intel_source` first, so a refresh of another source waits for this one to
    /// commit and then reads this source's new digest.
    ///
    /// A snapshot id already recorded, which is the same rows loaded again, keeps its row and
    /// takes the new `taken_at` and streams.
    pub async fn replace(
        &self,
        sources: &[Replacement<'_>],
        taken_at: &str,
    ) -> Result<Loaded, IntelError> {
        let mut tx = self.pool.begin().await.map_err(IntelError::Backend)?;

        // SHARE ROW EXCLUSIVE conflicts with itself and with any write to the table, and not
        // with a read.
        sqlx::query!("LOCK TABLE intel_source IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        let (mut advisories, mut aliases, mut affected, mut ranges, mut exploited) =
            (0, 0, 0, 0, 0);
        for replacement in sources {
            let encoded = replacement.encoded;
            let source = encoded.source.as_str();
            // Both tables, so a source is replaced whole whichever kind it was before.
            sqlx::query!("DELETE FROM advisory WHERE source = $1", source)
                .execute(&mut *tx)
                .await
                .map_err(IntelError::Backend)?;
            sqlx::query!("DELETE FROM exploited_cve WHERE source = $1", source)
                .execute(&mut *tx)
                .await
                .map_err(IntelError::Backend)?;
            match encoded.kind {
                Kind::Exploited => {
                    exploited += copy(&mut tx, load::EXPLOITED, &encoded.first_table).await?;
                }
                Kind::Advisories => {
                    advisories += copy(&mut tx, load::ADVISORY, &encoded.first_table).await?;
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
                    let children = load::children(replacement.rows, &keys).map_err(
                        |load::Unkeyed(advisory_id)| IntelError::Unkeyed { advisory_id },
                    )?;
                    aliases += copy(&mut tx, load::ALIAS, &children.alias).await?;
                    affected += copy(&mut tx, load::AFFECTED, &children.affected).await?;
                    ranges += copy(&mut tx, load::RANGE, &children.range).await?;
                }
            }

            // `::text` first, so the parameters are text and sqlx needs no date or JSON type.
            sqlx::query!(
                "INSERT INTO intel_source (source, digest, streams) \
                 VALUES ($1, $2, $3::text::jsonb) \
                 ON CONFLICT (source) DO UPDATE \
                 SET digest = EXCLUDED.digest, streams = EXCLUDED.streams",
                source,
                encoded.digest,
                load::streams_json(replacement.streams)
            )
            .execute(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        }
        let sources = sqlx::query!("SELECT source, digest FROM intel_source")
            .fetch_all(&mut *tx)
            .await
            .map_err(IntelError::Backend)?;
        let manifest = load::manifest(
            sources
                .iter()
                .map(|s| (s.source.as_str(), s.digest.as_str())),
        );
        let snapshot = load::snapshot_id(&manifest);
        // With no stream recorded, the aggregate is NULL and the column is not.
        sqlx::query!(
            "INSERT INTO intel_snapshot (digest, taken_at, streams) \
             SELECT $1, $2::text::timestamptz, COALESCE(jsonb_object_agg(e.key, e.value), '{}') \
             FROM intel_source s CROSS JOIN LATERAL jsonb_each(s.streams) e \
             ON CONFLICT (digest) DO UPDATE \
             SET taken_at = EXCLUDED.taken_at, streams = EXCLUDED.streams",
            snapshot,
            taken_at
        )
        .execute(&mut *tx)
        .await
        .map_err(IntelError::Backend)?;

        tx.commit().await.map_err(IntelError::Backend)?;
        Ok(Loaded {
            advisories,
            aliases,
            affected,
            ranges,
            exploited,
            snapshot,
            manifest,
        })
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

    fn snapshot(&self) -> Lookup<'_, Option<LoadedSnapshot>> {
        Box::pin(async move {
            // One row per stream of the newest snapshot, or one row with no stream when it
            // records none.
            let rows = sqlx::query!(
                r#"
                SELECT
                    s.digest AS "digest!",
                    to_char(s.taken_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                        AS "taken_at!",
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
                // Refresh records a sha256 for every stream, so one without is not reported
                // as if it had been verified.
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
            // One statement, so the snapshot id and the rows are read from the same
            // committed state. A refresh replaces both in one transaction, and a second
            // query could see the other side of it.
            //
            // `m` is every version-shaped row for the package: listed versions and every
            // version from `advisory_affected`, intervals from `advisory_range`.
            //
            // An advisory is exploited when its id or an alias is in `exploited_cve`, the same
            // match as `intel::is_named`.
            let rows = sqlx::query!(
                r#"
                SELECT
                    s.digest        AS "snapshot!",
                    EXISTS (SELECT 1 FROM intel_source WHERE source = $3)
                                    AS "exploitation_loaded!",
                    m.is_range      AS "is_range?",
                    m.version       AS "version?",
                    m.introduced    AS "introduced?",
                    m.fixed         AS "fixed?",
                    m.last_affected AS "last_affected?",
                    a.publisher_id  AS "advisory_id?",
                    a.source        AS "source?",
                    a.cvss          AS "cvss?",
                    a.cvss_source   AS "cvss_source?",
                    (a.exploited OR EXISTS (
                        SELECT 1 FROM exploited_cve k
                        WHERE k.cve_id = a.publisher_id
                           OR k.cve_id IN (
                               SELECT al.alias FROM advisory_alias al WHERE al.advisory_id = a.id
                           )
                    ))              AS "exploited?",
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
                name,
                kev::SOURCE
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
