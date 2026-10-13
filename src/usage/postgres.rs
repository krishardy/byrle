//! [`Use`] rows over Postgres, in the database the intel store uses. Tested by
//! `tests/postgres.rs`.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use sqlx::PgPool;

use super::{Collapsed, FailureQuery, FailureRow, Read, ServedQuery, ServedRow, Usage, Use};
use crate::util::batched::{Batched, Sink};

/// The usage tables beside `intel`'s store, to read, when there is one.
pub fn reader(intel: Option<&crate::intel::postgres::PgIntel>) -> Option<Arc<dyn Usage>> {
    intel.map(|intel| Arc::new(PgUsage::new(intel.pool().clone())) as Arc<dyn Usage>)
}

/// The queue into the usage tables beside `intel`'s store, when there is one.
pub fn queue(intel: Option<&crate::intel::postgres::PgIntel>) -> Option<Batched<Use>> {
    intel.map(|intel| Batched::new("usage rows", Arc::new(PgUsage::new(intel.pool().clone()))))
}

#[derive(Debug, Clone)]
pub struct PgUsage {
    pool: PgPool,
}

impl PgUsage {
    /// Over `pool`, which the intel store has migrated.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Merge `rows` into `served_version` and `failure_count`, in one transaction.
    pub async fn write(&self, rows: &[Use]) -> Result<(), sqlx::Error> {
        let Collapsed { served, failed } = Collapsed::of(rows);
        let mut served_columns: (Vec<_>, Vec<_>, Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
            Default::default();
        for ((account, ecosystem, name, version), (first, last)) in served {
            served_columns.0.push(account);
            served_columns.1.push(ecosystem);
            served_columns.2.push(name);
            served_columns.3.push(version);
            served_columns.4.push(first.to_string());
            served_columns.5.push(last.to_string());
        }
        let mut failed_columns: (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = Default::default();
        for ((hour, ecosystem, answered), count) in failed {
            failed_columns.0.push(hour.to_string());
            failed_columns.1.push(ecosystem);
            failed_columns.2.push(answered.name());
            failed_columns.3.push(count);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query!(
            r#"
            INSERT INTO served_version
                (account, ecosystem, name, version, first_served, last_served)
            SELECT account, ecosystem, name, version, first::timestamptz, last::timestamptz
            FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
                AS u (account, ecosystem, name, version, first, last)
            ON CONFLICT (account, ecosystem, name, version) DO UPDATE SET
                first_served = LEAST(served_version.first_served, EXCLUDED.first_served),
                last_served  = GREATEST(served_version.last_served, EXCLUDED.last_served)
            "#,
            &served_columns.0 as &[Option<String>],
            &served_columns.1,
            &served_columns.2,
            &served_columns.3,
            &served_columns.4,
            &served_columns.5,
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query!(
            r#"
            INSERT INTO failure_count (hour, ecosystem, answered, count)
            SELECT hour::timestamptz, ecosystem, answered, count
            FROM UNNEST($1::text[], $2::text[], $3::text[], $4::bigint[])
                AS u (hour, ecosystem, answered, count)
            ON CONFLICT (hour, ecosystem, answered) DO UPDATE SET
                count = failure_count.count + EXCLUDED.count
            "#,
            &failed_columns.0,
            &failed_columns.1,
            &failed_columns.2,
            &failed_columns.3,
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await
    }
}

impl Sink<Use> for PgUsage {
    fn put<'a>(&'a self, rows: &'a [Use]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.write(rows).await.map_err(|e| e.to_string()) })
    }
}

impl Usage for PgUsage {
    fn served<'a>(&'a self, query: &'a ServedQuery) -> Read<'a, Vec<ServedRow>> {
        Box::pin(async move {
            sqlx::query_as!(
                ServedRow,
                r#"
                SELECT id, account, ecosystem, name, version,
                    to_char(first_served AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "first_served!",
                    to_char(last_served AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "last_served!"
                FROM served_version
                WHERE id > $1
                    AND ($2::text IS NULL OR ecosystem = $2)
                    AND ($3::text IS NULL OR name = $3)
                    AND ($4::text IS NULL OR account = $4)
                    AND ($5::text IS NULL OR last_served >= $5::text::timestamptz)
                    AND ($6::text IS NULL OR first_served < $6::text::timestamptz)
                ORDER BY id
                LIMIT $7
                "#,
                query.after,
                query.ecosystem,
                query.name,
                query.account,
                query.since.map(|at| at.to_string()),
                query.until.map(|at| at.to_string()),
                i64::from(query.limit),
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn failures<'a>(&'a self, query: &'a FailureQuery) -> Read<'a, Vec<FailureRow>> {
        Box::pin(async move {
            sqlx::query_as!(
                FailureRow,
                r#"
                SELECT to_char(hour AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "hour!",
                    ecosystem, answered, count
                FROM failure_count
                WHERE hour >= $1::text::timestamptz AND hour < $2::text::timestamptz
                    AND ($3::text IS NULL OR ecosystem = $3)
                    AND ($4::text IS NULL OR answered = $4)
                ORDER BY hour, ecosystem, answered
                "#,
                query.since.to_string(),
                query.until.to_string(),
                query.ecosystem,
                query.answered,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())
        })
    }
}
