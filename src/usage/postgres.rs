//! [`Use`] rows over Postgres, in the database the intel store uses. Tested by
//! `tests/postgres.rs`.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use sqlx::PgPool;

use super::{Collapsed, Use};
use crate::util::batched::{Batched, Sink};

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
