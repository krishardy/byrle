//! [`Accounts`] over Postgres, in the database the intel store uses. Tested by
//! `tests/postgres.rs`.

use super::{Account, AccountError, Accounts, Holder, Name, Pending, Token, TokenDigest};
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct PgAccounts {
    pool: PgPool,
}

/// The accounts kept beside `intel`'s store, when there is one.
pub fn store(
    intel: Option<&crate::intel::postgres::PgIntel>,
) -> Option<std::sync::Arc<dyn super::Accounts>> {
    intel.map(|intel| {
        std::sync::Arc::new(PgAccounts::new(intel.pool().clone()))
            as std::sync::Arc<dyn super::Accounts>
    })
}

impl PgAccounts {
    /// Over `pool`, which the intel store has migrated.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn backend(e: sqlx::Error) -> AccountError {
    AccountError::Backend(e.to_string())
}

/// A name read back from the table, which only [`Name::parse`]d names are written to.
fn stored(name: String) -> Name {
    Name(name)
}

/// `Exists` for a unique violation, else the backend's error.
fn unique_or_backend(e: sqlx::Error, what: String) -> AccountError {
    match e.as_database_error() {
        Some(d) if d.is_unique_violation() => AccountError::Exists(what),
        _ => backend(e),
    }
}

impl Accounts for PgAccounts {
    fn create_account<'a>(&'a self, name: &'a Name) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query!("INSERT INTO account (name) VALUES ($1)", name.as_str())
                .execute(&self.pool)
                .await
                .map(drop)
                .map_err(|e| unique_or_backend(e, format!("account {name}")))
        })
    }

    fn disable_account<'a>(&'a self, name: &'a Name) -> Pending<'a, ()> {
        Box::pin(async move {
            let done = sqlx::query!(
                "UPDATE account SET disabled_at = COALESCE(disabled_at, now()) WHERE name = $1",
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(backend)?;
            if done.rows_affected() == 0 {
                return Err(super::no_account(name));
            }
            Ok(())
        })
    }

    fn accounts(&self) -> Pending<'_, Vec<Account>> {
        Box::pin(async move {
            let rows = sqlx::query!(
                r#"
                SELECT
                    name,
                    to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "created!",
                    to_char(disabled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS disabled
                FROM account
                ORDER BY name
                "#
            )
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
            Ok(rows
                .into_iter()
                .map(|row| Account {
                    name: stored(row.name),
                    created: row.created,
                    disabled: row.disabled,
                })
                .collect())
        })
    }

    fn create_token<'a>(
        &'a self,
        account: &'a Name,
        name: &'a Name,
        digest: &'a TokenDigest,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            let done = sqlx::query!(
                r#"
                INSERT INTO proxy_token (account_id, name, digest)
                SELECT id, $2, $3 FROM account WHERE name = $1
                "#,
                account.as_str(),
                name.as_str(),
                digest.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(|e| unique_or_backend(e, format!("token {name} of account {account}")))?;
            if done.rows_affected() == 0 {
                return Err(super::no_account(account));
            }
            Ok(())
        })
    }

    fn revoke_token<'a>(&'a self, account: &'a Name, name: &'a Name) -> Pending<'a, ()> {
        Box::pin(async move {
            let done = sqlx::query!(
                r#"
                UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now())
                FROM account
                WHERE proxy_token.account_id = account.id
                  AND account.name = $1
                  AND proxy_token.name = $2
                "#,
                account.as_str(),
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(backend)?;
            if done.rows_affected() == 0 {
                return Err(super::no_token(account, name));
            }
            Ok(())
        })
    }

    fn tokens<'a>(&'a self, account: Option<&'a Name>) -> Pending<'a, Vec<Token>> {
        Box::pin(async move {
            if let Some(name) = account {
                let known = sqlx::query_scalar!(
                    r#"SELECT EXISTS (SELECT 1 FROM account WHERE name = $1) AS "known!""#,
                    name.as_str()
                )
                .fetch_one(&self.pool)
                .await
                .map_err(backend)?;
                if !known {
                    return Err(super::no_account(name));
                }
            }
            let rows = sqlx::query!(
                r#"
                SELECT
                    account.name AS account,
                    proxy_token.name,
                    to_char(proxy_token.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "created!",
                    to_char(proxy_token.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked
                FROM proxy_token
                JOIN account ON account.id = proxy_token.account_id
                WHERE $1::text IS NULL OR account.name = $1
                ORDER BY account.name, proxy_token.name
                "#,
                account.map(Name::as_str)
            )
            .fetch_all(&self.pool)
            .await
            .map_err(backend)?;
            Ok(rows
                .into_iter()
                .map(|row| Token {
                    account: stored(row.account),
                    name: stored(row.name),
                    created: row.created,
                    revoked: row.revoked,
                })
                .collect())
        })
    }

    fn holder<'a>(&'a self, digest: &'a TokenDigest) -> Pending<'a, Option<Holder>> {
        Box::pin(async move {
            let row = sqlx::query!(
                r#"
                SELECT account.name AS account, proxy_token.name
                FROM proxy_token
                JOIN account ON account.id = proxy_token.account_id
                WHERE proxy_token.digest = $1
                  AND proxy_token.revoked_at IS NULL
                  AND account.disabled_at IS NULL
                "#,
                digest.as_str()
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            Ok(row.map(|row| Holder {
                account: stored(row.account),
                token: stored(row.name),
            }))
        })
    }
}
