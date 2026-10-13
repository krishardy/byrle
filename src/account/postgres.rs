//! [`Accounts`] over Postgres, in the database the intel store uses. Tested by
//! `tests/postgres.rs`.

use super::{
    Account, AccountError, Accounts, Caller, Holder, Name, Pending, Role, Token, TokenDigest,
};
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

/// The roles in `names` this build knows, sorted. A role a later build added is skipped.
fn known(names: &[String]) -> Vec<Role> {
    super::sorted(
        &names
            .iter()
            .filter_map(|name| Role::parse(name).ok())
            .collect::<Vec<_>>(),
    )
}

/// `Exists` for a unique violation, else the backend's error.
fn unique_or_backend(e: sqlx::Error, what: String) -> AccountError {
    match e.as_database_error() {
        Some(d) if d.is_unique_violation() => AccountError::Exists(what),
        _ => backend(e),
    }
}

impl Accounts for PgAccounts {
    fn create_account<'a>(&'a self, name: &'a Name, roles: &'a [Role]) -> Pending<'a, ()> {
        Box::pin(async move {
            let roles: Vec<String> = roles.iter().map(|role| role.name().to_owned()).collect();
            sqlx::query!(
                r#"
                WITH created AS (INSERT INTO account (name) VALUES ($1) RETURNING id)
                INSERT INTO account_role (account_id, role)
                SELECT created.id, role FROM created, (SELECT DISTINCT UNNEST($2::text[]) AS role) AS r
                "#,
                name.as_str(),
                &roles,
            )
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
                    a.name,
                    to_char(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "created!",
                    to_char(a.disabled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS disabled,
                    ARRAY(SELECT role::text FROM account_role r WHERE r.account_id = a.id ORDER BY role)
                        AS "roles!"
                FROM account a
                ORDER BY a.name
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
                    roles: known(&row.roles),
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

    fn set_password<'a>(&'a self, account: &'a Name, hash: &'a str) -> Pending<'a, ()> {
        Box::pin(async move {
            let done = sqlx::query!(
                r#"
                INSERT INTO account_password (account_id, hash)
                SELECT id, $2 FROM account WHERE name = $1
                ON CONFLICT (account_id) DO UPDATE SET hash = EXCLUDED.hash, set_at = now()
                "#,
                account.as_str(),
                hash,
            )
            .execute(&self.pool)
            .await
            .map_err(backend)?;
            if done.rows_affected() == 0 {
                return Err(super::no_account(account));
            }
            Ok(())
        })
    }

    fn password<'a>(&'a self, account: &'a Name) -> Pending<'a, Option<String>> {
        Box::pin(async move {
            sqlx::query_scalar!(
                r#"
                SELECT p.hash FROM account_password p JOIN account a ON a.id = p.account_id
                WHERE a.name = $1 AND a.disabled_at IS NULL
                "#,
                account.as_str(),
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)
        })
    }

    fn roles<'a>(&'a self, account: &'a Name) -> Pending<'a, Vec<Role>> {
        Box::pin(async move {
            sqlx::query_scalar!(
                r#"
                SELECT r.role::text AS "role!" FROM account_role r JOIN account a ON a.id = r.account_id
                WHERE a.name = $1 AND a.disabled_at IS NULL
                "#,
                account.as_str(),
            )
            .fetch_all(&self.pool)
            .await
            .map(|names| known(&names))
            .map_err(backend)
        })
    }

    fn create_session<'a>(
        &'a self,
        account: &'a Name,
        digest: &'a TokenDigest,
        expires: &'a str,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query!("DELETE FROM session WHERE expires_at <= now()")
                .execute(&self.pool)
                .await
                .map_err(backend)?;
            let done = sqlx::query!(
                r#"
                INSERT INTO session (account_id, digest, expires_at)
                SELECT id, $2, $3::text::timestamptz FROM account WHERE name = $1
                "#,
                account.as_str(),
                digest.as_str(),
                expires,
            )
            .execute(&self.pool)
            .await
            .map_err(backend)?;
            if done.rows_affected() == 0 {
                return Err(super::no_account(account));
            }
            Ok(())
        })
    }

    fn session<'a>(&'a self, digest: &'a TokenDigest) -> Pending<'a, Option<Caller>> {
        Box::pin(async move {
            let row = sqlx::query!(
                r#"
                SELECT a.name,
                    ARRAY(SELECT role::text FROM account_role r WHERE r.account_id = a.id ORDER BY role)
                        AS "roles!"
                FROM session s JOIN account a ON a.id = s.account_id
                WHERE s.digest = $1 AND s.expires_at > now() AND a.disabled_at IS NULL
                "#,
                digest.as_str(),
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
            Ok(row.map(|row| Caller {
                account: stored(row.name),
                roles: known(&row.roles),
            }))
        })
    }

    fn end_session<'a>(&'a self, digest: &'a TokenDigest) -> Pending<'a, ()> {
        Box::pin(async move {
            sqlx::query!("DELETE FROM session WHERE digest = $1", digest.as_str())
                .execute(&self.pool)
                .await
                .map(drop)
                .map_err(backend)
        })
    }
}
