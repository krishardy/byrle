//! `byrle account` and `byrle token`: what each prints and exits with, against any
//! [`Accounts`].

use super::{AccountError, Accounts, Name, TokenDigest};

/// What a command printed and exits with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    fn done(stdout: String) -> Self {
        Self {
            code: 0,
            stdout,
            stderr: String::new(),
        }
    }

    fn refused(e: &AccountError) -> Self {
        Self {
            code: 1,
            stdout: String::new(),
            stderr: format!("{e}\n"),
        }
    }
}

pub async fn create_account(store: &dyn Accounts, name: &Name) -> Outcome {
    match store.create_account(name).await {
        Ok(()) => Outcome::done(format!("account {name} created\n")),
        Err(e) => Outcome::refused(&e),
    }
}

pub async fn disable_account(store: &dyn Accounts, name: &Name) -> Outcome {
    match store.disable_account(name).await {
        Ok(()) => Outcome::done(format!(
            "account {name} disabled; its tokens no longer work\n"
        )),
        Err(e) => Outcome::refused(&e),
    }
}

/// One line per account: name, created, and disabled or `-`.
pub async fn list_accounts(store: &dyn Accounts) -> Outcome {
    match store.accounts().await {
        Ok(accounts) => Outcome::done(table(
            ["ACCOUNT", "CREATED", "DISABLED"],
            accounts.iter().map(|a| {
                [
                    a.name.to_string(),
                    a.created.clone(),
                    a.disabled.clone().unwrap_or_else(|| "-".into()),
                ]
            }),
        )),
        Err(e) => Outcome::refused(&e),
    }
}

/// Make a token and print it, alone, on stdout. It is not shown again.
pub async fn create_token(store: &dyn Accounts, account: &Name, name: &Name) -> Outcome {
    let token = super::issue();
    match store
        .create_token(account, name, &TokenDigest::of(&token))
        .await
    {
        Ok(()) => Outcome {
            code: 0,
            stdout: format!("{token}\n"),
            stderr: format!(
                "token {name} of account {account} created. It is shown once; byrle keeps \
                 only its SHA-256\n"
            ),
        },
        Err(e) => Outcome::refused(&e),
    }
}

pub async fn revoke_token(store: &dyn Accounts, account: &Name, name: &Name) -> Outcome {
    match store.revoke_token(account, name).await {
        Ok(()) => Outcome::done(format!("token {name} of account {account} revoked\n")),
        Err(e) => Outcome::refused(&e),
    }
}

/// One line per token: account, name, created, and revoked or `-`.
pub async fn list_tokens(store: &dyn Accounts, account: Option<&Name>) -> Outcome {
    match store.tokens(account).await {
        Ok(tokens) => Outcome::done(table(
            ["ACCOUNT", "TOKEN", "CREATED", "REVOKED"],
            tokens.iter().map(|t| {
                [
                    t.account.to_string(),
                    t.name.to_string(),
                    t.created.clone(),
                    t.revoked.clone().unwrap_or_else(|| "-".into()),
                ]
            }),
        )),
        Err(e) => Outcome::refused(&e),
    }
}

/// `header` and `rows` in columns two spaces apart, each as wide as its widest cell.
fn table<const N: usize>(header: [&str; N], rows: impl Iterator<Item = [String; N]>) -> String {
    let rows: Vec<[String; N]> = std::iter::once(header.map(str::to_owned))
        .chain(rows)
        .collect();
    let widths: Vec<usize> = (0..N)
        .map(|i| rows.iter().map(|row| row[i].len()).max().unwrap_or(0))
        .collect();
    rows.iter()
        .map(|row| {
            let cells: Vec<String> = row
                .iter()
                .zip(&widths)
                .map(|(cell, width)| format!("{cell:width$}"))
                .collect();
            format!("{}\n", cells.join("  ").trim_end())
        })
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::InMemory;

    const NOW: &str = "2026-10-11T00:00:00Z";

    fn name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    #[tokio::test]
    async fn an_account_is_created_listed_and_disabled() {
        let store = InMemory::new(NOW);
        let ci = name("ci");
        assert_eq!(
            create_account(&store, &ci).await.stdout,
            "account ci created\n"
        );
        let again = create_account(&store, &ci).await;
        assert_eq!(
            (again.code, again.stderr.as_str()),
            (1, "account ci already exists\n")
        );
        assert_eq!(
            list_accounts(&store).await.stdout,
            "ACCOUNT  CREATED               DISABLED\nci       2026-10-11T00:00:00Z  -\n"
        );
        assert_eq!(disable_account(&store, &ci).await.code, 0);
        assert!(
            list_accounts(&store)
                .await
                .stdout
                .ends_with("2026-10-11T00:00:00Z\n")
        );
        assert_eq!(disable_account(&store, &name("nobody")).await.code, 1);
    }

    #[tokio::test]
    async fn a_token_is_printed_once_alone_and_works_until_revoked() {
        let store = InMemory::new(NOW);
        let (ci, laptop) = (name("ci"), name("laptop"));
        create_account(&store, &ci).await;
        let made = create_token(&store, &ci, &laptop).await;
        assert_eq!(made.code, 0);
        let token = made.stdout.trim_end();
        assert!(token.starts_with(crate::account::TOKEN_PREFIX));
        assert_eq!(made.stdout.lines().count(), 1);
        assert!(made.stderr.contains("shown once"), "{}", made.stderr);
        assert!(!made.stderr.contains(token));

        let digest = TokenDigest::of(token);
        assert!(store.holder(&digest).await.unwrap().is_some());
        assert_eq!(create_token(&store, &ci, &laptop).await.code, 1);
        assert_eq!(create_token(&store, &name("nobody"), &laptop).await.code, 1);

        let listed = list_tokens(&store, Some(&ci)).await.stdout;
        assert_eq!(
            listed,
            "ACCOUNT  TOKEN   CREATED               REVOKED\n\
             ci       laptop  2026-10-11T00:00:00Z  -\n"
        );
        assert!(!listed.contains(token));
        assert_eq!(
            revoke_token(&store, &ci, &laptop).await.stdout,
            "token laptop of account ci revoked\n"
        );
        assert_eq!(store.holder(&digest).await.unwrap(), None);
        assert_eq!(revoke_token(&store, &ci, &name("phone")).await.code, 1);
        assert_eq!(list_tokens(&store, Some(&name("nobody"))).await.code, 1);
        assert_eq!(list_tokens(&store, None).await.stdout.lines().count(), 2);
    }

    /// A store that cannot answer fails every command with its reason.
    #[tokio::test]
    async fn a_store_that_cannot_answer_fails_each_command() {
        use crate::account::testing::Down;
        let ci = name("ci");
        for failed in [
            create_account(&Down, &ci).await,
            disable_account(&Down, &ci).await,
            list_accounts(&Down).await,
            create_token(&Down, &ci, &ci).await,
            revoke_token(&Down, &ci, &ci).await,
            list_tokens(&Down, None).await,
        ] {
            assert_eq!(failed.code, 1);
            assert_eq!(failed.stderr, "the account store did not answer: closed\n");
        }
    }
}
