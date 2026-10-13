//! `byrle account` and `byrle token`: what each prints and exits with, against any
//! [`Accounts`], and the account event log lines for what each changed.

use super::events::{AccountEvent, Action};
use super::{AccountError, Accounts, Name, Role, TokenDigest};

/// What a command printed and exits with.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
    /// What it changed, for the account event log.
    pub events: Vec<AccountEvent>,
}

impl Outcome {
    fn done(stdout: String, events: Vec<AccountEvent>) -> Self {
        Self {
            code: 0,
            stdout,
            stderr: String::new(),
            events,
        }
    }

    fn refused(e: &AccountError) -> Self {
        Self {
            code: 1,
            stdout: String::new(),
            stderr: format!("{e}\n"),
            events: Vec::new(),
        }
    }
}

/// Create `name` holding `roles`. Logged as `account-created`, then `role-granted` for
/// each role.
pub async fn create_account(store: &dyn Accounts, name: &Name, roles: &[Role]) -> Outcome {
    match store.create_account(name, roles).await {
        Ok(()) => {
            Outcome::done(
                format!("account {name} created\n"),
                std::iter::once(AccountEvent::by_cli(Action::AccountCreated, name))
                    .chain(super::sorted(roles).into_iter().map(|role| {
                        AccountEvent::by_cli(Action::RoleGranted, name).with_role(role)
                    }))
                    .collect(),
            )
        }
        Err(e) => Outcome::refused(&e),
    }
}

pub async fn disable_account(store: &dyn Accounts, name: &Name) -> Outcome {
    match store.disable_account(name).await {
        Ok(()) => Outcome::done(
            format!("account {name} disabled; its tokens no longer work\n"),
            vec![AccountEvent::by_cli(Action::AccountDisabled, name)],
        ),
        Err(e) => Outcome::refused(&e),
    }
}

/// Set `name`'s console password to `password`, of `min_chars` or more, hashed with
/// `hasher`. Logged as `password-set`, without the password.
pub async fn set_password(
    store: &dyn Accounts,
    name: &Name,
    password: &str,
    (min_chars, hasher): (usize, &super::password::Hasher),
) -> Outcome {
    let hash = match super::password::acceptable(password, min_chars) {
        Ok(password) => hasher.hash(password),
        Err(why) => {
            return Outcome {
                code: 1,
                stdout: String::new(),
                stderr: format!("{why}\n"),
                events: Vec::new(),
            };
        }
    };
    match store.set_password(name, &hash).await {
        Ok(()) => Outcome::done(
            format!("password of account {name} set\n"),
            vec![AccountEvent::by_cli(Action::PasswordSet, name)],
        ),
        Err(e) => Outcome::refused(&e),
    }
}

/// One line per account: name, roles or `-`, created, and disabled or `-`.
pub async fn list_accounts(store: &dyn Accounts) -> Outcome {
    match store.accounts().await {
        Ok(accounts) => Outcome::done(
            table(
                ["ACCOUNT", "ROLES", "CREATED", "DISABLED"],
                accounts.iter().map(|a| {
                    let roles: Vec<&str> = a.roles.iter().map(|role| role.name()).collect();
                    [
                        a.name.to_string(),
                        or_dash(Some(roles.join(",")).filter(|r| !r.is_empty())),
                        a.created.clone(),
                        or_dash(a.disabled.clone()),
                    ]
                }),
            ),
            Vec::new(),
        ),
        Err(e) => Outcome::refused(&e),
    }
}

/// `outcome`, with what it changed appended to the account event log at `log`, when one
/// is set. A change made and not logged exits 1, and says so.
pub fn logged(outcome: Outcome, log: Option<&std::path::Path>) -> Outcome {
    match log
        .filter(|_| !outcome.events.is_empty())
        .map(|path| super::events::append(path, &outcome.events))
    {
        Some(Err(e)) => Outcome {
            code: 1,
            stderr: format!(
                "{}the change was made, and is not in the account event log: {e}\n",
                outcome.stderr
            ),
            ..outcome
        },
        _ => outcome,
    }
}

/// `value`, or `-` when there is none.
fn or_dash(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".into())
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
            events: vec![AccountEvent::by_cli(Action::TokenCreated, account).with_token(name)],
        },
        Err(e) => Outcome::refused(&e),
    }
}

pub async fn revoke_token(store: &dyn Accounts, account: &Name, name: &Name) -> Outcome {
    match store.revoke_token(account, name).await {
        Ok(()) => Outcome::done(
            format!("token {name} of account {account} revoked\n"),
            vec![AccountEvent::by_cli(Action::TokenRevoked, account).with_token(name)],
        ),
        Err(e) => Outcome::refused(&e),
    }
}

/// One line per token: account, name, created, and revoked or `-`.
pub async fn list_tokens(store: &dyn Accounts, account: Option<&Name>) -> Outcome {
    match store.tokens(account).await {
        Ok(tokens) => Outcome::done(
            table(
                ["ACCOUNT", "TOKEN", "CREATED", "REVOKED"],
                tokens.iter().map(|t| {
                    [
                        t.account.to_string(),
                        t.name.to_string(),
                        t.created.clone(),
                        or_dash(t.revoked.clone()),
                    ]
                }),
            ),
            Vec::new(),
        ),
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

    /// Each event's action and role, which is what varies between commands.
    fn actions(outcome: &Outcome) -> Vec<(Action, Option<String>)> {
        outcome
            .events
            .iter()
            .map(|event| (event.action, event.role.clone()))
            .collect()
    }

    #[tokio::test]
    async fn an_account_is_created_listed_and_disabled() {
        let store = InMemory::new(NOW);
        let ci = name("ci");
        let created = create_account(&store, &ci, &[]).await;
        assert_eq!(created.stdout, "account ci created\n");
        assert_eq!(actions(&created), [(Action::AccountCreated, None)]);
        let again = create_account(&store, &ci, &[Role::Admin]).await;
        assert_eq!(
            (again.code, again.stderr.as_str()),
            (1, "account ci already exists\n")
        );
        assert!(again.events.is_empty());
        let admin = create_account(&store, &name("alice"), &[Role::Admin, Role::Admin]).await;
        assert_eq!(
            actions(&admin),
            [
                (Action::AccountCreated, None),
                (Action::RoleGranted, Some("admin".into()))
            ]
        );
        assert_eq!(
            list_accounts(&store).await.stdout,
            "ACCOUNT  ROLES  CREATED               DISABLED\n\
             alice    admin  2026-10-11T00:00:00Z  -\n\
             ci       -      2026-10-11T00:00:00Z  -\n"
        );
        let disabled = disable_account(&store, &ci).await;
        assert_eq!(disabled.code, 0);
        assert_eq!(actions(&disabled), [(Action::AccountDisabled, None)]);
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
        create_account(&store, &ci, &[]).await;
        let made = create_token(&store, &ci, &laptop).await;
        assert_eq!(made.code, 0);
        assert_eq!(actions(&made), [(Action::TokenCreated, None)]);
        assert_eq!(made.events[0].token.as_deref(), Some("laptop"));
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
        let revoked = revoke_token(&store, &ci, &laptop).await;
        assert_eq!(revoked.stdout, "token laptop of account ci revoked\n");
        assert_eq!(actions(&revoked), [(Action::TokenRevoked, None)]);
        assert_eq!(store.holder(&digest).await.unwrap(), None);
        assert_eq!(revoke_token(&store, &ci, &name("phone")).await.code, 1);
        assert_eq!(list_tokens(&store, Some(&name("nobody"))).await.code, 1);
        assert_eq!(list_tokens(&store, None).await.stdout.lines().count(), 2);
    }

    /// The events are appended when there is a log; a log that cannot be written fails the
    /// command after the change, and a command that changed nothing writes nothing.
    #[tokio::test]
    async fn what_a_command_changed_is_appended_to_the_event_log() {
        let dir = crate::util::test_support::tempdir("account-command-log");
        let path = dir.join("events.log");
        let store = InMemory::new(NOW);
        let created = logged(create_account(&store, &name("ci"), &[]).await, Some(&path));
        assert_eq!(created.code, 0);
        let listed = logged(list_accounts(&store).await, Some(&dir.join("x/y")));
        assert_eq!(listed.code, 0);
        assert_eq!(
            logged(disable_account(&store, &name("ci")).await, None).code,
            0
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

        let unwritable = dir.join("missing").join("events.log");
        let failed = logged(
            create_account(&store, &name("alice"), &[]).await,
            Some(&unwritable),
        );
        assert_eq!(failed.code, 1);
        assert_eq!(failed.stdout, "account alice created\n");
        assert!(
            failed
                .stderr
                .starts_with("the change was made, and is not in the account event log"),
            "{}",
            failed.stderr
        );
    }

    /// The password is stored as its hash and logged without it; one too short is
    /// refused before the store is asked.
    #[tokio::test]
    async fn a_password_is_stored_as_its_hash() {
        let store = InMemory::new(NOW);
        let alice = name("alice");
        let hasher = crate::account::password::tests::cheap();
        create_account(&store, &alice, &[]).await;
        let set = set_password(&store, &alice, "correct horse battery", (15, &hasher)).await;
        assert_eq!(set.stdout, "password of account alice set\n");
        assert_eq!(actions(&set), [(Action::PasswordSet, None)]);
        let stored = store.password(&alice).await.unwrap().unwrap();
        assert!(hasher.verify("correct horse battery", &stored));
        assert!(
            !serde_json::to_string(&set.events)
                .unwrap()
                .contains("horse")
        );

        let short = set_password(&store, &alice, "short", (15, &hasher)).await;
        assert_eq!(short.code, 1);
        assert!(
            short.stderr.contains("needs at least 15"),
            "{}",
            short.stderr
        );
        assert!(short.events.is_empty());
        assert_eq!(store.password(&alice).await.unwrap(), Some(stored));
        let nobody = name("nobody");
        let missing = set_password(&store, &nobody, "correct horse battery", (15, &hasher)).await;
        assert_eq!(missing.stderr, "account nobody does not exist\n");
    }

    /// A store that cannot answer fails every command with its reason.
    #[tokio::test]
    async fn a_store_that_cannot_answer_fails_each_command() {
        use crate::account::testing::Down;
        let ci = name("ci");
        for failed in [
            create_account(&Down, &ci, &[]).await,
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
