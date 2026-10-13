//! Accounts, and the proxy tokens that identify them on each request. The tokens are stored as
//! their SHA-256, so the store never contains one that works.
//!
//! See docs/engineering_decisions/account-identification.md and docs/admin-plan.md §4.1.

pub mod command;
pub mod events;
pub mod gate;
pub mod postgres;
pub mod role;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

pub use role::{Permission, Role};

/// What every token starts with, so a secret scanner can find one where it should not be.
pub const TOKEN_PREFIX: &str = "byrle_";

/// Random bytes in a token: 256 bits.
const TOKEN_BYTES: usize = 32;

/// The longest account or token name.
pub const MAX_NAME: usize = 64;

/// An account's or token's name: 1 to [`MAX_NAME`] of `a-z0-9._-`, nothing a URL escapes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    pub fn parse(name: &str) -> Result<Name, String> {
        let starts = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest = name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
        if starts && rest && name.len() <= MAX_NAME {
            Ok(Name(name.to_owned()))
        } else {
            Err(format!(
                "`{name}` is not a name: 1 to {MAX_NAME} of a-z, 0-9, `.`, `_` and `-`, \
                 starting with a letter or digit"
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A token's SHA-256, in lowercase hex: what the store keeps and looks a token up by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenDigest(String);

impl TokenDigest {
    pub fn of(token: &str) -> TokenDigest {
        TokenDigest(crate::util::hex(&Sha256::digest(token.as_bytes())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A new token: [`TOKEN_PREFIX`] and 32 random bytes, base64url without padding. Shown
/// once, when it is made.
pub fn issue() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).expect("the operating system supplies random bytes");
    format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// One account, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: Name,
    /// RFC 3339, UTC.
    pub created: String,
    /// When it was disabled. Its tokens stop working then.
    pub disabled: Option<String>,
    /// Its roles, sorted.
    pub roles: Vec<Role>,
}

/// One token, as listed. The token itself is never held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub account: Name,
    pub name: Name,
    /// RFC 3339, UTC.
    pub created: String,
    pub revoked: Option<String>,
}

/// Who a token that works belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub account: Name,
    pub token: Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// An account, or a token of the account, already has the name.
    Exists(String),
    /// Nothing has the name.
    NotFound(String),
    /// The store could not answer.
    Backend(String),
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists(what) => write!(f, "{what} already exists"),
            Self::NotFound(what) => write!(f, "{what} does not exist"),
            Self::Backend(why) => write!(f, "the account store did not answer: {why}"),
        }
    }
}

/// A read or write in flight, boxed so a caller can hold a `dyn Accounts`.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, AccountError>> + Send + 'a>>;

/// Where accounts and tokens are kept.
pub trait Accounts: Send + Sync {
    /// Create an account holding `roles`, in one write.
    fn create_account<'a>(&'a self, name: &'a Name, roles: &'a [Role]) -> Pending<'a, ()>;

    /// Disable an account, which stops each of its tokens. Disabling one already disabled
    /// keeps the first time.
    fn disable_account<'a>(&'a self, name: &'a Name) -> Pending<'a, ()>;

    /// Every account, by name.
    fn accounts(&self) -> Pending<'_, Vec<Account>>;

    /// Record a token for `account` under `name`, by its digest.
    fn create_token<'a>(
        &'a self,
        account: &'a Name,
        name: &'a Name,
        digest: &'a TokenDigest,
    ) -> Pending<'a, ()>;

    /// Revoke a token. Revoking one already revoked keeps the first time.
    fn revoke_token<'a>(&'a self, account: &'a Name, name: &'a Name) -> Pending<'a, ()>;

    /// Every token, or `account`'s, by account and name.
    fn tokens<'a>(&'a self, account: Option<&'a Name>) -> Pending<'a, Vec<Token>>;

    /// Whose token has this digest. `None` for a token that is unknown, one revoked,
    /// or one whose account is disabled.
    fn holder<'a>(&'a self, digest: &'a TokenDigest) -> Pending<'a, Option<Holder>>;
}

/// Accounts held in memory, for tests. Every time is the one given at construction.
pub struct InMemory {
    now: String,
    held: Mutex<Held>,
}

#[derive(Default)]
struct Held {
    accounts: BTreeMap<Name, Account>,
    tokens: BTreeMap<(Name, Name), (Token, TokenDigest)>,
}

impl InMemory {
    pub fn new(now: &str) -> Self {
        Self {
            now: now.to_owned(),
            held: Mutex::default(),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().expect("account store lock")
    }

    fn ready<T: Send + 'static>(result: Result<T, AccountError>) -> Pending<'static, T> {
        Box::pin(std::future::ready(result))
    }
}

/// `roles` sorted, each once.
fn sorted(roles: &[Role]) -> Vec<Role> {
    let roles: std::collections::BTreeSet<Role> = roles.iter().copied().collect();
    roles.into_iter().collect()
}

fn no_account(name: &Name) -> AccountError {
    AccountError::NotFound(format!("account {name}"))
}

fn no_token(account: &Name, name: &Name) -> AccountError {
    AccountError::NotFound(format!("token {name} of account {account}"))
}

impl Accounts for InMemory {
    fn create_account<'a>(&'a self, name: &'a Name, roles: &'a [Role]) -> Pending<'a, ()> {
        let mut held = self.held();
        Self::ready(if held.accounts.contains_key(name) {
            Err(AccountError::Exists(format!("account {name}")))
        } else {
            let account = Account {
                name: name.clone(),
                created: self.now.clone(),
                disabled: None,
                roles: sorted(roles),
            };
            held.accounts.insert(name.clone(), account);
            Ok(())
        })
    }

    fn disable_account<'a>(&'a self, name: &'a Name) -> Pending<'a, ()> {
        let mut held = self.held();
        Self::ready(match held.accounts.get_mut(name) {
            Some(account) => {
                account.disabled.get_or_insert_with(|| self.now.clone());
                Ok(())
            }
            None => Err(no_account(name)),
        })
    }

    fn accounts(&self) -> Pending<'_, Vec<Account>> {
        Self::ready(Ok(self.held().accounts.values().cloned().collect()))
    }

    fn create_token<'a>(
        &'a self,
        account: &'a Name,
        name: &'a Name,
        digest: &'a TokenDigest,
    ) -> Pending<'a, ()> {
        let mut held = self.held();
        if !held.accounts.contains_key(account) {
            return Self::ready(Err(no_account(account)));
        }
        let token = Token {
            account: account.clone(),
            name: name.clone(),
            created: self.now.clone(),
            revoked: None,
        };
        Self::ready(match held.tokens.entry((account.clone(), name.clone())) {
            std::collections::btree_map::Entry::Occupied(_) => Err(AccountError::Exists(format!(
                "token {name} of account {account}"
            ))),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert((token, digest.clone()));
                Ok(())
            }
        })
    }

    fn revoke_token<'a>(&'a self, account: &'a Name, name: &'a Name) -> Pending<'a, ()> {
        let mut held = self.held();
        Self::ready(
            match held.tokens.get_mut(&(account.clone(), name.clone())) {
                Some((token, _)) => {
                    token.revoked.get_or_insert_with(|| self.now.clone());
                    Ok(())
                }
                None => Err(no_token(account, name)),
            },
        )
    }

    fn tokens<'a>(&'a self, account: Option<&'a Name>) -> Pending<'a, Vec<Token>> {
        let held = self.held();
        Self::ready(match account {
            Some(name) if !held.accounts.contains_key(name) => Err(no_account(name)),
            _ => Ok(held
                .tokens
                .values()
                .map(|(token, _)| token)
                .filter(|token| account.is_none_or(|name| &token.account == name))
                .cloned()
                .collect()),
        })
    }

    fn holder<'a>(&'a self, digest: &'a TokenDigest) -> Pending<'a, Option<Holder>> {
        let held = self.held();
        let found = held
            .tokens
            .values()
            .find(|(token, held_digest)| held_digest == digest && token.revoked.is_none())
            .filter(|(token, _)| {
                held.accounts
                    .get(&token.account)
                    .is_some_and(|account| account.disabled.is_none())
            })
            .map(|(token, _)| Holder {
                account: token.account.clone(),
                token: token.name.clone(),
            });
        Self::ready(Ok(found))
    }
}

/// Stores for tests elsewhere in the crate.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod testing {
    use super::*;

    /// A store that cannot answer: each call fails as a closed connection does.
    pub struct Down;

    fn closed<'a, T: Send + 'a>() -> Pending<'a, T> {
        Box::pin(async { Err(AccountError::Backend("closed".into())) })
    }

    impl Accounts for Down {
        fn create_account<'a>(&'a self, _: &'a Name, _: &'a [Role]) -> Pending<'a, ()> {
            closed()
        }
        fn disable_account<'a>(&'a self, _: &'a Name) -> Pending<'a, ()> {
            closed()
        }
        fn accounts(&self) -> Pending<'_, Vec<Account>> {
            closed()
        }
        fn create_token<'a>(
            &'a self,
            _: &'a Name,
            _: &'a Name,
            _: &'a TokenDigest,
        ) -> Pending<'a, ()> {
            closed()
        }
        fn revoke_token<'a>(&'a self, _: &'a Name, _: &'a Name) -> Pending<'a, ()> {
            closed()
        }
        fn tokens<'a>(&'a self, _: Option<&'a Name>) -> Pending<'a, Vec<Token>> {
            closed()
        }
        fn holder<'a>(&'a self, _: &'a TokenDigest) -> Pending<'a, Option<Holder>> {
            closed()
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    pub(crate) fn name(s: &str) -> Name {
        Name::parse(s).expect("a valid name")
    }

    #[test]
    fn a_name_is_lowercase_letters_digits_dots_underscores_and_dashes() {
        for valid in [
            "ci",
            "alice",
            "build-01",
            "a.b_c-d",
            "0day",
            &"a".repeat(MAX_NAME),
        ] {
            assert_eq!(name(valid).as_str(), valid);
        }
        for invalid in [
            "",
            "-ci",
            ".ci",
            "Alice",
            "a b",
            "a:b",
            "a@b",
            &"a".repeat(MAX_NAME + 1),
        ] {
            let refused = Name::parse(invalid).unwrap_err();
            assert!(refused.contains("is not a name"), "{invalid}: {refused}");
        }
        assert_eq!(name("ci").to_string(), "ci");
    }

    #[test]
    fn a_token_is_the_prefix_and_43_url_safe_characters_and_never_repeats() {
        let first = issue();
        let second = issue();
        assert_ne!(first, second);
        let random = first.strip_prefix(TOKEN_PREFIX).expect("prefixed");
        assert_eq!(random.len(), 43);
        assert!(
            random
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn a_digest_is_the_sha256_in_hex() {
        assert_eq!(
            TokenDigest::of("abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn each_error_names_what_it_is_about() {
        assert_eq!(
            AccountError::Exists("account ci".into()).to_string(),
            "account ci already exists"
        );
        assert_eq!(
            no_token(&name("ci"), &name("laptop")).to_string(),
            "token laptop of account ci does not exist"
        );
        assert_eq!(
            AccountError::Backend("closed".into()).to_string(),
            "the account store did not answer: closed"
        );
    }

    #[tokio::test]
    async fn a_token_identifies_its_holder_until_it_is_revoked_or_its_account_disabled() {
        let store = InMemory::new("2026-10-11T00:00:00Z");
        let (ci, alice, laptop) = (name("ci"), name("alice"), name("laptop"));
        store.create_account(&ci, &[]).await.unwrap();
        store.create_account(&alice, &[]).await.unwrap();
        let ci_token = TokenDigest::of("one");
        let alice_token = TokenDigest::of("two");
        store.create_token(&ci, &laptop, &ci_token).await.unwrap();
        store
            .create_token(&alice, &laptop, &alice_token)
            .await
            .unwrap();

        let holder = store.holder(&ci_token).await.unwrap().expect("held");
        assert_eq!((holder.account, holder.token), (ci.clone(), laptop.clone()));
        assert_eq!(store.holder(&TokenDigest::of("other")).await.unwrap(), None);

        store.revoke_token(&ci, &laptop).await.unwrap();
        assert_eq!(store.holder(&ci_token).await.unwrap(), None);
        store.disable_account(&alice).await.unwrap();
        assert_eq!(store.holder(&alice_token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn names_are_unique_and_unknown_names_are_not_found() {
        let store = InMemory::new("2026-10-11T00:00:00Z");
        let (ci, laptop, nobody) = (name("ci"), name("laptop"), name("nobody"));
        store.create_account(&ci, &[]).await.unwrap();
        assert_eq!(
            store.create_account(&ci, &[]).await,
            Err(AccountError::Exists("account ci".into()))
        );
        let digest = TokenDigest::of("t");
        store.create_token(&ci, &laptop, &digest).await.unwrap();
        assert!(matches!(
            store.create_token(&ci, &laptop, &digest).await,
            Err(AccountError::Exists(_))
        ));
        for refused in [
            store.create_token(&nobody, &laptop, &digest).await,
            store.disable_account(&nobody).await,
            store.revoke_token(&ci, &nobody).await,
        ] {
            assert!(
                matches!(refused, Err(AccountError::NotFound(_))),
                "{refused:?}"
            );
        }
        assert!(matches!(
            store.tokens(Some(&nobody)).await,
            Err(AccountError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn listing_shows_when_each_was_made_disabled_and_revoked() {
        let store = InMemory::new("2026-10-11T00:00:00Z");
        let (ci, alice, laptop) = (name("ci"), name("alice"), name("laptop"));
        store.create_account(&ci, &[]).await.unwrap();
        store.create_account(&alice, &[]).await.unwrap();
        store
            .create_token(&ci, &laptop, &TokenDigest::of("a"))
            .await
            .unwrap();
        store
            .create_token(&alice, &laptop, &TokenDigest::of("b"))
            .await
            .unwrap();
        store.disable_account(&ci).await.unwrap();
        store.disable_account(&ci).await.unwrap();
        store.revoke_token(&alice, &laptop).await.unwrap();
        store.revoke_token(&alice, &laptop).await.unwrap();

        let accounts = store.accounts().await.unwrap();
        let listed: Vec<(&str, Option<&str>)> = accounts
            .iter()
            .map(|a| (a.name.as_str(), a.disabled.as_deref()))
            .collect();
        assert_eq!(
            listed,
            [("alice", None), ("ci", Some("2026-10-11T00:00:00Z"))]
        );
        assert_eq!(store.tokens(None).await.unwrap().len(), 2);
        let alices = store.tokens(Some(&alice)).await.unwrap();
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].revoked.as_deref(), Some("2026-10-11T00:00:00Z"));
        assert_eq!(alices[0].created, "2026-10-11T00:00:00Z");
    }
}
