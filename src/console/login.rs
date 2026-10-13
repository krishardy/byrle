//! Console login: a password checked against its Argon2id hash, a limit on failures, and
//! the session a success starts. See docs/engineering_decisions/console-login.md.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::account::events::{AccountEvent, Action, EventLog};
use crate::account::password::{self, Hasher};
use crate::account::{Accounts, Caller, Name, TokenDigest};
use crate::util::lru::Lru;

/// Session length and failed-login limits, as [`crate::env::Env::login_limits`] reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// From login.
    pub session: jiff::SignedDuration,
    /// How far back failed logins are counted.
    pub window: Duration,
    /// Failed logins per account in the window before more are refused unchecked.
    pub per_account: usize,
    /// Failed logins per address in the window before more are refused unchecked.
    pub per_address: usize,
}

/// Passwords hashed at once, each on a blocking thread, off those answering requests.
const HASHING: usize = 2;

/// Accounts and addresses whose failures are kept; the least recently failed are dropped.
const TRACKED: usize = 10_000;

/// What failures are counted against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Account(String),
    /// An IPv4 address, or an IPv6 address's /64, which one client usually holds whole.
    Address(IpAddr),
}

impl Key {
    fn address(address: IpAddr) -> Key {
        Key::Address(match address {
            IpAddr::V4(_) => address,
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
        })
    }
}

/// Failed logins in the last window, by account and by address, in this process.
pub struct Limiter {
    limits: Limits,
    failures: Mutex<Lru<Key, Vec<Instant>>>,
}

impl Limiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            failures: Mutex::new(Lru::new(TRACKED)),
        }
    }

    /// The failures against `key` within the window of `now`.
    fn recent(
        &self,
        failures: &mut Lru<Key, Vec<Instant>>,
        key: &Key,
        now: Instant,
    ) -> Vec<Instant> {
        failures
            .get(key)
            .map(|times| {
                times
                    .iter()
                    .copied()
                    .filter(|at| now.saturating_duration_since(*at) < self.limits.window)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn keys(&self, account: &str, address: Option<IpAddr>) -> Vec<(Key, usize)> {
        std::iter::once((Key::Account(account.to_owned()), self.limits.per_account))
            .chain(address.map(|address| (Key::address(address), self.limits.per_address)))
            .collect()
    }

    /// The address's key and limit alone: an OIDC login names no account until it ends.
    fn from(&self, address: Option<IpAddr>) -> Vec<(Key, usize)> {
        address
            .map(|address| (Key::address(address), self.limits.per_address))
            .into_iter()
            .collect()
    }

    /// Whether each of `keys` is under its limit at `now`.
    fn under(&self, keys: &[(Key, usize)], now: Instant) -> bool {
        let mut failures = self.failures.lock().expect("limiter lock");
        keys.iter()
            .all(|(key, limit)| self.recent(&mut failures, key, now).len() < *limit)
    }

    /// Count a failure at `now` against each of `keys`.
    fn count(&self, keys: Vec<(Key, usize)>, now: Instant) {
        let mut failures = self.failures.lock().expect("limiter lock");
        for (key, _) in keys {
            let mut times = self.recent(&mut failures, &key, now);
            times.push(now);
            failures.insert(key, times);
        }
    }

    /// Whether a login as `account` from `address` may be checked at `now`.
    pub fn allows(&self, account: &str, address: Option<IpAddr>, now: Instant) -> bool {
        self.under(&self.keys(account, address), now)
    }

    /// Count a failed login as `account` from `address` at `now`.
    pub fn failed(&self, account: &str, address: Option<IpAddr>, now: Instant) {
        self.count(self.keys(account, address), now);
    }

    /// Whether an OIDC login from `address` may go on at `now`.
    pub fn allows_from(&self, address: Option<IpAddr>, now: Instant) -> bool {
        self.under(&self.from(address), now)
    }

    /// Count a failed OIDC login from `address` at `now`.
    pub fn failed_from(&self, address: Option<IpAddr>, now: Instant) {
        self.count(self.from(address), now);
    }
}

/// A login that succeeded: the session's id, which only the cookie holds, and whose it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub id: String,
    pub caller: Caller,
    /// When the session ends.
    pub expires: jiff::Timestamp,
}

/// What a login attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Attempt {
    Started(Started),
    /// The account, the password, or both are wrong. Which is not said.
    Refused,
    /// Too many failures; the password was not checked.
    Limited,
    /// The account store did not answer.
    Unanswered,
}

/// Checks passwords and starts sessions.
pub struct Login {
    store: Arc<dyn Accounts>,
    hasher: Arc<Hasher>,
    /// What an account with no password is checked against, so it takes as long.
    dummy: String,
    hashing: Semaphore,
    limiter: Limiter,
    events: Option<Arc<EventLog>>,
}

impl Login {
    pub fn new(
        store: Arc<dyn Accounts>,
        hasher: Hasher,
        limits: Limits,
        events: Option<Arc<EventLog>>,
    ) -> Self {
        Self {
            dummy: hasher.hash(&crate::account::random()),
            store,
            hasher: Arc::new(hasher),
            hashing: Semaphore::new(HASHING),
            limiter: Limiter::new(limits),
            events,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limiter.limits
    }

    /// Log in as `account` with `password`, from `source`.
    pub async fn attempt(&self, account: &str, password: &str, source: Option<IpAddr>) -> Attempt {
        let now = Instant::now();
        if !self.limiter.allows(account, source, now) {
            return Attempt::Limited;
        }
        let name = Name::parse(account).ok();
        let hash = match &name {
            Some(name) => match self.store.password(name).await {
                Ok(hash) => hash,
                Err(_) => return Attempt::Unanswered,
            },
            None => None,
        };
        let verified = self.verify(password, hash.as_deref()).await;
        match name.filter(|_| verified && hash.is_some()) {
            Some(name) => self.start(name, source).await,
            None => {
                self.limiter.failed(account, source, now);
                self.record(AccountEvent::by_console(
                    Action::LoginFailed,
                    account,
                    None,
                    source,
                ));
                Attempt::Refused
            }
        }
    }

    /// Whether `password` matches `hash`, checked against the dummy when there is none, on
    /// a blocking thread. A password longer than [`password::MAX_BYTES`] is not hashed.
    async fn verify(&self, password: &str, hash: Option<&str>) -> bool {
        if password.len() > password::MAX_BYTES {
            return false;
        }
        let _slot = self
            .hashing
            .acquire()
            .await
            .expect("the semaphore is never closed");
        let (hasher, password) = (self.hasher.clone(), password.to_owned());
        let hash = hash.unwrap_or(&self.dummy).to_owned();
        tokio::task::spawn_blocking(move || hasher.verify(&password, &hash))
            .await
            .unwrap_or(false)
    }

    /// Start a session for `name`, logged as `login`.
    pub(super) async fn start(&self, name: Name, source: Option<IpAddr>) -> Attempt {
        let id = crate::account::random();
        let expires = jiff::Timestamp::now()
            .checked_add(self.limiter.limits.session)
            .expect("now and a session of at most a year is inside jiff's range");
        let started = async {
            let roles = self.store.roles(&name).await?;
            self.store
                .create_session(&name, &TokenDigest::of(&id), &expires.to_string())
                .await?;
            Ok::<_, crate::account::AccountError>(roles)
        };
        match started.await {
            Ok(roles) => {
                self.record(AccountEvent::by_console(
                    Action::Login,
                    name.as_str(),
                    Some(&name),
                    source,
                ));
                Attempt::Started(Started {
                    id,
                    caller: Caller {
                        account: name,
                        roles,
                    },
                    expires,
                })
            }
            Err(_) => Attempt::Unanswered,
        }
    }

    /// End the session `id` of `caller`, logged as `logout`.
    pub async fn end(
        &self,
        id: &str,
        caller: &Caller,
        source: Option<IpAddr>,
    ) -> Result<(), crate::account::AccountError> {
        self.store.end_session(&TokenDigest::of(id)).await?;
        self.record(AccountEvent::by_console(
            Action::Logout,
            caller.account.as_str(),
            Some(&caller.account),
            source,
        ));
        Ok(())
    }

    /// Whether an OIDC callback from `source` may be answered now.
    pub fn oidc_allows(&self, source: Option<IpAddr>) -> bool {
        self.limiter.allows_from(source, Instant::now())
    }

    /// Count an OIDC login from `source` that failed, logged as `login-failed` for `who`.
    pub fn oidc_failed(&self, who: &str, source: Option<IpAddr>) {
        self.limiter.failed_from(source, Instant::now());
        self.record(AccountEvent::by_console(
            Action::LoginFailed,
            who,
            None,
            source,
        ));
    }

    fn record(&self, event: AccountEvent) {
        if let Some(log) = &self.events {
            log.write(&event);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::account::password::tests::cheap;
    use crate::account::{InMemory, Role};

    pub const PASSWORD: &str = "correct horse battery";

    /// The defaults in [`crate::env`].
    pub fn limits() -> Limits {
        crate::env::testing::with(&[]).login_limits().unwrap()
    }

    /// A store with `alice`, an admin with [`PASSWORD`], and `bob`, with no role.
    pub async fn store() -> Arc<InMemory> {
        let store = Arc::new(InMemory::new("2026-10-13T00:00:00Z"));
        let hasher = cheap();
        for (name, roles) in [("alice", vec![Role::Admin]), ("bob", vec![])] {
            let name = Name::parse(name).unwrap();
            store.create_account(&name, &roles).await.unwrap();
            store
                .set_password(&name, &hasher.hash(PASSWORD))
                .await
                .unwrap();
        }
        store
    }

    fn address(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn an_account_is_limited_at_its_fifth_failure_in_the_window() {
        let limiter = Limiter::new(limits());
        let start = Instant::now();
        for n in 0..limits().per_account {
            assert!(limiter.allows("alice", None, start), "failure {n}");
            limiter.failed("alice", None, start);
        }
        assert!(!limiter.allows("alice", None, start));
        assert!(!limiter.allows("alice", address("192.0.2.1"), start));
        assert!(limiter.allows("bob", None, start));
        assert!(!limiter.allows(
            "alice",
            None,
            start + limits().window - Duration::from_secs(1)
        ));
        assert!(limiter.allows("alice", None, start + limits().window));
    }

    /// An address is limited across accounts; an IPv6 address by its /64.
    #[test]
    fn an_address_is_limited_at_its_twentieth_failure_and_ipv6_by_its_64() {
        let limiter = Limiter::new(limits());
        let now = Instant::now();
        for n in 0..limits().per_address {
            let tried = format!("user{n}");
            assert!(limiter.allows(&tried, address("2001:db8:0:1::1"), now));
            limiter.failed(&tried, address("2001:db8:0:1::1"), now);
        }
        assert!(!limiter.allows("other", address("2001:db8:0:1:ffff::9"), now));
        assert!(limiter.allows("other", address("2001:db8:0:2::1"), now));
        assert!(limiter.allows("other", address("192.0.2.1"), now));
        assert_eq!(
            Key::address("192.0.2.1".parse().unwrap()),
            Key::Address("192.0.2.1".parse().unwrap())
        );
    }

    fn login(store: Arc<InMemory>, events: Option<Arc<EventLog>>) -> Login {
        Login::new(store, cheap(), limits(), events)
    }

    #[tokio::test]
    async fn the_right_password_starts_a_session_the_store_knows() {
        let store = store().await;
        let dir = crate::util::test_support::tempdir("console-login-events");
        let events = Arc::new(EventLog::open(&dir.join("events.log"), 30).unwrap());
        let login = login(store.clone(), Some(events));
        let Attempt::Started(started) =
            login.attempt("alice", PASSWORD, address("192.0.2.1")).await
        else {
            panic!("alice logs in");
        };
        assert_eq!(started.caller.roles, [Role::Admin]);
        assert!(started.expires > jiff::Timestamp::now());
        let digest = TokenDigest::of(&started.id);
        assert_eq!(
            store.session(&digest).await.unwrap(),
            Some(started.caller.clone())
        );
        assert_eq!(
            login.attempt("alice", "wrong horse battery", None).await,
            Attempt::Refused
        );
        login.end(&started.id, &started.caller, None).await.unwrap();
        assert_eq!(store.session(&digest).await.unwrap(), None);

        let logged = std::fs::read_to_string(dir.join("events.log")).unwrap();
        let actions: Vec<String> = logged
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["action"].to_string()
            })
            .collect();
        assert_eq!(actions, ["\"login\"", "\"login-failed\"", "\"logout\""]);
        assert!(!logged.contains(PASSWORD) && !logged.contains("wrong horse"));
    }

    /// An unknown account, a name that is not one, an account with no password and a
    /// password too long to hash are each refused alike.
    #[tokio::test]
    async fn each_wrong_login_is_refused_alike() {
        let store = store().await;
        let carol = Name::parse("carol").unwrap();
        store.create_account(&carol, &[]).await.unwrap();
        let login = login(store, None);
        for (account, password) in [
            ("nobody", PASSWORD),
            ("Not A Name", PASSWORD),
            ("carol", PASSWORD),
            ("alice", &"a".repeat(password::MAX_BYTES + 1)),
        ] {
            assert_eq!(
                login.attempt(account, password, None).await,
                Attempt::Refused,
                "{account}"
            );
        }
    }

    /// A password of exactly the most bytes allowed is checked, and logs in.
    #[tokio::test]
    async fn a_password_of_the_most_bytes_allowed_logs_in() {
        let store = store().await;
        let longest = "a".repeat(password::MAX_BYTES);
        let carol = Name::parse("carol").unwrap();
        store.create_account(&carol, &[]).await.unwrap();
        store
            .set_password(&carol, &cheap().hash(&longest))
            .await
            .unwrap();
        let login = login(store, None);
        assert!(matches!(
            login.attempt("carol", &longest, None).await,
            Attempt::Started(_)
        ));
    }

    /// Past the limit even the right password is not checked.
    #[tokio::test]
    async fn a_limited_account_is_not_checked() {
        let login = login(store().await, None);
        for _ in 0..limits().per_account {
            login.attempt("alice", "wrong horse battery", None).await;
        }
        assert_eq!(
            login.attempt("alice", PASSWORD, None).await,
            Attempt::Limited
        );
        assert!(matches!(
            login.attempt("bob", PASSWORD, None).await,
            Attempt::Started(_)
        ));
    }

    /// A store that cannot answer is said so, whether it fails reading the password or
    /// starting the session.
    #[tokio::test]
    async fn a_store_that_cannot_answer_is_unanswered() {
        let down = Login::new(
            Arc::new(crate::account::testing::Down),
            cheap(),
            limits(),
            None,
        );
        assert_eq!(
            down.attempt("alice", PASSWORD, None).await,
            Attempt::Unanswered
        );
        for fails in ["roles", "create_session"] {
            let failing = crate::account::testing::Failing {
                inner: store().await,
                fails,
            };
            let failing = Login::new(Arc::new(failing), cheap(), limits(), None);
            assert_eq!(
                failing.attempt("alice", PASSWORD, None).await,
                Attempt::Unanswered,
                "{fails}"
            );
        }
        let caller = Caller {
            account: Name::parse("alice").unwrap(),
            roles: vec![],
        };
        assert!(down.end("id", &caller, None).await.is_err());
    }

    /// OIDC failures count against the address alone, and stop the next at the limit.
    #[test]
    fn oidc_failures_count_against_the_address() {
        let login_store = futures_util::FutureExt::now_or_never(store()).unwrap();
        let login = login(login_store, None);
        let from = address("192.0.2.9");
        for _ in 0..limits().per_address {
            assert!(login.oidc_allows(from));
            login.oidc_failed("someone", from);
        }
        assert!(!login.oidc_allows(from));
        assert!(login.oidc_allows(address("192.0.2.10")));
        assert!(
            login.oidc_allows(None),
            "with no address nothing is counted"
        );
    }
}
