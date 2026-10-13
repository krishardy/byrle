//! The account event log: one JSON line per change to an account, its roles, tokens or
//! password, and per login. Read by R8. See docs/admin-plan.md §4.5.

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Login,
    LoginFailed,
    Logout,
    AccountCreated,
    AccountDisabled,
    RoleGranted,
    RoleRevoked,
    PasswordSet,
    TokenCreated,
    TokenRevoked,
    OidcLinked,
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountEvent {
    /// RFC 3339, UTC.
    pub at: String,
    /// The account that acted. Absent from `byrle account` and `byrle token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub action: Action,
    /// The account acted on, or the username a failed login tried.
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Where the change came from: [`CLI`], or the client's address.
    pub source: String,
}

/// The source of a change made by `byrle account` or `byrle token`.
pub const CLI: &str = "cli";

/// The source of a console request whose peer address the server did not record.
pub const UNKNOWN: &str = "unknown";

impl AccountEvent {
    /// `action` on `account`, made now from the command line.
    pub fn by_cli(action: Action, account: &super::Name) -> Self {
        Self {
            at: jiff::Timestamp::now().to_string(),
            actor: None,
            action,
            account: account.to_string(),
            role: None,
            token: None,
            source: CLI.to_owned(),
        }
    }

    /// `action` on `account`, made now through the console by `actor` from `source`.
    /// `account` is the username a failed login tried, cut to 256 bytes.
    pub fn by_console(
        action: Action,
        account: &str,
        actor: Option<&super::Name>,
        source: Option<std::net::IpAddr>,
    ) -> Self {
        let mut cut = 256.min(account.len());
        while !account.is_char_boundary(cut) {
            cut -= 1;
        }
        Self {
            at: jiff::Timestamp::now().to_string(),
            actor: actor.map(ToString::to_string),
            action,
            account: account[..cut].to_owned(),
            role: None,
            token: None,
            source: source.map_or_else(|| UNKNOWN.to_owned(), |address| address.to_string()),
        }
    }

    pub fn with_role(mut self, role: super::Role) -> Self {
        self.role = Some(role.name().to_owned());
        self
    }

    pub fn with_token(mut self, token: &super::Name) -> Self {
        self.token = Some(token.to_string());
        self
    }
}

/// Open `path` for appending, creating it, to learn before a change whether it can be
/// recorded. The proxy rotates the file; a command only appends to it.
pub fn writable(path: &Path) -> std::io::Result<()> {
    opened(path).map(drop)
}

/// Append `events` to `path`, one line each.
pub fn append(path: &Path, events: &[AccountEvent]) -> std::io::Result<()> {
    let lines: Vec<u8> = events.iter().flat_map(line).collect();
    opened(path).and_then(|mut file| file.write_all(&lines))
}

/// `event` as one line of JSON.
fn line(event: &AccountEvent) -> Vec<u8> {
    let mut line = serde_json::to_vec(event).expect("an event serialises");
    line.push(b'\n');
    line
}

/// The log as the proxy writes it, rotated as the audit log is.
pub struct EventLog(crate::rotation::Lines);

impl EventLog {
    /// Open `path`, creating it. Rotated files older than `retention_days` are deleted.
    pub fn open(path: &Path, retention_days: u32) -> std::io::Result<Self> {
        let today = crate::rotation::today();
        crate::rotation::Lines::open(path, retention_days, "account event log", today).map(Self)
    }

    /// Append `event`. A failure is warned about once and otherwise ignored.
    pub fn write(&self, event: &AccountEvent) {
        self.0.append(&line(event), crate::rotation::today());
    }
}

fn opened(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::{Name, Role};
    use crate::util::test_support::tempdir;

    #[test]
    fn each_event_is_one_line_appended() {
        let dir = tempdir("account-events");
        let path = dir.join("events.log");
        writable(&path).unwrap();
        let alice = Name::parse("alice").unwrap();
        let created = AccountEvent::by_cli(Action::AccountCreated, &alice);
        let granted = AccountEvent::by_cli(Action::RoleGranted, &alice).with_role(Role::Admin);
        append(&path, &[created.clone(), granted.clone()]).unwrap();
        let token = AccountEvent::by_cli(Action::TokenCreated, &alice)
            .with_token(&Name::parse("laptop").unwrap());
        append(&path, std::slice::from_ref(&token)).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let read: Vec<AccountEvent> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(read, [created, granted, token]);
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["action"], "account-created");
        assert_eq!(first["source"], "cli");
        assert!(first.get("actor").is_none() && first.get("role").is_none());
    }

    /// The console names the actor and the address, and cuts a long username tried.
    #[test]
    fn the_console_writes_through_the_rotated_log() {
        let dir = tempdir("account-events-console");
        let path = dir.join("events.log");
        let log = EventLog::open(&path, 30).unwrap();
        let alice = Name::parse("alice").unwrap();
        let login = AccountEvent::by_console(
            Action::Login,
            "alice",
            Some(&alice),
            Some("203.0.113.7".parse().unwrap()),
        );
        log.write(&login);
        let long = format!("{}é", "a".repeat(255));
        let failed = AccountEvent::by_console(Action::LoginFailed, &long, None, None);
        assert_eq!(
            failed.account,
            "a".repeat(255),
            "cut before the character it splits"
        );
        assert_eq!(failed.source, UNKNOWN);
        log.write(&failed);
        let read: Vec<AccountEvent> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(read, [login.clone(), failed]);
        assert_eq!(login.actor.as_deref(), Some("alice"));
        assert_eq!(login.source, "203.0.113.7");
        assert!(EventLog::open(&dir.join("no-such-dir").join("x.log"), 30).is_err());
    }

    #[test]
    fn a_log_that_cannot_be_opened_is_an_error() {
        let dir = tempdir("account-events-missing");
        let path = dir.join("no-such-dir").join("events.log");
        assert!(writable(&path).is_err());
        assert!(append(&path, &[]).is_err());
    }
}
