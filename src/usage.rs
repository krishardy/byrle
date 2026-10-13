//! The versions the proxy served each account, and its failures by hour and case, written
//! beside each audit line through a bounded queue. See docs/admin-plan.md §4.3.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use jiff::{RoundMode, Timestamp, TimestampRound, Unit};
use serde::Serialize;

use crate::audit::{Answered, Event};

pub mod postgres;

/// One audit line, as the usage tables count it.
#[derive(Debug, Clone, PartialEq)]
pub enum Use {
    /// A version served to an account: `served_version`.
    Served {
        account: Option<String>,
        ecosystem: String,
        name: String,
        version: String,
        at: Timestamp,
    },
    /// A request answered anything but `served`: `failure_count`.
    Failed {
        hour: Timestamp,
        ecosystem: String,
        answered: Answered,
    },
}

impl Use {
    /// What `line` counts as. `None` for a document filtered, which has no `answered` in
    /// enforce mode and no version in observe mode, and for a line whose time does not parse.
    pub fn of(line: &Event) -> Option<Self> {
        let answered = line.answered?;
        let at: Timestamp = line.at.parse().ok()?;
        match answered {
            Answered::Served => line.version.as_ref().map(|version| Self::Served {
                account: line.account.clone(),
                ecosystem: line.ecosystem.clone(),
                name: line.name.clone(),
                version: version.clone(),
                at,
            }),
            answered => Some(Self::Failed {
                hour: hour_of(at),
                ecosystem: line.ecosystem.clone(),
                answered,
            }),
        }
    }
}

/// An account, ecosystem, name and version.
pub type ServedKey = (Option<String>, String, String, String);

/// An hour, ecosystem and the `answered` case.
pub type FailedKey = (Timestamp, String, Answered);

/// A batch with one row per key, as one statement can write it.
#[derive(Debug, Default, PartialEq)]
pub struct Collapsed {
    /// Each version's first and last time served in the batch.
    pub served: BTreeMap<ServedKey, (Timestamp, Timestamp)>,
    /// Each hour's failures in the batch, by case.
    pub failed: BTreeMap<FailedKey, i64>,
}

impl Collapsed {
    /// `rows` with their duplicates merged, since Postgres refuses to update one row twice
    /// in a statement.
    pub fn of(rows: &[Use]) -> Self {
        let mut collapsed = Self::default();
        for row in rows.iter().cloned() {
            match row {
                Use::Served {
                    account,
                    ecosystem,
                    name,
                    version,
                    at,
                } => {
                    let span = collapsed
                        .served
                        .entry((account, ecosystem, name, version))
                        .or_insert((at, at));
                    *span = (span.0.min(at), span.1.max(at));
                }
                Use::Failed {
                    hour,
                    ecosystem,
                    answered,
                } => {
                    *collapsed
                        .failed
                        .entry((hour, ecosystem, answered))
                        .or_default() += 1
                }
            }
        }
        collapsed
    }
}

/// A version served to an account, as `served_version` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct ServedRow {
    /// What the next page starts after.
    pub id: i64,
    /// `None` for requests without a token.
    pub account: Option<String>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// RFC 3339, UTC, to the second.
    pub first_served: String,
    pub last_served: String,
}

/// Which served versions to read: those after `after` by id, matching each filter set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServedQuery {
    pub after: i64,
    pub limit: u32,
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub account: Option<String>,
    /// Served at or after: `last_served` is not before it.
    pub since: Option<Timestamp>,
    /// Served before: `first_served` is before it.
    pub until: Option<Timestamp>,
}

/// One hour's count of one case in one ecosystem, as `failure_count` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct FailureRow {
    /// The hour's start, RFC 3339, UTC.
    pub hour: String,
    pub ecosystem: String,
    pub answered: String,
    pub count: i64,
}

/// Which hours' failures to read: from `since` up to `until`, matching each filter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureQuery {
    pub since: Timestamp,
    pub until: Timestamp,
    pub ecosystem: Option<String>,
    pub answered: Option<String>,
}

/// A read in flight. The error is the store's, as text.
pub type Read<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Where the usage tables are read from.
pub trait Usage: Send + Sync {
    /// Served versions by id, at most `query.limit`.
    fn served<'a>(&'a self, query: &'a ServedQuery) -> Read<'a, Vec<ServedRow>>;

    /// Failure counts by hour, ecosystem and case.
    fn failures<'a>(&'a self, query: &'a FailureQuery) -> Read<'a, Vec<FailureRow>>;
}

/// The start of the UTC hour `at` falls in.
pub fn hour_of(at: Timestamp) -> Timestamp {
    at.round(
        TimestampRound::new()
            .smallest(Unit::Hour)
            .mode(RoundMode::Trunc),
    )
    .expect("the start of an hour inside jiff's range is inside it")
}

/// `at` as RFC 3339 in UTC, to the second, as the tables give times back.
pub fn second(at: Timestamp) -> String {
    at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::sync::Mutex;

    use std::sync::Arc;

    use futures_util::future::BoxFuture;

    use super::*;
    use crate::util::batched::Sink;

    /// A sink that keeps every row it is given, in order.
    #[derive(Default)]
    pub struct Kept(pub Mutex<Vec<Use>>);

    impl Sink<Use> for Kept {
        fn put<'a>(&'a self, rows: &'a [Use]) -> BoxFuture<'a, Result<(), String>> {
            self.0.lock().unwrap().extend_from_slice(rows);
            Box::pin(async { Ok(()) })
        }
    }

    /// The rows kept, read as the tables would give them: one per key, ids by key order.
    impl Usage for Kept {
        fn served<'a>(&'a self, query: &'a ServedQuery) -> Read<'a, Vec<ServedRow>> {
            let kept = self.0.lock().unwrap();
            let mut spans: Vec<_> = Collapsed::of(&kept).served.into_iter().collect();
            let first_kept = |key: &ServedKey| {
                kept.iter().position(|row| {
                    matches!(row, Use::Served { account, ecosystem, name, version, .. }
                        if (account, ecosystem, name, version) == (&key.0, &key.1, &key.2, &key.3))
                })
            };
            spans.sort_by_key(|(key, _)| first_kept(key));
            let rows = spans
                .into_iter()
                .zip(1..)
                .map(
                    |(((account, ecosystem, name, version), (first, last)), id)| {
                        (
                            first,
                            last,
                            ServedRow {
                                id,
                                account,
                                ecosystem,
                                name,
                                version,
                                first_served: second(first),
                                last_served: second(last),
                            },
                        )
                    },
                )
                .filter(|(first, last, row)| {
                    row.id > query.after
                        && query.ecosystem.as_ref().is_none_or(|e| *e == row.ecosystem)
                        && query.name.as_ref().is_none_or(|n| *n == row.name)
                        && query
                            .account
                            .as_ref()
                            .is_none_or(|a| Some(a) == row.account.as_ref())
                        && query.since.is_none_or(|since| *last >= since)
                        && query.until.is_none_or(|until| *first < until)
                })
                .map(|(_, _, row)| row)
                .take(query.limit as usize)
                .collect();
            Box::pin(async { Ok(rows) })
        }

        fn failures<'a>(&'a self, query: &'a FailureQuery) -> Read<'a, Vec<FailureRow>> {
            let collapsed = Collapsed::of(&self.0.lock().unwrap());
            let rows = collapsed
                .failed
                .into_iter()
                .filter(|((hour, ecosystem, answered), _)| {
                    *hour >= query.since
                        && *hour < query.until
                        && query.ecosystem.as_ref().is_none_or(|e| e == ecosystem)
                        && query
                            .answered
                            .as_ref()
                            .is_none_or(|a| *a == answered.name())
                })
                .map(|((hour, ecosystem, answered), count)| FailureRow {
                    hour: second(hour),
                    ecosystem,
                    answered: answered.name(),
                    count,
                })
                .collect();
            Box::pin(async { Ok(rows) })
        }
    }

    fn served(account: Option<&str>, at: &str) -> Use {
        Use::Served {
            account: account.map(str::to_owned),
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.21".into(),
            at: at.parse().unwrap(),
        }
    }

    fn line(answered: Option<Answered>, version: Option<&str>, at: &str) -> Event {
        let mut line = Event::undecided("npm", "lodash", version, Answered::Served);
        line.answered = answered;
        line.at = at.into();
        line.with_account(Some("alice"))
    }

    #[test]
    fn a_served_version_is_counted_with_its_account_and_time() {
        let served_line = line(
            Some(Answered::Served),
            Some("4.17.21"),
            "2026-10-13T09:15:00Z",
        );
        assert_eq!(
            Use::of(&served_line),
            Some(served(Some("alice"), "2026-10-13T09:15:00Z"))
        );
        let metadata = line(Some(Answered::Served), None, "2026-10-13T09:15:00Z");
        assert_eq!(Use::of(&metadata), None);
    }

    #[test]
    fn a_failure_is_counted_in_the_hour_it_started_in() {
        let metadata = line(
            Some(Answered::UpstreamStatus),
            None,
            "2026-10-13T09:59:59.9Z",
        );
        assert_eq!(
            Use::of(&metadata),
            Some(Use::Failed {
                hour: "2026-10-13T09:00:00Z".parse().unwrap(),
                ecosystem: "npm".into(),
                answered: Answered::UpstreamStatus,
            })
        );
    }

    #[test]
    fn a_filtered_document_or_an_untimed_line_is_not_counted() {
        let enforced = Event::resolution("npm", "lodash", "allow", Vec::new(), Vec::new(), &[]);
        assert_eq!(Use::of(&enforced), None);
        assert_eq!(Use::of(&enforced.answered(Answered::Served)), None);
        assert_eq!(
            Use::of(&line(None, Some("1"), "2026-10-13T09:15:00Z")),
            None
        );
        assert_eq!(
            Use::of(&line(Some(Answered::Served), Some("1"), "yesterday")),
            None
        );
    }

    /// Duplicates in one batch become one row each: the earliest and latest time a version
    /// was served, and the sum of an hour's failures.
    #[test]
    fn a_batch_is_collapsed_to_one_row_per_key() {
        let failed = |at: &str| Use::Failed {
            hour: at.parse().unwrap(),
            ecosystem: "npm".into(),
            answered: Answered::Refused,
        };
        let rows = [
            served(Some("alice"), "2026-10-13T09:00:00Z"),
            served(None, "2026-10-13T09:30:00Z"),
            served(Some("alice"), "2026-10-13T08:00:00Z"),
            served(Some("alice"), "2026-10-13T10:00:00Z"),
            failed("2026-10-13T09:00:00Z"),
            failed("2026-10-13T09:00:00Z"),
            failed("2026-10-13T10:00:00Z"),
        ];
        let collapsed = Collapsed::of(&rows);
        let key = |account: Option<&str>| {
            (
                account.map(str::to_owned),
                "npm".to_owned(),
                "lodash".to_owned(),
                "4.17.21".to_owned(),
            )
        };
        let at = |s: &str| s.parse::<Timestamp>().unwrap();
        assert_eq!(
            collapsed.served,
            BTreeMap::from([
                (
                    key(None),
                    (at("2026-10-13T09:30:00Z"), at("2026-10-13T09:30:00Z"))
                ),
                (
                    key(Some("alice")),
                    (at("2026-10-13T08:00:00Z"), at("2026-10-13T10:00:00Z"))
                ),
            ])
        );
        let hour = |s: &str| (at(s), "npm".to_owned(), Answered::Refused);
        assert_eq!(
            collapsed.failed,
            BTreeMap::from([
                (hour("2026-10-13T09:00:00Z"), 2),
                (hour("2026-10-13T10:00:00Z"), 1),
            ])
        );
    }

    /// Every path of the queue, for its instantiation on usage rows.
    #[tokio::test(flavor = "current_thread")]
    async fn the_queue_of_usage_rows_takes_each_path() {
        let kept = Arc::new(Kept::default());
        crate::util::batched::tests::each_path(
            || served(None, "2026-10-13T09:00:00Z"),
            kept.clone(),
        )
        .await;
    }
}
