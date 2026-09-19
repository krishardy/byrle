//! A deferral this proxy can be told to return, so real clients can be measured against
//! it before the thing that would cause one exists.
//!
//! §5 defers a request when the proxy is not ready to answer it: warming, or an artifact
//! still under analysis. Which status code to use is an open decision, and it turns on
//! what package managers actually do with 429 and 503, which is not documented and does
//! not agree between them. This makes the response producible on demand so the answer
//! comes from measurement. `make retry-matrix` is the harness.
//!
//! # Debug builds only
//!
//! An env var that makes a proxy refuse traffic is a denial-of-service switch, so the
//! whole module is `#[cfg(debug_assertions)]` and is not compiled into a release binary.
//! The startup log says loudly when it is on.

use crate::route::RequestTarget;
use std::time::Duration;

/// Which requests a deferral applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Metadata requests: an npm packument, a PyPI index. §5's "we are not ready, all
    /// requests" case.
    Metadata,
    /// Artifact requests: an npm tarball, a PyPI file. §5's "this one artifact is under
    /// analysis" case.
    Artifact,
    /// Both.
    All,
}

impl Scope {
    fn covers(self, target: &RequestTarget) -> bool {
        matches!(
            (self, target),
            (
                Self::All,
                RequestTarget::Metadata(_) | RequestTarget::Artifact { .. }
            ) | (Self::Metadata, RequestTarget::Metadata(_))
                | (Self::Artifact, RequestTarget::Artifact { .. })
        )
    }
}

/// A deferral to return instead of fetching upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferTest {
    status: u16,
    /// Seconds for `Retry-After`. `None` omits the header, which is its own measurement:
    /// a client may retry on the code alone.
    retry_after: Option<u32>,
    scope: Scope,
    /// How long the deferral lasts, measured from startup. `None` never stops, which
    /// measures the client's retry budget. A duration measures the other half: whether a
    /// client waits out a proxy that is warming, which is §5's cold-start case.
    duration: Option<Duration>,
}

/// Why a spec was rejected. Startup fails on any of these rather than running with the
/// knob half-understood.
#[derive(Debug, PartialEq, Eq)]
pub enum SpecError {
    Fields(usize),
    Status(String),
    RetryAfter(String),
    Scope(String),
    Duration(String),
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fields(n) => write!(f, "expected 3 colon-separated fields, found {n}"),
            Self::Status(s) => write!(f, "`{s}` is not a status in 400..=599"),
            Self::RetryAfter(s) => write!(f, "`{s}` is not a number of seconds, or `none`"),
            Self::Scope(s) => write!(f, "`{s}` is not `metadata`, `artifact` or `all`"),
            Self::Duration(s) => write!(f, "`{s}` is not a number of seconds"),
        }
    }
}

impl std::error::Error for SpecError {}

impl DeferTest {
    /// Parse `<status>:<retry-after seconds|none>:<metadata|artifact|all>[:<seconds>]`.
    ///
    /// Examples: `429:1:artifact` defers those requests for as long as the proxy runs.
    /// `503:1:all:5` defers everything for the first five seconds and then serves.
    pub fn parse(spec: &str) -> Result<Self, SpecError> {
        let fields: Vec<&str> = spec.split(':').map(str::trim).collect();
        let (status, retry_after, scope, duration) = match fields.as_slice() {
            [status, retry_after, scope] => (status, retry_after, scope, None),
            [status, retry_after, scope, duration] => (status, retry_after, scope, Some(duration)),
            other => return Err(SpecError::Fields(other.len())),
        };

        // Bounded to the error range: this exists to measure how a client reacts to being
        // turned away, and a 2xx or a redirect is not that.
        let status: u16 = status
            .parse()
            .ok()
            .filter(|s| (400..=599).contains(s))
            .ok_or_else(|| SpecError::Status((*status).to_owned()))?;

        let retry_after = match *retry_after {
            "none" | "-" | "" => None,
            other => Some(
                other
                    .parse()
                    .map_err(|_| SpecError::RetryAfter(other.to_owned()))?,
            ),
        };

        let scope = match *scope {
            "metadata" => Scope::Metadata,
            "artifact" => Scope::Artifact,
            "all" => Scope::All,
            other => return Err(SpecError::Scope(other.to_owned())),
        };

        let duration = match duration {
            None => None,
            Some(seconds) => Some(Duration::from_secs(
                seconds
                    .parse()
                    .map_err(|_| SpecError::Duration((*seconds).to_owned()))?,
            )),
        };

        Ok(Self {
            status,
            retry_after,
            scope,
            duration,
        })
    }

    /// The status and `Retry-After` for this request, or `None` to handle it normally.
    ///
    /// `since_start` is how long the proxy has been running, which is what a bounded
    /// deferral is measured against.
    pub fn applies_to(
        &self,
        target: &RequestTarget,
        since_start: Duration,
    ) -> Option<(u16, Option<u32>)> {
        if self.duration.is_some_and(|d| since_start >= d) {
            return None;
        }
        self.scope
            .covers(target)
            .then_some((self.status, self.retry_after))
    }
}

impl std::fmt::Display for DeferTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let retry = match self.retry_after {
            Some(s) => format!("{s}s"),
            None => "no Retry-After".to_owned(),
        };
        let lasts = match self.duration {
            Some(d) => format!("for {}s", d.as_secs()),
            None => "until the proxy stops".to_owned(),
        };
        write!(
            f,
            "{} with {retry} on {:?}, {lasts}",
            self.status, self.scope
        )
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::identity::PackageKey;

    const SCOPES: [Scope; 3] = [Scope::Metadata, Scope::Artifact, Scope::All];

    /// A target in scope for something, so the time comparison is what decides rather
    /// than `Scope::covers` short-circuiting every case to `None`.
    fn covered_target() -> RequestTarget {
        RequestTarget::Metadata(
            PackageKey::from_registry_name(crate::identity::Ecosystem::Npm, "w").unwrap(),
        )
    }

    fn any_deferral() -> DeferTest {
        let i: usize = kani::any();
        kani::assume(i < SCOPES.len());
        let bounded: bool = kani::any();
        let seconds: u64 = kani::any();
        DeferTest {
            status: 503,
            retry_after: None,
            scope: SCOPES[i],
            duration: bounded.then(|| Duration::from_secs(seconds)),
        }
    }

    /// A bounded deferral models a proxy warming up, so once it has lifted it must stay
    /// lifted. A deferral that came back would be a client that had already retried
    /// successfully being turned away again, which is a failed install rather than a
    /// slow one.
    ///
    /// Over every scope, both bounded and unbounded, and every pair of times in order.
    #[kani::proof]
    fn a_deferral_that_has_lifted_never_comes_back() {
        let deferral = any_deferral();
        let target = covered_target();

        let earlier: u64 = kani::any();
        let later: u64 = kani::any();
        kani::assume(later >= earlier);

        if deferral
            .applies_to(&target, Duration::from_secs(earlier))
            .is_none()
        {
            assert!(
                deferral
                    .applies_to(&target, Duration::from_secs(later))
                    .is_none()
            );
        }
    }

    /// An unbounded deferral is the one that measures a retry budget, so it must never
    /// lift however long the proxy has been running.
    #[kani::proof]
    fn an_unbounded_deferral_never_lifts() {
        let i: usize = kani::any();
        kani::assume(i < SCOPES.len());
        let deferral = DeferTest {
            status: 429,
            retry_after: Some(1),
            scope: SCOPES[i],
            duration: None,
        };
        let target = covered_target();

        let at: u64 = kani::any();
        assert!(
            deferral.applies_to(&target, Duration::from_secs(at))
                == deferral.applies_to(&target, Duration::ZERO)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ecosystem, PackageKey};

    fn key() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap()
    }

    fn metadata() -> RequestTarget {
        RequestTarget::Metadata(key())
    }

    fn artifact() -> RequestTarget {
        RequestTarget::Artifact {
            key: key(),
            claimed_version: "4.17.21".to_owned(),
            filename: "lodash-4.17.21.tgz".to_owned(),
        }
    }

    const NOW: Duration = Duration::ZERO;

    #[test]
    fn a_spec_names_a_status_a_delay_and_what_it_applies_to() {
        let d = DeferTest::parse("429:1:artifact").unwrap();
        assert_eq!(d.applies_to(&artifact(), NOW), Some((429, Some(1))));
        assert_eq!(d.applies_to(&metadata(), NOW), None);
        assert_eq!(d.applies_to(&RequestTarget::Other, NOW), None);
    }

    /// The bounded form is the cold-start case: defer while warming, then serve.
    #[test]
    fn a_bounded_deferral_stops_once_the_proxy_has_run_that_long() {
        let d = DeferTest::parse("503:1:all:5").unwrap();
        assert_eq!(
            d.applies_to(&metadata(), Duration::ZERO),
            Some((503, Some(1)))
        );
        assert_eq!(
            d.applies_to(&metadata(), Duration::from_millis(4_999)),
            Some((503, Some(1)))
        );
        assert_eq!(d.applies_to(&metadata(), Duration::from_secs(5)), None);
        assert_eq!(d.applies_to(&metadata(), Duration::from_secs(600)), None);
    }

    /// Without a duration it never stops, which is what measures a retry budget.
    #[test]
    fn an_unbounded_deferral_still_applies_after_a_long_run() {
        let d = DeferTest::parse("429:1:all").unwrap();
        assert_eq!(
            d.applies_to(&artifact(), Duration::from_secs(86_400)),
            Some((429, Some(1)))
        );
    }

    #[test]
    fn retry_after_can_be_left_off_so_the_code_is_measured_alone() {
        for spec in ["503:none:metadata", "503:-:metadata", "503::metadata"] {
            let d = DeferTest::parse(spec).unwrap();
            assert_eq!(d.applies_to(&metadata(), NOW), Some((503, None)), "{spec}");
        }
    }

    #[test]
    fn all_covers_both_kinds_but_not_paths_this_does_not_classify() {
        let d = DeferTest::parse("503:2:all").unwrap();
        assert_eq!(d.applies_to(&metadata(), NOW), Some((503, Some(2))));
        assert_eq!(d.applies_to(&artifact(), NOW), Some((503, Some(2))));
        assert_eq!(d.applies_to(&RequestTarget::Other, NOW), None);
    }

    #[test]
    fn a_spec_that_is_not_understood_is_an_error_rather_than_a_default() {
        assert_eq!(DeferTest::parse("429:1"), Err(SpecError::Fields(2)));
        assert_eq!(
            DeferTest::parse("200:1:all"),
            Err(SpecError::Status("200".to_owned())),
            "a success is not a deferral"
        );
        assert_eq!(
            DeferTest::parse("600:1:all"),
            Err(SpecError::Status("600".to_owned()))
        );
        assert_eq!(
            DeferTest::parse("429:soon:all"),
            Err(SpecError::RetryAfter("soon".to_owned()))
        );
        assert_eq!(
            DeferTest::parse("429:1:everything"),
            Err(SpecError::Scope("everything".to_owned()))
        );
        assert_eq!(
            DeferTest::parse("429:1:all:soon"),
            Err(SpecError::Duration("soon".to_owned()))
        );
        assert_eq!(DeferTest::parse("429:1:all:5:6"), Err(SpecError::Fields(5)));
    }

    #[test]
    fn every_error_says_what_it_saw() {
        for e in [
            SpecError::Fields(2),
            SpecError::Status("200".to_owned()),
            SpecError::RetryAfter("soon".to_owned()),
            SpecError::Scope("everything".to_owned()),
            SpecError::Duration("soon".to_owned()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn the_startup_log_says_what_is_on() {
        assert_eq!(
            DeferTest::parse("429:1:artifact").unwrap().to_string(),
            "429 with 1s on Artifact, until the proxy stops"
        );
        assert_eq!(
            DeferTest::parse("503:none:all:5").unwrap().to_string(),
            "503 with no Retry-After on All, for 5s"
        );
    }
}
