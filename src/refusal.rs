//! What a policy refusal looks like on the wire.
//!
//! See docs/engineering_decisions/refusal-status.md.

use crate::identity::Ecosystem;
use std::collections::BTreeMap;
use std::fmt;

/// Whether the proxy refuses what the policy refuses: [`crate::env::MODE`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Enforce,
    /// Serves what the policy refuses and logs it. Never serves what cannot be assessed.
    Observe,
}

impl Mode {
    /// `enforce` or `observe`. `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "enforce" => Some(Self::Enforce),
            "observe" => Some(Self::Observe),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
        }
    }
}

/// The client that sent a request, by the first token of its user-agent.
///
/// `None` when there is no user-agent or it is empty. Lowercased, because the table is
/// operator-written and `Yarn` and `yarn` are the same client.
pub fn client_name(user_agent: Option<&str>) -> Option<String> {
    let ua = user_agent?.trim();
    let name = ua
        .split(['/', ' ', '\t'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// Which status a refusal uses, per ecosystem and client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalStatus {
    default: u16,
    by_client: BTreeMap<(Ecosystem, String), u16>,
}

impl Default for RefusalStatus {
    fn default() -> Self {
        Self {
            default: crate::env::DEFAULT_REFUSAL_STATUS,
            by_client: BTreeMap::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RefusalParseError {
    pub entry: String,
    pub reason: &'static str,
}

impl fmt::Display for RefusalParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is not a refusal rule: {}", self.entry, self.reason)
    }
}

impl std::error::Error for RefusalParseError {}

impl RefusalStatus {
    /// Parse a comma-separated table, such as `default=403,npm/pnpm=451`.
    /// A status outside 400..=599 is refused.
    pub fn parse(spec: &str) -> Result<Self, RefusalParseError> {
        let mut table = Self::default();
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (key, value) = entry.split_once('=').ok_or_else(|| RefusalParseError {
                entry: entry.to_owned(),
                reason: "expected <ecosystem>/<client>=<status> or default=<status>",
            })?;
            let status: u16 = value.trim().parse().map_err(|_| RefusalParseError {
                entry: entry.to_owned(),
                reason: "status is not a number",
            })?;
            if !(400..=599).contains(&status) {
                return Err(RefusalParseError {
                    entry: entry.to_owned(),
                    reason: "status must be between 400 and 599",
                });
            }

            let key = key.trim();
            if key.eq_ignore_ascii_case("default") {
                table.default = status;
                continue;
            }
            let (ecosystem, client) = key.split_once('/').ok_or_else(|| RefusalParseError {
                entry: entry.to_owned(),
                reason: "expected <ecosystem>/<client>",
            })?;
            let ecosystem = match ecosystem.trim().to_ascii_lowercase().parse::<Ecosystem>() {
                Ok(ecosystem) => ecosystem,
                Err(_) => {
                    return Err(RefusalParseError {
                        entry: entry.to_owned(),
                        reason: "unknown ecosystem",
                    });
                }
            };
            let client = client.trim().to_ascii_lowercase();
            if client.is_empty() {
                return Err(RefusalParseError {
                    entry: entry.to_owned(),
                    reason: "client is empty",
                });
            }
            table.by_client.insert((ecosystem, client), status);
        }
        Ok(table)
    }

    /// The status to answer this client with.
    /// `user_agent` names the client; an unknown or absent one gets the default.
    pub fn for_client(&self, ecosystem: Ecosystem, user_agent: Option<&str>) -> u16 {
        client_name(user_agent)
            .and_then(|name| self.by_client.get(&(ecosystem, name)).copied())
            .unwrap_or(self.default)
    }

    pub fn default_status(&self) -> u16 {
        self.default
    }

    /// Configured statuses of 500 or more, which clients read as the proxy not being ready.
    pub fn misleading(&self) -> Vec<u16> {
        let mut found: Vec<u16> = std::iter::once(self.default)
            .chain(self.by_client.values().copied())
            .filter(|status| *status >= 500)
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The delimiters, a lowercase letter, and an uppercase one for the lowercasing.
    const ALPHABET: [u8; 5] = [b'/', b' ', b'\t', b'n', b'N'];

    /// A client name contains no delimiter and is lowercase, so `pnpm/10.33.0 npm/?`
    /// is never read as npm.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_client_name_is_one_lowercase_token() {
        let bytes: [u8; 5] = kani::any();
        for byte in bytes {
            kani::assume(ALPHABET.contains(&byte));
        }
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());

        let ua = core::str::from_utf8(&bytes[..len]).expect("every byte is ASCII");

        let Some(name) = client_name(Some(ua)) else {
            return;
        };
        assert!(
            !name.is_empty(),
            "an empty name would match nothing, so it is None"
        );
        for b in name.bytes() {
            assert!(b != b'/' && b != b' ' && b != b'\t', "a delimiter survived");
            assert!(!b.is_ascii_uppercase(), "the table is written in lowercase");
        }
    }

    /// A user-agent with no name at all is `None` rather than an empty string, so it
    /// takes the default instead of matching a table entry keyed on "".
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_user_agent_of_only_delimiters_has_no_client() {
        let bytes: [u8; 4] = kani::any();
        for byte in bytes {
            kani::assume(byte == b'/' || byte == b' ' || byte == b'\t');
        }
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let ua = core::str::from_utf8(&bytes[..len]).expect("every byte is ASCII");

        assert!(client_name(Some(ua)).is_none());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::Mode;

    /// Each mode reads back from the name it prints, and nothing else is a mode.
    #[test]
    fn a_mode_parses_from_its_own_name() {
        for mode in [Mode::Enforce, Mode::Observe] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(Mode::parse("warn"), None);
        assert_eq!(Mode::default(), Mode::Enforce);
    }

    use super::*;

    /// The measured user-agents. pnpm and yarn both carry `npm/` further along, so the
    /// first token is the only thing that identifies the client.
    #[test]
    fn the_client_is_the_first_token_of_the_user_agent() {
        assert_eq!(
            client_name(Some("npm/9.9.4 node/v16.20.1 linux x64 workspaces/false")).as_deref(),
            Some("npm")
        );
        assert_eq!(
            client_name(Some("pnpm/10.33.0 npm/? node/v20.11.1 linux x64")).as_deref(),
            Some("pnpm"),
            "pnpm's user-agent contains npm/, and it is not npm"
        );
        assert_eq!(
            client_name(Some("yarn/1.22.22 npm/? node/v16.20.1 linux x64")).as_deref(),
            Some("yarn")
        );
    }

    #[test]
    fn a_missing_or_empty_user_agent_names_no_client() {
        assert_eq!(client_name(None), None);
        assert_eq!(client_name(Some("")), None);
        assert_eq!(client_name(Some("   ")), None);
        assert_eq!(client_name(Some("/leading-slash")), None);
    }

    #[test]
    fn client_names_are_matched_without_regard_to_case() {
        assert_eq!(client_name(Some("YARN/1.0")).as_deref(), Some("yarn"));
        let table = RefusalStatus::parse("npm/YARN=404").unwrap();
        assert_eq!(table.for_client(Ecosystem::Npm, Some("yarn/1.22.22")), 404);
    }

    /// 403 unless something says otherwise. §5: a 403 from a registry proxy means policy
    /// denied you.
    #[test]
    fn the_default_is_403() {
        let table = RefusalStatus::default();
        assert_eq!(table.default_status(), 403);
        assert_eq!(table.for_client(Ecosystem::Npm, Some("npm/9.9.4")), 403);
        assert_eq!(table.for_client(Ecosystem::Npm, None), 403);
        assert_eq!(RefusalStatus::parse("").unwrap(), RefusalStatus::default());
    }

    #[test]
    fn a_client_entry_overrides_the_default_for_that_client_only() {
        let table = RefusalStatus::parse("default=403, npm/pnpm=451").unwrap();
        assert_eq!(
            table.for_client(Ecosystem::Npm, Some("pnpm/10.33.0 npm/?")),
            451
        );
        assert_eq!(table.for_client(Ecosystem::Npm, Some("npm/9.9.4")), 403);
        assert_eq!(
            table.for_client(Ecosystem::Npm, Some("yarn/1.22.22 npm/?")),
            403
        );
    }

    /// The key is (ecosystem, client), so one ecosystem's entry does not move the other's.
    #[test]
    fn an_entry_applies_to_its_own_ecosystem_only() {
        let table = RefusalStatus::parse("default=403, pypi/pip=451, npm/pnpm=404").unwrap();
        assert_eq!(table.for_client(Ecosystem::PyPI, Some("pip/26.1.1")), 451);
        assert_eq!(
            table.for_client(Ecosystem::Npm, Some("pip/26.1.1")),
            403,
            "pip is not an npm client"
        );
        assert_eq!(
            table.for_client(Ecosystem::PyPI, Some("pnpm/10.33.0 npm/?")),
            403,
            "npm's entry does not answer for PyPI"
        );
        assert_eq!(
            table.for_client(Ecosystem::Npm, Some("pnpm/10.33.0 npm/?")),
            404
        );
    }

    /// An unrecognised client gets the default. A denial is meant to be terminal, so
    /// unlike the not-ready codes in §5 there is nothing to fall back toward.
    #[test]
    fn an_unknown_client_gets_the_default() {
        let table = RefusalStatus::parse("default=451, npm/npm=403").unwrap();
        assert_eq!(table.for_client(Ecosystem::Npm, Some("curl/8.0")), 451);
        assert_eq!(table.for_client(Ecosystem::Npm, None), 451);
        assert_eq!(table.for_client(Ecosystem::Npm, Some("npm/9.9.4")), 403);
    }

    #[test]
    fn the_default_can_be_set_on_its_own() {
        assert_eq!(
            RefusalStatus::parse("default=404")
                .unwrap()
                .default_status(),
            404
        );
    }

    /// A denial that answers 2xx is not a denial, and a 3xx would send the client
    /// somewhere else.
    #[test]
    fn statuses_outside_the_error_range_are_refused() {
        for spec in [
            "default=200",
            "default=302",
            "npm/npm=204",
            "default=99",
            "default=600",
        ] {
            let result = RefusalStatus::parse(spec);
            assert!(result.is_err(), "{spec} should not parse");
            assert!(
                result.unwrap_err().reason.contains("between 400 and 599"),
                "{spec}"
            );
        }
    }

    #[test]
    fn malformed_rules_say_what_was_expected() {
        for (spec, reason) in [
            (
                "npm/npm",
                "expected <ecosystem>/<client>=<status> or default=<status>",
            ),
            ("npm/npm=four-oh-three", "status is not a number"),
            ("npm=403", "expected <ecosystem>/<client>"),
            ("cargo/cargo=403", "unknown ecosystem"),
            ("npm/=403", "client is empty"),
        ] {
            let Err(e) = RefusalStatus::parse(spec) else {
                panic!("{spec} should not parse");
            };
            assert_eq!(e.reason, reason, "{spec}");
            assert!(e.to_string().contains(spec), "got: {e}");
        }
    }

    /// §5 reserves 5xx for the proxy not being ready. A denial wearing one tells an
    /// operator their registry is broken when it is doing its job. Allowed, and reported.
    #[test]
    fn a_5xx_refusal_is_allowed_and_reported_as_misleading() {
        let table = RefusalStatus::parse("default=403, npm/pnpm=503").unwrap();
        assert_eq!(table.for_client(Ecosystem::Npm, Some("pnpm/10")), 503);
        assert_eq!(table.misleading(), vec![503]);

        assert!(RefusalStatus::default().misleading().is_empty());
        assert_eq!(
            RefusalStatus::parse("default=503").unwrap().misleading(),
            vec![503]
        );
    }

    #[test]
    fn whitespace_and_trailing_commas_are_tolerated() {
        let table = RefusalStatus::parse("  default = 404 , npm / pnpm = 451 ,  ").unwrap();
        assert_eq!(table.default_status(), 404);
        assert_eq!(table.for_client(Ecosystem::Npm, Some("pnpm/1")), 451);
    }
}
