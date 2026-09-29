//! The command line: which command runs, and its arguments.
//!
//! Parsed by clap with its default features off, which leaves no colour and no typo
//! suggestions. See `docs/engineering_decisions/cli-parser-clap.md`. The proxy itself is
//! configured through the environment, which [`crate::env::help`] lists after the generated
//! help.
//!
//! Parsing is here rather than in `main.rs` so it is tested inside the coverage floor.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, PartialEq, Parser)]
#[command(
    name = "waharoa",
    version,
    about = "Dependency firewall",
    after_help = crate::env::help()
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum Command {
    /// Run the proxy in the foreground
    Daemon,
    /// Check whether this machine installs through the proxy
    Doctor,
    /// What this build does for each ecosystem, and which streams cover it
    Status,
    /// Why a package is allowed or refused
    Explain(Explain),
    /// Work with the audit log
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Read what the intel store records
    #[command(subcommand)]
    Intel(IntelCommand),
    /// Work with policy files
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Ask a running proxy for every artifact a lockfile locks, so each is analysed before
    /// a client asks for it. The exit code is the OR of 1 for a failure and 2 for an
    /// artifact still being analysed, and 4 on its own for an error
    Warm(Warm),
    #[command(about = format!(
        "Load OSV, GitHub, CISA KEV and Datadog intel into the Postgres at {}",
        crate::env::DATABASE_URL
    ))]
    Refresh,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum AuditCommand {
    /// Decide each pinned line again from the inputs it recorded. The exit code is the OR of
    /// 1 for a line that decides differently, 2 for one that cannot be decided again, and 4
    /// on its own for an error
    Verify(Verify),
}

#[derive(Debug, PartialEq, Args)]
pub struct Verify {
    /// The audit log
    pub log: PathBuf,
    /// A policy file a line may have been decided under, matched by digest
    #[arg(long, required = true)]
    pub policy: Vec<PathBuf>,
}

#[derive(Debug, PartialEq, Args)]
pub struct Warm {
    /// A lockfile whose artifacts to ask for. Repeatable
    #[arg(long, value_name = "PATH", required = true)]
    pub lockfile: Vec<PathBuf>,
    /// The proxy to ask [default: the public URL, or the listen address]
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,
    #[arg(
        long,
        value_name = "PLATFORM",
        value_parser = crate::lockfile::Target::parse,
        help = "Ask only for artifacts that install on this platform, <os>-<cpu> or \
                <os>-<cpu>-<libc> in npm's names, such as linux-x64. Repeatable [default: \
                this machine's]"
    )]
    pub platform: Vec<crate::lockfile::Target>,
    /// Ask for every platform's artifacts
    #[arg(long, conflicts_with = "platform")]
    pub all_platforms: bool,
    /// Stop asking for an artifact still being analysed after this long
    #[arg(long, value_name = "SECONDS", default_value_t = crate::warm::DEFAULT_DEADLINE.as_secs())]
    pub deadline: u64,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum IntelCommand {
    /// Each stream every `waharoa refresh` loaded or did not, newest first
    History(History),
}

#[derive(Debug, PartialEq, Args)]
pub struct History {
    /// Most entries to print
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
    pub limit: u32,
}

/// `explain --policy` or `explain <purl>`, exactly one.
#[derive(Debug, PartialEq, Args)]
#[group(required = true, multiple = false)]
pub struct Explain {
    #[arg(long, help = format!(
        "The policy in {} as loaded, and which checks can fire",
        crate::env::POLICY
    ))]
    pub policy: bool,
    /// One package version, for example pkg:npm/lodash@4.17.21
    pub purl: Option<String>,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum PolicyCommand {
    /// Load a policy as the proxy does, and list the package entries that do nothing. Exits
    /// 1 if it is refused
    Check(Check),
    /// Compare two policies over the audit log's and lockfiles' packages. The exit code is the
    /// OR of 1 for a loosening, 2 for a tightening, and 4 on its own for an error
    Diff(Diff),
}

#[derive(Debug, PartialEq, Args)]
pub struct Check {
    /// The policy file
    pub path: PathBuf,
    /// Judge the policy as of this date [default: today, UTC]
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub as_of: Option<jiff::civil::Date>,
    /// Also exit 1 when an entry changes nothing or never wins
    #[arg(long)]
    pub strict: bool,
    /// Ask each registry when the versions cooldown waivers name were published, and
    /// report the waivers their version no longer needs
    #[arg(long)]
    pub fetch: bool,
}

#[derive(Debug, PartialEq, Args)]
pub struct Diff {
    /// The policy in force
    pub from: PathBuf,
    /// The policy that would replace it
    pub to: PathBuf,
    #[arg(
        long,
        value_name = "DATE",
        value_parser = when,
        help = "Judge <FROM> as of this date, YYYY-MM-DD or +<days>d [default: today, UTC]"
    )]
    pub from_date: Option<When>,
    #[arg(
        long,
        value_name = "DATE",
        value_parser = when,
        help = "Judge <TO> as of this date, YYYY-MM-DD or +<days>d [default: today, UTC]"
    )]
    pub to_date: Option<When>,
    /// Judge both against this kept intel snapshot, not the store's latest load
    #[arg(long, value_name = "ID")]
    pub snapshot: Option<String>,
    /// Compare over this lockfile's packages too. Repeatable
    #[arg(long, value_name = "PATH")]
    pub lockfile: Vec<PathBuf>,
}

/// A date given to `policy diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    On(jiff::civil::Date),
    /// `+<days>d`.
    DaysFromToday(u32),
}

impl When {
    /// The date this is, when today is `today`. Past the last date jiff has, that date.
    pub fn date(self, today: jiff::civil::Date) -> jiff::civil::Date {
        match self {
            Self::On(date) => date,
            Self::DaysFromToday(days) => jiff::Span::new()
                .try_days(i64::from(days))
                .map_or(jiff::civil::Date::MAX, |span| today.saturating_add(span)),
        }
    }
}

fn when(value: &str) -> Result<When, String> {
    let parsed = match value.strip_prefix('+').and_then(|v| v.strip_suffix('d')) {
        Some(days) => days.parse().ok().map(When::DaysFromToday),
        None => value.parse().ok().map(When::On),
    };
    parsed.ok_or_else(|| format!("`{value}` is neither YYYY-MM-DD nor +<days>d"))
}

/// The exit code for a command line clap refused or answered.
///
/// A refused command line that starts `policy diff` exits
/// [`ERROR`](crate::policy::diff::ERROR), because 2 is that command's tightening bit. Every
/// other command line exits what clap gives: 0 for help and version, 2 for a refusal.
pub fn exit_code(error: &clap::Error, args: &[std::ffi::OsString]) -> u8 {
    let code = u8::try_from(error.exit_code()).unwrap_or(crate::policy::diff::ERROR);
    let words: Vec<&str> = args
        .iter()
        .skip(1)
        .take(2)
        .filter_map(|a| a.to_str())
        .collect();
    if code != 0 && words == ["policy", "diff"] {
        crate::policy::diff::ERROR
    } else {
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("waharoa").chain(args.iter().copied()))
    }

    fn diff(args: &[&str]) -> Result<Diff, clap::Error> {
        match parse(args)?.command {
            Command::Policy(PolicyCommand::Diff(diff)) => Ok(diff),
            other => panic!("{args:?} parsed as {other:?}"),
        }
    }

    /// Assert `args` ends parsing early with `kind`, and hand back the error.
    fn stops(args: &[&str], kind: ErrorKind) -> clap::Error {
        match parse(args) {
            Err(e) => {
                assert_eq!(e.kind(), kind, "{args:?}: {e}");
                e
            }
            Ok(parsed) => panic!("{args:?} parsed as {parsed:?}"),
        }
    }

    #[test]
    fn the_definition_is_one_clap_accepts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_command_prints_the_help_and_exits_2() {
        let refused = stops(&[], ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
        assert_eq!(refused.exit_code(), 2);
    }

    #[test]
    fn each_command_parses_to_its_arguments() {
        assert_eq!(parse(&["daemon"]).expect("parses").command, Command::Daemon);
        assert_eq!(parse(&["doctor"]).expect("parses").command, Command::Doctor);
        assert_eq!(
            parse(&["refresh"]).expect("parses").command,
            Command::Refresh
        );
        assert_eq!(
            parse(&["intel", "history"]).expect("parses").command,
            Command::Intel(IntelCommand::History(History { limit: 20 }))
        );
        assert_eq!(
            parse(&["intel", "history", "--limit", "1"])
                .expect("parses")
                .command,
            Command::Intel(IntelCommand::History(History { limit: 1 }))
        );
        assert_eq!(
            parse(&["explain", "--policy"]).expect("parses").command,
            Command::Explain(Explain {
                policy: true,
                purl: None
            })
        );
        assert_eq!(
            parse(&["explain", "pkg:npm/lodash@4.17.21"])
                .expect("parses")
                .command,
            Command::Explain(Explain {
                policy: false,
                purl: Some("pkg:npm/lodash@4.17.21".to_owned())
            })
        );
        assert_eq!(
            diff(&["policy", "diff", "a.yaml", "b.yaml"]).expect("parses"),
            Diff {
                from: "a.yaml".into(),
                to: "b.yaml".into(),
                from_date: None,
                to_date: None,
                snapshot: None,
                lockfile: Vec::new(),
            }
        );
        assert_eq!(
            parse(&[
                "policy",
                "check",
                "p.yaml",
                "--strict",
                "--as-of",
                "2026-01-01"
            ])
            .expect("parses")
            .command,
            Command::Policy(PolicyCommand::Check(Check {
                path: "p.yaml".into(),
                as_of: Some(jiff::civil::date(2026, 1, 1)),
                strict: true,
                fetch: false,
            }))
        );
    }

    #[test]
    fn audit_verify_takes_a_log_and_one_or_more_policies() {
        assert_eq!(
            parse(&[
                "audit", "verify", "a.jsonl", "--policy", "p.yaml", "--policy", "q.yaml"
            ])
            .expect("parses")
            .command,
            Command::Audit(AuditCommand::Verify(Verify {
                log: "a.jsonl".into(),
                policy: vec!["p.yaml".into(), "q.yaml".into()],
            }))
        );
        assert!(parse(&["audit", "verify", "a.jsonl"]).is_err());
    }

    /// The hand-written parser answered `--as-of 2026-01-01` with a usage error, although its
    /// usage line spelled it that way, and read only `--as-of=2026-01-01`.
    #[test]
    fn a_value_is_taken_with_a_space_or_an_equals_sign() {
        let date = When::On(jiff::civil::date(2026, 1, 1));
        for args in [
            ["policy", "diff", "a", "b", "--from-date", "2026-01-01"].as_slice(),
            &["policy", "diff", "a", "b", "--from-date=2026-01-01"],
            &["policy", "diff", "--from-date", "2026-01-01", "a", "b"],
        ] {
            assert_eq!(
                diff(args).expect("parses").from_date,
                Some(date),
                "{args:?}"
            );
        }
    }

    #[test]
    fn a_date_is_a_calendar_date_or_days_after_today() {
        let today = jiff::civil::date(2026, 9, 14);
        for (given, expected) in [
            ("2026-01-01", jiff::civil::date(2026, 1, 1)),
            ("+30d", jiff::civil::date(2026, 10, 14)),
            ("+0d", today),
        ] {
            let parsed = diff(&["policy", "diff", "a", "b", "--to-date", given]).expect(given);
            assert_eq!(
                parsed.to_date.expect(given).date(today),
                expected,
                "{given}"
            );
            assert_eq!(parsed.from_date, None);
        }
        assert_eq!(
            When::DaysFromToday(u32::MAX).date(today),
            jiff::civil::Date::MAX
        );
        for bad in ["30d", "+30", "+-3d", "+d", "tomorrow", "2026-13-01"] {
            let e = stops(
                &["policy", "diff", "a", "b", "--from-date", bad],
                ErrorKind::ValueValidation,
            );
            assert!(
                e.to_string()
                    .contains(&format!("`{bad}` is neither YYYY-MM-DD nor +<days>d")),
                "{e}"
            );
        }
    }

    #[test]
    fn a_malformed_policy_diff_exits_its_error_bit_and_other_commands_exit_2() {
        let code = |args: &[&str]| {
            let argv: Vec<std::ffi::OsString> = std::iter::once("waharoa")
                .chain(args.iter().copied())
                .map(Into::into)
                .collect();
            let e = Cli::try_parse_from(&argv).expect_err("answered or refused");
            exit_code(&e, &argv)
        };
        let error = crate::policy::diff::ERROR;
        assert_eq!(code(&["policy", "diff", "a"]), error);
        assert_eq!(
            code(&["policy", "diff", "--lockfile", "x", "a", "b", "c"]),
            error
        );
        assert_eq!(
            code(&["policy", "diff", "a", "b", "--as-of", "2026-01-01"]),
            error
        );
        assert_eq!(code(&["policy", "diff", "--help"]), 0);
        assert_eq!(code(&["policy", "check"]), 2);
        assert_eq!(code(&["policy", "dif", "a", "b"]), 2);
        assert_eq!(code(&["doctr"]), 2);
        assert_eq!(code(&["--version"]), 0);
    }

    #[test]
    fn a_snapshot_id_is_taken_as_given() {
        let parsed = diff(&["policy", "diff", "a", "b", "--snapshot", "sha256:x"]).expect("parses");
        assert_eq!(parsed.snapshot.as_deref(), Some("sha256:x"));
    }

    #[test]
    fn a_lockfile_can_be_given_more_than_once() {
        let parsed = diff(&[
            "policy",
            "diff",
            "a",
            "b",
            "--lockfile",
            "app/package-lock.json",
            "--lockfile",
            "yarn.lock",
        ])
        .expect("parses");
        assert_eq!(
            parsed.lockfile,
            [
                PathBuf::from("app/package-lock.json"),
                PathBuf::from("yarn.lock")
            ]
        );
        assert!(
            diff(&["policy", "diff", "a", "b"])
                .expect("parses")
                .lockfile
                .is_empty()
        );
    }

    /// Each of these the hand-written parser accepted, ignored or misread.
    #[test]
    fn a_malformed_command_line_is_refused_with_the_reason() {
        for (args, kind) in [
            (["doctr"].as_slice(), ErrorKind::InvalidSubcommand),
            (&["--bogus"], ErrorKind::UnknownArgument),
            (
                &["policy", "diff", "a", "b", "--bogus"],
                ErrorKind::UnknownArgument,
            ),
            (&["policy", "diff", "a"], ErrorKind::MissingRequiredArgument),
            (
                &["policy", "diff", "a", "b", "c"],
                ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "policy",
                    "diff",
                    "a",
                    "b",
                    "--to-date=2026-01-01",
                    "--to-date=2026-01-02",
                ],
                ErrorKind::ArgumentConflict,
            ),
            (
                &["policy", "diff", "a", "b", "--from-date", "nope"],
                ErrorKind::ValueValidation,
            ),
            (
                &["policy", "diff", "a", "b", "--as-of", "2026-01-01"],
                ErrorKind::UnknownArgument,
            ),
            (&["explain"], ErrorKind::MissingRequiredArgument),
            (&["explain", "--polcy"], ErrorKind::UnknownArgument),
            (
                &["explain", "--policy", "pkg:npm/a@1.0.0"],
                ErrorKind::ArgumentConflict,
            ),
            (
                &["explain", "pkg:npm/a@1.0.0", "extra"],
                ErrorKind::UnknownArgument,
            ),
            (&["doctor", "extra"], ErrorKind::UnknownArgument),
            (&["policy", "check"], ErrorKind::MissingRequiredArgument),
            (&["policy", "check", "a", "b"], ErrorKind::UnknownArgument),
            (
                &["intel", "history", "--limit", "0"],
                ErrorKind::ValueValidation,
            ),
            (
                &["intel", "history", "--limit", "many"],
                ErrorKind::ValueValidation,
            ),
            (&["intel", "histroy"], ErrorKind::InvalidSubcommand),
        ] {
            stops(args, kind);
        }
    }

    #[test]
    fn help_and_version_are_answered_rather_than_read_as_arguments() {
        for (args, kind) in [
            (["--help"].as_slice(), ErrorKind::DisplayHelp),
            (&["help"], ErrorKind::DisplayHelp),
            (&["explain", "--help"], ErrorKind::DisplayHelp),
            (&["policy", "diff", "-h"], ErrorKind::DisplayHelp),
            (&["--version"], ErrorKind::DisplayVersion),
        ] {
            stops(args, kind);
        }
        // Exit 0, where every refusal above exits 2.
        assert_eq!(stops(&["--help"], ErrorKind::DisplayHelp).exit_code(), 0);
        assert_eq!(
            stops(&["doctr"], ErrorKind::InvalidSubcommand).exit_code(),
            2
        );
    }

    /// Debug builds, which is what `cargo test` compiles, show [`crate::env::DEFER_TEST`]
    /// too.
    #[test]
    fn the_help_renders_as_the_golden_files_say() {
        // Rendered from the parse, which is what the binary prints: a subcommand rendered on
        // its own omits `waharoa` from its usage line.
        for (args, name) in [
            (["--help"].as_slice(), "help.txt"),
            (&["explain", "--help"], "explain.txt"),
            (&["audit", "verify", "--help"], "audit-verify.txt"),
            (&["intel", "history", "--help"], "intel-history.txt"),
            (&["policy", "check", "--help"], "policy-check.txt"),
            (&["policy", "diff", "--help"], "policy-diff.txt"),
            (&["warm", "--help"], "warm.txt"),
        ] {
            let help = stops(args, ErrorKind::DisplayHelp);
            crate::golden::assert_matches("cli", name, &help.render().to_string());
        }
    }
}
