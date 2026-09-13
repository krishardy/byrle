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
    about = "Dependency firewall. With no command, runs the proxy.",
    after_help = crate::env::help()
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum Command {
    /// Check whether this machine installs through the proxy
    Doctor,
    /// Why a package is allowed or refused
    Explain(Explain),
    /// Work with policy files
    #[command(subcommand)]
    Policy(PolicyCommand),
    #[command(about = format!(
        "Load OSV's npm advisories into the Postgres at {}",
        crate::env::DATABASE_URL
    ))]
    Refresh,
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
    /// Compare two policies over the audit log's packages. Exits 1 on any loosening
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
}

#[derive(Debug, PartialEq, Args)]
pub struct Diff {
    /// The policy in force
    pub from: PathBuf,
    /// The policy that would replace it
    pub to: PathBuf,
    /// Judge both policies as of this date [default: today, UTC]
    #[arg(long, value_name = "YYYY-MM-DD")]
    pub as_of: Option<jiff::civil::Date>,
    /// Accepted so it can be refused by name: nothing pins a snapshot yet
    #[arg(long, hide = true, value_name = "ID")]
    pub snapshot: Option<String>,
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
            Some(Command::Policy(PolicyCommand::Diff(diff))) => Ok(diff),
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
    fn no_command_runs_the_proxy() {
        assert_eq!(parse(&[]).expect("parses"), Cli { command: None });
    }

    #[test]
    fn each_command_parses_to_its_arguments() {
        assert_eq!(
            parse(&["doctor"]).expect("parses").command,
            Some(Command::Doctor)
        );
        assert_eq!(
            parse(&["refresh"]).expect("parses").command,
            Some(Command::Refresh)
        );
        assert_eq!(
            parse(&["explain", "--policy"]).expect("parses").command,
            Some(Command::Explain(Explain {
                policy: true,
                purl: None
            }))
        );
        assert_eq!(
            parse(&["explain", "pkg:npm/lodash@4.17.21"])
                .expect("parses")
                .command,
            Some(Command::Explain(Explain {
                policy: false,
                purl: Some("pkg:npm/lodash@4.17.21".to_owned())
            }))
        );
        assert_eq!(
            diff(&["policy", "diff", "a.yaml", "b.yaml"]).expect("parses"),
            Diff {
                from: "a.yaml".into(),
                to: "b.yaml".into(),
                as_of: None,
                snapshot: None,
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
            Some(Command::Policy(PolicyCommand::Check(Check {
                path: "p.yaml".into(),
                as_of: Some(jiff::civil::date(2026, 1, 1)),
                strict: true,
            })))
        );
    }

    /// The hand-written parser answered `--as-of 2026-01-01` with a usage error, although its
    /// usage line spelled it that way, and read only `--as-of=2026-01-01`.
    #[test]
    fn a_value_is_taken_with_a_space_or_an_equals_sign() {
        let date = jiff::civil::date(2026, 1, 1);
        for args in [
            ["policy", "diff", "a", "b", "--as-of", "2026-01-01"].as_slice(),
            &["policy", "diff", "a", "b", "--as-of=2026-01-01"],
            &["policy", "diff", "--as-of", "2026-01-01", "a", "b"],
        ] {
            assert_eq!(diff(args).expect("parses").as_of, Some(date), "{args:?}");
        }
    }

    #[test]
    fn a_hidden_snapshot_is_still_parsed_so_it_can_be_refused() {
        let parsed = diff(&["policy", "diff", "a", "b", "--snapshot", "sha256:x"]).expect("parses");
        assert_eq!(parsed.snapshot.as_deref(), Some("sha256:x"));
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
                    "--as-of=2026-01-01",
                    "--as-of=2026-01-02",
                ],
                ErrorKind::ArgumentConflict,
            ),
            (
                &["policy", "diff", "a", "b", "--as-of", "nope"],
                ErrorKind::ValueValidation,
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
            (&["policy", "check", "--help"], "policy-check.txt"),
            (&["policy", "diff", "--help"], "policy-diff.txt"),
        ] {
            let help = stops(args, ErrorKind::DisplayHelp);
            crate::golden::assert_matches("cli", name, &help.render().to_string());
        }
    }
}
