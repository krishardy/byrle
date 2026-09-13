//! The command line: which command runs, and its arguments.
//!
//! Parsed by clap with its default features off, which leaves no colour and no typo
//! suggestions. See `docs/engineering_decisions/cli-parser-clap.md`. The proxy itself is
//! configured through the environment, which [`environment`] documents after the generated
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
    after_help = environment()
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
    /// Load OSV's npm advisories into the Postgres at WAHAROA_DATABASE_URL
    Refresh,
}

/// `explain --policy` or `explain <purl>`, exactly one.
#[derive(Debug, PartialEq, Args)]
#[group(required = true, multiple = false)]
pub struct Explain {
    /// The policy in WAHAROA_POLICY as loaded, and which checks can fire
    #[arg(long)]
    pub policy: bool,
    /// One package version, for example pkg:npm/lodash@4.17.21
    pub purl: Option<String>,
}

#[derive(Debug, PartialEq, Subcommand)]
pub enum PolicyCommand {
    /// Compare two policies over the audit log's packages. Exits 1 on any loosening
    Diff(Diff),
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

const ENVIRONMENT: &str = "\
Proxy configuration, all through the environment:

  WAHAROA_LISTEN                    address to listen on (127.0.0.1:8080)
  WAHAROA_UPSTREAM                  registry to forward to (https://registry.npmjs.org)
  WAHAROA_PUBLIC_URL                address written into artifact URLs, and therefore
                                    into lockfiles. Defaults to each request's own Host,
                                    which is rarely what you want.
  WAHAROA_ARTIFACT_ORIGINS          comma-separated origins this proxy also serves
  WAHAROA_ALLOW_DIRECT_ORIGINS      comma-separated origins the proxy does not serve and
                                    permits anyway, fetched directly and unexamined
  WAHAROA_REWRITE_ARTIFACTS=0       do not point artifact URLs at the proxy. pnpm and
                                    yarn then fetch artifacts without the proxy seeing
                                    them.
  WAHAROA_CA_BUNDLE                 PEM bundle for the upstream connection
  WAHAROA_CA_BUNDLE_EXCLUSIVE=1     trust only that bundle, not the public roots
  WAHAROA_MAX_PACKUMENT_BYTES       ceiling on a packument body (32 MiB)
  WAHAROA_MAX_RECORDS               packument records held in memory (50,000)
  WAHAROA_MAX_VERIFIED              verified artifact digests remembered (50,000)
  WAHAROA_DATABASE_URL              Postgres holding intel from `waharoa refresh`. With a
                                    policy, known_malware is enforced from it, and a
                                    store that cannot answer is a 503
  WAHAROA_POLICY                    path to a policy file. Loaded, validated and
                                    enforced. Startup reports which checks can fire
  WAHAROA_AUDIT_LOG                 path for one JSON line per policy decision,
                                    appended. Refuses to start if it cannot be opened
  WAHAROA_EXPIRY_CEILING_DAYS       how far ahead a `packages` entry may be dated (90)
  WAHAROA_MAX_CONCURRENT_PACKUMENTS packuments decoded at once (8)
  WAHAROA_REFUSAL_STATUS            status a refusal answers with, per client, e.g.
                                    \"default=403,npm/pnpm=451\" (default 403)
  WAHAROA_REFUSE_UNSERVABLE=0       forward versions whose artifacts this proxy cannot
                                    see, instead of removing them from the packument";

/// The deferral knob is not compiled into a release binary, so a release binary does not
/// advertise it either.
#[cfg(debug_assertions)]
const DEBUG_ENVIRONMENT: &str = "
  WAHAROA_DEFER_TEST                DEBUG BUILDS ONLY: answer every matching request with
                                    a deferral instead of fetching, so client retry
                                    behaviour can be measured. `<status>:<seconds|none>:
                                    <packument|tarball|all>[:<seconds>]`, e.g.
                                    \"429:1:tarball\" or \"503:1:all:8\"";
#[cfg(not(debug_assertions))]
const DEBUG_ENVIRONMENT: &str = "";

/// The environment variables the proxy reads, shown after the generated help.
pub fn environment() -> String {
    format!("{ENVIRONMENT}{DEBUG_ENVIRONMENT}")
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

    fn golden(name: &str, actual: &str) {
        let path = format!("{}/tests/fixtures/cli/{name}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("WAHAROA_BLESS").is_some() {
            std::fs::write(&path, actual).expect("golden file should write");
        }
        let expected = std::fs::read_to_string(&path).expect("golden file should exist");
        assert!(
            expected == actual,
            "{name} differs. Rerun with WAHAROA_BLESS=1 and review the diff:\n{actual}"
        );
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
        ] {
            match parse(args) {
                Err(e) => assert_eq!(e.kind(), kind, "{args:?}: {e}"),
                Ok(parsed) => panic!("{args:?} parsed as {parsed:?}"),
            }
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
            match parse(args) {
                Err(e) => assert_eq!(e.kind(), kind, "{args:?}: {e}"),
                Ok(parsed) => panic!("{args:?} parsed as {parsed:?}"),
            }
        }
        // Exit 0, where every refusal above exits 2.
        assert_eq!(parse(&["--help"]).expect_err("help").exit_code(), 0);
        assert_eq!(parse(&["doctr"]).expect_err("refused").exit_code(), 2);
    }

    /// Debug builds, which is what `cargo test` compiles, show `WAHAROA_DEFER_TEST` too.
    #[test]
    fn the_help_renders_as_the_golden_files_say() {
        // Rendered from the parse, which is what the binary prints: a subcommand rendered on
        // its own omits `waharoa` from its usage line.
        for (args, name) in [
            (["--help"].as_slice(), "help.txt"),
            (&["explain", "--help"], "explain.txt"),
            (&["policy", "diff", "--help"], "policy-diff.txt"),
        ] {
            let help = parse(args).expect_err("help is an early exit");
            golden(name, &help.render().to_string());
        }
    }
}
