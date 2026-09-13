//! Every environment variable waharoa reads: its name, default, help text and parsing.
//!
//! No variable name appears anywhere else in the Rust code. Other modules use the [`Var`]
//! constants here, as values and inside messages, and
//! `a_variable_name_appears_only_in_this_module` fails on a name written anywhere else. The
//! defaults live here too, so `--help` is rendered from the values the code uses. See
//! `docs/engineering_decisions/environment-variables.md`.
//!
//! An empty value is the same as an unset one. A value that does not parse is an
//! [`EnvError`] naming the variable and the value, and the binary refuses to start on it.

#[cfg(debug_assertions)]
use crate::defer::DeferTest;
use crate::refusal::RefusalStatus;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

/// One environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Var {
    pub name: &'static str,
    /// Written after the name in `--help`, such as `=0` for a flag that is on by default.
    shown: &'static str,
    /// Wrapped by hand, because clap's `wrap_help` feature is off.
    help: &'static [&'static str],
    default: Default,
    kind: Kind,
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Configures the proxy or a command. Listed in `--help`.
    Runtime,
    /// Read only by a debug build, and listed only in a debug build's `--help`.
    Debug,
    /// Read by tests, never by the binary.
    Test,
    /// Another program's variable.
    External,
}

/// How a default is shown in `--help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Default {
    None,
    Text(&'static str),
    Number(u64),
    /// In MiB when it divides evenly.
    Bytes(usize),
}

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// npm's public registry, which `npm` also names for its own origin rules.
pub const DEFAULT_UPSTREAM: &str = crate::npm::DEFAULT_REGISTRY;

/// Default ceiling on a packument body, applied both to the bytes buffered and to the
/// bytes decompression is allowed to produce.
///
/// The largest packument measured is typescript: 8.7 MB as the abbreviated document,
/// 15.7 MB as the full one, 2.0 MB gzipped. This is roughly 2x headroom on that. Over
/// the limit the proxy forwards the response without normalising it, because an install
/// must not fail on account of what the proxy could not inspect.
pub const DEFAULT_MAX_PACKUMENT_BYTES: usize = 32 * 1024 * 1024;

/// Default record store budget, in records rather than bytes.
///
/// Roughly five installs of the size measured in `store`. A record is on the order of a few
/// hundred bytes, so this is tens of megabytes; `RecordStore::records` reports the live
/// count for anyone measuring it properly.
pub const DEFAULT_MAX_RECORDS: usize = 50_000;

/// Default verified-artifact budget, in artifacts.
///
/// An entry is an algorithm and a digest, on the order of 64 bytes, so this is a few
/// megabytes. Larger than the record store's budget would be pointless: an artifact only
/// reaches `verified` after a packument named it.
pub const DEFAULT_MAX_VERIFIED: usize = 50_000;

/// Default ceiling on how many packuments are decoded and rewritten at once.
///
/// Reading a packument costs far more than the bytes on the wire: the decoded copy, the
/// JSON value tree the rewrite walks, the re-serialised output, and the gzip buffer are
/// all live together. Measured with 24 simultaneous requests for the largest full
/// packuments (typescript, @types/node, react, next, @angular/core, eslint, webpack,
/// aws-sdk), the proxy peaked at 1,348 MB while the encoded bodies totalled 27.6 MB.
/// That is roughly 56 MB per request in flight, and nothing bounded how many there were.
///
/// Eight keeps the worst case near half a gigabyte. A normal install does not reach it:
/// npm's own request parallelism held a six-package install with 165 packuments to a
/// 141 MB peak.
pub const DEFAULT_MAX_CONCURRENT_PACKUMENTS: usize = 8;

/// §5.5's ceiling on how far ahead a package entry may be dated.
///
/// Long enough to cover a review cycle, short enough that an entry nobody looked at
/// again lapses within a quarter.
pub const DEFAULT_EXPIRY_CEILING_DAYS: i64 = 90;

/// A month of daily refreshes. npm's rows were 5,577,231 bytes gzipped on 2026-09-13, and a
/// source whose rows did not change is not written again.
pub const DEFAULT_SNAPSHOT_LIMIT: usize = 30;

/// What §5 says a policy denial is: 403 means policy denied you.
pub const DEFAULT_REFUSAL_STATUS: u16 = 403;

pub const DEFAULT_LOG_FILTER: &str = "waharoa=info";

pub const LISTEN: Var = runtime("WAHAROA_LISTEN", "", &["address to listen on"])
    .with_default(Default::Text(DEFAULT_LISTEN));
pub const UPSTREAM: Var = runtime("WAHAROA_UPSTREAM", "", &["registry to forward to"])
    .with_default(Default::Text(DEFAULT_UPSTREAM));
pub const PUBLIC_URL: Var = runtime(
    "WAHAROA_PUBLIC_URL",
    "",
    &[
        "address written into artifact URLs, and therefore",
        "into lockfiles. Defaults to each request's own Host,",
        "which is rarely what you want.",
    ],
);
pub const ARTIFACT_ORIGINS: Var = runtime(
    "WAHAROA_ARTIFACT_ORIGINS",
    "",
    &["comma-separated origins this proxy also serves"],
);
pub const ALLOW_DIRECT_ORIGINS: Var = runtime(
    "WAHAROA_ALLOW_DIRECT_ORIGINS",
    "",
    &[
        "comma-separated origins the proxy does not serve and",
        "permits anyway, fetched directly and unexamined",
    ],
);
pub const REWRITE_ARTIFACTS: Var = runtime(
    "WAHAROA_REWRITE_ARTIFACTS",
    "=0",
    &[
        "do not point artifact URLs at the proxy. pnpm and",
        "yarn then fetch artifacts without the proxy seeing",
        "them.",
    ],
);
pub const CA_BUNDLE: Var = runtime(
    "WAHAROA_CA_BUNDLE",
    "",
    &["PEM bundle for the upstream connection"],
);
pub const CA_BUNDLE_EXCLUSIVE: Var = runtime(
    "WAHAROA_CA_BUNDLE_EXCLUSIVE",
    "=1",
    &["trust only that bundle, not the public roots"],
);
pub const MAX_PACKUMENT_BYTES: Var = runtime(
    "WAHAROA_MAX_PACKUMENT_BYTES",
    "",
    &["ceiling on a packument body"],
)
.with_default(Default::Bytes(DEFAULT_MAX_PACKUMENT_BYTES));
pub const MAX_RECORDS: Var = runtime(
    "WAHAROA_MAX_RECORDS",
    "",
    &["packument records held in memory"],
)
.with_default(Default::Number(DEFAULT_MAX_RECORDS as u64));
pub const MAX_VERIFIED: Var = runtime(
    "WAHAROA_MAX_VERIFIED",
    "",
    &["verified artifact digests remembered"],
)
.with_default(Default::Number(DEFAULT_MAX_VERIFIED as u64));
pub const DATABASE_URL: Var = runtime(
    "WAHAROA_DATABASE_URL",
    "",
    &[
        "Postgres holding intel from `waharoa refresh`. With a",
        "policy, known_malware is enforced from it, and a",
        "store that cannot answer is a 503",
    ],
);
pub const SNAPSHOT_DIR: Var = runtime(
    "WAHAROA_SNAPSHOT_DIR",
    "",
    &[
        "directory `waharoa refresh` keeps each snapshot in,",
        "for `policy diff --snapshot`. Unset, none is kept",
    ],
);
pub const SNAPSHOT_LIMIT: Var = runtime(
    "WAHAROA_SNAPSHOT_LIMIT",
    "",
    &["most snapshots kept there; a refresh removes older ones"],
)
.with_default(Default::Number(DEFAULT_SNAPSHOT_LIMIT as u64));
pub const POLICY: Var = runtime(
    "WAHAROA_POLICY",
    "",
    &[
        "path to a policy file. Loaded, validated and",
        "enforced. Startup reports which checks can fire",
    ],
);
pub const AUDIT_LOG: Var = runtime(
    "WAHAROA_AUDIT_LOG",
    "",
    &[
        "path for one JSON line per policy decision,",
        "appended. Refuses to start if it cannot be opened",
    ],
);
pub const EXPIRY_CEILING_DAYS: Var = runtime(
    "WAHAROA_EXPIRY_CEILING_DAYS",
    "",
    &["how many days ahead a `packages` entry may be dated"],
)
.with_default(Default::Number(DEFAULT_EXPIRY_CEILING_DAYS as u64));
pub const MAX_CONCURRENT_PACKUMENTS: Var = runtime(
    "WAHAROA_MAX_CONCURRENT_PACKUMENTS",
    "",
    &["packuments decoded at once"],
)
.with_default(Default::Number(DEFAULT_MAX_CONCURRENT_PACKUMENTS as u64));
pub const REFUSAL_STATUS: Var = runtime(
    "WAHAROA_REFUSAL_STATUS",
    "",
    &[
        "status a refusal answers with, per client, e.g.",
        "\"default=403,npm/pnpm=451\"",
    ],
)
.with_default(Default::Number(DEFAULT_REFUSAL_STATUS as u64));
pub const REFUSE_UNSERVABLE: Var = runtime(
    "WAHAROA_REFUSE_UNSERVABLE",
    "=0",
    &[
        "forward versions whose artifacts this proxy cannot",
        "see, instead of removing them from the packument",
    ],
);
pub const LOG_FILTER: Var = runtime("RUST_LOG", "", &["log filter, in tracing's syntax"])
    .with_default(Default::Text(DEFAULT_LOG_FILTER));
pub const DEFER_TEST: Var = Var {
    kind: Kind::Debug,
    ..runtime(
        "WAHAROA_DEFER_TEST",
        "",
        &[
            "DEBUG BUILDS ONLY: answer every matching request with",
            "a deferral instead of fetching, so client retry",
            "behaviour can be measured. `<status>:<seconds|none>:",
            "<packument|tarball|all>[:<seconds>]`, e.g.",
            "\"429:1:tarball\" or \"503:1:all:8\"",
        ],
    )
};

pub const BLESS: Var = other(
    Kind::Test,
    "WAHAROA_BLESS",
    &["rewrite golden files instead of comparing against them"],
);
pub const NPM_CORPUS: Var = other(
    Kind::Test,
    "WAHAROA_NPM_CORPUS",
    &["directory of abbreviated packuments for the ignored corpus test"],
);
pub const NPM_CORPUS_FULL: Var = other(
    Kind::Test,
    "WAHAROA_NPM_CORPUS_FULL",
    &["directory of full packuments for the ignored corpus test"],
);
pub const TEST_DATABASE_URL: Var = other(
    Kind::Test,
    "WAHAROA_TEST_DATABASE_URL",
    &["Postgres the integration tests run against, set by `make test-integration`"],
);
pub const HOME: Var = other(
    Kind::External,
    "HOME",
    &["the user's home directory, under which bun keeps its default cache"],
);
pub const BUN_INSTALL_CACHE_DIR: Var = other(
    Kind::External,
    "BUN_INSTALL_CACHE_DIR",
    &["where bun keeps its cache, when set"],
);

/// Every variable, in the order `--help` lists them.
pub const ALL: [Var; 28] = [
    LISTEN,
    UPSTREAM,
    PUBLIC_URL,
    ARTIFACT_ORIGINS,
    ALLOW_DIRECT_ORIGINS,
    REWRITE_ARTIFACTS,
    CA_BUNDLE,
    CA_BUNDLE_EXCLUSIVE,
    MAX_PACKUMENT_BYTES,
    MAX_RECORDS,
    MAX_VERIFIED,
    DATABASE_URL,
    SNAPSHOT_DIR,
    SNAPSHOT_LIMIT,
    POLICY,
    AUDIT_LOG,
    EXPIRY_CEILING_DAYS,
    MAX_CONCURRENT_PACKUMENTS,
    REFUSAL_STATUS,
    REFUSE_UNSERVABLE,
    LOG_FILTER,
    DEFER_TEST,
    BLESS,
    NPM_CORPUS,
    NPM_CORPUS_FULL,
    TEST_DATABASE_URL,
    HOME,
    BUN_INSTALL_CACHE_DIR,
];

const fn runtime(name: &'static str, shown: &'static str, help: &'static [&'static str]) -> Var {
    Var {
        name,
        shown,
        help,
        default: Default::None,
        kind: Kind::Runtime,
    }
}

const fn other(kind: Kind, name: &'static str, help: &'static [&'static str]) -> Var {
    Var {
        kind,
        ..runtime(name, "", help)
    }
}

impl Var {
    const fn with_default(self, default: Default) -> Var {
        Var { default, ..self }
    }

    /// Whether `--help` lists it: what this build of the binary reads.
    fn listed(&self) -> bool {
        match self.kind {
            Kind::Runtime => true,
            Kind::Debug => cfg!(debug_assertions),
            Kind::Test | Kind::External => false,
        }
    }

    fn default_shown(&self) -> Option<String> {
        match self.default {
            Default::None => None,
            Default::Text(text) => Some(text.to_owned()),
            Default::Number(n) => Some(n.to_string()),
            Default::Bytes(n) if n.is_multiple_of(1 << 20) => Some(format!("{} MiB", n >> 20)),
            Default::Bytes(n) => Some(format!("{n} bytes")),
        }
    }
}

/// The variables the binary reads, as `--help` shows them after the commands.
pub fn help() -> String {
    let mut out = String::from("Proxy configuration, all through the environment:\n");
    for var in ALL.iter().filter(|var| var.listed()) {
        let label = format!("{}{}", var.name, var.shown);
        let last = var.help.len() - 1;
        for (i, line) in var.help.iter().enumerate() {
            let default = match (i == last, var.default_shown()) {
                (true, Some(shown)) => format!(" (default {shown})"),
                _ => String::new(),
            };
            let label = if i == 0 { label.as_str() } else { "" };
            out.push_str(&format!("\n  {label:<34}{line}{default}"));
        }
    }
    out
}

/// A variable whose value could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError {
    /// The variable's name. The name rather than the [`Var`], which would make every
    /// `Result` here several times larger.
    pub var: &'static str,
    pub value: String,
    pub reason: String,
}

impl EnvError {
    fn new(var: Var, value: String, reason: impl ToString) -> Self {
        Self {
            var: var.name,
            value,
            reason: reason.to_string(),
        }
    }
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: `{}` {}", self.var, self.value, self.reason)
    }
}

impl std::error::Error for EnvError {}

/// The environment, read through a lookup so tests can supply their own.
pub struct Env<L> {
    lookup: L,
}

/// The process environment.
pub fn process() -> Env<fn(&str) -> Option<OsString>> {
    Env {
        lookup: |name: &str| std::env::var_os(name),
    }
}

impl<L: Fn(&str) -> Option<OsString>> Env<L> {
    pub fn from_lookup(lookup: L) -> Self {
        Self { lookup }
    }

    /// The value, with empty treated as unset.
    fn text(&self, var: Var) -> Result<Option<String>, EnvError> {
        match (self.lookup)(var.name) {
            None => Ok(None),
            Some(raw) => match raw.into_string() {
                Ok(value) if value.is_empty() => Ok(None),
                Ok(value) => Ok(Some(value)),
                Err(raw) => Err(EnvError::new(
                    var,
                    raw.to_string_lossy().into_owned(),
                    "is not UTF-8",
                )),
            },
        }
    }

    fn text_or(&self, var: Var, default: &str) -> Result<String, EnvError> {
        Ok(self.text(var)?.unwrap_or_else(|| default.to_owned()))
    }

    fn path(&self, var: Var) -> Result<Option<PathBuf>, EnvError> {
        Ok(self.text(var)?.map(PathBuf::from))
    }

    fn parsed<T>(
        &self,
        var: Var,
        default: T,
        parse: impl Fn(&str) -> Option<T>,
        expected: &str,
    ) -> Result<T, EnvError> {
        match self.text(var)? {
            None => Ok(default),
            Some(value) => parse(&value).ok_or_else(|| EnvError::new(var, value, expected)),
        }
    }

    fn count(&self, var: Var, default: usize) -> Result<usize, EnvError> {
        self.parsed(var, default, |v| v.parse().ok(), "is not a whole number")
    }

    fn flag(&self, var: Var, default: bool) -> Result<bool, EnvError> {
        let parse = |v: &str| match v {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        };
        self.parsed(var, default, parse, "is not 0 or 1")
    }

    fn list(&self, var: Var) -> Result<Vec<String>, EnvError> {
        Ok(self
            .text(var)?
            .unwrap_or_default()
            .split(',')
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect())
    }

    pub fn listen(&self) -> Result<String, EnvError> {
        self.text_or(LISTEN, DEFAULT_LISTEN)
    }

    pub fn upstream(&self) -> Result<String, EnvError> {
        self.text_or(UPSTREAM, DEFAULT_UPSTREAM)
    }

    pub fn public_url(&self) -> Result<Option<String>, EnvError> {
        self.text(PUBLIC_URL)
    }

    pub fn artifact_origins(&self) -> Result<Vec<String>, EnvError> {
        self.list(ARTIFACT_ORIGINS)
    }

    pub fn allow_direct_origins(&self) -> Result<Vec<String>, EnvError> {
        self.list(ALLOW_DIRECT_ORIGINS)
    }

    pub fn rewrite_artifacts(&self) -> Result<bool, EnvError> {
        self.flag(REWRITE_ARTIFACTS, true)
    }

    pub fn ca_bundle(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(CA_BUNDLE)
    }

    pub fn ca_bundle_exclusive(&self) -> Result<bool, EnvError> {
        self.flag(CA_BUNDLE_EXCLUSIVE, false)
    }

    pub fn max_packument_bytes(&self) -> Result<usize, EnvError> {
        self.count(MAX_PACKUMENT_BYTES, DEFAULT_MAX_PACKUMENT_BYTES)
    }

    pub fn max_records(&self) -> Result<usize, EnvError> {
        self.count(MAX_RECORDS, DEFAULT_MAX_RECORDS)
    }

    pub fn max_verified(&self) -> Result<usize, EnvError> {
        self.count(MAX_VERIFIED, DEFAULT_MAX_VERIFIED)
    }

    pub fn max_concurrent_packuments(&self) -> Result<usize, EnvError> {
        self.count(MAX_CONCURRENT_PACKUMENTS, DEFAULT_MAX_CONCURRENT_PACKUMENTS)
    }

    pub fn database_url(&self) -> Result<Option<String>, EnvError> {
        self.text(DATABASE_URL)
    }

    pub fn snapshot_dir(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(SNAPSHOT_DIR)
    }

    /// At least one: keeping none would remove the snapshot the refresh just wrote.
    pub fn snapshot_limit(&self) -> Result<usize, EnvError> {
        self.parsed(
            SNAPSHOT_LIMIT,
            DEFAULT_SNAPSHOT_LIMIT,
            |v| v.parse().ok().filter(|limit| *limit > 0),
            "is not a whole number above 0",
        )
    }

    pub fn policy(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(POLICY)
    }

    pub fn audit_log(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(AUDIT_LOG)
    }

    pub fn expiry_ceiling_days(&self) -> Result<i64, EnvError> {
        self.parsed(
            EXPIRY_CEILING_DAYS,
            DEFAULT_EXPIRY_CEILING_DAYS,
            |v| v.parse::<u32>().ok().map(i64::from),
            "is not a whole number of days",
        )
    }

    pub fn refusal_status(&self) -> Result<RefusalStatus, EnvError> {
        let value = self.text(REFUSAL_STATUS)?.unwrap_or_default();
        RefusalStatus::parse(&value).map_err(|e| EnvError::new(REFUSAL_STATUS, value, e))
    }

    pub fn refuse_unservable(&self) -> Result<bool, EnvError> {
        self.flag(REFUSE_UNSERVABLE, true)
    }

    pub fn log_filter(&self) -> Result<String, EnvError> {
        self.text_or(LOG_FILTER, DEFAULT_LOG_FILTER)
    }

    #[cfg(debug_assertions)]
    pub fn defer_test(&self) -> Result<Option<DeferTest>, EnvError> {
        match self.text(DEFER_TEST)? {
            None => Ok(None),
            Some(value) => DeferTest::parse(&value)
                .map(Some)
                .map_err(|e| EnvError::new(DEFER_TEST, value, e)),
        }
    }

    pub fn bless(&self) -> bool {
        matches!(self.text(BLESS), Ok(Some(_)))
    }

    pub fn npm_corpus(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(NPM_CORPUS)
    }

    pub fn npm_corpus_full(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(NPM_CORPUS_FULL)
    }

    pub fn test_database_url(&self) -> Result<Option<String>, EnvError> {
        self.text(TEST_DATABASE_URL)
    }

    pub fn home(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(HOME)
    }

    pub fn bun_install_cache_dir(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(BUN_INSTALL_CACHE_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with(pairs: &[(Var, &str)]) -> Env<impl Fn(&str) -> Option<OsString>> {
        let map: HashMap<&'static str, OsString> = pairs
            .iter()
            .map(|(var, value)| (var.name, OsString::from(value)))
            .collect();
        Env::from_lookup(move |name: &str| map.get(name).cloned())
    }

    #[test]
    fn unset_is_the_default() {
        let env = with(&[]);
        assert_eq!(env.listen().unwrap(), DEFAULT_LISTEN);
        assert_eq!(env.upstream().unwrap(), DEFAULT_UPSTREAM);
        assert_eq!(env.public_url().unwrap(), None);
        assert!(env.artifact_origins().unwrap().is_empty());
        assert!(env.allow_direct_origins().unwrap().is_empty());
        assert!(env.rewrite_artifacts().unwrap());
        assert_eq!(env.ca_bundle().unwrap(), None);
        assert!(!env.ca_bundle_exclusive().unwrap());
        assert_eq!(
            env.max_packument_bytes().unwrap(),
            DEFAULT_MAX_PACKUMENT_BYTES
        );
        assert_eq!(env.max_records().unwrap(), DEFAULT_MAX_RECORDS);
        assert_eq!(env.max_verified().unwrap(), DEFAULT_MAX_VERIFIED);
        assert_eq!(
            env.max_concurrent_packuments().unwrap(),
            DEFAULT_MAX_CONCURRENT_PACKUMENTS
        );
        assert_eq!(env.database_url().unwrap(), None);
        assert_eq!(env.snapshot_dir().unwrap(), None);
        assert_eq!(env.snapshot_limit().unwrap(), DEFAULT_SNAPSHOT_LIMIT);
        assert_eq!(env.policy().unwrap(), None);
        assert_eq!(env.audit_log().unwrap(), None);
        assert_eq!(
            env.expiry_ceiling_days().unwrap(),
            DEFAULT_EXPIRY_CEILING_DAYS
        );
        assert_eq!(
            env.refusal_status().unwrap().default_status(),
            DEFAULT_REFUSAL_STATUS
        );
        assert!(env.refuse_unservable().unwrap());
        assert_eq!(env.log_filter().unwrap(), DEFAULT_LOG_FILTER);
        #[cfg(debug_assertions)]
        assert_eq!(env.defer_test().unwrap(), None);
        assert!(!env.bless());
        assert_eq!(env.npm_corpus().unwrap(), None);
        assert_eq!(env.npm_corpus_full().unwrap(), None);
        assert_eq!(env.test_database_url().unwrap(), None);
        assert_eq!(env.home().unwrap(), None);
        assert_eq!(env.bun_install_cache_dir().unwrap(), None);
    }

    /// `WAHAROA_LISTEN=` used to be bound as the empty address, and failed there.
    #[test]
    fn empty_is_unset() {
        let env = with(&[(LISTEN, ""), (MAX_RECORDS, ""), (POLICY, ""), (BLESS, "")]);
        assert_eq!(env.listen().unwrap(), DEFAULT_LISTEN);
        assert_eq!(env.max_records().unwrap(), DEFAULT_MAX_RECORDS);
        assert_eq!(env.policy().unwrap(), None);
        assert!(!env.bless());
    }

    #[test]
    fn a_set_value_is_parsed_to_its_type() {
        let env = with(&[
            (LISTEN, "0.0.0.0:9000"),
            (UPSTREAM, "https://registry.example"),
            (PUBLIC_URL, "https://proxy.example"),
            (ARTIFACT_ORIGINS, " https://a.example, ,https://b.example "),
            (ALLOW_DIRECT_ORIGINS, "https://c.example"),
            (REWRITE_ARTIFACTS, "0"),
            (CA_BUNDLE, "/etc/ca.pem"),
            (CA_BUNDLE_EXCLUSIVE, "1"),
            (MAX_PACKUMENT_BYTES, "1024"),
            (MAX_RECORDS, "10"),
            (MAX_VERIFIED, "20"),
            (MAX_CONCURRENT_PACKUMENTS, "2"),
            (DATABASE_URL, "postgres://db"),
            (SNAPSHOT_DIR, "/var/lib/waharoa"),
            (SNAPSHOT_LIMIT, "7"),
            (POLICY, "policy.yaml"),
            (AUDIT_LOG, "audit.jsonl"),
            (EXPIRY_CEILING_DAYS, "30"),
            (REFUSAL_STATUS, "default=451"),
            (REFUSE_UNSERVABLE, "0"),
            (LOG_FILTER, "debug"),
            (BLESS, "1"),
            (NPM_CORPUS, "abbrev"),
            (NPM_CORPUS_FULL, "full"),
            (TEST_DATABASE_URL, "postgres://test"),
            (HOME, "/home/u"),
            (BUN_INSTALL_CACHE_DIR, "/cache"),
        ]);
        assert_eq!(env.listen().unwrap(), "0.0.0.0:9000");
        assert_eq!(env.upstream().unwrap(), "https://registry.example");
        assert_eq!(
            env.public_url().unwrap().as_deref(),
            Some("https://proxy.example")
        );
        assert_eq!(
            env.artifact_origins().unwrap(),
            ["https://a.example", "https://b.example"]
        );
        assert_eq!(env.allow_direct_origins().unwrap(), ["https://c.example"]);
        assert!(!env.rewrite_artifacts().unwrap());
        assert_eq!(env.ca_bundle().unwrap(), Some(PathBuf::from("/etc/ca.pem")));
        assert!(env.ca_bundle_exclusive().unwrap());
        assert_eq!(env.max_packument_bytes().unwrap(), 1024);
        assert_eq!(env.max_records().unwrap(), 10);
        assert_eq!(env.max_verified().unwrap(), 20);
        assert_eq!(env.max_concurrent_packuments().unwrap(), 2);
        assert_eq!(
            env.database_url().unwrap().as_deref(),
            Some("postgres://db")
        );
        assert_eq!(
            env.snapshot_dir().unwrap(),
            Some(PathBuf::from("/var/lib/waharoa"))
        );
        assert_eq!(env.snapshot_limit().unwrap(), 7);
        assert_eq!(env.policy().unwrap(), Some(PathBuf::from("policy.yaml")));
        assert_eq!(env.audit_log().unwrap(), Some(PathBuf::from("audit.jsonl")));
        assert_eq!(env.expiry_ceiling_days().unwrap(), 30);
        assert_eq!(env.refusal_status().unwrap().default_status(), 451);
        assert!(!env.refuse_unservable().unwrap());
        assert_eq!(env.log_filter().unwrap(), "debug");
        assert!(env.bless());
        assert_eq!(env.npm_corpus().unwrap(), Some(PathBuf::from("abbrev")));
        assert_eq!(env.npm_corpus_full().unwrap(), Some(PathBuf::from("full")));
        assert_eq!(
            env.test_database_url().unwrap().as_deref(),
            Some("postgres://test")
        );
        assert_eq!(env.home().unwrap(), Some(PathBuf::from("/home/u")));
        assert_eq!(
            env.bun_install_cache_dir().unwrap(),
            Some(PathBuf::from("/cache"))
        );
    }

    /// Each of these fell back to its default without a word before this module.
    #[test]
    fn a_value_that_does_not_parse_is_an_error_naming_the_variable_and_the_value() {
        let env = with(&[
            (MAX_RECORDS, "5O000"),
            (MAX_PACKUMENT_BYTES, "-1"),
            (MAX_VERIFIED, "1e6"),
            (MAX_CONCURRENT_PACKUMENTS, "eight"),
            (EXPIRY_CEILING_DAYS, "-5"),
            (CA_BUNDLE_EXCLUSIVE, "yes"),
            (REWRITE_ARTIFACTS, "false"),
            (REFUSE_UNSERVABLE, "no"),
            (SNAPSHOT_LIMIT, "0"),
        ]);
        let cases: [(Result<(), EnvError>, &str); 9] = [
            (
                env.max_records().map(drop),
                "WAHAROA_MAX_RECORDS: `5O000` is not a whole number",
            ),
            (
                env.max_packument_bytes().map(drop),
                "WAHAROA_MAX_PACKUMENT_BYTES: `-1` is not a whole number",
            ),
            (
                env.max_verified().map(drop),
                "WAHAROA_MAX_VERIFIED: `1e6` is not a whole number",
            ),
            (
                env.max_concurrent_packuments().map(drop),
                "WAHAROA_MAX_CONCURRENT_PACKUMENTS: `eight` is not a whole number",
            ),
            (
                env.expiry_ceiling_days().map(drop),
                "WAHAROA_EXPIRY_CEILING_DAYS: `-5` is not a whole number of days",
            ),
            (
                env.ca_bundle_exclusive().map(drop),
                "WAHAROA_CA_BUNDLE_EXCLUSIVE: `yes` is not 0 or 1",
            ),
            (
                env.rewrite_artifacts().map(drop),
                "WAHAROA_REWRITE_ARTIFACTS: `false` is not 0 or 1",
            ),
            (
                env.refuse_unservable().map(drop),
                "WAHAROA_REFUSE_UNSERVABLE: `no` is not 0 or 1",
            ),
            (
                env.snapshot_limit().map(drop),
                "WAHAROA_SNAPSHOT_LIMIT: `0` is not a whole number above 0",
            ),
        ];
        for (result, expected) in cases {
            assert_eq!(result.expect_err(expected).to_string(), expected);
        }
    }

    #[test]
    fn a_parser_of_its_own_reports_its_reason_under_the_variable() {
        let env = with(&[(REFUSAL_STATUS, "npm=403"), (DEFER_TEST, "nope")]);
        let refusal = env.refusal_status().expect_err("malformed");
        assert_eq!(refusal.var, REFUSAL_STATUS.name);
        assert!(
            refusal
                .to_string()
                .starts_with("WAHAROA_REFUSAL_STATUS: `npm=403` "),
            "{refusal}"
        );
        #[cfg(debug_assertions)]
        {
            let defer = env.defer_test().expect_err("malformed");
            assert!(
                defer.to_string().starts_with("WAHAROA_DEFER_TEST: `nope` "),
                "{defer}"
            );
        }
    }

    #[test]
    fn a_debug_build_reads_a_well_formed_deferral() {
        #[cfg(debug_assertions)]
        assert!(
            with(&[(DEFER_TEST, "429:1:tarball")])
                .defer_test()
                .unwrap()
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_value_that_is_not_utf8_is_an_error() {
        use std::os::unix::ffi::OsStringExt;
        let env = Env::from_lookup(|_: &str| Some(OsString::from_vec(vec![0x66, 0xff])));
        assert_eq!(
            env.policy().expect_err("not UTF-8").to_string(),
            "WAHAROA_POLICY: `f\u{fffd}` is not UTF-8"
        );
        assert!(!env.bless());
    }

    #[test]
    fn process_reads_the_real_environment() {
        // PATH is set wherever tests run, and no variable here is named PATH, so this checks
        // only that `process` answers without panicking.
        assert!(process().listen().is_ok());
    }

    #[test]
    fn a_default_is_shown_in_the_unit_it_is_read_in() {
        assert_eq!(
            MAX_PACKUMENT_BYTES.default_shown().as_deref(),
            Some("32 MiB")
        );
        assert_eq!(
            MAX_PACKUMENT_BYTES
                .with_default(Default::Bytes(1000))
                .default_shown()
                .as_deref(),
            Some("1000 bytes")
        );
        assert_eq!(MAX_RECORDS.default_shown().as_deref(), Some("50000"));
        assert_eq!(REFUSAL_STATUS.default_shown().as_deref(), Some("403"));
        assert_eq!(PUBLIC_URL.default_shown(), None);
    }

    #[test]
    fn help_lists_what_the_binary_reads_and_nothing_else() {
        let help = help();
        for var in ALL {
            let listed = help.contains(&format!("  {}", var.name));
            assert_eq!(listed, var.listed(), "{var}");
        }
        assert!(LISTEN.listed() && LOG_FILTER.listed());
        assert_eq!(DEFER_TEST.listed(), cfg!(debug_assertions));
        assert!(!BLESS.listed() && !TEST_DATABASE_URL.listed() && !HOME.listed());
    }

    /// The rule item 16 set: a name written anywhere but here is a second place to change.
    #[test]
    fn a_variable_name_appears_only_in_this_module() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "tests", "examples"] {
            rust_files(&root.join(dir), &mut files);
        }
        let this = root.join("src/env.rs");
        let mut found = Vec::new();
        for file in files.iter().filter(|f| **f != this) {
            let text = std::fs::read_to_string(file).expect("readable");
            for (number, line) in text.lines().enumerate() {
                let named = ALL
                    .iter()
                    .map(|var| var.name)
                    .chain(["WAHAROA_"])
                    .filter(|name| contains_name(line, name));
                for name in named {
                    let path = file.strip_prefix(root).unwrap_or(file);
                    found.push(format!("{}:{}: {name}", path.display(), number + 1));
                }
            }
        }
        assert!(found.is_empty(), "{found:#?}");

        // And every WAHAROA_ name written here is one of `ALL`.
        let text = std::fs::read_to_string(&this).expect("readable");
        for (i, _) in text.match_indices("WAHAROA_") {
            let name: String = text[i..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            assert!(
                name == "WAHAROA_" || ALL.iter().any(|var| var.name == name),
                "{name} is written in env.rs but is not in ALL"
            );
        }
    }

    /// `name` in `line` with no identifier character on either side. `WAHAROA_` matches as a
    /// prefix, so a name missing from `ALL` is found too.
    fn contains_name(line: &str, name: &str) -> bool {
        let identifier = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_';
        line.match_indices(name).any(|(i, _)| {
            let before = line[..i].chars().next_back();
            let after = line[i + name.len()..].chars().next();
            !before.is_some_and(identifier)
                && (name.ends_with('_') || !after.is_some_and(identifier))
        })
    }

    fn rust_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
}
