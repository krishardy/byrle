//! Every environment variable byrle reads: its name, default, help text and parsing.
//!
//! No variable name appears anywhere else in the Rust code. An empty value is unset.
//! See environment-variables.md and default-ceilings.md in docs/engineering_decisions.

#[cfg(debug_assertions)]
use crate::defer::DeferTest;
use crate::mount::Mount;
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

/// Default ceiling on a metadata document, buffered and decompressed.
pub const DEFAULT_MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;

/// Default record store budget, in records rather than bytes.
pub const DEFAULT_MAX_RECORDS: usize = 50_000;

/// Default verified-artifact budget, in artifacts.
pub const DEFAULT_MAX_VERIFIED: usize = 50_000;

/// Default ceiling on how many metadata documents are decoded and rewritten at once.
pub const DEFAULT_MAX_CONCURRENT_METADATA: usize = 8;

/// Default ceiling on how many artifacts are analysed, and spool files exist, at once.
pub const DEFAULT_MAX_CONCURRENT_ANALYSES: usize = 8;

/// Default ceiling on how many client names a traffic window counts before `other`.
pub const DEFAULT_MAX_TRAFFIC_CLIENTS: usize = 256;

/// Default seconds between the watcher's passes over the packages the proxy has served.
pub const DEFAULT_WATCH_INTERVAL_SECONDS: u64 = 900;

/// Default ceiling on one artifact written to the spool.
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 1 << 30;

/// §5.5's ceiling on how far ahead a package entry may be dated.
pub const DEFAULT_EXPIRY_CEILING_DAYS: i64 = 90;

/// The default number of snapshot manifests kept: a month of daily refreshes.
pub const DEFAULT_SNAPSHOT_LIMIT: usize = 30;

/// What §5 says a policy denial is: 403 means policy denied you.
pub const DEFAULT_REFUSAL_STATUS: u16 = 403;

pub const DEFAULT_LOG_FILTER: &str = "byrle=info";

pub const LISTEN: Var = runtime("BYRLE_LISTEN", "", &["address to listen on"])
    .with_default(Default::Text(DEFAULT_LISTEN));
/// Defaults to npm's public registry.
pub const UPSTREAM_NPM: Var = runtime("BYRLE_UPSTREAM_NPM", "", &["npm registry to forward to"])
    .with_default(Default::Text(crate::ecosystem::npm::DEFAULT_REGISTRY));
pub const UPSTREAM_PYPI: Var = runtime(
    "BYRLE_UPSTREAM_PYPI",
    "",
    &["PyPI simple index to forward to"],
)
.with_default(Default::Text(crate::ecosystem::pypi::INDEX));
pub const PROXY_URL: Var = runtime(
    "BYRLE_PROXY_URL",
    "",
    &[
        "URL package managers use for the proxy. Its path is",
        "where the proxy answers, and it is written into artifact",
        "URLs, and therefore into lockfiles. Defaults to each",
        "request's own Host at /, which is rarely what you want.",
    ],
);
pub const CONSOLE_URL: Var = runtime(
    "BYRLE_CONSOLE_URL",
    "",
    &[
        "URL of the admin console. Its path is where the console",
        "answers, and is never the proxy's. Unset, there is no console",
    ],
);
pub const CONSOLE_LISTEN: Var = runtime(
    "BYRLE_CONSOLE_LISTEN",
    "",
    &[
        "address the console listens on. Unset, it shares",
        "BYRLE_LISTEN, and neither path may contain the other",
    ],
);
pub const REQUIRE_TOKEN: Var = runtime(
    "BYRLE_REQUIRE_TOKEN",
    "=0",
    &[
        "answer requests that carry no proxy token. Unset, each",
        "request needs one, and BYRLE_DATABASE_URL is required,",
        "since accounts and tokens are kept there",
    ],
);
pub const TOKEN: Var = runtime(
    "BYRLE_TOKEN",
    "",
    &["proxy token `byrle warm` sends, from `byrle token create`"],
);
pub const ARTIFACT_ORIGINS: Var = runtime(
    "BYRLE_ARTIFACT_ORIGINS",
    "",
    &["comma-separated origins this proxy also serves"],
);
pub const ALLOW_DIRECT_ORIGINS: Var = runtime(
    "BYRLE_ALLOW_DIRECT_ORIGINS",
    "",
    &[
        "comma-separated origins the proxy does not serve and",
        "permits anyway, fetched directly and unexamined",
    ],
);
pub const REWRITE_ARTIFACTS: Var = runtime(
    "BYRLE_REWRITE_ARTIFACTS",
    "=0",
    &[
        "do not point artifact URLs at the proxy. pnpm and",
        "yarn then fetch artifacts without the proxy seeing",
        "them.",
    ],
);
pub const CA_BUNDLE: Var = runtime(
    "BYRLE_CA_BUNDLE",
    "",
    &["PEM bundle for the upstream connection"],
);
pub const CA_BUNDLE_EXCLUSIVE: Var = runtime(
    "BYRLE_CA_BUNDLE_EXCLUSIVE",
    "=1",
    &["trust only that bundle, not the public roots"],
);
pub const MAX_METADATA_BYTES: Var = runtime(
    "BYRLE_MAX_METADATA_BYTES",
    "",
    &["ceiling on a metadata document"],
)
.with_default(Default::Bytes(DEFAULT_MAX_METADATA_BYTES));
pub const MAX_RECORDS: Var = runtime("BYRLE_MAX_RECORDS", "", &["package records held in memory"])
    .with_default(Default::Number(DEFAULT_MAX_RECORDS as u64));
pub const MAX_VERIFIED: Var = runtime(
    "BYRLE_MAX_VERIFIED",
    "",
    &["verified artifact digests remembered"],
)
.with_default(Default::Number(DEFAULT_MAX_VERIFIED as u64));
pub const DATABASE_URL: Var = runtime(
    "BYRLE_DATABASE_URL",
    "",
    &[
        "Postgres holding intel from `byrle refresh`. With a",
        "policy, known_malware is enforced from it, and a",
        "store that cannot answer is a 503",
    ],
);
pub const GITHUB_TOKEN: Var = runtime(
    "BYRLE_GITHUB_TOKEN",
    "",
    &[
        "token `byrle refresh` reads GitHub's Advisory",
        "Database with. Unset, that one stream does not load",
        "and the others still do",
    ],
);
pub const SNAPSHOT_DIR: Var = runtime(
    "BYRLE_SNAPSHOT_DIR",
    "",
    &[
        "directory `byrle refresh` keeps each snapshot in,",
        "for `policy diff --snapshot`. Unset, none is kept",
    ],
);
pub const SNAPSHOT_LIMIT: Var = runtime(
    "BYRLE_SNAPSHOT_LIMIT",
    "",
    &["most snapshots kept there; a refresh removes older ones"],
)
.with_default(Default::Number(DEFAULT_SNAPSHOT_LIMIT as u64));
pub const POLICY: Var = runtime(
    "BYRLE_POLICY",
    "",
    &[
        "path to a policy file. Loaded, validated and",
        "enforced. Startup reports which checks can fire",
    ],
);
pub const AUDIT_LOG: Var = runtime(
    "BYRLE_AUDIT_LOG",
    "",
    &[
        "path for one JSON line per policy decision,",
        "appended. Refuses to start if it cannot be opened",
    ],
);
pub const EXPIRY_CEILING_DAYS: Var = runtime(
    "BYRLE_EXPIRY_CEILING_DAYS",
    "",
    &["how many days ahead a `packages` entry may be dated"],
)
.with_default(Default::Number(DEFAULT_EXPIRY_CEILING_DAYS as u64));
pub const MAX_CONCURRENT_METADATA: Var = runtime(
    "BYRLE_MAX_CONCURRENT_METADATA",
    "",
    &["metadata documents decoded at once"],
)
.with_default(Default::Number(DEFAULT_MAX_CONCURRENT_METADATA as u64));
pub const SPOOL_DIR: Var = runtime(
    "BYRLE_SPOOL_DIR",
    "",
    &[
        "directory an artifact is written to while it is",
        "analysed. Locked; spool files left in it are removed",
        "at startup (default byrle-spool in the OS temp dir)",
    ],
);
pub const MAX_ARTIFACT_BYTES: Var = runtime(
    "BYRLE_MAX_ARTIFACT_BYTES",
    "",
    &["ceiling on an artifact written to the spool"],
)
.with_default(Default::Bytes(DEFAULT_MAX_ARTIFACT_BYTES as usize));
pub const MAX_CONCURRENT_ANALYSES: Var = runtime(
    "BYRLE_MAX_CONCURRENT_ANALYSES",
    "",
    &["artifacts analysed at once"],
)
.with_default(Default::Number(DEFAULT_MAX_CONCURRENT_ANALYSES as u64));
pub const MAX_TRAFFIC_CLIENTS: Var = runtime(
    "BYRLE_MAX_TRAFFIC_CLIENTS",
    "",
    &["client names counted apart in a traffic window"],
)
.with_default(Default::Number(DEFAULT_MAX_TRAFFIC_CLIENTS as u64));
pub const WATCH_INTERVAL: Var = runtime(
    "BYRLE_WATCH_INTERVAL",
    "",
    &[
        "seconds between checks of served packages for new versions to analyse",
        "before a client asks for them; 0 turns it off",
    ],
)
.with_default(Default::Number(DEFAULT_WATCH_INTERVAL_SECONDS));
pub const SOURCE_ARCHIVES: Var = runtime(
    "BYRLE_SOURCE_ARCHIVES",
    "",
    &[
        "host of the GitHub archives each artifact is compared with, the source",
        "its metadata names; off turns the comparison off",
    ],
)
.with_default(Default::Text(crate::analysis::source::ARCHIVES));
pub const REFUSAL_STATUS: Var = runtime(
    "BYRLE_REFUSAL_STATUS",
    "",
    &[
        "status a refusal answers with, per client, e.g.",
        "\"default=403,npm/pnpm=451\"",
    ],
)
.with_default(Default::Number(DEFAULT_REFUSAL_STATUS as u64));
pub const REFUSE_UNSERVABLE: Var = runtime(
    "BYRLE_REFUSE_UNSERVABLE",
    "=0",
    &[
        "forward versions whose artifacts this proxy cannot",
        "see, instead of removing them from the metadata",
    ],
);
pub const MODE: Var = runtime(
    "BYRLE_MODE",
    "",
    &["\"observe\" serves what the policy refuses and logs it"],
)
.with_default(Default::Text("enforce"));
pub const FORWARD_HTTPS: Var = runtime(
    "HTTPS_PROXY",
    "",
    &[
        "forward proxy for upstream https; the lowercase name",
        "is read too",
    ],
);
pub const FORWARD_HTTP: Var = runtime(
    "HTTP_PROXY",
    "",
    &[
        "forward proxy for upstream http; the lowercase name",
        "is read too",
    ],
);
pub const FORWARD_EXCEPT: Var = runtime(
    "NO_PROXY",
    "",
    &[
        "hosts fetched without the forward proxy, comma-separated;",
        "the lowercase name is read too",
    ],
);
pub const FORWARD_HTTPS_LOWER: Var = other(Kind::External, "https_proxy", &["as HTTPS_PROXY"]);
pub const FORWARD_HTTP_LOWER: Var = other(Kind::External, "http_proxy", &["as HTTP_PROXY"]);
pub const FORWARD_EXCEPT_LOWER: Var = other(Kind::External, "no_proxy", &["as NO_PROXY"]);
pub const DETECTORS: Var = runtime(
    "BYRLE_DETECTORS",
    "",
    &[
        "detectors run on each version served, `name=command argument...`, separated by `;`;",
        "{ecosystem}, {name} and {version} in the arguments are replaced. A detector is given",
        "PATH, HOME, SOCKS and the forward proxies, and nothing else",
    ],
);
pub const DETECTOR_SOCKS: Var = other(
    Kind::External,
    "SOCKS",
    &["a SOCKS5 proxy, host:port, passed to detectors"],
);
pub const VIRUSTOTAL_API_KEY: Var = runtime(
    "BYRLE_VIRUSTOTAL_API_KEY",
    "",
    &[
        "key each artifact's SHA-256 is looked up on VirusTotal with, a report-only",
        "signal. Unset, VirusTotal is not asked",
    ],
);
pub const VIRUSTOTAL_MODE: Var = runtime(
    "BYRLE_VIRUSTOTAL_MODE",
    "",
    &[
        "\"upload\" also sends VirusTotal an artifact it does not know, when it came from",
        "a public registry",
    ],
)
.with_default(Default::Text("hash"));
pub const VIRUSTOTAL_URL: Var = runtime("BYRLE_VIRUSTOTAL_URL", "", &["VirusTotal's API"])
    .with_default(Default::Text(crate::analysis::virustotal::API));
pub const VIRUSTOTAL_PER_MINUTE: Var = runtime(
    "BYRLE_VIRUSTOTAL_PER_MINUTE",
    "",
    &["requests to VirusTotal a minute; the public API allows 4"],
)
.with_default(Default::Number(
    crate::analysis::virustotal::PUBLIC_PER_MINUTE as u64,
));
pub const VIRUSTOTAL_PER_DAY: Var = runtime(
    "BYRLE_VIRUSTOTAL_PER_DAY",
    "",
    &["requests to VirusTotal a day; the public API allows 500"],
)
.with_default(Default::Number(
    crate::analysis::virustotal::PUBLIC_PER_DAY as u64,
));
pub const LOG_FORMAT: Var = runtime(
    "BYRLE_LOG_FORMAT",
    "",
    &["\"json\" writes one OpenTelemetry log record per line"],
)
.with_default(Default::Text("text"));
pub const LOG_FILTER: Var = runtime("RUST_LOG", "", &["log filter, in tracing's syntax"])
    .with_default(Default::Text(DEFAULT_LOG_FILTER));
pub const DEFER_TEST: Var = Var {
    kind: Kind::Debug,
    ..runtime(
        "BYRLE_DEFER_TEST",
        "",
        &[
            "DEBUG BUILDS ONLY: answer every matching request with",
            "a deferral instead of fetching, so client retry",
            "behaviour can be measured. `<status>:<seconds|none>:",
            "<metadata|artifact|all>[:<seconds>]`, e.g.",
            "\"429:1:artifact\" or \"503:1:all:8\"",
        ],
    )
};

pub const BLESS: Var = other(
    Kind::Test,
    "BYRLE_BLESS",
    &["rewrite golden files instead of comparing against them"],
);
pub const NPM_CORPUS: Var = other(
    Kind::Test,
    "BYRLE_NPM_CORPUS",
    &["directory of abbreviated packuments for the ignored corpus test"],
);
pub const NPM_CORPUS_FULL: Var = other(
    Kind::Test,
    "BYRLE_NPM_CORPUS_FULL",
    &["directory of full packuments for the ignored corpus test"],
);
pub const TEST_DATABASE_URL: Var = other(
    Kind::Test,
    "BYRLE_TEST_DATABASE_URL",
    &["Postgres the integration tests run against, set by `make test-integration`"],
);
pub const HOME_DIR: Var = other(
    Kind::External,
    "HOME",
    &["the user's home directory, under which bun keeps its default cache"],
);
pub const BUN_CACHE: Var = other(
    Kind::External,
    "BUN_INSTALL_CACHE_DIR",
    &["where bun keeps its cache, when set"],
);
pub const CONFIG_HOME: Var = other(
    Kind::External,
    "XDG_CONFIG_HOME",
    &["the user's configuration directory, where uv looks for `uv/uv.toml`"],
);
pub const UV_DEFAULT: Var = other(
    Kind::External,
    "UV_DEFAULT_INDEX",
    &["the index uv installs from"],
);
pub const UV_OLDER_INDEX: Var = other(
    Kind::External,
    "UV_INDEX_URL",
    &["the index uv installs from, under its older name"],
);
pub const UV_EXTRAS: Var = other(
    Kind::External,
    "UV_EXTRA_INDEX_URL",
    &["indexes uv also asks, separated by spaces"],
);
pub const UV_NAMED: Var = other(
    Kind::External,
    "UV_INDEX",
    &["named indexes uv also asks, separated by spaces"],
);
pub const UV_NO_FILES: Var = other(
    Kind::External,
    "UV_NO_CONFIG",
    &["set, uv reads no configuration file"],
);
pub const UV_FILE: Var = other(
    Kind::External,
    "UV_CONFIG_FILE",
    &["the one configuration file uv reads, when set"],
);

/// Every variable, in the order `--help` lists them.
pub const ALL: [Var; 62] = [
    LISTEN,
    UPSTREAM_NPM,
    UPSTREAM_PYPI,
    PROXY_URL,
    CONSOLE_URL,
    CONSOLE_LISTEN,
    REQUIRE_TOKEN,
    TOKEN,
    ARTIFACT_ORIGINS,
    ALLOW_DIRECT_ORIGINS,
    REWRITE_ARTIFACTS,
    CA_BUNDLE,
    CA_BUNDLE_EXCLUSIVE,
    MAX_METADATA_BYTES,
    MAX_RECORDS,
    MAX_VERIFIED,
    DATABASE_URL,
    GITHUB_TOKEN,
    SNAPSHOT_DIR,
    SNAPSHOT_LIMIT,
    POLICY,
    AUDIT_LOG,
    EXPIRY_CEILING_DAYS,
    MAX_CONCURRENT_METADATA,
    SPOOL_DIR,
    MAX_ARTIFACT_BYTES,
    MAX_CONCURRENT_ANALYSES,
    MAX_TRAFFIC_CLIENTS,
    WATCH_INTERVAL,
    SOURCE_ARCHIVES,
    DETECTORS,
    DETECTOR_SOCKS,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_MODE,
    VIRUSTOTAL_URL,
    VIRUSTOTAL_PER_MINUTE,
    VIRUSTOTAL_PER_DAY,
    REFUSAL_STATUS,
    REFUSE_UNSERVABLE,
    MODE,
    FORWARD_HTTPS,
    FORWARD_HTTP,
    FORWARD_EXCEPT,
    FORWARD_HTTPS_LOWER,
    FORWARD_HTTP_LOWER,
    FORWARD_EXCEPT_LOWER,
    LOG_FORMAT,
    LOG_FILTER,
    DEFER_TEST,
    BLESS,
    NPM_CORPUS,
    NPM_CORPUS_FULL,
    TEST_DATABASE_URL,
    HOME_DIR,
    BUN_CACHE,
    CONFIG_HOME,
    UV_DEFAULT,
    UV_OLDER_INDEX,
    UV_EXTRAS,
    UV_NAMED,
    UV_NO_FILES,
    UV_FILE,
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

    /// The default, when it is text.
    pub fn default_text(&self) -> Option<&'static str> {
        match self.default {
            Default::Text(text) => Some(text),
            _ => None,
        }
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
    /// The variable's name, not the [`Var`], which would make every `Result` larger.
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

/// An environment whose lookup is chosen at runtime: the process's own, or one a test holds.
pub type Process = Env<Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>>;

/// The process environment.
pub fn process() -> Process {
    Env::from_lookup(Box::new(|name: &str| std::env::var_os(name)))
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

    /// Where each ecosystem's requests are forwarded: the row's `upstream` variable, or its
    /// default. Each is an http or https URL with a host, kept with its path.
    pub fn upstreams(&self) -> Result<crate::ecosystem::Upstreams, EnvError> {
        let mut upstreams = crate::ecosystem::Upstreams::defaults();
        for registry in crate::ecosystem::TABLE {
            if let Some(value) = self.text(registry.upstream)? {
                upstreams =
                    upstreams.with(registry.ecosystem, &upstream(registry.upstream, value)?);
            }
        }
        Ok(upstreams)
    }

    /// [`PROXY_URL`], checked as [`Mount::from_url`] checks it.
    pub fn proxy_url(&self) -> Result<Option<String>, EnvError> {
        Ok(self.url_and_mount(PROXY_URL)?.map(|(url, _)| url))
    }

    /// Where a client on this machine reaches the proxy: [`PROXY_URL`] without its trailing
    /// `/`, or `http://` and [`LISTEN`].
    pub fn proxy_base(&self) -> Result<String, EnvError> {
        match self.proxy_url()? {
            Some(url) => Ok(url.trim_end_matches('/').to_owned()),
            None => Ok(format!("http://{}", self.listen()?)),
        }
    }

    /// The path the proxy answers at: [`PROXY_URL`]'s, or the root when it is unset.
    pub fn proxy_mount(&self) -> Result<Mount, EnvError> {
        Ok(self
            .url_and_mount(PROXY_URL)?
            .map_or(Mount::ROOT, |(_, mount)| mount))
    }

    /// [`CONSOLE_URL`] and its path. `None` when there is no console.
    pub fn console_url(&self) -> Result<Option<(String, Mount)>, EnvError> {
        self.url_and_mount(CONSOLE_URL)
    }

    /// [`CONSOLE_LISTEN`]. `None` when the console shares [`LISTEN`].
    pub fn console_listen(&self) -> Result<Option<String>, EnvError> {
        self.text(CONSOLE_LISTEN)
    }

    fn url_and_mount(&self, var: Var) -> Result<Option<(String, Mount)>, EnvError> {
        let Some(url) = self.text(var)? else {
            return Ok(None);
        };
        match Mount::from_url(&url) {
            Ok(mount) => Ok(Some((url, mount))),
            Err(reason) => Err(EnvError::new(var, url, reason)),
        }
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

    pub fn max_metadata_bytes(&self) -> Result<usize, EnvError> {
        self.count(MAX_METADATA_BYTES, DEFAULT_MAX_METADATA_BYTES)
    }

    pub fn max_records(&self) -> Result<usize, EnvError> {
        self.count(MAX_RECORDS, DEFAULT_MAX_RECORDS)
    }

    pub fn max_verified(&self) -> Result<usize, EnvError> {
        self.count(MAX_VERIFIED, DEFAULT_MAX_VERIFIED)
    }

    pub fn max_concurrent_metadata(&self) -> Result<usize, EnvError> {
        self.count(MAX_CONCURRENT_METADATA, DEFAULT_MAX_CONCURRENT_METADATA)
    }

    /// At least one: a window counting no name apart counts every client as `other`.
    pub fn max_traffic_clients(&self) -> Result<usize, EnvError> {
        self.parsed(
            MAX_TRAFFIC_CLIENTS,
            DEFAULT_MAX_TRAFFIC_CLIENTS,
            |v| v.parse().ok().filter(|limit| *limit > 0),
            "is not a whole number above 0",
        )
    }

    /// How long the watcher waits between passes. `None` when it is off.
    pub fn watch_interval(&self) -> Result<Option<std::time::Duration>, EnvError> {
        let seconds = self.parsed(
            WATCH_INTERVAL,
            DEFAULT_WATCH_INTERVAL_SECONDS,
            |v| v.parse().ok(),
            "is not a whole number of seconds",
        )?;
        Ok((seconds > 0).then(|| std::time::Duration::from_secs(seconds)))
    }

    /// Where source archives are fetched from, or `None` when the comparison is off.
    pub fn source_archives(&self) -> Result<Option<String>, EnvError> {
        Ok(match self.text(SOURCE_ARCHIVES)? {
            Some(off) if off == "off" => None,
            value => Some(value.unwrap_or_else(|| crate::analysis::source::ARCHIVES.to_owned())),
        })
    }

    /// Each detector's spec, `name=command argument...`. Empty when none is set.
    pub fn detectors(&self) -> Result<Vec<String>, EnvError> {
        Ok(self
            .text(DETECTORS)?
            .map(|specs| {
                specs
                    .split(';')
                    .map(str::trim)
                    .filter(|spec| !spec.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// All a detector is given of this environment: `PATH`, `HOME`, `SOCKS` and the forward
    /// proxies, those that are set. Nothing else, so no credential reaches it.
    pub fn detector_environment(&self) -> Vec<(String, OsString)> {
        let passed = [
            DETECTOR_SOCKS,
            FORWARD_HTTPS,
            FORWARD_HTTP,
            FORWARD_EXCEPT,
            FORWARD_HTTPS_LOWER,
            FORWARD_HTTP_LOWER,
            FORWARD_EXCEPT_LOWER,
        ]
        .map(|var| var.name);
        ["PATH", "HOME"]
            .into_iter()
            .chain(passed)
            .filter_map(|name| Some((name.to_owned(), (self.lookup)(name)?)))
            .collect()
    }

    pub fn max_concurrent_analyses(&self) -> Result<usize, EnvError> {
        self.count(MAX_CONCURRENT_ANALYSES, DEFAULT_MAX_CONCURRENT_ANALYSES)
    }

    /// [`crate::spool::default_dir`] when unset.
    pub fn spool_dir(&self) -> Result<PathBuf, EnvError> {
        Ok(self
            .path(SPOOL_DIR)?
            .unwrap_or_else(crate::spool::default_dir))
    }

    /// At least one byte: a ceiling of none would refuse every artifact.
    pub fn max_artifact_bytes(&self) -> Result<u64, EnvError> {
        self.parsed(
            MAX_ARTIFACT_BYTES,
            DEFAULT_MAX_ARTIFACT_BYTES,
            |v| v.parse().ok().filter(|limit| *limit > 0),
            "is not a whole number above 0",
        )
    }

    /// Whether a proxy request needs a token. On unless [`REQUIRE_TOKEN`] is `0`.
    pub fn require_token(&self) -> Result<bool, EnvError> {
        self.flag(REQUIRE_TOKEN, true)
    }

    /// The token `byrle warm` sends the proxy.
    pub fn token(&self) -> Result<Option<String>, EnvError> {
        self.text(TOKEN)
    }

    pub fn database_url(&self) -> Result<Option<String>, EnvError> {
        self.text(DATABASE_URL)
    }

    /// The GitHub Advisory stream's token. `None` leaves that stream unloaded.
    pub fn github_token(&self) -> Result<Option<String>, EnvError> {
        self.text(GITHUB_TOKEN)
    }

    /// How VirusTotal is asked. `None` when no key is set, which leaves it off.
    pub fn virustotal(&self) -> Result<Option<crate::analysis::virustotal::Settings>, EnvError> {
        use crate::analysis::virustotal::{
            API, Mode, PUBLIC_ORIGINS, PUBLIC_PER_DAY, PUBLIC_PER_MINUTE, Settings,
        };
        let Some(key) = self.text(VIRUSTOTAL_API_KEY)? else {
            return Ok(None);
        };
        let positive = |v: &str| v.parse::<u32>().ok().filter(|n| *n > 0);
        let above_0 = "is not a whole number above 0";
        Ok(Some(Settings {
            key,
            mode: self.parsed(
                VIRUSTOTAL_MODE,
                Mode::Hash,
                Mode::parse,
                "is not `hash` or `upload`",
            )?,
            base: self.text_or(VIRUSTOTAL_URL, API)?,
            per_minute: self.parsed(VIRUSTOTAL_PER_MINUTE, PUBLIC_PER_MINUTE, positive, above_0)?,
            per_day: self.parsed(VIRUSTOTAL_PER_DAY, PUBLIC_PER_DAY, positive, above_0)?,
            uploads_from: PUBLIC_ORIGINS.map(str::to_owned).to_vec(),
        }))
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

    pub fn mode(&self) -> Result<crate::refusal::Mode, EnvError> {
        self.parsed(
            MODE,
            crate::refusal::Mode::Enforce,
            crate::refusal::Mode::parse,
            "is not `enforce` or `observe`",
        )
    }

    /// The forward proxy settings reqwest reads, each name before its lowercase form.
    pub fn upstream_proxy(&self) -> Result<crate::http::UpstreamProxy, EnvError> {
        let first = |upper: Var, lower: Var| -> Result<Option<String>, EnvError> {
            Ok(self.text(upper)?.or(self.text(lower)?))
        };
        Ok(crate::http::UpstreamProxy {
            https: first(FORWARD_HTTPS, FORWARD_HTTPS_LOWER)?,
            http: first(FORWARD_HTTP, FORWARD_HTTP_LOWER)?,
            direct: first(FORWARD_EXCEPT, FORWARD_EXCEPT_LOWER)?,
        })
    }

    pub fn log_format(&self) -> Result<crate::logging::Format, EnvError> {
        self.parsed(
            LOG_FORMAT,
            crate::logging::Format::Text,
            crate::logging::Format::parse,
            "is not `text` or `json`",
        )
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
        self.path(HOME_DIR)
    }

    pub fn bun_install_cache_dir(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(BUN_CACHE)
    }

    pub fn xdg_config_home(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(CONFIG_HOME)
    }

    /// uv's index settings from the environment, which beat its configuration files.
    pub fn uv_indexes(&self) -> Result<crate::ecosystem::pypi::clients::UvVars, EnvError> {
        Ok(crate::ecosystem::pypi::clients::UvVars {
            default_index: self.text(UV_DEFAULT)?,
            index_url: self.text(UV_OLDER_INDEX)?,
            extra_index_url: self.text(UV_EXTRAS)?,
            index: self.text(UV_NAMED)?,
        })
    }

    /// Whether uv is told to read no configuration file.
    pub fn uv_no_config(&self) -> Result<bool, EnvError> {
        Ok(self.text(UV_NO_FILES)?.is_some())
    }

    pub fn uv_config_file(&self) -> Result<Option<PathBuf>, EnvError> {
        self.path(UV_FILE)
    }
}

/// `value` for `var`, refused unless it is an http or https URL with a host.
fn upstream(var: Var, value: String) -> Result<String, EnvError> {
    match crate::origin::normalise_origin(&value) {
        Ok(_) => Ok(value),
        Err(e) => Err(EnvError::new(
            var,
            value,
            format!("is not usable: {}", e.reason),
        )),
    }
}

/// Environments other modules' tests read, built here so no variable name is written there.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::ffi::OsString;

    use super::{BUN_CACHE, Env, HOME_DIR, Process, Var};

    /// An environment holding exactly `pairs`. Each variable is named by its `Var`, so no
    /// name is written outside this module.
    pub fn with(pairs: &[(Var, &str)]) -> Process {
        let map: HashMap<&'static str, OsString> = pairs
            .iter()
            .map(|(var, value)| (var.name, OsString::from(value)))
            .collect();
        Env::from_lookup(Box::new(move |name: &str| map.get(name).cloned()))
    }

    /// `pairs`, and `unreadable` set to bytes that are not UTF-8, which reading it refuses.
    pub fn with_unreadable(pairs: &[(Var, &str)], unreadable: Var) -> Process {
        use std::os::unix::ffi::OsStringExt;
        let set = with(pairs);
        Env::from_lookup(Box::new(move |name: &str| {
            if name == unreadable.name {
                Some(OsString::from_vec(vec![0x66, 0xff]))
            } else {
                (set.lookup)(name)
            }
        }))
    }

    /// bun's cache variable at `/bun`, and the home directory at `/home/u`.
    pub fn bun_cache_and_home() -> Process {
        with(&[(BUN_CACHE, "/bun"), (HOME_DIR, "/home/u")])
    }

    /// Only the home directory, at `/home/u`.
    pub fn home_only() -> Process {
        with(&[(HOME_DIR, "/home/u")])
    }

    /// Nothing set.
    pub fn empty() -> Process {
        with(&[])
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::identity::Ecosystem;

    use super::testing::with;

    /// The proxy's and the console's URLs give their paths, and one that cannot name a
    /// path is refused under its own name.
    #[test]
    fn each_url_gives_its_path_and_a_bad_one_is_refused_by_name() {
        let env = with(&[
            (PROXY_URL, "https://h/registry/"),
            (CONSOLE_URL, "https://h/admin"),
            (CONSOLE_LISTEN, "127.0.0.1:9090"),
        ]);
        assert_eq!(
            env.proxy_url().unwrap().as_deref(),
            Some("https://h/registry/")
        );
        assert_eq!(env.proxy_base().unwrap(), "https://h/registry");
        assert_eq!(env.proxy_mount().unwrap().to_string(), "/registry/");
        let (url, mount) = env.console_url().unwrap().unwrap();
        assert_eq!(
            (url.as_str(), mount.to_string().as_str()),
            ("https://h/admin", "/admin/")
        );
        assert_eq!(
            env.console_listen().unwrap().as_deref(),
            Some("127.0.0.1:9090")
        );

        let bad = with(&[(PROXY_URL, "https://user:pw@h/")]);
        for refused in [
            bad.proxy_url().unwrap_err(),
            bad.proxy_mount().unwrap_err(),
            bad.proxy_base().unwrap_err(),
        ] {
            assert_eq!(refused.var, PROXY_URL.name);
            assert_eq!(refused.reason, "carries credentials");
        }
        let unread = super::testing::with_unreadable(&[], LISTEN);
        assert_eq!(unread.proxy_base().unwrap_err().var, LISTEN.name);
    }

    #[test]
    fn unset_is_the_default() {
        let env = with(&[]);
        assert_eq!(env.listen().unwrap(), DEFAULT_LISTEN);
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::Npm),
            crate::ecosystem::npm::DEFAULT_REGISTRY
        );
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::PyPI),
            crate::ecosystem::pypi::INDEX
        );
        assert_eq!(env.proxy_url().unwrap(), None);
        assert!(env.artifact_origins().unwrap().is_empty());
        assert!(env.allow_direct_origins().unwrap().is_empty());
        assert!(env.rewrite_artifacts().unwrap());
        assert!(env.require_token().unwrap());
        assert_eq!(env.token().unwrap(), None);
        assert_eq!(env.ca_bundle().unwrap(), None);
        assert!(!env.ca_bundle_exclusive().unwrap());
        assert_eq!(
            env.max_metadata_bytes().unwrap(),
            DEFAULT_MAX_METADATA_BYTES
        );
        assert_eq!(env.max_records().unwrap(), DEFAULT_MAX_RECORDS);
        assert_eq!(env.max_verified().unwrap(), DEFAULT_MAX_VERIFIED);
        assert_eq!(
            env.max_concurrent_metadata().unwrap(),
            DEFAULT_MAX_CONCURRENT_METADATA
        );
        assert_eq!(env.spool_dir().unwrap(), crate::spool::default_dir());
        assert_eq!(
            env.max_concurrent_analyses().unwrap(),
            DEFAULT_MAX_CONCURRENT_ANALYSES
        );
        assert_eq!(
            env.watch_interval().unwrap(),
            Some(std::time::Duration::from_secs(
                DEFAULT_WATCH_INTERVAL_SECONDS
            ))
        );
        assert_eq!(
            env.max_traffic_clients().unwrap(),
            DEFAULT_MAX_TRAFFIC_CLIENTS
        );
        assert_eq!(
            env.source_archives().unwrap().as_deref(),
            Some(crate::analysis::source::ARCHIVES)
        );
        assert_eq!(
            env.max_artifact_bytes().unwrap(),
            DEFAULT_MAX_ARTIFACT_BYTES
        );
        assert_eq!(env.database_url().unwrap(), None);
        assert_eq!(env.proxy_mount().unwrap(), Mount::ROOT);
        assert_eq!(
            env.proxy_base().unwrap(),
            format!("http://{DEFAULT_LISTEN}")
        );
        assert_eq!(env.console_url().unwrap(), None);
        assert_eq!(env.console_listen().unwrap(), None);
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
        assert_eq!(env.mode().unwrap(), crate::refusal::Mode::Enforce);
        assert_eq!(env.log_format().unwrap(), crate::logging::Format::Text);
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

    /// `BYRLE_LISTEN=` used to be bound as the empty address, and failed there.
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
            (UPSTREAM_NPM, "https://registry.example"),
            (UPSTREAM_PYPI, "https://mirror.example/simple"),
            (PROXY_URL, "https://proxy.example"),
            (ARTIFACT_ORIGINS, " https://a.example, ,https://b.example "),
            (ALLOW_DIRECT_ORIGINS, "https://c.example"),
            (REWRITE_ARTIFACTS, "0"),
            (REQUIRE_TOKEN, "0"),
            (TOKEN, "byrle_t"),
            (CA_BUNDLE, "/etc/ca.pem"),
            (CA_BUNDLE_EXCLUSIVE, "1"),
            (MAX_METADATA_BYTES, "1024"),
            (MAX_RECORDS, "10"),
            (MAX_VERIFIED, "20"),
            (MAX_CONCURRENT_METADATA, "2"),
            (SPOOL_DIR, "/var/spool/byrle"),
            (MAX_ARTIFACT_BYTES, "4096"),
            (MAX_CONCURRENT_ANALYSES, "3"),
            (MAX_TRAFFIC_CLIENTS, "12"),
            (DATABASE_URL, "postgres://db"),
            (SNAPSHOT_DIR, "/var/lib/byrle"),
            (SNAPSHOT_LIMIT, "7"),
            (POLICY, "policy.yaml"),
            (AUDIT_LOG, "audit.jsonl"),
            (EXPIRY_CEILING_DAYS, "30"),
            (REFUSAL_STATUS, "default=451"),
            (REFUSE_UNSERVABLE, "0"),
            (MODE, "observe"),
            (LOG_FORMAT, "json"),
            (LOG_FILTER, "debug"),
            (BLESS, "1"),
            (NPM_CORPUS, "abbrev"),
            (NPM_CORPUS_FULL, "full"),
            (TEST_DATABASE_URL, "postgres://test"),
            (HOME_DIR, "/home/u"),
            (BUN_CACHE, "/cache"),
        ]);
        assert_eq!(env.listen().unwrap(), "0.0.0.0:9000");
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::Npm),
            "https://registry.example"
        );
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::PyPI),
            "https://mirror.example/simple"
        );
        assert_eq!(
            env.proxy_url().unwrap().as_deref(),
            Some("https://proxy.example")
        );
        assert_eq!(
            env.artifact_origins().unwrap(),
            ["https://a.example", "https://b.example"]
        );
        assert_eq!(env.allow_direct_origins().unwrap(), ["https://c.example"]);
        assert!(!env.rewrite_artifacts().unwrap());
        assert!(!env.require_token().unwrap());
        assert_eq!(env.token().unwrap().as_deref(), Some("byrle_t"));
        assert_eq!(env.ca_bundle().unwrap(), Some(PathBuf::from("/etc/ca.pem")));
        assert!(env.ca_bundle_exclusive().unwrap());
        assert_eq!(env.max_metadata_bytes().unwrap(), 1024);
        assert_eq!(env.max_records().unwrap(), 10);
        assert_eq!(env.max_verified().unwrap(), 20);
        assert_eq!(env.max_concurrent_metadata().unwrap(), 2);
        assert_eq!(env.spool_dir().unwrap(), PathBuf::from("/var/spool/byrle"));
        assert_eq!(env.max_artifact_bytes().unwrap(), 4096);
        assert_eq!(env.max_concurrent_analyses().unwrap(), 3);
        assert_eq!(env.max_traffic_clients().unwrap(), 12);
        assert_eq!(
            env.database_url().unwrap().as_deref(),
            Some("postgres://db")
        );
        assert_eq!(
            env.snapshot_dir().unwrap(),
            Some(PathBuf::from("/var/lib/byrle"))
        );
        assert_eq!(env.snapshot_limit().unwrap(), 7);
        assert_eq!(env.policy().unwrap(), Some(PathBuf::from("policy.yaml")));
        assert_eq!(env.audit_log().unwrap(), Some(PathBuf::from("audit.jsonl")));
        assert_eq!(env.expiry_ceiling_days().unwrap(), 30);
        assert_eq!(env.refusal_status().unwrap().default_status(), 451);
        assert!(!env.refuse_unservable().unwrap());
        assert_eq!(env.mode().unwrap(), crate::refusal::Mode::Observe);
        assert_eq!(env.log_format().unwrap(), crate::logging::Format::Json);
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

    /// Each name is read before its lowercase form, which is used when it is unset: the
    /// order reqwest reads them in.
    #[test]
    fn the_forward_proxy_is_read_uppercase_first() {
        let env = with(&[
            (FORWARD_HTTPS, "http://upper:3128"),
            (FORWARD_HTTPS_LOWER, "http://lower:3128"),
            (FORWARD_HTTP_LOWER, "http://lower:8080"),
            (FORWARD_EXCEPT_LOWER, "internal.example"),
        ]);
        assert_eq!(
            env.upstream_proxy().unwrap(),
            crate::http::UpstreamProxy {
                https: Some("http://upper:3128".to_owned()),
                http: Some("http://lower:8080".to_owned()),
                direct: Some("internal.example".to_owned()),
            }
        );
        assert_eq!(
            with(&[]).upstream_proxy().unwrap(),
            crate::http::UpstreamProxy::default()
        );
    }

    #[test]
    fn a_value_that_does_not_parse_is_an_error_naming_the_variable_and_the_value() {
        let env = with(&[
            (MAX_RECORDS, "5O000"),
            (MAX_METADATA_BYTES, "-1"),
            (MAX_VERIFIED, "1e6"),
            (MAX_CONCURRENT_METADATA, "eight"),
            (EXPIRY_CEILING_DAYS, "-5"),
            (CA_BUNDLE_EXCLUSIVE, "yes"),
            (REWRITE_ARTIFACTS, "false"),
            (REFUSE_UNSERVABLE, "no"),
            (MODE, "warn"),
            (LOG_FORMAT, "logfmt"),
            (SNAPSHOT_LIMIT, "0"),
            (MAX_ARTIFACT_BYTES, "0"),
            (MAX_TRAFFIC_CLIENTS, "0"),
        ]);
        let cases: [(Result<(), EnvError>, &str); 13] = [
            (
                env.max_records().map(drop),
                "BYRLE_MAX_RECORDS: `5O000` is not a whole number",
            ),
            (
                env.max_metadata_bytes().map(drop),
                "BYRLE_MAX_METADATA_BYTES: `-1` is not a whole number",
            ),
            (
                env.max_verified().map(drop),
                "BYRLE_MAX_VERIFIED: `1e6` is not a whole number",
            ),
            (
                env.max_concurrent_metadata().map(drop),
                "BYRLE_MAX_CONCURRENT_METADATA: `eight` is not a whole number",
            ),
            (
                env.expiry_ceiling_days().map(drop),
                "BYRLE_EXPIRY_CEILING_DAYS: `-5` is not a whole number of days",
            ),
            (
                env.ca_bundle_exclusive().map(drop),
                "BYRLE_CA_BUNDLE_EXCLUSIVE: `yes` is not 0 or 1",
            ),
            (
                env.rewrite_artifacts().map(drop),
                "BYRLE_REWRITE_ARTIFACTS: `false` is not 0 or 1",
            ),
            (
                env.refuse_unservable().map(drop),
                "BYRLE_REFUSE_UNSERVABLE: `no` is not 0 or 1",
            ),
            (
                env.mode().map(drop),
                "BYRLE_MODE: `warn` is not `enforce` or `observe`",
            ),
            (
                env.log_format().map(drop),
                "BYRLE_LOG_FORMAT: `logfmt` is not `text` or `json`",
            ),
            (
                env.snapshot_limit().map(drop),
                "BYRLE_SNAPSHOT_LIMIT: `0` is not a whole number above 0",
            ),
            (
                env.max_artifact_bytes().map(drop),
                "BYRLE_MAX_ARTIFACT_BYTES: `0` is not a whole number above 0",
            ),
            (
                env.max_traffic_clients().map(drop),
                "BYRLE_MAX_TRAFFIC_CLIENTS: `0` is not a whole number above 0",
            ),
        ];
        for (result, expected) in cases {
            assert_eq!(result.expect_err(expected).to_string(), expected);
        }
    }

    /// Both upstreams are refused the same way unless an http or https URL with a host,
    /// and the message names the variable.
    #[test]
    fn an_upstream_is_an_http_or_https_url_with_a_host() {
        for (value, reason) in [
            ("nope", "not a URL"),
            ("http://", "not a URL"),
            ("ftp://x", "scheme is not http or https"),
            ("file:///tmp", "no host"),
        ] {
            let npm = with(&[(UPSTREAM_NPM, value)]).upstreams().expect_err(value);
            assert_eq!(
                npm.to_string(),
                format!("BYRLE_UPSTREAM_NPM: `{value}` is not usable: {reason}")
            );
            let pypi = with(&[(UPSTREAM_PYPI, value)])
                .upstreams()
                .expect_err(value);
            assert_eq!(
                pypi.to_string(),
                format!("BYRLE_UPSTREAM_PYPI: `{value}` is not usable: {reason}")
            );
        }
        let mirror = "https://artifacts.example/api/npm/npm-remote/";
        assert_eq!(
            with(&[(UPSTREAM_NPM, mirror)])
                .upstreams()
                .unwrap()
                .get(Ecosystem::Npm),
            mirror.trim_end_matches('/'),
            "the path is kept, and the trailing slash dropped as the proxy drops it"
        );
        let index = "https://artifacts.example/api/pypi/pypi-remote/simple";
        assert_eq!(
            with(&[(UPSTREAM_PYPI, index)])
                .upstreams()
                .unwrap()
                .get(Ecosystem::PyPI),
            index
        );
    }

    /// One ecosystem's upstream does not move the other's.
    #[test]
    fn the_two_upstreams_are_set_independently() {
        let env = with(&[(UPSTREAM_NPM, "https://registry.example")]);
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::Npm),
            "https://registry.example"
        );
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::PyPI),
            crate::ecosystem::pypi::INDEX
        );

        let env = with(&[(UPSTREAM_PYPI, "https://mirror.example/simple")]);
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::Npm),
            crate::ecosystem::npm::DEFAULT_REGISTRY
        );
        assert_eq!(
            env.upstreams().unwrap().get(Ecosystem::PyPI),
            "https://mirror.example/simple"
        );
    }

    #[test]
    fn a_parser_of_its_own_reports_its_reason_under_the_variable() {
        let env = with(&[(REFUSAL_STATUS, "npm=403"), (DEFER_TEST, "nope")]);
        let refusal = env.refusal_status().expect_err("malformed");
        assert_eq!(refusal.var, REFUSAL_STATUS.name);
        assert!(
            refusal
                .to_string()
                .starts_with("BYRLE_REFUSAL_STATUS: `npm=403` "),
            "{refusal}"
        );
        #[cfg(debug_assertions)]
        {
            let defer = env.defer_test().expect_err("malformed");
            assert!(
                defer.to_string().starts_with("BYRLE_DEFER_TEST: `nope` "),
                "{defer}"
            );
        }
    }

    #[test]
    fn a_debug_build_reads_a_well_formed_deferral() {
        #[cfg(debug_assertions)]
        assert!(
            with(&[(DEFER_TEST, "429:1:artifact")])
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
            "BYRLE_POLICY: `f\u{fffd}` is not UTF-8"
        );
        assert!(!env.bless());
    }

    /// The watcher waits the given seconds, is off at 0, and refuses anything else.
    #[test]
    fn the_watch_interval_is_seconds_and_0_is_off() {
        let interval = |value: &str| testing::with(&[(WATCH_INTERVAL, value)]).watch_interval();
        assert_eq!(
            interval("60").unwrap(),
            Some(std::time::Duration::from_secs(60))
        );
        assert_eq!(interval("0").unwrap(), None);
        assert_eq!(
            interval("15m").unwrap_err().to_string(),
            "BYRLE_WATCH_INTERVAL: `15m` is not a whole number of seconds"
        );
    }

    /// No key leaves VirusTotal off; with one, each setting has the public API's default
    /// and refuses what does not parse.
    #[test]
    fn virustotal_is_off_without_a_key_and_its_settings_parse() {
        use crate::analysis::virustotal::{API, Mode, PUBLIC_ORIGINS};
        assert_eq!(testing::with(&[]).virustotal().unwrap(), None);
        let on = testing::with(&[(VIRUSTOTAL_API_KEY, "k")])
            .virustotal()
            .unwrap()
            .unwrap();
        assert_eq!(
            (on.key.as_str(), on.mode, on.base.as_str()),
            ("k", Mode::Hash, API)
        );
        assert_eq!((on.per_minute, on.per_day), (4, 500));
        assert_eq!(on.uploads_from, PUBLIC_ORIGINS.map(str::to_owned).to_vec());
        let set = testing::with(&[
            (VIRUSTOTAL_API_KEY, "k"),
            (VIRUSTOTAL_MODE, "upload"),
            (VIRUSTOTAL_URL, "http://vt.test"),
            (VIRUSTOTAL_PER_MINUTE, "1000"),
            (VIRUSTOTAL_PER_DAY, "300000"),
        ])
        .virustotal()
        .unwrap()
        .unwrap();
        assert_eq!(
            (set.mode, set.base.as_str()),
            (Mode::Upload, "http://vt.test")
        );
        assert_eq!((set.per_minute, set.per_day), (1000, 300_000));
        let refused = |var, value| {
            testing::with(&[(VIRUSTOTAL_API_KEY, "k"), (var, value)])
                .virustotal()
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            refused(VIRUSTOTAL_MODE, "all"),
            "BYRLE_VIRUSTOTAL_MODE: `all` is not `hash` or `upload`"
        );
        assert_eq!(
            refused(VIRUSTOTAL_PER_MINUTE, "0"),
            "BYRLE_VIRUSTOTAL_PER_MINUTE: `0` is not a whole number above 0"
        );
        assert_eq!(
            refused(VIRUSTOTAL_PER_DAY, "-1"),
            "BYRLE_VIRUSTOTAL_PER_DAY: `-1` is not a whole number above 0"
        );
        assert!(
            testing::with_unreadable(&[], VIRUSTOTAL_API_KEY)
                .virustotal()
                .is_err()
        );
        let url = testing::with_unreadable(&[(VIRUSTOTAL_API_KEY, "k")], VIRUSTOTAL_URL);
        assert!(url.virustotal().is_err());
    }

    /// Detectors are split on `;`, blanks dropped, and a detector is given PATH, HOME, SOCKS
    /// and the forward proxies that are set, nothing else.
    #[test]
    fn detectors_are_listed_and_given_little_of_the_environment() {
        let set = testing::with(&[
            (DETECTORS, " a=x ; ;b=y {name}"),
            (DETECTOR_SOCKS, "socks.test:1080"),
            (FORWARD_HTTPS, "http://proxy.test:3128"),
            (GITHUB_TOKEN, "secret"),
        ]);
        assert_eq!(set.detectors().unwrap(), ["a=x", "b=y {name}"]);
        let given: Vec<String> = set
            .detector_environment()
            .into_iter()
            .map(|(name, value)| format!("{name}={}", value.to_string_lossy()))
            .collect();
        assert_eq!(
            given,
            [
                "SOCKS=socks.test:1080",
                "HTTPS_PROXY=http://proxy.test:3128"
            ]
        );
        assert_eq!(
            testing::with(&[]).detectors().unwrap(),
            Vec::<String>::new()
        );
        assert!(
            testing::with_unreadable(&[], DETECTORS)
                .detectors()
                .is_err()
        );
    }

    /// A mirror replaces GitHub's archive host, and `off` turns the comparison off.
    #[test]
    fn source_archives_name_a_host_or_are_off() {
        let archives = |value: &str| {
            testing::with(&[(SOURCE_ARCHIVES, value)])
                .source_archives()
                .unwrap()
        };
        assert_eq!(
            archives("https://mirror.test").as_deref(),
            Some("https://mirror.test")
        );
        assert_eq!(archives("off"), None);
        assert!(
            testing::with_unreadable(&[], SOURCE_ARCHIVES)
                .source_archives()
                .is_err()
        );
    }

    #[test]
    fn process_reads_the_real_environment() {
        assert!(
            process().listen().is_ok(),
            "`process` answers without panicking; no variable here is named PATH"
        );
    }

    #[test]
    fn a_default_is_shown_in_the_unit_it_is_read_in() {
        assert_eq!(
            MAX_METADATA_BYTES.default_shown().as_deref(),
            Some("64 MiB")
        );
        assert_eq!(
            MAX_METADATA_BYTES
                .with_default(Default::Bytes(1000))
                .default_shown()
                .as_deref(),
            Some("1000 bytes")
        );
        assert_eq!(MAX_RECORDS.default_shown().as_deref(), Some("50000"));
        assert_eq!(REFUSAL_STATUS.default_shown().as_deref(), Some("403"));
        assert_eq!(PROXY_URL.default_shown(), None);
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
        assert!(!BLESS.listed() && !TEST_DATABASE_URL.listed() && !HOME_DIR.listed());
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
        files.retain(|f| *f != this);
        let found = named_outside(root, &files);
        assert!(found.is_empty(), "{found:#?}");

        let text = std::fs::read_to_string(&this).expect("readable");
        for (i, _) in text.match_indices("BYRLE_") {
            let name: String = text[i..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            assert!(
                name == "BYRLE_" || ALL.iter().any(|var| var.name == name),
                "{name} is written in env.rs but is not in ALL"
            );
        }
    }

    /// Each line of `files` that writes a variable's name, as `path:line: name` with the path
    /// under `root`.
    fn named_outside(root: &std::path::Path, files: &[PathBuf]) -> Vec<String> {
        let mut found = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(file).expect("readable");
            for (number, line) in text.lines().enumerate() {
                let named = ALL
                    .iter()
                    .map(|var| var.name)
                    .chain(["BYRLE_"])
                    .filter(|name| contains_name(line, name));
                for name in named {
                    let path = file.strip_prefix(root).unwrap_or(file);
                    found.push(format!("{}:{}: {name}", path.display(), number + 1));
                }
            }
        }
        found
    }

    /// The check above finds a name, and a prefix of one it does not know.
    #[test]
    fn a_name_written_elsewhere_is_found() {
        let root = crate::util::test_support::tempdir("env-named-outside");
        let file = root.join("elsewhere.rs");
        let name = LISTEN.name;
        std::fs::write(&file, format!("fn a() {{}}\nlet _ = \"{name}\";\n")).unwrap();
        assert_eq!(
            named_outside(&root, std::slice::from_ref(&file)),
            [
                format!("elsewhere.rs:2: {name}"),
                "elsewhere.rs:2: BYRLE_".to_owned()
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every accessor refuses a value that is not UTF-8, naming its variable.
    #[test]
    fn an_unreadable_variable_is_refused_by_its_accessor() {
        use testing::with_unreadable;

        type Read = fn(&Process) -> Option<EnvError>;
        let cases: [(Var, Read); 17] = [
            (EXPIRY_CEILING_DAYS, |e| e.expiry_ceiling_days().err()),
            (ARTIFACT_ORIGINS, |e| e.artifact_origins().err()),
            (UPSTREAM_NPM, |e| e.upstreams().err()),
            (SPOOL_DIR, |e| e.spool_dir().err()),
            (REFUSAL_STATUS, |e| e.refusal_status().err()),
            (FORWARD_HTTPS, |e| e.upstream_proxy().err()),
            (FORWARD_HTTPS_LOWER, |e| e.upstream_proxy().err()),
            (FORWARD_HTTP, |e| e.upstream_proxy().err()),
            (FORWARD_HTTP_LOWER, |e| e.upstream_proxy().err()),
            (FORWARD_EXCEPT, |e| e.upstream_proxy().err()),
            (FORWARD_EXCEPT_LOWER, |e| e.upstream_proxy().err()),
            (DEFER_TEST, |e| e.defer_test().err()),
            (UV_DEFAULT, |e| e.uv_indexes().err()),
            (UV_OLDER_INDEX, |e| e.uv_indexes().err()),
            (UV_EXTRAS, |e| e.uv_indexes().err()),
            (UV_NAMED, |e| e.uv_indexes().err()),
            (GITHUB_TOKEN, |e| e.github_token().err()),
        ];
        for (var, read) in cases {
            let error = read(&with_unreadable(&[], var)).expect(var.name);
            assert_eq!(error.var, var.name);
        }
        assert_eq!(
            testing::with(&[(GITHUB_TOKEN, "t")])
                .github_token()
                .unwrap(),
            Some("t".to_owned())
        );
    }

    /// The constructors every variable is declared with, run rather than evaluated by the
    /// compiler.
    #[test]
    fn a_variable_is_built_with_its_kind_and_no_default() {
        let built = runtime("BUILT_AT_RUNTIME", "<shown>", &["help"]);
        assert_eq!(
            (built.name, built.shown, built.kind, built.default_text()),
            ("BUILT_AT_RUNTIME", "<shown>", Kind::Runtime, None)
        );
        let other = other(Kind::External, "BUILT", &["help"]);
        assert_eq!((other.kind, other.shown), (Kind::External, ""));
        assert_eq!(MAX_RECORDS.default_text(), None, "a number");
    }

    /// `name` in `line` with no identifier character on either side. `BYRLE_` matches as a
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
