//! Detectors that report findings about a package version, which become signals in its risk
//! score and refuse nothing. A detector is a command run on the version by name, GuardDog
//! first. See docs/engineering_decisions/detectors.md.

pub mod guarddog;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::identity::Ecosystem;

/// The detectors whose rules a policy may weight, and those rules.
pub const KNOWN: [(&str, &[&str]); 1] = [("guarddog", &guarddog::RULES)];

/// Whether `rule`, written `detector.rule`, is a rule of a detector [`KNOWN`] lists.
pub fn knows(rule: &str) -> bool {
    rule.split_once('.').is_some_and(|(detector, rule)| {
        KNOWN
            .iter()
            .any(|(name, rules)| *name == detector && rules.contains(&rule))
    })
}

/// How long one run of a command may take before it is killed.
pub const TIMEOUT: Duration = Duration::from_secs(300);

/// The most a command may print on either stream before it is killed.
pub const MAX_OUTPUT_BYTES: usize = 16 << 20;

/// The longest detail kept for a finding, in characters.
const MAX_DETAIL: usize = 500;

/// What one run of a detector found about a version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Each rule that fired, and what it said.
    pub findings: Vec<Finding>,
    /// Each rule that could not run, and why, such as a lookup the network refused.
    pub errors: Vec<Finding>,
}

/// One rule, and what it said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub detail: String,
}

/// The version a detector is asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

/// A run in flight, boxed so the analyser can hold a `dyn Detector`.
pub type Detecting<'a> = Pin<Box<dyn Future<Output = Result<Detection, String>> + Send + 'a>>;

/// Something that reports findings about a package version.
pub trait Detector: Send + Sync {
    /// Its name, which prefixes its rules in `signal_weights`.
    fn name(&self) -> &str;

    /// Its version. A result another version wrote is not read back.
    fn version(&self) -> &str;

    /// Run it on `target`. Errors when it could not run at all, which stores nothing.
    fn detect<'a>(&'a self, target: &'a Target) -> Detecting<'a>;
}

/// A detector that is a command printing GuardDog's JSON, run as detectors.md says.
#[derive(Debug, Clone)]
pub struct Command {
    name: String,
    version: String,
    program: PathBuf,
    args: Vec<String>,
    environment: Vec<(String, OsString)>,
    timeout: Duration,
    /// Where each run's directory is made: the system's temporary directory.
    scratch: PathBuf,
}

/// What a command printed, and whether it exited 0.
struct Output {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Command {
    /// The detector `spec` describes, as `name=program argument...`, with the version that
    /// `program --version` prints last. It is given `environment` and nothing else.
    /// Errors when the spec does not parse, or the program does not print a version.
    pub async fn configured(
        spec: &str,
        environment: Vec<(String, OsString)>,
    ) -> Result<Self, String> {
        let (name, command) = spec
            .split_once('=')
            .ok_or_else(|| format!("`{spec}` is not name=command"))?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!("`{name}` is not a detector name: a-z, 0-9 and -"));
        }
        let mut words = command.split_whitespace();
        let program = PathBuf::from(
            words
                .next()
                .ok_or_else(|| format!("`{spec}` names no program"))?,
        );
        let mut detector = Self {
            name: name.to_owned(),
            version: String::new(),
            program,
            args: words.map(str::to_owned).collect(),
            environment,
            timeout: TIMEOUT,
            scratch: std::env::temp_dir(),
        };
        let printed = detector.run(&["--version".to_owned()]).await?;
        let version = String::from_utf8_lossy(&printed.stdout)
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .map(str::to_owned);
        detector.version = match (printed.success, version) {
            (true, Some(version)) => version,
            _ => {
                return Err(format!(
                    "{} --version printed no version: {}",
                    detector.program.display(),
                    tail(&printed.stderr)
                ));
            }
        };
        Ok(detector)
    }

    /// The same detector, killed after `timeout` in place of [`TIMEOUT`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Run the program with `args` in a new directory, which is removed after.
    /// Errors when it cannot start, prints too much, or outlasts the timeout, all of which
    /// kill it.
    async fn run(&self, args: &[String]) -> Result<Output, String> {
        static RUNS: AtomicU64 = AtomicU64::new(0);
        let directory = self.scratch.join(format!(
            "waharoa-detector-{}-{}",
            std::process::id(),
            RUNS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(args)
            .env_clear()
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let program = self.program.display();
        let running = async {
            let mut child = command
                .spawn()
                .map_err(|e| format!("{program} did not start: {e}"))?;
            let mut stdout = child.stdout.take().expect("stdout is piped");
            let mut stderr = child.stderr.take().expect("stderr is piped");
            let (stdout, stderr) =
                tokio::try_join!(read_capped(&mut stdout), read_capped(&mut stderr))
                    .map_err(|e| format!("{program}: {e}"))?;
            let success = child.wait().await.is_ok_and(|status| status.success());
            Ok(Output {
                success,
                stdout,
                stderr,
            })
        };
        let ran = tokio::time::timeout(self.timeout, running)
            .await
            .unwrap_or_else(|_| {
                Err(format!(
                    "{program} ran past {} seconds",
                    self.timeout.as_secs_f32()
                ))
            });
        let _ = std::fs::remove_dir_all(&directory);
        ran
    }
}

impl Detector for Command {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn detect<'a>(&'a self, target: &'a Target) -> Detecting<'a> {
        Box::pin(async move {
            for value in [&target.name, &target.version] {
                if value.starts_with('-') {
                    return Err(format!("`{value}` could be read as an option"));
                }
            }
            let args: Vec<String> = self
                .args
                .iter()
                .map(|arg| {
                    arg.replace("{ecosystem}", target.ecosystem.as_str())
                        .replace("{name}", &target.name)
                        .replace("{version}", &target.version)
                })
                .collect();
            let printed = self.run(&args).await?;
            detection(&printed.stdout)
                .map_err(|e| format!("{}: {e}; it said {}", self.name, tail(&printed.stderr)))
        })
    }
}

/// Read `stream` to its end, or to where it can no longer be read.
/// Errors past [`MAX_OUTPUT_BYTES`].
async fn read_capped(stream: &mut (dyn AsyncRead + Unpin + Send)) -> Result<Vec<u8>, String> {
    let mut read = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return Ok(read);
        }
        if read.len() + n > MAX_OUTPUT_BYTES {
            return Err(format!("printed more than {MAX_OUTPUT_BYTES} bytes"));
        }
        read.extend_from_slice(&chunk[..n]);
    }
}

/// The findings and errors in a detector's JSON output.
/// Errors when it is not a JSON object.
fn detection(stdout: &[u8]) -> Result<Detection, String> {
    #[derive(Deserialize)]
    struct Printed {
        #[serde(default)]
        results: BTreeMap<String, serde_json::Value>,
        #[serde(default)]
        errors: BTreeMap<String, serde_json::Value>,
    }
    let printed: Printed = serde_json::from_slice(stdout)
        .map_err(|e| format!("its output is not the JSON a detector prints: {e}"))?;
    let fired = |value: &serde_json::Value| match value {
        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(fields) => !fields.is_empty(),
        _ => true,
    };
    let finding = |(rule, value): (String, serde_json::Value)| Finding {
        rule,
        detail: detail(&value),
    };
    Ok(Detection {
        findings: printed
            .results
            .into_iter()
            .filter(|(_, value)| fired(value))
            .map(finding)
            .collect(),
        errors: printed.errors.into_iter().map(finding).collect(),
    })
}

/// `value` as text, a string as it is and anything else as JSON, cut at [`MAX_DETAIL`].
fn detail(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    text.chars().take(MAX_DETAIL).collect()
}

/// The last line `stderr` printed that is not blank, or `nothing` when there is none.
fn tail(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("nothing")
        .chars()
        .take(MAX_DETAIL)
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    /// A fake detector: its version is 9.9.9, and a scan answers by the name it is given.
    pub(crate) const FAKE: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake detector"; echo "9.9.9"; exit 0; fi
case "$3" in
  quiet) echo '{"results":{"r":null,"f":false,"s":"","a":[],"o":{}}}' ;;
  loud) echo '{"results":{"a":{"x":1},"b":["y"],"c":"text","n":3},"errors":{"e":"boom"}}' ;;
  env) printf '{"results":{"env":"%s","cwd":"%s"}}' "$(env | sort | tr '\n' ' ')" "$(pwd)" ;;
  slow) echo $$ > "$4"; sleep 30 ;;
  flood) head -c 20000000 /dev/zero | tr '\0' 'x' ;;
  garbage) echo "not json" ; echo "it went wrong" >&2 ;;
esac
"#;

    /// `script` written to an executable file in a directory of `label`'s own.
    pub(crate) fn installed(label: &str, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = crate::util::test_support::tempdir(label).join("detector");
        std::fs::write(&path, script).expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmods");
        path
    }

    async fn fake(label: &str) -> Command {
        let path = installed(label, FAKE);
        Command::configured(
            &format!(
                "fake={} scan {{ecosystem}} {{name}} {{version}}",
                path.display()
            ),
            vec![("PATH".to_owned(), OsString::from("/usr/bin:/bin"))],
        )
        .await
        .expect("configures")
    }

    fn target(name: &str) -> Target {
        Target {
            ecosystem: Ecosystem::Npm,
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    #[test]
    fn a_rule_is_known_only_as_a_known_detectors() {
        assert!(knows("guarddog.threat-process-hooks"));
        assert!(knows("guarddog.bundled_binary"));
        assert!(!knows("guarddog.threat-proces-hooks"), "misspelt");
        assert!(!knows("other.threat-process-hooks"));
        assert!(!knows("threat-process-hooks"));
        assert!(
            guarddog::RULES.windows(2).all(|pair| pair[0] < pair[1]),
            "sorted"
        );
    }

    /// The version is the last line `--version` prints, and a scan's rules that found
    /// something are findings, its errors errors, each detail cut to its length.
    #[tokio::test]
    async fn a_command_reports_the_rules_that_fired() {
        let detector = fake("detector-loud").await;
        assert_eq!((detector.name(), detector.version()), ("fake", "9.9.9"));
        assert_eq!(
            detector.detect(&target("quiet")).await,
            Ok(Detection::default())
        );
        let loud = detector.detect(&target("loud")).await.expect("runs");
        let rules: Vec<(&str, &str)> = loud
            .findings
            .iter()
            .map(|f| (f.rule.as_str(), f.detail.as_str()))
            .collect();
        assert_eq!(
            rules,
            [
                ("a", r#"{"x":1}"#),
                ("b", r#"["y"]"#),
                ("c", "text"),
                ("n", "3")
            ]
        );
        assert_eq!(
            loud.errors,
            [Finding {
                rule: "e".to_owned(),
                detail: "boom".to_owned()
            }]
        );
        assert_eq!(
            detail(&serde_json::json!("x".repeat(600))).len(),
            MAX_DETAIL
        );
    }

    /// Only the environment it was given reaches it, and it runs in a directory of its own
    /// that is removed after.
    #[tokio::test]
    async fn a_command_is_given_its_environment_alone() {
        let detector = fake("detector-env").await;
        let seen = detector.detect(&target("env")).await.expect("runs");
        let said = |rule: &str| {
            seen.findings
                .iter()
                .find(|f| f.rule == rule)
                .map(|f| f.detail.clone())
                .expect("printed")
        };
        let env = said("env");
        assert!(env.contains("PATH=/usr/bin:/bin"), "{env}");
        let leaked: Vec<String> = std::env::vars()
            .map(|(name, _)| name)
            .filter(|name| !["PATH", "PWD", "OLDPWD", "SHLVL", "_"].contains(&name.as_str()))
            .filter(|name| {
                env.contains(&format!(" {name}=")) || env.starts_with(&format!("{name}="))
            })
            .collect();
        assert_eq!(leaked, Vec::<String>::new(), "{env}");
        let cwd = said("cwd");
        assert!(cwd.contains("waharoa-detector-"), "{cwd}");
        assert!(!std::path::Path::new(&cwd).exists(), "removed after: {cwd}");
    }

    /// A value that could be read as an option is refused before anything runs, output that
    /// is not JSON says what it printed on stderr, and too much output is refused.
    #[tokio::test]
    async fn what_a_command_cannot_answer_is_an_error() {
        let detector = fake("detector-errors").await;
        let dashed = detector.detect(&target("--help")).await.unwrap_err();
        assert_eq!(dashed, "`--help` could be read as an option");
        let mut version = target("x");
        version.version = "-1".to_owned();
        assert!(detector.detect(&version).await.is_err());
        let garbage = detector.detect(&target("garbage")).await.unwrap_err();
        assert!(
            garbage.starts_with("fake: its output is not the JSON")
                && garbage.ends_with("it said it went wrong"),
            "{garbage}"
        );
        let mut unwritable = detector.clone();
        unwritable.scratch = PathBuf::from("/nonexistent/scratch");
        let error = unwritable.detect(&target("quiet")).await.unwrap_err();
        assert!(
            error.starts_with("/nonexistent/scratch/waharoa-detector-"),
            "{error}"
        );
        let flood = detector.detect(&target("flood")).await.unwrap_err();
        assert!(flood.contains("printed more than"), "{flood}");
        assert_eq!(tail(b"\n  \n"), "nothing");
    }

    /// A run past its timeout is killed: the process it started is gone.
    #[tokio::test]
    async fn a_command_past_its_timeout_is_killed() {
        let detector = fake("detector-slow")
            .await
            .with_timeout(Duration::from_millis(500));
        let pidfile = crate::util::test_support::tempdir("detector-slow-pid").join("pid");
        let mut slow = target("slow");
        slow.version = pidfile.display().to_string();
        let error = detector.detect(&slow).await.unwrap_err();
        assert!(error.contains("ran past 0.5 seconds"), "{error}");
        let pid = std::fs::read_to_string(&pidfile).expect("the script wrote its pid");
        let status = format!("/proc/{}/stat", pid.trim());
        let gone = || {
            std::fs::read_to_string(&status)
                .map_or(true, |stat| stat.split_whitespace().nth(2) == Some("Z"))
        };
        for _ in 0..40 {
            if gone() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(gone(), "process {} still runs", pid.trim());
    }

    /// Each spec that cannot be a detector is refused, and so is a program that prints no
    /// version or does not start.
    #[tokio::test]
    async fn a_spec_that_is_not_a_detector_is_refused() {
        let silent = installed("detector-silent", "#!/bin/sh\nexit 1\n");
        let silent = format!("silent={}", silent.display());
        for (spec, said) in [
            ("no equals sign", "is not name=command"),
            ("Bad=prog", "is not a detector name"),
            ("=prog", "is not a detector name"),
            ("name=", "names no program"),
            ("name=/nonexistent/program", "did not start"),
            (silent.as_str(), "printed no version"),
        ] {
            let error = Command::configured(spec, Vec::new()).await.unwrap_err();
            assert!(error.contains(said), "{spec}: {error}");
        }
    }
}
