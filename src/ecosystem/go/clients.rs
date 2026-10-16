//! go, as `byrle doctor` checks it, from `go env`: `GOPROXY`, `GONOPROXY` and `GOFLAGS` as
//! go resolves them from the environment and its `go env -w` file. `GONOPROXY` defaults to
//! `GOPRIVATE`. `GOSUMDB` and `GONOSUMDB` are not checked: the proxy checks each zip and
//! `go.mod` against sum.golang.org whatever they say.

use serde::Deserialize;

use crate::doctor::{
    CacheBypass, CacheLocation, Client, Finding, Indexes, Machine, RegistrySource, Severity,
};
use crate::env::EnvError;

pub const GO: Client = Client {
    name: "go",
    version_args: &["version"],
    registry: Some(RegistrySource::Read {
        read: go_indexes,
        set_index: super::setup_line,
        drop_extra: || "remove what follows the proxy's URL in GOPROXY".to_owned(),
    }),
    set_registry: "",
    cache: CacheLocation::Asked {
        args: &["env", "GOMODCACHE"],
        under: Some("cache/download"),
    },
    bypass: CacheBypass::Complete,
    clear_cache: "go clean -modcache",
    settings: Some(go_settings),
};

pub const CLIENTS: &[Client] = &[GO];

/// What doctor asks `go env` for.
const VARIABLES: &[&str] = &["env", "-json", "GOPROXY", "GONOPROXY", "GOFLAGS"];

/// The variables, as `go env -json` prints them.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub struct GoEnv {
    #[serde(default)]
    pub goproxy: String,
    #[serde(default)]
    pub gonoproxy: String,
    #[serde(default)]
    pub goflags: String,
}

/// `go env`'s answer. `None` when go is not installed or prints no JSON.
fn go_env(machine: &Machine) -> Option<GoEnv> {
    serde_json::from_str(&machine.ask("go", VARIABLES)?).ok()
}

fn go_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    Ok(go_env(machine).map(|env| proxies(&env.goproxy)))
}

/// The first entry of `GOPROXY`, and those go asks after any error from it: the entries
/// after a `|`. After a `,` go asks the next only on a 404 or 410, and did not after any
/// refusal measured in docs/go-plan.md, step 5. `off` fetches nothing.
pub fn proxies(goproxy: &str) -> Indexes {
    let first_end = goproxy.find([',', '|']).unwrap_or(goproxy.len());
    let index = goproxy[..first_end].trim().to_owned();
    let extra = match goproxy[first_end..].strip_prefix('|') {
        Some(rest) => rest
            .split([',', '|'])
            .map(str::trim)
            .filter(|entry| !entry.is_empty() && *entry != "off")
            .map(str::to_owned)
            .collect(),
        None => Vec::new(),
    };
    Indexes { index, extra }
}

fn go_settings(machine: &Machine) -> Vec<Finding> {
    go_env(machine).map_or_else(Vec::new, |env| settings(&env))
}

/// `GONOPROXY` sends the modules it matches to their origin. `-mod=vendor` in `GOFLAGS`
/// builds from `vendor/`, fetching no module.
pub fn settings(env: &GoEnv) -> Vec<Finding> {
    let unproxied = if env.gonoproxy.is_empty() {
        Finding::new(
            Severity::Ok,
            "go GONOPROXY",
            "empty, so every module is fetched through GOPROXY",
        )
    } else {
        Finding::new(
            Severity::Warn,
            "go GONOPROXY",
            format!(
                "modules matching {} are fetched from their origin, never through the proxy",
                env.gonoproxy
            ),
        )
    };
    let vendored = env
        .goflags
        .split_whitespace()
        .any(|flag| flag == "-mod=vendor");
    let flags = if vendored {
        Finding::new(
            Severity::Warn,
            "go GOFLAGS",
            "-mod=vendor: builds read vendor/ and fetch no module, so the proxy sees none of them",
        )
        .with_fix("remove -mod=vendor from GOFLAGS")
    } else {
        Finding::new(Severity::Ok, "go GOFLAGS", "no -mod=vendor")
    };
    vec![unproxied, flags]
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn indexes(index: &str, extra: &[&str]) -> Indexes {
        Indexes {
            index: index.to_owned(),
            extra: extra.iter().map(|e| (*e).to_owned()).collect(),
        }
    }

    /// Only what follows a `|` after the first entry is asked when the proxy refuses.
    #[test]
    fn the_first_entry_is_the_index_and_what_follows_a_bar_is_extra() {
        for (goproxy, expected) in [
            ("https://h/go", indexes("https://h/go", &[])),
            ("https://h/go,direct", indexes("https://h/go", &[])),
            (
                "https://proxy.golang.org,direct",
                indexes("https://proxy.golang.org", &[]),
            ),
            ("https://h/go|direct", indexes("https://h/go", &["direct"])),
            (
                "https://h/go | https://other.example,direct|off",
                indexes("https://h/go", &["https://other.example", "direct"]),
            ),
            ("off", indexes("off", &[])),
            ("", indexes("", &[])),
        ] {
            assert_eq!(proxies(goproxy), expected, "{goproxy}");
        }
    }

    fn titled(findings: &[Finding]) -> Vec<(Severity, &str, &str)> {
        findings
            .iter()
            .map(|f| (f.severity, f.title.as_str(), f.detail.as_str()))
            .collect()
    }

    #[test]
    fn gonoproxy_and_vendoring_are_warned_of() {
        assert_eq!(
            titled(&settings(&GoEnv::default())),
            [
                (
                    Severity::Ok,
                    "go GONOPROXY",
                    "empty, so every module is fetched through GOPROXY"
                ),
                (Severity::Ok, "go GOFLAGS", "no -mod=vendor"),
            ]
        );
        let other_flags = settings(&GoEnv {
            goflags: "-modcacherw".to_owned(),
            ..GoEnv::default()
        });
        assert_eq!(
            other_flags[1].severity,
            Severity::Ok,
            "{:?}",
            other_flags[1]
        );
        let found = settings(&GoEnv {
            goproxy: String::new(),
            gonoproxy: "corp.example/*".to_owned(),
            goflags: "-modcacherw -mod=vendor".to_owned(),
        });
        assert_eq!(
            titled(&found),
            [
                (
                    Severity::Warn,
                    "go GONOPROXY",
                    "modules matching corp.example/* are fetched from their origin, never \
                     through the proxy"
                ),
                (
                    Severity::Warn,
                    "go GOFLAGS",
                    "-mod=vendor: builds read vendor/ and fetch no module, so the proxy sees \
                     none of them"
                ),
            ]
        );
        assert_eq!(
            found[1].fix.as_deref(),
            Some("remove -mod=vendor from GOFLAGS")
        );
    }

    /// What go 1.27.2 printed for `go env -json GOPROXY GONOPROXY GOFLAGS` on 2026-10-16.
    const PRINTED: &str = "{\n\t\"GOFLAGS\": \"\",\n\t\"GONOPROXY\": \"corp.example/*\",\n\t\
                           \"GOPROXY\": \"https://a:b@h.example/go|direct\"\n}";

    fn machine<'a>(
        environment: &'a crate::env::Process,
        run: &'a (dyn Fn(&str, &[&str]) -> Option<String> + Sync),
    ) -> Machine<'a> {
        Machine {
            environment,
            dir: std::path::Path::new("/"),
            run,
        }
    }

    /// go is asked once per check, and a go that is absent or prints no JSON gives nothing.
    #[test]
    fn go_env_is_read_from_the_go_command() {
        let environment = crate::env::testing::with(&[]);
        let printed = |program: &str, args: &[&str]| {
            (program == "go" && args == VARIABLES).then(|| PRINTED.to_owned())
        };
        let found = machine(&environment, &printed);
        assert_eq!(
            go_indexes(&found).unwrap(),
            Some(indexes("https://a:b@h.example/go", &["direct"]))
        );
        assert_eq!(go_settings(&found)[0].severity, Severity::Warn);

        for answer in [None, Some("not json".to_owned())] {
            let answering = move |_: &str, _: &[&str]| answer.clone();
            let absent = machine(&environment, &answering);
            assert_eq!(go_indexes(&absent).unwrap(), None);
            assert!(go_settings(&absent).is_empty());
        }
        assert_eq!(
            (GO.registry.as_ref().map(|registry| match registry {
                RegistrySource::Read { drop_extra, .. } => drop_extra(),
                RegistrySource::Asked(_) => String::new(),
            })),
            Some("remove what follows the proxy's URL in GOPROXY".to_owned())
        );
    }
}
