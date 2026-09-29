//! The package managers that install from a PyPI index, as `waharoa doctor` checks them.
//!
//! Neither has one command that prints the index it uses, as `npm config get registry` does,
//! so each is read here. What was measured, 2026-09-19, pip 26.1.1 and uv 0.12.5:
//!
//! | | pip | uv |
//! |---|---|---|
//! | configured index | `pip config list`, which includes pip's own variables as `:env:` keys. `pip config get global.index-url` answers `No such key` for a set key | no command: uv's variables, then `uv.toml` or `pyproject.toml` `[tool.uv]` |
//! | second install through the proxy with one cache | the index and the files reach the proxy again | nothing reaches the proxy |
//!
//! `pip config list` prints values as written, credentials included, so nothing here prints
//! a URL without [`crate::origin::without_credentials`].

use std::path::{Path, PathBuf};

use crate::doctor::{CacheBypass, CacheLocation, Client, Indexes, Machine, RegistrySource};
use crate::env::{self, Env, EnvError};

/// Where pip and uv install from when nothing is configured.
const DEFAULT_INDEX: &str = super::INDEX;

pub const PIP: Client = Client {
    name: "pip",
    registry: Some(RegistrySource::Read {
        read: pip_indexes,
        set_index: |url| format!("pip config set global.index-url {url}"),
        drop_extra: || {
            "pip config unset global.extra-index-url, and the same for any other section or \
             variable `pip config list` shows setting one"
                .to_owned()
        },
    }),
    set_registry: "",
    cache: CacheLocation::Asked {
        args: &["cache", "dir"],
        under: None,
    },
    bypass: CacheBypass::None,
    clear_cache: "pip cache purge",
};

pub const UV: Client = Client {
    name: "uv",
    registry: Some(RegistrySource::Read {
        read: uv_indexes,
        set_index: |url| {
            format!(
                "set {} to {url}, or `index-url` in uv.toml",
                env::UV_DEFAULT
            )
        },
        drop_extra: || {
            format!(
                "unset {} and {}, and remove `extra-index-url` and each `[[index]]` that is \
                 not `default = true` from uv.toml or pyproject.toml",
                env::UV_EXTRAS,
                env::UV_NAMED
            )
        },
    }),
    set_registry: "",
    cache: CacheLocation::Asked {
        args: &["cache", "dir"],
        under: None,
    },
    bypass: CacheBypass::Complete,
    clear_cache: "uv cache clean",
};

pub const CLIENTS: &[Client] = &[PIP, UV];

fn pip_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    Ok((machine.run)("pip", &["config", "list"]).map(|listed| pip_config(&listed)))
}

/// The indexes `pip config list` says pip uses.
///
/// A `PIP_INDEX_URL` variable, listed as `:env:.index-url`, beats the `install` section, which
/// beats `global`. Every `extra-index-url`, from any of them, is asked too. A value is one
/// line of `section.key='value'`, and an `extra-index-url` may hold several URLs separated
/// by whitespace.
pub fn pip_config(listed: &str) -> Indexes {
    let values: Vec<(&str, &str)> = listed
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = value.trim().trim_matches(['\'', '"']);
            Some((key.trim(), value))
        })
        .collect();
    let value = |key: &str| values.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    let index = [":env:.index-url", "install.index-url", "global.index-url"]
        .into_iter()
        .find_map(value)
        .unwrap_or(DEFAULT_INDEX);
    let extra = values
        .iter()
        .filter(|(key, _)| key.ends_with(".extra-index-url"))
        .flat_map(|(_, urls)| urls.split_whitespace())
        .map(str::to_owned)
        .collect();
    Indexes {
        index: index.to_owned(),
        extra,
    }
}

/// uv's index settings from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UvVars {
    pub default_index: Option<String>,
    pub index_url: Option<String>,
    pub extra_index_url: Option<String>,
    pub index: Option<String>,
}

fn uv_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    if (machine.run)("uv", &["--version"]).is_none() {
        return Ok(None);
    }
    let environment = machine.environment;
    let files = uv_config_files(environment, machine.dir)?;
    let read: Vec<String> = files
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect();
    let texts: Vec<&str> = read.iter().map(String::as_str).collect();
    Ok(Some(uv_config(&environment.uv_indexes()?, &texts)))
}

/// The configuration files uv reads, most specific first: the nearest `uv.toml`, or
/// `pyproject.toml` with a `[tool.uv]` table, from `cwd` up; then the user's
/// `uv/uv.toml`; then `/etc/uv/uv.toml`. The file [`env::UV_FILE`] names alone when it is
/// set, and none when [`env::UV_NO_FILES`] is.
pub fn uv_config_files<L: Fn(&str) -> Option<std::ffi::OsString>>(
    environment: &Env<L>,
    cwd: &Path,
) -> Result<Vec<PathBuf>, EnvError> {
    if environment.uv_no_config()? {
        return Ok(Vec::new());
    }
    if let Some(file) = environment.uv_config_file()? {
        return Ok(vec![file]);
    }
    let mut files: Vec<PathBuf> = cwd
        .ancestors()
        .find_map(|dir| {
            let uv = dir.join("uv.toml");
            let pyproject = dir.join("pyproject.toml");
            if uv.is_file() {
                Some(uv)
            } else if std::fs::read_to_string(&pyproject).is_ok_and(|text| has_tool_uv(&text)) {
                Some(pyproject)
            } else {
                None
            }
        })
        .into_iter()
        .collect();
    let user = match environment.xdg_config_home()? {
        Some(dir) => Some(dir),
        None => environment.home()?.map(|home| home.join(".config")),
    };
    files.extend(user.map(|dir| dir.join("uv").join("uv.toml")));
    files.push(PathBuf::from("/etc/uv/uv.toml"));
    Ok(files.into_iter().filter(|path| path.is_file()).collect())
}

fn has_tool_uv(pyproject: &str) -> bool {
    table(pyproject, true).is_some()
}

/// The table uv reads settings from: the document itself for `uv.toml`, `[tool.uv]` for
/// `pyproject.toml`. `None` when the text is not TOML or has no such table.
fn table(text: &str, pyproject: bool) -> Option<toml::Table> {
    let document: toml::Table = toml::from_str(text).ok()?;
    if !pyproject {
        return Some(document);
    }
    document.get("tool")?.get("uv")?.as_table().cloned()
}

/// The indexes uv uses, from its variables and from `files`, most specific first, each a
/// `uv.toml` or a `pyproject.toml`.
///
/// [`env::UV_DEFAULT`], or its older name [`env::UV_OLDER_INDEX`], beats a file's
/// `[[index]]` with `default = true` or its `index-url`, and a nearer file beats a farther
/// one. Every URL in [`env::UV_EXTRAS`] and [`env::UV_NAMED`], and every `extra-index-url`
/// and other `[[index]]`, is asked too.
/// A file that is not TOML is skipped; uv refuses it, so it configures nothing.
pub fn uv_config(vars: &UvVars, files: &[&str]) -> Indexes {
    let tables: Vec<toml::Table> = files
        .iter()
        .filter_map(|text| {
            table(text, true)
                .filter(|t| !t.is_empty())
                .or_else(|| table(text, false))
        })
        .collect();
    let urls = |table: &toml::Table, key: &str| -> Vec<String> {
        match table.get(key) {
            Some(toml::Value::String(url)) => vec![url.clone()],
            Some(toml::Value::Array(urls)) => urls
                .iter()
                .filter_map(|u| u.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    };
    let indexes = |table: &toml::Table| -> Vec<(String, bool)> {
        table
            .get("index")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let url = entry.get("url")?.as_str()?.to_owned();
                let default = entry
                    .get("default")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false);
                Some((url, default))
            })
            .collect()
    };

    let from_files = tables.iter().find_map(|table| {
        indexes(table)
            .into_iter()
            .find(|(_, default)| *default)
            .map(|(url, _)| url)
            .or_else(|| urls(table, "index-url").into_iter().next())
    });
    let index = vars
        .default_index
        .clone()
        .or_else(|| vars.index_url.clone())
        .or(from_files)
        .unwrap_or_else(|| DEFAULT_INDEX.to_owned());

    let spaced = |value: &Option<String>| -> Vec<String> {
        value
            .iter()
            .flat_map(|v| v.split_whitespace())
            .map(|entry| {
                entry
                    .split_once('=')
                    .map_or(entry, |(_, url)| url)
                    .to_owned()
            })
            .collect()
    };
    let mut extra = spaced(&vars.extra_index_url);
    extra.extend(spaced(&vars.index));
    for table in &tables {
        extra.extend(urls(table, "extra-index-url"));
        extra.extend(
            indexes(table)
                .into_iter()
                .filter(|(_, default)| !default)
                .map(|(url, _)| url),
        );
    }
    Indexes { index, extra }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::testing::with;

    #[test]
    fn pip_uses_the_environment_then_install_then_global_and_asks_every_extra() {
        let listed = "global.extra-index-url='https://user:secret@example.jfrog.io/simple/'\n\
                      global.index-url='https://global.example/simple/'\n\
                      install.index-url='https://install.example/simple/'\n\
                      :env:.config-file='/dev/null'\n\
                      :env:.extra-index-url='https://a.example/simple/ https://b.example/simple/'";
        assert_eq!(
            pip_config(listed),
            Indexes {
                index: "https://install.example/simple/".to_owned(),
                extra: vec![
                    "https://user:secret@example.jfrog.io/simple/".to_owned(),
                    "https://a.example/simple/".to_owned(),
                    "https://b.example/simple/".to_owned(),
                ],
            }
        );
        assert_eq!(
            pip_config(&format!("{listed}\n:env:.index-url='http://proxy/simple/'")).index,
            "http://proxy/simple/"
        );
        assert_eq!(
            pip_config("global.index-url='https://global.example/simple/'").index,
            "https://global.example/simple/"
        );
        assert_eq!(
            pip_config("WARNING: not a setting\nglobal.index-url='https://global.example/simple/'")
                .index,
            "https://global.example/simple/",
            "a line with no `=` is skipped"
        );
        assert_eq!(
            pip_config(""),
            Indexes {
                index: DEFAULT_INDEX.to_owned(),
                extra: Vec::new(),
            }
        );
    }

    #[test]
    fn uv_uses_its_variables_then_the_nearest_file_and_asks_every_extra() {
        let project = r#"
            [tool.uv]
            extra-index-url = ["https://extra.example/simple/"]

            [[tool.uv.index]]
            url = "https://project.example/simple/"
            default = true

            [[tool.uv.index]]
            name = "internal"
            url = "https://internal.example/simple/"
        "#;
        let user = r#"index-url = "https://user.example/simple/""#;
        assert_eq!(
            uv_config(&UvVars::default(), &[project, user]),
            Indexes {
                index: "https://project.example/simple/".to_owned(),
                extra: vec![
                    "https://extra.example/simple/".to_owned(),
                    "https://internal.example/simple/".to_owned(),
                ],
            }
        );
        assert_eq!(
            uv_config(&UvVars::default(), &[user]).index,
            "https://user.example/simple/"
        );
        let vars = UvVars {
            default_index: Some("http://proxy/simple/".to_owned()),
            index_url: Some("https://older.example/simple/".to_owned()),
            extra_index_url: Some("https://e1.example/ https://e2.example/".to_owned()),
            index: Some("named=https://n.example/simple/".to_owned()),
        };
        assert_eq!(
            uv_config(&vars, &[user]),
            Indexes {
                index: "http://proxy/simple/".to_owned(),
                extra: vec![
                    "https://e1.example/".to_owned(),
                    "https://e2.example/".to_owned(),
                    "https://n.example/simple/".to_owned(),
                ],
            }
        );
        let older = UvVars {
            index_url: Some("https://older.example/simple/".to_owned()),
            ..UvVars::default()
        };
        assert_eq!(
            uv_config(&older, &[]).index,
            "https://older.example/simple/"
        );
        let unusable = r#"
            [tool.black]
            line-length = 100

            [[index]]
            name = "no-url"

            [[index]]
            url = 7
        "#;
        assert_eq!(
            uv_config(&UvVars::default(), &[unusable]),
            Indexes {
                index: DEFAULT_INDEX.to_owned(),
                extra: Vec::new(),
            },
            "a `[tool]` with no `uv`, and an index with no URL string"
        );
        assert_eq!(
            uv_config(&UvVars::default(), &["not = [toml"]),
            Indexes {
                index: DEFAULT_INDEX.to_owned(),
                extra: Vec::new(),
            }
        );
    }

    /// The nearest `uv.toml`, or `pyproject.toml` with `[tool.uv]`, then the user's file;
    /// [`env::UV_FILE`] alone; nothing under [`env::UV_NO_FILES`].
    #[test]
    fn uv_reads_the_files_it_would() {
        let root = crate::util::test_support::tempdir("uv-config-files");
        let (project, nested, config) = (
            root.join("project"),
            root.join("project/src/deep"),
            root.join("config"),
        );
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(config.join("uv")).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.uv]\nindex-url = \"x\"\n",
        )
        .unwrap();
        std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"n\"\n").unwrap();
        std::fs::write(config.join("uv/uv.toml"), "index-url = \"y\"\n").unwrap();
        let config_home = config.to_str().unwrap();

        let found =
            uv_config_files(&with(&[(crate::env::CONFIG_HOME, config_home)]), &nested).unwrap();
        assert_eq!(
            found[..2],
            [project.join("pyproject.toml"), config.join("uv/uv.toml")]
        );

        std::fs::write(project.join("src/uv.toml"), "index-url = \"z\"\n").unwrap();
        let found =
            uv_config_files(&with(&[(crate::env::CONFIG_HOME, config_home)]), &nested).unwrap();
        assert_eq!(found[0], project.join("src/uv.toml"));

        let home = root.to_str().unwrap();
        std::fs::create_dir_all(root.join(".config/uv")).unwrap();
        std::fs::write(root.join(".config/uv/uv.toml"), "").unwrap();
        let found = uv_config_files(&with(&[(crate::env::HOME_DIR, home)]), &root).unwrap();
        assert!(
            found.contains(&root.join(".config/uv/uv.toml")),
            "{found:?}"
        );
        assert!(
            !found.contains(&root.join("pyproject.toml")),
            "no [tool.uv]"
        );

        let only = config.join("uv/uv.toml");
        assert_eq!(
            uv_config_files(
                &with(&[(crate::env::UV_FILE, only.to_str().unwrap())]),
                &nested
            )
            .unwrap(),
            std::slice::from_ref(&only)
        );
        assert!(
            uv_config_files(&with(&[(crate::env::UV_NO_FILES, "1")]), &nested)
                .unwrap()
                .is_empty()
        );
    }

    /// uv is read only when it runs, from the files it would read. A file that cannot be
    /// read configures nothing.
    #[test]
    fn uv_is_read_when_it_runs() {
        use crate::env::testing::with_unreadable;
        use crate::env::{self, Var};

        let root = crate::util::test_support::tempdir("uv-indexes");
        let file = root.join("uv.toml");
        std::fs::write(&file, "index-url = \"https://file.example/simple/\"\n").unwrap();
        let file = file.to_str().unwrap().to_owned();
        let missing = root.join("missing.toml").to_str().unwrap().to_owned();
        let runs = |_: &str, _: &[&str]| Some("uv 0.12.20".to_owned());
        let absent = |_: &str, _: &[&str]| None;
        let read = |environment: &env::Process,
                    run: &(dyn Fn(&str, &[&str]) -> Option<String> + Sync)| {
            uv_indexes(&Machine {
                environment,
                dir: &root,
                run,
            })
        };

        let named = with(&[(env::UV_FILE, &file)]);
        assert_eq!(read(&named, &absent).unwrap(), None, "uv is not installed");
        assert_eq!(
            read(&named, &runs).unwrap().expect("uv runs").index,
            "https://file.example/simple/"
        );
        assert_eq!(
            read(&with(&[(env::UV_FILE, &missing)]), &runs)
                .unwrap()
                .expect("uv runs")
                .index,
            DEFAULT_INDEX
        );

        let cases: [(&[(Var, &str)], Var); 4] = [
            (&[(env::UV_NO_FILES, "1")], env::UV_DEFAULT),
            (&[], env::UV_FILE),
            (&[], env::CONFIG_HOME),
            (&[], env::HOME_DIR),
        ];
        for (pairs, unreadable) in cases {
            let error =
                read(&with_unreadable(pairs, unreadable), &runs).expect_err(unreadable.name);
            assert!(error.to_string().starts_with(unreadable.name), "{error}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
