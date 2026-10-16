//! cargo, as `byrle doctor` checks it, from its configuration files: cargo prints no
//! registry, and 1.99.0 ignored `CARGO_SOURCE_CRATES_IO_REPLACE_WITH`. With crates.io
//! replaced, it kept the replacement's `.crate` files in a directory of their own.

use std::path::{Path, PathBuf};

use crate::doctor::{CacheBypass, CacheLocation, Client, Indexes, Machine, RegistrySource};
use crate::env::{EnvError, Process};

use super::INDEX;

pub const CARGO: Client = Client {
    name: "cargo",
    version_args: &["version"],
    registry: Some(RegistrySource::Read {
        read: cargo_indexes,
        set_index: super::config_line,
        drop_extra: || "cargo asks one registry per source".to_owned(),
    }),
    set_registry: "",
    cache: CacheLocation::Configured {
        configured: cargo_cache,
        under_home: ".cargo/registry/cache",
    },
    bypass: CacheBypass::PerRegistry,
    clear_cache: "remove ~/.cargo/registry/cache",
    settings: None,
};

pub const CLIENTS: &[Client] = &[CARGO];

/// Where cargo keeps the `.crate` files it downloaded, a directory per registry.
fn cargo_cache(environment: &Process) -> Result<Option<PathBuf>, EnvError> {
    Ok(environment
        .cargo_home()?
        .map(|home| home.join("registry/cache")))
}

fn cargo_indexes(machine: &Machine) -> Result<Option<Indexes>, EnvError> {
    if (machine.run)("cargo", &["--version"]).is_none() {
        return Ok(None);
    }
    let home = match machine.environment.cargo_home()? {
        Some(home) => Some(home),
        None => machine.environment.home()?.map(|home| home.join(".cargo")),
    };
    let read: Vec<String> = config_files(machine.dir, home.as_deref())
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect();
    let texts: Vec<&str> = read.iter().map(String::as_str).collect();
    Ok(Some(cargo_config(&texts)))
}

/// The configuration files cargo reads, nearest first: `.cargo/config.toml`, or the older
/// `.cargo/config`, in `cwd` and each directory above it, then the one in `home`.
pub fn config_files(cwd: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = cwd
        .ancestors()
        .map(|dir| dir.join(".cargo"))
        .chain(home.map(Path::to_path_buf))
        .filter_map(|dir| {
            ["config.toml", "config"]
                .iter()
                .map(|name| dir.join(name))
                .find(|path| path.is_file())
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    files.retain(|path| seen.insert(path.clone()));
    files
}

/// The index cargo asks for crates.io's crates, from `files`, nearest first: the one the
/// replacing source names, else crates.io's own. A protocol prefix such as `sparse+` is
/// dropped. An empty index when the replacement names a source with none.
pub fn cargo_config(files: &[&str]) -> Indexes {
    let tables: Vec<toml::Table> = files.iter().filter_map(|text| text.parse().ok()).collect();
    let first = |path: &[&str]| -> Option<String> {
        tables.iter().find_map(|table| {
            let mut value = table.get(path[0])?;
            for key in &path[1..] {
                value = value.get(key)?;
            }
            value.as_str().map(str::to_owned)
        })
    };
    let index = match first(&["source", "crates-io", "replace-with"]) {
        None => format!("{INDEX}/"),
        Some(name) => first(&["registries", &name, "index"])
            .or_else(|| first(&["source", &name, "registry"]))
            .unwrap_or_default(),
    };
    let index = index
        .split_once('+')
        .filter(|(protocol, _)| ["sparse", "registry"].contains(protocol))
        .map_or(index.clone(), |(_, url)| url.to_owned());
    Indexes {
        index,
        extra: Vec::new(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const PROXY: &str = "[source.crates-io]\nreplace-with = \"byrle\"\n\
                         [registries.byrle]\nindex = \"sparse+http://127.0.0.1:8080/cargo/\"\n";

    #[test]
    fn the_replacing_registry_s_index_is_where_cargo_asks() {
        assert_eq!(cargo_config(&[PROXY]).index, "http://127.0.0.1:8080/cargo/");
        assert_eq!(cargo_config(&[]).index, "https://index.crates.io/");
        assert_eq!(
            cargo_config(&["not toml ["]).index,
            "https://index.crates.io/"
        );
    }

    /// The nearest file's replacement wins, and its source may be named in a farther file.
    #[test]
    fn the_nearest_file_names_the_replacement_and_any_file_its_index() {
        let project = "[source.crates-io]\nreplace-with = \"mirror\"\n";
        let home = "[source.mirror]\nregistry = \"https://mirror.example/index\"\n";
        assert_eq!(
            cargo_config(&[project, PROXY, home]).index,
            "https://mirror.example/index"
        );
        assert_eq!(cargo_config(&[project]).index, "", "a source with no index");
        let git = "[source.crates-io]\nreplace-with = \"g\"\n[source.g]\nregistry = \"git+https://g.example\"\n";
        assert_eq!(cargo_config(&[git]).index, "git+https://g.example");
    }

    #[test]
    fn config_files_are_read_nearest_first_with_home_last() {
        let root = crate::util::test_support::tempdir("cargo-config");
        let project = root.join("work/project");
        std::fs::create_dir_all(project.join(".cargo")).unwrap();
        std::fs::create_dir_all(root.join("work/.cargo")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::write(project.join(".cargo/config.toml"), "").unwrap();
        std::fs::write(root.join("work/.cargo/config"), "").unwrap();
        std::fs::write(root.join("home/config.toml"), "").unwrap();
        assert_eq!(
            config_files(&project, Some(&root.join("home"))),
            [
                project.join(".cargo/config.toml"),
                root.join("work/.cargo/config"),
                root.join("home/config.toml"),
            ]
        );
        assert_eq!(
            config_files(&project, Some(&project.join(".cargo"))),
            [
                project.join(".cargo/config.toml"),
                root.join("work/.cargo/config"),
            ],
            "home inside the project is read once"
        );
    }

    /// [`crate::env::CARGO_DIR`] holds the user's file and the cache, else `~/.cargo` does.
    #[test]
    fn cargo_home_is_where_the_user_s_file_and_the_cache_are() {
        let root = crate::util::test_support::tempdir("cargo-home");
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        for home in [root.join("cargo"), root.join("user/.cargo")] {
            std::fs::create_dir_all(&home).unwrap();
            std::fs::write(home.join("config.toml"), PROXY).unwrap();
        }
        let run = |_: &str, _: &[&str]| Some("cargo 1.99.0".to_owned());
        let cargo_home = root.join("cargo");
        let user = root.join("user");
        for (vars, cache) in [
            (
                vec![(crate::env::CARGO_DIR, cargo_home.to_str().unwrap())],
                Some(cargo_home.join("registry/cache")),
            ),
            (vec![(crate::env::HOME_DIR, user.to_str().unwrap())], None),
        ] {
            let environment = crate::env::testing::with(&vars);
            let machine = Machine {
                environment: &environment,
                dir: &work,
                run: &run,
            };
            assert_eq!(
                cargo_indexes(&machine).unwrap().unwrap().index,
                "http://127.0.0.1:8080/cargo/"
            );
            assert_eq!(cargo_cache(&environment).unwrap(), cache);
        }
    }

    /// A home that is not UTF-8 is an error, not a cargo pointed nowhere.
    #[test]
    fn an_unreadable_home_is_an_error() {
        use crate::env::testing::with_unreadable;
        let dir = crate::util::test_support::tempdir("cargo-unreadable");
        let run = |_: &str, _: &[&str]| Some("cargo 1.99.0".to_owned());
        for unreadable in [crate::env::CARGO_DIR, crate::env::HOME_DIR] {
            let environment = with_unreadable(&[], unreadable);
            let machine = Machine {
                environment: &environment,
                dir: &dir,
                run: &run,
            };
            assert!(cargo_indexes(&machine).is_err(), "{}", unreadable.name);
        }
        assert!(cargo_cache(&with_unreadable(&[], crate::env::CARGO_DIR)).is_err());
    }

    #[test]
    fn cargo_is_read_only_when_it_runs() {
        let environment = crate::env::testing::empty();
        let dir = crate::util::test_support::tempdir("cargo-doctor");
        let absent = Machine {
            environment: &environment,
            dir: &dir,
            run: &|_, _| None,
        };
        assert_eq!(cargo_indexes(&absent), Ok(None));
        let present = Machine {
            run: &|_, _| Some("cargo 1.99.0".to_owned()),
            ..absent
        };
        assert_eq!(
            cargo_indexes(&present).unwrap().map(|i| i.index),
            Some("https://index.crates.io/".to_owned())
        );
    }
}
