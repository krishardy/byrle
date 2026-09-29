//! The package managers that install from an npm registry, as `waharoa doctor` checks them.

use crate::doctor::{CacheBypass, CacheLocation, Client, RegistryQuery, RegistrySource};
use crate::env::Process;

/// How npm, pnpm and yarn print their registry: `config get`, `undefined` for no value.
const CONFIG_GET_REGISTRY: RegistryQuery = RegistryQuery {
    args: &["config", "get", "registry"],
    unset: "undefined",
};

/// npm itself. The startup log's setup line for npm reads this row.
pub const NPM: Client = Client {
    name: "npm",
    registry: Some(RegistrySource::Asked(CONFIG_GET_REGISTRY)),
    set_registry: "npm config set registry",
    cache: CacheLocation::Asked {
        args: &["config", "get", "cache"],
        under: Some("_cacache/index-v5"),
    },
    bypass: CacheBypass::Complete,
    clear_cache: "npm cache clean --force",
};

/// The npm clients doctor checks. See docs/engineering_decisions/client-caches.md.
pub const CLIENTS: &[Client] = &[
    NPM,
    Client {
        name: "pnpm",
        registry: Some(RegistrySource::Asked(CONFIG_GET_REGISTRY)),
        set_registry: "pnpm config set registry",
        cache: CacheLocation::Asked {
            args: &["store", "path"],
            under: None,
        },
        bypass: CacheBypass::Complete,
        clear_cache: "pnpm store prune, or delete the store directory",
    },
    Client {
        name: "yarn",
        registry: Some(RegistrySource::Asked(CONFIG_GET_REGISTRY)),
        set_registry: "yarn config set registry",
        cache: CacheLocation::Asked {
            args: &["cache", "dir"],
            under: None,
        },
        bypass: CacheBypass::ArtifactsOnly,
        clear_cache: "yarn cache clean --force",
    },
    Client {
        name: "bun",
        registry: None,
        set_registry: "",
        cache: CacheLocation::Configured {
            configured: Process::bun_install_cache_dir,
            under_home: ".bun/install/cache",
        },
        bypass: CacheBypass::Complete,
        clear_cache: "bun pm cache rm",
    },
];

/// The client called `name`. Test use only.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn named(name: &str) -> &'static Client {
    CLIENTS
        .iter()
        .find(|client| client.name == name)
        .expect("npm's row lists this client")
}
