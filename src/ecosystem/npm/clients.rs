//! The package managers that install from an npm registry, as `waharoa doctor` checks them.

use crate::doctor::{CacheBypass, CacheLocation, Client};
use crate::env::Process;

/// npm, pnpm and yarn all read `registry` with `config get` and write it with `config set`.
const CONFIG_GET_REGISTRY: &[&str] = &["config", "get", "registry"];

/// What `bypass` is for each client was measured by installing the same package twice
/// through the proxy with one cache, and counting what the proxy saw the second time:
///
/// | Client | Second install |
/// |---|---|
/// | npm 11, pnpm 10, bun 1.3 | nothing reached the proxy |
/// | yarn 1, yarn 4 | the packument did, the artifact did not |
pub const CLIENTS: &[Client] = &[
    Client {
        name: "npm",
        registry: Some(CONFIG_GET_REGISTRY),
        set_registry: "npm config set registry",
        // npm's cache directory holds _cacache, and every cached response is one file
        // under its index.
        cache: CacheLocation::Asked {
            args: &["config", "get", "cache"],
            under: Some("_cacache/index-v5"),
        },
        bypass: CacheBypass::Complete,
        clear_cache: "npm cache clean --force",
    },
    Client {
        name: "pnpm",
        registry: Some(CONFIG_GET_REGISTRY),
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
        registry: Some(CONFIG_GET_REGISTRY),
        set_registry: "yarn config set registry",
        cache: CacheLocation::Asked {
            args: &["cache", "dir"],
            under: None,
        },
        bypass: CacheBypass::ArtifactsOnly,
        clear_cache: "yarn cache clean --force",
    },
    // `bun pm cache` needs a package.json in the working directory, which doctor cannot
    // assume, so bun's documented location is used. Its registry is not checked.
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
pub(crate) fn named(name: &str) -> &'static Client {
    CLIENTS
        .iter()
        .find(|client| client.name == name)
        .expect("npm's row lists this client")
}
