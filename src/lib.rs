//! waharoa: a dependency firewall.
//!
//! The binary in `main.rs` is the proxy; this library holds the pieces that are
//! meaningful on their own and testable without a network, starting with package
//! identity. Splitting into separate *crates* remains deliberately deferred (TODO.md);
//! a lib plus a bin in one crate is not that split.

/// Debug builds only: see the module docs.
#[cfg(debug_assertions)]
pub mod audit;
pub mod cli;
pub mod defer;
pub mod doctor;
pub mod explain;
pub mod http;
pub mod identity;
pub mod intel;
pub mod integrity;
pub mod npm;
pub mod policy;
pub mod proxy;
pub mod record;
pub mod refusal;
pub mod store;
pub mod tls;
pub mod verified;
