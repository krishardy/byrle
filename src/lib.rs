//! waharoa: a dependency firewall.
//!
//! The binary in `main.rs` is the proxy; this library holds the pieces that are
//! meaningful on their own and testable without a network, starting with package
//! identity. Splitting into separate *crates* remains deliberately deferred (TODO.md);
//! a lib plus a bin in one crate is not that split.

pub mod audit;
pub mod cli;
/// Debug builds only: see the module docs.
#[cfg(debug_assertions)]
pub mod defer;
pub mod doctor;
pub mod ecosystem;
pub mod env;
pub mod explain;
#[cfg(test)]
mod golden;
pub mod http;
pub mod identity;
pub mod integrity;
pub mod intel;
pub mod lockfile;
pub mod origin;
pub mod policy;
pub mod proxy;
pub mod record;
pub mod refusal;
pub mod route;
pub mod startup;
pub mod store;
#[cfg(test)]
mod test_support;
pub mod tls;
pub mod verified;
