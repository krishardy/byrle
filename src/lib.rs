//! waharoa: a dependency firewall. The binary is in `main.rs`, and every command it runs is
//! here, where it can be tested without a network.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod analysis;
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod golden;
pub mod http;
pub mod identity;
pub mod integrity;
pub mod intel;
pub mod lockfile;
pub mod logging;
pub mod origin;
pub mod policy;
pub mod proxy;
pub mod record;
pub mod refusal;
pub mod route;
pub mod signal;
pub mod spool;
pub mod startup;
pub mod status;
pub mod store;
pub mod tls;
mod util;
pub mod verified;
pub mod warm;
