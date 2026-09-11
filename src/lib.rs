//! waharoa: a dependency firewall.
//!
//! The binary in `main.rs` is the proxy; this library holds the pieces that are
//! meaningful on their own and testable without a network, starting with package
//! identity. Splitting into separate *crates* remains deliberately deferred (TODO.md);
//! a lib plus a bin in one crate is not that split.

pub mod identity;
