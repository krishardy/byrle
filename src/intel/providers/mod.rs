//! Where advisories come from: one module per provider, each reading that provider's bundle
//! into [`crate::intel::rows::Rows`] or exploited CVE ids.
//!
//! | Module | Provider | Stream |
//! |---|---|---|
//! | `osv` | OSV, with `bundle.rs` reading its zip | `osv/npm` |
//! | `datadog` | Datadog's malicious software packages dataset | `datadog/npm` |
//! | `github` | GitHub's Advisory Database, through GraphQL | `github/npm` |
//! | `kev` | CISA's Known Exploited Vulnerabilities catalogue | `cisa/kev` |
//!
//! `crate::intel::stream` declares each stream and which provider parses it.

pub mod datadog;
pub mod github;
pub mod kev;
pub mod osv;
