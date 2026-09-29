//! Where advisories come from: one module per provider, each reading that provider's bundle
//! into [`crate::intel::rows::Rows`] or exploited CVE ids. [`crate::intel::stream`] names the
//! stream each one reads.

pub mod datadog;
pub mod github;
pub mod kev;
pub mod osv;
