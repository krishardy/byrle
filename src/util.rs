//! Helpers shared between modules.

pub mod lru;

/// `bytes` in lowercase hex, two digits each.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_support;
