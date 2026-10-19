//! The binary's allocator, mimalloc: how soon it returns freed memory to the system. See
//! docs/engineering_decisions/0120-allocator-purge-delay.md.

use std::os::raw::c_long;

/// mimalloc v3's `mi_option_purge_delay`, which `libmimalloc-sys` names no constant for.
const PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

/// Return freed memory to the system `ms` milliseconds after it is freed, rather than when
/// the thread that freed it next allocates. Overrides `MIMALLOC_PURGE_DELAY`.
pub fn set_purge_delay(ms: usize) {
    let ms = c_long::try_from(ms).unwrap_or(c_long::MAX);
    unsafe { libmimalloc_sys::mi_option_set(PURGE_DELAY, ms) };
}

/// The purge delay mimalloc uses, in milliseconds.
pub fn purge_delay() -> c_long {
    unsafe { libmimalloc_sys::mi_option_get(PURGE_DELAY) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The variable mimalloc reads for its purge delay, which names the option at index 15.
    const MIMALLOC_PURGE_DELAY: &str = "MIMALLOC_PURGE_DELAY";

    /// Index 15 is the option `MIMALLOC_PURGE_DELAY` sets, read by a fresh process.
    #[test]
    fn option_15_is_the_purge_delay() {
        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "allocator::tests::reads_mimalloc_purge_delay",
                "--exact",
                "--ignored",
                "--quiet",
            ])
            .env(MIMALLOC_PURGE_DELAY, "7")
            .stdout(std::process::Stdio::null())
            .status()
            .expect("the test binary runs");
        assert!(status.success());
    }

    #[test]
    #[ignore = "run by option_15_is_the_purge_delay, with MIMALLOC_PURGE_DELAY set"]
    fn reads_mimalloc_purge_delay() {
        assert_eq!(purge_delay(), 7);
    }

    /// A delay set is the one mimalloc uses, and one past `c_long` is the largest.
    #[test]
    fn a_delay_set_is_used() {
        set_purge_delay(250);
        assert_eq!(purge_delay(), 250);
        set_purge_delay(usize::MAX);
        assert_eq!(purge_delay(), c_long::MAX);
        set_purge_delay(0);
        assert_eq!(purge_delay(), 0);
    }
}
