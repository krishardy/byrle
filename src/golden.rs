//! Golden files: output compared against a committed copy under `tests/fixtures/`.
//!
//! With [`crate::env::BLESS`] set, the copy is rewritten first, and the diff is what to review.

/// Assert `actual` equals `tests/fixtures/<dir>/<name>`.
pub fn assert_matches(dir: &str, name: &str, actual: &str) {
    let path = format!("{}/tests/fixtures/{dir}/{name}", env!("CARGO_MANIFEST_DIR"));
    if crate::env::process().bless() {
        std::fs::write(&path, actual).expect("golden file should write");
    }
    let expected = std::fs::read_to_string(&path).expect("golden file should exist");
    assert!(
        expected == actual,
        "{dir}/{name} differs. Rerun with {}=1 and review the diff:\n{actual}",
        crate::env::BLESS
    );
}
