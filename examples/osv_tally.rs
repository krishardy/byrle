//! One-off: read OSV's npm bundle with `refresh::read_bundle` and print what a load would
//! store, without a database.
//!
//! Not a test, because it needs OSV's ~205MB npm bundle:
//!
//!   curl -sO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
//!
//! PyPI's is `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`.
//!
//! Run: cargo run --example osv_tally -- all.zip [npm|pypi]
use byrle::identity::Ecosystem;
use byrle::intel::providers::osv::bundle;

fn main() {
    // The rule below guards against trusting argv for security decisions. This is a
    // developer tool reading a file the developer just typed.
    // nosemgrep: rust.lang.security.args.args
    let path = std::env::args()
        .nth(1)
        .expect("usage: osv_tally <all.zip> [npm|pypi]");
    // nosemgrep: rust.lang.security.args.args
    let ecosystem: Ecosystem = std::env::args()
        .nth(2)
        .map_or(Ok(Ecosystem::Npm), |e| e.parse())
        .expect("npm or pypi");
    let bytes = std::fs::read(&path).expect("cannot read bundle");

    match bundle::read_bundle(ecosystem, &bytes) {
        Ok(bundle) => {
            print!("{}", bundle.tally);
            let affected: usize = bundle.rows.iter().map(|r| r.affected.len()).sum();
            println!("{:32} {:>8}", "affected rows", affected);
            let ranges: usize = bundle.rows.iter().map(|r| r.ranges.len()).sum();
            println!("{:32} {:>8}", "ranges", ranges);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
