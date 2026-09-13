//! One-off: read OSV's npm bundle with `refresh::read_bundle` and print what a load would
//! store, without a database.
//!
//! Not a test, because it needs OSV's ~205MB npm bundle:
//!
//!   curl -sO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
//!
//! Run: cargo run --example osv_tally -- all.zip
use waharoa::intel::refresh;

fn main() {
    // The rule below guards against trusting argv for security decisions. This is a
    // developer tool reading a file the developer just typed.
    // nosemgrep: rust.lang.security.args.args
    let path = std::env::args().nth(1).expect("usage: osv_tally <all.zip>");
    let bytes = std::fs::read(&path).expect("cannot read bundle");

    match refresh::read_bundle(&bytes) {
        Ok(bundle) => {
            print!("{}", bundle.tally);
            let affected: usize = bundle.rows.iter().map(|r| r.affected.len()).sum();
            println!("{:32} {:>8}", "affected rows", affected);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
