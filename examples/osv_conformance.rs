//! One-off conformance check: does `PackageKey` reproduce OSV's own purl for every
//! npm package OSV knows about?
//!
//! Not a unit test, because it needs OSV's ~205MB npm bundle. Regenerate the input with:
//!
//!   curl -sO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
//!   # then, per advisory, emit "<affected[].package.name>\t<affected[].package.purl>"
//!   # for entries whose ecosystem is npm
//!
//! Run: cargo run --example osv_conformance -- /path/to/osv_pairs.tsv
use waharoa::identity::{Ecosystem, PackageKey};

fn main() {
    // The rule below guards against trusting argv for security decisions, such as
    // deriving identity from argv[0]. This is a developer tool reading an input file
    // path the developer just typed, and nothing downstream is a trust decision.
    // nosemgrep: rust.lang.security.args.args
    let path = std::env::args().nth(1).expect("usage: osv_conformance <pairs.tsv>");
    let data = std::fs::read_to_string(&path).expect("cannot read pairs file");

    let (mut checked, mut mismatched, mut unparseable) = (0u64, 0u64, 0u64);
    let mut examples = Vec::new();

    for line in data.lines() {
        let Some((name, osv_purl)) = line.split_once('\t') else {
            continue;
        };
        checked += 1;
        // The invariant is NOT "we emit OSV's bytes": OSV is internally inconsistent,
        // writing scoped packages as both `%40scope/name` and `%40scope%2Fname`. What
        // must hold is that a key built from the registry name and a key parsed from
        // OSV's purl are the SAME key, so a lookup finds the record either way.
        match PackageKey::from_registry_name(Ecosystem::Npm, name) {
            Ok(from_name) => match osv_purl.parse::<PackageKey>() {
                Ok(from_purl) if from_purl == from_name => {}
                Ok(from_purl) => {
                    mismatched += 1;
                    if examples.len() < 15 {
                        examples.push(format!(
                            "  name={name:?}\n    osv purl={osv_purl}\n    from name={from_name}  from purl={from_purl}"
                        ));
                    }
                }
                Err(e) => {
                    unparseable += 1;
                    if examples.len() < 15 {
                        examples.push(format!("  osv purl {osv_purl:?} did not parse: {e}"));
                    }
                }
            },
            Err(e) => {
                unparseable += 1;
                if examples.len() < 15 {
                    examples.push(format!("  name={name:?} -> REJECTED: {e}"));
                }
            }
        }
    }

    println!("checked      : {checked:>8}");
    println!("mismatched   : {mismatched:>8}");
    println!("rejected     : {unparseable:>8}");
    if !examples.is_empty() {
        println!("\nfirst divergences:");
        for e in &examples {
            println!("{e}");
        }
    }
    if mismatched == 0 && unparseable == 0 {
        println!("\nPASS: registry name and OSV purl agree on the key for every npm package.");
    } else {
        std::process::exit(1);
    }
}
