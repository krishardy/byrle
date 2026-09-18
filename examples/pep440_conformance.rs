//! One-off conformance check: does `pypi::version::Version` read and order every version
//! OSV lists for PyPI as Python's `packaging` does?
//!
//! Not a unit test, because it needs OSV's PyPI bundle and `packaging`. Regenerate the input
//! with:
//!
//!   curl -sO https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
//!   # then, with packaging installed, emit one line per distinct version written in an
//!   # `affected[].versions` list or an ECOSYSTEM range event:
//!   #   "<written>\t<str(Version(written)) or INVALID>\t<rank among distinct versions or -1>"
//!   # where equal versions share a rank.
//!
//! Run: cargo run --example pep440_conformance -- /path/to/pep440_expected.tsv
use waharoa::ecosystem::pypi::version::Version;

fn main() {
    // The rule below guards against trusting argv for security decisions. This is a
    // developer tool reading an input file path the developer just typed, and nothing
    // downstream is a trust decision.
    // nosemgrep: rust.lang.security.args.args
    let path = std::env::args()
        .nth(1)
        .expect("usage: pep440_conformance <expected.tsv>");
    let data = std::fs::read_to_string(&path).expect("cannot read the expected file");

    let (mut checked, mut misread) = (0u64, 0u64);
    let mut examples = Vec::new();
    let mut ranked: Vec<(i64, Version, String)> = Vec::new();
    for line in data.lines() {
        let mut fields = line.split('\t');
        let (Some(written), Some(expected), Some(rank)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        checked += 1;
        let read = Version::parse(written);
        let got = read
            .as_ref()
            .map_or_else(|| "INVALID".to_owned(), Version::to_string);
        if got != expected {
            misread += 1;
            if examples.len() < 15 {
                examples.push(format!("{written:?}: packaging {expected}, this {got}"));
            }
        }
        if let (Some(version), Ok(rank)) = (read, rank.parse::<i64>())
            && rank >= 0
        {
            ranked.push((rank, version, written.to_owned()));
        }
    }

    // Sorted by packaging's rank, each version must order at or above the one before it,
    // and equal exactly when the ranks are equal.
    ranked.sort_by_key(|(rank, _, _)| *rank);
    let mut misordered = 0u64;
    for pair in ranked.windows(2) {
        let ((a_rank, a, a_written), (b_rank, b, b_written)) = (&pair[0], &pair[1]);
        let expected = a_rank.cmp(b_rank);
        if a.cmp(b) != expected {
            misordered += 1;
            if examples.len() < 30 {
                examples.push(format!(
                    "{a_written:?} and {b_written:?}: packaging {expected:?}, this {:?}",
                    a.cmp(b)
                ));
            }
        }
    }

    println!("versions checked:   {checked}");
    println!("read differently:   {misread}");
    println!("ordered, adjacent:  {}", ranked.len().saturating_sub(1));
    println!("ordered differently: {misordered}");
    for example in &examples {
        println!("  {example}");
    }
    if misread + misordered > 0 {
        std::process::exit(1);
    }
}
