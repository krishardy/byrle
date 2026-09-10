#![allow(dead_code)]
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Instant;

/// Our own recursive value type, so every parser is asked to materialize the
/// same thing. serde-saphyr ships no `Value` (it has no intermediate document
/// model at all, which is itself part of the security argument).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnyVal {
    Str(String),
    Seq(Vec<AnyVal>),
    Map(BTreeMap<String, AnyVal>),
}
type Doc = BTreeMap<String, AnyVal>;

fn bomb(levels: usize, fan: usize) -> String {
    let mut s = format!("a: &a [{}]\n", vec!["x"; fan].join(","));
    let names: Vec<char> = ('a'..='z').take(levels + 1).collect();
    for w in names.windows(2) {
        let (p, c) = (w[0], w[1]);
        let refs = vec![format!("*{p}"); fan].join(",");
        s.push_str(&format!("{c}: &{c} [{refs}]\n"));
    }
    s
}

fn main() {
    // Deserialize into the crate's own Value type: forces FULL materialization,
    // which is what a lazy struct-directed deserializer would otherwise skip.
    for (levels, fan) in [(6usize, 9usize), (8, 9)] {
        let src = bomb(levels, fan);
        let leaves = (fan as u64).pow(levels as u32 + 1);
        println!(
            "\n== {} bytes, {} levels x fan {} => {} leaves ==",
            src.len(),
            levels,
            fan,
            leaves
        );

        let t = Instant::now();
        let r = serde_saphyr::from_str::<Doc>(&src);
        println!(
            "  serde-saphyr  {:<9} {:?}",
            if r.is_ok() { "PARSED" } else { "REFUSED" },
            t.elapsed()
        );
        if let Err(e) = &r {
            println!("     {}", e.to_string().lines().next().unwrap_or(""));
        }

        let t = Instant::now();
        let r = serde_norway::from_str::<Doc>(&src);
        println!(
            "  serde_norway  {:<9} {:?}",
            if r.is_ok() { "PARSED" } else { "REFUSED" },
            t.elapsed()
        );
        if let Err(e) = &r {
            println!("     {}", e.to_string().lines().next().unwrap_or(""));
        }

        let t = Instant::now();
        let r = serde_yaml_ng::from_str::<Doc>(&src);
        println!(
            "  serde_yaml_ng {:<9} {:?}",
            if r.is_ok() { "PARSED" } else { "REFUSED" },
            t.elapsed()
        );
        if let Err(e) = &r {
            println!("     {}", e.to_string().lines().next().unwrap_or(""));
        }
    }
}
