#![allow(dead_code)]
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SBool { v: bool }
#[derive(Debug, Deserialize)]
struct SStr { v: String }

fn tri<T: std::fmt::Debug>(label: &str, r: Result<T, impl std::fmt::Display>) {
    match r {
        Ok(v) => println!("    {label:<14} OK  {v:?}"),
        Err(e) => println!("    {label:<14} ERR {}", e.to_string().lines().next().unwrap_or("")),
    }
}

fn main() {
    println!("== 1. Norway: how does each parser resolve the bare token `no`? ==");
    for (ty, src) in [("target=bool", "v: no"), ("target=String", "v: no")] {
        println!("  {ty}:  `{src}`");
        if ty.contains("bool") {
            tri("serde-saphyr", serde_saphyr::from_str::<SBool>(src));
            tri("serde_norway", serde_norway::from_str::<SBool>(src));
            tri("serde_yaml_ng", serde_yaml_ng::from_str::<SBool>(src));
        } else {
            tri("serde-saphyr", serde_saphyr::from_str::<SStr>(src));
            tri("serde_norway", serde_norway::from_str::<SStr>(src));
            tri("serde_yaml_ng", serde_yaml_ng::from_str::<SStr>(src));
        }
    }

    println!("\n== 2. Billion laughs: do aliases expand unbounded? ==");
    let bomb = {
        let mut s = String::from("a: &a [x,x,x,x,x,x,x,x,x]\n");
        for c in ["b", "c", "d", "e", "f", "g", "h"] {
            let p = (c.as_bytes()[0] - 1) as char;
            s.push_str(&format!(
                "{c}: &{c} [*{p},*{p},*{p},*{p},*{p},*{p},*{p},*{p},*{p}]\n"
            ));
        }
        s.push_str("v: \"done\"\n");
        s
    };
    println!("  payload is {} bytes, expands to 9^8 = {} leaves", bomb.len(), 9u64.pow(8));
    let t = std::time::Instant::now();
    tri("serde-saphyr", serde_saphyr::from_str::<SStr>(&bomb));
    println!("      (serde-saphyr default took {:?})", t.elapsed());
    let t = std::time::Instant::now();
    tri("serde_norway", serde_norway::from_str::<SStr>(&bomb));
    println!("      (serde_norway took {:?})", t.elapsed());
}
