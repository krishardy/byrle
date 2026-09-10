mod schema;
use schema::Policy;
use std::fs;

fn banner(t: &str) {
    println!("\n{}\n=== {} ===", "=".repeat(78), t);
}

fn show(loader: &str, file: &str, r: Result<Policy, String>) {
    match r {
        Ok(p) => println!(
            "  [{loader:<13}] {file:<26} OK   ({} denials, {} floors, {} eco, {} pkgs)",
            p.denials.len(),
            p.floor.len(),
            p.ecosystems.len(),
            p.packages.len()
        ),
        Err(e) => {
            let e = e.trim_end();
            println!("  [{loader:<13}] {file:<26} ERR");
            for line in e.lines() {
                println!("       | {line}");
            }
        }
    }
}

fn yaml_loaders(file: &str, src: &str) {
    show(
        "serde-saphyr",
        file,
        serde_saphyr::from_str::<Policy>(src).map_err(|e| e.to_string()),
    );
    show(
        "serde_norway",
        file,
        serde_norway::from_str::<Policy>(src).map_err(|e| e.to_string()),
    );
    show(
        "serde_yaml_ng",
        file,
        serde_yaml_ng::from_str::<Policy>(src).map_err(|e| e.to_string()),
    );
}

fn toml_loader(file: &str, src: &str) {
    show(
        "toml",
        file,
        toml::from_str::<Policy>(src).map_err(|e| e.to_string()),
    );
}

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/policies");
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    // Good files first, then the malformed variants.
    files.sort_by_key(|f| f.starts_with("bad_"));

    for f in files {
        let src = fs::read_to_string(format!("{dir}/{f}")).unwrap();
        banner(&f);
        if f.ends_with(".yaml") {
            yaml_loaders(&f, &src);
        } else {
            toml_loader(&f, &src);
        }
    }
}
