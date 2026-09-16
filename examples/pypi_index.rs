//! Read a real PyPI simple index and report what this build makes of it.
//!
//! `cargo run --example pypi_index -- requests flask ...`
//! Live, so it is not part of the test suite. It exists to check the parser against real
//! documents at a scale fixtures cannot reach.
fn main() {
    let names: Vec<String> = std::env::args().skip(1).collect();
    let names = if names.is_empty() {
        vec!["requests".to_owned()]
    } else {
        names
    };
    let client = std::process::Command::new("curl");
    drop(client);
    println!(
        "{:22} {:>6} {:>6} {:>7} {:>7} {:>7} {:>8}",
        "project", "files", "vers", "skipped", "wheels", "sdists", "yanked"
    );
    for name in names {
        let url = match waharoa::pypi::index_url(waharoa::pypi::INDEX, &name) {
            Ok(url) => url,
            Err(e) => {
                eprintln!("{name}: {e}");
                continue;
            }
        };
        let out = std::process::Command::new("curl")
            .args([
                "-sSL",
                "-H",
                &format!("Accept: {}", waharoa::pypi::SIMPLE_JSON),
                &url,
            ])
            .output()
            .expect("curl runs");
        let listed: usize = serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .ok()
            .and_then(|v| Some(v.get("files")?.as_array()?.len()))
            .unwrap_or(0);
        match waharoa::pypi::parse(&name, &out.stdout) {
            Ok(project) => {
                let wheels = project
                    .files
                    .iter()
                    .filter(|f| f.kind == waharoa::pypi::Kind::Wheel)
                    .count();
                let yanked = project.files.iter().filter(|f| f.yanked).count();
                println!(
                    "{:22} {:>6} {:>6} {:>7} {:>7} {:>7} {:>8}",
                    project.name,
                    listed,
                    project.versions().len(),
                    listed - project.files.len(),
                    wheels,
                    project.files.len() - wheels,
                    yanked
                );
            }
            Err(e) => eprintln!("{name}: {e}"),
        }
    }
}
