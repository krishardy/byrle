//! Fetch real PyPI indexes through `pypi::Client` and report what this build makes of them.
//!
//! `cargo run --example pypi_index -- requests flask ...`
//! Live, so it is not part of the test suite. It checks the transport and the parse
//! against real documents at a scale fixtures cannot reach.
#[tokio::main]
async fn main() {
    let names: Vec<String> = std::env::args().skip(1).collect();
    let names = if names.is_empty() {
        vec!["requests".to_owned()]
    } else {
        names
    };
    let http = reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("a client");
    let client = waharoa::pypi::Client::new(http, waharoa::pypi::INDEX);

    println!(
        "{:22} {:>6} {:>7} {:>7} {:>7} {:>8} {:>9}",
        "project", "vers", "records", "wheels", "sdists", "yanked", "sdist-only"
    );
    for name in names {
        match client.project(&name).await {
            Ok(project) => {
                let records = match waharoa::pypi::records(&project) {
                    Ok(records) => records,
                    Err(e) => {
                        eprintln!("{name}: {e}");
                        continue;
                    }
                };
                let wheels = project
                    .files
                    .iter()
                    .filter(|f| f.kind == waharoa::pypi::Kind::Wheel)
                    .count();
                println!(
                    "{:22} {:>6} {:>7} {:>7} {:>7} {:>8} {:>9}",
                    project.name,
                    project.versions().len(),
                    records.len(),
                    wheels,
                    project.files.len() - wheels,
                    project.files.iter().filter(|f| f.yanked).count(),
                    records.iter().filter(|r| r.has_install_scripts).count(),
                );
            }
            Err(e) => eprintln!("{name}: {e}"),
        }
    }
}
