//! One-off measurement: how many heap bytes a stored `PackageMetadata` holds, per document.
//!
//! A counting global allocator reports the bytes still allocated after a document is read,
//! normalised and its input dropped. Not a test, because it reads documents fetched from the
//! registries:
//!
//!   curl -s -H 'Accept: application/vnd.npm.install-v1+json' https://registry.npmjs.org/typescript -o npm-typescript.json
//!   curl -s -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/botocore/ -o pypi-botocore.json
//!
//! Run: cargo run --release --example record_memory -- npm-typescript.json pypi-botocore.json ...
//! A file named `npm-*` is read as an abbreviated packument, `pypi-*` as a PEP 691 index.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use byrle::ecosystem::{npm, pypi};
use byrle::record::{DocumentDetail, PackageMetadata};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is passed straight to `System`, which upholds the contract; the only
// addition is a counter.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn read(path: &str) -> PackageMetadata {
    let bytes = std::fs::read(path).expect("readable");
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name.starts_with("npm-") {
        npm::normalize_packument(&bytes, DocumentDetail::Abbreviated).expect("a packument")
    } else {
        pypi::normalize(&pypi::parse("", &bytes).expect("an index")).expect("normalises")
    }
}

fn main() {
    println!(
        "{:28} {:>10} {:>8} {:>10} {:>12} {:>10}",
        "document", "bytes", "records", "artifacts", "held bytes", "per record"
    );
    // nosemgrep: rust.lang.security.args.args
    for path in std::env::args().skip(1) {
        let size = std::fs::metadata(&path).map_or(0, |m| m.len());
        let before = LIVE.load(Ordering::Relaxed);
        let metadata = read(&path);
        let held = LIVE.load(Ordering::Relaxed) - before;
        let records = metadata.records.len();
        let artifacts: usize = metadata.records.iter().map(|r| r.artifacts.len()).sum();
        println!(
            "{:28} {:>10} {:>8} {:>10} {:>12} {:>10}",
            std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default(),
            size,
            records,
            artifacts,
            held,
            held as usize / records.max(1)
        );
        drop(metadata);
    }
}
