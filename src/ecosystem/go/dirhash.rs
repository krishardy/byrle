//! `h1:`, the hash sum.golang.org publishes for a module zip and for its `go.mod`, as
//! `golang.org/x/mod/sumdb/dirhash.Hash1` computes it: a sha256 over one line per file,
//! `<hex sha256 of the file>  <name>\n`, in byte order of the names.

use std::io::{Read, Seek};

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// The prefix of every hash this module computes.
pub const PREFIX: &str = "h1:";

/// The `h1:` of `files`, each a name and its contents. Errors when a name holds a newline,
/// which would forge a line of another file.
fn hash1<'a>(files: impl IntoIterator<Item = (String, &'a [u8])>) -> Result<String, String> {
    let mut lines: Vec<(String, String)> = Vec::new();
    for (name, contents) in files {
        if name.contains('\n') {
            return Err(format!("a file name holds a newline: {name:?}"));
        }
        lines.push((name, crate::util::hex(&Sha256::digest(contents))));
    }
    lines.sort();
    let mut summary = Sha256::new();
    for (name, digest) in &lines {
        summary.update(format!("{digest}  {name}\n"));
    }
    Ok(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(summary.finalize())
    ))
}

/// The `h1:` of a module zip, every file under the bytes of the name the zip gives it, as
/// `dirhash.HashZip` computes it. Errors when the zip cannot be read, or a name is not UTF-8.
pub fn zip_h1<R: Read + Seek>(zip: R) -> Result<String, String> {
    let mut archive = zip::ZipArchive::new(zip).map_err(|e| format!("not a zip: {e}"))?;
    let mut files = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|e| format!("zip entry {index}: {e}"))?;
        let name = std::str::from_utf8(file.name_raw())
            .map_err(|e| format!("zip entry {index}'s name is not UTF-8: {e}"))?
            .to_owned();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| format!("{name}: {e}"))?;
        files.push((name, contents));
    }
    hash1(
        files
            .iter()
            .map(|(name, contents)| (name.clone(), contents.as_slice())),
    )
}

/// The `h1:` of a module's `go.mod`, the one file `go.mod`.
pub fn go_mod_h1(go_mod: &[u8]) -> String {
    hash1([("go.mod".to_owned(), go_mod)]).expect("`go.mod` holds no newline")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/go/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("a fixture")
    }

    /// sum.golang.org's lines for rsc.io/quote v1.5.2 on 2026-10-15.
    #[test]
    fn the_hashes_are_the_ones_sum_golang_org_publishes() {
        let zip = fixture("rsc.io-quote-v1.5.2.zip");
        assert_eq!(
            zip_h1(std::io::Cursor::new(zip)).unwrap(),
            "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="
        );
        assert_eq!(
            go_mod_h1(&fixture("rsc.io-quote-v1.5.2.mod")),
            "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0="
        );
    }

    /// A changed file, or files listed in another order, are each a different or the same
    /// hash as dirhash says: the order of the zip does not matter, its contents do.
    #[test]
    fn the_hash_is_over_sorted_names_and_their_contents() {
        let a = |files: &[(&str, &[u8])]| {
            hash1(files.iter().map(|(n, c)| ((*n).to_owned(), *c))).unwrap()
        };
        assert_eq!(
            a(&[("b", b"2"), ("a", b"1")]),
            a(&[("a", b"1"), ("b", b"2")])
        );
        assert_ne!(
            a(&[("a", b"1"), ("b", b"2")]),
            a(&[("a", b"1"), ("b", b"3")])
        );
        assert!(hash1([("a\nb".to_owned(), b"x".as_slice())]).is_err());
    }

    #[test]
    fn a_zip_that_cannot_be_read_is_an_error() {
        assert!(zip_h1(std::io::Cursor::new(b"not a zip".to_vec())).is_err());
        let truncated = fixture("rsc.io-quote-v1.5.2.zip");
        let corrupt: Vec<u8> = truncated
            .iter()
            .enumerate()
            .map(|(i, b)| if (40..400).contains(&i) { 0 } else { *b })
            .collect();
        assert!(zip_h1(std::io::Cursor::new(corrupt)).is_err());
        let mut no_header = truncated.clone();
        no_header[..4].copy_from_slice(&[0; 4]);
        assert!(zip_h1(std::io::Cursor::new(no_header)).is_err());
        let named = crate::util::test_support::zip_of(&[("x.txt", b"y")]);
        let mut not_utf8 = named.clone();
        for at in 0..not_utf8.len() - 4 {
            if &not_utf8[at..at + 5] == b"x.txt" {
                not_utf8[at] = 0xff;
            }
        }
        assert!(zip_h1(std::io::Cursor::new(named)).is_ok());
        let error = zip_h1(std::io::Cursor::new(not_utf8)).unwrap_err();
        assert!(error.contains("name"), "{error}");
    }
}
