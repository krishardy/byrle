//! The digests a Maven repository publishes beside a file: `.sha512`, `.sha256`, `.sha1` and
//! `.md5`, each its file's digest as hex. A claim is the strongest one published, written
//! `<algorithm>:<hex>` ([maven-digests](../../../docs/engineering_decisions/0112-maven-digests.md)).

use std::io::Read;

use aws_lc_rs::digest::{self, Algorithm, Context};

/// The sidecars a claim is read from, strongest first, and how each digests a file.
pub const CLAIMED: [Sidecar; 3] = [
    Sidecar {
        suffix: ".sha512",
        name: "sha512",
        hex_len: 128,
        file: sha512_file,
        bytes: sha512_claim,
    },
    Sidecar {
        suffix: ".sha256",
        name: "sha256",
        hex_len: 64,
        file: sha256_file,
        bytes: sha256_claim,
    },
    Sidecar {
        suffix: ".sha1",
        name: "sha1",
        hex_len: 40,
        file: sha1_file,
        bytes: sha1_claim,
    },
];

/// One kind of sidecar: its suffix, the claim's prefix, and its digest of a file and of bytes.
#[derive(Debug, Clone, Copy)]
pub struct Sidecar {
    pub suffix: &'static str,
    pub name: &'static str,
    pub hex_len: usize,
    pub file: fn(std::fs::File) -> Result<String, String>,
    pub bytes: fn(&[u8]) -> String,
}

impl Sidecar {
    /// The claim a sidecar's `text` makes: its first word of hex this long, lower-cased, as
    /// `<name>:<hex>`. `None` when no word is.
    pub fn claim(&self, text: &str) -> Option<String> {
        let word = text.split_whitespace().next()?.to_ascii_lowercase();
        let is_hex = word.bytes().all(|b| b.is_ascii_hexdigit());
        (word.len() == self.hex_len && is_hex).then(|| format!("{}:{word}", self.name))
    }
}

/// `bytes`' SHA-1 as hex, as a `.sha1` holds it.
pub fn sha1(bytes: &[u8]) -> String {
    crate::util::hex(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, bytes).as_ref())
}

/// `bytes`' MD5 as hex, as a `.md5` holds it.
pub fn md5(bytes: &[u8]) -> String {
    use md5::Digest as _;
    crate::util::hex(&md5::Md5::digest(bytes))
}

fn sha512_claim(bytes: &[u8]) -> String {
    claim_of(&digest::SHA512, "sha512", bytes)
}

fn sha256_claim(bytes: &[u8]) -> String {
    claim_of(&digest::SHA256, "sha256", bytes)
}

fn sha1_claim(bytes: &[u8]) -> String {
    claim_of(&digest::SHA1_FOR_LEGACY_USE_ONLY, "sha1", bytes)
}

fn sha512_file(mut file: std::fs::File) -> Result<String, String> {
    file_claim(&digest::SHA512, "sha512", &mut file)
}

fn sha256_file(mut file: std::fs::File) -> Result<String, String> {
    file_claim(&digest::SHA256, "sha256", &mut file)
}

fn sha1_file(mut file: std::fs::File) -> Result<String, String> {
    file_claim(&digest::SHA1_FOR_LEGACY_USE_ONLY, "sha1", &mut file)
}

/// `bytes`' digest by `algorithm` as a claim named `name`.
fn claim_of(algorithm: &'static Algorithm, name: &str, bytes: &[u8]) -> String {
    format!(
        "{name}:{}",
        crate::util::hex(digest::digest(algorithm, bytes).as_ref())
    )
}

/// What `read` holds, digested by `algorithm` as it is read, as a claim named `name`.
/// Errors when it cannot be read.
fn file_claim(
    algorithm: &'static Algorithm,
    name: &str,
    read: &mut dyn Read,
) -> Result<String, String> {
    let mut context = Context::new(algorithm);
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        match read.read(&mut buffer).map_err(|e| e.to_string())? {
            0 => break,
            n => context.update(&buffer[..n]),
        }
    }
    Ok(format!(
        "{name}:{}",
        crate::util::hex(context.finish().as_ref())
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// FIPS 180's `abc`, in each algorithm, from bytes and from a file.
    #[test]
    fn each_sidecar_digests_bytes_and_a_file_alike() {
        let expected = [
            "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha1:a9993e364706816aba3e25717850c26c9cd0d89d",
        ];
        let dir = std::env::temp_dir().join(format!("byrle-maven-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc");
        std::fs::write(&path, b"abc").unwrap();
        for (sidecar, expected) in CLAIMED.iter().zip(expected) {
            assert_eq!((sidecar.bytes)(b"abc"), expected, "{}", sidecar.name);
            let file = std::fs::File::open(&path).unwrap();
            assert_eq!((sidecar.file)(file).unwrap(), expected, "{}", sidecar.name);
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    /// A `.sha1` on Central holds the hex alone, or the hex and the file's name.
    #[test]
    fn a_sidecar_claims_its_first_word_of_hex() {
        let sha1 = &CLAIMED[2];
        for text in [
            "A9993E364706816ABA3E25717850C26C9CD0D89D",
            "a9993e364706816aba3e25717850c26c9cd0d89d  commons-lang3-3.17.0.jar\n",
        ] {
            assert_eq!(
                sha1.claim(text).as_deref(),
                Some("sha1:a9993e364706816aba3e25717850c26c9cd0d89d"),
                "{text}"
            );
        }
        for not in [
            "",
            "a9993e36",
            "z9993e364706816aba3e25717850c26c9cd0d89d",
            "<html>",
        ] {
            assert_eq!(sha1.claim(not), None, "{not}");
        }
    }

    /// A read that fails is no digest.
    #[test]
    fn a_file_that_cannot_be_read_has_no_digest() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("unreadable"))
            }
        }
        assert_eq!(
            file_claim(&digest::SHA256, "sha256", &mut Broken),
            Err("unreadable".to_owned())
        );
    }
}
