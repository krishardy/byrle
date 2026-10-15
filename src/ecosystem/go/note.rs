//! A signed note, as `golang.org/x/mod/sumdb/note` writes it: text, a blank line, and one
//! line per signature. sum.golang.org signs its tree heads with Ed25519.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::tlog::Hash;

/// sum.golang.org's key, as go 1.27.2 embeds it in `cmd/go/internal/modfetch/key.go`.
pub const SUM_GOLANG_ORG: &str =
    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

/// The first word of a signature line: an em dash, which the format requires.
const SIGNATURE: &str = "\u{2014} ";

/// The algorithm byte of an Ed25519 key.
const ED25519: u8 = 1;

/// The first line of a tree head's text.
const TREE: &str = "go.sum database tree\n";

/// A key a note's signature is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    name: String,
    hash: [u8; 4],
    public: [u8; 32],
}

impl Verifier {
    /// The key written as `<name>+<hash>+<key>`, as [`SUM_GOLANG_ORG`] is. Errors when it is
    /// not one, its key is not Ed25519, or its hash is not its own.
    pub fn parse(key: &str) -> Result<Self, String> {
        let mut parts = key.splitn(3, '+');
        let (Some(name), Some(hash), Some(encoded)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("`{key}` is not <name>+<hash>+<key>"));
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("the key of `{key}`: {e}"))?;
        let (&[ED25519], Ok(public)) = (&decoded[..decoded.len().min(1)], decoded[1..].try_into())
        else {
            return Err(format!("`{key}` is not an Ed25519 key"));
        };
        let verifier = Self {
            name: name.to_owned(),
            hash: key_hash(name, &decoded),
            public,
        };
        if crate::util::hex(&verifier.hash) != hash {
            return Err(format!("`{key}`'s hash is not its key's"));
        }
        Ok(verifier)
    }

    /// The text of `note` when one of its signatures is this key's and verifies. Errors
    /// with why not.
    pub fn open<'a>(&self, note: &'a str) -> Result<&'a str, String> {
        let Some((text, signatures)) = note.split_once("\n\n") else {
            return Err("the note has no signature".to_owned());
        };
        let text = &note[..text.len() + 1];
        let prefix = format!("{SIGNATURE}{} ", self.name);
        for line in signatures.lines() {
            let Some(encoded) = line.strip_prefix(&prefix) else {
                continue;
            };
            let signed = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| format!("a signature by {}: {e}", self.name))?;
            if signed.len() != 68 || signed[..4] != self.hash {
                continue;
            }
            let key = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ED25519,
                &self.public,
            );
            return match key.verify(text.as_bytes(), &signed[4..]) {
                Ok(()) => Ok(text),
                Err(_) => Err(format!("{}'s signature does not verify", self.name)),
            };
        }
        Err(format!("the note has no signature by {}", self.name))
    }
}

/// The first four bytes of the SHA-256 of the name, a newline and the key.
fn key_hash(name: &str, key: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update(key);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// A tree head: how many records the log holds, and its root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tree {
    pub size: u64,
    pub root: Hash,
}

impl Tree {
    /// The tree a note's verified text names. Errors when it names none.
    pub fn parse(text: &str) -> Result<Self, String> {
        let not = || format!("not a tree head: {text:?}");
        let rest = text.strip_prefix(TREE).ok_or_else(not)?;
        let mut lines = rest.lines();
        let size = lines.next().and_then(|n| n.parse().ok()).ok_or_else(not)?;
        let root = lines
            .next()
            .and_then(|r| base64::engine::general_purpose::STANDARD.decode(r).ok())
            .and_then(|r| r.try_into().ok())
            .ok_or_else(not)?;
        Ok(Self { size, root })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// sum.golang.org's tree head of 2026-10-15, signed.
    const SIGNED: &str = "go.sum database tree\n69104914\n\
                          1i5okhA0SJfHFAlniAkZdC1bWViUG/E7l6VEhvUz7sM=\n\n\
                          \u{2014} sum.golang.org Az3gri8PL8jK3XLX2QRsam4Kd/LuGmGhCL+4X1/eLfYISNOP0iBhBLk3iS4agdikyIkgqBDE52VgVVYCNJ2IPu5a6go=\n";

    fn verifier() -> Verifier {
        Verifier::parse(SUM_GOLANG_ORG).expect("the go command's key")
    }

    #[test]
    fn sum_golang_org_s_tree_head_verifies_and_names_its_tree() {
        let text = verifier().open(SIGNED).unwrap();
        assert_eq!(
            text,
            "go.sum database tree\n69104914\n1i5okhA0SJfHFAlniAkZdC1bWViUG/E7l6VEhvUz7sM=\n"
        );
        let tree = Tree::parse(text).unwrap();
        assert_eq!(tree.size, 69_104_914);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(tree.root),
            "1i5okhA0SJfHFAlniAkZdC1bWViUG/E7l6VEhvUz7sM="
        );
    }

    /// One changed digit of the size is a note the signature no longer covers.
    #[test]
    fn a_changed_note_does_not_verify() {
        let forged = SIGNED.replace("69104914", "69104915");
        let error = verifier().open(&forged).unwrap_err();
        assert!(error.contains("does not verify"), "{error}");
    }

    #[test]
    fn a_note_signed_by_no_one_this_key_names_is_refused() {
        for note in [
            "go.sum database tree\n1\nAAAA\n",
            "go.sum database tree\n1\nAAAA\n\n\u{2014} other.example AAAA\n",
            "go.sum database tree\n1\nAAAA\n\n\u{2014} sum.golang.org AAAA\n",
        ] {
            assert!(verifier().open(note).is_err(), "{note:?}");
        }
        let error = verifier()
            .open("text\n\n\u{2014} sum.golang.org !!!\n")
            .unwrap_err();
        assert!(error.contains("a signature by sum.golang.org"), "{error}");
    }

    #[test]
    fn a_key_that_is_not_one_is_refused() {
        for key in [
            "sum.golang.org",
            "sum.golang.org+033de0ae+!!!",
            "sum.golang.org+033de0ae+Ag==",
            "sum.golang.org+00000000+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
            "other.example+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
        ] {
            assert!(Verifier::parse(key).is_err(), "{key}");
        }
    }

    #[test]
    fn text_that_is_no_tree_head_is_refused() {
        for text in [
            "something else\n",
            "go.sum database tree\nmany\nAAAA\n",
            "go.sum database tree\n5\nnot base64\n",
            "go.sum database tree\n5\nAAAA\n",
        ] {
            assert!(Tree::parse(text).is_err(), "{text:?}");
        }
    }
}
