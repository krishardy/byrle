//! Console passwords: checked for length, hashed with Argon2id to a PHC string, and
//! verified against one. See docs/engineering_decisions/console-login.md.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};

/// The fewest characters a password may have.
pub const MIN_CHARS: usize = 15;

/// The most bytes a password may have, which bounds the work of hashing one.
pub const MAX_BYTES: usize = 1024;

/// Random bytes of salt per hash.
const SALT_BYTES: usize = 16;

/// Argon2id with the parameters for new hashes; one is verified with those it names.
pub struct Hasher(argon2::Argon2<'static>);

impl Hasher {
    /// Argon2id v19, 19 MiB, 2 passes, 1 lane: the `argon2` crate's defaults.
    pub fn standard() -> Self {
        Self(argon2::Argon2::default())
    }

    /// Argon2id with `params`, which tests make cheap.
    pub fn with(params: argon2::Params) -> Self {
        Self(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }

    /// `password` as a PHC string, with a new random salt.
    pub fn hash(&self, password: &str) -> String {
        let mut salt = [0u8; SALT_BYTES];
        getrandom::fill(&mut salt).expect("the operating system supplies random bytes");
        self.0
            .hash_password_with_salt(password.as_bytes(), &salt)
            .expect("a password of at most MAX_BYTES with a 16-byte salt hashes")
            .to_string()
    }

    /// Whether `password` is the one `phc` was made from. A `phc` that does not parse
    /// matches nothing.
    pub fn verify(&self, password: &str, phc: &str) -> bool {
        PasswordHash::new(phc)
            .is_ok_and(|hash| self.0.verify_password(password.as_bytes(), &hash).is_ok())
    }
}

/// `password` if it is long enough and not too long; else why not.
pub fn acceptable(password: &str) -> Result<&str, String> {
    let chars = password.chars().count();
    if chars < MIN_CHARS {
        Err(format!(
            "the password has {chars} characters; it needs at least {MIN_CHARS}"
        ))
    } else if password.len() > MAX_BYTES {
        Err(format!(
            "the password has {} bytes; it may have at most {MAX_BYTES}",
            password.len()
        ))
    } else {
        Ok(password)
    }
}

/// The first line of `input`, without its line ending, as the password.
pub fn read(input: &mut dyn std::io::BufRead) -> Result<String, String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| format!("the password could not be read: {e}"))?;
    let line = line.strip_suffix('\n').unwrap_or(&line);
    Ok(line.strip_suffix('\r').unwrap_or(line).to_owned())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    /// Argon2id at its smallest cost, so a test hashes in microseconds.
    pub fn cheap() -> Hasher {
        Hasher::with(argon2::Params::new(8, 1, 1, None).unwrap())
    }

    #[test]
    fn a_hash_verifies_its_password_and_no_other() {
        let hasher = cheap();
        let phc = hasher.hash("correct horse battery");
        assert!(phc.starts_with("$argon2id$v=19$m=8,t=1,p=1$"), "{phc}");
        assert!(hasher.verify("correct horse battery", &phc));
        assert!(!hasher.verify("correct horse battery ", &phc));
        assert!(!hasher.verify("correct horse battery", "not a hash"));
        assert_ne!(
            phc,
            hasher.hash("correct horse battery"),
            "a new salt each time"
        );
    }

    /// The standard parameters are the ones the decision names, and a hash made with
    /// them is verified by a hasher with any parameters.
    #[test]
    fn the_standard_hash_is_argon2id_at_19_mib_and_2_passes() {
        let phc = Hasher::standard().hash("correct horse battery");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(cheap().verify("correct horse battery", &phc));
    }

    #[test]
    fn a_password_is_at_least_15_characters_and_at_most_1024_bytes() {
        assert_eq!(
            acceptable("fourteen chars"),
            Err("the password has 14 characters; it needs at least 15".into())
        );
        assert_eq!(acceptable("ééééééééééééééé"), Ok("ééééééééééééééé"));
        assert!(acceptable(&"a".repeat(MAX_BYTES)).is_ok());
        assert_eq!(
            acceptable(&"a".repeat(MAX_BYTES + 1)),
            Err("the password has 1025 bytes; it may have at most 1024".into())
        );
    }

    #[test]
    fn the_password_is_the_first_line_without_its_ending() {
        let read_from = |text: &[u8]| read(&mut std::io::Cursor::new(text));
        assert_eq!(read_from(b"a b \r\nsecond\n"), Ok("a b ".into()));
        assert_eq!(read_from(b"no ending"), Ok("no ending".into()));
        assert_eq!(read_from(b""), Ok(String::new()));
        assert!(
            read_from(b"\xff\n")
                .unwrap_err()
                .contains("could not be read")
        );
    }
}
