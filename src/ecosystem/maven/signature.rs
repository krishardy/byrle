//! A file's detached PGP signature checked as
//! [maven-signatures](../../../docs/engineering_decisions/0113-maven-signatures.md) decides:
//! made by the key or one of its signing subkeys, unexpired when it signed, and not revoked
//! as RFC 9580 reads a revocation. Read with `pgp` 0.21.0, MIT OR Apache-2.0.

use std::io::SeekFrom;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{RevocationCode, Signature, SignatureType};
use pgp::types::{KeyDetails, Tag};

/// What checks Maven's signatures, as their results are stored: the crate, and 0113's rules.
pub const VERIFIER: &str = "pgp 0.21.0; maven-signatures 1";

/// What a signature and the keys a server holds for it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signed {
    /// It verified, made by the primary key with this fingerprint or one of its subkeys.
    Verified { key: String },
    /// It did not, and why.
    Failed { why: String },
}

/// The key a signature names as its signer: its fingerprint when it says, else its key id,
/// in upper-case hex, as a key server is asked by it. Errors when it does not read.
pub fn issuer(signature: &[u8]) -> Result<String, String> {
    let signature = parse(signature)?;
    if let Some(fingerprint) = signature.issuer_fingerprint().first() {
        return Ok(format!("{fingerprint:X}"));
    }
    signature
        .issuer_key_id()
        .first()
        .map(|id| hex_upper(id.as_ref()))
        .ok_or_else(|| "the signature names no key".to_owned())
}

/// Whether `signature` is a good signature of `file` by a key in `keys`, an armored key
/// server answer. Errors when `file` cannot be read.
pub fn verify(
    signature: &[u8],
    keys: &str,
    file: &mut dyn crate::ecosystem::Source,
) -> std::io::Result<Signed> {
    let signature = match parse(signature) {
        Ok(signature) => signature,
        Err(why) => return Ok(Signed::Failed { why }),
    };
    if signature.typ() != Some(SignatureType::Binary) {
        return Ok(Signed::Failed {
            why: "it is not a signature of a file's bytes".to_owned(),
        });
    }
    let Some(signed_at) = signature.created().map(|t| t.as_secs()) else {
        return Ok(Signed::Failed {
            why: "it carries no creation time".to_owned(),
        });
    };
    let issuers = issuers(&signature);
    let Ok((parsed, _)) = SignedPublicKey::from_string_many(keys) else {
        return Ok(Signed::Failed {
            why: "the key server's answer is no key".to_owned(),
        });
    };
    let mut why = "no key the server holds made it".to_owned();
    for key in parsed.flatten() {
        let found = if names(&key.primary_key, &issuers) {
            check(&signature, &key, None, file, signed_at)?
        } else if let Some(sub) = key.public_subkeys.iter().find(|s| names(&s.key, &issuers)) {
            check(&signature, &key, Some(sub), file, signed_at)?
        } else {
            continue;
        };
        match found {
            Ok(()) => {
                return Ok(Signed::Verified {
                    key: format!("{:X}", key.primary_key.fingerprint()),
                });
            }
            Err(failed) => why = failed,
        }
    }
    Ok(Signed::Failed { why })
}

/// The detached signature `bytes` armor. Errors when they are not one.
fn parse(bytes: &[u8]) -> Result<Signature, String> {
    DetachedSignature::from_armor_single(bytes)
        .map(|(detached, _)| detached.signature)
        .map_err(|e| format!("it is no signature: {e}"))
}

/// The fingerprints and key ids a signature names its signer by, in upper-case hex.
fn issuers(signature: &Signature) -> Vec<String> {
    let fingerprints = signature
        .issuer_fingerprint()
        .into_iter()
        .map(|f| format!("{f:X}"));
    let ids = signature
        .issuer_key_id()
        .into_iter()
        .map(|id| hex_upper(id.as_ref()));
    fingerprints.chain(ids).collect()
}

/// Whether `key` is one of `issuers`, by its fingerprint or its key id.
fn names(key: &impl KeyDetails, issuers: &[String]) -> bool {
    let fingerprint = format!("{:X}", key.fingerprint());
    let id = hex_upper(key.legacy_key_id().as_ref());
    issuers.iter().any(|i| *i == fingerprint || *i == id)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Whether `signature`, made at `signed_at`, is a good one of `file` by `key`, or by its
/// subkey `sub`, unexpired and unrevoked then. `Err` inside says why not; the outer error is
/// `file` that cannot be read.
fn check(
    signature: &Signature,
    key: &SignedPublicKey,
    sub: Option<&SignedPublicSubKey>,
    file: &mut dyn crate::ecosystem::Source,
    signed_at: u32,
) -> std::io::Result<Result<(), String>> {
    file.seek(SeekFrom::Start(0))?;
    let made = match sub {
        Some(sub) => signature.verify(sub, &mut *file),
        None => signature.verify(key, &mut *file),
    };
    if made.is_err() {
        return Ok(Err("the signature does not verify".to_owned()));
    }
    let primary = &key.primary_key;
    let created = primary.created_at().as_secs();
    let mut lives: Vec<(u32, Option<u32>)> = key
        .details
        .direct_signatures
        .iter()
        .filter(|s| s.verify_key(primary).is_ok())
        .map(|s| life(s, created))
        .collect();
    lives.extend(key.details.users.iter().flat_map(|user| {
        user.signatures
            .iter()
            .filter(|s| {
                s.verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
            })
            .map(|s| life(s, created))
    }));
    if let Some(why) = expired(&lives, signed_at, "the key") {
        return Ok(Err(why));
    }
    let revocations: Vec<(u32, bool)> = key
        .details
        .revocation_signatures
        .iter()
        .filter(|s| s.verify_key(primary).is_ok())
        .map(revocation)
        .collect();
    if let Some(why) = revoked(&revocations, signed_at, "the key") {
        return Ok(Err(why));
    }
    let Some(sub) = sub else {
        return Ok(Ok(()));
    };
    let bound: Vec<&Signature> = sub
        .signatures
        .iter()
        .filter(|s| s.verify_subkey_binding(primary, &sub.key).is_ok())
        .collect();
    let sub_created = sub.key.created_at().as_secs();
    let lives: Vec<(u32, Option<u32>)> = bound
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .map(|s| life(s, sub_created))
        .collect();
    if lives.is_empty() {
        return Ok(Err("its subkey is not bound to the key".to_owned()));
    }
    if let Some(why) = expired(&lives, signed_at, "its subkey") {
        return Ok(Err(why));
    }
    let revocations: Vec<(u32, bool)> = bound
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
        .map(|s| revocation(s))
        .collect();
    Ok(revoked(&revocations, signed_at, "its subkey").map_or(Ok(()), Err))
}

/// A self-signature's time, and when it says its key expires: `created` plus its key
/// expiration time, `None` for never.
fn life(signature: &Signature, created: u32) -> (u32, Option<u32>) {
    let made = signature.created().map_or(0, |t| t.as_secs());
    let expires = signature
        .key_expiration_time()
        .map(|d| d.as_secs())
        .filter(|secs| *secs > 0)
        .map(|secs| created.saturating_add(secs));
    (made, expires)
}

/// Why a key whose self-signatures say `lives` had expired at `signed_at`, `None` when it
/// had not. The most recent self-signature says when the key expires.
fn expired(lives: &[(u32, Option<u32>)], signed_at: u32, what: &str) -> Option<String> {
    let (_, expires) = lives.iter().max_by_key(|(made, _)| *made)?;
    let expires = (*expires)?;
    (expires <= signed_at).then(|| format!("{what} expired before it signed"))
}

/// A revocation's time, and whether its reason is soft: superseded or retired.
fn revocation(signature: &Signature) -> (u32, bool) {
    let at = signature.created().map_or(0, |t| t.as_secs());
    let soft = matches!(
        signature.revocation_reason_code(),
        Some(RevocationCode::KeySuperseded | RevocationCode::KeyRetired)
    );
    (at, soft)
}

/// Why `revocations` revoke a signature made at `signed_at`, `None` when none does. A soft
/// one revokes only a signature made after it; any other, every signature.
fn revoked(revocations: &[(u32, bool)], signed_at: u32, what: &str) -> Option<String> {
    revocations
        .iter()
        .find(|(at, soft)| !soft || *at <= signed_at)
        .map(|(_, soft)| {
            if *soft {
                format!("{what} was retired before it signed")
            } else {
                format!("{what} is revoked")
            }
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::{Read, Seek};

    /// A file of `tests/fixtures/maven/signed/`.
    fn signed(name: &str) -> Vec<u8> {
        super::super::fixture(&format!("signed/{name}"))
    }

    /// What `jar`'s `.asc` says of `file`, a fixture, with `key`'s copy from `server`.
    fn checked(jar: &str, file: &str, key: &str) -> Signed {
        let keys = String::from_utf8(signed(key)).unwrap();
        let mut file = std::io::Cursor::new(signed(file));
        verify(&signed(&format!("{jar}.asc")), &keys, &mut file).unwrap()
    }

    /// Central's signatures verify, by a key expired or superseded since, with either copy:
    /// keys.openpgp.org's holds no user id.
    #[test]
    fn central_s_signatures_verify() {
        for (jar, server) in [
            ("jakarta.annotation-api-2.1.1.jar", "openpgp"),
            ("jakarta.annotation-api-2.1.1.jar", "ubuntu"),
            ("json-simple-3.0.2.jar", "ubuntu"),
            ("plexus-build-api-0.0.7.jar", "ubuntu"),
            ("plexus-component-annotations-2.0.0.jar", "openpgp"),
        ] {
            let found = checked(jar, jar, &format!("{jar}.{server}.key"));
            assert!(
                matches!(found, Signed::Verified { .. }),
                "{jar} {server}: {found:?}"
            );
        }
        assert_eq!(
            checked(
                "plexus-component-annotations-2.0.0.jar",
                "plexus-component-annotations-2.0.0.jar",
                "plexus-component-annotations-2.0.0.jar.ubuntu.key"
            ),
            Signed::Verified {
                key: "AE9E53FC28FF2AB1012273D0BF1518E0160788A2".to_owned()
            }
        );
    }

    #[test]
    fn a_signature_of_other_bytes_or_by_another_key_fails() {
        let jakarta = "jakarta.annotation-api-2.1.1.jar";
        let json = "json-simple-3.0.2.jar";
        for (file, key, said) in [
            (
                json,
                format!("{jakarta}.ubuntu.key"),
                "the signature does not verify",
            ),
            (
                jakarta,
                format!("{json}.ubuntu.key"),
                "no key the server holds made it",
            ),
        ] {
            assert_eq!(
                checked(jakarta, file, &key),
                Signed::Failed {
                    why: said.to_owned()
                }
            );
        }
        let mut file = std::io::Cursor::new(signed(jakarta));
        let keys = String::from_utf8(signed(&format!("{jakarta}.ubuntu.key"))).unwrap();
        for (signature, keys, said) in [
            (&b"not armor"[..], keys.as_str(), "it is no signature"),
            (
                &signed(&format!("{jakarta}.asc"))[..],
                "not a key",
                "the key server's answer is no key",
            ),
        ] {
            let Signed::Failed { why } = verify(signature, keys, &mut file).unwrap() else {
                panic!("{said}");
            };
            assert!(why.starts_with(said), "{why}");
        }
    }

    /// Keys and signatures made for the cases no signature measured on Central has.
    mod made {
        use pgp::composed::{
            ArmorOptions, DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
            SignedSecretKey, SubkeyParamsBuilder,
        };
        use pgp::crypto::hash::HashAlgorithm;
        use pgp::packet::{
            RevocationCode, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
        };
        use pgp::types::{Duration, KeyDetails, Password, SigningKey, Timestamp};

        /// Now, which the key's own self-signatures are made at.
        pub fn now() -> u32 {
            pgp::types::Timestamp::now().as_secs()
        }

        /// When the key is made: before its self-signatures, which say when it expires.
        pub fn made() -> u32 {
            now() - 1000
        }

        /// A key that certifies and signs, with a subkey that signs.
        pub fn key() -> SignedSecretKey {
            let sub = SubkeyParamsBuilder::default()
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .created_at(Timestamp::from_secs(made()))
                .build()
                .unwrap();
            SecretKeyParamsBuilder::default()
                .key_type(KeyType::Ed25519Legacy)
                .can_certify(true)
                .can_sign(true)
                .created_at(Timestamp::from_secs(made()))
                .primary_user_id("test <test@example.com>".into())
                .subkeys(vec![sub])
                .build()
                .unwrap()
                .generate(rand::thread_rng())
                .unwrap()
        }

        /// A v4 signature's config of `typ` made at `at` by `signer`, naming it, with `extra`.
        pub fn config(
            typ: SignatureType,
            at: Option<u32>,
            signer: &impl KeyDetails,
            extra: Vec<SubpacketData>,
        ) -> SignatureConfig {
            let mut config = SignatureConfig::v4(typ, signer.algorithm(), HashAlgorithm::Sha256);
            let mut hashed = Vec::new();
            if let Some(at) = at {
                hashed.push(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    at,
                )));
            }
            hashed.push(SubpacketData::IssuerFingerprint(signer.fingerprint()));
            hashed.extend(extra);
            config.hashed_subpackets = hashed
                .into_iter()
                .map(|d| Subpacket::regular(d).unwrap())
                .collect();
            config
        }

        /// `data` signed by `signer` at `at`, armored, as an `.asc` is.
        pub fn signature(
            signer: &impl SigningKey,
            typ: SignatureType,
            at: Option<u32>,
            data: &[u8],
        ) -> Vec<u8> {
            let signed = config(typ, at, signer, Vec::new())
                .sign(signer, &Password::empty(), data)
                .unwrap();
            DetachedSignature::new(signed)
                .to_armored_bytes(ArmorOptions::default())
                .unwrap()
        }

        /// A direct key signature over `key` at `at`, saying it expires `after` seconds after
        /// it was made.
        pub fn expiring(key: &SignedSecretKey, at: u32, after: u32) -> Signature {
            config(
                SignatureType::Key,
                Some(at),
                &key.primary_key,
                vec![SubpacketData::KeyExpirationTime(Duration::from_secs(after))],
            )
            .sign_key(
                &key.primary_key,
                &Password::empty(),
                key.primary_key.public_key(),
            )
            .unwrap()
        }

        /// A revocation of `typ` by the primary key at `at`, for `code`.
        pub fn revocation(
            key: &SignedSecretKey,
            typ: SignatureType,
            at: u32,
            code: RevocationCode,
        ) -> SignatureConfig {
            config(
                typ,
                Some(at),
                &key.primary_key,
                vec![SubpacketData::RevocationReason(code, "test".into())],
            )
        }

        /// A binding of `key`'s subkey at `at`, saying it expires `after` seconds after it
        /// was made, or never.
        pub fn binding(
            key: &SignedSecretKey,
            typ: SignatureType,
            at: u32,
            extra: Vec<SubpacketData>,
        ) -> Signature {
            let sub = &key.secret_subkeys[0].key;
            config(typ, Some(at), &key.primary_key, extra)
                .sign_subkey_binding(
                    &key.primary_key,
                    key.primary_key.public_key(),
                    &Password::empty(),
                    sub.public_key(),
                )
                .unwrap()
        }

        /// The public key, armored, as a key server answers it.
        pub fn armored(key: SignedPublicKey) -> String {
            key.to_armored_string(ArmorOptions::default()).unwrap()
        }
    }

    /// What `signature` says of `data` with `key`.
    fn judged(signature: &[u8], key: pgp::composed::SignedPublicKey, data: &[u8]) -> Signed {
        let mut file = std::io::Cursor::new(data.to_vec());
        verify(signature, &made::armored(key), &mut file).unwrap()
    }

    fn failed(why: &str) -> Signed {
        Signed::Failed {
            why: why.to_owned(),
        }
    }

    /// A key's latest self-signature says when it expires; a revocation for compromise
    /// revokes what it signed before it. Times are from now, after the key's own.
    #[test]
    fn a_primary_key_s_expiry_and_revocation_are_read() {
        use made::*;
        use pgp::packet::{RevocationCode, SignatureType};
        let (key, base) = (key(), now());
        let public = || pgp::composed::SignedPublicKey::from(key.clone());
        let data = b"the file";
        let at = |offset| {
            signature(
                &key.primary_key,
                SignatureType::Binary,
                Some(base + offset),
                data,
            )
        };
        assert!(matches!(
            judged(&at(20), public(), data),
            Signed::Verified { .. }
        ));
        let mut expires = public();
        let life = base + 100 - made();
        expires
            .details
            .direct_signatures
            .push(expiring(&key, base + 10, life));
        assert_eq!(
            judged(&at(200), expires.clone(), data),
            failed("the key expired before it signed")
        );
        assert!(matches!(
            judged(&at(50), expires, data),
            Signed::Verified { .. }
        ));
        let mut never = public();
        never
            .details
            .direct_signatures
            .push(expiring(&key, base + 10, 0));
        assert!(
            matches!(judged(&at(200), never, data), Signed::Verified { .. }),
            "a key expiration time of 0 is no expiry"
        );
        let mut revoked = public();
        let revocation = revocation(
            &key,
            SignatureType::KeyRevocation,
            base + 50,
            RevocationCode::KeyCompromised,
        )
        .sign_key(
            &key.primary_key,
            &pgp::types::Password::empty(),
            key.primary_key.public_key(),
        )
        .unwrap();
        revoked.details.revocation_signatures.push(revocation);
        assert_eq!(judged(&at(20), revoked, data), failed("the key is revoked"));
    }

    /// A subkey signs only while bound, unexpired and unrevoked.
    #[test]
    fn a_signing_subkey_s_binding_expiry_and_revocation_are_read() {
        use made::*;
        use pgp::packet::{RevocationCode, SignatureType, SubpacketData};
        let (key, base) = (key(), now());
        let public = || pgp::composed::SignedPublicKey::from(key.clone());
        let data = b"the file";
        let sub = &key.secret_subkeys[0].key;
        let signed = signature(sub, SignatureType::Binary, Some(base + 200), data);
        assert!(matches!(
            judged(&signed, public(), data),
            Signed::Verified { .. }
        ));
        let mut expires = public();
        let life = pgp::types::Duration::from_secs(base + 100 - made());
        let renewed = binding(
            &key,
            SignatureType::SubkeyBinding,
            base + 10,
            vec![SubpacketData::KeyExpirationTime(life)],
        );
        expires.public_subkeys[0].signatures.push(renewed);
        assert_eq!(
            judged(&signed, expires, data),
            failed("its subkey expired before it signed")
        );
        let mut revoked = public();
        let reason = SubpacketData::RevocationReason(RevocationCode::KeyRetired, "test".into());
        let revocation = binding(
            &key,
            SignatureType::SubkeyRevocation,
            base + 300,
            vec![reason],
        );
        revoked.public_subkeys[0].signatures.push(revocation);
        assert!(matches!(
            judged(&signed, revoked.clone(), data),
            Signed::Verified { .. }
        ));
        let later = signature(sub, SignatureType::Binary, Some(base + 400), data);
        assert_eq!(
            judged(&later, revoked, data),
            failed("its subkey was retired before it signed")
        );
        let mut unbound = public();
        let only = binding(
            &key,
            SignatureType::SubkeyRevocation,
            base + 300,
            Vec::new(),
        );
        unbound.public_subkeys[0].signatures = vec![only];
        assert_eq!(
            judged(&signed, unbound, data),
            failed("its subkey is not bound to the key")
        );
    }

    /// A signature over text, one with no time, and one naming no key are not decided on.
    #[test]
    fn a_signature_that_is_no_file_s_with_a_time_is_refused() {
        use made::*;
        use pgp::packet::SignatureType;
        let (key, base) = (key(), now());
        let public = || pgp::composed::SignedPublicKey::from(key.clone());
        let data = b"the file";
        let text = signature(&key.primary_key, SignatureType::Text, Some(base), data);
        assert_eq!(
            judged(&text, public(), data),
            failed("it is not a signature of a file's bytes")
        );
        let untimed = signature(&key.primary_key, SignatureType::Binary, None, data);
        assert_eq!(
            judged(&untimed, public(), data),
            failed("it carries no creation time")
        );
        let mut nameless = config(
            SignatureType::Binary,
            Some(base),
            &key.primary_key,
            Vec::new(),
        );
        nameless
            .hashed_subpackets
            .retain(|p| !matches!(p.data, pgp::packet::SubpacketData::IssuerFingerprint(_)));
        let nameless = nameless
            .sign(&key.primary_key, &pgp::types::Password::empty(), &data[..])
            .unwrap();
        let armored = pgp::composed::DetachedSignature::new(nameless)
            .to_armored_bytes(pgp::composed::ArmorOptions::default())
            .unwrap();
        assert_eq!(
            issuer(&armored),
            Err("the signature names no key".to_owned())
        );
    }

    /// A file that cannot be read is an error, whichever key signed it, not a failure.
    #[test]
    fn a_file_that_cannot_be_read_is_an_error() {
        struct Unseekable;
        impl Read for Unseekable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for Unseekable {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("unseekable"))
            }
        }
        use made::*;
        use pgp::packet::SignatureType;
        let key = key();
        let keys = armored(pgp::composed::SignedPublicKey::from(key.clone()));
        for signer in [
            signature(&key.primary_key, SignatureType::Binary, Some(now()), b"x"),
            signature(
                &key.secret_subkeys[0].key,
                SignatureType::Binary,
                Some(now()),
                b"x",
            ),
        ] {
            assert!(verify(&signer, &keys, &mut Unseekable).is_err());
        }
    }

    /// A key server is asked by the fingerprint a signature names, or its key id alone.
    #[test]
    fn a_signature_names_its_key() {
        assert_eq!(
            issuer(&signed("plexus-component-annotations-2.0.0.jar.asc")).as_deref(),
            Ok("AE9E53FC28FF2AB1012273D0BF1518E0160788A2")
        );
        assert_eq!(
            issuer(&signed("plexus-build-api-0.0.7.jar.asc")).as_deref(),
            Ok("0374CF2E8DD1BDFD")
        );
        assert!(issuer(b"not armor").is_err());
    }

    #[test]
    fn a_soft_revocation_revokes_only_what_it_follows() {
        assert_eq!(revoked(&[(100, true)], 50, "the key"), None);
        assert_eq!(
            revoked(&[(100, true)], 150, "the key").as_deref(),
            Some("the key was retired before it signed")
        );
        assert_eq!(
            revoked(&[(100, false)], 50, "the key").as_deref(),
            Some("the key is revoked")
        );
        assert_eq!(revoked(&[], 50, "the key"), None);
    }

    #[test]
    fn the_latest_self_signature_says_when_a_key_expires() {
        assert_eq!(expired(&[(10, Some(100))], 50, "the key"), None);
        assert_eq!(
            expired(&[(10, Some(100))], 100, "the key").as_deref(),
            Some("the key expired before it signed")
        );
        assert_eq!(expired(&[(10, Some(100)), (20, Some(300))], 150, "k"), None);
        assert_eq!(expired(&[(10, Some(100)), (20, None)], 150, "k"), None);
        assert_eq!(expired(&[], 150, "k"), None);
    }
}
