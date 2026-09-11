//! Trust for the upstream connection.
//!
//! reqwest 0.13's default `rustls` feature pulls `rustls-platform-verifier`, so the
//! upstream leg validates against the OS trust store with no configuration. That is not
//! enough for two real cases: a private registry with an internal CA, and a corporate
//! TLS-inspecting middlebox whose certificate the OS store may not carry.
//!
//! Two modes, and the difference matters:
//!
//! - **Merge.** The bundle is trusted in addition to the platform's roots.
//! - **Exclusive.** Only the bundle is trusted, and every public root is dropped.
//!
//! Exclusive is worth having on its own terms. Pinning the upstream to a known CA means a
//! compromise of any of the hundreds of public CAs cannot be used to impersonate the
//! registry. Verified with a self-signed CA against registry.npmjs.org: merged, the
//! request succeeds; exclusive, it fails at the TLS handshake.

use reqwest::Certificate;
use std::fmt;
use std::path::{Path, PathBuf};

/// How a bundle should be combined with the platform's own roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Trust the bundle as well as the platform's roots.
    Merge,
    /// Trust only the bundle. Public roots are dropped, so the upstream is pinned to
    /// whoever issued these certificates.
    Exclusive,
}

#[derive(Debug)]
pub enum TrustError {
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    Malformed {
        path: PathBuf,
        source: reqwest::Error,
    },
    /// The file parsed and held no certificates.
    ///
    /// Its own case rather than an empty `Vec`, because the two modes would both fail
    /// quietly: merging nothing changes nothing, and trusting nothing exclusively rejects
    /// every connection at the handshake, which reads as a network fault.
    Empty(PathBuf),
    /// The bundle parsed, and the TLS backend refused it when the client was built.
    ///
    /// A `CERTIFICATE` block whose base64 decodes to something that is not a certificate
    /// gets through `from_pem_bundle`, which reports one certificate, and is rejected at
    /// build time. Without this the failure surfaces as "failed to build HTTP client"
    /// with no mention of the file that caused it.
    Rejected {
        path: PathBuf,
        source: reqwest::Error,
    },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, source } => {
                write!(f, "cannot read CA bundle {}: {source}", path.display())
            }
            Self::Malformed { path, source } => {
                write!(f, "CA bundle {} is not valid PEM: {source}", path.display())
            }
            Self::Empty(path) => write!(f, "CA bundle {} contains no certificates", path.display()),
            Self::Rejected { path, source } => write!(
                f,
                "CA bundle {} was rejected by the TLS backend: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for TrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            Self::Malformed { source, .. } => Some(source),
            Self::Empty(_) => None,
            Self::Rejected { source, .. } => Some(source),
        }
    }
}

/// Read a PEM bundle from disk.
pub fn load_bundle(path: &Path) -> Result<Vec<Certificate>, TrustError> {
    let pem = std::fs::read(path).map_err(|source| TrustError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    parse_bundle(&pem, path)
}

/// Parse a PEM bundle. `path` is carried only so errors can name the file.
pub fn parse_bundle(pem: &[u8], path: &Path) -> Result<Vec<Certificate>, TrustError> {
    let certificates =
        Certificate::from_pem_bundle(pem).map_err(|source| TrustError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
    if certificates.is_empty() {
        return Err(TrustError::Empty(path.to_path_buf()));
    }
    Ok(certificates)
}

/// Apply a bundle to a client builder.
pub fn apply(
    builder: reqwest::ClientBuilder,
    certificates: Vec<Certificate>,
    mode: TrustMode,
) -> reqwest::ClientBuilder {
    match mode {
        TrustMode::Merge => builder.tls_certs_merge(certificates),
        TrustMode::Exclusive => builder.tls_certs_only(certificates),
    }
}

/// Build the client, naming the bundle if the TLS backend refuses it.
///
/// `bundle` is only used for the error message. Pass `None` when no bundle was applied,
/// in which case a failure is not about trust configuration.
pub fn build(
    builder: reqwest::ClientBuilder,
    bundle: Option<&Path>,
) -> Result<reqwest::Client, TrustError> {
    builder.build().map_err(|source| match bundle {
        Some(path) => TrustError::Rejected {
            path: path.to_path_buf(),
            source,
        },
        None => TrustError::Rejected {
            path: PathBuf::from("<none>"),
            source,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/")).join(name)
    }

    #[test]
    fn a_single_certificate_loads() {
        let certificates = load_bundle(&fixture("test-ca.pem")).expect("fixture should load");
        assert_eq!(certificates.len(), 1);
    }

    /// A bundle is several certificates in one file, and every one of them has to be
    /// trusted. Loading only the first would drop an intermediate silently.
    #[test]
    fn every_certificate_in_a_bundle_loads() {
        let certificates =
            load_bundle(&fixture("test-ca-bundle.pem")).expect("fixture should load");
        assert_eq!(certificates.len(), 2);
    }

    /// A file with no certificates is a misconfiguration, and both modes would hide it:
    /// merging nothing changes nothing, and trusting nothing exclusively fails every
    /// handshake, which reads as a network fault rather than a bad path.
    #[test]
    fn a_bundle_with_no_certificates_is_an_error() {
        for content in [
            &b""[..],
            b"# a comment and nothing else\n",
            b"-----BEGIN PRIVATE KEY-----\nnot a certificate\n-----END PRIVATE KEY-----\n",
        ] {
            let result = parse_bundle(content, Path::new("empty.pem"));
            assert!(
                matches!(
                    result,
                    Err(TrustError::Empty(_)) | Err(TrustError::Malformed { .. })
                ),
                "{:?} should not load as a trust bundle",
                String::from_utf8_lossy(content)
            );
        }
    }

    /// Bad base64 inside a `CERTIFICATE` block fails at parse time.
    #[test]
    fn a_malformed_pem_block_is_an_error() {
        let pem = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
        let Err(e) = parse_bundle(pem, Path::new("bad.pem")) else {
            panic!("this is not parseable PEM");
        };
        assert!(matches!(e, TrustError::Malformed { .. }), "got: {e:?}");
        assert!(e.to_string().contains("bad.pem"), "got: {e}");
        assert!(e.to_string().contains("not valid PEM"), "got: {e}");
        assert!(std::error::Error::source(&e).is_some());
    }

    /// A `CERTIFICATE` block whose base64 decodes to something that is not a certificate
    /// gets through parsing, which reports one certificate, and is refused when the
    /// client is built. The error has to name the file either way.
    #[test]
    fn a_bundle_the_tls_backend_refuses_names_the_file() {
        let pem = b"-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n";
        let path = Path::new("not-really-a-cert.pem");
        let certificates = parse_bundle(pem, path).expect("this parses, which is the point");
        assert_eq!(certificates.len(), 1);

        let builder = apply(reqwest::Client::builder(), certificates, TrustMode::Merge);
        let Err(e) = build(builder, Some(path)) else {
            panic!("the backend should refuse this");
        };
        assert!(matches!(e, TrustError::Rejected { .. }), "got: {e:?}");
        assert!(e.to_string().contains("not-really-a-cert.pem"), "got: {e}");
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn a_good_bundle_builds_a_client() {
        let certificates = load_bundle(&fixture("test-ca.pem")).unwrap();
        let builder = apply(reqwest::Client::builder(), certificates, TrustMode::Merge);
        assert!(build(builder, Some(&fixture("test-ca.pem"))).is_ok());
        assert!(build(reqwest::Client::builder(), None).is_ok());
    }

    #[test]
    fn errors_name_the_file_and_the_problem() {
        let missing = load_bundle(Path::new("/nonexistent/ca.pem"));
        let Err(e) = missing else {
            panic!("a missing file cannot load");
        };
        assert!(e.to_string().contains("/nonexistent/ca.pem"), "got: {e}");
        assert!(e.to_string().contains("cannot read"), "got: {e}");
        assert!(std::error::Error::source(&e).is_some());

        let empty = parse_bundle(b"", Path::new("/tmp/empty.pem"));
        let Err(e) = empty else {
            panic!("an empty file holds no certificates");
        };
        assert!(e.to_string().contains("no certificates"), "got: {e}");
        assert!(std::error::Error::source(&e).is_none());
    }

    /// Both modes have to reach a usable client. `tls_certs_merge` can fail depending on
    /// the verifier in use, so this is checked rather than assumed.
    #[test]
    fn both_modes_build_a_client() {
        for mode in [TrustMode::Merge, TrustMode::Exclusive] {
            let certificates = load_bundle(&fixture("test-ca.pem")).unwrap();
            let built = apply(reqwest::Client::builder(), certificates, mode).build();
            assert!(built.is_ok(), "{mode:?} should build: {:?}", built.err());
        }
    }
}
