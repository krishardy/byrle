//! Package identity. PURL throughout the core (plan §4).
//!
//! Two types, because the advisory data has two shapes and conflating them loses
//! matches:
//!
//! * [`PackageKey`] is a **versionless** identity, `pkg:npm/lodash`. This is the
//!   lookup key. Every one of the 231,533 npm entries in OSV's bundle carries a
//!   versionless purl and version ranges in a separate field, so a key that demanded
//!   a version could not express a lookup at all.
//! * [`PackageRef`] is a key plus a concrete version, `pkg:npm/lodash@4.17.21`. This
//!   is what a verdict is about, and what §5.5 `denials` match on.
//!
//! # Casing: npm names are not lowercased
//!
//! The purl specification says npm names MUST be lowercased. **We do not**, because
//! the advisory corpus we have to match does not.
//!
//! Measured against OSV's full npm bundle (Sept 2026, 228,941 advisories): 112 npm
//! package names contain uppercase, and all 112 are case-preserved in OSV's own purl.
//! Nearly all are `MAL-` records, which are malicious-package advisories. §5.5 pins
//! `known_malware: block` to the non-overridable floor. Confirmed live against the
//! OSV API:
//!
//! ```text
//! pkg:npm/AdultJS  -> MAL-2025-14119
//! pkg:npm/adultjs  -> no match
//! ```
//!
//! OSV also holds four npm names that differ only by case, one of them three ways:
//! `OpenClaw`, `Openclaw` and `openclaw`. Case-insensitive keying merges their
//! advisories.
//!
//! Do not change this to comply with the spec without re-running
//! `cargo run --example osv_conformance`.
//!
//! Identity comes from the packument's own `name` field, not the request path. The
//! registry reports the canonical spelling there; the path also carries
//! percent-encoding and query strings.

use purl::GenericPurl;
use std::fmt;
use std::str::FromStr;

/// Ecosystems we can express an identity for.
///
/// Which of them the proxy serves is `crate::ecosystem::TABLE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    /// PyPI. `crate::ecosystem::pypi` reads its simple index.
    PyPI,
}

impl Ecosystem {
    /// Every ecosystem a package can be named in, served or not.
    ///
    /// `ecosystem::TABLE` is checked against this: a variant with no row would make
    /// `ecosystem::of` panic on the request path, so the count has to match.
    pub const EXPRESSIBLE: [Ecosystem; 2] = [Ecosystem::Npm, Ecosystem::PyPI];

    /// The purl `type` component, and the string OSV keys on.
    pub const fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            // The purl type and OSV's ecosystem key are both lowercase, unlike PyPI's own
            // spelling of itself.
            Ecosystem::PyPI => "pypi",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" => Ok(Ecosystem::PyPI),
            other => Err(IdentityError::UnsupportedEcosystem(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Not a purl we can act on. Carries the ecosystem so the caller can say which.
    UnsupportedEcosystem(String),
    /// Malformed purl, or one missing a component we require.
    Malformed(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::UnsupportedEcosystem(e) => {
                write!(f, "unsupported ecosystem `{e}`")
            }
            IdentityError::Malformed(m) => write!(f, "malformed package identity: {m}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// A package, without a version. The advisory lookup key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageKey {
    ecosystem: Ecosystem,
    /// The npm scope, stored decoded: `@babel`, not `%40babel`.
    namespace: Option<String>,
    name: String,
}

impl PackageKey {
    /// Build a key from a registry-reported package name.
    ///
    /// Takes the npm-style name as the registry spells it, scope included
    /// (`@babel/core`), and splits the scope into the purl namespace. Case is
    /// preserved exactly; see the module docs for why that is not an oversight.
    pub fn from_registry_name(ecosystem: Ecosystem, name: &str) -> Result<Self, IdentityError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(IdentityError::Malformed("empty package name".into()));
        }
        let (namespace, bare) = match name.split_once('/') {
            Some((scope, rest)) => {
                if rest.is_empty() || rest.contains('/') {
                    return Err(IdentityError::Malformed(format!(
                        "`{name}` is not a valid npm package name"
                    )));
                }
                (Some(scope.to_string()), rest.to_string())
            }
            None => (None, name.to_string()),
        };
        // Not a `return Err`: with the empty check above and the empty-`rest` check in
        // the scoped arm, there is no input that reaches here with an empty `bare`. An
        // unreachable error arm is a branch no test can ever cover, which makes it look
        // like a gap in the test suite instead of what it is.
        debug_assert!(!bare.is_empty(), "`{name}` produced an empty package name");
        Ok(PackageKey {
            ecosystem,
            namespace,
            name: bare,
        })
    }

    /// Attach a concrete version, producing something a verdict can be about.
    pub fn at_version(&self, version: &str) -> Result<PackageRef, IdentityError> {
        let version = version.trim();
        if version.is_empty() {
            return Err(IdentityError::Malformed("empty version".into()));
        }
        Ok(PackageRef {
            key: self.clone(),
            version: version.to_string(),
        })
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    /// The npm scope, decoded and including the `@`, if there is one.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The name without its scope.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The name as the registry spells it, scope included: `@babel/core`.
    pub fn registry_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        }
    }
}

impl fmt::Display for PackageKey {
    /// Renders the canonical purl, percent-encoding the scope the way OSV does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = GenericPurl::builder(self.ecosystem.as_str().to_string(), &self.name);
        if let Some(ns) = &self.namespace {
            builder = builder.with_namespace(ns.clone());
        }
        match builder.build() {
            Ok(p) => write!(f, "{p}"),
            // Unreachable for values built through the constructors, which validate.
            Err(e) => write!(f, "<invalid purl: {e}>"),
        }
    }
}

/// Reunite a scope that arrived encoded into the name component.
///
/// OSV publishes scoped npm packages in **two** forms, and they do not parse alike:
///
/// ```text
/// pkg:npm/%40antv/algorithm    -> namespace "@antv", name "algorithm"
/// pkg:npm/%40antv%2Falgorithm  -> namespace None,    name "@antv/algorithm"
/// ```
///
/// Measured across OSV's npm bundle: 16,904 scoped entries use the first form and
/// 855 use the second. OSV's own API normalizes them, but a local mirror holds the
/// raw strings, so without this those 855 records are unreachable by a key built from
/// a registry name. `MAL-` malware records are over-represented among them.
fn split_encoded_scope(namespace: Option<&str>, name: &str) -> (Option<String>, String) {
    if namespace.is_none()
        && let Some(rest) = name.strip_prefix('@')
        && let Some((scope, bare)) = rest.split_once('/')
        && !scope.is_empty()
        && !bare.is_empty()
        && !bare.contains('/')
    {
        return (Some(format!("@{scope}")), bare.to_string());
    }
    (namespace.map(str::to_string), name.to_string())
}

impl FromStr for PackageKey {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = GenericPurl::<String>::from_str(s)
            .map_err(|e| IdentityError::Malformed(format!("{s}: {e}")))?;
        let ecosystem = parsed.package_type().parse::<Ecosystem>()?;
        if parsed.version().is_some() {
            return Err(IdentityError::Malformed(format!(
                "`{s}` carries a version; a PackageKey is versionless, use PackageRef"
            )));
        }
        let (namespace, name) = split_encoded_scope(parsed.namespace(), parsed.name());
        Ok(PackageKey {
            ecosystem,
            namespace,
            name,
        })
    }
}

/// A specific version of a package. What a verdict is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageRef {
    key: PackageKey,
    version: String,
}

impl PackageRef {
    pub fn key(&self) -> &PackageKey {
        &self.key
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.key.ecosystem
    }
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder =
            GenericPurl::builder(self.key.ecosystem.as_str().to_string(), &self.key.name)
                .with_version(self.version.clone());
        if let Some(ns) = &self.key.namespace {
            builder = builder.with_namespace(ns.clone());
        }
        match builder.build() {
            Ok(p) => write!(f, "{p}"),
            Err(e) => write!(f, "<invalid purl: {e}>"),
        }
    }
}

impl FromStr for PackageRef {
    type Err = IdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = GenericPurl::<String>::from_str(s)
            .map_err(|e| IdentityError::Malformed(format!("{s}: {e}")))?;
        let ecosystem = parsed.package_type().parse::<Ecosystem>()?;
        let version = parsed
            .version()
            .ok_or_else(|| IdentityError::Malformed(format!("`{s}` has no version")))?;
        let (namespace, name) = split_encoded_scope(parsed.namespace(), parsed.name());
        Ok(PackageRef {
            key: PackageKey {
                ecosystem,
                namespace,
                name,
            },
            version: version.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ecosystem's own name is the purl type, and it appears in log lines and
    /// operator-facing messages.
    #[test]
    fn ecosystem_displays_as_its_purl_type() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::Npm.as_str(), "npm");
    }

    /// Both error variants are read by operators, so both have to say which is which.
    #[test]
    fn identity_errors_describe_themselves() {
        let unsupported = IdentityError::UnsupportedEcosystem("cargo".into());
        assert_eq!(unsupported.to_string(), "unsupported ecosystem `cargo`");

        let Err(malformed) = PackageKey::from_registry_name(Ecosystem::Npm, "  ") else {
            panic!("whitespace is not a package name");
        };
        assert_eq!(
            malformed.to_string(),
            "malformed package identity: empty package name"
        );

        let Err(nested) = PackageKey::from_registry_name(Ecosystem::Npm, "@a/b/c") else {
            panic!("a second slash is not a scope");
        };
        assert!(nested.to_string().contains("not a valid npm package name"));

        let Err(empty_scope) = PackageKey::from_registry_name(Ecosystem::Npm, "@scope/") else {
            panic!("an empty name after the scope is not a package");
        };
        assert!(
            empty_scope
                .to_string()
                .contains("not a valid npm package name")
        );
    }

    /// A reference carries its key's ecosystem, so callers holding either can dispatch
    /// without unwrapping first.
    #[test]
    fn ecosystem_is_reachable_from_both_key_and_reference() {
        let key = PackageKey::from_registry_name(Ecosystem::Npm, "lodash").unwrap();
        assert_eq!(key.ecosystem(), Ecosystem::Npm);
        assert_eq!(
            key.at_version("4.17.21").unwrap().ecosystem(),
            Ecosystem::Npm
        );
    }

    fn key(name: &str) -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Npm, name).expect("valid name")
    }

    #[test]
    fn unscoped_package_renders_as_purl() {
        assert_eq!(key("lodash").to_string(), "pkg:npm/lodash");
        assert_eq!(
            key("lodash").at_version("4.17.21").unwrap().to_string(),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn npm_scope_becomes_a_percent_encoded_namespace() {
        // OSV writes scoped purls exactly this way; verified across its npm bundle.
        assert_eq!(key("@babel/core").to_string(), "pkg:npm/%40babel/core");
        assert_eq!(
            key("@babel/traverse")
                .at_version("7.23.1")
                .unwrap()
                .to_string(),
            "pkg:npm/%40babel/traverse@7.23.1"
        );
    }

    /// The regression this module exists to prevent.
    ///
    /// purl-spec says npm names must be lowercased. `pkg:npm/AdultJS` matches
    /// MAL-2025-14119; `pkg:npm/adultjs` matches nothing. MAL- records are
    /// malicious-package advisories.
    #[test]
    fn uppercase_names_are_preserved_not_lowercased() {
        assert_eq!(key("AdultJS").to_string(), "pkg:npm/AdultJS");
        assert_eq!(key("AVNjs").to_string(), "pkg:npm/AVNjs");
        assert_eq!(key("Blink1Control2").to_string(), "pkg:npm/Blink1Control2");
    }

    /// OSV holds these as distinct packages. Case-insensitive keying would merge
    /// their advisories, so the key must treat them as different.
    #[test]
    fn names_differing_only_by_case_are_distinct_keys() {
        assert_ne!(key("OpenClaw"), key("openclaw"));
        assert_ne!(key("OpenClaw"), key("Openclaw"));
        assert_ne!(key("Rambox"), key("rambox"));
    }

    #[test]
    fn round_trips_osv_purl_forms_byte_for_byte() {
        for s in [
            "pkg:npm/lodash",
            "pkg:npm/AdultJS",
            "pkg:npm/%40babel/traverse",
            "pkg:npm/%40types/node",
        ] {
            let parsed: PackageKey = s.parse().expect("OSV form should parse");
            assert_eq!(parsed.to_string(), s, "round-trip changed {s}");
        }
        for s in ["pkg:npm/lodash@4.17.21", "pkg:npm/%40babel/traverse@7.23.1"] {
            let parsed: PackageRef = s.parse().expect("OSV form should parse");
            assert_eq!(parsed.to_string(), s, "round-trip changed {s}");
        }
    }

    /// OSV writes scoped packages two ways and they do not parse alike. Both must
    /// land on one key or the 855 entries using the encoded form are unreachable.
    #[test]
    fn both_osv_scoped_forms_collapse_to_one_key() {
        let slash: PackageKey = "pkg:npm/%40antv/algorithm".parse().unwrap();
        let encoded: PackageKey = "pkg:npm/%40antv%2Falgorithm".parse().unwrap();
        assert_eq!(slash, encoded);
        // ...and both agree with the key built from the name the registry reports.
        assert_eq!(slash, key("@antv/algorithm"));
        assert_eq!(encoded.registry_name(), "@antv/algorithm");

        let slash: PackageRef = "pkg:npm/%40antv/algorithm@1.0.0".parse().unwrap();
        let encoded: PackageRef = "pkg:npm/%40antv%2Falgorithm@1.0.0".parse().unwrap();
        assert_eq!(slash, encoded);
    }

    /// A name that merely contains a slash without a leading `@` is not a scope, and
    /// must not be silently split into one.
    #[test]
    fn only_at_prefixed_scopes_are_rejoined() {
        let k: PackageKey = "pkg:npm/plain%2Fslash".parse().unwrap();
        assert_eq!(k.namespace(), None);
        assert_eq!(k.name(), "plain/slash");
    }

    #[test]
    fn parsing_recovers_the_registry_name() {
        let k: PackageKey = "pkg:npm/%40babel/traverse".parse().unwrap();
        assert_eq!(k.registry_name(), "@babel/traverse");
        assert_eq!(k.namespace(), Some("@babel"));
        assert_eq!(k.name(), "traverse");

        let k: PackageKey = "pkg:npm/lodash".parse().unwrap();
        assert_eq!(k.registry_name(), "lodash");
        assert_eq!(k.namespace(), None);
    }

    /// The two shapes must not be silently interchangeable: OSV's lookup keys are
    /// versionless, and a verdict without a version is meaningless.
    #[test]
    fn key_and_ref_do_not_accept_each_others_shape() {
        assert!("pkg:npm/lodash@4.17.21".parse::<PackageKey>().is_err());
        assert!("pkg:npm/lodash".parse::<PackageRef>().is_err());
    }

    #[test]
    fn rejects_input_we_cannot_act_on() {
        assert!(PackageKey::from_registry_name(Ecosystem::Npm, "").is_err());
        assert!(PackageKey::from_registry_name(Ecosystem::Npm, "@scope/").is_err());
        assert!(PackageKey::from_registry_name(Ecosystem::Npm, "a/b/c").is_err());
        assert!(key("lodash").at_version("").is_err());
        // Ecosystems we have not implemented must fail loudly rather than be guessed at.
        assert!(matches!(
            "pkg:cargo/serde".parse::<PackageKey>(),
            Err(IdentityError::UnsupportedEcosystem(_))
        ));
    }

    #[test]
    fn a_pypi_identity_is_a_pypi_purl() {
        let key: PackageKey = "pkg:pypi/requests".parse().expect("pypi parses");
        assert_eq!(key.ecosystem(), Ecosystem::PyPI);
        assert_eq!(key.ecosystem().as_str(), "pypi");
        assert_eq!(
            key.at_version("2.34.2").expect("a version").to_string(),
            "pkg:pypi/requests@2.34.2"
        );
    }
}
