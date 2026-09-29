//! Package identity as purls: [`PackageKey`] is versionless, the lookup key, and
//! [`PackageRef`] is a key and a version. npm names keep their case, against purl-spec.
//!
//! See docs/engineering_decisions/purl-identity-rules.md.

use purl::GenericPurl;
use std::fmt;
use std::str::FromStr;

/// Ecosystems an identity can be expressed for. `crate::ecosystem::TABLE` lists those served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    /// PyPI. `crate::ecosystem::pypi` reads its simple index.
    PyPI,
}

impl Ecosystem {
    /// Every ecosystem a package can be named in. `ecosystem::TABLE` has a row for each.
    pub const EXPRESSIBLE: [Ecosystem; 2] = [Ecosystem::Npm, Ecosystem::PyPI];

    /// The purl `type` component, and the string OSV keys on.
    pub const fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
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
    /// Build a key from a registry-reported package name, split by the ecosystem's
    /// `split_name`. Case is preserved.
    pub fn from_registry_name(ecosystem: Ecosystem, name: &str) -> Result<Self, IdentityError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(IdentityError::Malformed("empty package name".into()));
        }
        let (namespace, bare) = (crate::ecosystem::of(ecosystem).split_name)(name)?;
        debug_assert!(!bare.is_empty(), "`{name}` produced an empty package name");
        Ok(PackageKey {
            ecosystem,
            namespace,
            name: bare,
        })
    }

    /// A key with no namespace, built without the ecosystem's name rule. Calling through
    /// [`crate::ecosystem::of`] brings every function in [`crate::ecosystem::TABLE`] into a
    /// kani harness, down to `Url::parse`, which kani 0.67.0 cannot compile.
    #[cfg(kani)]
    pub(crate) fn for_proof(ecosystem: Ecosystem, name: &str) -> Self {
        PackageKey {
            ecosystem,
            namespace: None,
            name: name.to_owned(),
        }
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
            Err(e) => write!(f, "<invalid purl: {e}>"),
        }
    }
}

/// The key a purl names: its namespace and name joined by `/`, then split as
/// [`PackageKey::from_registry_name`] splits a registry name, so both of OSV's scoped forms
/// give one key.
pub fn key_from_purl(
    ecosystem: Ecosystem,
    namespace: Option<&str>,
    name: &str,
) -> Result<PackageKey, IdentityError> {
    match namespace {
        Some(namespace) => {
            PackageKey::from_registry_name(ecosystem, &format!("{namespace}/{name}"))
        }
        None => PackageKey::from_registry_name(ecosystem, name),
    }
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
        key_from_purl(ecosystem, parsed.namespace(), parsed.name())
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
        Ok(PackageRef {
            key: key_from_purl(ecosystem, parsed.namespace(), parsed.name())?,
            version: version.to_string(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

        let Err(unscoped) = PackageKey::from_registry_name(Ecosystem::Npm, "foo/bar") else {
            panic!("an npm `/` needs an `@` scope");
        };
        assert!(unscoped.to_string().contains("a `/` needs an `@` scope"));

        let Err(pypi) = PackageKey::from_registry_name(Ecosystem::PyPI, "a/b") else {
            panic!("a PyPI project has no namespace");
        };
        assert!(pypi.to_string().contains("not a valid PyPI project name"));

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
        assert_eq!(key("@babel/core").to_string(), "pkg:npm/%40babel/core");
        assert_eq!(
            key("@babel/traverse")
                .at_version("7.23.1")
                .unwrap()
                .to_string(),
            "pkg:npm/%40babel/traverse@7.23.1"
        );
    }

    /// purl-spec says npm names must be lowercased, but `pkg:npm/AdultJS` matches
    /// MAL-2025-14119 and `pkg:npm/adultjs` matches nothing.
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
        assert_eq!(
            slash,
            key("@antv/algorithm"),
            "both agree with the key built from the registry's name"
        );
        assert_eq!(encoded.registry_name(), "@antv/algorithm");

        let slash: PackageRef = "pkg:npm/%40antv/algorithm@1.0.0".parse().unwrap();
        let encoded: PackageRef = "pkg:npm/%40antv%2Falgorithm@1.0.0".parse().unwrap();
        assert_eq!(slash, encoded);
    }

    /// A purl is read by its ecosystem's name rule, as a registry name is. An npm `/` needs
    /// an `@` scope, and a PyPI project has no namespace, whichever way the purl spells it.
    #[test]
    fn a_purl_is_read_by_its_ecosystems_name_rule() {
        for refused in [
            "pkg:npm/plain%2Fslash",
            "pkg:npm/babel/core",
            "pkg:pypi/%40a%2Fb",
            "pkg:pypi/ns/name",
        ] {
            assert!(refused.parse::<PackageKey>().is_err(), "{refused}");
        }
        assert!("pkg:pypi/ns/name@1.0".parse::<PackageRef>().is_err());
        let k: PackageKey = "pkg:pypi/requests".parse().unwrap();
        assert_eq!((k.namespace(), k.name()), (None, "requests"));
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

    /// A key the constructors refuse, built directly, prints as what it is not.
    #[test]
    fn a_key_that_makes_no_purl_says_so() {
        let invalid = PackageKey {
            ecosystem: Ecosystem::Npm,
            namespace: Some(String::new()),
            name: String::new(),
        };
        assert!(
            invalid.to_string().starts_with("<invalid purl: "),
            "{invalid}"
        );
        let reference = PackageRef {
            key: invalid,
            version: "1.0.0".to_owned(),
        };
        assert!(
            reference.to_string().starts_with("<invalid purl: "),
            "{reference}"
        );
    }

    /// A purl that does not parse, or names an ecosystem this build does not serve, is no
    /// key.
    #[test]
    fn a_purl_that_is_not_one_or_of_another_ecosystem_is_no_key() {
        for purl in ["not a purl", "pkg:cargo/serde"] {
            assert!(purl.parse::<PackageKey>().is_err(), "{purl}");
        }
        assert!("pkg:cargo/serde@1.0.0".parse::<PackageRef>().is_err());
    }
}
