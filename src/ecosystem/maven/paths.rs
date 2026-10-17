//! What a Maven request path refers to, and where it goes upstream. mvn and Gradle ask
//! under [`PREFIX`] for `<group path>/<artifact>/maven-metadata.xml` and for
//! `<group path>/<artifact>/<version>/<file>`, the group's dots written as `/`.

use crate::identity::{Ecosystem, IdentityError, PackageKey};
use crate::route::{DocumentKind, RequestTarget};

use super::PREFIX;

/// The file naming an artifact's versions, and a group's plugin prefixes.
pub const METADATA: &str = "maven-metadata.xml";

/// Files beside another that hold its digest or signature, never decided on their own.
const SIDECARS: [&str; 5] = [".sha1", ".md5", ".sha256", ".sha512", ".asc"];

/// Files of a version a build reads for its dependencies, decided with its jar in step 4.3.
const DESCRIPTORS: [&str; 2] = [".pom", ".module"];

/// Split `group:artifact`, or `group/artifact` as a purl's namespace and name join, into
/// the group as the namespace and the artifact as the name. Errors for any other form.
pub fn split_name(name: &str) -> Result<(Option<String>, String), IdentityError> {
    let malformed = || {
        IdentityError::Malformed(format!(
            "`{name}` is not a Maven groupId:artifactId of letters, digits, `_`, `-` and `.`"
        ))
    };
    let (group, artifact) = name
        .split_once(':')
        .or_else(|| name.split_once('/'))
        .ok_or_else(malformed)?;
    if !is_coordinate(group) || !is_coordinate(artifact) {
        return Err(malformed());
    }
    Ok((Some(group.to_owned()), artifact.to_owned()))
}

/// Whether `part` is a groupId or artifactId as Maven's model validator allows one.
fn is_coordinate(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

/// A name in a policy selector as a key's registry name spells it: `group/artifact`.
pub fn canonical_name(name: &str) -> String {
    name.replacen(':', "/", 1)
}

/// The path of `key`'s directory on a repository: its group's dots as `/`, then its name.
pub fn directory(key: &PackageKey) -> String {
    let group = key.namespace().unwrap_or_default().replace('.', "/");
    format!("{group}/{}", key.name())
}

/// The file name of a version's jar, which a version's record names.
pub fn filename(key: &PackageKey, version: &str) -> String {
    format!("{}-{version}.jar", key.name())
}

/// The key a group path and an artifact directory name, `None` when they are not one.
fn key(group: &[&str], artifact: &str) -> Option<PackageKey> {
    if group.is_empty() {
        return None;
    }
    let name = format!("{}:{artifact}", group.join("."));
    PackageKey::from_registry_name(Ecosystem::Maven, &name).ok()
}

/// An artifact's `maven-metadata.xml` is its metadata, and any file in a version's
/// directory but a sidecar, a `.pom` and a `.module` is an artifact of that version.
pub fn classify_path(path: &str) -> RequestTarget {
    let path = path.split('?').next().unwrap_or(path);
    let Some(rest) = path.strip_prefix(PREFIX) else {
        return RequestTarget::Other;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return RequestTarget::Other;
    }
    match parts.as_slice() {
        [group @ .., artifact, file] if *file == METADATA => {
            key(group, artifact).map_or(RequestTarget::Other, RequestTarget::Metadata)
        }
        [group @ .., artifact, version, file] if is_artifact(file) => match key(group, artifact) {
            Some(key) => RequestTarget::Artifact {
                filename: (*file).to_owned(),
                claimed_version: (*version).to_owned(),
                key,
            },
            None => RequestTarget::Other,
        },
        _ => RequestTarget::Other,
    }
}

/// Whether `file` is decided as an artifact: not metadata, a sidecar or a descriptor.
fn is_artifact(file: &str) -> bool {
    !file.starts_with(METADATA)
        && !SIDECARS.iter().any(|sidecar| file.ends_with(sidecar))
        && !DESCRIPTORS
            .iter()
            .any(|descriptor| file.ends_with(descriptor))
}

/// A `maven-metadata.xml`'s `.sha1` or `.md5`: the document's path, and its digest. `None`
/// for any other path.
pub fn metadata_sidecar(path: &str) -> Option<(String, crate::ecosystem::Digest)> {
    let path = path.split('?').next().unwrap_or(path);
    let (document, digest): (&str, crate::ecosystem::Digest) = match path.rsplit_once('.') {
        Some((document, "sha1")) => (document, sha1),
        Some((document, "md5")) => (document, md5),
        _ => return None,
    };
    let named = document.ends_with(&format!("/{METADATA}"));
    (named && matches!(classify_path(document), RequestTarget::Metadata(_)))
        .then(|| (document.to_owned(), digest))
}

/// `bytes`' SHA-1 as hex, as a `.sha1` holds it.
pub fn sha1(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, bytes);
    crate::util::hex(digest.as_ref())
}

/// `bytes`' MD5 as hex, as a `.md5` holds it.
pub fn md5(bytes: &[u8]) -> String {
    use md5::Digest as _;
    crate::util::hex(&md5::Md5::digest(bytes))
}

/// Everything under [`PREFIX`] goes to the repository at `base`, under the same path.
pub fn upstream_url(base: &str, path_and_query: &str) -> String {
    let rest = crate::ecosystem::within(PREFIX, path_and_query).unwrap_or(path_and_query);
    format!("{base}{rest}")
}

/// The URL of the directory holding an artifact's version directories, from the upstream
/// URL of its `maven-metadata.xml`. `None` for any other.
pub fn versions_url(page: &str) -> Option<String> {
    let page = page.split('?').next().unwrap_or(page);
    page.strip_suffix(METADATA).map(str::to_owned)
}

/// `maven-metadata.xml` is `text/xml`, as repo1.maven.org serves it, or `application/xml`.
pub fn document_from_content_type(content_type: Option<&str>) -> Option<DocumentKind> {
    match crate::route::media_type(content_type)?.as_str() {
        "text/xml" | "application/xml" => Some(DocumentKind::MavenMetadata),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn lang3() -> PackageKey {
        PackageKey::from_registry_name(Ecosystem::Maven, "org.apache.commons:commons-lang3")
            .unwrap()
    }

    #[test]
    fn a_name_is_split_at_its_colon_or_its_slash() {
        for written in [
            "org.apache.commons:commons-lang3",
            "org.apache.commons/commons-lang3",
        ] {
            assert_eq!(
                split_name(written).unwrap(),
                (
                    Some("org.apache.commons".to_owned()),
                    "commons-lang3".to_owned()
                )
            );
        }
        for not in [
            "commons-lang3",
            ":commons-lang3",
            "org.apache.commons:",
            "org.apache commons:lang",
            "a:b:c",
            "org/apache:x",
        ] {
            assert!(split_name(not).is_err(), "{not}");
        }
        assert_eq!(lang3().registry_name(), "org.apache.commons/commons-lang3");
        assert_eq!(
            canonical_name("org.apache.commons:commons-lang3"),
            lang3().registry_name()
        );
        assert_eq!(
            lang3().to_string(),
            "pkg:maven/org.apache.commons/commons-lang3"
        );
    }

    #[test]
    fn an_artifact_s_metadata_is_its_metadata() {
        assert_eq!(
            classify_path("/maven/org/apache/commons/commons-lang3/maven-metadata.xml"),
            RequestTarget::Metadata(lang3())
        );
        assert_eq!(
            classify_path("/maven/commons-lang3/maven-metadata.xml"),
            RequestTarget::Other,
            "an artifact is in a group"
        );
        for other in [
            "/maven/org/apache/commons/commons-lang3/maven-metadata.xml.sha1",
            "/maven/org/apache/commons/commons-lang3/",
            "/maven/org//commons-lang3/maven-metadata.xml",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.pom",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.module",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.sha1",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.asc",
            "/maven/org/apache/commons/commons-lang3/3.17.0/maven-metadata.xml.md5",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.sha256",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.sha512",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.md5",
            "/maven/x/3.17.0/a.jar",
            "/npm/org/x/1/x-1.jar",
            "/maven/org/apache/comm ons/x/1/x-1.jar",
        ] {
            assert_eq!(classify_path(other), RequestTarget::Other, "{other}");
        }
    }

    /// A version's directory can hold a `.war`, an `.aar`, a distribution or a file named
    /// for no artifact; each is decided as the version's.
    #[test]
    fn any_other_file_of_a_version_is_its_artifact() {
        for file in [
            "commons-lang3-3.17.0.jar",
            "commons-lang3-3.17.0-sources.jar",
            "commons-lang3-3.17.0.war",
            "commons-lang3-3.17.0-bin.tar.gz",
            "anything.zip",
        ] {
            let path = format!("/maven/org/apache/commons/commons-lang3/3.17.0/{file}?x=1");
            assert_eq!(
                classify_path(&path),
                RequestTarget::Artifact {
                    filename: file.to_owned(),
                    claimed_version: "3.17.0".to_owned(),
                    key: lang3(),
                },
                "{file}"
            );
        }
    }

    #[test]
    fn a_path_goes_to_the_same_path_on_the_repository() {
        assert_eq!(
            upstream_url(
                "https://repo1.maven.org/maven2",
                "/maven/org/apache/commons/commons-lang3/maven-metadata.xml"
            ),
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
        assert_eq!(directory(&lang3()), "org/apache/commons/commons-lang3");
        assert_eq!(filename(&lang3(), "3.17.0"), "commons-lang3-3.17.0.jar");
        assert_eq!(
            versions_url("https://r.example/a/b/maven-metadata.xml?x"),
            Some("https://r.example/a/b/".to_owned())
        );
        assert_eq!(versions_url("https://r.example/a/b/x.pom"), None);
    }

    /// mvn asks for a `maven-metadata.xml`'s `.sha1`, and for its `.md5` when that is missing.
    #[test]
    fn a_metadata_file_s_sha1_and_md5_are_its_sidecars() {
        let (document, digest) =
            metadata_sidecar("/maven/org/apache/commons/commons-lang3/maven-metadata.xml.sha1?x=1")
                .expect("a sidecar");
        assert_eq!(
            document,
            "/maven/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
        assert_eq!(digest(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let (_, digest) =
            metadata_sidecar("/maven/org/apache/commons/commons-lang3/maven-metadata.xml.md5")
                .expect("a sidecar");
        assert_eq!(digest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        for other in [
            "/maven/org/apache/commons/commons-lang3/maven-metadata.xml.sha256",
            "/maven/org/apache/commons/commons-lang3/maven-metadata.xml",
            "/maven/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar.sha1",
            "/maven/commons-lang3/maven-metadata.xml.sha1",
            "/maven/org/x/not-maven-metadata.xml.sha1",
            "/maven/org/apache/commons/commons-lang3/maven-metadata",
        ] {
            assert!(metadata_sidecar(other).is_none(), "{other}");
        }
    }

    #[test]
    fn metadata_is_xml() {
        for xml in ["text/xml", "application/xml; charset=UTF-8"] {
            assert_eq!(
                document_from_content_type(Some(xml)),
                Some(DocumentKind::MavenMetadata)
            );
        }
        assert_eq!(document_from_content_type(Some("text/plain")), None);
        assert_eq!(document_from_content_type(None), None);
    }
}
