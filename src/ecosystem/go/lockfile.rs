//! `go.sum` and `go.work.sum`, for `byrle policy diff`, `explain`, `warm` and
//! `lockfile verify`. Only a zip's line locks a version: go reads the `go.mod` of versions
//! it never builds, and the proxy never refuses a `go.mod`. Neither file records a URL.

use std::collections::BTreeSet;

use super::PREFIX;
use super::paths::{escape, filename};
use super::wire::is_version;
use crate::identity::Ecosystem;
use crate::lockfile::{Locked, LockedArtifact, Lockfile, Platform, Unread};

/// The files go writes checksums to, a module's and a workspace's, and their readers.
pub const LOCKFILES: &[Lockfile] = &[sums("go.sum"), sums("go.work.sum")];

/// A file of go's checksum lines named `name`, and its readers.
const fn sums(name: &'static str) -> Lockfile {
    Lockfile {
        name,
        read: packages,
        artifacts: Some(zips),
        urls: Some(zips),
        pins: None,
        repository: None,
    }
}

/// File names go writes that no reader here takes.
pub const UNREAD: &[Unread] = &[];

/// What follows a version on the line of its `go.mod`.
const GO_MOD: &str = "/go.mod";

/// Each module version whose zip the text records, in file order, or the first line that
/// is not a `go.sum` line.
fn zip_lines(text: &str) -> Result<Vec<(&str, &str)>, String> {
    let mut found = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [module, version, hash] = fields.as_slice() else {
            if fields.is_empty() {
                continue;
            }
            return Err(format!("line {}: not `<module> <version> <hash>`", at + 1));
        };
        let (version, zip) = match version.strip_suffix(GO_MOD) {
            Some(version) => (version, false),
            None => (*version, true),
        };
        if !is_version(version) || !hash.starts_with("h1:") {
            return Err(format!("line {}: `{line}` is not a go.sum line", at + 1));
        }
        if zip {
            found.push((*module, version));
        }
    }
    Ok(found)
}

fn locked(module: &str, version: &str) -> Locked {
    (
        Ecosystem::Go.as_str().to_owned(),
        module.to_owned(),
        version.to_owned(),
    )
}

/// Every module version whose zip the file records.
fn packages(text: &str) -> Result<BTreeSet<Locked>, String> {
    Ok(zip_lines(text)?
        .into_iter()
        .map(|(module, version)| locked(module, version))
        .collect())
}

/// For `byrle warm` and `byrle lockfile verify`: each zip at the path the proxy serves it.
/// No URL is recorded; `GOPROXY` says where go fetched it.
fn zips(text: &str) -> Result<Vec<LockedArtifact>, String> {
    Ok(zip_lines(text)?
        .into_iter()
        .map(|(module, version)| LockedArtifact {
            locked: locked(module, version),
            path: format!(
                "{PREFIX}{}/@v/{}",
                escape(module),
                filename(&escape(version))
            ),
            platform: Platform::default(),
            url: None,
        })
        .collect())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// go 1.27.2's `go get` of quote, toml and jwt on 2026-10-16, and a lone `go.mod` line.
    const SUM: &str = "\
github.com/BurntSushi/toml v1.4.0 h1:kuoIxZQy2WRRk1pttg9asf+WVv6tWQuBNVmK8+nqPr0=
github.com/BurntSushi/toml v1.4.0/go.mod h1:ukJfTF/6rtPPRCnwkur4qwRxa8vTRFBF0uk2lLoLwho=
github.com/golang-jwt/jwt v3.2.2+incompatible h1:IfV12K8xAKAnZqdXVzCZ+TOjboZ2keLg81eXfW3O+oY=
github.com/golang-jwt/jwt v3.2.2+incompatible/go.mod h1:8pz2t5EyA70fFQQSrl6XZXzqecmYZeUEB8OUGHkxJ+I=
golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c h1:qgOY6WgZOaTkIIMiVjBQcw93ERBE4m30iBm00nkL0i8=
golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
rsc.io/quote v1.5.2 h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=
rsc.io/quote v1.5.2/go.mod h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=
rsc.io/sampler v1.3.0 h1:7uVkIFmeBqHfdjD+gZwtXXI+RODJ2Wc4O7MPEh/QiW4=
rsc.io/sampler v1.3.0/go.mod h1:T1hPZKmBbMNahiBKFy5HrXp6adAjACjK9JXDnKaTXpA=
rsc.io/sampler v1.2.0/go.mod h1:T1hPZKmBbMNahiBKFy5HrXp6adAjACjK9JXDnKaTXpA=

";

    #[test]
    fn only_a_version_with_a_zip_line_is_locked() {
        let locked: Vec<Locked> = packages(SUM).expect("reads").into_iter().collect();
        let names: Vec<(&str, &str)> = locked
            .iter()
            .map(|(_, module, version)| (module.as_str(), version.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("github.com/BurntSushi/toml", "v1.4.0"),
                ("github.com/golang-jwt/jwt", "v3.2.2+incompatible"),
                ("golang.org/x/text", "v0.0.0-20170915032832-14c0d48ead0c"),
                ("rsc.io/quote", "v1.5.2"),
                ("rsc.io/sampler", "v1.3.0"),
            ]
        );
        assert!(locked.iter().all(|(ecosystem, _, _)| ecosystem == "golang"));
    }

    /// Each locked version makes a purl, its module's case and `+incompatible` kept.
    #[test]
    fn each_locked_version_makes_its_purl() {
        let listed = packages(SUM).expect("reads").into_iter().map(|l| (None, l));
        let references = crate::lockfile::references(listed);
        assert_eq!(references.len(), 5);
        let (_, toml, version, _) = &references[0];
        assert_eq!(toml.key().namespace(), Some("github.com/BurntSushi"));
        assert_eq!(version, "v1.4.0");
        assert_eq!(references[1].1.version(), "v3.2.2+incompatible");
    }

    /// The path is escaped as go asks for it. No URL is recorded.
    #[test]
    fn warm_and_verify_ask_for_each_zip_at_the_proxy_s_path() {
        let found = zips(SUM).expect("reads");
        let paths: Vec<&str> = found.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/go/github.com/!burnt!sushi/toml/@v/v1.4.0.zip",
                "/go/github.com/golang-jwt/jwt/@v/v3.2.2+incompatible.zip",
                "/go/golang.org/x/text/@v/v0.0.0-20170915032832-14c0d48ead0c.zip",
                "/go/rsc.io/quote/@v/v1.5.2.zip",
                "/go/rsc.io/sampler/@v/v1.3.0.zip",
            ]
        );
        assert!(found.iter().all(|a| a.url.is_none()));
        assert!(
            paths.iter().all(|path| matches!(
                super::super::classify_path(path),
                crate::route::RequestTarget::Artifact { .. }
            )),
            "the proxy reads each as a zip"
        );
    }

    /// A workspace's `go.work.sum` is read as a module's `go.sum` is.
    #[test]
    fn both_files_are_read_alike() {
        let names: Vec<&str> = LOCKFILES.iter().map(|lockfile| lockfile.name).collect();
        assert_eq!(names, ["go.sum", "go.work.sum"]);
        let work = sums("go.work.sum");
        assert_eq!((work.read)(SUM), packages(SUM));
        for read in [work.artifacts, work.urls] {
            assert_eq!(read.expect("set")(SUM), zips(SUM));
        }
        assert!(work.pins.is_none());
    }

    #[test]
    fn a_line_that_is_not_a_go_sum_line_is_an_error() {
        for (text, error) in [
            (
                "rsc.io/quote v1.5.2\n",
                "line 1: not `<module> <version> <hash>`",
            ),
            (
                "\nrsc.io/quote 1.5.2 h1:x=\n",
                "line 2: `rsc.io/quote 1.5.2 h1:x=` is not a go.sum line",
            ),
            (
                "rsc.io/quote v1.5.2 h2:x=\n",
                "line 1: `rsc.io/quote v1.5.2 h2:x=` is not a go.sum line",
            ),
        ] {
            assert_eq!(packages(text).expect_err(text), error);
            assert_eq!(zips(text).expect_err(text), error);
        }
        assert!(packages("").expect("reads").is_empty());
    }
}
