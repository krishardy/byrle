//! `byrle lockfile verify`: whether every artifact a lockfile locks is fetched through the
//! proxy, for a CI job to catch an install that went around it.
//! See docs/engineering_decisions/lockfile-verify.md.

use std::path::PathBuf;

use super::{LockedArtifact, LockfileError, lockfile_for, text_of};
use crate::env::Env;

/// Exit bit: an artifact is fetched from somewhere other than the proxy.
pub const ELSEWHERE: u8 = 1;
/// Exit bit: an artifact whose lockfile records no URL, so where it comes from is not known.
pub const UNRECORDED: u8 = 2;
/// Exit code, on its own: a lockfile does not read or records no URLs, or no proxy is named.
pub const UNREAD: u8 = 4;

/// Where a locked artifact is fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The proxy.
    Proxy,
    /// Somewhere else: an origin, or what the lockfile records when it is not an HTTP URL.
    Elsewhere(String),
    /// The lockfile records no URL, as pnpm does for the registry it was configured with.
    Unrecorded,
}

/// What `byrle lockfile verify` prints, and its exit code.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// For stderr: why nothing was verified.
    pub notes: Vec<String>,
    pub report: String,
    /// The OR of [`ELSEWHERE`] and [`UNRECORDED`], or [`UNREAD`] on its own.
    pub code: u8,
}

/// `byrle lockfile verify`: each artifact `lockfiles` lock, against the proxy at `proxy`,
/// or the environment's public URL.
pub fn run<L: Fn(&str) -> Option<std::ffi::OsString>>(
    lockfiles: &[PathBuf],
    proxy: Option<&str>,
    environment: &Env<L>,
) -> Verified {
    let unread = |note: String| Verified {
        notes: vec![note],
        report: String::new(),
        code: UNREAD,
    };
    let base = match proxy.map(str::to_owned).map_or_else(
        || environment.public_url().map_err(|e| e.to_string()),
        |proxy| Ok(Some(proxy)),
    ) {
        Ok(Some(base)) => base,
        Ok(None) => {
            return unread(format!(
                "no proxy to verify against: pass --proxy, or set {}",
                crate::env::PUBLIC_URL
            ));
        }
        Err(e) => return unread(e),
    };
    let base = match reqwest::Url::parse(&base) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => url,
        _ => return unread(format!("`{base}` is not an http or https URL")),
    };
    let mut report = String::new();
    let mut code = 0;
    for path in lockfiles {
        let routes = match routes(path, &base) {
            Ok(routes) => routes,
            Err(e) => return unread(e),
        };
        report.push_str(&render(path, &routes));
        for (_, route) in &routes {
            code |= match route {
                Route::Proxy => 0,
                Route::Elsewhere(_) => ELSEWHERE,
                Route::Unrecorded => UNRECORDED,
            };
        }
    }
    Verified {
        notes: Vec::new(),
        report,
        code,
    }
}

/// Each artifact the lockfile at `path` locks, labelled `name@version`, and its route to `base`.
/// Errors when the file does not read, or its format records no URLs.
fn routes(path: &std::path::Path, base: &reqwest::Url) -> Result<Vec<(String, Route)>, String> {
    let lockfile = lockfile_for(path).map_err(|e| e.to_string())?;
    let Some(urls) = lockfile.urls else {
        return Err(format!(
            "{}: {} records no artifact URLs, so where its packages come from cannot be verified",
            path.display(),
            lockfile.name
        ));
    };
    let text = text_of(path).map_err(|e| e.to_string())?;
    let artifacts = urls(&text).map_err(|reason| {
        LockfileError::Invalid {
            path: path.to_path_buf(),
            reason,
        }
        .to_string()
    })?;
    let npmjs_when_absent = lockfile
        .pins
        .as_ref()
        .is_some_and(|pins| pins.absent_is_off_proxy);
    Ok(artifacts
        .iter()
        .map(|artifact| {
            (
                label(artifact),
                route(artifact.url.as_deref(), base, npmjs_when_absent),
            )
        })
        .collect())
}

/// `name@version`.
fn label(artifact: &LockedArtifact) -> String {
    let (_, name, version) = &artifact.locked;
    format!("{name}@{version}")
}

/// Where an artifact whose lockfile records `url` is fetched from, given the proxy at `base`.
/// `npmjs_when_absent` is a format, bun's, that records no URL for registry.npmjs.org.
fn route(url: Option<&str>, base: &reqwest::Url, npmjs_when_absent: bool) -> Route {
    let Some(url) = url else {
        return match npmjs_when_absent {
            true => Route::Elsewhere("https://registry.npmjs.org".to_owned()),
            false => Route::Unrecorded,
        };
    };
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => parsed,
        _ => return Route::Elsewhere(url.to_owned()),
    };
    let origin = parsed.origin().ascii_serialization();
    let prefix = base.path().trim_end_matches('/');
    let under = parsed
        .path()
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    match origin == base.origin().ascii_serialization() && under {
        true => Route::Proxy,
        false => Route::Elsewhere(origin),
    }
}

/// One line for the lockfile at `path` with its counts, then one for each package and origin
/// fetched from elsewhere: a package's wheels from one origin are one line.
fn render(path: &std::path::Path, routes: &[(String, Route)]) -> String {
    let count = |wanted: fn(&Route) -> bool| routes.iter().filter(|(_, r)| wanted(r)).count();
    let mut out = format!(
        "{}: {} artifacts, {} through the proxy",
        path.display(),
        routes.len(),
        count(|r| *r == Route::Proxy)
    );
    let elsewhere = count(|r| matches!(r, Route::Elsewhere(_)));
    if elsewhere > 0 {
        out.push_str(&format!(", {elsewhere} from elsewhere"));
    }
    let unrecorded = count(|r| *r == Route::Unrecorded);
    if unrecorded > 0 {
        out.push_str(&format!(", {unrecorded} with no URL recorded"));
    }
    out.push('\n');
    let mut seen = std::collections::BTreeSet::new();
    for (label, route) in routes {
        if let Route::Elsewhere(from) = route
            && seen.insert((label, from))
        {
            out.push_str(&format!("  {label}\t{from}\n"));
        }
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::env::testing::with;

    fn base(url: &str) -> reqwest::Url {
        reqwest::Url::parse(url).unwrap()
    }

    /// The proxy's origin and path prefix is through the proxy; any other origin, a port
    /// or a path outside the prefix, or a spec that is not an HTTP URL is not.
    #[test]
    fn each_url_has_its_route() {
        let proxy = base("http://proxy.test/npm/");
        let elsewhere = |from: &str| Route::Elsewhere(from.to_owned());
        for (url, expected) in [
            (Some("http://proxy.test/npm/a/-/a-1.0.0.tgz"), Route::Proxy),
            (Some("http://proxy.test/npm"), Route::Proxy),
            (
                Some("http://proxy.test/npmx/a.tgz"),
                elsewhere("http://proxy.test"),
            ),
            (
                Some("http://proxy.test:8080/npm/a.tgz"),
                elsewhere("http://proxy.test:8080"),
            ),
            (
                Some("https://proxy.test/npm/a.tgz"),
                elsewhere("https://proxy.test"),
            ),
            (
                Some("https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
                elsewhere("https://registry.npmjs.org"),
            ),
            (
                Some("git+ssh://git@github.com/o/r.git"),
                elsewhere("git+ssh://git@github.com/o/r.git"),
            ),
            (Some("not a url"), elsewhere("not a url")),
            (None, Route::Unrecorded),
        ] {
            assert_eq!(route(url, &proxy, false), expected, "{url:?}");
        }
        assert_eq!(
            route(None, &proxy, true),
            elsewhere("https://registry.npmjs.org"),
            "bun writes no URL for npmjs.org"
        );
    }

    /// `name` holding `text`, in a directory of `label`'s own.
    fn written(label: &str, name: &str, text: &str) -> PathBuf {
        let path = crate::util::test_support::tempdir(label).join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Each format that records URLs, its counts and the artifacts from elsewhere, and the
    /// exit bits they set.
    #[test]
    fn each_lockfile_is_verified_against_the_proxy() {
        let npm = written(
            "verify-npm",
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},
                "node_modules/a":{"version":"1.0.0","resolved":"http://proxy.test/a/-/a-1.0.0.tgz"},
                "node_modules/b":{"version":"2.0.0","resolved":"https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}}"#,
        );
        let pnpm = written(
            "verify-pnpm",
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  \
             b@2.0.0:\n    resolution: {integrity: sha512-y, tarball: http://proxy.test/b/-/b-2.0.0.tgz}\n",
        );
        let bun = written(
            "verify-bun",
            "bun.lock",
            r#"{"lockfileVersion":1,"packages":{"a":["a@1.0.0","",{},"sha512-x"],
                "b":["b@2.0.0","http://proxy.test/b/-/b-2.0.0.tgz",{},"sha512-y"]}}"#,
        );
        let uv = written(
            "verify-uv",
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"idna\"\nversion = \"3.10\"\n\
             source = { registry = \"http://proxy.test/simple\" }\n\
             sdist = { url = \"http://proxy.test/packages/x/idna-3.10.tar.gz\" }\n\
             wheels = [{ url = \"https://files.pythonhosted.org/packages/y/idna-3.10-py3-none-any.whl\" }, \
             { url = \"https://files.pythonhosted.org/packages/z/idna-3.10-py2-none-any.whl\" }, {}]\n",
        );
        let verify = |path: &PathBuf| {
            run(
                std::slice::from_ref(path),
                Some("http://proxy.test"),
                &with(&[]),
            )
        };
        let npm_verified = verify(&npm);
        assert_eq!(npm_verified.code, ELSEWHERE);
        assert_eq!(
            npm_verified.report,
            format!(
                "{}: 2 artifacts, 1 through the proxy, 1 from elsewhere\n  b@2.0.0\thttps://registry.npmjs.org\n",
                npm.display()
            )
        );
        let pnpm_verified = verify(&pnpm);
        assert_eq!(pnpm_verified.code, UNRECORDED);
        assert!(
            pnpm_verified
                .report
                .ends_with("2 artifacts, 1 through the proxy, 1 with no URL recorded\n"),
            "{}",
            pnpm_verified.report
        );
        let bun_verified = verify(&bun);
        assert_eq!(bun_verified.code, ELSEWHERE);
        assert_eq!(
            bun_verified.report,
            format!(
                "{}: 2 artifacts, 1 through the proxy, 1 from elsewhere\n  a@1.0.0\thttps://registry.npmjs.org\n",
                bun.display()
            ),
            "bun's empty URL is npmjs.org, and its URL for b is the proxy's"
        );
        let uv_verified = verify(&uv);
        assert_eq!(uv_verified.code, ELSEWHERE | UNRECORDED);
        assert!(
            uv_verified
                .report
                .matches("idna@3.10\thttps://files.pythonhosted.org")
                .count()
                == 1,
            "{}",
            uv_verified.report
        );

        let both = run(&[npm.clone(), pnpm], Some("http://proxy.test"), &with(&[]));
        assert_eq!(both.code, ELSEWHERE | UNRECORDED);
        let through = run(&[npm], Some("https://registry.npmjs.org"), &with(&[]));
        assert!(
            through.report.contains("1 through the proxy"),
            "{}",
            through.report
        );
    }

    /// Real lockfiles with git, outside directory and tarball, and workspace dependencies:
    /// each is from elsewhere but the workspace, and `policy diff` reads only the registry's.
    #[test]
    fn git_and_path_dependencies_are_from_elsewhere() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lockfiles/unregistered/"
        );
        for (name, proxy, report, registry) in [
            (
                "package-lock.json",
                "https://registry.npmjs.org",
                "4 artifacts, 1 through the proxy, 3 from elsewhere\n\
                 \x20 is-number@7.0.0\tgit+ssh://git@github.com/jonschlinkert/is-number.git#98e8ff1da1a89f93d1397a24d7413ed15421c139\n\
                 \x20 localdir@1.0.0\t../localdir\n\
                 \x20 tarpkg@2.0.0\tfile:../tarpkg-2.0.0.tgz\n",
                "ms",
            ),
            (
                "bun.lock",
                "https://registry.npmjs.org",
                "4 artifacts, 0 through the proxy, 4 from elsewhere\n\
                 \x20 is-number@github:jonschlinkert/is-number#98e8ff1\tgithub:jonschlinkert/is-number#98e8ff1\n\
                 \x20 localdir@file:../localdir\tfile:../localdir\n\
                 \x20 ms@2.1.3\thttps://registry.npmjs.org\n\
                 \x20 tarpkg@../tarpkg-2.0.0.tgz\t../tarpkg-2.0.0.tgz\n",
                "ms",
            ),
            (
                "pnpm-lock.yaml",
                "https://registry.npmjs.org",
                "4 artifacts, 0 through the proxy, 3 from elsewhere, 1 with no URL recorded\n\
                 \x20 is-number@7.0.0\thttps://codeload.github.com\n\
                 \x20 localdir@file:../localdir\tfile:../localdir\n\
                 \x20 tarpkg@2.0.0\tfile:../tarpkg-2.0.0.tgz\n",
                "ms",
            ),
            (
                "yarn.lock",
                "https://registry.npmjs.org",
                "4 artifacts, 1 through the proxy, 3 from elsewhere\n\
                 \x20 is-number@7.0.0\thttps://codeload.github.com\n\
                 \x20 localdir@1.0.0\tfile:../localdir\n\
                 \x20 tarpkg@2.0.0\tfile:../tarpkg-2.0.0.tgz#3302cafef861b63a804358c6f27b02d011c3bcd2\n",
                "ms",
            ),
            (
                "uv.lock",
                "https://files.pythonhosted.org",
                "5 artifacts, 2 through the proxy, 3 from elsewhere\n\
                 \x20 localpy@1.0.0\t../localpy\n\
                 \x20 six@1.16.0\tgit+https://github.com/benjaminp/six?rev=1.16.0#65486e4383f9f411da95937451205d3c7b61b9e1\n\
                 \x20 tarpy@2.0.0\t../dist/tarpy-2.0.0.tar.gz\n",
                "idna",
            ),
        ] {
            let path = PathBuf::from(format!("{dir}{name}"));
            let verified = run(std::slice::from_ref(&path), Some(proxy), &with(&[]));
            assert_eq!(
                verified.report,
                format!("{}: {report}", path.display()),
                "{name}"
            );
            assert_eq!(verified.code & ELSEWHERE, ELSEWHERE, "{name}");
            let read = crate::lockfile::read(&path).expect("reads");
            assert_eq!(
                read.iter()
                    .map(|(_, name, _)| name.as_str())
                    .collect::<Vec<_>>(),
                [registry],
                "{name}"
            );
        }
    }

    /// The proxy defaults to the public URL. No proxy, one not HTTP, a format that records no
    /// URLs, and a file that does not read or parse are each an error on its own.
    #[test]
    fn what_cannot_be_verified_is_an_error() {
        let npm = written(
            "verify-env",
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"http://proxy.test/a/-/a-1.0.0.tgz"}}}"#,
        );
        let from_env = run(
            std::slice::from_ref(&npm),
            None,
            &with(&[(crate::env::PUBLIC_URL, "http://proxy.test")]),
        );
        assert_eq!(from_env.code, 0, "{from_env:?}");
        let poetry = written("verify-poetry", "poetry.lock", "");
        let broken = written("verify-broken", "package-lock.json", "{");
        let broken_uv = written("verify-broken-uv", "uv.lock", "[[package");
        let unreadable_env = crate::env::testing::with_unreadable(&[], crate::env::PUBLIC_URL);
        for (label, verified) in [
            (
                "no proxy",
                run(std::slice::from_ref(&npm), None, &with(&[])),
            ),
            (
                "unreadable env",
                run(std::slice::from_ref(&npm), None, &unreadable_env),
            ),
            (
                "not http",
                run(
                    std::slice::from_ref(&npm),
                    Some("ftp://proxy.test"),
                    &with(&[]),
                ),
            ),
            (
                "not a url",
                run(std::slice::from_ref(&npm), Some("proxy"), &with(&[])),
            ),
            (
                "no urls",
                run(&[poetry], Some("http://proxy.test"), &with(&[])),
            ),
            (
                "broken",
                run(&[broken], Some("http://proxy.test"), &with(&[])),
            ),
            (
                "broken uv",
                run(&[broken_uv], Some("http://proxy.test"), &with(&[])),
            ),
            (
                "missing",
                run(
                    &[PathBuf::from("/nonexistent/package-lock.json")],
                    Some("http://proxy.test"),
                    &with(&[]),
                ),
            ),
            (
                "unknown",
                run(
                    &[PathBuf::from("/nonexistent/Cargo.lock")],
                    Some("http://proxy.test"),
                    &with(&[]),
                ),
            ),
        ] {
            assert_eq!(verified.code, UNREAD, "{label}: {verified:?}");
            assert_eq!(verified.notes.len(), 1, "{label}");
            assert!(verified.report.is_empty(), "{label}");
        }
        let no_urls = run(
            &[written("verify-poetry2", "poetry.lock", "")],
            Some("http://proxy.test"),
            &with(&[]),
        );
        assert!(
            no_urls.notes[0].ends_with("cannot be verified"),
            "{:?}",
            no_urls.notes
        );
    }
}
