//! Which registry answers a request, and what that registry does differently.
//!
//! Every ecosystem the proxy serves fills in one [`Registry`]. The table is the list of
//! them, so adding a third ecosystem is a new entry rather than a new arm in each of the
//! places that used to `match` on [`Ecosystem`].
//!
//! Only the answers that are a plain function of a path or a header live here. Four
//! dispatch points still match on [`Ecosystem`] directly, and each has a reason:
//!
//! | Dispatch point | Why it is not a field yet |
//! |---|---|
//! | `proxy::upstream_url` | reads `Proxy`'s per-ecosystem upstream fields |
//! | `proxy::fetch_and_store` | `async`, and reads `Proxy`'s clients |
//! | `proxy::handle`'s `match document` | npm's arm is written inline in `handle`, not as a function |
//! | `proxy::publish_times_for` | does not match at all: it asks npm for every ecosystem, which TODO.md records |
//!
//! A field added here without an entry in every row of [`TABLE`] does not compile, which
//! is the property the table exists for.

use crate::identity::Ecosystem;
use crate::route::{DocumentKind, RequestTarget};

/// What one ecosystem answers.
pub struct Registry {
    /// The ecosystem this row is for.
    pub ecosystem: Ecosystem,

    /// Path prefixes this registry claims. Empty means it answers whatever no other
    /// registry claimed: see [`ROOT`].
    ///
    /// A prefix claims a path whatever the path turns out to name: `/simple/` itself and
    /// `/packages/nonsense` are PyPI's to answer even though neither names a project.
    /// Without that they would be forwarded to the npm registry, which is not where the
    /// client is looking.
    pub prefixes: &'static [&'static str],

    /// Origins the proxy may fetch from for this ecosystem whatever the operator
    /// configured, because they are where the ecosystem's own packages live.
    pub always_reachable: &'static [&'static str],

    /// What a request path under this registry refers to.
    pub classify_path: fn(&str) -> RequestTarget,

    /// Which metadata document a response body is, read from its `Content-Type`.
    pub read_media_type: fn(Option<&str>) -> Option<DocumentKind>,
}

impl Registry {
    /// Whether this registry claims `path`.
    ///
    /// The query is dropped first, so `/simple/requests/?foo=1` is claimed. `/simple` and
    /// `/packages` without the trailing slash are npm packages by those names, and
    /// `npm::key_from_name` no longer turns `/simple/requests` into
    /// `pkg:npm/simple/requests`, so nothing npm can serve lives under either prefix.
    pub fn serves(&self, path: &str) -> bool {
        let path = path.split('?').next().unwrap_or(path);
        self.prefixes.iter().any(|prefix| path.starts_with(prefix))
    }

    /// What `path` refers to, in this registry's spelling.
    pub fn classify(&self, path: &str) -> RequestTarget {
        (self.classify_path)(path)
    }

    /// Which metadata document a body with this `Content-Type` is, if any.
    pub fn document(&self, content_type: Option<&str>) -> Option<DocumentKind> {
        (self.read_media_type)(content_type)
    }
}

/// The registry that answers a path no other registry claimed.
///
/// npm, because that is where a client configured with `registry=http://proxy/` looks: it
/// asks for `/lodash`, with no prefix to claim. Stated here rather than left as the `else`
/// of a prefix test, so a third ecosystem's prefix cannot lose to npm by falling through.
pub const ROOT: Ecosystem = Ecosystem::Npm;

pub const NPM: Registry = Registry {
    ecosystem: Ecosystem::Npm,
    prefixes: &[],
    always_reachable: &[crate::npm::DEFAULT_REGISTRY],
    classify_path: crate::npm::classify_path,
    read_media_type: crate::npm::document_from_content_type,
};

pub const PYPI: Registry = Registry {
    ecosystem: Ecosystem::PyPI,
    // The index and the files it points at are separate hosts, so both are claimed.
    prefixes: &["/simple/", "/packages/"],
    always_reachable: &[crate::pypi::INDEX, crate::pypi::FILES],
    classify_path: crate::pypi::classify_path,
    read_media_type: crate::pypi::document_from_content_type,
};

/// Every ecosystem the proxy routes, one row each.
pub const TABLE: &[Registry] = &[NPM, PYPI];

/// The row for `ecosystem`.
///
/// Panics if the table has no row for it, which `every_expressible_ecosystem_has_a_row`
/// makes unreachable.
pub fn of(ecosystem: Ecosystem) -> &'static Registry {
    TABLE
        .iter()
        .find(|registry| registry.ecosystem == ecosystem)
        .expect("every ecosystem has a row in ecosystem::TABLE")
}

/// The row that answers `path`: the one whose prefixes claim it, else [`ROOT`]'s.
pub fn serving(path: &str) -> &'static Registry {
    TABLE
        .iter()
        .find(|registry| registry.serves(path))
        .unwrap_or_else(|| of(ROOT))
}

#[cfg(test)]
mod table {
    use super::*;
    use crate::record::PackumentDetail;

    /// The property the table exists for. A variant with no row makes `of` panic, and
    /// `of` is on the request path.
    #[test]
    fn every_expressible_ecosystem_has_a_row() {
        for ecosystem in Ecosystem::EXPRESSIBLE {
            let rows = TABLE
                .iter()
                .filter(|registry| registry.ecosystem == ecosystem)
                .count();
            assert_eq!(rows, 1, "{ecosystem} has {rows} rows in TABLE");
        }
        assert_eq!(TABLE.len(), Ecosystem::EXPRESSIBLE.len());
    }

    /// Exactly one row may fall through, or a path with no prefix has two answers.
    #[test]
    fn one_row_claims_no_prefix_and_it_is_the_root() {
        let rootless: Vec<_> = TABLE
            .iter()
            .filter(|registry| registry.prefixes.is_empty())
            .map(|registry| registry.ecosystem)
            .collect();
        assert_eq!(rootless, vec![ROOT]);
    }

    /// Two rows claiming the same prefix would make `serving` depend on table order.
    #[test]
    fn no_prefix_is_claimed_twice() {
        let mut claimed: Vec<&str> = TABLE
            .iter()
            .flat_map(|registry| registry.prefixes.iter().copied())
            .collect();
        let before = claimed.len();
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(claimed.len(), before, "a prefix is claimed by two rows");
    }

    #[test]
    fn a_prefixed_path_goes_to_the_row_that_claims_it() {
        for path in [
            "/simple/",
            "/simple/requests/",
            "/simple/nonsense",
            "/packages/a/b/c/requests-2.32.3-py3-none-any.whl",
            "/packages/nonsense",
            "/simple/requests/?foo=1",
        ] {
            assert_eq!(serving(path).ecosystem, Ecosystem::PyPI, "{path}");
        }
    }

    #[test]
    fn an_unclaimed_path_goes_to_the_root() {
        for path in [
            "/lodash",
            "/@babel%2fcore",
            "/lodash/-/lodash-4.17.21.tgz",
            "/simple",
            "/packages",
            "/-/v1/search?text=lodash",
            "/",
        ] {
            assert_eq!(serving(path).ecosystem, ROOT, "{path}");
        }
    }

    #[test]
    fn of_answers_with_the_row_it_was_asked_for() {
        for ecosystem in Ecosystem::EXPRESSIBLE {
            assert_eq!(of(ecosystem).ecosystem, ecosystem);
        }
    }

    /// Each row reads its own ecosystem's media types and no other's.
    #[test]
    fn each_row_reads_only_its_own_media_types() {
        assert_eq!(
            of(Ecosystem::Npm).document(Some(crate::npm::ABBREVIATED_ACCEPT)),
            Some(DocumentKind::Packument(PackumentDetail::Abbreviated)),
        );
        assert_eq!(
            of(Ecosystem::Npm).document(Some(crate::pypi::SIMPLE_JSON)),
            None
        );
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(crate::pypi::SIMPLE_JSON)),
            Some(DocumentKind::SimpleIndex),
        );
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(crate::npm::ABBREVIATED_ACCEPT)),
            None,
        );
    }

    /// `ReachableOrigins` normalises each of these, and a row with none would leave that
    /// ecosystem's own packages unreachable under the default policy.
    #[test]
    fn every_row_names_at_least_one_https_origin() {
        for registry in TABLE {
            assert!(
                !registry.always_reachable.is_empty(),
                "{} names no origin of its own",
                registry.ecosystem
            );
            for origin in registry.always_reachable {
                assert!(origin.starts_with("https://"), "{origin}");
                assert!(!origin.ends_with('/'), "{origin}");
            }
        }
    }
}
