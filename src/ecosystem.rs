//! Which registry answers a request, and what that registry does differently.
//!
//! Every ecosystem the proxy serves fills in one [`Registry`]. The table is the list of
//! them, so adding a third ecosystem is a new entry rather than a new arm in each of the
//! places that used to `match` on [`Ecosystem`].
//!
//! The answers here are a plain function of a path or a header, or a declaration: where a
//! version's publish time comes from, and which advisory streams list the ecosystem's
//! packages. Three dispatch points still match on [`Ecosystem`] directly, and each has a
//! reason:
//!
//! | Dispatch point | Why it is not a field yet |
//! |---|---|
//! | `proxy::upstream_url` | picks `Proxy`'s per-ecosystem upstream field |
//! | `proxy::fetch_and_store` | picks `Proxy`'s per-ecosystem client, and is `async` |
//! | `proxy::handle`'s `match document` | npm's arm goes on to publish times, intel and the rewrite; PyPI's returns |
//!
//! A field added here without an entry in every row of [`TABLE`] does not compile, which
//! is the property the table exists for.

pub mod npm;
pub mod pypi;

use crate::doctor::Client;
use crate::identity::Ecosystem;
use crate::intel::stream::{self, Stream};
use crate::lockfile::{Lockfile, Unread};
use crate::record::PackageMetadata;
use crate::route::{DocumentKind, RequestTarget};

/// Metadata the proxy fetched on its own behalf, as records. The outer error is the fetch,
/// the inner one the document; both are said in the log and neither is propagated.
pub type Fetched = Result<Result<PackageMetadata, String>, String>;

/// Where the policy reads a version's publish time from, for `cooldown_days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishTimeSource {
    /// The normaliser sets `published_at` on every record from the metadata document the
    /// client asked for. Nothing is fetched.
    Record,
    /// npm's full packument, fetched with `npm::Client::publish_times` because the
    /// abbreviated document clients ask for carries no `time` map. Only npm's row declares
    /// this: the fetch uses npm's client.
    FullPackument,
}

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

    /// Whether a request that is neither metadata nor an artifact is a resolver probing
    /// rather than a client installing, and is logged at DEBUG.
    pub other_is_probe: bool,

    /// Where a version's publish time comes from.
    pub publish_times: PublishTimeSource,

    /// The package-keyed advisory streams for this ecosystem. A grant scoped
    /// [`stream::Scope::Listed`] applies to the ecosystems whose row lists its stream.
    /// Catalogue streams such as KEV are keyed by CVE id, apply to every served ecosystem,
    /// and are not listed.
    ///
    /// Empty means `waharoa doctor` and the startup log report the ecosystem as served with
    /// no stream providing `match` or `malware`.
    pub streams: &'static [&'static Stream],

    /// Lockfiles this ecosystem's clients write, by file name, and how each is read.
    pub lockfiles: &'static [Lockfile],

    /// File names a client writes that no reader takes, and what to write instead.
    pub unread_lockfiles: &'static [Unread],

    /// The package managers `waharoa doctor` checks for this ecosystem.
    pub clients: &'static [Client],
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
    always_reachable: &[npm::DEFAULT_REGISTRY],
    classify_path: npm::classify_path,
    read_media_type: npm::document_from_content_type,
    // `/-/v1/search` and `/-/whoami` are a handful per install, and
    // `scripts/make/retry-matrix.sh` counts their INFO lines.
    other_is_probe: false,
    publish_times: PublishTimeSource::FullPackument,
    streams: &[&stream::OSV_NPM, &stream::DATADOG_NPM, &stream::GITHUB_NPM],
    lockfiles: npm::lockfile::LOCKFILES,
    unread_lockfiles: npm::lockfile::UNREAD,
    clients: npm::clients::CLIENTS,
};

pub const PYPI: Registry = Registry {
    ecosystem: Ecosystem::PyPI,
    // PEP 503 puts a project's index under `/simple/`. `/packages/` is where PyPI serves
    // its files, and the proxy keeps that path so a rewritten file URL round-trips: the
    // hash segments the index published are what locate the file upstream.
    prefixes: &["/simple/", "/packages/"],
    always_reachable: &[pypi::INDEX, pypi::FILES],
    classify_path: pypi::classify_path,
    read_media_type: pypi::document_from_content_type,
    // PEP 658 `<file>.metadata` requests.
    other_is_probe: true,
    // `pypi::normalize` reads each file's `upload-time`.
    publish_times: PublishTimeSource::Record,
    // OSV, Datadog and GitHub all publish PyPI advisories. None is fetched yet: TODO.md,
    // step 4 of the module directory item.
    streams: &[],
    // requirements.txt, uv.lock and poetry.lock are not read yet.
    lockfiles: &[],
    unread_lockfiles: &[],
    // pip and uv are not checked yet: TODO.md, "`doctor` checks five npm clients".
    clients: &[],
};

/// Every ecosystem the proxy routes, one row each. `intel::served` reads this, so a row
/// here is an ecosystem `waharoa doctor` reports advisory coverage for.
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
    use crate::record::DocumentDetail;

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
            of(Ecosystem::Npm).document(Some(npm::ABBREVIATED_ACCEPT)),
            Some(DocumentKind::Packument(DocumentDetail::Abbreviated)),
        );
        assert_eq!(of(Ecosystem::Npm).document(Some(pypi::SIMPLE_JSON)), None);
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(pypi::SIMPLE_JSON)),
            Some(DocumentKind::SimpleIndex),
        );
        assert_eq!(
            of(Ecosystem::PyPI).document(Some(npm::ABBREVIATED_ACCEPT)),
            None,
        );
    }

    /// A listed stream that the refresh does not load would grant coverage nothing fetches.
    #[test]
    fn every_listed_stream_is_one_the_refresh_loads() {
        for registry in TABLE {
            for listed in registry.streams {
                assert!(
                    stream::by_stream(listed.stream).is_some(),
                    "{} lists {}, which stream::ALL does not hold",
                    registry.ecosystem,
                    listed.stream
                );
            }
        }
    }

    /// A stream is listed exactly when one of its grants is scoped to the listing. Listed
    /// with no such grant, it would say nothing; granted and listed nowhere, it would say
    /// nothing either, and no test would notice.
    #[test]
    fn a_stream_is_listed_by_one_row_exactly_when_a_grant_is_scoped_to_its_listing() {
        for declared in stream::ALL {
            let listed_by = TABLE
                .iter()
                .filter(|registry| {
                    registry
                        .streams
                        .iter()
                        .any(|listed| listed.stream == declared.stream)
                })
                .count();
            let scoped = declared
                .grants
                .iter()
                .any(|grant| grant.scope == stream::Scope::Listed);
            assert_eq!(
                listed_by,
                usize::from(scoped),
                "{} is listed by {listed_by} rows",
                declared.stream
            );
        }
    }

    /// npm's client is what fetches a full packument, so another row declaring it would
    /// have npm asked about a package in a different registry.
    #[test]
    fn only_npm_reads_publish_times_from_a_full_packument() {
        let fetching: Vec<_> = TABLE
            .iter()
            .filter(|registry| registry.publish_times == PublishTimeSource::FullPackument)
            .map(|registry| registry.ecosystem)
            .collect();
        assert_eq!(fetching, [Ecosystem::Npm]);
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
