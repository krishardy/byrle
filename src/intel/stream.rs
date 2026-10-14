//! What a refresh knows about each advisory stream before it fetches anything.
//!
//! One [`Stream`] per stream, in [`all`]. `byrle refresh` does the fetching.
//! See docs/engineering_decisions/stream-descriptor-table.md.

use std::collections::BTreeSet;

use super::Capability;
use super::load::{Encoded, encode, encode_exploited};
use super::providers::osv::bundle::{self, Tally};
use super::providers::{datadog, github, kev};
use super::rows::Rows;
use crate::identity::Ecosystem;

/// The ecosystems one grant covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The ecosystems whose [`crate::ecosystem::Registry::streams`] lists this stream.
    Listed,
    /// Every ecosystem this build serves, for a catalogue keyed by CVE id.
    Served,
}

/// How a refresh gets a stream's bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// One unauthenticated GET of `url`, whose body is the bundle.
    Get,
    /// A POST of `query` to `url`, paged by cursor and joined into one JSON array.
    GithubGraphql { query: &'static str },
}

/// What one stream may say about the ecosystems in `scope`.
#[derive(Debug, Clone, Copy)]
pub struct Grant {
    pub scope: Scope,
    pub capabilities: &'static [Capability],
}

/// The rows a bundle parsed to, in the two shapes a load encodes.
#[derive(Debug, PartialEq)]
pub enum Payload {
    /// Advisory records, which [`encode`] writes.
    Advisories(Vec<Rows>),
    /// CVE ids a catalogue lists, which [`encode_exploited`] writes.
    Exploited(BTreeSet<String>),
}

impl Payload {
    /// The rows as a load stores them under `source`.
    pub fn encode(&self, source: &str) -> Encoded {
        match self {
            Self::Advisories(rows) => encode(source, rows),
            Self::Exploited(ids) => encode_exploited(source, ids),
        }
    }

    /// The records the other tables are built from once Postgres has keyed them. Empty for
    /// exploited ids, which have no child tables.
    pub fn rows(&self) -> &[Rows] {
        match self {
            Self::Advisories(rows) => rows,
            Self::Exploited(_) => &[],
        }
    }
}

/// One stream's bundle, read.
#[derive(Debug)]
pub struct Parsed {
    pub payload: Payload,
    /// What the parse counted, for the refresh to print.
    pub tally: Option<Tally>,
}

/// One advisory stream, as this build declares it.
#[derive(Debug, Clone, Copy)]
pub struct Stream {
    /// The name of the bundle in a snapshot, and the source of its rows in the store.
    pub stream: &'static str,
    /// Where the bundle is fetched from.
    pub url: &'static str,
    /// Bytes past which the fetch is refused.
    pub ceiling: usize,
    pub transport: Transport,
    /// What this stream may say, per ecosystem.
    pub grants: &'static [Grant],
    /// The bundle's bytes as rows.
    pub parse: fn(&[u8]) -> Result<Parsed, String>,
}

/// Match and malware, which OSV and Datadog both hold for the packages they list.
pub const MATCH_AND_MALWARE: &[Grant] = &[Grant {
    scope: Scope::Listed,
    capabilities: &[Capability::Match, Capability::Malware],
}];

/// Match, which GitHub's advisories hold. It publishes malware separately, and not here.
pub const MATCH: &[Grant] = &[Grant {
    scope: Scope::Listed,
    capabilities: &[Capability::Match],
}];

/// The bytes of a bundle as the rows it holds.
pub type Parse = fn(&[u8]) -> Result<Parsed, String>;

/// An ecosystem's OSV bundle at `url`: every vulnerability and malware record OSV holds for
/// it. `parse` is [`osv_bundle`] for that ecosystem.
pub const fn osv(stream: &'static str, url: &'static str, parse: Parse) -> Stream {
    Stream {
        stream,
        url,
        ceiling: bundle::MAX_BUNDLE_BYTES,
        transport: Transport::Get,
        grants: MATCH_AND_MALWARE,
        parse,
    }
}

/// An ecosystem's Datadog manifest at `url`. `parse` is [`datadog_manifest`] for it.
pub const fn datadog(stream: &'static str, url: &'static str, parse: Parse) -> Stream {
    Stream {
        stream,
        url,
        ceiling: datadog::MAX_MANIFEST_BYTES,
        transport: Transport::Get,
        grants: MATCH_AND_MALWARE,
        parse,
    }
}

/// An ecosystem's GitHub advisories, asked for with `query`, a signal stream beside OSV.
/// `parse` is [`github_advisories`] for it.
pub const fn github(stream: &'static str, query: &'static str, parse: Parse) -> Stream {
    Stream {
        stream,
        url: github::ENDPOINT,
        ceiling: github::MAX_BYTES,
        transport: Transport::GithubGraphql { query },
        grants: MATCH,
        parse,
    }
}

/// `bytes`, an OSV bundle, as `ecosystem`'s rows.
pub fn osv_bundle(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    bundle::read_bundle(ecosystem, bytes)
        .map(|bundle| Parsed {
            payload: Payload::Advisories(bundle.rows),
            tally: Some(bundle.tally),
        })
        .map_err(|e| e.to_string())
}

/// `bytes`, a Datadog manifest, as `ecosystem`'s rows.
pub fn datadog_manifest(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    datadog::parse(ecosystem, bytes)
        .map(|rows| Parsed {
            payload: Payload::Advisories(rows),
            tally: None,
        })
        .map_err(|e| e.to_string())
}

/// `bytes`, GitHub's advisories, as `ecosystem`'s rows.
pub fn github_advisories(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    github::parse(ecosystem, bytes)
        .map(|rows| Parsed {
            payload: Payload::Advisories(rows),
            tally: None,
        })
        .map_err(|e| e.to_string())
}

/// CISA's KEV catalogue, which covers no one ecosystem.
const KEV: Stream = Stream {
    stream: kev::STREAM,
    url: kev::CATALOGUE,
    ceiling: kev::MAX_CATALOGUE_BYTES,
    transport: Transport::Get,
    grants: &[Grant {
        scope: Scope::Served,
        capabilities: &[Capability::Enrich],
    }],
    parse: |bytes| {
        kev::parse(bytes)
            .map(|ids| Parsed {
                payload: Payload::Exploited(ids),
                tally: None,
            })
            .map_err(|e| e.to_string())
    },
};

/// The order a refresh loads providers in, by the prefix of their streams' names.
const PROVIDERS: [&str; 4] = ["osv/", "cisa/", "datadog/", "github/"];

/// Every stream a refresh loads, in the order it loads them: each ecosystem's from its row
/// of [`crate::ecosystem::TABLE`], and KEV, by provider and then by row.
pub fn all() -> &'static [Stream] {
    static ALL: std::sync::OnceLock<Vec<Stream>> = std::sync::OnceLock::new();
    ALL.get_or_init(|| {
        let mut all: Vec<Stream> = crate::ecosystem::TABLE
            .iter()
            .flat_map(|row| row.streams.iter().map(|stream| **stream))
            .chain([KEV])
            .collect();
        all.sort_by_key(|stream| {
            PROVIDERS
                .iter()
                .position(|provider| stream.stream.starts_with(provider))
        });
        all
    })
}

/// The stream a snapshot records under `stream`, or `None` for one this build does not know.
pub fn by_stream(stream: &str) -> Option<&'static Stream> {
    all().iter().find(|s| s.stream == stream)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::intel::load::Kind;

    fn declared(stream: &str) -> &'static Stream {
        by_stream(stream).expect("this build declares the stream")
    }

    #[test]
    fn a_stream_this_build_does_not_declare_is_not_found() {
        assert_eq!(
            all().iter().map(|s| s.stream).collect::<Vec<_>>(),
            [
                "osv/npm",
                "osv/pypi",
                "osv/cargo",
                "cisa/kev",
                "datadog/npm",
                "datadog/pypi",
                "github/npm",
                "github/pypi"
            ]
        );
        assert!(by_stream("osv/gem").is_none());
        assert!(by_stream("osv").is_none());
    }

    #[test]
    fn each_stream_declares_the_url_and_ceiling_its_module_gives() {
        for (stream, url, ceiling) in [
            (
                bundle::NPM_STREAM,
                bundle::NPM_BUNDLE,
                bundle::MAX_BUNDLE_BYTES,
            ),
            (kev::STREAM, kev::CATALOGUE, kev::MAX_CATALOGUE_BYTES),
            (
                datadog::NPM_STREAM,
                datadog::NPM_MANIFEST,
                datadog::MAX_MANIFEST_BYTES,
            ),
        ] {
            let declared = declared(stream);
            assert_eq!(declared.url, url);
            assert_eq!(declared.ceiling, ceiling);
        }
    }

    #[test]
    fn advisories_encode_as_advisories_and_carry_the_rows_the_child_tables_are_built_from() {
        let parsed = (declared(datadog::NPM_STREAM).parse)(br#"{"vant": ["2.13.3"], "0h": null}"#)
            .expect("the manifest parses");
        assert_eq!(parsed.payload.rows().len(), 2);
        assert!(
            parsed.tally.is_none(),
            "a manifest counts nothing for the refresh to print"
        );
        let encoded = parsed.payload.encode(datadog::NPM_STREAM);
        assert_eq!(encoded.kind, Kind::Advisories);
        assert_eq!(encoded.source, "datadog/npm");
    }

    #[test]
    fn exploited_ids_encode_as_exploited_and_have_no_rows() {
        let catalogue = br#"{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}"#;
        let parsed = (declared(kev::STREAM).parse)(catalogue).expect("the catalogue parses");
        assert_eq!(
            parsed.payload,
            Payload::Exploited(BTreeSet::from(["CVE-2021-44228".to_owned()]))
        );
        assert!(
            parsed.payload.rows().is_empty(),
            "exploited ids have no child tables"
        );
        let encoded = parsed.payload.encode(kev::STREAM);
        assert_eq!(encoded.kind, Kind::Exploited);
        assert_eq!(encoded.source, "cisa/kev");
    }

    /// The one stream whose parse counts records for the refresh to print.
    #[test]
    fn the_osv_bundle_parses_to_advisories_and_a_tally() {
        let path = format!(
            "{}/tests/fixtures/osv/bundle.zip",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(path).expect("the fixture is present");
        let parsed = (declared(bundle::NPM_STREAM).parse)(&bytes).expect("the bundle reads");
        let tally = parsed.tally.expect("the bundle counts its records");
        assert_eq!(tally.records(), 7);
        assert_eq!(tally.withdrawn, 1);
        assert_eq!(
            parsed.payload.rows().len(),
            6,
            "the withdrawn record is counted and not stored"
        );
        assert_eq!(
            parsed.payload.encode(bundle::NPM_STREAM).kind,
            Kind::Advisories
        );
    }

    /// The shim turns each module's error type into the string the refresh records as
    /// `NotLoaded::error`.
    #[test]
    fn a_bundle_that_does_not_read_gives_the_error_as_a_string() {
        for (stream, bytes) in [
            (bundle::NPM_STREAM, &b"not a zip"[..]),
            (kev::STREAM, &b"not json"[..]),
            (datadog::NPM_STREAM, &b"not json"[..]),
        ] {
            let error = (declared(stream).parse)(bytes).expect_err("the bundle does not read");
            assert!(!error.is_empty(), "{stream} gives no error text");
        }
    }

    /// Every stream's reader refuses a body that is not its document, and GitHub's reads a
    /// page into advisory rows.
    #[test]
    fn each_stream_reads_its_own_document_only() {
        for stream in all() {
            assert!(
                (stream.parse)(b"not a document").is_err(),
                "{}",
                stream.stream
            );
        }
        let page = br#"[{"data": {"securityVulnerabilities": {"nodes": [
            {"package": {"name": "a"}, "vulnerableVersionRange": "< 1.0.0",
             "advisory": {"ghsaId": "GHSA-1", "identifiers": [], "withdrawnAt": null}}]}}}]"#;
        let parsed =
            (declared(crate::intel::providers::github::NPM_STREAM).parse)(page).expect("a page");
        assert!(matches!(parsed.payload, Payload::Advisories(rows) if rows.len() == 1));
    }

    /// Each provider's constructor gives its ceiling, transport and grants, whatever the
    /// ecosystem: the adapters' streams are built with them as constants.
    #[test]
    fn a_provider_constructor_fills_in_what_the_provider_shares() {
        let parse: Parse = |_| Err("unread".to_owned());
        let osv = osv("osv/x", "https://osv.example/x.zip", parse);
        assert_eq!(
            (osv.ceiling, osv.grants.len(), osv.url),
            (bundle::MAX_BUNDLE_BYTES, 1, "https://osv.example/x.zip")
        );
        assert!(matches!(osv.transport, Transport::Get));
        let datadog = datadog("datadog/x", "https://datadog.example/x", parse);
        assert_eq!(datadog.ceiling, datadog::MAX_MANIFEST_BYTES);
        assert!(matches!(datadog.transport, Transport::Get));
        let github = github("github/x", "query", parse);
        assert_eq!(
            (github.ceiling, github.url),
            (github::MAX_BYTES, github::ENDPOINT)
        );
        assert!(matches!(
            github.transport,
            Transport::GithubGraphql { query: "query" }
        ));
        assert_eq!(github.grants[0].capabilities, MATCH[0].capabilities);
        assert!((github.parse)(b"").is_err());
    }
}
