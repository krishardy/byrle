//! What a refresh knows about each advisory stream before it fetches anything.
//!
//! One [`Stream`] per stream, in [`ALL`], holding the facts a refresh needs: where the
//! bundle is, how large it may be, what it may say once loaded, and how its bytes become
//! rows.
//!
//! Each stream is its own source in the store, so one stream's load replaces its own rows
//! and nothing else. A stream that does not load keeps its last load, and the others load
//! without it: `osv/pypi` failing does not hold back `osv/npm`.
//!
//! This is the declaration side. `waharoa refresh` does the fetching, because a fetch is
//! network I/O and everything here is decidable from the bytes alone.
//!
//! Mirroring is not here. Serving a stream from a local copy is tracked separately; see
//! "Local mirrors for all streams" in `TODO.md`.

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
    /// The ecosystems whose [`crate::ecosystem::Registry::streams`] lists this stream. A
    /// package-keyed stream is listed by the ecosystem its packages are in.
    Listed,
    /// Every ecosystem this build serves. A catalogue entry carries a CVE id and no package
    /// identifier, so what it says applies wherever a finding names that id.
    Served,
}

/// How a refresh gets a stream's bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// One unauthenticated GET of `url`, whose body is the bundle.
    Get,
    /// A POST of `query` to `url` with `Authorization: bearer`, paged by cursor
    /// until GitHub reports no next page. The response bodies are concatenated into one JSON
    /// array, so `parse` still reads one buffer, and `ceiling` bounds that whole array.
    /// The token comes from `crate::env::GITHUB_TOKEN`; without it the stream does not load.
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
    /// What the parse counted, for the refresh to print. `None` for a stream that counts
    /// nothing.
    pub tally: Option<Tally>,
}

/// One advisory stream, as this build declares it.
#[derive(Debug)]
pub struct Stream {
    /// The name a snapshot records the bundle under, and the source its rows are stored
    /// under.
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
const MATCH_AND_MALWARE: &[Grant] = &[Grant {
    scope: Scope::Listed,
    capabilities: &[Capability::Match, Capability::Malware],
}];

/// OSV's npm bundle: every npm vulnerability and malware record OSV holds.
pub const OSV_NPM: Stream = Stream {
    stream: bundle::NPM_STREAM,
    url: bundle::NPM_BUNDLE,
    ceiling: bundle::MAX_BUNDLE_BYTES,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| osv_bundle(Ecosystem::Npm, bytes),
};

/// OSV's PyPI bundle: every PyPI vulnerability and malware record OSV holds.
pub const OSV_PYPI: Stream = Stream {
    stream: bundle::PYPI_STREAM,
    url: bundle::PYPI_BUNDLE,
    ceiling: bundle::MAX_BUNDLE_BYTES,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| osv_bundle(Ecosystem::PyPI, bytes),
};

fn osv_bundle(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    bundle::read_bundle(ecosystem, bytes)
        .map(|bundle| Parsed {
            payload: Payload::Advisories(bundle.rows),
            tally: Some(bundle.tally),
        })
        .map_err(|e| e.to_string())
}

/// CISA's KEV catalogue.
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

/// Datadog's npm manifest.
pub const DATADOG_NPM: Stream = Stream {
    stream: datadog::NPM_STREAM,
    url: datadog::NPM_MANIFEST,
    ceiling: datadog::MAX_MANIFEST_BYTES,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| datadog_manifest(Ecosystem::Npm, bytes),
};

/// Datadog's PyPI manifest.
pub const DATADOG_PYPI: Stream = Stream {
    stream: datadog::PYPI_STREAM,
    url: datadog::PYPI_MANIFEST,
    ceiling: datadog::MAX_MANIFEST_BYTES,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| datadog_manifest(Ecosystem::PyPI, bytes),
};

fn datadog_manifest(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    datadog::parse(ecosystem, bytes)
        .map(|rows| Parsed {
            payload: Payload::Advisories(rows),
            tally: None,
        })
        .map_err(|e| e.to_string())
}

/// GitHub's Advisory Database. A signal stream beside OSV: it publishes the same `GHSA-` ids
/// OSV imports, and `advisory` is keyed `(source, publisher_id)` so both rows exist. A
/// refresh without a token loads the rest.
pub const GITHUB_NPM: Stream = Stream {
    stream: github::NPM_STREAM,
    url: github::ENDPOINT,
    ceiling: github::MAX_BYTES,
    transport: Transport::GithubGraphql {
        query: github::NPM_QUERY,
    },
    grants: MATCH,
    parse: |bytes| github_advisories(Ecosystem::Npm, bytes),
};

/// GitHub's PyPI advisories, as [`GITHUB_NPM`] reads npm's.
pub const GITHUB_PYPI: Stream = Stream {
    stream: github::PYPI_STREAM,
    url: github::ENDPOINT,
    ceiling: github::MAX_BYTES,
    transport: Transport::GithubGraphql {
        query: github::PYPI_QUERY,
    },
    grants: MATCH,
    parse: |bytes| github_advisories(Ecosystem::PyPI, bytes),
};

/// Match, which GitHub's advisories hold. It publishes malware separately, and not here.
const MATCH: &[Grant] = &[Grant {
    scope: Scope::Listed,
    capabilities: &[Capability::Match],
}];

fn github_advisories(ecosystem: Ecosystem, bytes: &[u8]) -> Result<Parsed, String> {
    github::parse(ecosystem, bytes)
        .map(|rows| Parsed {
            payload: Payload::Advisories(rows),
            tally: None,
        })
        .map_err(|e| e.to_string())
}

/// Every stream a refresh loads, in the order it loads them.
pub const ALL: &[Stream] = &[
    OSV_NPM,
    OSV_PYPI,
    KEV,
    DATADOG_NPM,
    DATADOG_PYPI,
    GITHUB_NPM,
    GITHUB_PYPI,
];

/// The stream a snapshot records under `stream`, or `None` for one this build does not know.
pub fn by_stream(stream: &str) -> Option<&'static Stream> {
    ALL.iter().find(|s| s.stream == stream)
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
            ALL.iter().map(|s| s.stream).collect::<Vec<_>>(),
            [
                "osv/npm",
                "osv/pypi",
                "cisa/kev",
                "datadog/npm",
                "datadog/pypi",
                "github/npm",
                "github/pypi"
            ]
        );
        assert!(by_stream("osv/cargo").is_none());
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
        // Seven records, of which the withdrawn one is counted and not stored.
        assert_eq!(tally.records(), 7);
        assert_eq!(tally.withdrawn, 1);
        assert_eq!(parsed.payload.rows().len(), 6);
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
}
