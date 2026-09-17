//! What a refresh knows about each advisory stream before it fetches anything.
//!
//! One [`Stream`] per stream, in [`ALL`], holding the facts a refresh needs: where the
//! bundle is, how large it may be, whether the refresh continues without it, what it may
//! say once loaded, and how its bytes become rows.
//!
//! This is the declaration side. `waharoa refresh` does the fetching, because a fetch is
//! network I/O and everything here is decidable from the bytes alone.
//!
//! Mirroring is not here. Serving a stream from a local copy is tracked separately; see
//! "Local mirrors for all streams" in `TODO.md`.

use std::collections::BTreeSet;

use super::load::{Encoded, encode, encode_exploited};
use super::osv::Rows;
use super::refresh::Tally;
use super::{Capability, datadog, github, kev, osv, refresh};

/// Whether a refresh loads anything at all when this stream does not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// A refresh that cannot load this stream loads nothing, and stops before fetching the
    /// streams after it.
    Required,
    /// A refresh that cannot load this stream keeps that stream's last load, loads the
    /// others and exits 1.
    Optional,
}

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
    /// A POST of [`github::QUERY`] to `url` with `Authorization: bearer`, paged by cursor
    /// until GitHub reports no next page. The response bodies are concatenated into one JSON
    /// array, so `parse` still reads one buffer, and `ceiling` bounds that whole array.
    /// The token comes from `crate::env::GITHUB_TOKEN`; without it the stream does not load.
    GithubGraphql,
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
    /// The source a row is stored under.
    pub source: &'static str,
    /// The name a snapshot records the bundle under.
    pub stream: &'static str,
    /// Where the bundle is fetched from.
    pub url: &'static str,
    /// Bytes past which the fetch is refused.
    pub ceiling: usize,
    pub requirement: Requirement,
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

/// OSV's npm bundle. Required: it carries every vulnerability and malware record the proxy
/// matches on, so a refresh without it would replace the store with the catalogues alone.
pub const OSV_NPM: Stream = Stream {
    source: osv::SOURCE,
    stream: refresh::NPM_STREAM,
    url: refresh::NPM_BUNDLE,
    ceiling: refresh::MAX_BUNDLE_BYTES,
    requirement: Requirement::Required,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| {
        refresh::read_bundle(bytes)
            .map(|bundle| Parsed {
                payload: Payload::Advisories(bundle.rows),
                tally: Some(bundle.tally),
            })
            .map_err(|e| e.to_string())
    },
};

/// CISA's KEV catalogue. `source` and `stream` are the same string, which snapshots and the
/// ingestion history already record.
const KEV: Stream = Stream {
    source: kev::SOURCE,
    stream: kev::SOURCE,
    url: kev::CATALOGUE,
    ceiling: kev::MAX_CATALOGUE_BYTES,
    requirement: Requirement::Optional,
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
    source: datadog::SOURCE,
    stream: datadog::STREAM,
    url: datadog::MANIFEST,
    ceiling: datadog::MAX_MANIFEST_BYTES,
    requirement: Requirement::Optional,
    transport: Transport::Get,
    grants: MATCH_AND_MALWARE,
    parse: |bytes| {
        datadog::parse(bytes)
            .map(|rows| Parsed {
                payload: Payload::Advisories(rows),
                tally: None,
            })
            .map_err(|e| e.to_string())
    },
};

/// GitHub's Advisory Database. A signal stream beside OSV: it publishes the same `GHSA-` ids
/// OSV imports, and `advisory` is keyed `(source, publisher_id)` so both rows exist.
/// `Optional`, so a refresh without a token still loads the rest.
pub const GITHUB_NPM: Stream = Stream {
    source: github::SOURCE,
    stream: github::STREAM,
    url: github::ENDPOINT,
    ceiling: github::MAX_BYTES,
    requirement: Requirement::Optional,
    transport: Transport::GithubGraphql,
    grants: &[Grant {
        scope: Scope::Listed,
        capabilities: &[Capability::Match],
    }],
    parse: |bytes| {
        github::parse(bytes)
            .map(|rows| Parsed {
                payload: Payload::Advisories(rows),
                tally: None,
            })
            .map_err(|e| e.to_string())
    },
};

/// Every stream a refresh loads, in the order it loads them.
///
/// OSV is first because it is the one [`Requirement::Required`] stream: a refresh that
/// cannot load it stops here rather than downloading the rest.
pub const ALL: &[Stream] = &[OSV_NPM, KEV, DATADOG_NPM, GITHUB_NPM];

/// The stream a snapshot records under `stream`, or `None` for one this build does not know.
pub fn by_stream(stream: &str) -> Option<&'static Stream> {
    ALL.iter().find(|s| s.stream == stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::load::Kind;

    fn declared(stream: &str) -> &'static Stream {
        by_stream(stream).expect("this build declares the stream")
    }

    /// The refresh loop returns on the first `Required` stream it cannot read, so a required
    /// stream after an optional one would be reached only when the optional one was fetched
    /// first.
    #[test]
    fn exactly_one_stream_is_required_and_it_is_the_first() {
        let required: Vec<&str> = ALL
            .iter()
            .filter(|s| s.requirement == Requirement::Required)
            .map(|s| s.stream)
            .collect();
        assert_eq!(required, [refresh::NPM_STREAM]);
        assert_eq!(ALL[0].stream, refresh::NPM_STREAM);
    }

    #[test]
    fn a_stream_this_build_does_not_declare_is_not_found() {
        assert_eq!(
            ALL.iter().map(|s| s.stream).collect::<Vec<_>>(),
            ["osv/npm", "cisa/kev", "datadog/npm", "github/npm"]
        );
        assert!(by_stream("osv/pypi").is_none());
        assert!(by_stream("osv").is_none());
    }

    /// `source` is what a row is stored under and `stream` is what a snapshot records. They
    /// are the same string for KEV, which snapshots and the ingestion history already hold.
    #[test]
    fn kev_stores_and_records_under_the_same_name() {
        let kev = declared(kev::SOURCE);
        assert_eq!(kev.source, "cisa/kev");
        assert_eq!(kev.stream, "cisa/kev");
    }

    #[test]
    fn each_stream_declares_the_url_and_ceiling_its_module_gives() {
        for (stream, url, ceiling) in [
            (
                refresh::NPM_STREAM,
                refresh::NPM_BUNDLE,
                refresh::MAX_BUNDLE_BYTES,
            ),
            (kev::SOURCE, kev::CATALOGUE, kev::MAX_CATALOGUE_BYTES),
            (
                datadog::STREAM,
                datadog::MANIFEST,
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
        let parsed = (declared(datadog::STREAM).parse)(br#"{"vant": ["2.13.3"], "0h": null}"#)
            .expect("the manifest parses");
        assert_eq!(parsed.payload.rows().len(), 2);
        assert!(
            parsed.tally.is_none(),
            "a manifest counts nothing for the refresh to print"
        );
        let encoded = parsed.payload.encode(datadog::SOURCE);
        assert_eq!(encoded.kind, Kind::Advisories);
        assert_eq!(encoded.source, "datadog");
    }

    #[test]
    fn exploited_ids_encode_as_exploited_and_have_no_rows() {
        let catalogue = br#"{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}"#;
        let parsed = (declared(kev::SOURCE).parse)(catalogue).expect("the catalogue parses");
        assert_eq!(
            parsed.payload,
            Payload::Exploited(BTreeSet::from(["CVE-2021-44228".to_owned()]))
        );
        assert!(
            parsed.payload.rows().is_empty(),
            "exploited ids have no child tables"
        );
        let encoded = parsed.payload.encode(kev::SOURCE);
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
        let parsed = (declared(refresh::NPM_STREAM).parse)(&bytes).expect("the bundle reads");
        let tally = parsed.tally.expect("the bundle counts its records");
        // Seven records, of which the withdrawn one is counted and not stored.
        assert_eq!(tally.records(), 7);
        assert_eq!(tally.withdrawn, 1);
        assert_eq!(parsed.payload.rows().len(), 6);
        assert_eq!(parsed.payload.encode(osv::SOURCE).kind, Kind::Advisories);
    }

    /// The shim turns each module's error type into the string the refresh records as
    /// `NotLoaded::error`.
    #[test]
    fn a_bundle_that_does_not_read_gives_the_error_as_a_string() {
        for (stream, bytes) in [
            (refresh::NPM_STREAM, &b"not a zip"[..]),
            (kev::SOURCE, &b"not json"[..]),
            (datadog::STREAM, &b"not json"[..]),
        ] {
            let error = (declared(stream).parse)(bytes).expect_err("the bundle does not read");
            assert!(!error.is_empty(), "{stream} gives no error text");
        }
    }
}
