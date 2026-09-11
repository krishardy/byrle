//! HTTP mechanics the proxy needs, separated from the proxy so they can be tested
//! without a server.
//!
//! Two jobs: deciding which headers cross a hop, and turning an encoded response body
//! into bytes something can parse.

use std::io::{Read, Write};

/// Headers that describe a single hop and must not be forwarded to the next one.
///
/// `Host` is not here because it is handled separately: reqwest sets it from the
/// upstream URL, so the proxy drops the client's copy rather than filtering it.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// What the proxy will ask upstream for when it intends to read the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedEncoding {
    /// `Accept-Encoding: gzip`.
    Gzip,
    /// `Accept-Encoding: identity`.
    Identity,
    /// The client accepts neither gzip nor identity. Forward its header untouched and
    /// do not attempt to read the body.
    Unreadable,
}

impl RequestedEncoding {
    pub fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("gzip"),
            Self::Identity => Some("identity"),
            Self::Unreadable => None,
        }
    }
}

/// Pick the encoding to request upstream for a body the proxy needs to read.
///
/// registry.npmjs.org serves brotli when it is offered, and npm 9 asks for
/// `gzip,deflate`. Narrowing the outbound request to gzip means only two encodings ever
/// have to be decoded here, and the body can still be forwarded to the client byte for
/// byte, because the client said it accepts gzip.
///
/// Identity is assumed acceptable when the header is absent, per RFC 9110 §12.5.3.
pub fn encoding_to_request(accept_encoding: Option<&str>) -> RequestedEncoding {
    let Some(header) = accept_encoding else {
        return RequestedEncoding::Identity;
    };

    let mut identity_ok = true;
    let mut wildcard: Option<bool> = None;
    for token in header.split(',') {
        let (coding, acceptable) = parse_coding(token);
        match coding.as_str() {
            "gzip" | "x-gzip" if acceptable => return RequestedEncoding::Gzip,
            "identity" => identity_ok = acceptable,
            "*" => wildcard = Some(acceptable),
            _ => {}
        }
    }

    // A wildcard covers gzip, but only if gzip was not itself named: an explicit
    // `gzip;q=0` alongside `*` is a refusal of gzip, and the loop above has already
    // returned for any acceptable gzip.
    if wildcard == Some(true) && !names_coding(header, "gzip") {
        return RequestedEncoding::Gzip;
    }
    if identity_ok && wildcard != Some(false) {
        return RequestedEncoding::Identity;
    }
    RequestedEncoding::Unreadable
}

/// Split one `Accept-Encoding` element into its coding and whether q is above zero.
fn parse_coding(token: &str) -> (String, bool) {
    let mut parts = token.split(';');
    let coding = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let acceptable = !parts.any(|p| {
        let p = p.trim();
        p.strip_prefix("q=")
            .or_else(|| p.strip_prefix("Q="))
            .map(|q| q.trim().parse::<f32>().is_ok_and(|v| v <= 0.0))
            .unwrap_or(false)
    });
    (coding, acceptable)
}

fn names_coding(header: &str, coding: &str) -> bool {
    header.split(',').any(|t| parse_coding(t).0 == coding)
}

/// A body could not be turned into bytes to parse.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// `Content-Encoding` was something this does not decode.
    UnsupportedEncoding(String),
    /// The compressed stream was invalid.
    Corrupt(String),
    /// Decompressed output passed the limit. Carries the limit, not the real size,
    /// which is not known without producing it.
    TooLarge(usize),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEncoding(e) => write!(f, "cannot decode `Content-Encoding: {e}`"),
            Self::Corrupt(e) => write!(f, "compressed body is corrupt: {e}"),
            Self::TooLarge(limit) => write!(f, "decompressed body exceeds {limit} bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode a response body for parsing, refusing to produce more than `limit` bytes.
///
/// The limit is the point of this function. gzip compresses about 5x on a packument and
/// far more on crafted input, so decompressing an attacker-influenced body without a
/// ceiling turns a small response into unbounded memory.
///
/// The returned bytes are for inspection only. What gets forwarded to the client is the
/// original encoded body, unchanged.
pub fn decode_for_parsing(
    body: &[u8],
    content_encoding: Option<&str>,
    limit: usize,
) -> Result<Vec<u8>, DecodeError> {
    let coding = content_encoding.unwrap_or("identity").trim();

    if coding.eq_ignore_ascii_case("identity") || coding.is_empty() {
        if body.len() > limit {
            return Err(DecodeError::TooLarge(limit));
        }
        return Ok(body.to_vec());
    }

    if !coding.eq_ignore_ascii_case("gzip") && !coding.eq_ignore_ascii_case("x-gzip") {
        return Err(DecodeError::UnsupportedEncoding(coding.to_owned()));
    }

    // `limit + 1` so hitting the limit exactly is distinguishable from passing it.
    let mut out = Vec::new();
    let mut decoder = flate2::read::GzDecoder::new(body).take(limit as u64 + 1);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| DecodeError::Corrupt(e.to_string()))?;

    if out.len() > limit {
        return Err(DecodeError::TooLarge(limit));
    }
    Ok(out)
}

/// Compress a body the proxy produced.
///
/// `fast` rather than `default`: on the largest packument measured (typescript, 8.7 MB)
/// that is 17.7 ms against 117.3 ms, for 2.06 MB against 1.69 MB. A 22% larger body on a
/// hop that is usually loopback or a LAN, for a sixth of the CPU time, on a path that
/// runs for every packument.
pub fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Marker on an `ETag` for a body this proxy rewrote.
const ETAG_PREFIX: &str = "waharoa.";

/// Label an upstream `ETag` as describing *our* version of the body.
///
/// A rewritten packument is not the document the upstream `ETag` names, and the URLs in
/// it depend on the address the proxy answers on. `base` is mixed in so that a proxy
/// reachable at a different address produces different tags: without that, a client
/// revalidates, upstream answers 304, and the client keeps serving artifact URLs pointing
/// at an address nobody listens on.
///
/// The weak marker keeps its position outside the quotes, and the prefix goes inside
/// them, so `W/` round-trips exactly.
pub fn mark_etag(etag: &str, base: &str) -> String {
    let etag = etag.trim();
    let (weak, tag) = match etag.strip_prefix("W/") {
        Some(rest) => ("W/", rest),
        None => ("", etag),
    };
    let Some(inner) = tag.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
        return etag.to_owned();
    };
    format!("{weak}\"{ETAG_PREFIX}{}.{inner}\"", base_tag(base))
}

/// Turn an `If-None-Match` the client got from us back into what upstream issued.
///
/// Returns `None` when the header must not be forwarded: it names a body this proxy
/// rewrote for a different address, so a 304 would leave the client serving URLs that no
/// longer resolve. Upstream then answers 200 and the body is rewritten afresh.
///
/// Entries that are not ours pass through untouched, so a client that also talks to the
/// registry directly is unaffected.
pub fn unmark_if_none_match(header: &str, base: &str) -> Option<String> {
    let ours = format!("{ETAG_PREFIX}{}.", base_tag(base));
    let mut out = Vec::new();
    for entry in header.split(',') {
        let entry = entry.trim();
        let (weak, tag) = match entry.strip_prefix("W/") {
            Some(rest) => ("W/", rest),
            None => ("", entry),
        };
        let inner = tag.strip_prefix('"').and_then(|t| t.strip_suffix('"'));
        match inner {
            Some(inner) if inner.starts_with(ETAG_PREFIX) => {
                // Ours, but a missing prefix means another address. Revalidating against
                // it would return a body built for somewhere else.
                let original = inner.strip_prefix(&ours)?;
                out.push(format!("{weak}\"{original}\""));
            }
            _ => out.push(entry.to_owned()),
        }
    }
    Some(out.join(", "))
}

/// A short, stable tag for the address the proxy answers on.
fn base_tag(base: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(base.trim_end_matches('/').as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real encoder, so the tests exercise what the proxy emits.
    fn gzip(data: &[u8]) -> Vec<u8> {
        super::gzip(data).expect("writing to a Vec cannot fail")
    }

    #[test]
    fn gzip_round_trips_through_the_decoder() {
        let data = b"a packument, more or less";
        let compressed = gzip(data);
        assert_eq!(
            decode_for_parsing(&compressed, Some("gzip"), 1024).unwrap(),
            data
        );
    }

    /// The weak marker stays outside the quotes and the prefix goes inside, so both
    /// forms survive the round trip exactly.
    #[test]
    fn etags_round_trip_through_marking() {
        let base = "http://127.0.0.1:8080";
        for original in ["\"abc123\"", "W/\"abc123\""] {
            let marked = mark_etag(original, base);
            assert_ne!(marked, original, "a rewritten body needs its own tag");
            assert_eq!(
                marked.starts_with("W/"),
                original.starts_with("W/"),
                "weakness has to survive: {original}"
            );
            assert_eq!(
                unmark_if_none_match(&marked, base).as_deref(),
                Some(original),
                "{original}"
            );
        }
    }

    /// The point of mixing the address in. A tag issued by a proxy at another address
    /// must not be revalidated, or a 304 leaves the client serving artifact URLs
    /// pointing at an address nobody listens on.
    #[test]
    fn a_tag_from_another_address_is_not_forwarded() {
        let marked = mark_etag("\"abc123\"", "http://old.example");
        assert_eq!(unmark_if_none_match(&marked, "http://new.example"), None);
        assert!(
            unmark_if_none_match(&marked, "http://old.example").is_some(),
            "the same address still revalidates"
        );
    }

    /// A client that also talks to the registry directly sends tags we never issued.
    #[test]
    fn tags_we_did_not_issue_pass_through_untouched() {
        let base = "http://127.0.0.1:8080";
        assert_eq!(
            unmark_if_none_match("\"upstream-tag\"", base).as_deref(),
            Some("\"upstream-tag\"")
        );
        assert_eq!(unmark_if_none_match("*", base).as_deref(), Some("*"));
        assert_eq!(
            unmark_if_none_match("\"a\", W/\"b\"", base).as_deref(),
            Some("\"a\", W/\"b\""),
            "a list is preserved entry by entry"
        );
    }

    /// Mixed lists keep the entries that are not ours.
    #[test]
    fn a_mixed_list_keeps_what_it_should() {
        let base = "http://127.0.0.1:8080";
        let marked = mark_etag("\"ours\"", base);
        let header = format!("\"theirs\", {marked}");
        assert_eq!(
            unmark_if_none_match(&header, base).as_deref(),
            Some("\"theirs\", \"ours\"")
        );
    }

    /// Anything that is not a quoted tag is left exactly as it came.
    #[test]
    fn a_malformed_etag_is_not_mangled() {
        assert_eq!(mark_etag("not-quoted", "base"), "not-quoted");
    }

    #[test]
    fn hop_by_hop_headers_are_matched_without_regard_to_case() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("TRANSFER-ENCODING"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(
            !is_hop_by_hop("host"),
            "Host is dropped separately, not filtered here"
        );
    }

    /// npm 9.9.4 sends `gzip,deflate`, and registry.npmjs.org answers brotli whenever br
    /// is offered. Requesting gzip keeps the decode side to one algorithm.
    #[test]
    fn gzip_is_requested_whenever_the_client_accepts_it() {
        for header in [
            "gzip,deflate",
            "gzip, deflate, br",
            "br, gzip",
            "GZIP",
            "deflate, gzip;q=0.5",
            "x-gzip",
        ] {
            assert_eq!(
                encoding_to_request(Some(header)),
                RequestedEncoding::Gzip,
                "{header}"
            );
        }
    }

    /// An absent header means identity is acceptable (RFC 9110 §12.5.3).
    #[test]
    fn identity_is_requested_when_gzip_is_not_on_offer() {
        assert_eq!(encoding_to_request(None), RequestedEncoding::Identity);
        for header in [
            "",
            "deflate",
            "br",
            "identity",
            "gzip;q=0",
            "gzip;q=0.0, br",
        ] {
            assert_eq!(
                encoding_to_request(Some(header)),
                RequestedEncoding::Identity,
                "{header}"
            );
        }
    }

    /// A wildcard covers gzip unless gzip is named and refused.
    #[test]
    fn a_wildcard_offers_gzip_unless_gzip_is_refused_by_name() {
        assert_eq!(encoding_to_request(Some("*")), RequestedEncoding::Gzip);
        assert_eq!(
            encoding_to_request(Some("gzip;q=0, *")),
            RequestedEncoding::Identity,
            "naming gzip with q=0 refuses it, wildcard or not"
        );
    }

    /// A client refusing both gzip and identity gets its own header forwarded and its
    /// body left alone. Rewriting it to something the client rejected would break the
    /// install to satisfy our own inspection.
    #[test]
    fn a_client_refusing_gzip_and_identity_is_left_alone() {
        assert_eq!(
            encoding_to_request(Some("br, identity;q=0")),
            RequestedEncoding::Unreadable
        );
        assert_eq!(
            encoding_to_request(Some("*;q=0")),
            RequestedEncoding::Unreadable
        );
        assert_eq!(RequestedEncoding::Unreadable.header_value(), None);
        assert_eq!(RequestedEncoding::Gzip.header_value(), Some("gzip"));
        assert_eq!(RequestedEncoding::Identity.header_value(), Some("identity"));
    }

    #[test]
    fn identity_and_gzip_bodies_both_decode() {
        let json = br#"{"name":"lodash"}"#;
        assert_eq!(decode_for_parsing(json, None, 1024).unwrap(), json);
        assert_eq!(
            decode_for_parsing(json, Some("identity"), 1024).unwrap(),
            json
        );
        assert_eq!(
            decode_for_parsing(&gzip(json), Some("gzip"), 1024).unwrap(),
            json
        );
        assert_eq!(
            decode_for_parsing(&gzip(json), Some("x-gzip"), 1024).unwrap(),
            json
        );
    }

    /// gzip reaches roughly 5x on a packument and far more on crafted input. Without a
    /// ceiling the decoder produces whatever the sender chose.
    #[test]
    fn decompression_stops_at_the_limit() {
        let bomb = gzip(&vec![b'A'; 10_000]);
        assert!(
            bomb.len() < 200,
            "10kB of one byte should compress small: {} bytes",
            bomb.len()
        );
        assert_eq!(
            decode_for_parsing(&bomb, Some("gzip"), 1_000),
            Err(DecodeError::TooLarge(1_000))
        );
        assert!(decode_for_parsing(&bomb, Some("gzip"), 10_000).is_ok());
        assert_eq!(
            decode_for_parsing(&vec![b'A'; 2_000], None, 1_000),
            Err(DecodeError::TooLarge(1_000)),
            "an identity body is capped too"
        );
    }

    #[test]
    fn unsupported_and_corrupt_bodies_are_distinguishable() {
        assert_eq!(
            decode_for_parsing(b"whatever", Some("br"), 1024),
            Err(DecodeError::UnsupportedEncoding("br".into()))
        );
        assert!(matches!(
            decode_for_parsing(b"not gzip at all", Some("gzip"), 1024),
            Err(DecodeError::Corrupt(_))
        ));
    }

    #[test]
    fn decode_errors_describe_themselves() {
        assert!(
            DecodeError::UnsupportedEncoding("br".into())
                .to_string()
                .contains("Content-Encoding: br")
        );
        assert!(
            DecodeError::TooLarge(99)
                .to_string()
                .contains("exceeds 99 bytes")
        );
        assert!(
            DecodeError::Corrupt("bad header".into())
                .to_string()
                .contains("bad header")
        );
    }
}
