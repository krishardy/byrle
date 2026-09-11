//! HTTP mechanics the proxy needs, separated from the proxy so they can be tested
//! without a server.
//!
//! Two jobs: deciding which headers cross a hop, and turning an encoded response body
//! into bytes something can parse.

use std::io::Read;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
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
