//! HTTP mechanics the proxy needs, separated from the proxy so they can be tested
//! without a server.
//!
//! Two jobs: deciding which headers cross a hop, and turning an encoded response body
//! into bytes something can parse.

use std::io::{Read, Write};
use std::time::Duration;

/// Past this, a host is not answering at all.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// No bytes for this long is a stalled connection rather than a slow one.
///
/// Per read, reset by each one, so a download that keeps arriving is never cut off: OSV's
/// 215,141,389-byte npm bundle took 9 s on 2026-09-17 and would take 36 minutes at 100 kB/s,
/// both without a 30 s gap. A total timeout would have to be longer than that whole 36
/// minutes to allow it, and would then let a stall run that long.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The forward proxy settings reqwest applies to every client, as the environment gives
/// them: [`crate::env::Env::upstream_proxy`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamProxy {
    pub https: Option<String>,
    pub http: Option<String>,
    /// Hosts fetched without the forward proxy.
    pub direct: Option<String>,
}

impl UpstreamProxy {
    /// `https`, `http` and `direct` for the startup log, with any user and password in a
    /// proxy URL replaced. Returns `None` when no forward proxy is set.
    pub fn fields(&self) -> Option<[String; 3]> {
        if self.https.is_none() && self.http.is_none() {
            return None;
        }
        let shown = |url: &Option<String>| url.as_deref().map_or("none".to_owned(), redacted);
        Some([
            shown(&self.https),
            shown(&self.http),
            self.direct.clone().unwrap_or_else(|| "nothing".to_owned()),
        ])
    }
}

/// `url` with its user and password replaced by `***`. A value that is not a URL is
/// replaced whole, since it cannot be told apart from a credential.
fn redacted(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "***".to_owned();
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        let _ = parsed.set_username("***");
        let _ = parsed.set_password(None);
    }
    parsed.to_string()
}

/// Every client this build fetches with: the proxy's upstream client and the intel
/// refresh's. `read_timeout` is [`READ_TIMEOUT`] in the binary; a test passes a short one.
/// There is no total timeout: see [`READ_TIMEOUT`].
pub fn client_builder(read_timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(concat!("waharoa/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(read_timeout)
}

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

/// Request headers that ask upstream to answer 304 instead of sending a body.
///
/// A 304 authorises the client to serve what it has cached. When the proxy rewrites
/// bodies that is only safe for a body the proxy produced at this address, and only
/// `If-None-Match` carries enough identity to tell: see [`unmark_if_none_match`]. The
/// rest are dropped whole while rewriting, so the only conditional that reaches upstream
/// is one this proxy issued the tag for.
///
/// yarn 4 sends `If-Modified-Since` alongside `If-None-Match` on every packument
/// revalidation, measured over two installs of lodash. npm, pnpm, yarn 1 and bun sent no
/// conditional at all in the same run: each served the second install from its own cache.
/// RFC 9110 §13.1.3 has the server ignore the date when a tag is present, so dropping it
/// changes nothing for yarn 4 and removes the case where a date arrives alone.
pub const CONDITIONAL: &[&str] = &[
    "if-none-match",
    "if-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
];

pub fn is_conditional(name: &str) -> bool {
    CONDITIONAL.iter().any(|h| name.eq_ignore_ascii_case(h))
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
            .is_some_and(|q| is_zero_qvalue(q.trim()))
    });
    (coding, acceptable)
}

/// Whether a q-value means "not acceptable".
///
/// RFC 9110 §12.4.2 writes a qvalue as `0` or `0.` followed by up to three digits, so the
/// zero forms are `0`, `0.`, `0.0`, `0.00` and `0.000`. Matched on the text rather than
/// parsed as a float: the input is attacker-controlled, comparing against zero is the
/// only question being asked, and float parsing brings rounding and NaN to a decision
/// that has neither.
fn is_zero_qvalue(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('0') else {
        return false;
    };
    match rest.strip_prefix('.') {
        Some(decimals) => decimals.len() <= 3 && decimals.bytes().all(|b| b == b'0'),
        None => rest.is_empty(),
    }
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

/// Turn an `If-None-Match` the client got from us back into what upstream issued, keeping
/// **only** the tags this proxy issued at this address.
///
/// A 304 authorises the client to serve the body it has cached. When the proxy rewrites
/// bodies, that is only safe for a body the proxy itself produced here. Every other tag
/// is dropped, so upstream answers 200 and the body is rewritten afresh. Returns `None`
/// when nothing is left to send.
///
/// Dropped, and why each one matters:
///
/// - **A tag from this proxy at another address.** A 304 would leave the client serving
///   artifact URLs pointing at an address nobody listens on.
/// - **A tag the proxy never issued.** The client holds a body from somewhere else, with
///   artifact URLs that were never pointed here. Measured: after enabling rewriting at an
///   address that previously ran without it, npm sent the upstream's own tag, the registry
///   answered 304, and the client kept its unrewritten copy. npm re-derives artifact URLs
///   from the configured registry so it still came through the proxy, but pnpm, yarn and
///   bun use the URL as written, so for them that cached copy sends every artifact to the
///   origin registry.
/// - **`*`**, which asks upstream to 304 if any representation exists at all.
pub fn unmark_if_none_match(header: &str, base: &str) -> Option<String> {
    let ours = format!("{ETAG_PREFIX}{}.", base_tag(base));
    let mut out = Vec::new();
    for entry in header.split(',') {
        let entry = entry.trim();
        let (weak, tag) = match entry.strip_prefix("W/") {
            Some(rest) => ("W/", rest),
            None => ("", entry),
        };
        let Some(inner) = tag.strip_prefix('"').and_then(|t| t.strip_suffix('"')) else {
            continue;
        };
        if let Some(original) = inner.strip_prefix(&ours) {
            out.push(format!("{weak}\"{original}\""));
        }
    }
    if out.is_empty() {
        return None;
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
    /// A proxy URL's user and password never reach the log; its host does.
    #[test]
    fn a_forward_proxy_is_described_without_its_credentials() {
        let proxy = UpstreamProxy {
            https: Some("http://alice:s3cret@egress.example:3128".to_owned()),
            http: Some("not a url".to_owned()),
            direct: None,
        };
        assert_eq!(
            proxy.fields(),
            Some([
                "http://***@egress.example:3128/".to_owned(),
                "***".to_owned(),
                "nothing".to_owned(),
            ])
        );
        assert_eq!(UpstreamProxy::default().fields(), None);
        for (url, shown) in [
            ("http://alice@egress.example/", "http://***@egress.example/"),
            (
                "http://:s3cret@egress.example/",
                "http://***@egress.example/",
            ),
        ] {
            assert_eq!(redacted(url), shown, "{url}");
        }
        assert_eq!(
            UpstreamProxy {
                http: Some("http://egress.example:3128".to_owned()),
                direct: Some("internal.example".to_owned()),
                ..UpstreamProxy::default()
            }
            .fields(),
            Some([
                "none".to_owned(),
                "http://egress.example:3128/".to_owned(),
                "internal.example".to_owned(),
            ])
        );
    }

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

    /// A 304 lets the client serve what it has cached, which is only safe for a body this
    /// proxy produced. A tag we never issued means the client holds a body whose artifact
    /// URLs were never pointed here.
    ///
    /// Measured: after enabling rewriting at an address that previously ran without it,
    /// npm sent the upstream's own tag and the registry answered 304, leaving the client
    /// on its unrewritten copy.
    #[test]
    fn tags_we_did_not_issue_are_dropped() {
        let base = "http://127.0.0.1:8080";
        assert_eq!(unmark_if_none_match("\"upstream-tag\"", base), None);
        assert_eq!(
            unmark_if_none_match("*", base),
            None,
            "`*` asks upstream to 304 if any representation exists"
        );
        assert_eq!(unmark_if_none_match("\"a\", W/\"b\"", base), None);
        assert_eq!(unmark_if_none_match("not-a-tag", base), None);
    }

    /// A mixed list keeps only what we issued.
    #[test]
    fn a_mixed_list_keeps_only_our_own_tags() {
        let base = "http://127.0.0.1:8080";
        let marked = mark_etag("\"ours\"", base);
        let header = format!("\"theirs\", {marked}, \"another\"");
        assert_eq!(
            unmark_if_none_match(&header, base).as_deref(),
            Some("\"ours\"")
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

    /// RFC 9110 §12.4.2 writes a qvalue as `0` or `0.` and up to three digits.
    #[test]
    fn the_zero_qvalue_forms_refuse_a_coding() {
        for zero in ["q=0", "q=0.", "q=0.0", "q=0.00", "q=0.000", "Q=0"] {
            assert_eq!(
                encoding_to_request(Some(&format!("gzip;{zero}"))),
                RequestedEncoding::Identity,
                "{zero} refuses gzip"
            );
        }
        for nonzero in ["q=1", "q=0.001", "q=0.5", "q=0.0001", "q=", "q=x"] {
            assert_eq!(
                encoding_to_request(Some(&format!("gzip;{nonzero}"))),
                RequestedEncoding::Gzip,
                "{nonzero} does not refuse gzip"
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

/// Proofs about the q-value grammar.
///
/// [`is_zero_qvalue`] decides whether a client refused a coding, on text the client chose.
/// It is the smallest piece of [`encoding_to_request`] that makes a decision, and the only
/// one that allocates nothing, which is what makes it provable rather than sampled.
///
/// `encoding_to_request` itself is not proved here. It lowercases each token, and a heap
/// allocation inside a symbolic loop puts it out of reach: three arbitrary bytes did not
/// finish in two minutes. The tests cover it instead.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// The characters the grammar is written in, plus one that is not.
    const ALPHABET: [u8; 4] = [b'0', b'.', b'1', b'a'];

    /// RFC 9110 §12.4.2 writes a qvalue as `0` or `0.` and up to three digits, so these
    /// are every string that means "not acceptable".
    const ZERO_FORMS: [&str; 5] = ["0", "0.", "0.0", "0.00", "0.000"];

    /// Total, and true for exactly the zero forms.
    ///
    /// The right hand side is an explicit list rather than a restatement of the
    /// implementation, so this compares the function against the grammar rather than
    /// against itself.
    #[kani::proof]
    #[kani::unwind(6)]
    fn is_zero_qvalue_accepts_exactly_the_zero_forms() {
        let bytes: [u8; 5] = kani::any();
        for byte in bytes {
            kani::assume(ALPHABET.contains(&byte));
        }
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());

        // Every byte is ASCII, so this cannot fail.
        let value = core::str::from_utf8(&bytes[..len]).unwrap();

        assert_eq!(is_zero_qvalue(value), ZERO_FORMS.contains(&value));
    }

    /// An absent header means identity is acceptable, per RFC 9110 §12.5.3.
    #[kani::proof]
    fn an_absent_header_is_identity() {
        assert!(encoding_to_request(None) == RequestedEncoding::Identity);
    }
}

/// The instant an HTTP date names, or `None` when it is not one.
///
/// `Last-Modified` is an IMF-fixdate, `Sun, 15 Sep 2024 18:07:39 GMT`, which is RFC 2822's
/// shape with a named zone. The two obsolete forms RFC 9110 still allows are not read: a
/// host that writes one gives no publish time rather than a wrong one.
pub fn http_date(value: &str) -> Option<jiff::Timestamp> {
    let zoned = jiff::fmt::rfc2822::parse(value.trim()).ok()?;
    Some(zoned.timestamp())
}

#[cfg(test)]
mod http_date_tests {
    /// Read from files.pythonhosted.org, www.piwheels.org and pypi.nvidia.com on
    /// 2026-09-21.
    #[test]
    fn an_imf_fixdate_is_read_and_anything_else_is_not() {
        for (value, expected) in [
            (
                "Sun, 15 Sep 2024 18:07:39 GMT",
                Some("2024-09-15T18:07:39Z"),
            ),
            (
                "Wed, 24 Sep 2025 00:07:42 GMT",
                Some("2025-09-24T00:07:42Z"),
            ),
            // RFC 850, which RFC 9110 calls obsolete.
            ("Sunday, 15-Sep-24 18:07:39 GMT", None),
            ("not a date", None),
            ("", None),
        ] {
            assert_eq!(
                super::http_date(value).map(|t| t.to_string()),
                expected.map(str::to_owned),
                "{value}"
            );
        }
    }
}
