//! The address a request came from. Behind nginx, every peer is nginx, so the client's
//! address is read from `X-Forwarded-For`, but only on a request carrying the shared key
//! [`crate::env::RP_KEY`]. See docs/fronting-tls.md.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderName};
use sha2::{Digest as _, Sha256};

/// The header nginx sends the key in.
pub const KEY_HEADER: HeaderName = HeaderName::from_static("x-byrle-rp-key");

/// The fewest bytes a key may have.
pub const MIN_KEY_BYTES: usize = 32;

/// The key nginx authenticates itself with, held as its SHA-256.
#[derive(Clone, PartialEq, Eq)]
pub struct RpKey([u8; 32]);

impl std::fmt::Debug for RpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpKey(..)")
    }
}

impl RpKey {
    /// `key`, if it has at least [`MIN_KEY_BYTES`]; else why not, without the key.
    pub fn parse(key: &str) -> Result<RpKey, String> {
        if key.len() < MIN_KEY_BYTES {
            return Err(format!(
                "has {} bytes; it needs at least {MIN_KEY_BYTES}. Make one with \
                 `openssl rand -hex 32`",
                key.len()
            ));
        }
        Ok(RpKey(Sha256::digest(key.as_bytes()).into()))
    }

    /// Whether `presented` is the key. Digests are compared, so the time taken says
    /// nothing about how much of the key matched.
    fn matches(&self, presented: &[u8]) -> bool {
        <[u8; 32]>::from(Sha256::digest(presented)) == self.0
    }
}

/// The address of the client of a request with `headers` from `peer`: the last entry of
/// `X-Forwarded-For` when the request carries `key`, else the peer's. `None` with neither.
pub fn client(headers: &HeaderMap, peer: Option<IpAddr>, key: Option<&RpKey>) -> Option<IpAddr> {
    key.filter(|key| {
        headers
            .get(KEY_HEADER)
            .is_some_and(|presented| key.matches(presented.as_bytes()))
    })
    .and_then(|_| headers.get_all("x-forwarded-for").iter().next_back())
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.rsplit(',').next())
    .and_then(|last| last.trim().parse().ok())
    .or(peer)
}

/// The peer address of a request, when the server recorded it.
pub fn peer(extensions: &axum::http::Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const KEY: &str = "0123456789abcdef0123456789abcdef";
    const NGINX: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn a_key_has_at_least_32_bytes_and_is_not_shown() {
        let refused = RpKey::parse(&KEY[1..]).unwrap_err();
        assert!(
            refused.starts_with("has 31 bytes; it needs at least 32"),
            "{refused}"
        );
        assert!(!refused.contains(&KEY[1..]));
        let key = RpKey::parse(KEY).unwrap();
        assert_eq!(format!("{key:?}"), "RpKey(..)");
    }

    /// With the key, the last `X-Forwarded-For` entry, which nginx wrote; without it, or
    /// with an entry that is not an address, the peer.
    #[test]
    fn the_forwarded_address_is_read_only_with_the_key() {
        let key = RpKey::parse(KEY).unwrap();
        let with = |pairs: &[(&'static str, &str)]| client(&headers(pairs), NGINX, Some(&key));
        assert_eq!(
            with(&[("x-byrle-rp-key", KEY), ("x-forwarded-for", "203.0.113.7")]),
            ip("203.0.113.7")
        );
        assert_eq!(
            with(&[
                ("x-byrle-rp-key", KEY),
                ("x-forwarded-for", "198.51.100.1"),
                ("x-forwarded-for", "10.0.0.9, 2001:db8::1 "),
            ]),
            ip("2001:db8::1"),
            "the last entry of the last header"
        );
        assert_eq!(with(&[("x-forwarded-for", "203.0.113.7")]), NGINX);
        assert_eq!(
            with(&[
                ("x-byrle-rp-key", "wrong"),
                ("x-forwarded-for", "203.0.113.7")
            ]),
            NGINX
        );
        assert_eq!(with(&[("x-byrle-rp-key", KEY)]), NGINX);
        assert_eq!(
            with(&[("x-byrle-rp-key", KEY), ("x-forwarded-for", "unknown")]),
            NGINX
        );
        let opaque = HeaderValue::from_bytes(b"\xff").unwrap();
        let mut unreadable = headers(&[("x-byrle-rp-key", KEY)]);
        unreadable.insert("x-forwarded-for", opaque);
        assert_eq!(client(&unreadable, NGINX, Some(&key)), NGINX);
    }

    #[test]
    fn without_a_configured_key_the_header_is_ignored() {
        let sent = headers(&[("x-byrle-rp-key", KEY), ("x-forwarded-for", "203.0.113.7")]);
        assert_eq!(client(&sent, NGINX, None), NGINX);
        assert_eq!(client(&sent, None, None), None);
    }

    #[test]
    fn the_peer_is_read_from_the_connection() {
        let mut extensions = axum::http::Extensions::new();
        assert_eq!(peer(&extensions), None);
        extensions.insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 4], 51000))));
        assert_eq!(peer(&extensions), ip("192.0.2.4"));
    }
}
