//! What can go wrong reading a packument, and what can go wrong fetching one.
//!
//! Two kinds, kept apart so the proxy can answer 404 or 502 rather than conflating a
//! registry saying no with a document it could not model.

use std::fmt;

use crate::identity::IdentityError;

/// A packument could not be turned into records.
///
/// Deliberately distinct from a transport failure. The proxy must not answer 502
/// because a registry served a document shape we did not model: that is our gap, not
/// the upstream's outage.
#[derive(Debug)]
pub enum NormalizeError {
    /// The body was not JSON, or not a JSON object of the expected shape.
    Json(serde_json::Error),
    /// The document's `name` is not a usable package identity.
    Name(IdentityError),
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "packument is not valid JSON: {e}"),
            Self::Name(e) => write!(f, "packument name is unusable: {e}"),
        }
    }
}

impl std::error::Error for NormalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Name(e) => Some(e),
        }
    }
}

/// A fetch did not produce a packument body.
#[derive(Debug)]
pub enum FetchError {
    /// The request never completed: DNS, TLS, connection, timeout.
    Transport(reqwest::Error),
    /// The registry answered, with something other than success.
    Status(reqwest::StatusCode),
    /// The body arrived and could not be decoded: an encoding this does not handle, a
    /// corrupt stream, or more output than the limit allows.
    Undecodable(crate::http::DecodeError),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "registry request failed: {e}"),
            Self::Status(s) => write!(f, "registry answered {s}"),
            Self::Undecodable(e) => write!(f, "registry body could not be decoded: {e}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::Status(_) => None,
            Self::Undecodable(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ecosystem::npm::normalize_packument;
    use crate::record::DocumentDetail;

    /// Errors are read by operators, so their text is part of the interface. `source()`
    /// keeps the underlying cause reachable rather than flattened into a string.
    #[test]
    fn error_messages_name_the_problem_and_keep_their_cause() {
        use std::error::Error as _;

        let Err(json) = normalize_packument(b"not json", DocumentDetail::Abbreviated) else {
            panic!("should not parse");
        };
        assert!(json.to_string().contains("not valid JSON"), "got: {json}");
        assert!(json.source().is_some());

        let Err(name) = normalize_packument(br#"{"name":"","versions":{}}"#, DocumentDetail::Full)
        else {
            panic!("an empty name is not a package identity");
        };
        assert!(name.to_string().contains("name is unusable"), "got: {name}");
        assert!(name.source().is_some());
        assert!(matches!(name, NormalizeError::Name(_)));

        let status = FetchError::Status(reqwest::StatusCode::NOT_FOUND);
        assert!(status.to_string().contains("404"), "got: {status}");
        assert!(
            status.source().is_none(),
            "a status is the whole story; there is nothing underneath it"
        );
    }
}
