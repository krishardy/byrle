//! Which account a proxy request comes from, read from the token it carries. Each request
//! asks the store, so a revoked token or a disabled account stops on the next request. See
//! docs/admin-plan.md §4.1.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

use super::{Accounts, Holder, TokenDigest};

/// A token sent in a header of its own, for a client that sets custom headers.
pub const TOKEN_HEADER: HeaderName = HeaderName::from_static("x-byrle-token");

/// What a 401 asks for. pip and uv send Basic credentials only once asked.
pub const CHALLENGE: &str = r#"Basic realm="byrle""#;

/// The token a request carries, and the username it came with in Basic credentials.
#[derive(Debug, PartialEq, Eq)]
struct Presented {
    token: String,
    user: Option<String>,
}

/// The credential in `headers`: [`TOKEN_HEADER`] when it is set, otherwise
/// `Authorization` as `Bearer <token>`, or `Basic` with the token as the password. `None`
/// for no credential, or one in another form.
fn presented(headers: &HeaderMap) -> Option<Presented> {
    if let Some(value) = headers.get(TOKEN_HEADER) {
        return value.to_str().ok().map(|token| Presented {
            token: token.trim().to_owned(),
            user: None,
        });
    }
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credentials) = value.trim().split_once(' ')?;
    let credentials = credentials.trim();
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(Presented {
            token: credentials.to_owned(),
            user: None,
        });
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials)
        .ok()?;
    let (user, token) = std::str::from_utf8(&decoded).ok()?.split_once(':')?;
    Some(Presented {
        token: token.to_owned(),
        user: Some(user.to_owned()),
    })
}

/// Why a request is not let through.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// No credential, a form not read, an unknown token, or a Basic username not its own.
    Unauthorized,
    /// The store did not answer. The cause is logged, not served.
    Unanswered,
}

/// 401, asking for Basic credentials.
pub fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, CHALLENGE)],
        "byrle: this proxy needs a token from `byrle token create`\n",
    )
        .into_response()
}

/// Checks each proxy request's token.
#[derive(Clone)]
pub struct Gate {
    store: Arc<dyn Accounts>,
}

impl Gate {
    pub fn new(store: Arc<dyn Accounts>) -> Self {
        Self { store }
    }

    /// Who sent the request with `headers`, or why it is refused.
    pub async fn admit(&self, headers: &HeaderMap) -> Result<Holder, Refused> {
        let presented = presented(headers).ok_or(Refused::Unauthorized)?;
        let holder = match self.store.holder(&TokenDigest::of(&presented.token)).await {
            Ok(holder) => holder.ok_or(Refused::Unauthorized)?,
            Err(e) => {
                tracing::error!(byrle.reason = %e, "account store cannot answer; not ready");
                return Err(Refused::Unanswered);
            }
        };
        match presented.user {
            Some(user) if user != holder.account.as_str() => Err(Refused::Unauthorized),
            _ => Ok(holder),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::account::testing::Down;
    use crate::account::{InMemory, Name};
    use axum::http::HeaderValue;

    fn headers(pairs: &[(HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    fn token(token: &str) -> Option<Presented> {
        Some(Presented {
            token: token.into(),
            user: None,
        })
    }

    #[test]
    fn each_form_gives_its_token() {
        assert_eq!(presented(&headers(&[])), None);
        assert_eq!(
            presented(&headers(&[(header::AUTHORIZATION, "Bearer byrle_a")])),
            token("byrle_a")
        );
        assert_eq!(
            presented(&headers(&[(header::AUTHORIZATION, "bearer  byrle_a ")])),
            token("byrle_a")
        );
        assert_eq!(
            presented(&headers(&[(
                header::AUTHORIZATION,
                &basic("ci", "byrle_b")
            )])),
            Some(Presented {
                token: "byrle_b".into(),
                user: Some("ci".into()),
            })
        );
        assert_eq!(
            presented(&headers(&[(TOKEN_HEADER, " byrle_c ")])),
            token("byrle_c")
        );
    }

    /// [`TOKEN_HEADER`] is read first, so `Authorization` is not read beside it.
    #[test]
    fn the_token_header_is_read_before_authorization() {
        let both = headers(&[
            (TOKEN_HEADER, "byrle_c"),
            (header::AUTHORIZATION, "Bearer byrle_a"),
        ]);
        assert_eq!(presented(&both), token("byrle_c"));
    }

    #[test]
    fn a_credential_in_another_form_is_none() {
        for value in [
            "Digest x",
            "Bearer",
            "Basic !!!",
            "Basic bm9jb2xvbg==",
            "Basic /w==",
        ] {
            assert_eq!(
                presented(&headers(&[(header::AUTHORIZATION, value)])),
                None,
                "{value}"
            );
        }
        let mut opaque = HeaderMap::new();
        opaque.insert(TOKEN_HEADER, HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(presented(&opaque), None);
        let mut opaque = HeaderMap::new();
        opaque.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
        );
        assert_eq!(presented(&opaque), None);
    }

    async fn gate_with_token() -> (Gate, String, Arc<InMemory>) {
        let store = Arc::new(InMemory::new("2026-10-11T00:00:00Z"));
        let (ci, runner) = (Name::parse("ci").unwrap(), Name::parse("runner").unwrap());
        store.create_account(&ci).await.unwrap();
        let issued = crate::account::issue();
        store
            .create_token(&ci, &runner, &TokenDigest::of(&issued))
            .await
            .unwrap();
        (Gate::new(store.clone()), issued, store)
    }

    #[tokio::test]
    async fn a_held_token_is_admitted_in_each_form() {
        let (gate, issued, _) = gate_with_token().await;
        for sent in [
            headers(&[(header::AUTHORIZATION, &format!("Bearer {issued}"))]),
            headers(&[(header::AUTHORIZATION, &basic("ci", &issued))]),
            headers(&[(TOKEN_HEADER, &issued)]),
        ] {
            let holder = gate.admit(&sent).await.unwrap();
            assert_eq!(
                (holder.account.as_str(), holder.token.as_str()),
                ("ci", "runner")
            );
        }
    }

    #[tokio::test]
    async fn no_token_a_wrong_one_or_another_accounts_name_is_unauthorized() {
        let (gate, issued, _) = gate_with_token().await;
        for sent in [
            headers(&[]),
            headers(&[(header::AUTHORIZATION, "Bearer byrle_unknown")]),
            headers(&[(header::AUTHORIZATION, &basic("other", &issued))]),
        ] {
            assert_eq!(gate.admit(&sent).await, Err(Refused::Unauthorized));
        }
    }

    /// No answer is kept: revoking a token stops the next request.
    #[tokio::test]
    async fn a_revoked_token_stops_on_the_next_request() {
        let (gate, issued, store) = gate_with_token().await;
        let sent = headers(&[(TOKEN_HEADER, &issued)]);
        assert!(gate.admit(&sent).await.is_ok());
        let (ci, runner) = (Name::parse("ci").unwrap(), Name::parse("runner").unwrap());
        store.revoke_token(&ci, &runner).await.unwrap();
        assert_eq!(gate.admit(&sent).await, Err(Refused::Unauthorized));
    }

    #[tokio::test]
    async fn a_store_that_cannot_answer_is_unanswered() {
        let gate = Gate::new(Arc::new(Down));
        let sent = headers(&[(TOKEN_HEADER, "byrle_x")]);
        assert_eq!(gate.admit(&sent).await, Err(Refused::Unanswered));
    }

    #[test]
    fn unauthorized_asks_for_basic_credentials() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], CHALLENGE);
    }
}
