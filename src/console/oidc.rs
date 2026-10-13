//! OIDC login's parts that ask no one: the settings, the provider's discovery document,
//! the pending login a browser carries, the authorization URL, and the ID token's checks.
//! See docs/engineering_decisions/console-login.md and admin-plan.md §4.1.

use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// Under the console's path: where the provider sends the browser back.
pub const CALLBACK_PATH: &str = "/oidc/callback";

/// How a provider is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Compared with the discovery document's and each token's `iss` exactly.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// The algorithms a token may be signed with; a token's header names one of them.
    pub algorithms: Vec<Algorithm>,
    /// Seconds a token's `exp` may have passed.
    pub leeway: u64,
}

/// `list`, comma separated, as algorithms a token may be signed with. A shared-secret one
/// is refused: with it, the client secret would be the key that verifies.
pub fn algorithms(list: &str) -> Result<Vec<Algorithm>, String> {
    let read: Vec<Algorithm> = list
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| {
            let algorithm = name
                .parse::<Algorithm>()
                .map_err(|_| format!("`{name}` is not a JWT signing algorithm"))?;
            match algorithm.family() {
                jsonwebtoken::AlgorithmFamily::Hmac => Err(format!(
                    "`{name}` is verified with a shared secret, which would be the client secret"
                )),
                _ => Ok(algorithm),
            }
        })
        .collect::<Result<_, _>>()?;
    if read.is_empty() {
        return Err("names no algorithm".to_owned());
    }
    Ok(read)
}

/// `url` if it is `https`, or `http` to loopback. Anything else could be read on the way.
pub fn trusted(url: &str) -> Result<reqwest::Url, String> {
    reqwest::Url::parse(url)
        .ok()
        .filter(super::secure_or_loopback)
        .ok_or_else(|| format!("`{url}` is not an https URL, or http to loopback"))
}

/// What the provider's discovery document says, of what login uses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl Discovery {
    /// The document in `body`, if it names `issuer` exactly and each endpoint is trusted.
    pub fn read(body: &[u8], issuer: &str) -> Result<Discovery, String> {
        let found: Discovery = serde_json::from_slice(body)
            .map_err(|e| format!("the discovery document does not read: {e}"))?;
        if found.issuer != issuer {
            return Err(format!(
                "the discovery document names issuer `{}`, not `{issuer}`",
                found.issuer
            ));
        }
        for endpoint in [
            &found.authorization_endpoint,
            &found.token_endpoint,
            &found.jwks_uri,
        ] {
            trusted(endpoint)?;
        }
        Ok(found)
    }
}

/// A login begun and not yet come back: what the browser carries in a cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Sent to the provider and back; the callback's must equal the cookie's.
    pub state: String,
    /// Sent to the provider, and named in the ID token.
    pub nonce: String,
    /// PKCE's secret: its SHA-256 goes to the provider, it to the token endpoint.
    pub verifier: String,
}

impl Pending {
    /// A login begun now, each value 32 random bytes.
    pub fn begin() -> Self {
        Self {
            state: crate::account::random(),
            nonce: crate::account::random(),
            verifier: crate::account::random(),
        }
    }

    /// As a cookie's value: the three, joined by `.`, which base64url never holds.
    pub fn cookie(&self) -> String {
        format!("{}.{}.{}", self.state, self.nonce, self.verifier)
    }

    /// From a cookie's value.
    pub fn parse(cookie: &str) -> Option<Pending> {
        let parts: Vec<&str> = cookie.split('.').collect();
        let [state, nonce, verifier] = parts.as_slice() else {
            return None;
        };
        let filled = [state, nonce, verifier].iter().all(|part| !part.is_empty());
        filled.then(|| Pending {
            state: (*state).to_owned(),
            nonce: (*nonce).to_owned(),
            verifier: (*verifier).to_owned(),
        })
    }

    /// PKCE's S256 challenge: the verifier's SHA-256, base64url without padding.
    pub fn challenge(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(self.verifier.as_bytes()))
    }
}

/// Where to send the browser to log in at the provider, coming back to `redirect`.
pub fn authorization(
    discovery: &Discovery,
    settings: &Settings,
    pending: &Pending,
    redirect: &str,
) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&discovery.authorization_endpoint)
        .map_err(|e| format!("the authorization endpoint is not a URL: {e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &settings.client_id)
        .append_pair("redirect_uri", redirect)
        .append_pair("scope", "openid")
        .append_pair("state", &pending.state)
        .append_pair("nonce", &pending.nonce)
        .append_pair("code_challenge", &pending.challenge())
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

/// What an ID token says, of what login reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    /// One client id, or several.
    pub aud: serde_json::Value,
    /// The client the token was issued to, when `aud` names several.
    pub azp: Option<String>,
    pub nonce: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
}

/// Why an ID token is not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// It names a key the set does not hold, which a fresh set may.
    UnknownKey(String),
    /// Anything else, and why.
    Invalid(String),
}

fn invalid(why: impl ToString) -> Refused {
    Refused::Invalid(why.to_string())
}

/// Whether `parameters` are a key of the family `algorithm` signs with.
fn fits(parameters: &AlgorithmParameters, algorithm: Algorithm) -> bool {
    matches!(
        (parameters, algorithm.family()),
        (
            AlgorithmParameters::EllipticCurve(_),
            jsonwebtoken::AlgorithmFamily::Ec
        ) | (
            AlgorithmParameters::RSA(_),
            jsonwebtoken::AlgorithmFamily::Rsa
        ) | (
            AlgorithmParameters::OctetKeyPair(_),
            jsonwebtoken::AlgorithmFamily::Ed
        )
    )
}

/// `token`'s claims, if it is signed with a configured algorithm by a key in `keys` of
/// that algorithm, issued by the issuer to this client, not expired, and for `nonce`.
pub fn verify(
    token: &str,
    keys: &JwkSet,
    settings: &Settings,
    nonce: &str,
) -> Result<Claims, Refused> {
    let header = jsonwebtoken::decode_header(token).map_err(invalid)?;
    if !settings.algorithms.contains(&header.alg) {
        return Err(invalid(format!(
            "the token is signed with {:?}, which is not accepted",
            header.alg
        )));
    }
    let kid = header
        .kid
        .ok_or_else(|| invalid("the token names no key"))?;
    let jwk = keys
        .find(&kid)
        .ok_or_else(|| Refused::UnknownKey(kid.clone()))?;
    let declared = jwk.common.key_algorithm.map(|a| format!("{a:?}"));
    if !fits(&jwk.algorithm, header.alg)
        || declared.is_some_and(|a| a != format!("{:?}", header.alg))
    {
        return Err(invalid(format!("key {kid} is not a {:?} key", header.alg)));
    }
    let key = DecodingKey::from_jwk(jwk).map_err(invalid)?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&settings.issuer]);
    validation.set_audience(&[&settings.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = settings.leeway;
    let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(invalid)?
        .claims;
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(invalid("the token's nonce is not this login's"));
    }
    let several = claims.aud.as_array().is_some_and(|aud| aud.len() > 1);
    if several && claims.azp.as_deref() != Some(settings.client_id.as_str()) {
        return Err(invalid(
            "the token names several audiences and was not issued to this client",
        ));
    }
    Ok(claims)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use jsonwebtoken::{EncodingKey, Header};

    pub const ISSUER: &str = "http://127.0.0.1:9999/realm";
    pub const CLIENT: &str = "byrle-console";

    pub fn settings() -> Settings {
        Settings {
            issuer: ISSUER.into(),
            client_id: CLIENT.into(),
            client_secret: "secret".into(),
            algorithms: vec![Algorithm::ES256],
            leeway: 0,
        }
    }

    /// A P-256 key made now, as a signing key and as its public JWK under `kid`.
    pub fn key(kid: &str) -> (EncodingKey, serde_json::Value) {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let der = pair.to_pkcs8v1().unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
            "x": b64(&point[1..33]), "y": b64(&point[33..65]),
        });
        (EncodingKey::from_ec_der(der.as_ref()), jwk)
    }

    /// `claims` signed with `key` under `kid`.
    pub fn signed(key: &EncodingKey, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, claims, key).unwrap()
    }

    /// Claims as the provider issues them to this client for `nonce`, an hour from now.
    pub fn claims(nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER, "sub": "user-42", "aud": CLIENT, "nonce": nonce,
            "exp": jsonwebtoken::get_current_timestamp() + 3600,
            "preferred_username": "alice", "email": "alice@example.com",
        })
    }

    fn set(keys: &[serde_json::Value]) -> JwkSet {
        serde_json::from_value(serde_json::json!({ "keys": keys })).unwrap()
    }

    #[test]
    fn a_shared_secret_algorithm_or_an_unknown_one_is_refused() {
        assert_eq!(
            algorithms(" RS256, ES256 ,").unwrap(),
            [Algorithm::RS256, Algorithm::ES256]
        );
        assert!(algorithms("HS256").unwrap_err().contains("shared secret"));
        assert!(
            algorithms("RS256,none")
                .unwrap_err()
                .contains("`none` is not a JWT signing algorithm")
        );
        assert_eq!(algorithms(" , ").unwrap_err(), "names no algorithm");
    }

    #[test]
    fn a_url_is_trusted_over_https_or_to_loopback() {
        for url in [
            "https://idp.example/realm",
            "http://127.0.0.1:8080/",
            "http://localhost/x",
        ] {
            assert!(trusted(url).is_ok(), "{url}");
        }
        for url in [
            "http://idp.example/realm",
            "ftp://idp.example/",
            "not a url",
        ] {
            assert!(
                trusted(url).unwrap_err().contains("is not an https URL"),
                "{url}"
            );
        }
    }

    #[test]
    fn the_discovery_document_must_name_the_issuer_and_trusted_endpoints() {
        let document = |issuer: &str, token: &str| {
            serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{ISSUER}/auth"),
                "token_endpoint": token, "jwks_uri": format!("{ISSUER}/keys"),
            })
            .to_string()
        };
        let read = Discovery::read(
            document(ISSUER, &format!("{ISSUER}/token")).as_bytes(),
            ISSUER,
        )
        .unwrap();
        assert_eq!(read.token_endpoint, format!("{ISSUER}/token"));
        let other =
            Discovery::read(document("https://evil.example", "x").as_bytes(), ISSUER).unwrap_err();
        assert!(
            other.contains("names issuer `https://evil.example`"),
            "{other}"
        );
        let plain = Discovery::read(
            document(ISSUER, "http://idp.example/token").as_bytes(),
            ISSUER,
        )
        .unwrap_err();
        assert!(plain.contains("is not an https URL"), "{plain}");
        assert!(
            Discovery::read(b"{}", ISSUER)
                .unwrap_err()
                .contains("does not read")
        );
    }

    /// The cookie holds the three values and nothing else; the challenge is RFC 7636's.
    #[test]
    fn a_pending_login_is_carried_in_its_cookie() {
        let pending = Pending::begin();
        assert_eq!(Pending::parse(&pending.cookie()), Some(pending.clone()));
        assert_ne!(pending.state, Pending::begin().state);
        for cookie in ["abc", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b."] {
            assert_eq!(Pending::parse(cookie), None, "{cookie}");
        }
        let known = Pending {
            state: "s".into(),
            nonce: "n".into(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
        };
        assert_eq!(
            known.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorization_url_asks_for_a_code_with_pkce() {
        let discovery = Discovery {
            issuer: ISSUER.into(),
            authorization_endpoint: format!("{ISSUER}/auth?prompt=login"),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
        };
        let pending = Pending {
            state: "s1".into(),
            nonce: "n1".into(),
            verifier: "v".into(),
        };
        let url = authorization(
            &discovery,
            &settings(),
            &pending,
            "https://h/admin/oidc/callback",
        )
        .unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let pairs: std::collections::BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs["prompt"], "login");
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["client_id"], CLIENT);
        assert_eq!(pairs["redirect_uri"], "https://h/admin/oidc/callback");
        assert_eq!(pairs["scope"], "openid");
        assert_eq!(
            (pairs["state"].as_str(), pairs["nonce"].as_str()),
            ("s1", "n1")
        );
        assert_eq!(pairs["code_challenge"], pending.challenge());
        assert_eq!(pairs["code_challenge_method"], "S256");
        let broken = Discovery {
            authorization_endpoint: "not a url".into(),
            ..discovery
        };
        assert!(authorization(&broken, &settings(), &pending, "x").is_err());
    }

    #[test]
    fn a_token_from_the_provider_for_this_login_is_taken() {
        let (key, jwk) = key("k1");
        let token = signed(&key, "k1", &claims("n1"));
        let read = verify(&token, &set(&[jwk]), &settings(), "n1").unwrap();
        assert_eq!((read.iss.as_str(), read.sub.as_str()), (ISSUER, "user-42"));
        assert_eq!(read.preferred_username.as_deref(), Some("alice"));
    }

    /// Each check refuses a token that fails it, naming why.
    #[test]
    fn each_check_refuses_a_token_that_fails_it() {
        let (key, jwk) = key("k1");
        let keys = set(std::slice::from_ref(&jwk));
        let refused = |token: &str| match verify(token, &keys, &settings(), "n1") {
            Err(Refused::Invalid(why)) => why,
            other => panic!("{other:?}"),
        };
        let with = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut claims = claims("n1");
            change(&mut claims);
            signed(&key, "k1", &claims)
        };
        assert!(!refused("not.a.token").is_empty());
        assert!(refused(&with(&|c| c["nonce"] = "other".into())).contains("nonce"));
        assert!(
            refused(&with(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }))
            .contains("nonce")
        );
        assert!(refused(&with(&|c| c["iss"] = "https://evil.example".into())).contains("Issuer"));
        assert!(refused(&with(&|c| c["aud"] = "other-client".into())).contains("Audience"));
        assert!(refused(&with(&|c| c["exp"] = 1.into())).contains("Expired"));
        assert!(
            refused(&with(&|c| {
                c.as_object_mut().unwrap().remove("sub");
            }))
            .contains("sub")
        );
        let several = with(&|c| c["aud"] = serde_json::json!([CLIENT, "other"]));
        assert!(refused(&several).contains("several audiences"));
        let ours = with(&|c| {
            c["aud"] = serde_json::json!([CLIENT, "other"]);
            c["azp"] = CLIENT.into();
        });
        assert!(verify(&ours, &keys, &settings(), "n1").is_ok());
        let one = with(&|c| c["aud"] = serde_json::json!([CLIENT]));
        assert!(
            verify(&one, &keys, &settings(), "n1").is_ok(),
            "one audience in a list needs no azp"
        );

        let mut rs = settings();
        rs.algorithms = vec![Algorithm::RS256];
        assert!(
            matches!(verify(&with(&|_| {}), &keys, &rs, "n1"), Err(Refused::Invalid(why)) if why.contains("not accepted"))
        );
        let mut header = Header::new(Algorithm::ES256);
        header.kid = None;
        let unnamed = jsonwebtoken::encode(&header, &claims("n1"), &key).unwrap();
        assert!(refused(&unnamed).contains("names no key"));
        assert_eq!(
            verify(&signed(&key, "k2", &claims("n1")), &keys, &settings(), "n1"),
            Err(Refused::UnknownKey("k2".into()))
        );
        let mut mislabelled = jwk.clone();
        mislabelled["alg"] = "ES384".into();
        let wrong = verify(&with(&|_| {}), &set(&[mislabelled]), &settings(), "n1");
        assert!(matches!(wrong, Err(Refused::Invalid(why)) if why.contains("is not a ES256 key")));
        let rsa = serde_json::json!({ "kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB" });
        let wrong = verify(&with(&|_| {}), &set(&[rsa]), &settings(), "n1");
        assert!(matches!(wrong, Err(Refused::Invalid(why)) if why.contains("is not a ES256 key")));
        let mut broken = jwk.clone();
        broken["x"] = "!!! not base64".into();
        let unread = verify(&with(&|_| {}), &set(&[broken]), &settings(), "n1");
        assert!(matches!(unread, Err(Refused::Invalid(_))));
        let (other, _) = super::tests::key("k1");
        let forged = signed(&other, "k1", &claims("n1"));
        assert!(refused(&forged).contains("InvalidSignature"));
        assert!(fits(
            &serde_json::from_value::<jsonwebtoken::jwk::Jwk>(
                serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"AA"})
            )
            .unwrap()
            .algorithm,
            Algorithm::EdDSA
        ));
    }
}
