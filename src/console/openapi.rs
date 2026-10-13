//! The console API's OpenAPI document, generated from the handlers' annotations and the
//! types their bodies are. Served at [`OPENAPI_PATH`]; a test checks it against
//! [`super::routes::ROUTES`]. See docs/engineering_decisions/console-openapi.md.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use utoipa::OpenApi as _;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};

use super::Site;

/// Under the console's path: `GET` this document.
pub const OPENAPI_PATH: &str = "/api/v1/openapi.json";

/// The document, without the server it is served from.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "byrle console",
        description = "The admin console's API. Each operation that needs a permission names \
                       it in `x-byrle-permission`; see docs/admin-plan.md §4.2.",
    ),
    paths(
        super::health,
        openapi,
        super::api::login,
        super::api::logout,
        super::api::session,
        super::api::accounts,
        super::usage::dependencies,
        super::usage::failures,
    ),
    modifiers(&Credentials),
)]
pub struct Document;

/// The two ways a caller is known: the session cookie, and a proxy token.
struct Credentials;

impl utoipa::Modify for Credentials {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(super::api::COOKIE))),
        );
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "A proxy token from `byrle token create`, in any form the proxy \
                         takes: Bearer, Basic with the token as the password, or X-Byrle-Token",
                    ))
                    .build(),
            ),
        );
    }
}

/// The document, as JSON, with `server` as where it is served.
pub fn document(server: &str) -> serde_json::Value {
    let mut document = Document::openapi();
    document.servers = Some(vec![utoipa::openapi::Server::new(server)]);
    serde_json::to_value(&document).expect("the document serialises")
}

/// `GET openapi.json`: this API's OpenAPI document, its server the console's URL.
#[utoipa::path(
    get,
    path = OPENAPI_PATH,
    tag = "status",
    security(()),
    responses((status = 200, description = "The OpenAPI 3.1 document", content_type = "application/json")),
)]
pub async fn openapi(site: Arc<Site>) -> Response {
    let server = site.console.url.trim_end_matches('/');
    super::api::json(StatusCode::OK, &document(server))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::console::routes::{Guard, ROUTES};

    /// The document as served, kept in tests/fixtures/console/openapi.json for reading and
    /// review, and rewritten as every golden file is.
    #[test]
    fn the_document_is_the_one_kept_for_review() {
        let document = serde_json::to_string_pretty(&document("https://byrle.example/admin"));
        crate::golden::assert_matches("console", "openapi.json", &(document.unwrap() + "\n"));
    }

    /// Each route is in the document, and only they are. One that needs a permission names
    /// it and needs a session or token; one that is public needs neither.
    #[test]
    fn the_document_has_every_route_with_its_permission() {
        let document = document("https://h");
        let operations: usize = document["paths"]
            .as_object()
            .unwrap()
            .values()
            .map(|item| item.as_object().unwrap().len())
            .sum();
        assert_eq!(operations, ROUTES.len());
        for route in ROUTES.iter() {
            let method = route.method.as_str().to_lowercase();
            let operation = &document["paths"][route.path][&method];
            assert!(
                operation.is_object(),
                "{method} {} is not in the document",
                route.path
            );
            let security = operation["security"].as_array().unwrap();
            match route.guard {
                Guard::Needs(permission, _) => {
                    assert_eq!(
                        operation["x-byrle-permission"],
                        permission.name(),
                        "{}",
                        route.path
                    );
                    let schemes: Vec<&str> = security
                        .iter()
                        .flat_map(|need| need.as_object().unwrap().keys())
                        .map(String::as_str)
                        .collect();
                    assert_eq!(schemes, ["session", "token"], "{}", route.path);
                }
                Guard::Authenticated(_) => {
                    assert!(
                        operation.get("x-byrle-permission").is_none(),
                        "{}",
                        route.path
                    );
                    assert!(
                        security
                            .iter()
                            .all(|need| !need.as_object().unwrap().is_empty())
                    );
                }
                Guard::Public(_) => {
                    assert!(
                        operation.get("x-byrle-permission").is_none(),
                        "{}",
                        route.path
                    );
                    assert_eq!(security, &[serde_json::json!({})], "{}", route.path);
                }
            }
        }
        let schemes = &document["components"]["securitySchemes"];
        assert_eq!(schemes["session"]["in"], "cookie");
        assert_eq!(schemes["session"]["name"], "byrle_session");
        assert_eq!(schemes["token"]["scheme"], "bearer");
    }

    /// Served, the document names the console's URL as its server.
    #[tokio::test]
    async fn the_document_is_served_with_the_consoles_url() {
        let store = std::sync::Arc::new(crate::account::InMemory::new("2026-10-13T00:00:00Z"));
        let (_, base) = crate::console::tests::served(store).await;
        let served = reqwest::get(format!("{base}/admin{OPENAPI_PATH}"))
            .await
            .unwrap();
        assert_eq!(served.status(), 200);
        let document: serde_json::Value =
            serde_json::from_str(&served.text().await.unwrap()).unwrap();
        assert_eq!(document["servers"][0]["url"], "https://h/admin");
        assert_eq!(document["openapi"], "3.1.0");
    }
}
