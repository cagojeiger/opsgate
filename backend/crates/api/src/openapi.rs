#![allow(dead_code)]

use std::io::Write;

use axum::Router;
use serde::Serialize;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::openapi::{Components, OpenApi as OpenApiDoc};
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::rest::api_call::{ApiCallRequest, ApiCallResponse};
use crate::rest::credentials::{
    CredentialListResponse, CredentialPageResponse, CredentialResponse, DeleteCredentialRequest,
    DeleteCredentialResponse, RegisterCredentialRequest, RegisterCredentialResponse,
    RegisterSecretRequest, RestCredentialCategory, RestCredentialPolicy, SecretHeaderRequest,
};
use crate::rest::me::MeResponse;
use crate::rest::sql_query::{SqlQueryRequest, SqlQueryResponse};
use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(title = "Opsgate API", version = env!("CARGO_PKG_VERSION")),
    paths(
        get_me,
        list_credentials,
        register_credential,
        delete_credential,
        call_api,
        query_sql
    ),
    components(schemas(
        ApiCallRequest,
        ApiCallResponse,
        CredentialListResponse,
        CredentialPageResponse,
        CredentialResponse,
        DeleteCredentialRequest,
        DeleteCredentialResponse,
        ErrorResponse,
        MeResponse,
        RegisterCredentialRequest,
        RegisterCredentialResponse,
        RegisterSecretRequest,
        RestCredentialCategory,
        RestCredentialPolicy,
        SecretHeaderRequest,
        SqlQueryRequest,
        SqlQueryResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "identity", description = "Authenticated owner identity"),
        (name = "credentials", description = "Secret-safe credential management"),
        (name = "runtime", description = "Policy-gated target execution")
    )
)]
pub(crate) struct ApiDoc;

pub(crate) fn routes() -> Router<AppState> {
    SwaggerUi::new("/swagger-ui")
        .url("/openapi.json", ApiDoc::openapi())
        .into()
}

pub(crate) fn write_json(mut writer: impl Write) -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(&mut writer, &ApiDoc::openapi())
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut OpenApiDoc) {
        let components = openapi.components.get_or_insert_with(Components::new);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/me",
    tag = "identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Authenticated owner identity", body = MeResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 403, description = "Inactive user", body = ErrorResponse)
    )
)]
fn get_me() {}

#[utoipa::path(
    get,
    path = "/api/v1/credentials",
    tag = "credentials",
    security(("bearer_auth" = [])),
    params(
        ("category" = Option<String>, Query, description = "Filter by category: http or sql"),
        ("provider" = Option<String>, Query, description = "Filter by provider"),
        ("env" = Option<String>, Query, description = "Filter by env"),
        ("tag" = Option<String>, Query, description = "Filter by tag"),
        ("q" = Option<String>, Query, description = "Search alias/provider/description"),
        ("fields" = Option<String>, Query, description = "Repeatable projected fields"),
        ("limit" = Option<i64>, Query, description = "Page size"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "Secret-free credential list", body = CredentialListResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn list_credentials() {}

#[utoipa::path(
    post,
    path = "/api/v1/credentials",
    tag = "credentials",
    security(("bearer_auth" = [])),
    request_body = RegisterCredentialRequest,
    responses(
        (status = 200, description = "Credential registered", body = RegisterCredentialResponse),
        (status = 400, description = "Invalid credential input", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 409, description = "Alias conflict", body = ErrorResponse)
    )
)]
fn register_credential() {}

#[utoipa::path(
    delete,
    path = "/api/v1/credentials/{alias}",
    tag = "credentials",
    security(("bearer_auth" = [])),
    params(("alias" = String, Path, description = "Credential alias")),
    request_body = DeleteCredentialRequest,
    responses(
        (status = 200, description = "Credential deleted", body = DeleteCredentialResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse)
    )
)]
fn delete_credential() {}

#[utoipa::path(
    post,
    path = "/api/v1/api/call",
    tag = "runtime",
    security(("bearer_auth" = [])),
    request_body = ApiCallRequest,
    responses(
        (status = 200, description = "Target JSON response shaped for LLM/FE consumption", body = ApiCallResponse),
        (status = 400, description = "Invalid input, policy denial, or safe target error", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse)
    )
)]
fn call_api() {}

#[utoipa::path(
    post,
    path = "/api/v1/sql/query",
    tag = "runtime",
    security(("bearer_auth" = [])),
    request_body = SqlQueryRequest,
    responses(
        (status = 200, description = "Read-only SQL result shaped as column arrays", body = SqlQueryResponse),
        (status = 400, description = "Invalid input, policy denial, or safe SQL error", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse)
    )
)]
fn query_sql() {}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use utoipa::OpenApi;

    use super::ApiDoc;

    #[test]
    fn openapi_document_contains_current_rest_paths() {
        let doc = ApiDoc::openapi();
        let paths = doc.paths.paths;
        for path in [
            "/api/v1/me",
            "/api/v1/credentials",
            "/api/v1/credentials/{alias}",
            "/api/v1/api/call",
            "/api/v1/sql/query",
        ] {
            assert!(paths.contains_key(path), "missing OpenAPI path: {path}");
        }
    }
}
