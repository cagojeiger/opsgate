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
use crate::rest::mcp_connect::McpConnectResponse;
use crate::rest::me::MeResponse;
use crate::rest::observability::{
    ActivityItem, ActivityResponse, ActivitySummaryResponse, ApiCallHistoryItem,
    ApiCallHistoryResponse, AuditEventResponse, AuditEventsResponse, CredentialHistoryItem,
    CredentialHistoryResponse, CredentialSummaryResponse, PageResponse, SqlQueryHistoryItem,
    SqlQueryHistoryResponse, SummaryResponse,
};
use crate::rest::sql_query::{SqlQueryRequest, SqlQueryResponse};
use crate::rest::sql_schema::{SqlSchemaRequest, SqlSchemaResponse};
use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(title = "Opsgate API", version = env!("CARGO_PKG_VERSION")),
    paths(
        get_me,
        get_mcp_connect,
        get_summary,
        get_activity,
        get_audit_events,
        get_api_call_history,
        get_sql_query_history,
        get_credential_history,
        list_credentials,
        register_credential,
        delete_credential,
        call_api,
        query_sql,
        schema_sql
    ),
    components(schemas(
        ApiCallRequest,
        ApiCallResponse,
        ActivityItem,
        ActivityResponse,
        ActivitySummaryResponse,
        ApiCallHistoryItem,
        ApiCallHistoryResponse,
        AuditEventResponse,
        AuditEventsResponse,
        CredentialHistoryItem,
        CredentialHistoryResponse,
        CredentialListResponse,
        CredentialPageResponse,
        CredentialResponse,
        CredentialSummaryResponse,
        DeleteCredentialRequest,
        DeleteCredentialResponse,
        ErrorResponse,
        McpConnectResponse,
        MeResponse,
        PageResponse,
        RegisterCredentialRequest,
        RegisterCredentialResponse,
        RegisterSecretRequest,
        RestCredentialCategory,
        RestCredentialPolicy,
        SecretHeaderRequest,
        SqlQueryHistoryItem,
        SqlQueryHistoryResponse,
        SqlQueryRequest,
        SqlQueryResponse,
        SqlSchemaRequest,
        SqlSchemaResponse,
        SummaryResponse
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "identity", description = "Authenticated owner identity"),
        (name = "credentials", description = "Secret-safe credential management"),
        (name = "mcp", description = "MCP connection guidance"),
        (name = "observability", description = "Read-only activity, audit, and history views"),
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
    path = "/api/v1/mcp/connect",
    tag = "mcp",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "MCP URLs and tool lists for onboarding", body = McpConnectResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_mcp_connect() {}

#[utoipa::path(
    get,
    path = "/api/v1/summary",
    tag = "observability",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Credential and activity summary", body = SummaryResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_summary() {}

#[utoipa::path(
    get,
    path = "/api/v1/activity",
    tag = "observability",
    security(("bearer_auth" = [])),
    params(
        ("channel" = Option<String>, Query, description = "Filter by channel: api, mcp, browser, system"),
        ("tool" = Option<String>, Query, description = "Alias for action filter"),
        ("outcome" = Option<String>, Query, description = "Filter by outcome: ok, denied, error"),
        ("credential" = Option<String>, Query, description = "Filter by target credential alias"),
        ("limit" = Option<i64>, Query, description = "Page size 1-100"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "Recent activity timeline", body = ActivityResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_activity() {}

#[utoipa::path(
    get,
    path = "/api/v1/audit/events",
    tag = "observability",
    security(("bearer_auth" = [])),
    params(
        ("channel" = Option<String>, Query, description = "Filter by channel"),
        ("action" = Option<String>, Query, description = "Filter by audit action"),
        ("outcome" = Option<String>, Query, description = "Filter by outcome"),
        ("target_type" = Option<String>, Query, description = "Filter by target type"),
        ("credential" = Option<String>, Query, description = "Filter by target credential alias"),
        ("limit" = Option<i64>, Query, description = "Page size 1-100"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "Detailed audit events", body = AuditEventsResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_audit_events() {}

#[utoipa::path(
    get,
    path = "/api/v1/history/api-calls",
    tag = "observability",
    security(("bearer_auth" = [])),
    params(
        ("channel" = Option<String>, Query, description = "Filter by channel"),
        ("credential" = Option<String>, Query, description = "Filter by credential alias"),
        ("outcome" = Option<String>, Query, description = "Filter by outcome"),
        ("error_kind" = Option<String>, Query, description = "Filter by safe error kind"),
        ("limit" = Option<i64>, Query, description = "Page size 1-100"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "API call history rows", body = ApiCallHistoryResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_api_call_history() {}

#[utoipa::path(
    get,
    path = "/api/v1/history/sql-queries",
    tag = "observability",
    security(("bearer_auth" = [])),
    params(
        ("channel" = Option<String>, Query, description = "Filter by channel"),
        ("credential" = Option<String>, Query, description = "Filter by credential alias"),
        ("outcome" = Option<String>, Query, description = "Filter by outcome"),
        ("error_kind" = Option<String>, Query, description = "Filter by safe error kind"),
        ("limit" = Option<i64>, Query, description = "Page size 1-100"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "SQL query history rows without raw SQL text", body = SqlQueryHistoryResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_sql_query_history() {}

#[utoipa::path(
    get,
    path = "/api/v1/history/credentials",
    tag = "observability",
    security(("bearer_auth" = [])),
    params(
        ("credential" = Option<String>, Query, description = "Filter by credential alias"),
        ("action" = Option<String>, Query, description = "register, update, or delete"),
        ("channel" = Option<String>, Query, description = "Filter by channel"),
        ("limit" = Option<i64>, Query, description = "Page size 1-100"),
        ("cursor" = Option<String>, Query, description = "Continuation cursor")
    ),
    responses(
        (status = 200, description = "Credential mutation history", body = CredentialHistoryResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse)
    )
)]
fn get_credential_history() {}

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

#[utoipa::path(
    post,
    path = "/api/v1/sql/schema",
    tag = "runtime",
    security(("bearer_auth" = [])),
    request_body = SqlSchemaRequest,
    responses(
        (status = 200, description = "Postgres schema metadata without row values", body = SqlSchemaResponse),
        (status = 400, description = "Invalid input, policy denial, or safe SQL error", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse)
    )
)]
fn schema_sql() {}

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
            "/api/v1/mcp/connect",
            "/api/v1/summary",
            "/api/v1/activity",
            "/api/v1/audit/events",
            "/api/v1/history/api-calls",
            "/api/v1/history/sql-queries",
            "/api/v1/history/credentials",
            "/api/v1/credentials",
            "/api/v1/credentials/{alias}",
            "/api/v1/api/call",
            "/api/v1/sql/query",
            "/api/v1/sql/schema",
        ] {
            assert!(paths.contains_key(path), "missing OpenAPI path: {path}");
        }
    }
}
