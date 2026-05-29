//! rmcp 1.7.0 A1 adapter decision:
//! - Streamable HTTP server is `rmcp::transport::streamable_http_server::StreamableHttpService`.
//! - Axum integration is via the tower `Service`/`handle` API; this module wraps it in an axum
//!   handler so Bearer verification can run before rmcp consumes the body.
//! - rmcp injects raw `http::request::Parts` into each request's MCP extensions. We insert the
//!   verified domain `Caller` into the HTTP parts' `extensions` before calling rmcp; tools read
//!   that request-scoped `Caller` through `Extension<Parts>`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::USER_AGENT;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use opsgate_db::AuditLogParams;
use opsgate_domain::Caller;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, Json, ServerHandler, tool, tool_handler, tool_router};

use crate::api_call::{ApiCallInput, ApiCallOutput};
use crate::auth::bearer::{
    AuthError, auth_error_body, extract_bearer, shared_scoped_challenge_header, status_for_error,
    verify_bearer_mcp,
};
use crate::credential::{
    DeleteCredentialInput, ListCredentialsInput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, UpdateCredentialInput,
};
use crate::mcp::tools::credentials::{
    CredentialListOutput, DeleteCredentialOutput, RegisterCredentialOutput, UpdateCredentialOutput,
};
use crate::mcp::tools::me::{McpMeOutput, McpToolset};
use crate::sql_query::{SqlQueryInput, SqlQueryOutput};
use crate::sql_schema::{SqlSchemaInput, SqlSchemaOutput};
use crate::state::AppState;

#[derive(Clone)]
pub struct RuntimeMcpServer {
    state: AppState,
}

#[tool_router]
impl RuntimeMcpServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[tool(name = "me", description = "Return the authenticated caller identity.")]
    pub async fn me_tool(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<Json<McpMeOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::me::call(&self.state, &parts, McpToolset::Runtime).await;
        crate::mcp::tools::audit::record_tool_result(&self.state, &parts, "me", started, &result)
            .await;
        result
    }

    #[tool(
        name = "credential.list",
        description = "List visible credential aliases, metadata, and policy without returning secrets or endpoints."
    )]
    pub async fn credential_list(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<ListCredentialsInput>,
    ) -> Result<Json<CredentialListOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::list(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.list",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "api.call",
        description = "Invoke a registered category=http credential by alias without exposing endpoint or secrets. Returns JSON only."
    )]
    pub async fn api_call(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<ApiCallInput>,
    ) -> Result<Json<ApiCallOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::api_call::call(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "api.call",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "sql.query",
        description = "Execute a read-only Postgres SELECT through a registered category=sql credential. Returns budgeted JSON rows only."
    )]
    pub async fn sql_query(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<SqlQueryInput>,
    ) -> Result<Json<SqlQueryOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::sql_query::call(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "sql.query",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "sql.schema",
        description = "Inspect Postgres schema metadata for a registered category=sql credential without returning row values."
    )]
    pub async fn sql_schema(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<SqlSchemaInput>,
    ) -> Result<Json<SqlSchemaOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::sql_schema::call(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "sql.schema",
            started,
            &result,
        )
        .await;
        result
    }
}

#[tool_handler]
impl ServerHandler for RuntimeMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(
                Implementation::new("opsgate", env!("CARGO_PKG_VERSION")).with_title("opsgate"),
            )
            .with_instructions("Runtime MCP tools for opsgate.")
    }
}

#[derive(Clone)]
pub struct AdminMcpServer {
    state: AppState,
}

#[tool_router]
impl AdminMcpServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[tool(name = "me", description = "Return the authenticated caller identity.")]
    pub async fn me_tool(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<Json<McpMeOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::me::call(&self.state, &parts, McpToolset::Admin).await;
        crate::mcp::tools::audit::record_tool_result(&self.state, &parts, "me", started, &result)
            .await;
        result
    }

    #[tool(
        name = "credential.list",
        description = "List visible credential aliases, metadata, and policy without returning secrets or endpoints."
    )]
    pub async fn credential_list(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<ListCredentialsInput>,
    ) -> Result<Json<CredentialListOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::list(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.list",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "credential.register_http",
        description = "Register an HTTPS API credential for later api.call use. Secrets are sealed and never returned."
    )]
    pub async fn credential_register_http(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<RegisterHttpCredentialInput>,
    ) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result =
            crate::mcp::tools::credentials::register_http(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.register_http",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "credential.register_sql",
        description = "Register a Postgres credential for later sql.schema and sql.query use. Secrets are sealed and never returned."
    )]
    pub async fn credential_register_sql(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<RegisterSqlCredentialInput>,
    ) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::register_sql(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.register_sql",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "credential.update_http",
        description = "Update mutable metadata and policy for an existing HTTP credential. Secrets and endpoints are immutable."
    )]
    pub async fn credential_update_http(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<UpdateCredentialInput>,
    ) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::update_http(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.update_http",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "credential.update_sql",
        description = "Update mutable metadata and policy for an existing SQL credential. Secrets and endpoints are immutable."
    )]
    pub async fn credential_update_sql(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<UpdateCredentialInput>,
    ) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::update_sql(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.update_sql",
            started,
            &result,
        )
        .await;
        result
    }

    #[tool(
        name = "credential.delete",
        description = "Soft-delete a credential and destroy its sealed secret material."
    )]
    pub async fn credential_delete(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<DeleteCredentialInput>,
    ) -> Result<Json<DeleteCredentialOutput>, ErrorData> {
        let started = std::time::Instant::now();
        let result = crate::mcp::tools::credentials::delete(&self.state, &parts, input).await;
        crate::mcp::tools::audit::record_tool_result(
            &self.state,
            &parts,
            "credential.delete",
            started,
            &result,
        )
        .await;
        result
    }
}

#[tool_handler]
impl ServerHandler for AdminMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(
                Implementation::new("opsgate", env!("CARGO_PKG_VERSION")).with_title("opsgate"),
            )
            .with_instructions("Admin MCP tools for opsgate credential lifecycle management.")
    }
}

pub async fn mcp_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let request = match verify_mcp_request(&state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&state, error),
    };
    let config = streamable_config();
    let manager = Arc::new(NeverSessionManager::default());
    let service_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(RuntimeMcpServer::new(service_state.clone())),
        manager,
        config,
    );
    let response = service.handle(request).await;
    response.map(Body::new).into_response()
}

pub async fn mcp_admin_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let request = match verify_mcp_request(&state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&state, error),
    };
    let Some(caller) = request.extensions().get::<Caller>() else {
        return mcp_auth_response(&state, AuthError::Internal);
    };
    if !caller.role.is_admin() {
        record_mcp_admin_denied(&state, caller).await;
        return mcp_auth_response(&state, AuthError::InsufficientRole);
    }
    let config = streamable_config();
    let manager = Arc::new(NeverSessionManager::default());
    let service_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(AdminMcpServer::new(service_state.clone())),
        manager,
        config,
    );
    let response = service.handle(request).await;
    response.map(Body::new).into_response()
}

async fn verify_mcp_request(
    state: &AppState,
    request: Request<Body>,
) -> Result<Request<Body>, AuthError> {
    let (mut parts, body) = request.into_parts();
    let Some(token) = extract_bearer(&parts.headers).map(str::to_owned) else {
        return Err(AuthError::MissingToken);
    };
    let request_id = request_id(&parts.headers);
    let remote_ip = remote_ip(&parts.headers);
    let user_agent = user_agent(&parts.headers);
    let caller = verify_bearer_mcp(state, &token)
        .await?
        .with_request_metadata(request_id, remote_ip, user_agent);
    parts.extensions.insert(caller);
    Ok(Request::from_parts(parts, body))
}

fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn remote_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

async fn record_mcp_admin_denied(state: &AppState, caller: &Caller) {
    let detail = serde_json::json!({
        "schema_version": 1,
        "denial_reason": "required_role",
        "required_role": "admin",
        "actor_role": caller.role.as_str(),
        "sub": caller.user.sub.clone(),
    });
    let params = AuditLogParams {
        action: "mcp.auth.denied".to_owned(),
        channel: "mcp".to_owned(),
        outcome: "denied".to_owned(),
        severity: "warning".to_owned(),
        actor_user_id: Some(caller.user.id),
        actor_role: Some(caller.role.as_str().to_owned()),
        actor_ip: caller.remote_ip.clone(),
        actor_user_agent: caller.user_agent.clone(),
        target_type: Some("identity".to_owned()),
        target_id: Some(caller.user.id.to_string()),
        target_key: Some(caller.user.sub.clone()),
        request_id: caller.request_id.clone(),
        purpose: None,
        detail,
    };
    if let Err(error) = state.audit.append(params).await {
        tracing::error!(event = "mcp.auth.audit_failed", detail = %error);
    }
}

fn streamable_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts()
}

fn mcp_auth_response(state: &AppState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    tracing::warn!(event = "mcp.auth.denied", error = %error, status = status.as_u16());
    let mut response = (status, axum::Json(auth_error_body(state, &error))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            shared_scoped_challenge_header(&state.config.resource_url),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{AdminMcpServer, RuntimeMcpServer};

    #[test]
    fn tool_schemas_do_not_use_boolean_schema_nodes() -> Result<(), String> {
        let tools = RuntimeMcpServer::tool_router()
            .list_all()
            .into_iter()
            .chain(AdminMcpServer::tool_router().list_all());

        for tool in tools {
            let input = Value::Object(tool.input_schema.as_ref().clone());
            assert_no_boolean_schema(&input, &format!("{}.inputSchema", tool.name))?;
            if let Some(output_schema) = tool.output_schema {
                let output = Value::Object(output_schema.as_ref().clone());
                assert_no_boolean_schema(&output, &format!("{}.outputSchema", tool.name))?;
            }
        }
        Ok(())
    }

    fn assert_no_boolean_schema(value: &Value, path: &str) -> Result<(), String> {
        match value {
            Value::Bool(_) if path.ends_with(".default") => Ok(()),
            Value::Bool(_) => Err(format!("boolean schema at {path}")),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_boolean_schema(item, &format!("{path}[{index}]"))?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (key, item) in map {
                    assert_no_boolean_schema(item, &format!("{path}.{key}"))?;
                }
                Ok(())
            }
            Value::Null | Value::Number(_) | Value::String(_) => Ok(()),
        }
    }
}
