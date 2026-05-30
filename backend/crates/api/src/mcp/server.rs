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
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
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
use crate::request_context::RequestMetadata;
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "me",
            crate::mcp::tools::me::call(&self.state, &parts, McpToolset::Runtime),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.list",
            crate::mcp::tools::credentials::list(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "api.call",
            crate::mcp::tools::api_call::call(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "sql.query",
            crate::mcp::tools::sql_query::call(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "sql.schema",
            crate::mcp::tools::sql_schema::call(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "me",
            crate::mcp::tools::me::call(&self.state, &parts, McpToolset::Admin),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.list",
            crate::mcp::tools::credentials::list(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.register_http",
            crate::mcp::tools::credentials::register_http(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.register_sql",
            crate::mcp::tools::credentials::register_sql(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.update_http",
            crate::mcp::tools::credentials::update_http(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.update_sql",
            crate::mcp::tools::credentials::update_sql(&self.state, &parts, input),
        )
        .await
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
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential.delete",
            crate::mcp::tools::credentials::delete(&self.state, &parts, input),
        )
        .await
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
    let metadata = RequestMetadata::from_headers(&parts.headers);
    let caller = match verify_bearer_mcp(state, &token).await {
        Ok(caller) => caller.with_request_metadata(
            metadata.request_id.clone(),
            metadata.remote_ip.clone(),
            metadata.user_agent.clone(),
        ),
        Err(error) => {
            crate::audit::auth::record_auth_denied(
                &state.audit,
                opsgate_domain::Channel::Mcp,
                &metadata,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    parts.extensions.insert(caller);
    Ok(Request::from_parts(parts, body))
}

fn streamable_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts()
}

fn mcp_auth_response(state: &AppState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    mcp_auth_response_with_status(state, error, status)
}

fn mcp_auth_response_with_status(
    state: &AppState,
    error: AuthError,
    status: StatusCode,
) -> Response {
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
    fn runtime_and_admin_tool_surfaces_match_go_smoke_contract() {
        let mut runtime_names = RuntimeMcpServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        runtime_names.sort();
        assert_eq!(
            runtime_names,
            [
                "api.call",
                "credential.list",
                "me",
                "sql.query",
                "sql.schema"
            ]
        );

        let mut admin_names = AdminMcpServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        admin_names.sort();
        assert_eq!(
            admin_names,
            [
                "credential.delete",
                "credential.list",
                "credential.register_http",
                "credential.register_sql",
                "credential.update_http",
                "credential.update_sql",
                "me",
            ]
        );
    }

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
