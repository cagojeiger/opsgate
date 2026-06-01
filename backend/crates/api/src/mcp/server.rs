//! rmcp 1.7.0 A1 adapter decision:
//! - Streamable HTTP server is `rmcp::transport::streamable_http_server::StreamableHttpService`.
//! - Axum integration is via the tower `Service`/`handle` API; this module wraps it in an axum
//!   handler so Bearer verification can run before rmcp consumes the body.
//! - rmcp injects raw `http::request::Parts` into each request's MCP extensions. We insert the
//!   verified domain `Caller` into the HTTP parts' `extensions` before calling rmcp; tools read
//!   that request-scoped `Caller` through `Extension<Parts>`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRef, State};
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

use crate::auth::bearer::{
    AuthError, auth_error_body, extract_bearer, shared_scoped_challenge_header, status_for_error,
};
use crate::auth::mcp::verify_bearer_mcp;
use crate::mcp::tools::me::{McpMeOutput, McpToolset};
use crate::request_context::RequestMetadata;
use crate::state::{AppState, AuthRuntimeState};
use opsgate_service::api_call::{ApiCallInput, ApiCallOutput};
use opsgate_service::credential::{
    CredentialListOutput, DeleteCredentialInput, DeleteCredentialOutput, ListCredentialsInput,
    RegisterCredentialOutput, RegisterHttpCredentialInput, RegisterSqlCredentialInput,
    UpdateCredentialInput, UpdateCredentialOutput,
};
use opsgate_service::sql_query::{SqlQueryInput, SqlQueryOutput};
use opsgate_service::sql_schema::{SqlSchemaInput, SqlSchemaOutput};

#[derive(Clone)]
pub(crate) struct RuntimeMcpServer {
    state: AppState,
}

#[tool_router]
impl RuntimeMcpServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[tool(
        name = "me",
        description = "Use first for infrastructure investigation. Identifies the owner and exposed tools; does not reveal credentials or targets."
    )]
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
        description = "Start here for infrastructure investigation. Lists safe aliases for HTTP/API and SQL targets such as Kubernetes, internal APIs, Postgres, audit/history. Never returns secrets or target URLs."
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
        description = "Required: alias, purpose, request_path. Use for registered HTTP/API infrastructure targets, especially Kubernetes and internal JSON APIs. Call credential.list first if alias is unknown. Send only request_path under hidden origin/base_path. For counts: length() returns array/string/object length; count() returns matched node count."
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
        description = "Required: alias, purpose, query. Use for read-only investigation of registered Postgres targets, including opsgate audit/history when registered. Call sql.schema first when tables or columns are unknown. Prefer explicit columns/WHERE/count/group; avoid SELECT *. For SQL column arrays, use row_count or $.column.length() for row count."
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
        description = "Required: alias, purpose. Inspect registered Postgres schemas before unknown infra/audit queries. mode=tables lists tables; mode=table with namespace/table shows columns/indexes. Never returns row data."
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
            .with_instructions("For infrastructure investigation, start with me or credential.list, then choose an alias from safe metadata. For HTTP/Kubernetes/internal APIs, call api.call with request_path only; target URLs stay hidden. For Postgres/audit/history, run sql.schema before unknown tables, then sql.query with explicit columns/WHERE/count/group and avoid SELECT *. Use 1-3 jsonpath paths to shrink large JSON outputs.")
    }
}

#[derive(Clone)]
pub(crate) struct AdminMcpServer {
    state: AppState,
}

#[tool_router]
impl AdminMcpServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    #[tool(
        name = "me",
        description = "Identify the authenticated owner and show which admin tools this surface exposes. Does not reveal credentials or targets."
    )]
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
        description = "List existing credential aliases, metadata, and policy before update/delete. Never returns secrets, origin/base_path, or database_url."
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
        description = "Register an HTTP/API infrastructure target for api.call, e.g. Kubernetes or internal JSON APIs. Use secret_headers for header auth and/or client_cert_pem/client_key_pem for mTLS auth. Put scheme+host in origin, optional fixed prefix in base_path, and per-call paths in api.call.request_path. Secrets are sealed and never returned."
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
        description = "Register a Postgres target for sql.schema/sql.query. database_url identifies host/db/options; username/password are separate secrets and are never returned."
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
        description = "Update metadata and policy for an HTTP alias. origin/base_path, secret headers, TLS CA, and mTLS client certificate/key are immutable; rotate by delete + register."
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
        description = "Update metadata and policy for a SQL alias. database_url and username/password are immutable; rotate by delete + register."
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
        description = "Delete an alias and destroy its sealed secret material. Use only when the credential should no longer be callable."
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
            .with_instructions("Admin surface manages credentials. Use origin/base_path/request_path for HTTP target boundaries: origin is scheme+host, base_path is a fixed hidden prefix, api.call.request_path is supplied later. For SQL, database_url is the target and username/password are separate secrets. Secrets and target URLs are never returned; rotate immutable target/secret fields by delete + register.")
    }
}

pub(crate) async fn mcp_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let auth_state = AuthRuntimeState::from_ref(&state);
    let request = match verify_mcp_request(&auth_state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&auth_state, error),
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

pub(crate) async fn mcp_admin_handler(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let auth_state = AuthRuntimeState::from_ref(&state);
    let request = match verify_mcp_request(&auth_state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&auth_state, error),
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
    state: &AuthRuntimeState,
    request: Request<Body>,
) -> Result<Request<Body>, AuthError> {
    let (mut parts, body) = request.into_parts();
    let Some(token) = extract_bearer(&parts.headers).map(str::to_owned) else {
        return Err(AuthError::MissingToken);
    };
    let metadata = RequestMetadata::from_headers(&parts.headers);
    let caller = match verify_bearer_mcp(&state.auth, &token).await {
        Ok(caller) => caller.with_request_metadata(
            metadata.request_id.clone(),
            metadata.remote_ip.clone(),
            metadata.user_agent.clone(),
        ),
        Err(error) => {
            crate::audit::auth::record_auth_denied(
                &state.audit,
                opsgate_model::Channel::Mcp,
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

fn mcp_auth_response(state: &AuthRuntimeState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    mcp_auth_response_with_status(state, error, status)
}

fn mcp_auth_response_with_status(
    state: &AuthRuntimeState,
    error: AuthError,
    status: StatusCode,
) -> Response {
    tracing::warn!(event = "mcp.auth.denied", error = %error, status = status.as_u16());
    let mut response = (status, axum::Json(auth_error_body(&state.config, &error))).into_response();
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
