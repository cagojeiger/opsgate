//! Runtime and admin MCP tool definitions.

use axum::http::request::Parts;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, Json, ServerHandler, tool, tool_handler, tool_router};

use crate::mcp::tools::me::{McpMeOutput, McpToolset};
use crate::state::AppState;
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
        description = "Identify the authenticated owner and show which tools this surface exposes. Does not reveal credentials or targets."
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
        name = "credential_list",
        description = "Start here. Lists aliases, category/provider/env/tags, and policy only. Never returns secrets, origin/base_path, or database_url."
    )]
    pub async fn credential_list(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<ListCredentialsInput>,
    ) -> Result<Json<CredentialListOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential_list",
            crate::mcp::tools::credentials::list(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "api_call",
        description = "Required: alias, purpose, request_path. Call an HTTP alias from credential_list; send only request_path under the hidden origin/base_path. To shape large JSON: jsonpath returns one array per path (columnar); table returns one object per row (base + columns, like SQL JSON_TABLE) — prefer table to align several fields per item. length()/count() suffixes return small scalar counts."
    )]
    pub async fn api_call(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<ApiCallInput>,
    ) -> Result<Json<ApiCallOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "api_call",
            crate::mcp::tools::api_call::call(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "sql_query",
        description = "Required: alias, purpose, query. Optional database selects another DB on the same registered Postgres server. Run read-only SELECT/WITH on a SQL alias. Prefer explicit columns/WHERE/count/group; avoid SELECT *. For SQL column arrays, use row_count or $.column.length() for row count."
    )]
    pub async fn sql_query(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<SqlQueryInput>,
    ) -> Result<Json<SqlQueryOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "sql_query",
            crate::mcp::tools::sql_query::call(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "sql_schema",
        description = "Required: alias, purpose. Optional database selects another DB on the same registered Postgres server. Inspect SQL schema before unknown queries. mode=tables lists tables; mode=table with namespace/table shows columns/indexes. Never returns row data."
    )]
    pub async fn sql_schema(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<SqlSchemaInput>,
    ) -> Result<Json<SqlSchemaOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "sql_schema",
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
            .with_instructions("Use credential_list first to choose an alias. For HTTP, call api_call with request_path only; target URLs stay hidden. To shape an HTTP response, jsonpath returns one array per path (columnar), while table returns one object per row (base enumerates rows, columns maps each column name to a path relative to each row, like SQL JSON_TABLE); prefer table when you need several columns aligned per item, and the two are mutually exclusive. For SQL, optional database selects another DB on the same registered Postgres server; run sql_schema before unknown tables, then sql_query with explicit columns/WHERE/count/group and avoid SELECT *. If body is omitted, follow omit_reason and more.options.next_action: add_jsonpath means inspect more.preview.paths and retry with 1-3 selected JSONPath paths; narrow_jsonpath means reduce the existing JSONPath scope; narrow_request means reduce the upstream request with target-native pagination/filter/selector/time range.")
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
        name = "credential_list",
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
            "credential_list",
            crate::mcp::tools::credentials::list(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "credential_register_http",
        description = "Register an HTTP target for api_call. Put scheme+host in origin, optional fixed prefix in base_path, and per-call paths in api_call.request_path. Secrets are sealed and never returned."
    )]
    pub async fn credential_register_http(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<RegisterHttpCredentialInput>,
    ) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential_register_http",
            crate::mcp::tools::credentials::register_http(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "credential_register_sql",
        description = "Register a Postgres target for sql_schema/sql_query. database_url identifies host/db/options; username/password are separate secrets and are never returned."
    )]
    pub async fn credential_register_sql(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<RegisterSqlCredentialInput>,
    ) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential_register_sql",
            crate::mcp::tools::credentials::register_sql(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "credential_update_http",
        description = "Update metadata and policy for an HTTP alias. origin/base_path and secret headers are immutable; rotate by delete + register."
    )]
    pub async fn credential_update_http(
        &self,
        Extension(parts): Extension<Parts>,
        input: Parameters<UpdateCredentialInput>,
    ) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
        crate::audit::mcp::record_tool(
            self.state.audit.as_ref(),
            &parts,
            "credential_update_http",
            crate::mcp::tools::credentials::update_http(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "credential_update_sql",
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
            "credential_update_sql",
            crate::mcp::tools::credentials::update_sql(&self.state, &parts, input),
        )
        .await
    }

    #[tool(
        name = "credential_delete",
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
            "credential_delete",
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
            .with_instructions("Admin surface manages credentials. Use origin/base_path/request_path for HTTP target boundaries: origin is scheme+host, base_path is a fixed hidden prefix, api_call.request_path is supplied later. For SQL, database_url is the target and username/password are separate secrets. Secrets and target URLs are never returned; rotate immutable target/secret fields by delete + register.")
    }
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
                "api_call",
                "credential_list",
                "me",
                "sql_query",
                "sql_schema"
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
                "credential_delete",
                "credential_list",
                "credential_register_http",
                "credential_register_sql",
                "credential_update_http",
                "credential_update_sql",
                "me",
            ]
        );
    }

    #[test]
    fn tool_names_match_frontend_remote_mcp_pattern() -> Result<(), String> {
        let tools = RuntimeMcpServer::tool_router()
            .list_all()
            .into_iter()
            .chain(AdminMcpServer::tool_router().list_all());

        for tool in tools {
            let name = tool.name.as_ref();
            if name.is_empty() || name.len() > 64 {
                return Err(format!("tool name length out of range: {name}"));
            }
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(format!(
                    "tool name must match ^[a-zA-Z0-9_-]{{1,64}}$: {name}"
                ));
            }
        }
        Ok(())
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
