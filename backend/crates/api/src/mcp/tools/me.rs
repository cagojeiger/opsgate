use axum::http::request::Parts;
use opsgate_domain::Caller;
use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::tool::Extension;
use rmcp::model::CallToolResult;
use rmcp::tool;

use crate::mcp::server::McpServer;
use crate::me::{MeOutput, build_me};

impl McpServer {
    #[tool(name = "me", description = "Return the authenticated caller identity.")]
    pub async fn me_tool(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<Json<MeOutput>, ErrorData> {
        let caller = parts.extensions.get::<Caller>().ok_or_else(|| {
            ErrorData::invalid_params("authenticated caller extension missing", None)
        })?;
        Ok(Json(build_me(caller, &self.state.config.admin_email)))
    }
}

pub fn _result_type_marker(_result: CallToolResult) {}
