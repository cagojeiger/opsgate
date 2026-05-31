use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::state::AppState;
use opsgate_service::sql_schema::{SqlSchemaInput, SqlSchemaOutput};

pub async fn call(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<SqlSchemaInput>,
) -> Result<Json<SqlSchemaOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    state
        .tools
        .sql_schema
        .execute(caller, input)
        .await
        .map(Json)
        .map_err(|error| crate::mcp::tools::map_core_error("sql.schema", error))
}
