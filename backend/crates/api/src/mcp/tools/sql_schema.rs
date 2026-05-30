use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::sql_schema::{SqlSchemaInput, SqlSchemaOutput};
use crate::state::AppState;

pub async fn call(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<SqlSchemaInput>,
) -> Result<Json<SqlSchemaOutput>, ErrorData> {
    let caller = crate::mcp::tools::context::caller(parts)?;
    state
        .sql_schema
        .execute(caller, input)
        .await
        .map(Json)
        .map_err(|error| crate::mcp::tools::error::map_core_error("sql.schema", error))
}
