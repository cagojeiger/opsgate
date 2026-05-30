use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::sql_query::{SqlQueryInput, SqlQueryOutput};
use crate::state::AppState;

pub async fn call(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<SqlQueryInput>,
) -> Result<Json<SqlQueryOutput>, ErrorData> {
    let caller = crate::mcp::tools::context::caller(parts)?;
    state
        .sql_query
        .execute(caller, input)
        .await
        .map(Json)
        .map_err(|error| crate::mcp::tools::error::map_core_error("sql.query", error))
}
