use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::state::AppState;
use opsgate_service::api_call::{ApiCallInput, ApiCallOutput};

pub async fn call(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<ApiCallInput>,
) -> Result<Json<ApiCallOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    state
        .tools
        .api_calls
        .call(caller, input)
        .await
        .map(Json)
        .map_err(|error| crate::mcp::tools::map_core_error("api_call", error))
}
