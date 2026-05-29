use axum::http::request::Parts;
use opsgate_domain::Caller;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::api_call::{ApiCallInput, ApiCallOutput};
use crate::state::AppState;

pub async fn call(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<ApiCallInput>,
) -> Result<Json<ApiCallOutput>, ErrorData> {
    let caller = parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))?;
    state
        .api_calls
        .call(caller, input)
        .await
        .map(Json)
        .map_err(map_error)
}

fn map_error(error: opsgate_core::Error) -> ErrorData {
    match error {
        opsgate_core::Error::Forbidden(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Validation(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::NotFound(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.api_call.internal_error", detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}
