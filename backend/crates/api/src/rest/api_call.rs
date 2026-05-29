use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::routing::post;
use axum::{Json, Router};
use opsgate_domain::Caller;

use crate::api_call::{ApiCallInput, ApiCallOutput};
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/api/call", post(call))
}

async fn call(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<ApiCallOutput>, ApiError> {
    let input = serde_json::from_slice::<ApiCallInput>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    state
        .api_calls
        .call(&caller, input)
        .await
        .map(Json)
        .map_err(ApiError::from)
}
