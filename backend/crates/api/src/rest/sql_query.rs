use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::routing::post;
use axum::{Json, Router};
use opsgate_model::Caller;

use crate::error::ApiError;
use crate::state::AppState;
use opsgate_service::sql_query::{SqlQueryInput, SqlQueryOutput};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/sql/query", post(query))
}

async fn query(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<SqlQueryOutput>, ApiError> {
    let input = serde_json::from_slice::<SqlQueryInput>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    state
        .tools
        .sql_query
        .execute(&caller, input)
        .await
        .map(Json)
        .map_err(ApiError::from)
}
