use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::routing::post;
use axum::{Json, Router};
use opsgate_model::Caller;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

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
) -> Result<Json<SqlQueryResponse>, ApiError> {
    let request = serde_json::from_slice::<SqlQueryRequest>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    state
        .tools
        .sql_query
        .execute(&caller, request.into_service_input())
        .await
        .map(SqlQueryResponse::from)
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct SqlQueryRequest {
    pub(crate) alias: String,
    pub(crate) purpose: String,
    pub(crate) query: String,
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub(crate) params: Vec<Value>,
    #[serde(default)]
    pub(crate) jsonpath: Vec<String>,
    pub(crate) max_rows: Option<i32>,
    pub(crate) max_bytes: Option<usize>,
    pub(crate) timeout_ms: Option<u32>,
}

impl SqlQueryRequest {
    fn into_service_input(self) -> SqlQueryInput {
        SqlQueryInput {
            alias: self.alias,
            purpose: self.purpose,
            query: self.query,
            params: self.params,
            jsonpath: self.jsonpath,
            max_rows: self.max_rows,
            max_bytes: self.max_bytes,
            timeout_ms: self.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SqlQueryResponse {
    #[schema(value_type = Object)]
    pub(crate) body: Value,
    pub(crate) row_count: usize,
    pub(crate) truncated: bool,
    pub(crate) original_bytes: usize,
    pub(crate) returned_bytes: usize,
    pub(crate) latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub(crate) more: Option<Value>,
}

impl From<SqlQueryOutput> for SqlQueryResponse {
    fn from(output: SqlQueryOutput) -> Self {
        Self {
            body: output.body,
            row_count: output.row_count,
            truncated: output.truncated,
            original_bytes: output.original_bytes,
            returned_bytes: output.returned_bytes,
            latency_ms: output.latency_ms,
            more: output.more.map(|more| serde_json::json!(more)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_maps_to_service_input() {
        let request = SqlQueryRequest {
            alias: "analytics".to_owned(),
            purpose: "Count recent rows".to_owned(),
            query: "select count(*) from audit_logs".to_owned(),
            params: vec![Value::String("ok".to_owned())],
            jsonpath: vec!["$.count.length()".to_owned()],
            max_rows: Some(10),
            max_bytes: Some(2048),
            timeout_ms: Some(1000),
        };

        let input = request.into_service_input();
        assert_eq!(input.alias, "analytics");
        assert_eq!(input.params.len(), 1);
        assert_eq!(input.max_rows, Some(10));
    }
}
