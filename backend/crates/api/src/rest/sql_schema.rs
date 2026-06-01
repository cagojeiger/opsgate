use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::routing::post;
use axum::{Json, Router};
use opsgate_model::Caller;
use opsgate_service::sql_schema::{SqlSchemaInput, SqlSchemaOutput};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/sql/schema", post(schema))
}

async fn schema(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<SqlSchemaResponse>, ApiError> {
    let request = serde_json::from_slice::<SqlSchemaRequest>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    state
        .tools
        .sql_schema
        .execute(&caller, request.into_service_input())
        .await
        .map(SqlSchemaResponse::from)
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct SqlSchemaRequest {
    pub(crate) alias: String,
    pub(crate) purpose: String,
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) namespace: String,
    #[serde(default)]
    pub(crate) table: String,
    pub(crate) limit: Option<i32>,
    #[serde(default)]
    pub(crate) cursor: String,
    pub(crate) max_bytes: Option<usize>,
    pub(crate) timeout_ms: Option<u32>,
    #[serde(default)]
    pub(crate) include_indexes: bool,
}

impl SqlSchemaRequest {
    fn into_service_input(self) -> SqlSchemaInput {
        SqlSchemaInput {
            alias: self.alias,
            purpose: self.purpose,
            mode: self.mode,
            namespace: self.namespace,
            table: self.table,
            limit: self.limit,
            cursor: self.cursor,
            max_bytes: self.max_bytes,
            timeout_ms: self.timeout_ms,
            include_indexes: self.include_indexes,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SqlSchemaResponse {
    pub(crate) mode: String,
    #[schema(value_type = Object)]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) tables: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub(crate) table: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub(crate) page: Option<Value>,
    pub(crate) truncated: bool,
    pub(crate) returned_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub(crate) more: Option<Value>,
    pub(crate) latency_ms: i64,
}

impl From<SqlSchemaOutput> for SqlSchemaResponse {
    fn from(output: SqlSchemaOutput) -> Self {
        Self {
            mode: output.mode,
            tables: output
                .tables
                .into_iter()
                .map(|table| serde_json::json!(table))
                .collect(),
            table: output.table.map(|table| serde_json::json!(table)),
            page: output.page.map(|page| serde_json::json!(page)),
            truncated: output.truncated,
            returned_bytes: output.returned_bytes,
            more: output.more.map(|more| serde_json::json!(more)),
            latency_ms: output.latency_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_maps_to_service_input() {
        let request = SqlSchemaRequest {
            alias: "analytics".to_owned(),
            purpose: "Inspect schema safely".to_owned(),
            mode: "table".to_owned(),
            namespace: "public".to_owned(),
            table: "audit_logs".to_owned(),
            limit: Some(10),
            cursor: String::new(),
            max_bytes: Some(4096),
            timeout_ms: Some(1000),
            include_indexes: true,
        };
        let input = request.into_service_input();
        assert_eq!(input.alias, "analytics");
        assert_eq!(input.mode, "table");
        assert!(input.include_indexes);
    }
}
