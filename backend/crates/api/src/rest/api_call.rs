use std::collections::BTreeMap;

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
use opsgate_service::api_call::{ApiCallInput, ApiCallOutput};

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/api/call", post(call))
}

async fn call(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<ApiCallResponse>, ApiError> {
    let request = serde_json::from_slice::<ApiCallRequest>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    state
        .tools
        .api_calls
        .call(&caller, request.into_service_input())
        .await
        .map(ApiCallResponse::from)
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct ApiCallRequest {
    pub(crate) alias: String,
    pub(crate) purpose: String,
    #[serde(default)]
    pub(crate) method: String,
    pub(crate) request_path: String,
    #[serde(default)]
    pub(crate) query: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub(crate) body: Option<Value>,
    #[serde(default)]
    pub(crate) content_type: String,
    #[serde(default)]
    pub(crate) jsonpath: Vec<String>,
    pub(crate) max_bytes: Option<usize>,
}

impl ApiCallRequest {
    fn into_service_input(self) -> ApiCallInput {
        ApiCallInput {
            alias: self.alias,
            purpose: self.purpose,
            method: self.method,
            request_path: self.request_path,
            query: self.query,
            headers: self.headers,
            body: self.body,
            content_type: self.content_type,
            jsonpath: self.jsonpath,
            max_bytes: self.max_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ApiCallResponse {
    pub(crate) status_code: i32,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) headers: BTreeMap<String, String>,
    #[schema(value_type = Object)]
    pub(crate) body: Value,
    pub(crate) truncated: bool,
    pub(crate) original_bytes: usize,
    pub(crate) returned_bytes: usize,
    pub(crate) latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub(crate) more: Option<Value>,
}

impl From<ApiCallOutput> for ApiCallResponse {
    fn from(output: ApiCallOutput) -> Self {
        Self {
            status_code: output.status_code,
            headers: output.headers,
            body: output.body,
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
        let request = ApiCallRequest {
            alias: "prod".to_owned(),
            purpose: "Check pod phases".to_owned(),
            method: "GET".to_owned(),
            request_path: "/api/v1/pods".to_owned(),
            query: BTreeMap::from([("limit".to_owned(), "10".to_owned())]),
            headers: BTreeMap::new(),
            body: None,
            content_type: String::new(),
            jsonpath: vec!["$.items[*].metadata.name".to_owned()],
            max_bytes: Some(4096),
        };

        let input = request.into_service_input();
        assert_eq!(input.alias, "prod");
        assert_eq!(input.request_path, "/api/v1/pods");
        assert_eq!(input.query.get("limit").map(String::as_str), Some("10"));
    }
}
