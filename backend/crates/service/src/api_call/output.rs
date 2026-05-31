use std::collections::BTreeMap;

use opsgate_core::llm_output::More;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ApiCallOutput {
    pub status_code: i32,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
    pub truncated: bool,
    pub original_bytes: usize,
    pub returned_bytes: usize,
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
}
