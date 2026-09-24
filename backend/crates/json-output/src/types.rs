use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_MAX_BYTES: usize = 4096;
const DEFAULT_MAX_ALLOWED_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonOutputOptions {
    pub max_bytes: usize,
    pub max_allowed_bytes: usize,
    pub json_paths: Vec<String>,
    pub table: Option<TableProjection>,
    pub source_body_truncated: bool,
    pub original_bytes: Option<usize>,
    pub source_body_mode: SourceBodyMode,
}

impl Default for JsonOutputOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_allowed_bytes: DEFAULT_MAX_ALLOWED_BYTES,
            json_paths: Vec::new(),
            table: None,
            source_body_truncated: false,
            original_bytes: None,
            source_body_mode: SourceBodyMode::RawJson,
        }
    }
}

/// Table projection over ragged JSON, mirroring the ISO SQL/JSON
/// `JSON_TABLE` model: `base` enumerates the rows, and each `columns` entry is a
/// column path evaluated relative to a single row (the path's `$` rebinds to the
/// row node). The result is an array of one object per row. Every path is the
/// same RFC 9535 safe subset enforced by [`crate::validate_json_paths`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableProjection {
    pub base: String,
    pub columns: std::collections::BTreeMap<String, String>,
}

impl JsonOutputOptions {
    /// True when the body is reshaped (keyed jsonpath or table) rather
    /// than returned raw. Drives body mode, preview, and omit-reason selection.
    pub(super) fn is_projection(&self) -> bool {
        !self.json_paths.is_empty() || self.table.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceBodyMode {
    RawJson,
    ColumnarJson,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyMode {
    RawJson,
    ColumnarJson,
    JsonpathProjection,
    TableProjection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    Returned,
    Omitted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum OmitReason {
    #[serde(rename = "output_body_too_large")]
    Output,
    #[serde(rename = "projection_body_too_large")]
    Projection,
    #[serde(rename = "source_body_too_large")]
    Source,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    AddJsonpath,
    NarrowJsonpath,
    NarrowTableProjection,
    NarrowRequest,
    AdjustMaxRows,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct JsonOutput {
    pub body_mode: BodyMode,
    pub body_state: BodyState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_reason: Option<OmitReason>,
    #[schemars(schema_with = "opsgate_core::schema::json_value_schema")]
    pub body: Value,
    pub original_bytes: usize,
    pub returned_bytes: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more: Option<More>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct More {
    pub truncated: bool,
    pub options: MoreOptions,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Preview>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct MoreOptions {
    pub next_action: NextAction,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggested_jsonpath: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct Preview {
    pub path_count: usize,
    pub returned_paths: usize,
    pub truncated: bool,
    pub paths: Vec<PreviewPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PreviewPath {
    pub path: String,
    #[serde(rename = "type")]
    pub value_type: String,
    pub present_sampled: usize,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub nulls_sampled: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_length_min_sampled: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_length_max_sampled: Option<usize>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub nested_expansion_stopped: bool,
}

impl From<SourceBodyMode> for BodyMode {
    fn from(value: SourceBodyMode) -> Self {
        match value {
            SourceBodyMode::RawJson => BodyMode::RawJson,
            SourceBodyMode::ColumnarJson => BodyMode::ColumnarJson,
        }
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}
