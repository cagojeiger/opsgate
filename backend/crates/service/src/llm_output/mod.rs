//! LLM-facing JSON output shaping.
//!
//! This module is intentionally transport-agnostic. API/MCP layers can use it
//! to return complete JSON when it fits the budget, or a bounded truncation
//! envelope with next-step hints when it does not.

mod json;

pub use json::{
    BodyMode, BodyState, JsonOutput, JsonOutputOptions, More, MoreOptions, NextAction, OmitReason,
    SourceBodyMode, TableProjection, build_json_output, build_json_output_from_value,
    validate_json_paths, validate_table_projection,
};
