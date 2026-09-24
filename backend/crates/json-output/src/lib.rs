//! LLM-facing JSON output shaping.
//!
//! This module is intentionally transport-agnostic. API/MCP layers can use it
//! to return complete JSON when it fits the budget, or a bounded truncation
//! envelope with next-step hints when it does not.

mod json;
mod preview;
mod projection;
mod types;

pub use json::{build_json_output, build_json_output_from_value};
pub use projection::{validate_json_paths, validate_table_projection};
pub use types::{
    BodyMode, BodyState, JsonOutput, JsonOutputOptions, More, MoreOptions, NextAction, OmitReason,
    SourceBodyMode, TableProjection,
};
