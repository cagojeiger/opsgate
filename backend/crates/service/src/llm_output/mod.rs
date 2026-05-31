//! LLM-facing JSON output shaping.
//!
//! This module is intentionally transport-agnostic. API/MCP layers can use it
//! to return complete JSON when it fits the budget, or a bounded truncation
//! envelope with next-step hints when it does not.

mod json;

pub use json::{
    JsonOutput, JsonOutputOptions, More, MoreOptions, build_json_output,
    build_json_output_from_value, validate_json_paths,
};
