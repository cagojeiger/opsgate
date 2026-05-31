//! Application services for opsgate use cases.
//!
//! This crate orchestrates credential lookup, policy checks, secret handling,
//! target infrastructure, output shaping, and audit/history recording. It must
//! not depend on axum, rmcp, or OAuth transport types.

pub mod api_call;
mod audit;
pub mod credential;
mod llm_output;
pub mod sql_common;
pub mod sql_query;
pub mod sql_schema;
