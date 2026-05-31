//! Application services for opsgate use cases.
//!
//! This crate orchestrates credential lookup, policy checks, secret handling,
//! target infrastructure, output shaping, and audit/history recording. It must
//! not depend on axum, rmcp, or OAuth transport types.

pub mod api_call;
mod audit;
pub mod credential;
pub mod crypto;
mod llm_output;
pub mod sql_common;
pub mod sql_query;
pub mod sql_schema;

// Re-exported for bootstrap wiring so the API crate does not depend on infra directly.
pub use opsgate_infra::postgres_pool::TargetPgPools;
