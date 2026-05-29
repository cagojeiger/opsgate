//! Shared primitives for opsgate: configuration and error types.
//!
//! This crate has no knowledge of HTTP or the database — keep it that way so
//! every other crate can depend on it without pulling heavy dependencies.

pub mod config;
pub mod error;

pub use config::Config;
pub use error::{Error, Result};
