//! Application-wide error type.
//!
//! Domain and db layers return `core::Error`; the api layer maps it to HTTP
//! responses. Keep variants coarse-grained here and add detail via messages.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The requested resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// The caller sent something invalid.
    #[error("invalid input: {0}")]
    Validation(String),

    /// A dependency (db, external service) failed.
    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    pub fn not_found(msg: impl fmt::Display) -> Self {
        Self::NotFound(msg.to_string())
    }

    pub fn validation(msg: impl fmt::Display) -> Self {
        Self::Validation(msg.to_string())
    }

    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::Internal(msg.to_string())
    }
}
