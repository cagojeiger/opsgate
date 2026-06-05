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

    /// The caller is authenticated but not allowed to perform this action.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// The caller sent something invalid.
    #[error("invalid input: {0}")]
    Validation(String),

    /// A dependency (db, external service) failed.
    #[error("internal error: {0}")]
    Internal(String),

    /// A dependency returned an error that is safe and useful for the caller.
    #[error("{kind}: {message}")]
    UserSafe {
        kind: &'static str,
        message: String,
        hint: Option<String>,
        data: Option<serde_json::Value>,
    },
}

impl Error {
    pub fn not_found(msg: impl fmt::Display) -> Self {
        Self::NotFound(msg.to_string())
    }

    pub fn forbidden(msg: impl fmt::Display) -> Self {
        Self::Forbidden(msg.to_string())
    }

    pub fn validation(msg: impl fmt::Display) -> Self {
        Self::Validation(msg.to_string())
    }

    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::Internal(msg.to_string())
    }

    pub fn user_safe(
        kind: &'static str,
        message: impl fmt::Display,
        hint: Option<impl fmt::Display>,
    ) -> Self {
        Self::UserSafe {
            kind,
            message: message.to_string(),
            hint: hint.map(|hint| hint.to_string()),
            data: None,
        }
    }

    pub fn user_safe_with_data(
        kind: &'static str,
        message: impl fmt::Display,
        hint: Option<impl fmt::Display>,
        data: serde_json::Value,
    ) -> Self {
        Self::UserSafe {
            kind,
            message: message.to_string(),
            hint: hint.map(|hint| hint.to_string()),
            data: Some(data),
        }
    }
}
