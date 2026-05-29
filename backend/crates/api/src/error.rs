//! HTTP error type. Domain/db errors map into this on their way out.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use opsgate_core::Error as CoreError;
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn invalid_field(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_field", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}

/// Map the domain error to an HTTP response. Internal details are logged but
/// never leaked to the client.
impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::NotFound(msg) => Self::not_found(msg),
            CoreError::Validation(msg) => Self::invalid_field(msg),
            CoreError::Internal(msg) => {
                tracing::error!(event = "error.internal", detail = %msg);
                Self::internal("internal server error")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.code,
                "message": self.message,
            })),
        )
            .into_response()
    }
}
