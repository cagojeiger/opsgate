//! HTTP error type. Domain/db errors map into this on their way out.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use opsgate_core::Error as CoreError;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<String>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            hint: None,
        }
    }

    pub(crate) fn user_safe(
        code: &'static str,
        message: impl Into<String>,
        hint: Option<String>,
    ) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
            hint,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub(crate) fn invalid_field(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_field", message)
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }
}

/// Map the domain error to an HTTP response. Internal details are logged but
/// never leaked to the client.
impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::NotFound(msg) => Self::not_found(msg),
            CoreError::Forbidden(msg) => Self::forbidden(msg),
            CoreError::Validation(msg) => Self::invalid_field(msg),
            CoreError::UserSafe {
                kind,
                message,
                hint,
            } => Self::user_safe(kind, message, hint),
            CoreError::Internal(msg) => {
                tracing::error!(event = "error.internal", detail = %msg);
                Self::internal("internal server error")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({
            "error": self.code,
            "message": self.message,
        });
        if let Some(hint) = self.hint
            && let Some(object) = body.as_object_mut()
        {
            object.insert("hint".to_owned(), serde_json::json!(hint));
        }
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn user_safe_core_error_maps_to_public_http_error() {
        let error = ApiError::from(opsgate_core::Error::user_safe(
            "sql_undefined_column",
            "SQL references a column that does not exist.",
            Some("Use sql.schema first."),
        ));

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "sql_undefined_column");
        assert!(error.message.contains("column"));
        assert_eq!(error.hint.as_deref(), Some("Use sql.schema first."));
    }
}
