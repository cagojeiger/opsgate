//! HTTP error type. Domain/db errors map into this on their way out.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use opsgate_core::Error as CoreError;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<String>,
    data: Option<Value>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            hint: None,
            data: None,
        }
    }

    pub(crate) fn user_safe(
        code: &'static str,
        message: impl Into<String>,
        hint: Option<String>,
        data: Option<Value>,
    ) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
            hint,
            data,
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
                data,
            } => Self::user_safe(kind, message, hint, data),
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
        if let Some(data) = self.data
            && let Some(object) = body.as_object_mut()
        {
            object.insert("data".to_owned(), data);
        }
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn internal_core_error_is_redacted_for_http_clients() {
        let error = ApiError::from(opsgate_core::Error::internal(
            "target returned password=secret-token",
        ));

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "internal_error");
        assert_eq!(error.message, "internal server error");
        assert!(!error.message.contains("secret-token"));
    }

    #[test]
    fn validation_core_error_stays_actionable_for_http_clients() {
        let error = ApiError::from(opsgate_core::Error::validation(
            "request_path not allowed by credential policy",
        ));

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "invalid_field");
        assert!(error.message.contains("request_path"));
    }

    #[test]
    fn user_safe_core_error_maps_to_public_http_error() {
        let error = ApiError::from(opsgate_core::Error::user_safe(
            "sql_undefined_column",
            "SQL references a column that does not exist.",
            Some("Use sql_schema first."),
        ));

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "sql_undefined_column");
        assert_eq!(
            error.message,
            "SQL references a column that does not exist."
        );
        assert_eq!(error.hint.as_deref(), Some("Use sql_schema first."));
        assert!(error.data.is_none());
    }

    #[test]
    fn user_safe_core_error_preserves_public_http_data() {
        let error = ApiError::from(opsgate_core::Error::user_safe_with_data(
            "policy_method_not_allowed",
            "method not allowed by credential policy",
            Some("Use one of the allowed methods."),
            serde_json::json!({
                "next_action": "use_allowed_method",
                "policy_hint": {
                    "allowed_methods": ["GET"]
                }
            }),
        ));

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "policy_method_not_allowed");
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("next_action")),
            Some(&serde_json::json!("use_allowed_method"))
        );
    }
}
