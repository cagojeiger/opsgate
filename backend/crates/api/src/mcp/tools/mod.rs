use axum::http::request::Parts;
use opsgate_model::Caller;
use rmcp::ErrorData;
use serde_json::{Value, json};

pub(crate) mod api_call;
pub(crate) mod credentials;
pub(crate) mod me;
pub(crate) mod sql_query;
pub(crate) mod sql_schema;

pub(crate) fn caller(parts: &Parts) -> Result<&Caller, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))
}

pub(crate) fn map_core_error(tool: &'static str, error: opsgate_core::Error) -> ErrorData {
    match error {
        opsgate_core::Error::Forbidden(message)
        | opsgate_core::Error::Validation(message)
        | opsgate_core::Error::NotFound(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::UserSafe {
            kind,
            message,
            hint,
            data,
        } => ErrorData::invalid_params(message, Some(user_safe_error_data(kind, hint, data))),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.tool.internal_error", tool, detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}

fn user_safe_error_data(kind: &'static str, hint: Option<String>, data: Option<Value>) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("kind".to_owned(), json!(kind));
    object.insert("hint".to_owned(), json!(hint));
    if let Some(data) = data {
        if let Value::Object(data) = data {
            object.extend(data);
        } else {
            object.insert("data".to_owned(), data);
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_core_error_is_redacted_for_mcp_clients() {
        let error = map_core_error(
            "api_call",
            opsgate_core::Error::internal("target returned Authorization: Bearer secret-token"),
        );

        assert_eq!(error.message, "internal server error");
        assert!(error.data.is_none());
        assert!(!error.message.contains("secret-token"));
    }

    #[test]
    fn validation_core_error_stays_actionable_for_mcp_clients() {
        let error = map_core_error(
            "api_call",
            opsgate_core::Error::validation("target response is not JSON"),
        );

        assert_eq!(error.message, "target response is not JSON");
        assert!(error.data.is_none());
    }

    #[test]
    fn user_safe_core_error_maps_to_invalid_params_with_data() -> Result<(), String> {
        let error = map_core_error(
            "sql_query",
            opsgate_core::Error::user_safe(
                "sql_undefined_column",
                "SQL references a column that does not exist.",
                Some("Use sql_schema first."),
            ),
        );

        let data = error.data.ok_or_else(|| "expected error data".to_owned())?;
        assert_eq!(
            error.message,
            "SQL references a column that does not exist."
        );
        assert_eq!(
            data.get("kind").and_then(serde_json::Value::as_str),
            Some("sql_undefined_column")
        );
        assert_eq!(
            data.get("hint").and_then(serde_json::Value::as_str),
            Some("Use sql_schema first.")
        );
        Ok(())
    }

    #[test]
    fn user_safe_core_error_preserves_public_mcp_data() -> Result<(), String> {
        let error = map_core_error(
            "api_call",
            opsgate_core::Error::user_safe_with_data(
                "policy_method_not_allowed",
                "method not allowed by credential policy",
                Some("Use one of the allowed methods."),
                json!({
                    "next_action": "use_allowed_method",
                    "policy_hint": {
                        "allowed_methods": ["GET"]
                    }
                }),
            ),
        );

        let data = error.data.ok_or_else(|| "expected error data".to_owned())?;
        assert_eq!(
            data.get("kind").and_then(serde_json::Value::as_str),
            Some("policy_method_not_allowed")
        );
        assert_eq!(
            data.get("next_action").and_then(serde_json::Value::as_str),
            Some("use_allowed_method")
        );
        assert_eq!(
            data.pointer("/policy_hint/allowed_methods/0")
                .and_then(serde_json::Value::as_str),
            Some("GET")
        );
        Ok(())
    }
}
