use axum::http::request::Parts;
use opsgate_model::Caller;
use rmcp::ErrorData;
use serde_json::json;

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
        } => ErrorData::invalid_params(
            message,
            Some(json!({
                "kind": kind,
                "hint": hint,
            })),
        ),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.tool.internal_error", tool, detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_safe_core_error_maps_to_invalid_params_with_data() -> Result<(), String> {
        let error = map_core_error(
            "sql.query",
            opsgate_core::Error::user_safe(
                "sql_undefined_column",
                "SQL references a column that does not exist.",
                Some("Use sql.schema first."),
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
            Some("Use sql.schema first.")
        );
        Ok(())
    }
}
