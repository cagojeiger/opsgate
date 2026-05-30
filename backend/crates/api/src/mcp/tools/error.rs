use rmcp::ErrorData;

pub(crate) fn map_core_error(tool: &'static str, error: opsgate_core::Error) -> ErrorData {
    match error {
        opsgate_core::Error::Forbidden(message)
        | opsgate_core::Error::Validation(message)
        | opsgate_core::Error::NotFound(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.tool.internal_error", tool, detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}
