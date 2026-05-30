use axum::http::request::Parts;
use opsgate_domain::Caller;
use rmcp::ErrorData;

pub(crate) fn caller(parts: &Parts) -> Result<&Caller, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))
}
