use axum::http::request::Parts;
use opsgate_domain::Caller;
use rmcp::ErrorData;
use rmcp::Json;

use crate::identity::me::{MeOutput, build_me};

pub fn call(parts: &Parts) -> Result<Json<MeOutput>, ErrorData> {
    let caller = parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))?;
    Ok(Json(build_me(caller)))
}
