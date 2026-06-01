use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::state::AppState;
use opsgate_service::credential::{
    CredentialListOutput, DeleteCredentialInput, DeleteCredentialOutput, ListCredentialsInput,
    RegisterCredentialOutput, RegisterHttpCredentialInput, RegisterSqlCredentialInput,
    UpdateCredentialInput, UpdateCredentialOutput,
};

pub async fn list(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<ListCredentialsInput>,
) -> Result<Json<CredentialListOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    state
        .tools
        .credentials
        .list(caller.user.id, input)
        .await
        .map(Json)
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))
}

pub async fn register_http(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<RegisterHttpCredentialInput>,
) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let credential = state
        .tools
        .credentials
        .register_http(caller, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

pub async fn register_sql(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<RegisterSqlCredentialInput>,
) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let credential = state
        .tools
        .credentials
        .register_sql(caller, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

pub async fn update_http(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<UpdateCredentialInput>,
) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let update = state
        .tools
        .credentials
        .update_http(caller, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    Ok(Json(UpdateCredentialOutput::from_update(update)))
}

pub async fn update_sql(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<UpdateCredentialInput>,
) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let update = state
        .tools
        .credentials
        .update_sql(caller, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    Ok(Json(UpdateCredentialOutput::from_update(update)))
}

pub async fn delete(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<DeleteCredentialInput>,
) -> Result<Json<DeleteCredentialOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let credential = state
        .tools
        .credentials
        .delete(caller, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    Ok(Json(DeleteCredentialOutput::deleted(credential.alias)))
}
