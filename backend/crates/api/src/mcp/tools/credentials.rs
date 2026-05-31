use axum::http::request::Parts;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};

use crate::state::AppState;
use opsgate_service::credential::{
    CredentialListOutput, CredentialOutput, DeleteCredentialInput, DeleteCredentialOutput,
    ListCredentialsInput, PageOutput, RegisterCredentialOutput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, UpdateCredentialInput, UpdateCredentialOutput, normalize_fields,
};

pub async fn list(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<ListCredentialsInput>,
) -> Result<Json<CredentialListOutput>, ErrorData> {
    let caller = crate::mcp::tools::caller(parts)?;
    let fields = input.fields.clone().and_then(normalize_fields);
    let page = state
        .tools
        .credentials
        .list(caller.user.id, input)
        .await
        .map_err(|error| crate::mcp::tools::map_core_error("credential", error))?;
    let returned = page.credentials.len();
    Ok(Json(CredentialListOutput {
        credentials: page
            .credentials
            .into_iter()
            .map(|credential| CredentialOutput::from_with_fields(credential, fields.as_ref()))
            .collect(),
        page: PageOutput {
            limit: page.limit,
            returned,
            has_more: page.has_more,
            next_cursor: page.next_cursor,
        },
    }))
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
