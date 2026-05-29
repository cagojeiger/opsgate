use axum::http::request::Parts;
use opsgate_domain::credential::{Credential, CredentialPolicy};
use opsgate_domain::{Caller, CredentialCategory};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};
use schemars::JsonSchema;
use serde::Serialize;

use crate::credential::{
    CredentialUpdate, DeleteCredentialInput, ListCredentialsInput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, UpdateCredentialInput,
};
use crate::state::AppState;

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialListOutput {
    pub credentials: Vec<CredentialOutput>,
    pub page: PageOutput,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PageOutput {
    pub limit: i64,
    pub returned: usize,
    pub has_more: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialOutput {
    pub alias: String,
    pub category: CredentialCategory,
    pub provider: String,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
    pub has_tls_ca: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct UpdateCredentialOutput {
    pub alias: String,
    pub category: CredentialCategory,
    pub provider: String,
    pub env: String,
    pub tags: Vec<String>,
    pub description: String,
    pub updated: bool,
    pub changed_fields: Vec<&'static str>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteCredentialOutput {
    pub alias: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RegisterCredentialOutput {
    pub alias: String,
    pub category: CredentialCategory,
    pub provider: String,
    pub env: String,
    pub tags: Vec<String>,
    pub description: String,
    pub created: bool,
}

pub async fn list(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<ListCredentialsInput>,
) -> Result<Json<CredentialListOutput>, ErrorData> {
    let caller = caller(parts)?;
    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let credentials = state
        .credentials
        .list(caller.user.id, input)
        .await
        .map_err(map_error)?;
    let returned = credentials.len();
    Ok(Json(CredentialListOutput {
        credentials: credentials
            .into_iter()
            .map(CredentialOutput::from)
            .collect(),
        page: PageOutput {
            limit,
            returned,
            has_more: returned >= usize::try_from(limit).unwrap_or(100),
        },
    }))
}

pub async fn register_http(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<RegisterHttpCredentialInput>,
) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
    let caller = caller(parts)?;
    let credential = state
        .credentials
        .register_http(caller.user.id, input)
        .await
        .map_err(map_error)?;
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

pub async fn register_sql(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<RegisterSqlCredentialInput>,
) -> Result<Json<RegisterCredentialOutput>, ErrorData> {
    let caller = caller(parts)?;
    let credential = state
        .credentials
        .register_sql(caller.user.id, input)
        .await
        .map_err(map_error)?;
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

pub async fn update_http(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<UpdateCredentialInput>,
) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
    let caller = caller(parts)?;
    let update = state
        .credentials
        .update_http(caller.user.id, input)
        .await
        .map_err(map_error)?;
    Ok(Json(UpdateCredentialOutput::from_update(update)))
}

pub async fn update_sql(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<UpdateCredentialInput>,
) -> Result<Json<UpdateCredentialOutput>, ErrorData> {
    let caller = caller(parts)?;
    let update = state
        .credentials
        .update_sql(caller.user.id, input)
        .await
        .map_err(map_error)?;
    Ok(Json(UpdateCredentialOutput::from_update(update)))
}

pub async fn delete(
    state: &AppState,
    parts: &Parts,
    Parameters(input): Parameters<DeleteCredentialInput>,
) -> Result<Json<DeleteCredentialOutput>, ErrorData> {
    let caller = caller(parts)?;
    let credential = state
        .credentials
        .delete(caller.user.id, input)
        .await
        .map_err(map_error)?;
    Ok(Json(DeleteCredentialOutput {
        alias: credential.alias,
        deleted: true,
    }))
}

impl From<Credential> for CredentialOutput {
    fn from(credential: Credential) -> Self {
        Self {
            alias: credential.alias,
            category: credential.category,
            provider: credential.provider,
            description: credential.description,
            env: credential.env,
            tags: credential.tags,
            policy: credential.policy,
            allow_private_network: credential.allow_private_network,
            has_tls_ca: credential.has_tls_ca,
        }
    }
}

impl UpdateCredentialOutput {
    fn from_update(update: CredentialUpdate) -> Self {
        Self {
            alias: update.credential.alias,
            category: update.credential.category,
            provider: update.credential.provider,
            env: update.credential.env,
            tags: update.credential.tags,
            description: update.credential.description,
            updated: true,
            changed_fields: update.changed_fields,
        }
    }
}

impl RegisterCredentialOutput {
    fn created(credential: Credential) -> Self {
        Self {
            alias: credential.alias,
            category: credential.category,
            provider: credential.provider,
            env: credential.env,
            tags: credential.tags,
            description: credential.description,
            created: true,
        }
    }
}

fn caller(parts: &Parts) -> Result<&Caller, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .ok_or_else(|| ErrorData::invalid_params("authenticated caller extension missing", None))
}

fn map_error(error: opsgate_core::Error) -> ErrorData {
    match error {
        opsgate_core::Error::Validation(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::NotFound(message) => ErrorData::invalid_params(message, None),
        opsgate_core::Error::Internal(message) => {
            tracing::error!(event = "mcp.credential.internal_error", detail = %message);
            ErrorData::internal_error("internal server error", None)
        }
    }
}
