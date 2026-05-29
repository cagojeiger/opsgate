use axum::http::request::Parts;
use opsgate_domain::credential::{Credential, CredentialPolicy};
use opsgate_domain::{Caller, CredentialCategory};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, Json};
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::BTreeSet;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialOutput {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<CredentialCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<CredentialPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_private_network: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_tls_ca: Option<bool>,
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
    let fields = input.fields.clone().map(normalize_fields);
    let page = state
        .credentials
        .list(caller.user.id, input)
        .await
        .map_err(map_error)?;
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

impl CredentialOutput {
    fn from_with_fields(credential: Credential, fields: Option<&BTreeSet<String>>) -> Self {
        Self {
            alias: credential.alias,
            category: include_field(fields, "category").then_some(credential.category),
            provider: include_field(fields, "provider").then_some(credential.provider),
            description: include_field(fields, "description").then_some(credential.description),
            env: include_field(fields, "env").then_some(credential.env),
            tags: include_field(fields, "tags").then_some(credential.tags),
            policy: include_field(fields, "policy").then_some(credential.policy),
            allow_private_network: include_field(fields, "allow_private_network")
                .then_some(credential.allow_private_network),
            has_tls_ca: include_field(fields, "has_tls_ca").then_some(credential.has_tls_ca),
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

fn normalize_fields(fields: Vec<String>) -> BTreeSet<String> {
    fields
        .into_iter()
        .map(|field| field.trim().to_ascii_lowercase())
        .filter(|field| !field.is_empty())
        .collect()
}

fn include_field(fields: Option<&BTreeSet<String>>, field: &str) -> bool {
    fields.is_none_or(|fields| fields.contains(field))
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::credential::CredentialCategory;
    use uuid::Uuid;

    use super::*;

    fn credential() -> Credential {
        Credential {
            id: Uuid::nil(),
            owner_user_id: Uuid::nil(),
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            endpoint: "https://internal.example.test/secret-path".to_owned(),
            description: "cluster api".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["prod".to_owned(), "k8s".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            has_tls_ca: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn credential_output_never_serializes_endpoint_or_secret_material()
    -> Result<(), serde_json::Error> {
        let output = CredentialOutput::from_with_fields(credential(), None);
        let json = serde_json::to_string(&output)?;

        assert!(json.contains("prod-api"));
        assert!(!json.contains("internal.example.test"));
        assert!(!json.contains("secret-path"));
        assert!(!json.contains("secret"));
        Ok(())
    }

    #[test]
    fn credential_output_fields_limit_metadata_surface() -> Result<(), serde_json::Error> {
        let fields = BTreeSet::from(["provider".to_owned()]);
        let output = CredentialOutput::from_with_fields(credential(), Some(&fields));
        let value = serde_json::to_value(output)?;

        assert_eq!(value.get("alias"), Some(&serde_json::json!("prod-api")));
        assert_eq!(value.get("provider"), Some(&serde_json::json!("k8s")));
        assert!(value.get("policy").is_none());
        assert!(value.get("tags").is_none());
        assert!(value.get("allow_private_network").is_none());
        Ok(())
    }
}
