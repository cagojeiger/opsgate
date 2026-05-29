use std::collections::BTreeSet;

use axum::body::Bytes;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use opsgate_domain::Caller;
use opsgate_domain::credential::{Credential, CredentialCategory, CredentialPolicy};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::credential::{
    DeleteCredentialInput, ListCredentialsInput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, SecretHeaderInput,
};
use crate::error::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/credentials", get(list).post(register))
        .route("/v1/credentials/{alias}", delete(remove))
}

async fn register(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<RegisterCredentialOutput>, ApiError> {
    let input = serde_json::from_slice::<RegisterCredentialInput>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    let credential = match input.into_service_input() {
        RegisterServiceInput::Http(input) => {
            state.credentials.register_http(&caller, input).await?
        }
        RegisterServiceInput::Sql(input) => state.credentials.register_sql(&caller, input).await?,
    };
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

async fn list(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<CredentialListOutput>, ApiError> {
    let input = parse_list_query(query.as_deref())?;
    let fields = input.fields.clone().map(normalize_fields);
    let page = state.credentials.list(caller.user.id, input).await?;
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

fn parse_list_query(query: Option<&str>) -> Result<ListCredentialsInput, ApiError> {
    let mut input = ListCredentialsInput {
        category: None,
        provider: None,
        env: None,
        tag: None,
        q: None,
        fields: None,
        limit: None,
        cursor: None,
    };
    let mut fields = Vec::new();

    let Some(query) = query else {
        return Ok(input);
    };

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = value.into_owned();
        match key.as_ref() {
            "category" if input.category.is_none() && !value.trim().is_empty() => {
                input.category = Some(parse_category(&value)?);
            }
            "provider" => set_first(&mut input.provider, value),
            "env" => set_first(&mut input.env, value),
            "tag" => set_first(&mut input.tag, value),
            "q" => set_first(&mut input.q, value),
            "fields" => fields.push(value),
            "limit" if input.limit.is_none() && !value.trim().is_empty() => {
                let limit = value
                    .parse::<i64>()
                    .map_err(|error| ApiError::invalid_field(format!("invalid limit: {error}")))?;
                input.limit = Some(limit);
            }
            "cursor" => set_first(&mut input.cursor, value),
            _ => {}
        }
    }

    if !fields.is_empty() {
        input.fields = Some(fields);
    }
    Ok(input)
}

fn parse_category(value: &str) -> Result<CredentialCategory, ApiError> {
    match value.trim() {
        "http" => Ok(CredentialCategory::Http),
        "sql" => Ok(CredentialCategory::Sql),
        _ => Err(ApiError::invalid_field("invalid category")),
    }
}

fn set_first(target: &mut Option<String>, value: String) {
    if target.is_none() {
        *target = Some(value);
    }
}

async fn remove(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(alias): Path<String>,
    body: Bytes,
) -> Result<Json<DeleteCredentialOutput>, ApiError> {
    let reason = if body.is_empty() {
        String::new()
    } else {
        serde_json::from_slice::<DeleteCredentialBody>(&body)
            .map_err(|_error| ApiError::invalid_field("invalid json"))?
            .reason
    };
    let credential = state
        .credentials
        .delete(&caller, DeleteCredentialInput { alias, reason })
        .await?;
    Ok(Json(DeleteCredentialOutput {
        alias: credential.alias,
        deleted: true,
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterCredentialInput {
    category: CredentialCategory,
    provider: String,
    alias: String,
    endpoint: String,
    #[serde(default)]
    secret: RegisterSecretInput,
    #[serde(default)]
    description: String,
    #[serde(default)]
    env: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    policy: CredentialPolicy,
    #[serde(default)]
    allow_private_network: bool,
    #[serde(default)]
    tls_server_ca: String,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterSecretInput {
    #[serde(default)]
    headers: Vec<SecretHeaderInput>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

enum RegisterServiceInput {
    Http(RegisterHttpCredentialInput),
    Sql(RegisterSqlCredentialInput),
}

impl RegisterCredentialInput {
    fn into_service_input(self) -> RegisterServiceInput {
        match self.category {
            CredentialCategory::Http => RegisterServiceInput::Http(RegisterHttpCredentialInput {
                provider: self.provider,
                alias: self.alias,
                endpoint: self.endpoint,
                secret_headers: self.secret.headers,
                description: self.description,
                env: self.env,
                tags: self.tags,
                policy: self.policy,
                allow_private_network: self.allow_private_network,
                tls_server_ca: self.tls_server_ca,
            }),
            CredentialCategory::Sql => RegisterServiceInput::Sql(RegisterSqlCredentialInput {
                provider: self.provider,
                alias: self.alias,
                endpoint: self.endpoint,
                username: self.secret.username,
                password: self.secret.password,
                description: self.description,
                env: self.env,
                tags: self.tags,
                policy: self.policy,
                allow_private_network: self.allow_private_network,
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeleteCredentialBody {
    #[serde(default)]
    reason: String,
}

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

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteCredentialOutput {
    pub alias: String,
    pub deleted: bool,
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
        .map(|field| field.trim().to_owned())
        .filter(|field| !field.is_empty())
        .collect()
}

fn include_field(fields: Option<&BTreeSet<String>>, field: &str) -> bool {
    fields.is_none_or(|fields| fields.contains(field))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn unified_register_input_maps_http_secret_headers() -> Result<(), String> {
        let input = RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            endpoint: "https://api.example.test".to_owned(),
            secret: RegisterSecretInput {
                headers: vec![SecretHeaderInput {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: "ignored".to_owned(),
                password: "ignored".to_owned(),
            },
            description: "cluster api".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["k8s".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: true,
            tls_server_ca: "-----BEGIN CERTIFICATE-----".to_owned(),
        };

        let input = match input.into_service_input() {
            RegisterServiceInput::Http(input) => input,
            RegisterServiceInput::Sql(_) => return Err("expected http credential input".to_owned()),
        };
        assert_eq!(input.secret_headers.len(), 1);
        assert_eq!(
            input
                .secret_headers
                .first()
                .map(|header| header.name.as_str()),
            Some("Authorization")
        );
        assert_eq!(input.tls_server_ca, "-----BEGIN CERTIFICATE-----");
        Ok(())
    }

    #[test]
    fn unified_register_input_maps_sql_secret() -> Result<(), String> {
        let input = RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: String::new(),
            alias: "prod-db".to_owned(),
            endpoint: "postgres://db.example.test/app".to_owned(),
            secret: RegisterSecretInput {
                headers: Vec::new(),
                username: "app".to_owned(),
                password: "secret".to_owned(),
            },
            description: "database".to_owned(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            tls_server_ca: "ignored".to_owned(),
        };

        let input = match input.into_service_input() {
            RegisterServiceInput::Sql(input) => input,
            RegisterServiceInput::Http(_) => return Err("expected sql credential input".to_owned()),
        };
        assert_eq!(input.username, "app");
        assert_eq!(input.password, "secret");
        assert_eq!(input.provider, "");
        Ok(())
    }

    #[test]
    fn credential_output_never_serializes_endpoint_or_secret_material()
    -> Result<(), serde_json::Error> {
        let output = CredentialOutput::from_with_fields(credential(), None);
        let json = serde_json::to_string(&output)?;

        assert!(json.contains("prod-api"));
        assert!(!json.contains("internal.example.test"));
        assert!(!json.contains("secret"));
        Ok(())
    }

    #[test]
    fn list_query_preserves_repeated_fields() -> Result<(), ApiError> {
        let input = parse_list_query(Some(
            "category=http&provider=k8s&fields=provider&fields=env&limit=25",
        ))?;

        assert_eq!(input.category, Some(CredentialCategory::Http));
        assert_eq!(input.provider, Some("k8s".to_owned()));
        assert_eq!(
            input.fields,
            Some(vec!["provider".to_owned(), "env".to_owned()])
        );
        assert_eq!(input.limit, Some(25));
        Ok(())
    }

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
            tags: vec!["prod".to_owned()],
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            has_tls_ca: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
