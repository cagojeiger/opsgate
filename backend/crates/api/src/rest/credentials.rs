use axum::body::Bytes;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use opsgate_model::Caller;
use opsgate_model::credential::{
    CredentialCategory as ModelCredentialCategory, CredentialPolicy as ModelCredentialPolicy,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::state::AppState;
use opsgate_service::credential::{
    CredentialListOutput, DeleteCredentialInput, DeleteCredentialOutput, ListCredentialsInput,
    RegisterCredentialOutput, RegisterHttpCredentialInput, RegisterSqlCredentialInput,
    SecretHeaderInput,
};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/credentials", get(list).post(register))
        .route("/v1/credentials/{alias}", delete(remove))
}

async fn register(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Result<Json<RegisterCredentialResponse>, ApiError> {
    let input = serde_json::from_slice::<RegisterCredentialRequest>(&body)
        .map_err(|_error| ApiError::invalid_field("invalid json"))?;
    let credential = match input.into_service_input()? {
        RegisterServiceInput::Http(input) => {
            state
                .tools
                .credentials
                .register_http(&caller, input)
                .await?
        }
        RegisterServiceInput::Sql(input) => {
            state.tools.credentials.register_sql(&caller, input).await?
        }
    };
    Ok(Json(RegisterCredentialResponse::from(
        RegisterCredentialOutput::created(credential),
    )))
}

async fn list(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<CredentialListResponse>, ApiError> {
    let input = parse_list_query(query.as_deref())?;
    state
        .tools
        .credentials
        .list(caller.user.id, input)
        .await
        .map(CredentialListResponse::from)
        .map(Json)
        .map_err(ApiError::from)
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

fn parse_category(value: &str) -> Result<ModelCredentialCategory, ApiError> {
    match value.trim() {
        "http" => Ok(ModelCredentialCategory::Http),
        "sql" => Ok(ModelCredentialCategory::Sql),
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
) -> Result<Json<DeleteCredentialResponse>, ApiError> {
    let reason = if body.is_empty() {
        String::new()
    } else {
        serde_json::from_slice::<DeleteCredentialRequest>(&body)
            .map_err(|_error| ApiError::invalid_field("invalid json"))?
            .reason
    };
    let credential = state
        .tools
        .credentials
        .delete(&caller, DeleteCredentialInput { alias, reason })
        .await?;
    Ok(Json(DeleteCredentialResponse::from(
        DeleteCredentialOutput::deleted(credential.alias),
    )))
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct RegisterCredentialRequest {
    category: RestCredentialCategory,
    provider: String,
    alias: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    database_url: String,
    #[serde(default)]
    secret: RegisterSecretRequest,
    #[serde(default)]
    description: String,
    #[serde(default)]
    env: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    policy: RestCredentialPolicy,
    #[serde(default)]
    allow_private_network: bool,
    #[serde(default)]
    allow_insecure_transport: bool,
    #[serde(default)]
    tls_server_ca: String,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct RegisterSecretRequest {
    #[serde(default)]
    headers: Vec<SecretHeaderRequest>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

enum RegisterServiceInput {
    Http(RegisterHttpCredentialInput),
    Sql(RegisterSqlCredentialInput),
}

impl RegisterCredentialRequest {
    fn into_service_input(self) -> Result<RegisterServiceInput, ApiError> {
        match self.category {
            RestCredentialCategory::Http => {
                if !self.secret.username.trim().is_empty()
                    || !self.secret.password.trim().is_empty()
                {
                    return Err(ApiError::invalid_field("http secret only supports headers"));
                }
                Ok(RegisterServiceInput::Http(RegisterHttpCredentialInput {
                    provider: self.provider,
                    alias: self.alias,
                    origin: self.origin,
                    base_path: self.base_path,
                    secret_headers: self
                        .secret
                        .headers
                        .into_iter()
                        .map(SecretHeaderInput::from)
                        .collect(),
                    description: self.description,
                    env: self.env,
                    tags: self.tags,
                    policy: self.policy.into(),
                    allow_private_network: self.allow_private_network,
                    allow_insecure_transport: self.allow_insecure_transport,
                    tls_server_ca: self.tls_server_ca,
                }))
            }
            RestCredentialCategory::Sql => {
                if !self.secret.headers.is_empty() {
                    return Err(ApiError::invalid_field(
                        "sql secret does not support headers",
                    ));
                }
                Ok(RegisterServiceInput::Sql(RegisterSqlCredentialInput {
                    provider: self.provider,
                    alias: self.alias,
                    database_url: self.database_url,
                    username: self.secret.username,
                    password: self.secret.password,
                    description: self.description,
                    env: self.env,
                    tags: self.tags,
                    policy: self.policy.into(),
                    allow_private_network: self.allow_private_network,
                    allow_insecure_transport: self.allow_insecure_transport,
                }))
            }
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct DeleteCredentialRequest {
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RestCredentialCategory {
    Http,
    Sql,
}

impl From<RestCredentialCategory> for ModelCredentialCategory {
    fn from(category: RestCredentialCategory) -> Self {
        match category {
            RestCredentialCategory::Http => Self::Http,
            RestCredentialCategory::Sql => Self::Sql,
        }
    }
}

impl From<ModelCredentialCategory> for RestCredentialCategory {
    fn from(category: ModelCredentialCategory) -> Self {
        match category {
            ModelCredentialCategory::Http => Self::Http,
            ModelCredentialCategory::Sql => Self::Sql,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
pub(crate) struct RestCredentialPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_request_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) denied_query_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_request_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) allow_metadata: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) allow_explain: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) allow_explain_analyze: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) denied_functions: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) max_rows: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) max_bytes: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) timeout_ms: u32,
}

impl From<RestCredentialPolicy> for ModelCredentialPolicy {
    fn from(policy: RestCredentialPolicy) -> Self {
        Self {
            allowed_methods: policy.allowed_methods,
            allowed_request_path_prefixes: policy.allowed_request_path_prefixes,
            denied_query_keys: policy.denied_query_keys,
            allowed_request_headers: policy.allowed_request_headers,
            allow_metadata: policy.allow_metadata,
            allow_explain: policy.allow_explain,
            allow_explain_analyze: policy.allow_explain_analyze,
            denied_functions: policy.denied_functions,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            timeout_ms: policy.timeout_ms,
        }
    }
}

impl From<ModelCredentialPolicy> for RestCredentialPolicy {
    fn from(policy: ModelCredentialPolicy) -> Self {
        Self {
            allowed_methods: policy.allowed_methods,
            allowed_request_path_prefixes: policy.allowed_request_path_prefixes,
            denied_query_keys: policy.denied_query_keys,
            allowed_request_headers: policy.allowed_request_headers,
            allow_metadata: policy.allow_metadata,
            allow_explain: policy.allow_explain,
            allow_explain_analyze: policy.allow_explain_analyze,
            denied_functions: policy.denied_functions,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            timeout_ms: policy.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct SecretHeaderRequest {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl From<SecretHeaderRequest> for SecretHeaderInput {
    fn from(header: SecretHeaderRequest) -> Self {
        Self {
            name: header.name,
            value: header.value,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CredentialListResponse {
    pub(crate) credentials: Vec<CredentialResponse>,
    pub(crate) page: CredentialPageResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CredentialPageResponse {
    pub(crate) limit: i64,
    pub(crate) returned: usize,
    pub(crate) has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CredentialResponse {
    pub(crate) alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) category: Option<RestCredentialCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy: Option<RestCredentialPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allow_private_network: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allow_insecure_transport: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RegisterCredentialResponse {
    pub(crate) alias: String,
    pub(crate) category: RestCredentialCategory,
    pub(crate) provider: String,
    pub(crate) env: String,
    pub(crate) tags: Vec<String>,
    pub(crate) description: String,
    pub(crate) created: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DeleteCredentialResponse {
    pub(crate) alias: String,
    pub(crate) deleted: bool,
}

impl From<CredentialListOutput> for CredentialListResponse {
    fn from(output: CredentialListOutput) -> Self {
        Self {
            credentials: output
                .credentials
                .into_iter()
                .map(|credential| CredentialResponse {
                    alias: credential.alias,
                    category: credential.category.map(RestCredentialCategory::from),
                    provider: credential.provider,
                    description: credential.description,
                    env: credential.env,
                    tags: credential.tags,
                    policy: credential.policy.map(RestCredentialPolicy::from),
                    allow_private_network: credential.allow_private_network,
                    allow_insecure_transport: credential.allow_insecure_transport,
                })
                .collect(),
            page: CredentialPageResponse {
                limit: output.page.limit,
                returned: output.page.returned,
                has_more: output.page.has_more,
                next_cursor: output.page.next_cursor,
            },
        }
    }
}

impl From<RegisterCredentialOutput> for RegisterCredentialResponse {
    fn from(output: RegisterCredentialOutput) -> Self {
        Self {
            alias: output.alias,
            category: RestCredentialCategory::from(output.category),
            provider: output.provider,
            env: output.env,
            tags: output.tags,
            description: output.description,
            created: output.created,
        }
    }
}

impl From<DeleteCredentialOutput> for DeleteCredentialResponse {
    fn from(output: DeleteCredentialOutput) -> Self {
        Self {
            alias: output.alias,
            deleted: output.deleted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_register_input_maps_http_secret_headers() -> Result<(), String> {
        let input = RegisterCredentialRequest {
            category: RestCredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            origin: "https://api.example.test".to_owned(),
            base_path: String::new(),
            database_url: String::new(),
            secret: RegisterSecretRequest {
                headers: vec![SecretHeaderRequest {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: String::new(),
                password: String::new(),
            },
            description: "cluster api".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["k8s".to_owned()],
            policy: RestCredentialPolicy::default(),
            allow_private_network: true,
            allow_insecure_transport: false,
            tls_server_ca: "-----BEGIN CERTIFICATE-----".to_owned(),
        };

        let input = match input
            .into_service_input()
            .map_err(|_error| "unexpected error".to_owned())?
        {
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
        let input = RegisterCredentialRequest {
            category: RestCredentialCategory::Sql,
            provider: String::new(),
            alias: "prod-db".to_owned(),
            origin: String::new(),
            base_path: String::new(),
            database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
            secret: RegisterSecretRequest {
                headers: Vec::new(),
                username: "app".to_owned(),
                password: "secret".to_owned(),
            },
            description: "database".to_owned(),
            env: "prod".to_owned(),
            tags: Vec::new(),
            policy: RestCredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: "ignored".to_owned(),
        };

        let input = match input
            .into_service_input()
            .map_err(|_error| "unexpected error".to_owned())?
        {
            RegisterServiceInput::Sql(input) => input,
            RegisterServiceInput::Http(_) => return Err("expected sql credential input".to_owned()),
        };
        assert_eq!(input.username, "app");
        assert_eq!(input.password, "secret");
        assert_eq!(input.provider, "");
        Ok(())
    }

    #[test]
    fn unified_register_input_rejects_wrong_secret_shape() {
        let http_with_sql_secret = RegisterCredentialRequest {
            category: RestCredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            origin: "https://api.example.test".to_owned(),
            base_path: String::new(),
            database_url: String::new(),
            secret: RegisterSecretRequest {
                headers: vec![SecretHeaderRequest {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: "wrong".to_owned(),
                password: String::new(),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: RestCredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
        };
        assert!(http_with_sql_secret.into_service_input().is_err());

        let sql_with_http_secret = RegisterCredentialRequest {
            category: RestCredentialCategory::Sql,
            provider: String::new(),
            alias: "prod-db".to_owned(),
            origin: String::new(),
            base_path: String::new(),
            database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
            secret: RegisterSecretRequest {
                headers: vec![SecretHeaderRequest {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: "app".to_owned(),
                password: "secret".to_owned(),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: RestCredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
        };
        assert!(sql_with_http_secret.into_service_input().is_err());
    }

    #[test]
    fn list_query_preserves_repeated_fields() -> Result<(), ApiError> {
        let input = parse_list_query(Some(
            "category=http&provider=k8s&fields=provider&fields=env&limit=25",
        ))?;

        assert_eq!(input.category, Some(ModelCredentialCategory::Http));
        assert_eq!(input.provider, Some("k8s".to_owned()));
        assert_eq!(
            input.fields,
            Some(vec!["provider".to_owned(), "env".to_owned()])
        );
        assert_eq!(input.limit, Some(25));
        Ok(())
    }
}
