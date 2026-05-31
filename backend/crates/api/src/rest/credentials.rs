use axum::body::Bytes;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use opsgate_model::Caller;
use opsgate_model::credential::{CredentialCategory, CredentialPolicy};
use serde::Deserialize;

use crate::credential::{
    CredentialListOutput, CredentialOutput, DeleteCredentialInput, DeleteCredentialOutput,
    ListCredentialsInput, PageOutput, RegisterCredentialOutput, RegisterHttpCredentialInput,
    RegisterSqlCredentialInput, SecretHeaderInput, normalize_fields,
};
use crate::error::ApiError;
use crate::state::AppState;

pub(crate) fn routes() -> Router<AppState> {
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
    Ok(Json(RegisterCredentialOutput::created(credential)))
}

async fn list(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<CredentialListOutput>, ApiError> {
    let input = parse_list_query(query.as_deref())?;
    let fields = input.fields.clone().and_then(normalize_fields);
    let page = state.tools.credentials.list(caller.user.id, input).await?;
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
        .tools
        .credentials
        .delete(&caller, DeleteCredentialInput { alias, reason })
        .await?;
    Ok(Json(DeleteCredentialOutput::deleted(credential.alias)))
}

#[derive(Debug, Deserialize)]
struct RegisterCredentialInput {
    category: CredentialCategory,
    provider: String,
    alias: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    database_url: String,
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
    allow_insecure_transport: bool,
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
    fn into_service_input(self) -> Result<RegisterServiceInput, ApiError> {
        match self.category {
            CredentialCategory::Http => {
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
                    secret_headers: self.secret.headers,
                    description: self.description,
                    env: self.env,
                    tags: self.tags,
                    policy: self.policy,
                    allow_private_network: self.allow_private_network,
                    allow_insecure_transport: self.allow_insecure_transport,
                    tls_server_ca: self.tls_server_ca,
                }))
            }
            CredentialCategory::Sql => {
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
                    policy: self.policy,
                    allow_private_network: self.allow_private_network,
                    allow_insecure_transport: self.allow_insecure_transport,
                }))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeleteCredentialBody {
    #[serde(default)]
    reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_register_input_maps_http_secret_headers() -> Result<(), String> {
        let input = RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            origin: "https://api.example.test".to_owned(),
            base_path: String::new(),
            database_url: String::new(),
            secret: RegisterSecretInput {
                headers: vec![SecretHeaderInput {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: String::new(),
                password: String::new(),
            },
            description: "cluster api".to_owned(),
            env: "prod".to_owned(),
            tags: vec!["k8s".to_owned()],
            policy: CredentialPolicy::default(),
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
        let input = RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: String::new(),
            alias: "prod-db".to_owned(),
            origin: String::new(),
            base_path: String::new(),
            database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
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
        let http_with_sql_secret = RegisterCredentialInput {
            category: CredentialCategory::Http,
            provider: "k8s".to_owned(),
            alias: "prod-api".to_owned(),
            origin: "https://api.example.test".to_owned(),
            base_path: String::new(),
            database_url: String::new(),
            secret: RegisterSecretInput {
                headers: vec![SecretHeaderInput {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: "wrong".to_owned(),
                password: String::new(),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
            allow_private_network: false,
            allow_insecure_transport: false,
            tls_server_ca: String::new(),
        };
        assert!(http_with_sql_secret.into_service_input().is_err());

        let sql_with_http_secret = RegisterCredentialInput {
            category: CredentialCategory::Sql,
            provider: String::new(),
            alias: "prod-db".to_owned(),
            origin: String::new(),
            base_path: String::new(),
            database_url: "postgres://db.example.test/app?sslmode=require".to_owned(),
            secret: RegisterSecretInput {
                headers: vec![SecretHeaderInput {
                    name: "Authorization".to_owned(),
                    value: "Bearer token".to_owned(),
                }],
                username: "app".to_owned(),
                password: "secret".to_owned(),
            },
            description: String::new(),
            env: String::new(),
            tags: Vec::new(),
            policy: CredentialPolicy::default(),
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

        assert_eq!(input.category, Some(CredentialCategory::Http));
        assert_eq!(input.provider, Some("k8s".to_owned()));
        assert_eq!(
            input.fields,
            Some(vec!["provider".to_owned(), "env".to_owned()])
        );
        assert_eq!(input.limit, Some(25));
        Ok(())
    }
}
