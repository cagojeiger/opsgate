use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CredentialPolicy;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCategory {
    Http,
    Sql,
}

impl CredentialCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sql => "sql",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub category: CredentialCategory,
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
    pub has_tls_ca: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SecretHeader {
    pub name: String,
    pub value: SecretString,
}

#[derive(Debug, Clone)]
pub enum CredentialSecret {
    Http {
        headers: Vec<SecretHeader>,
    },
    Sql {
        username: SecretString,
        password: SecretString,
    },
}

#[derive(Debug, Clone)]
pub struct RegisterHttpCredentialInput {
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub secret_headers: Vec<SecretHeader>,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
    pub tls_server_ca: String,
}

#[derive(Debug, Clone)]
pub struct RegisterSqlCredentialInput {
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub username: SecretString,
    pub password: SecretString,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterCredentialInput {
    pub category: CredentialCategory,
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub secret: CredentialSecret,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
    pub tls_server_ca: Option<String>,
}

impl From<RegisterHttpCredentialInput> for RegisterCredentialInput {
    fn from(input: RegisterHttpCredentialInput) -> Self {
        Self {
            category: CredentialCategory::Http,
            provider: input.provider,
            alias: input.alias,
            endpoint: input.endpoint,
            secret: CredentialSecret::Http {
                headers: input.secret_headers,
            },
            description: input.description,
            env: input.env,
            tags: input.tags,
            policy: input.policy,
            allow_private_network: input.allow_private_network,
            tls_server_ca: Some(input.tls_server_ca),
        }
    }
}

impl From<RegisterSqlCredentialInput> for RegisterCredentialInput {
    fn from(input: RegisterSqlCredentialInput) -> Self {
        let provider = if input.provider.trim().is_empty() {
            "postgres".to_owned()
        } else {
            input.provider
        };
        Self {
            category: CredentialCategory::Sql,
            provider,
            alias: input.alias,
            endpoint: input.endpoint,
            secret: CredentialSecret::Sql {
                username: input.username,
                password: input.password,
            },
            description: input.description,
            env: input.env,
            tags: input.tags,
            policy: input.policy,
            allow_private_network: input.allow_private_network,
            tls_server_ca: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InsertCredentialParams {
    pub owner_user_id: Uuid,
    pub actor_user_id: Uuid,
    pub category: CredentialCategory,
    pub provider: String,
    pub alias: String,
    pub endpoint: String,
    pub secret_ciphertext: Vec<u8>,
    pub description: String,
    pub env: String,
    pub tags: Vec<String>,
    pub policy: CredentialPolicy,
    pub allow_private_network: bool,
    pub tls_ca: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct UpdateCredentialParams {
    pub owner_user_id: Uuid,
    pub actor_user_id: Uuid,
    pub alias: String,
    pub category: CredentialCategory,
    pub description: Option<String>,
    pub env: Option<String>,
    pub tags: Option<Vec<String>>,
    pub policy: Option<CredentialPolicy>,
}

#[derive(Debug, Clone, Default)]
pub struct CredentialListParams {
    pub owner_user_id: Uuid,
    pub category: Option<CredentialCategory>,
    pub provider: Option<String>,
    pub env: Option<String>,
    pub tag: Option<String>,
    pub q: Option<String>,
    pub cursor: Option<String>,
    pub limit: i64,
}
