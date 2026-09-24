use chrono::{DateTime, Utc};
use opsgate_core::{Error, Result};
use opsgate_model::credential::{
    Credential, CredentialCategory, CredentialPolicy, CredentialTarget,
};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct CountRow {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone)]
pub struct CredentialSummaryRows {
    pub total: i64,
    pub by_category: Vec<CountRow>,
    pub by_provider: Vec<CountRow>,
    pub tags: Vec<CountRow>,
}

#[derive(Debug, FromRow)]
pub(super) struct CredentialRow {
    id: Uuid,
    owner_user_id: Uuid,
    category: String,
    provider: String,
    alias: String,
    http_origin: Option<String>,
    http_base_path: Option<String>,
    sql_database_url: Option<String>,
    description: String,
    env: String,
    tags: Vec<String>,
    policy: Value,
    allow_private_network: bool,
    allow_insecure_transport: bool,
    has_tls_ca: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct CredentialSecretRow {
    id: Uuid,
    owner_user_id: Uuid,
    category: String,
    provider: String,
    alias: String,
    http_origin: Option<String>,
    http_base_path: Option<String>,
    sql_database_url: Option<String>,
    description: String,
    env: String,
    tags: Vec<String>,
    policy: Value,
    allow_private_network: bool,
    allow_insecure_transport: bool,
    has_tls_ca: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    pub secret_ciphertext: Option<Vec<u8>>,
    pub tls_ca: Option<Vec<u8>>,
}

pub struct CredentialSecretMaterial {
    pub credential: Credential,
    pub secret_ciphertext: Option<Vec<u8>>,
    pub tls_ca: Option<Vec<u8>>,
}

impl CredentialSecretRow {
    pub fn into_credential(self) -> Result<CredentialSecretMaterial> {
        let credential = CredentialRow {
            id: self.id,
            owner_user_id: self.owner_user_id,
            category: self.category,
            provider: self.provider,
            alias: self.alias,
            http_origin: self.http_origin,
            http_base_path: self.http_base_path,
            sql_database_url: self.sql_database_url,
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy: self.policy,
            allow_private_network: self.allow_private_network,
            allow_insecure_transport: self.allow_insecure_transport,
            has_tls_ca: self.has_tls_ca,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .into_credential()?;
        Ok(CredentialSecretMaterial {
            credential,
            secret_ciphertext: self.secret_ciphertext,
            tls_ca: self.tls_ca,
        })
    }
}

impl CredentialRow {
    pub(super) fn into_credential(self) -> Result<Credential> {
        let category = match self.category.as_str() {
            "http" => CredentialCategory::Http,
            "sql" => CredentialCategory::Sql,
            other => {
                return Err(Error::internal(format!(
                    "unknown credential category in database: {other}"
                )));
            }
        };
        let target = row_target(
            category,
            self.http_origin,
            self.http_base_path,
            self.sql_database_url,
        )?;
        let policy = serde_json::from_value::<CredentialPolicy>(self.policy)
            .map_err(|error| Error::internal(format!("decode credential policy: {error}")))?;
        Ok(Credential {
            id: self.id,
            owner_user_id: self.owner_user_id,
            category,
            provider: self.provider,
            alias: self.alias,
            target,
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy,
            allow_private_network: self.allow_private_network,
            allow_insecure_transport: self.allow_insecure_transport,
            has_tls_ca: self.has_tls_ca,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

pub(super) fn target_columns(
    target: CredentialTarget,
) -> (Option<String>, Option<String>, Option<String>) {
    match target {
        CredentialTarget::Http { origin, base_path } => (Some(origin), Some(base_path), None),
        CredentialTarget::Sql { database_url } => (None, None, Some(database_url)),
    }
}

fn row_target(
    category: CredentialCategory,
    http_origin: Option<String>,
    http_base_path: Option<String>,
    sql_database_url: Option<String>,
) -> Result<CredentialTarget> {
    match category {
        CredentialCategory::Http => Ok(CredentialTarget::Http {
            origin: http_origin.ok_or_else(|| Error::internal("http credential missing origin"))?,
            base_path: http_base_path
                .ok_or_else(|| Error::internal("http credential missing base_path"))?,
        }),
        CredentialCategory::Sql => Ok(CredentialTarget::Sql {
            database_url: sql_database_url
                .ok_or_else(|| Error::internal("sql credential missing database_url"))?,
        }),
    }
}
