use chrono::{DateTime, Utc};
use opsgate_core::{Error, Result};
use opsgate_domain::credential::{
    Credential, CredentialCategory, CredentialListParams, CredentialPolicy, InsertCredentialParams,
    UpdateCredentialParams,
};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CredentialRepo {
    pool: PgPool,
}

impl CredentialRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert_credential(
        &self,
        params: InsertCredentialParams,
        audit: CredentialAuditParams,
    ) -> Result<Credential> {
        let category = params.category.as_str();
        let policy = serde_json::to_value(&params.policy)
            .map_err(|error| Error::internal(format!("serialize credential policy: {error}")))?;
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let row = sqlx::query_as::<_, CredentialRow>(
            r#"
            INSERT INTO credentials (
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                secret_ciphertext,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            RETURNING
                id,
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca IS NOT NULL AS has_tls_ca,
                created_at,
                updated_at
            "#,
        )
        .bind(params.owner_user_id)
        .bind(category)
        .bind(params.provider)
        .bind(params.alias)
        .bind(params.endpoint)
        .bind(params.secret_ciphertext)
        .bind(params.description)
        .bind(params.env)
        .bind(params.tags)
        .bind(policy)
        .bind(params.allow_private_network)
        .bind(params.tls_ca)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        let credential = row.into_credential()?;
        insert_audit_event(&mut tx, &credential, audit).await?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(credential)
    }

    pub async fn find_credential_by_alias(
        &self,
        owner_user_id: Uuid,
        alias: &str,
    ) -> Result<Option<Credential>> {
        let row = sqlx::query_as::<_, CredentialRow>(
            r#"
            SELECT
                id,
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca IS NOT NULL AS has_tls_ca,
                created_at,
                updated_at
            FROM credentials
            WHERE owner_user_id = $1
              AND alias = $2
              AND deleted_at IS NULL
            "#,
        )
        .bind(owner_user_id)
        .bind(alias)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        row.map(CredentialRow::into_credential).transpose()
    }

    pub async fn update_credential_mutable_fields(
        &self,
        params: UpdateCredentialParams,
        audit: CredentialAuditParams,
    ) -> Result<Credential> {
        let category = params.category.as_str();
        let policy = params
            .policy
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| Error::internal(format!("serialize credential policy: {error}")))?;
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let row = sqlx::query_as::<_, CredentialRow>(
            r#"
            UPDATE credentials
            SET description = COALESCE($4, description),
                env = COALESCE($5, env),
                tags = COALESCE($6, tags),
                policy = COALESCE($7, policy),
                updated_at = now()
            WHERE owner_user_id = $1
              AND alias = $2
              AND category = $3
              AND deleted_at IS NULL
            RETURNING
                id,
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca IS NOT NULL AS has_tls_ca,
                created_at,
                updated_at
            "#,
        )
        .bind(params.owner_user_id)
        .bind(params.alias)
        .bind(category)
        .bind(params.description)
        .bind(params.env)
        .bind(params.tags)
        .bind(policy)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        let credential = row.into_credential()?;
        insert_audit_event(&mut tx, &credential, audit).await?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(credential)
    }

    pub async fn soft_delete_credential(
        &self,
        owner_user_id: Uuid,
        alias: &str,
        audit: CredentialAuditParams,
    ) -> Result<Credential> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let row = sqlx::query_as::<_, CredentialRow>(
            r#"
            UPDATE credentials
            SET secret_ciphertext = NULL,
                secret_destroyed_at = now(),
                deleted_at = now(),
                updated_at = now()
            WHERE owner_user_id = $1
              AND alias = $2
              AND deleted_at IS NULL
            RETURNING
                id,
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca IS NOT NULL AS has_tls_ca,
                created_at,
                updated_at
            "#,
        )
        .bind(owner_user_id)
        .bind(alias)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        let credential = row.into_credential()?;
        insert_audit_event(&mut tx, &credential, audit).await?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(credential)
    }

    pub async fn list_credentials(&self, params: CredentialListParams) -> Result<Vec<Credential>> {
        let category = params.category.map(|category| category.as_str().to_owned());
        let provider = empty_to_none(params.provider);
        let env = empty_to_none(params.env);
        let tag = empty_to_none(params.tag);
        let q = empty_to_none(params.q).map(|q| format!("%{q}%"));
        let cursor = empty_to_none(params.cursor);
        let limit = if params.limit <= 0 {
            50
        } else {
            params.limit.min(101)
        };

        let rows = sqlx::query_as::<_, CredentialRow>(
            r#"
            SELECT
                id,
                owner_user_id,
                category,
                provider,
                alias,
                endpoint,
                description,
                env,
                tags,
                policy,
                allow_private_network,
                tls_ca IS NOT NULL AS has_tls_ca,
                created_at,
                updated_at
            FROM credentials
            WHERE owner_user_id = $1
              AND deleted_at IS NULL
              AND ($2::text IS NULL OR category = $2)
              AND ($3::text IS NULL OR provider = $3)
              AND ($4::text IS NULL OR env = $4)
              AND ($5::text IS NULL OR $5 = ANY(tags))
              AND ($6::text IS NULL OR alias ILIKE $6 OR description ILIKE $6)
              AND ($7::text IS NULL OR alias > $7)
            ORDER BY alias ASC
            LIMIT $8
            "#,
        )
        .bind(params.owner_user_id)
        .bind(category)
        .bind(provider)
        .bind(env)
        .bind(tag)
        .bind(q)
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        rows.into_iter()
            .map(CredentialRow::into_credential)
            .collect()
    }

    pub async fn credential_summary(&self, owner_user_id: Uuid) -> Result<CredentialSummaryRows> {
        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT count(*)
            FROM credentials
            WHERE owner_user_id = $1
              AND deleted_at IS NULL
            "#,
        )
        .bind(owner_user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        let by_category = sqlx::query_as::<_, CountRow>(
            r#"
            SELECT category AS key, count(*) AS count
            FROM credentials
            WHERE owner_user_id = $1
              AND deleted_at IS NULL
            GROUP BY category
            ORDER BY category
            "#,
        )
        .bind(owner_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        let by_provider = sqlx::query_as::<_, CountRow>(
            r#"
            SELECT provider AS key, count(*) AS count
            FROM credentials
            WHERE owner_user_id = $1
              AND deleted_at IS NULL
            GROUP BY provider
            ORDER BY provider
            "#,
        )
        .bind(owner_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        let tags = sqlx::query_as::<_, CountRow>(
            r#"
            SELECT expanded_tags.tag AS key, count(*) AS count
            FROM credentials
            CROSS JOIN unnest(credentials.tags) AS expanded_tags(tag)
            WHERE owner_user_id = $1
              AND deleted_at IS NULL
            GROUP BY expanded_tags.tag
            ORDER BY expanded_tags.tag
            "#,
        )
        .bind(owner_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(CredentialSummaryRows {
            total,
            by_category,
            by_provider,
            tags,
        })
    }
}

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

#[derive(Debug, Clone, Copy)]
pub enum CredentialAuditAction {
    Register,
    Update,
    Delete,
}

impl CredentialAuditAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialAuditParams {
    pub actor_user_id: Uuid,
    pub action: CredentialAuditAction,
    pub reason: Option<String>,
    pub changed_fields: Vec<String>,
    pub detail: Value,
}

async fn insert_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    credential: &Credential,
    audit: CredentialAuditParams,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO credential_audit_events (
            owner_user_id,
            actor_user_id,
            credential_id,
            alias,
            category,
            action,
            reason,
            changed_fields,
            detail
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
    .bind(credential.owner_user_id)
    .bind(audit.actor_user_id)
    .bind(credential.id)
    .bind(&credential.alias)
    .bind(credential.category.as_str())
    .bind(audit.action.as_str())
    .bind(audit.reason)
    .bind(audit.changed_fields)
    .bind(audit.detail)
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_error)?;
    Ok(())
}

#[derive(Debug, FromRow)]
struct CredentialRow {
    id: Uuid,
    owner_user_id: Uuid,
    category: String,
    provider: String,
    alias: String,
    endpoint: String,
    description: String,
    env: String,
    tags: Vec<String>,
    policy: Value,
    allow_private_network: bool,
    has_tls_ca: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl CredentialRow {
    fn into_credential(self) -> Result<Credential> {
        let category = match self.category.as_str() {
            "http" => CredentialCategory::Http,
            "sql" => CredentialCategory::Sql,
            other => {
                return Err(Error::internal(format!(
                    "unknown credential category in database: {other}"
                )));
            }
        };
        let policy = serde_json::from_value::<CredentialPolicy>(self.policy)
            .map_err(|error| Error::internal(format!("decode credential policy: {error}")))?;
        Ok(Credential {
            id: self.id,
            owner_user_id: self.owner_user_id,
            category,
            provider: self.provider,
            alias: self.alias,
            endpoint: self.endpoint,
            description: self.description,
            env: self.env,
            tags: self.tags,
            policy,
            allow_private_network: self.allow_private_network,
            has_tls_ca: self.has_tls_ca,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().to_owned();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn map_sqlx_error(error: sqlx::Error) -> Error {
    match error {
        sqlx::Error::RowNotFound => Error::not_found("credential not found"),
        other => Error::internal(format!("credential store error: {other}")),
    }
}
