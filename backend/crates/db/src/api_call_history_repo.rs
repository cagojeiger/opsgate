use opsgate_core::{Error, Result};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ApiCallHistoryRepo {
    pool: PgPool,
}

impl ApiCallHistoryRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, params: ApiCallHistoryParams) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO api_call_history (
                owner_user_id,
                actor_user_id,
                channel,
                request_id,
                credential_id,
                credential_alias,
                credential_category,
                credential_provider,
                credential_env,
                method,
                path,
                query_keys,
                request_header_keys,
                projection_keys,
                max_bytes,
                purpose,
                outcome,
                status_code,
                latency_ms,
                original_bytes,
                returned_bytes,
                truncated,
                error_kind,
                error_message_safe
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
            "#,
        )
        .bind(params.owner_user_id)
        .bind(params.actor_user_id)
        .bind(params.channel)
        .bind(params.request_id)
        .bind(params.credential_id)
        .bind(params.credential_alias)
        .bind(params.credential_category)
        .bind(params.credential_provider)
        .bind(params.credential_env)
        .bind(params.method)
        .bind(params.path)
        .bind(params.query_keys)
        .bind(params.request_header_keys)
        .bind(params.projection_keys)
        .bind(params.max_bytes)
        .bind(params.purpose)
        .bind(params.outcome)
        .bind(params.status_code)
        .bind(params.latency_ms)
        .bind(params.original_bytes)
        .bind(params.returned_bytes)
        .bind(params.truncated)
        .bind(params.error_kind)
        .bind(params.error_message_safe)
        .execute(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("api call history store error: {error}")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ApiCallHistoryParams {
    pub owner_user_id: Option<Uuid>,
    pub actor_user_id: Option<Uuid>,
    pub channel: String,
    pub request_id: Option<String>,
    pub credential_id: Option<Uuid>,
    pub credential_alias: String,
    pub credential_category: String,
    pub credential_provider: String,
    pub credential_env: String,
    pub method: String,
    pub path: String,
    pub query_keys: Value,
    pub request_header_keys: Value,
    pub projection_keys: Value,
    pub max_bytes: i32,
    pub purpose: Option<String>,
    pub outcome: String,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub original_bytes: Option<i32>,
    pub returned_bytes: Option<i32>,
    pub truncated: bool,
    pub error_kind: Option<String>,
    pub error_message_safe: Option<String>,
}
