use opsgate_core::{Error, Result};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SqlQueryHistoryRepo {
    pool: PgPool,
}

impl SqlQueryHistoryRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, params: SqlQueryHistoryParams) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sql_query_history (
                owner_user_id,
                actor_user_id,
                channel,
                request_id,
                credential_id,
                credential_alias,
                credential_category,
                credential_provider,
                credential_env,
                query_sha256,
                params_count,
                max_rows,
                max_bytes,
                timeout_ms,
                purpose,
                outcome,
                latency_ms,
                row_count,
                returned_bytes,
                truncated,
                result_columns,
                error_kind,
                error_message_safe
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
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
        .bind(params.query_sha256)
        .bind(params.params_count)
        .bind(params.max_rows)
        .bind(params.max_bytes)
        .bind(params.timeout_ms)
        .bind(params.purpose)
        .bind(params.outcome)
        .bind(params.latency_ms)
        .bind(params.row_count)
        .bind(params.returned_bytes)
        .bind(params.truncated)
        .bind(params.result_columns)
        .bind(params.error_kind)
        .bind(params.error_message_safe)
        .execute(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("sql query history store error: {error}")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SqlQueryHistoryParams {
    pub owner_user_id: Option<Uuid>,
    pub actor_user_id: Option<Uuid>,
    pub channel: String,
    pub request_id: Option<String>,
    pub credential_id: Option<Uuid>,
    pub credential_alias: String,
    pub credential_category: String,
    pub credential_provider: String,
    pub credential_env: String,
    pub query_sha256: String,
    pub params_count: i32,
    pub max_rows: i32,
    pub max_bytes: i32,
    pub timeout_ms: i32,
    pub purpose: Option<String>,
    pub outcome: String,
    pub latency_ms: Option<i64>,
    pub row_count: Option<i32>,
    pub returned_bytes: Option<i32>,
    pub truncated: bool,
    pub result_columns: Value,
    pub error_kind: Option<String>,
    pub error_message_safe: Option<String>,
}
