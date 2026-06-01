use chrono::{DateTime, Utc};
use opsgate_core::{Error, Result};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ReadRepo {
    pool: PgPool,
}

impl ReadRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_audit_events(
        &self,
        params: AuditEventListParams,
    ) -> Result<Vec<AuditEventRow>> {
        sqlx::query_as::<_, AuditEventRow>(
            r#"
            SELECT id, action, channel, outcome, severity, actor_user_id, target_type,
                   target_id, target_key, request_id, purpose, detail, created_at
            FROM audit_logs
            WHERE actor_user_id = $1
              AND ($2::text IS NULL OR channel = $2)
              AND ($3::text IS NULL OR action = $3)
              AND ($4::text IS NULL OR outcome = $4)
              AND ($5::text IS NULL OR target_type = $5)
              AND ($6::text IS NULL OR target_key = $6)
              AND ($7::timestamptz IS NULL OR $8::uuid IS NULL OR (created_at, id) < ($7, $8))
            ORDER BY created_at DESC, id DESC
            LIMIT $9
            "#,
        )
        .bind(params.actor_user_id)
        .bind(params.channel)
        .bind(params.action)
        .bind(params.outcome)
        .bind(params.target_type)
        .bind(params.target_key)
        .bind(params.cursor_created_at)
        .bind(params.cursor_id)
        .bind(params.limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("audit event read error: {error}")))
    }

    pub async fn list_api_call_history(
        &self,
        params: RuntimeHistoryListParams,
    ) -> Result<Vec<ApiCallHistoryRow>> {
        sqlx::query_as::<_, ApiCallHistoryRow>(
            r#"
            SELECT id, owner_user_id, actor_user_id, channel, request_id, credential_id,
                   credential_alias, credential_category, credential_provider, credential_env,
                   method, request_path, query_keys, request_header_keys, projection_keys,
                   max_bytes, purpose, outcome, status_code, latency_ms, original_bytes,
                   returned_bytes, truncated, error_kind, error_message_safe, created_at
            FROM api_call_history
            WHERE owner_user_id = $1
              AND ($2::text IS NULL OR channel = $2)
              AND ($3::text IS NULL OR credential_alias = $3)
              AND ($4::text IS NULL OR outcome = $4)
              AND ($5::text IS NULL OR error_kind = $5)
              AND ($6::timestamptz IS NULL OR $7::uuid IS NULL OR (created_at, id) < ($6, $7))
            ORDER BY created_at DESC, id DESC
            LIMIT $8
            "#,
        )
        .bind(params.owner_user_id)
        .bind(params.channel)
        .bind(params.credential_alias)
        .bind(params.outcome)
        .bind(params.error_kind)
        .bind(params.cursor_created_at)
        .bind(params.cursor_id)
        .bind(params.limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("api call history read error: {error}")))
    }

    pub async fn list_sql_query_history(
        &self,
        params: RuntimeHistoryListParams,
    ) -> Result<Vec<SqlQueryHistoryRow>> {
        sqlx::query_as::<_, SqlQueryHistoryRow>(
            r#"
            SELECT id, owner_user_id, actor_user_id, channel, request_id, credential_id,
                   credential_alias, credential_category, credential_provider, credential_env,
                   query_sha256, params_count, max_rows, max_bytes, timeout_ms, purpose,
                   outcome, latency_ms, row_count, returned_bytes, truncated, result_columns,
                   error_kind, error_message_safe, created_at
            FROM sql_query_history
            WHERE owner_user_id = $1
              AND ($2::text IS NULL OR channel = $2)
              AND ($3::text IS NULL OR credential_alias = $3)
              AND ($4::text IS NULL OR outcome = $4)
              AND ($5::text IS NULL OR error_kind = $5)
              AND ($6::timestamptz IS NULL OR $7::uuid IS NULL OR (created_at, id) < ($6, $7))
            ORDER BY created_at DESC, id DESC
            LIMIT $8
            "#,
        )
        .bind(params.owner_user_id)
        .bind(params.channel)
        .bind(params.credential_alias)
        .bind(params.outcome)
        .bind(params.error_kind)
        .bind(params.cursor_created_at)
        .bind(params.cursor_id)
        .bind(params.limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("sql query history read error: {error}")))
    }

    pub async fn list_credential_history(
        &self,
        params: CredentialHistoryListParams,
    ) -> Result<Vec<CredentialHistoryRow>> {
        sqlx::query_as::<_, CredentialHistoryRow>(
            r#"
            SELECT id, credential_id, owner_user_id, alias, action, actor_user_id,
                   actor_ip, actor_user_agent, request_id, channel, reason,
                   changed_fields, version, detail, created_at
            FROM credential_history
            WHERE owner_user_id = $1
              AND ($2::text IS NULL OR alias = $2)
              AND ($3::text IS NULL OR action = $3)
              AND ($4::text IS NULL OR channel = $4)
              AND ($5::timestamptz IS NULL OR $6::uuid IS NULL OR (created_at, id) < ($5, $6))
            ORDER BY created_at DESC, id DESC
            LIMIT $7
            "#,
        )
        .bind(params.owner_user_id)
        .bind(params.alias)
        .bind(params.action)
        .bind(params.channel)
        .bind(params.cursor_created_at)
        .bind(params.cursor_id)
        .bind(params.limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("credential history read error: {error}")))
    }

    pub async fn summary(&self, owner_user_id: Uuid) -> Result<SummaryRow> {
        sqlx::query_as::<_, SummaryRow>(
            r#"
            SELECT
                (SELECT count(*) FROM credentials WHERE owner_user_id = $1 AND deleted_at IS NULL) AS credential_total,
                (SELECT count(*) FROM credentials WHERE owner_user_id = $1 AND deleted_at IS NULL AND category = 'http') AS credential_http,
                (SELECT count(*) FROM credentials WHERE owner_user_id = $1 AND deleted_at IS NULL AND category = 'sql') AS credential_sql,
                (SELECT count(*) FROM api_call_history WHERE owner_user_id = $1 AND created_at >= now() - interval '24 hours') AS api_calls_24h,
                (SELECT count(*) FROM sql_query_history WHERE owner_user_id = $1 AND created_at >= now() - interval '24 hours') AS sql_queries_24h,
                (SELECT count(*) FROM audit_logs WHERE actor_user_id = $1 AND created_at >= now() - interval '24 hours') AS audit_events_24h,
                (SELECT count(*) FROM audit_logs WHERE actor_user_id = $1 AND created_at >= now() - interval '24 hours' AND outcome = 'error') AS errors_24h,
                (SELECT count(*) FROM audit_logs WHERE actor_user_id = $1 AND created_at >= now() - interval '24 hours' AND outcome = 'denied') AS denied_24h
            "#,
        )
        .bind(owner_user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("summary read error: {error}")))
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeHistoryListParams {
    pub owner_user_id: Uuid,
    pub channel: Option<String>,
    pub credential_alias: Option<String>,
    pub outcome: Option<String>,
    pub error_kind: Option<String>,
    pub cursor_created_at: Option<DateTime<Utc>>,
    pub cursor_id: Option<Uuid>,
    pub limit: i64,
}

#[derive(Debug, Clone)]
pub struct AuditEventListParams {
    pub actor_user_id: Uuid,
    pub channel: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub target_type: Option<String>,
    pub target_key: Option<String>,
    pub cursor_created_at: Option<DateTime<Utc>>,
    pub cursor_id: Option<Uuid>,
    pub limit: i64,
}

#[derive(Debug, Clone)]
pub struct CredentialHistoryListParams {
    pub owner_user_id: Uuid,
    pub alias: Option<String>,
    pub action: Option<String>,
    pub channel: Option<String>,
    pub cursor_created_at: Option<DateTime<Utc>>,
    pub cursor_id: Option<Uuid>,
    pub limit: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEventRow {
    pub id: Uuid,
    pub action: String,
    pub channel: String,
    pub outcome: String,
    pub severity: String,
    pub actor_user_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_key: Option<String>,
    pub request_id: Option<String>,
    pub purpose: Option<String>,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiCallHistoryRow {
    pub id: Uuid,
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
    pub request_path: String,
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
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct SqlQueryHistoryRow {
    pub id: Uuid,
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
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CredentialHistoryRow {
    pub id: Uuid,
    pub credential_id: Option<Uuid>,
    pub owner_user_id: Uuid,
    pub alias: String,
    pub action: String,
    pub actor_user_id: Uuid,
    pub actor_ip: Option<String>,
    pub actor_user_agent: Option<String>,
    pub request_id: Option<String>,
    pub channel: Option<String>,
    pub reason: Option<String>,
    pub changed_fields: Vec<String>,
    pub version: i64,
    pub detail: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct SummaryRow {
    pub credential_total: i64,
    pub credential_http: i64,
    pub credential_sql: i64,
    pub api_calls_24h: i64,
    pub sql_queries_24h: i64,
    pub audit_events_24h: i64,
    pub errors_24h: i64,
    pub denied_24h: i64,
}
