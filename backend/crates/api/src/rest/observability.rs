use axum::extract::{Extension, RawQuery, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use opsgate_db::{
    ApiCallHistoryRow, AuditEventListParams, AuditEventRow, CredentialHistoryListParams,
    CredentialHistoryRow, RuntimeHistoryListParams, SqlQueryHistoryRow,
};
use opsgate_model::Caller;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/summary", get(summary))
        .route("/v1/activity", get(activity))
        .route("/v1/audit/events", get(audit_events))
        .route("/v1/history/api-calls", get(api_call_history))
        .route("/v1/history/sql-queries", get(sql_query_history))
        .route("/v1/history/credentials", get(credential_history))
}

async fn summary(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<SummaryResponse>, ApiError> {
    state
        .reads
        .summary(caller.user.id)
        .await
        .map(SummaryResponse::from)
        .map(Json)
        .map_err(ApiError::from)
}

async fn activity(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<ActivityResponse>, ApiError> {
    let filters = parse_query(query.as_deref())?;
    let limit = filters.limit_plus_one();
    let rows = state
        .reads
        .list_audit_events(AuditEventListParams {
            actor_user_id: caller.user.id,
            channel: filters.channel,
            action: filters.action,
            outcome: filters.outcome,
            target_type: filters.target_type,
            target_key: filters.credential,
            cursor_created_at: filters.cursor_created_at,
            cursor_id: filters.cursor_id,
            limit,
        })
        .await?;
    let page = page_from_rows(&rows, filters.limit, |row| row.created_at, |row| row.id);
    let items = rows
        .into_iter()
        .take(page.returned)
        .map(ActivityItem::from)
        .collect();
    Ok(Json(ActivityResponse { items, page }))
}

async fn audit_events(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<AuditEventsResponse>, ApiError> {
    let filters = parse_query(query.as_deref())?;
    let limit = filters.limit_plus_one();
    let rows = state
        .reads
        .list_audit_events(AuditEventListParams {
            actor_user_id: caller.user.id,
            channel: filters.channel,
            action: filters.action,
            outcome: filters.outcome,
            target_type: filters.target_type,
            target_key: filters.credential,
            cursor_created_at: filters.cursor_created_at,
            cursor_id: filters.cursor_id,
            limit,
        })
        .await?;
    let page = page_from_rows(&rows, filters.limit, |row| row.created_at, |row| row.id);
    let events = rows
        .into_iter()
        .take(page.returned)
        .map(AuditEventResponse::from)
        .collect();
    Ok(Json(AuditEventsResponse { events, page }))
}

async fn api_call_history(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<ApiCallHistoryResponse>, ApiError> {
    let filters = parse_query(query.as_deref())?;
    let limit = filters.limit_plus_one();
    let rows = state
        .reads
        .list_api_call_history(RuntimeHistoryListParams {
            owner_user_id: caller.user.id,
            channel: filters.channel,
            credential_alias: filters.credential,
            outcome: filters.outcome,
            error_kind: filters.error_kind,
            cursor_created_at: filters.cursor_created_at,
            cursor_id: filters.cursor_id,
            limit,
        })
        .await?;
    let page = page_from_rows(&rows, filters.limit, |row| row.created_at, |row| row.id);
    let calls = rows
        .into_iter()
        .take(page.returned)
        .map(ApiCallHistoryItem::from)
        .collect();
    Ok(Json(ApiCallHistoryResponse { calls, page }))
}

async fn sql_query_history(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<SqlQueryHistoryResponse>, ApiError> {
    let filters = parse_query(query.as_deref())?;
    let limit = filters.limit_plus_one();
    let rows = state
        .reads
        .list_sql_query_history(RuntimeHistoryListParams {
            owner_user_id: caller.user.id,
            channel: filters.channel,
            credential_alias: filters.credential,
            outcome: filters.outcome,
            error_kind: filters.error_kind,
            cursor_created_at: filters.cursor_created_at,
            cursor_id: filters.cursor_id,
            limit,
        })
        .await?;
    let page = page_from_rows(&rows, filters.limit, |row| row.created_at, |row| row.id);
    let queries = rows
        .into_iter()
        .take(page.returned)
        .map(SqlQueryHistoryItem::from)
        .collect();
    Ok(Json(SqlQueryHistoryResponse { queries, page }))
}

async fn credential_history(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    RawQuery(query): RawQuery,
) -> Result<Json<CredentialHistoryResponse>, ApiError> {
    let filters = parse_query(query.as_deref())?;
    let limit = filters.limit_plus_one();
    let rows = state
        .reads
        .list_credential_history(CredentialHistoryListParams {
            owner_user_id: caller.user.id,
            alias: filters.credential,
            action: filters.action,
            channel: filters.channel,
            cursor_created_at: filters.cursor_created_at,
            cursor_id: filters.cursor_id,
            limit,
        })
        .await?;
    let page = page_from_rows(&rows, filters.limit, |row| row.created_at, |row| row.id);
    let events = rows
        .into_iter()
        .take(page.returned)
        .map(CredentialHistoryItem::from)
        .collect();
    Ok(Json(CredentialHistoryResponse { events, page }))
}

#[derive(Debug)]
struct QueryFilters {
    channel: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    target_type: Option<String>,
    credential: Option<String>,
    error_kind: Option<String>,
    cursor_created_at: Option<DateTime<Utc>>,
    cursor_id: Option<Uuid>,
    limit: i64,
}

impl QueryFilters {
    fn limit_plus_one(&self) -> i64 {
        self.limit.saturating_add(1)
    }
}

fn parse_query(raw: Option<&str>) -> Result<QueryFilters, ApiError> {
    let mut filters = QueryFilters {
        channel: None,
        action: None,
        outcome: None,
        target_type: None,
        credential: None,
        error_kind: None,
        cursor_created_at: None,
        cursor_id: None,
        limit: DEFAULT_LIMIT,
    };
    let Some(raw) = raw else {
        return Ok(filters);
    };
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let value = value.into_owned();
        if value.trim().is_empty() {
            continue;
        }
        match key.as_ref() {
            "channel" if filters.channel.is_none() => filters.channel = Some(value),
            "action" | "tool" if filters.action.is_none() => filters.action = Some(value),
            "outcome" if filters.outcome.is_none() => filters.outcome = Some(value),
            "target_type" if filters.target_type.is_none() => filters.target_type = Some(value),
            "credential" | "credential_alias" if filters.credential.is_none() => {
                filters.credential = Some(value);
            }
            "error_kind" if filters.error_kind.is_none() => filters.error_kind = Some(value),
            "limit" => filters.limit = parse_limit(&value)?,
            "cursor" if filters.cursor_created_at.is_none() && filters.cursor_id.is_none() => {
                let cursor = parse_cursor(&value)?;
                filters.cursor_created_at = Some(cursor.created_at);
                filters.cursor_id = Some(cursor.id);
            }
            _ => {}
        }
    }
    Ok(filters)
}

fn parse_limit(value: &str) -> Result<i64, ApiError> {
    let limit = value
        .parse::<i64>()
        .map_err(|error| ApiError::invalid_field(format!("invalid limit: {error}")))?;
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::invalid_field("limit out of range"));
    }
    Ok(limit)
}

#[derive(Debug)]
struct Cursor {
    created_at: DateTime<Utc>,
    id: Uuid,
}

fn parse_cursor(value: &str) -> Result<Cursor, ApiError> {
    let (created_at, id) = value
        .split_once('|')
        .ok_or_else(|| ApiError::invalid_field("invalid cursor"))?;
    let created_at = DateTime::parse_from_rfc3339(created_at)
        .map_err(|_error| ApiError::invalid_field("invalid cursor"))?
        .with_timezone(&Utc);
    let id = Uuid::parse_str(id).map_err(|_error| ApiError::invalid_field("invalid cursor"))?;
    Ok(Cursor { created_at, id })
}

fn encode_cursor(created_at: DateTime<Utc>, id: Uuid) -> String {
    format!("{}|{}", created_at.to_rfc3339(), id)
}

fn page_from_rows<T>(
    rows: &[T],
    limit: i64,
    created_at: impl Fn(&T) -> DateTime<Utc>,
    id: impl Fn(&T) -> Uuid,
) -> PageResponse {
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit_usize;
    let returned = rows.len().min(limit_usize);
    let next_cursor = if has_more {
        rows.iter()
            .take(returned)
            .last()
            .map(|row| encode_cursor(created_at(row), id(row)))
    } else {
        None
    };
    PageResponse {
        limit,
        returned,
        has_more,
        next_cursor,
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct PageResponse {
    pub(crate) limit: i64,
    pub(crate) returned: usize,
    pub(crate) has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SummaryResponse {
    pub(crate) credentials: CredentialSummaryResponse,
    pub(crate) activity_24h: ActivitySummaryResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct CredentialSummaryResponse {
    pub(crate) total: i64,
    pub(crate) http: i64,
    pub(crate) sql: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ActivitySummaryResponse {
    pub(crate) api_calls: i64,
    pub(crate) sql_queries: i64,
    pub(crate) audit_events: i64,
    pub(crate) errors: i64,
    pub(crate) denied: i64,
}

impl From<opsgate_db::SummaryRow> for SummaryResponse {
    fn from(row: opsgate_db::SummaryRow) -> Self {
        Self {
            credentials: CredentialSummaryResponse {
                total: row.credential_total,
                http: row.credential_http,
                sql: row.credential_sql,
            },
            activity_24h: ActivitySummaryResponse {
                api_calls: row.api_calls_24h,
                sql_queries: row.sql_queries_24h,
                audit_events: row.audit_events_24h,
                errors: row.errors_24h,
                denied: row.denied_24h,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ActivityResponse {
    pub(crate) items: Vec<ActivityItem>,
    pub(crate) page: PageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ActivityItem {
    pub(crate) id: Uuid,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) action: String,
    pub(crate) channel: String,
    pub(crate) outcome: String,
    pub(crate) severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
}

impl From<AuditEventRow> for ActivityItem {
    fn from(row: AuditEventRow) -> Self {
        Self {
            id: row.id,
            created_at: row.created_at,
            action: row.action,
            channel: row.channel,
            outcome: row.outcome,
            severity: row.severity,
            target_type: row.target_type,
            target_key: row.target_key,
            purpose: row.purpose,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct AuditEventsResponse {
    pub(crate) events: Vec<AuditEventResponse>,
    pub(crate) page: PageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct AuditEventResponse {
    pub(crate) id: Uuid,
    pub(crate) action: String,
    pub(crate) channel: String,
    pub(crate) outcome: String,
    pub(crate) severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
    #[schema(value_type = Object)]
    pub(crate) detail: Value,
    pub(crate) created_at: DateTime<Utc>,
}

impl From<AuditEventRow> for AuditEventResponse {
    fn from(row: AuditEventRow) -> Self {
        Self {
            id: row.id,
            action: row.action,
            channel: row.channel,
            outcome: row.outcome,
            severity: row.severity,
            actor_user_id: row.actor_user_id,
            target_type: row.target_type,
            target_id: row.target_id,
            target_key: row.target_key,
            request_id: row.request_id,
            purpose: row.purpose,
            detail: row.detail,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ApiCallHistoryResponse {
    pub(crate) calls: Vec<ApiCallHistoryItem>,
    pub(crate) page: PageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct ApiCallHistoryItem {
    pub(crate) id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor_user_id: Option<Uuid>,
    pub(crate) channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_id: Option<Uuid>,
    pub(crate) credential_alias: String,
    pub(crate) credential_category: String,
    pub(crate) credential_provider: String,
    pub(crate) credential_env: String,
    pub(crate) method: String,
    pub(crate) request_path: String,
    #[schema(value_type = Object)]
    pub(crate) query_keys: Value,
    #[schema(value_type = Object)]
    pub(crate) request_header_keys: Value,
    #[schema(value_type = Object)]
    pub(crate) projection_keys: Value,
    pub(crate) max_bytes: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
    pub(crate) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) original_bytes: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) returned_bytes: Option<i32>,
    pub(crate) truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_message_safe: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
}

impl From<ApiCallHistoryRow> for ApiCallHistoryItem {
    fn from(row: ApiCallHistoryRow) -> Self {
        Self {
            id: row.id,
            owner_user_id: row.owner_user_id,
            actor_user_id: row.actor_user_id,
            channel: row.channel,
            request_id: row.request_id,
            credential_id: row.credential_id,
            credential_alias: row.credential_alias,
            credential_category: row.credential_category,
            credential_provider: row.credential_provider,
            credential_env: row.credential_env,
            method: row.method,
            request_path: row.request_path,
            query_keys: row.query_keys,
            request_header_keys: row.request_header_keys,
            projection_keys: row.projection_keys,
            max_bytes: row.max_bytes,
            purpose: row.purpose,
            outcome: row.outcome,
            status_code: row.status_code,
            latency_ms: row.latency_ms,
            original_bytes: row.original_bytes,
            returned_bytes: row.returned_bytes,
            truncated: row.truncated,
            error_kind: row.error_kind,
            error_message_safe: row.error_message_safe,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SqlQueryHistoryResponse {
    pub(crate) queries: Vec<SqlQueryHistoryItem>,
    pub(crate) page: PageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct SqlQueryHistoryItem {
    pub(crate) id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor_user_id: Option<Uuid>,
    pub(crate) channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_id: Option<Uuid>,
    pub(crate) credential_alias: String,
    pub(crate) credential_category: String,
    pub(crate) credential_provider: String,
    pub(crate) credential_env: String,
    pub(crate) query_sha256: String,
    pub(crate) params_count: i32,
    pub(crate) max_rows: i32,
    pub(crate) max_bytes: i32,
    pub(crate) timeout_ms: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purpose: Option<String>,
    pub(crate) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) row_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) returned_bytes: Option<i32>,
    pub(crate) truncated: bool,
    #[schema(value_type = Object)]
    pub(crate) result_columns: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_message_safe: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
}

impl From<SqlQueryHistoryRow> for SqlQueryHistoryItem {
    fn from(row: SqlQueryHistoryRow) -> Self {
        Self {
            id: row.id,
            owner_user_id: row.owner_user_id,
            actor_user_id: row.actor_user_id,
            channel: row.channel,
            request_id: row.request_id,
            credential_id: row.credential_id,
            credential_alias: row.credential_alias,
            credential_category: row.credential_category,
            credential_provider: row.credential_provider,
            credential_env: row.credential_env,
            query_sha256: row.query_sha256,
            params_count: row.params_count,
            max_rows: row.max_rows,
            max_bytes: row.max_bytes,
            timeout_ms: row.timeout_ms,
            purpose: row.purpose,
            outcome: row.outcome,
            latency_ms: row.latency_ms,
            row_count: row.row_count,
            returned_bytes: row.returned_bytes,
            truncated: row.truncated,
            result_columns: row.result_columns,
            error_kind: row.error_kind,
            error_message_safe: row.error_message_safe,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct CredentialHistoryResponse {
    pub(crate) events: Vec<CredentialHistoryItem>,
    pub(crate) page: PageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct CredentialHistoryItem {
    pub(crate) id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) credential_id: Option<Uuid>,
    pub(crate) owner_user_id: Uuid,
    pub(crate) alias: String,
    pub(crate) action: String,
    pub(crate) actor_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actor_user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    pub(crate) changed_fields: Vec<String>,
    pub(crate) version: i64,
    #[schema(value_type = Object)]
    pub(crate) detail: Value,
    pub(crate) created_at: DateTime<Utc>,
}

impl From<CredentialHistoryRow> for CredentialHistoryItem {
    fn from(row: CredentialHistoryRow) -> Self {
        Self {
            id: row.id,
            credential_id: row.credential_id,
            owner_user_id: row.owner_user_id,
            alias: row.alias,
            action: row.action,
            actor_user_id: row.actor_user_id,
            actor_ip: row.actor_ip,
            actor_user_agent: row.actor_user_agent,
            request_id: row.request_id,
            channel: row.channel,
            reason: row.reason,
            changed_fields: row.changed_fields,
            version: row.version,
            detail: row.detail,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() -> Result<(), ApiError> {
        let id = Uuid::from_u128(7);
        let created_at = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .map_err(|_error| ApiError::invalid_field("bad test time"))?
            .with_timezone(&Utc);
        let encoded = encode_cursor(created_at, id);
        let parsed = parse_cursor(&encoded)?;
        assert_eq!(parsed.created_at, created_at);
        assert_eq!(parsed.id, id);
        Ok(())
    }

    #[test]
    fn query_parses_common_filters() -> Result<(), ApiError> {
        let filters = parse_query(Some(
            "channel=mcp&tool=mcp.api.call&credential=prod&outcome=ok&limit=10",
        ))?;
        assert_eq!(filters.channel.as_deref(), Some("mcp"));
        assert_eq!(filters.action.as_deref(), Some("mcp.api.call"));
        assert_eq!(filters.credential.as_deref(), Some("prod"));
        assert_eq!(filters.outcome.as_deref(), Some("ok"));
        assert_eq!(filters.limit, 10);
        Ok(())
    }
}
