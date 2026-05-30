use opsgate_core::{Error, Result};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuditRepo {
    pool: PgPool,
}

impl AuditRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn append(&self, params: AuditLogParams) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                action,
                channel,
                outcome,
                severity,
                actor_user_id,
                actor_ip,
                actor_user_agent,
                target_type,
                target_id,
                target_key,
                request_id,
                purpose,
                detail
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            "#,
        )
        .bind(params.action)
        .bind(params.channel)
        .bind(params.outcome)
        .bind(params.severity)
        .bind(params.actor_user_id)
        .bind(params.actor_ip)
        .bind(params.actor_user_agent)
        .bind(params.target_type)
        .bind(params.target_id)
        .bind(params.target_key)
        .bind(params.request_id)
        .bind(params.purpose)
        .bind(params.detail)
        .execute(&self.pool)
        .await
        .map_err(|error| Error::internal(format!("audit log store error: {error}")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AuditLogParams {
    pub action: String,
    pub channel: String,
    pub outcome: String,
    pub severity: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_ip: Option<String>,
    pub actor_user_agent: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_key: Option<String>,
    pub request_id: Option<String>,
    pub purpose: Option<String>,
    pub detail: Value,
}
