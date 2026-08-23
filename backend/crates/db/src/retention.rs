//! Retention cleanup for audit/history tables.

use chrono::{DateTime, Duration, Utc};
use opsgate_core::{Error, Result};
use sqlx::{PgConnection, PgPool};

const LOCK_CLASS_ID: i32 = 78_001;
const LOCK_OBJECT_ID: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub batch_size: u32,
    pub audit_log_days: u32,
    pub api_call_history_days: u32,
    pub sql_query_history_days: u32,
    pub credential_history_days: u32,
    pub deleted_credential_days: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionCounts {
    pub audit_logs: u64,
    pub api_call_history: u64,
    pub sql_query_history: u64,
    pub credential_history: u64,
    pub deleted_credentials: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionRun {
    Completed(RetentionCounts),
    LockBusy,
}

pub async fn run_retention_once(pool: &PgPool, policy: RetentionPolicy) -> Result<RetentionRun> {
    run_retention_once_at(pool, policy, Utc::now()).await
}

pub async fn run_retention_once_at(
    pool: &PgPool,
    policy: RetentionPolicy,
    now: DateTime<Utc>,
) -> Result<RetentionRun> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| Error::internal(format!("retention database acquire failed: {error}")))?;

    if !try_lock(&mut connection).await? {
        return Ok(RetentionRun::LockBusy);
    }

    let cleanup = cleanup_locked(&mut connection, policy, now).await;
    if let Err(error) = unlock(&mut connection).await {
        tracing::warn!(%error, event = "retention.unlock_failed");
    }
    cleanup.map(RetentionRun::Completed)
}

async fn try_lock(connection: &mut PgConnection) -> Result<bool> {
    sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
        .bind(LOCK_CLASS_ID)
        .bind(LOCK_OBJECT_ID)
        .fetch_one(connection)
        .await
        .map_err(|error| Error::internal(format!("retention advisory lock failed: {error}")))
}

async fn unlock(connection: &mut PgConnection) -> Result<()> {
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1, $2)")
        .bind(LOCK_CLASS_ID)
        .bind(LOCK_OBJECT_ID)
        .fetch_one(connection)
        .await
        .map_err(|error| Error::internal(format!("retention advisory unlock failed: {error}")))?;

    if unlocked {
        Ok(())
    } else {
        Err(Error::internal("retention advisory lock was not held"))
    }
}

async fn cleanup_locked(
    connection: &mut PgConnection,
    policy: RetentionPolicy,
    now: DateTime<Utc>,
) -> Result<RetentionCounts> {
    let batch_size = i64::from(policy.batch_size);
    let counts = RetentionCounts {
        api_call_history: delete_all_batches(
            connection,
            RetentionTable::ApiCallHistory,
            cutoff(now, policy.api_call_history_days)?,
            batch_size,
        )
        .await?,
        sql_query_history: delete_all_batches(
            connection,
            RetentionTable::SqlQueryHistory,
            cutoff(now, policy.sql_query_history_days)?,
            batch_size,
        )
        .await?,
        audit_logs: delete_all_batches(
            connection,
            RetentionTable::AuditLogs,
            cutoff(now, policy.audit_log_days)?,
            batch_size,
        )
        .await?,
        credential_history: delete_all_batches(
            connection,
            RetentionTable::CredentialHistory,
            cutoff(now, policy.credential_history_days)?,
            batch_size,
        )
        .await?,
        deleted_credentials: delete_all_batches(
            connection,
            RetentionTable::DeletedCredentials,
            cutoff(now, policy.deleted_credential_days)?,
            batch_size,
        )
        .await?,
    };
    Ok(counts)
}

fn cutoff(now: DateTime<Utc>, days: u32) -> Result<DateTime<Utc>> {
    now.checked_sub_signed(Duration::days(i64::from(days)))
        .ok_or_else(|| Error::validation("retention cutoff is out of range"))
}

#[derive(Clone, Copy)]
enum RetentionTable {
    ApiCallHistory,
    SqlQueryHistory,
    AuditLogs,
    CredentialHistory,
    DeletedCredentials,
}

async fn delete_all_batches(
    connection: &mut PgConnection,
    table: RetentionTable,
    cutoff: DateTime<Utc>,
    batch_size: i64,
) -> Result<u64> {
    let mut total = 0;
    loop {
        let deleted = delete_batch(connection, table, cutoff, batch_size).await?;
        total += deleted;
        if deleted == 0 {
            return Ok(total);
        }
    }
}

async fn delete_batch(
    connection: &mut PgConnection,
    table: RetentionTable,
    cutoff: DateTime<Utc>,
    batch_size: i64,
) -> Result<u64> {
    let sql = match table {
        RetentionTable::ApiCallHistory => {
            "WITH doomed AS (
                SELECT id FROM api_call_history
                WHERE created_at < $1
                ORDER BY created_at
                LIMIT $2
            )
            DELETE FROM api_call_history h
            USING doomed
            WHERE h.id = doomed.id"
        }
        RetentionTable::SqlQueryHistory => {
            "WITH doomed AS (
                SELECT id FROM sql_query_history
                WHERE created_at < $1
                ORDER BY created_at
                LIMIT $2
            )
            DELETE FROM sql_query_history h
            USING doomed
            WHERE h.id = doomed.id"
        }
        RetentionTable::AuditLogs => {
            "WITH doomed AS (
                SELECT id FROM audit_logs
                WHERE created_at < $1
                ORDER BY created_at
                LIMIT $2
            )
            DELETE FROM audit_logs h
            USING doomed
            WHERE h.id = doomed.id"
        }
        RetentionTable::CredentialHistory => {
            "WITH doomed AS (
                SELECT id FROM credential_history
                WHERE created_at < $1
                ORDER BY created_at
                LIMIT $2
            )
            DELETE FROM credential_history h
            USING doomed
            WHERE h.id = doomed.id"
        }
        RetentionTable::DeletedCredentials => {
            "WITH doomed AS (
                SELECT id FROM credentials
                WHERE deleted_at IS NOT NULL
                  AND deleted_at < $1
                ORDER BY deleted_at
                LIMIT $2
            )
            DELETE FROM credentials c
            USING doomed
            WHERE c.id = doomed.id"
        }
    };

    sqlx::query(sql)
        .bind(cutoff)
        .bind(batch_size)
        .execute(connection)
        .await
        .map(|result| result.rows_affected())
        .map_err(|error| Error::internal(format!("retention delete failed: {error}")))
}
