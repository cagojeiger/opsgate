use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::Config;

pub async fn spawn_if_enabled(
    config: &Config,
    shutdown: CancellationToken,
) -> opsgate_core::Result<Option<tokio::task::JoinHandle<()>>> {
    if !config.retention_enabled {
        return Ok(None);
    }

    let retention_url = config.retention_database_url();
    if config.retention_database_url.is_none() {
        warn!(
            event = "retention.using_migration_database_url",
            "OPSGATE_RETENTION_DATABASE_URL is not set; falling back to migration database URL"
        );
    }

    let pool = opsgate_db::connect_retention(retention_url).await?;
    let policy = config.retention_policy();
    let interval = Duration::from_secs(config.retention_run_interval_hours.saturating_mul(3600));
    let handle = tokio::spawn(async move {
        worker_loop(pool, policy, interval, shutdown).await;
    });
    Ok(Some(handle))
}

async fn worker_loop(
    pool: opsgate_db::PgPool,
    policy: opsgate_db::RetentionPolicy,
    interval: Duration,
    shutdown: CancellationToken,
) {
    info!(
        event = "retention.worker_started",
        interval_hours = interval.as_secs() / 3600,
        batch_size = policy.batch_size
    );

    let jitter = Duration::from_secs(u64::from(std::process::id() % 30));
    if !wait_or_shutdown(jitter, &shutdown).await {
        pool.close().await;
        info!(event = "retention.worker_stopped");
        return;
    }

    loop {
        run_once(&pool, policy).await;
        if !wait_or_shutdown(interval, &shutdown).await {
            break;
        }
    }

    pool.close().await;
    info!(event = "retention.worker_stopped");
}

async fn wait_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => true,
        () = shutdown.cancelled() => false,
    }
}

async fn run_once(pool: &opsgate_db::PgPool, policy: opsgate_db::RetentionPolicy) {
    match opsgate_db::run_retention_once(pool, policy).await {
        Ok(opsgate_db::RetentionRun::Completed(counts)) => {
            info!(
                event = "retention.cleanup_completed",
                api_call_history_deleted = counts.api_call_history,
                sql_query_history_deleted = counts.sql_query_history,
                audit_logs_deleted = counts.audit_logs,
                credential_history_deleted = counts.credential_history,
                deleted_credentials_deleted = counts.deleted_credentials
            );
        }
        Ok(opsgate_db::RetentionRun::LockBusy) => {
            info!(event = "retention.lock_busy");
        }
        Err(error) => {
            warn!(%error, event = "retention.cleanup_failed");
        }
    }
}
