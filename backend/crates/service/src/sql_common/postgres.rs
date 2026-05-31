use std::time::Duration;

use opsgate_core::{Error, Result};
use secrecy::ExposeSecret;
use sqlx::pool::PoolConnection;
use sqlx::{Executor, PgConnection, Postgres};
use uuid::Uuid;

use crate::sql_common::SqlSecret;
use opsgate_infra::postgres::GuardedPostgresTarget;
use opsgate_infra::postgres_pool::TargetPgPools;

const POSTGRES_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Acquire a pooled, read-only Postgres connection for one tool call.
///
/// The connection is reused across calls via [`TargetPgPools`]; the per-call
/// `BEGIN READ ONLY` transaction and transaction-local `statement_timeout` keep
/// each call isolated, and both reset on COMMIT/ROLLBACK so the connection
/// returns to the pool clean.
pub async fn begin_read_only_connection(
    pools: &TargetPgPools,
    credential_id: Uuid,
    target: &GuardedPostgresTarget,
    secret: &SqlSecret,
    timeout_ms: u32,
) -> Result<PoolConnection<Postgres>> {
    let options = target.connect_options(
        secret.username.expose_secret(),
        secret.password.expose_secret(),
    )?;
    let pool = pools.pool_for(credential_id, options)?;
    let mut conn = tokio::time::timeout(POSTGRES_CONNECT_TIMEOUT, pool.acquire())
        .await
        .map_err(|_error| Error::internal("postgres connection timed out"))?
        .map_err(|_error| Error::internal("postgres connection failed"))?;
    conn.execute("BEGIN READ ONLY")
        .await
        .map_err(|_error| Error::internal("postgres transaction failed"))?;
    if let Err(error) = set_statement_timeout(&mut conn, timeout_ms).await {
        let _ = conn.execute("ROLLBACK").await;
        return Err(error);
    }
    Ok(conn)
}

pub async fn finish_read_only_result<T>(conn: &mut PgConnection, result: Result<T>) -> Result<T> {
    if result.is_ok() {
        conn.execute("COMMIT")
            .await
            .map_err(|_error| Error::internal("postgres transaction commit failed"))?;
    } else {
        let _ = conn.execute("ROLLBACK").await;
    }
    result
}

async fn set_statement_timeout(conn: &mut PgConnection, timeout_ms: u32) -> Result<()> {
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(format!("{timeout_ms}ms"))
        .execute(conn)
        .await
        .map_err(|_error| Error::internal("postgres statement timeout setup failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_connect_timeout_is_bounded() {
        assert_eq!(POSTGRES_CONNECT_TIMEOUT, Duration::from_secs(5));
    }
}
