use opsgate_core::{Error, Result};
use secrecy::ExposeSecret;
use sqlx::{Connection, Executor, PgConnection};

use crate::sql_common::SqlSecret;
use crate::target::postgres::GuardedPostgresTarget;

pub(crate) async fn begin_read_only_connection(
    target: &GuardedPostgresTarget,
    secret: &SqlSecret,
    timeout_ms: u32,
) -> Result<PgConnection> {
    let options = target.connect_options(
        secret.username.expose_secret(),
        secret.password.expose_secret(),
    )?;
    let mut conn = PgConnection::connect_with(&options)
        .await
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

pub(crate) async fn finish_read_only_result<T>(
    conn: &mut PgConnection,
    result: Result<T>,
) -> Result<T> {
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
