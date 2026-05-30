//! Database access: connection pool construction and migrations.

use opsgate_core::{Config, Error, Result};
use sqlx::postgres::PgPoolOptions;

pub mod api_call_history_repo;
pub mod audit_repo;
pub mod credential_repo;
pub mod sql_query_history_repo;
pub mod user_repo;

pub use api_call_history_repo::{ApiCallHistoryParams, ApiCallHistoryRepo};
pub use audit_repo::{AuditLogParams, AuditRepo};
pub use credential_repo::{
    CredentialAuditAction, CredentialAuditParams, CredentialRepo, CredentialSummaryRows,
};
pub use sql_query_history_repo::{SqlQueryHistoryParams, SqlQueryHistoryRepo};
pub use sqlx::PgPool;
pub use user_repo::UserRepo;

/// Embedded migrations from `migrations/`, run at startup via [`run_migrations`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Build the narrowed runtime Postgres connection pool from configuration.
pub async fn connect(config: &Config) -> Result<PgPool> {
    connect_url(&config.database_url, config.db_max_connections)
        .await
        .map_err(|e| Error::internal(format!("failed to connect to database: {e}")))
}

/// Build the owner/migration Postgres connection pool from configuration.
pub async fn connect_migrate(config: &Config) -> Result<PgPool> {
    connect_url(&config.database_migrate_url, 1)
        .await
        .map_err(|e| Error::internal(format!("failed to connect to migration database: {e}")))
}

async fn connect_url(
    database_url: &str,
    max_connections: u32,
) -> std::result::Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await
}

/// Apply any pending migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| Error::internal(format!("migration failed: {e}")))
}
