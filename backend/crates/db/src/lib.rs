//! Database access: connection pool construction and migrations.

use opsgate_core::{Config, Error, Result};
use sqlx::postgres::PgPoolOptions;

pub mod credential_repo;
pub mod user_repo;

pub use credential_repo::{
    CredentialAuditAction, CredentialAuditParams, CredentialRepo, CredentialSummaryRows,
};
pub use sqlx::PgPool;
pub use user_repo::UserRepo;

/// Embedded migrations from `migrations/`, run at startup via [`run_migrations`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Build a Postgres connection pool from configuration.
pub async fn connect(config: &Config) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(&config.database_url)
        .await
        .map_err(|e| Error::internal(format!("failed to connect to database: {e}")))
}

/// Apply any pending migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| Error::internal(format!("migration failed: {e}")))
}
