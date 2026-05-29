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

#[cfg(test)]
mod tests {
    const IDENTITY_ROLES_MIGRATION: &str = include_str!("../migrations/0009_identity_roles.sql");

    #[test]
    fn identity_roles_migration_backfills_legacy_roles_before_constraints() {
        assert_before(
            "DROP CONSTRAINT IF EXISTS audit_logs_actor_role_chk;",
            "UPDATE audit_logs\nSET actor_role = 'viewer'\nWHERE actor_role = 'active';",
        );
        assert_before(
            "UPDATE audit_logs\nSET actor_role = 'viewer'\nWHERE actor_role = 'active';",
            "ADD CONSTRAINT audit_logs_actor_role_chk",
        );
        assert_before(
            "DROP CONSTRAINT IF EXISTS sql_query_history_actor_role_chk;",
            "UPDATE sql_query_history\nSET actor_role = 'viewer'\nWHERE actor_role = 'active';",
        );
        assert_before(
            "UPDATE sql_query_history\nSET actor_role = 'viewer'\nWHERE actor_role = 'active';",
            "ADD CONSTRAINT sql_query_history_actor_role_chk",
        );
        assert!(IDENTITY_ROLES_MIGRATION.contains(
            "CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'))"
        ));
    }

    #[test]
    fn identity_roles_migration_adds_api_call_history_role_metadata() {
        assert!(IDENTITY_ROLES_MIGRATION.contains("ADD COLUMN IF NOT EXISTS actor_role TEXT"));
        assert!(IDENTITY_ROLES_MIGRATION.contains("ADD COLUMN IF NOT EXISTS request_id TEXT"));
        assert!(IDENTITY_ROLES_MIGRATION.contains(
            "ADD CONSTRAINT api_call_history_actor_role_chk\n        CHECK (actor_role IS NULL OR actor_role IN ('admin', 'operator', 'viewer'))"
        ));
    }

    fn assert_before(first: &str, second: &str) {
        let first_pos = IDENTITY_ROLES_MIGRATION.find(first).unwrap_or(usize::MAX);
        let second_pos = IDENTITY_ROLES_MIGRATION.find(second).unwrap_or(usize::MAX);
        assert_ne!(
            first_pos,
            usize::MAX,
            "missing migration statement: {first}"
        );
        assert_ne!(
            second_pos,
            usize::MAX,
            "missing migration statement: {second}"
        );
        assert!(
            first_pos < second_pos,
            "expected `{first}` before `{second}`"
        );
    }
}
