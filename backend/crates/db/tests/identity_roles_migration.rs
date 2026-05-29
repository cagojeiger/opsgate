use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const MIGRATIONS_BEFORE_IDENTITY_ROLES: [&str; 8] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_users_oauth.sql"),
    include_str!("../migrations/0003_credentials.sql"),
    include_str!("../migrations/0004_credentials_delete_secret.sql"),
    include_str!("../migrations/0005_credential_audit_events.sql"),
    include_str!("../migrations/0006_api_call_history.sql"),
    include_str!("../migrations/0007_audit_logs.sql"),
    include_str!("../migrations/0008_sql_query_history.sql"),
];

const IDENTITY_ROLES_MIGRATION: &str = include_str!("../migrations/0009_identity_roles.sql");

#[tokio::test]
async fn identity_roles_migration_rehearses_legacy_data_and_role_inserts()
-> Result<(), Box<dyn std::error::Error>> {
    let database_url = match std::env::var("OPSGATE_TEST_DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            eprintln!(
                "skipping Postgres migration rehearsal; set OPSGATE_TEST_DATABASE_URL to run it"
            );
            return Ok(());
        }
    };

    let mut conn = PgConnection::connect(&database_url).await?;
    let schema = format!("opsgate_identity_roles_{}", Uuid::new_v4().simple());

    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut conn)
        .await?;
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&mut conn)
        .await?;

    let result = run_rehearsal(&mut conn).await;

    let _ = sqlx::query("SET search_path TO public")
        .execute(&mut conn)
        .await;
    let cleanup = sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
        .execute(&mut conn)
        .await;
    if let Err(err) = cleanup {
        eprintln!("failed to drop temporary schema {schema}: {err}");
    }

    result
}

async fn run_rehearsal(conn: &mut PgConnection) -> Result<(), Box<dyn std::error::Error>> {
    for migration in MIGRATIONS_BEFORE_IDENTITY_ROLES {
        sqlx::raw_sql(migration).execute(&mut *conn).await?;
    }

    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, sub, display_name) \
         VALUES ('legacy@example.test', 'legacy-sub', 'Legacy User') \
         RETURNING id",
    )
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO audit_logs \
         (action, channel, outcome, severity, actor_user_id, actor_role, detail) \
         VALUES ('test.audit', 'mcp', 'ok', 'info', $1, 'active', '{}'::jsonb)",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO sql_query_history \
         (owner_user_id, actor_user_id, actor_role, outcome) \
         VALUES ($1, $1, 'active', 'ok')",
    )
    .bind(user_id)
    .execute(&mut *conn)
    .await?;

    sqlx::raw_sql(IDENTITY_ROLES_MIGRATION)
        .execute(&mut *conn)
        .await?;

    assert_legacy_active_rows_became_viewer(conn).await?;
    assert_allowed_roles_insert(conn, user_id).await?;
    assert_legacy_active_role_is_rejected(conn).await?;

    Ok(())
}

async fn assert_legacy_active_rows_became_viewer(
    conn: &mut PgConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let audit_viewer_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE actor_role = 'viewer'")
            .fetch_one(&mut *conn)
            .await?;
    let sql_viewer_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sql_query_history WHERE actor_role = 'viewer'")
            .fetch_one(&mut *conn)
            .await?;

    assert_eq!(audit_viewer_count, 1);
    assert_eq!(sql_viewer_count, 1);
    Ok(())
}

async fn assert_allowed_roles_insert(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    for role in ["admin", "operator", "viewer"] {
        sqlx::query(
            "INSERT INTO audit_logs \
             (action, channel, outcome, severity, actor_user_id, actor_role, detail) \
             VALUES ('test.audit', 'api', 'ok', 'info', $1, $2, '{}'::jsonb)",
        )
        .bind(user_id)
        .bind(role)
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "INSERT INTO sql_query_history \
             (owner_user_id, actor_user_id, actor_role, outcome) \
             VALUES ($1, $1, $2, 'ok')",
        )
        .bind(user_id)
        .bind(role)
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "INSERT INTO api_call_history \
             (owner_user_id, actor_user_id, actor_role, request_id, outcome) \
             VALUES ($1, $1, $2, $3, 'ok')",
        )
        .bind(user_id)
        .bind(role)
        .bind(format!("req-{role}"))
        .execute(&mut *conn)
        .await?;
    }

    let api_role_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_call_history \
         WHERE actor_role IN ('admin', 'operator', 'viewer') \
           AND request_id IN ('req-admin', 'req-operator', 'req-viewer')",
    )
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(api_role_count, 3);
    Ok(())
}

async fn assert_legacy_active_role_is_rejected(
    conn: &mut PgConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let audit_insert = sqlx::query(
        "INSERT INTO audit_logs (action, channel, outcome, severity, actor_role, detail) \
         VALUES ('test.audit', 'api', 'ok', 'info', 'active', '{}'::jsonb)",
    )
    .execute(&mut *conn)
    .await;
    assert!(audit_insert.is_err());

    let sql_insert =
        sqlx::query("INSERT INTO sql_query_history (actor_role, outcome) VALUES ('active', 'ok')")
            .execute(&mut *conn)
            .await;
    assert!(sql_insert.is_err());

    let api_insert =
        sqlx::query("INSERT INTO api_call_history (actor_role, outcome) VALUES ('active', 'ok')")
            .execute(&mut *conn)
            .await;
    assert!(api_insert.is_err());
    Ok(())
}
