use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const MIGRATIONS_BEFORE_CREDENTIAL_LIFECYCLE: [&str; 9] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_users_oauth.sql"),
    include_str!("../migrations/0003_credentials.sql"),
    include_str!("../migrations/0004_credentials_delete_secret.sql"),
    include_str!("../migrations/0005_credential_audit_events.sql"),
    include_str!("../migrations/0006_api_call_history.sql"),
    include_str!("../migrations/0007_audit_logs.sql"),
    include_str!("../migrations/0008_sql_query_history.sql"),
    include_str!("../migrations/0009_identity_roles.sql"),
];

const CREDENTIAL_LIFECYCLE_MIGRATION: &str =
    include_str!("../migrations/0010_credential_lifecycle_history.sql");

#[tokio::test]
async fn credential_lifecycle_migration_rehearses_non_empty_credentials()
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
    let schema = format!("opsgate_credential_lifecycle_{}", Uuid::new_v4().simple());

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
    for migration in MIGRATIONS_BEFORE_CREDENTIAL_LIFECYCLE {
        sqlx::raw_sql(migration).execute(&mut *conn).await?;
    }

    let owner_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, sub, display_name) \
         VALUES ('owner@example.test', 'owner-sub', 'Owner') \
         RETURNING id",
    )
    .fetch_one(&mut *conn)
    .await?;

    seed_legacy_credentials(conn, owner_id).await?;
    sqlx::raw_sql(CREDENTIAL_LIFECYCLE_MIGRATION)
        .execute(&mut *conn)
        .await?;

    assert_actor_columns_backfilled(conn, owner_id).await?;
    assert_history_table_and_unique_version(conn, owner_id).await?;
    assert_lifecycle_constraints(conn, owner_id).await?;
    Ok(())
}

async fn seed_legacy_credentials(
    conn: &mut PgConnection,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        "INSERT INTO credentials \
         (owner_user_id, category, provider, alias, endpoint, secret_ciphertext, description, env, tags, policy) \
         VALUES ($1, 'http', 'k8s', 'active-api', 'https://api.example.test', $2, '', 'prod', ARRAY['prod'], '{}'::jsonb)",
    )
    .bind(owner_id)
    .bind(vec![1_u8, 2, 3])
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO credentials \
         (owner_user_id, category, provider, alias, endpoint, secret_ciphertext, description, env, tags, policy, deleted_at, secret_destroyed_at) \
         VALUES ($1, 'sql', 'postgres', 'old-db', 'postgres://db.example.test/app', NULL, '', 'dev', ARRAY['old'], '{}'::jsonb, now(), now())",
    )
    .bind(owner_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn assert_actor_columns_backfilled(
    conn: &mut PgConnection,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let active: (Uuid, Uuid, Option<Uuid>, Vec<u8>) = sqlx::query_as(
        "SELECT created_by, updated_by, deleted_by, secret_ciphertext \
         FROM credentials WHERE alias = 'active-api'",
    )
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(active.0, owner_id);
    assert_eq!(active.1, owner_id);
    assert_eq!(active.2, None);
    assert_eq!(active.3, vec![1_u8, 2, 3]);

    let deleted: (Uuid, Uuid, Option<Uuid>, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT created_by, updated_by, deleted_by, secret_ciphertext, secret_destroyed_at IS NOT NULL \
         FROM credentials WHERE alias = 'old-db'",
    )
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(deleted.0, owner_id);
    assert_eq!(deleted.1, owner_id);
    assert_eq!(deleted.2, Some(owner_id));
    assert_eq!(deleted.3, None);
    assert!(deleted.4);

    for column in ["created_by", "updated_by"] {
        let is_nullable: String = sqlx::query_scalar(
            "SELECT is_nullable \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'credentials' \
               AND column_name = $1",
        )
        .bind(column)
        .fetch_one(&mut *conn)
        .await?;
        assert_eq!(is_nullable, "NO");
    }
    Ok(())
}

async fn assert_history_table_and_unique_version(
    conn: &mut PgConnection,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let credential_id: Uuid =
        sqlx::query_scalar("SELECT id FROM credentials WHERE alias = 'active-api'")
            .fetch_one(&mut *conn)
            .await?;
    sqlx::query(
        "INSERT INTO credential_history \
         (credential_id, owner_user_id, alias, action, actor_user_id, version, detail) \
         VALUES ($1, $2, 'active-api', 'register', $2, 1, '{}'::jsonb)",
    )
    .bind(credential_id)
    .bind(owner_id)
    .execute(&mut *conn)
    .await?;

    let duplicate = sqlx::query(
        "INSERT INTO credential_history \
         (credential_id, owner_user_id, alias, action, actor_user_id, version, detail) \
         VALUES ($1, $2, 'active-api', 'update', $2, 1, '{}'::jsonb)",
    )
    .bind(credential_id)
    .bind(owner_id)
    .execute(&mut *conn)
    .await;
    assert!(duplicate.is_err());
    Ok(())
}

async fn assert_lifecycle_constraints(
    conn: &mut PgConnection,
    owner_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let bad_deleted_pair = sqlx::query(
        "INSERT INTO credentials \
         (owner_user_id, created_by, updated_by, category, provider, alias, endpoint, secret_ciphertext, description, env, tags, policy, deleted_at, secret_destroyed_at) \
         VALUES ($1, $1, $1, 'http', 'k8s', 'bad-delete', 'https://bad.example.test', NULL, '', 'dev', ARRAY[]::text[], '{}'::jsonb, now(), now())",
    )
    .bind(owner_id)
    .execute(&mut *conn)
    .await;
    assert!(bad_deleted_pair.is_err());

    let bad_secret_lifecycle = sqlx::query(
        "INSERT INTO credentials \
         (owner_user_id, created_by, updated_by, category, provider, alias, endpoint, secret_ciphertext, description, env, tags, policy) \
         VALUES ($1, $1, $1, 'http', 'k8s', 'bad-secret', 'https://bad.example.test', NULL, '', 'dev', ARRAY[]::text[], '{}'::jsonb)",
    )
    .bind(owner_id)
    .execute(&mut *conn)
    .await;
    assert!(bad_secret_lifecycle.is_err());
    Ok(())
}
