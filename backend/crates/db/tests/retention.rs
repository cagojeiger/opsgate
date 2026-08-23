use std::str::FromStr;

use chrono::{Duration, Utc};
use opsgate_db::{RetentionCounts, RetentionPolicy, RetentionRun};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgPool};
use uuid::Uuid;

const MIGRATIONS: [&str; 1] = [include_str!("../migrations/0001_schema.sql")];

struct TestDb {
    database_url: String,
    schema: String,
    pool: PgPool,
}

#[tokio::test]
async fn retention_deletes_only_expired_rows_in_batches() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let now = Utc::now();
    let old = now - Duration::days(10);
    let fresh = now - Duration::days(1);
    let user_id = insert_user(&db.pool).await?;

    seed_api_call_history(&db.pool, old, 3).await?;
    seed_api_call_history(&db.pool, fresh, 1).await?;
    seed_sql_query_history(&db.pool, old, 2).await?;
    seed_sql_query_history(&db.pool, fresh, 1).await?;
    seed_audit_logs(&db.pool, old, 2).await?;
    seed_audit_logs(&db.pool, fresh, 1).await?;
    seed_credential_history(&db.pool, user_id, old, 2).await?;
    seed_credential_history(&db.pool, user_id, fresh, 1).await?;
    seed_deleted_credentials(&db.pool, user_id, old, 2).await?;
    seed_deleted_credentials(&db.pool, user_id, fresh, 1).await?;

    let run = opsgate_db::retention::run_retention_once_at(&db.pool, policy(), now).await?;
    assert_eq!(
        run,
        RetentionRun::Completed(RetentionCounts {
            api_call_history: 3,
            sql_query_history: 2,
            audit_logs: 2,
            credential_history: 2,
            deleted_credentials: 2,
        })
    );

    assert_eq!(count_rows(&db.pool, "api_call_history").await?, 1);
    assert_eq!(count_rows(&db.pool, "sql_query_history").await?, 1);
    assert_eq!(count_rows(&db.pool, "audit_logs").await?, 1);
    assert_eq!(count_rows(&db.pool, "credential_history").await?, 1);
    assert_eq!(count_rows(&db.pool, "credentials").await?, 1);

    let second_run = opsgate_db::retention::run_retention_once_at(&db.pool, policy(), now).await?;
    assert_eq!(
        second_run,
        RetentionRun::Completed(RetentionCounts::default())
    );

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn retention_skips_when_another_replica_holds_lock() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let mut lock_holder = db.pool.acquire().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
        .bind(78_001_i32)
        .bind(1_i32)
        .fetch_one(&mut *lock_holder)
        .await?;
    assert!(locked);

    let run = opsgate_db::retention::run_retention_once_at(&db.pool, policy(), Utc::now()).await?;
    assert_eq!(run, RetentionRun::LockBusy);

    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1, $2)")
        .bind(78_001_i32)
        .bind(1_i32)
        .fetch_one(&mut *lock_holder)
        .await?;
    assert!(unlocked);

    db.cleanup().await;
    Ok(())
}

impl TestDb {
    async fn setup() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let database_url = match std::env::var("OPSGATE_TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping Postgres retention tests; set OPSGATE_TEST_DATABASE_URL to run them"
                );
                return Ok(None);
            }
        };
        let schema = format!("opsgate_retention_{}", Uuid::new_v4().simple());
        let mut admin = sqlx::PgConnection::connect(&database_url).await?;
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut admin)
            .await?;

        let options =
            PgConnectOptions::from_str(&database_url)?.options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?;
        for migration in MIGRATIONS {
            sqlx::raw_sql(migration).execute(&pool).await?;
        }
        Ok(Some(Self {
            database_url,
            schema,
            pool,
        }))
    }

    async fn cleanup(self) {
        self.pool.close().await;
        match sqlx::PgConnection::connect(&self.database_url).await {
            Ok(mut conn) => {
                if let Err(err) =
                    sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
                        .execute(&mut conn)
                        .await
                {
                    eprintln!("failed to drop temporary schema {}: {err}", self.schema);
                }
            }
            Err(err) => {
                eprintln!("failed to reconnect for cleanup {}: {err}", self.schema);
            }
        }
    }
}

fn policy() -> RetentionPolicy {
    RetentionPolicy {
        batch_size: 2,
        audit_log_days: 5,
        api_call_history_days: 5,
        sql_query_history_days: 5,
        credential_history_days: 5,
        deleted_credential_days: 5,
    }
}

async fn insert_user(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO users (sub, email, display_name)
         VALUES ('retention-sub', 'retention@example.test', 'Retention')
         RETURNING id",
    )
    .fetch_one(pool)
    .await
}

async fn seed_api_call_history(
    pool: &PgPool,
    created_at: chrono::DateTime<Utc>,
    count: i32,
) -> Result<(), sqlx::Error> {
    for _ in 0..count {
        sqlx::query("INSERT INTO api_call_history (outcome, created_at) VALUES ('ok', $1)")
            .bind(created_at)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn seed_sql_query_history(
    pool: &PgPool,
    created_at: chrono::DateTime<Utc>,
    count: i32,
) -> Result<(), sqlx::Error> {
    for _ in 0..count {
        sqlx::query("INSERT INTO sql_query_history (outcome, created_at) VALUES ('ok', $1)")
            .bind(created_at)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn seed_audit_logs(
    pool: &PgPool,
    created_at: chrono::DateTime<Utc>,
    count: i32,
) -> Result<(), sqlx::Error> {
    for _ in 0..count {
        sqlx::query(
            "INSERT INTO audit_logs (action, outcome, severity, created_at)
             VALUES ('retention.test', 'ok', 'info', $1)",
        )
        .bind(created_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn seed_credential_history(
    pool: &PgPool,
    user_id: Uuid,
    created_at: chrono::DateTime<Utc>,
    count: i32,
) -> Result<(), sqlx::Error> {
    for version in 0..count {
        sqlx::query(
            "INSERT INTO credential_history (
                owner_user_id, alias, action, actor_user_id, version, created_at
             )
             VALUES ($1, $2, 'register', $1, $3, $4)",
        )
        .bind(user_id)
        .bind(format!("history-{version}-{created_at}"))
        .bind(i64::from(version) + 1)
        .bind(created_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn seed_deleted_credentials(
    pool: &PgPool,
    user_id: Uuid,
    deleted_at: chrono::DateTime<Utc>,
    count: i32,
) -> Result<(), sqlx::Error> {
    for index in 0..count {
        sqlx::query(
            "INSERT INTO credentials (
                owner_user_id, category, provider, alias,
                http_origin, http_base_path,
                created_by, updated_by, deleted_by,
                deleted_at, secret_destroyed_at
             )
             VALUES (
                $1, 'http', 'test', $2,
                'https://example.test', '/',
                $1, $1, $1,
                $3, $3
             )",
        )
        .bind(user_id)
        .bind(format!("deleted-{index}-{deleted_at}"))
        .bind(deleted_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn count_rows(pool: &PgPool, table: &str) -> Result<i64, sqlx::Error> {
    let sql = format!("SELECT count(*) FROM {table}");
    sqlx::query_scalar(&sql).fetch_one(pool).await
}
