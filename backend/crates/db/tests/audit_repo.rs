use std::str::FromStr;

use opsgate_db::{AuditLogParams, AuditRepo};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgPool, Row};
use uuid::Uuid;

const MIGRATIONS: [&str; 2] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0007_audit_logs.sql"),
];

struct TestDb {
    database_url: String,
    schema: String,
    pool: PgPool,
}

#[tokio::test]
async fn append_persists_auth_denial_request_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    AuditRepo::new(db.pool.clone())
        .append(AuditLogParams {
            action: "mcp.auth.denied".to_owned(),
            channel: "mcp".to_owned(),
            outcome: "denied".to_owned(),
            severity: "warning".to_owned(),
            actor_user_id: None,
            actor_ip: Some("203.0.113.40".to_owned()),
            actor_user_agent: Some("opsgate-test".to_owned()),
            target_type: Some("identity".to_owned()),
            target_id: None,
            target_key: Some("sub-1".to_owned()),
            request_id: Some("req-auth".to_owned()),
            purpose: None,
            detail: serde_json::json!({
                "schema_version": 1,
                "denial_reason": "not_registered"
            }),
        })
        .await?;

    let row = sqlx::query(
        "SELECT action, channel, outcome, actor_ip, actor_user_agent, request_id, detail \
         FROM audit_logs WHERE action = 'mcp.auth.denied'",
    )
    .fetch_one(&db.pool)
    .await?;
    assert_eq!(row.try_get::<String, _>("action")?, "mcp.auth.denied");
    assert_eq!(row.try_get::<String, _>("channel")?, "mcp");
    assert_eq!(row.try_get::<String, _>("outcome")?, "denied");
    assert_eq!(row.try_get::<String, _>("actor_ip")?, "203.0.113.40");
    assert_eq!(
        row.try_get::<String, _>("actor_user_agent")?,
        "opsgate-test"
    );
    assert_eq!(row.try_get::<String, _>("request_id")?, "req-auth");
    let detail = row.try_get::<Value, _>("detail")?;
    assert_eq!(
        detail.get("denial_reason"),
        Some(&serde_json::json!("not_registered"))
    );

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn append_persists_browser_signup_denial_without_secret_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    AuditRepo::new(db.pool.clone())
        .append(AuditLogParams {
            action: "browser.signup".to_owned(),
            channel: "browser".to_owned(),
            outcome: "denied".to_owned(),
            severity: "warning".to_owned(),
            actor_user_id: None,
            actor_ip: Some("203.0.113.41".to_owned()),
            actor_user_agent: Some("opsgate-test".to_owned()),
            target_type: Some("identity".to_owned()),
            target_id: None,
            target_key: Some("sub-2".to_owned()),
            request_id: Some("req-browser".to_owned()),
            purpose: None,
            detail: serde_json::json!({
                "schema_version": 1,
                "denial_reason": "not_admin",
                "sub": "sub-2",
                "email": "not-admin@example.test"
            }),
        })
        .await?;

    let detail: Value =
        sqlx::query_scalar("SELECT detail FROM audit_logs WHERE action = 'browser.signup'")
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(detail.get("sub"), Some(&serde_json::json!("sub-2")));
    assert_eq!(
        detail.get("email"),
        Some(&serde_json::json!("not-admin@example.test"))
    );
    let serialized = detail.to_string();
    assert!(!serialized.contains("token"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("body"));

    db.cleanup().await;
    Ok(())
}

impl TestDb {
    async fn setup() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let database_url = match std::env::var("OPSGATE_TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping Postgres audit repo tests; set OPSGATE_TEST_DATABASE_URL to run them"
                );
                return Ok(None);
            }
        };
        let schema = format!("opsgate_audit_repo_{}", Uuid::new_v4().simple());
        let mut admin = sqlx::PgConnection::connect(&database_url).await?;
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut admin)
            .await?;

        let options =
            PgConnectOptions::from_str(&database_url)?.options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(1)
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
