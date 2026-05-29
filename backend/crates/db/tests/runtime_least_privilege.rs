use std::str::FromStr;

use opsgate_db::{
    ApiCallHistoryParams, ApiCallHistoryRepo, AuditLogParams, AuditRepo, CredentialAuditAction,
    CredentialAuditParams, CredentialRepo, SqlQueryHistoryParams, SqlQueryHistoryRepo, UserRepo,
};
use opsgate_domain::UserStore;
use opsgate_domain::credential::{
    CredentialCategory, CredentialPolicy, InsertCredentialParams, UpdateCredentialParams,
};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

const MIGRATIONS: [&str; 11] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_users_oauth.sql"),
    include_str!("../migrations/0003_credentials.sql"),
    include_str!("../migrations/0004_credentials_delete_secret.sql"),
    include_str!("../migrations/0005_credential_audit_events.sql"),
    include_str!("../migrations/0006_api_call_history.sql"),
    include_str!("../migrations/0007_audit_logs.sql"),
    include_str!("../migrations/0008_sql_query_history.sql"),
    include_str!("../migrations/0009_identity_roles.sql"),
    include_str!("../migrations/0010_credential_lifecycle_history.sql"),
    include_str!("../migrations/0011_runtime_least_privilege.sql"),
];

struct TestDb {
    owner_url: String,
    schema: String,
    owner_pool: PgPool,
    runtime_pool: PgPool,
}

#[tokio::test]
async fn opsgate_app_can_run_normal_runtime_operations() -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let user_repo = UserRepo::new(db.runtime_pool.clone());
    let user = user_repo
        .upsert_by_sub("runtime-sub", "runtime@example.test", "Runtime User")
        .await?;
    let found = user_repo.find_by_sub("runtime-sub").await?;
    assert_eq!(found.map(|user| user.id), Some(user.id));

    let credential_repo = CredentialRepo::new(db.runtime_pool.clone());
    let credential = credential_repo
        .insert_credential(
            insert_params(user.id, "runtime-api"),
            audit(user.id, CredentialAuditAction::Register),
        )
        .await?;
    let updated = credential_repo
        .update_credential_mutable_fields(
            UpdateCredentialParams {
                owner_user_id: user.id,
                actor_user_id: user.id,
                alias: credential.alias.clone(),
                category: CredentialCategory::Http,
                description: Some("runtime updated".to_owned()),
                env: None,
                tags: None,
                policy: None,
            },
            CredentialAuditParams {
                actor_user_id: user.id,
                action: CredentialAuditAction::Update,
                reason: Some("Update runtime credential safely".to_owned()),
                changed_fields: vec!["description".to_owned()],
                detail: json!({"changed_fields": ["description"]}),
            },
        )
        .await?;
    assert_eq!(updated.description, "runtime updated");

    ApiCallHistoryRepo::new(db.runtime_pool.clone())
        .insert(api_history(user.id, credential.id))
        .await?;
    SqlQueryHistoryRepo::new(db.runtime_pool.clone())
        .insert(sql_history(user.id, credential.id))
        .await?;
    AuditRepo::new(db.runtime_pool.clone())
        .append(audit_log(user.id))
        .await?;

    credential_repo
        .soft_delete_credential(
            user.id,
            &credential.alias,
            user.id,
            CredentialAuditParams {
                actor_user_id: user.id,
                action: CredentialAuditAction::Delete,
                reason: Some("Retire runtime credential safely".to_owned()),
                changed_fields: Vec::new(),
                detail: json!({"secret_destroyed": true}),
            },
        )
        .await?;

    let history_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_history WHERE owner_user_id = $1 AND alias = 'runtime-api'",
    )
    .bind(user.id)
    .fetch_one(&db.owner_pool)
    .await?;
    assert_eq!(history_count, 3);

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn opsgate_app_cannot_modify_schema_or_protected_user_role()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (sub, email, display_name) \
         VALUES ('protected-sub', 'protected@example.test', 'Protected') \
         RETURNING id",
    )
    .fetch_one(&db.owner_pool)
    .await?;

    let create_table = sqlx::query("CREATE TABLE denied_table(id int)")
        .execute(&db.runtime_pool)
        .await;
    assert!(create_table.is_err());

    let alter_table = sqlx::query("ALTER TABLE users ADD COLUMN denied_column TEXT")
        .execute(&db.runtime_pool)
        .await;
    assert!(alter_table.is_err());

    let update_role = sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
        .bind(user_id)
        .execute(&db.runtime_pool)
        .await;
    assert!(update_role.is_err());

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.owner_pool)
        .await?;
    assert_eq!(role, "viewer");

    db.cleanup().await;
    Ok(())
}

impl TestDb {
    async fn setup() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let owner_url = match std::env::var("OPSGATE_TEST_DATABASE_MIGRATE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping runtime least-privilege tests; set OPSGATE_TEST_DATABASE_MIGRATE_URL and OPSGATE_TEST_DATABASE_URL"
                );
                return Ok(None);
            }
        };
        let runtime_url = match std::env::var("OPSGATE_TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping runtime least-privilege tests; set OPSGATE_TEST_DATABASE_MIGRATE_URL and OPSGATE_TEST_DATABASE_URL"
                );
                return Ok(None);
            }
        };

        let schema = format!("opsgate_runtime_lp_{}", Uuid::new_v4().simple());
        let mut owner_conn = PgConnection::connect(&owner_url).await?;
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut owner_conn)
            .await?;

        let owner_pool = connect_with_schema(&owner_url, &schema).await?;
        for migration in MIGRATIONS {
            sqlx::raw_sql(migration).execute(&owner_pool).await?;
        }

        let role_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsgate_app')",
        )
        .fetch_one(&owner_pool)
        .await?;
        assert!(role_exists);

        let runtime_pool = connect_with_schema(&runtime_url, &schema).await?;
        Ok(Some(Self {
            owner_url,
            schema,
            owner_pool,
            runtime_pool,
        }))
    }

    async fn cleanup(self) {
        self.runtime_pool.close().await;
        self.owner_pool.close().await;
        let mut owner_conn = match PgConnection::connect(&self.owner_url).await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!(
                    "failed to connect for schema cleanup {}: {err}",
                    self.schema
                );
                return;
            }
        };
        let cleanup = sqlx::query(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
            .execute(&mut owner_conn)
            .await;
        if let Err(err) = cleanup {
            eprintln!("failed to drop temporary schema {}: {err}", self.schema);
        }
    }
}

async fn connect_with_schema(
    database_url: &str,
    schema: &str,
) -> Result<PgPool, Box<dyn std::error::Error>> {
    let options = PgConnectOptions::from_str(database_url)?.options([("search_path", schema)]);
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?)
}

fn insert_params(owner_user_id: Uuid, alias: &str) -> InsertCredentialParams {
    InsertCredentialParams {
        owner_user_id,
        actor_user_id: owner_user_id,
        category: CredentialCategory::Http,
        provider: "k8s".to_owned(),
        alias: alias.to_owned(),
        endpoint: "https://api.example.test".to_owned(),
        secret_ciphertext: b"sealed-secret-token".to_vec(),
        description: String::new(),
        env: "prod".to_owned(),
        tags: vec!["prod".to_owned()],
        policy: CredentialPolicy::default(),
        allow_private_network: false,
        tls_ca: None,
    }
}

fn audit(actor_user_id: Uuid, action: CredentialAuditAction) -> CredentialAuditParams {
    CredentialAuditParams {
        actor_user_id,
        action,
        reason: None,
        changed_fields: Vec::new(),
        detail: json!({}),
    }
}

fn api_history(user_id: Uuid, credential_id: Uuid) -> ApiCallHistoryParams {
    ApiCallHistoryParams {
        owner_user_id: Some(user_id),
        actor_user_id: Some(user_id),
        actor_role: Some("admin".to_owned()),
        channel: "api".to_owned(),
        request_id: Some("req-api".to_owned()),
        credential_id: Some(credential_id),
        credential_alias: "runtime-api".to_owned(),
        credential_category: "http".to_owned(),
        credential_provider: "k8s".to_owned(),
        credential_env: "prod".to_owned(),
        method: "GET".to_owned(),
        path: "/api/v1/pods".to_owned(),
        query_keys: json!(["limit"]),
        request_header_keys: json!(["Accept"]),
        projection_keys: json!([]),
        max_bytes: 4096,
        purpose: Some("Runtime least privilege api history".to_owned()),
        outcome: "ok".to_owned(),
        status_code: Some(200),
        latency_ms: Some(12),
        original_bytes: Some(128),
        returned_bytes: Some(64),
        truncated: false,
        error_kind: None,
        error_message_safe: None,
    }
}

fn sql_history(user_id: Uuid, credential_id: Uuid) -> SqlQueryHistoryParams {
    SqlQueryHistoryParams {
        owner_user_id: Some(user_id),
        actor_user_id: Some(user_id),
        actor_role: Some("admin".to_owned()),
        channel: "api".to_owned(),
        request_id: Some("req-sql".to_owned()),
        credential_id: Some(credential_id),
        credential_alias: "runtime-api".to_owned(),
        credential_category: "sql".to_owned(),
        credential_provider: "postgres".to_owned(),
        credential_env: "prod".to_owned(),
        query_sha256: "0".repeat(64),
        params_count: 0,
        shape: "rows".to_owned(),
        max_rows: 5,
        max_bytes: 4096,
        timeout_ms: 5000,
        purpose: Some("Runtime least privilege sql history".to_owned()),
        outcome: "ok".to_owned(),
        latency_ms: Some(10),
        row_count: Some(1),
        returned_bytes: Some(8),
        truncated: false,
        result_columns: json!(["n"]),
        error_kind: None,
        error_message_safe: None,
    }
}

fn audit_log(user_id: Uuid) -> AuditLogParams {
    AuditLogParams {
        action: "runtime.least_privilege".to_owned(),
        channel: "api".to_owned(),
        outcome: "ok".to_owned(),
        severity: "info".to_owned(),
        actor_user_id: Some(user_id),
        actor_role: Some("admin".to_owned()),
        actor_ip: Some("127.0.0.1".to_owned()),
        actor_user_agent: Some("least-privilege-test".to_owned()),
        target_type: Some("service".to_owned()),
        target_id: None,
        target_key: Some("opsgate".to_owned()),
        request_id: Some("req-audit".to_owned()),
        purpose: None,
        detail: json!({"ok": true}),
    }
}
