use std::str::FromStr;

use opsgate_db::{CredentialAuditAction, CredentialAuditParams, CredentialRepo};
use opsgate_domain::credential::{
    CredentialCategory, CredentialListParams, CredentialPolicy, InsertCredentialParams,
    UpdateCredentialParams,
};
use serde_json::Value;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgPool, Row};
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
    include_str!("../migrations/0012_credential_audit_request_metadata.sql"),
];

struct TestDb {
    database_url: String,
    schema: String,
    pool: PgPool,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditMetadataRow {
    actor_role: Option<String>,
    actor_ip: Option<String>,
    actor_user_agent: Option<String>,
    request_id: Option<String>,
    channel: Option<String>,
}

#[tokio::test]
async fn list_credentials_searches_go_visible_fields_and_keeps_owner_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let owner = insert_user(&db.pool, "owner@example.test").await?;
    let other_owner = insert_user(&db.pool, "other@example.test").await?;
    seed_credential(
        &db.pool,
        SeedCredential {
            owner,
            alias: "alpha-api",
            category: "http",
            provider: "k8s",
            env: "prod",
            tags: &["cluster"],
            description: "",
        },
    )
    .await?;
    seed_credential(
        &db.pool,
        SeedCredential {
            owner,
            alias: "beta-db",
            category: "sql",
            provider: "postgres",
            env: "stage",
            tags: &["warehouse"],
            description: "",
        },
    )
    .await?;
    seed_credential(
        &db.pool,
        SeedCredential {
            owner: other_owner,
            alias: "other-only",
            category: "http",
            provider: "stripe",
            env: "prod",
            tags: &["otheronly"],
            description: "otheronly",
        },
    )
    .await?;

    let repo = CredentialRepo::new(db.pool.clone());
    assert_aliases(&repo, owner, "sql", &["beta-db"]).await?;
    assert_aliases(&repo, owner, "postgres", &["beta-db"]).await?;
    assert_aliases(&repo, owner, "stage", &["beta-db"]).await?;
    assert_aliases(&repo, owner, "warehouse", &["beta-db"]).await?;
    assert_aliases(&repo, owner, "otheronly", &[]).await?;

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn credential_mutations_write_actor_columns_and_history_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let owner = insert_user(&db.pool, "owner@example.test").await?;
    let repo = CredentialRepo::new(db.pool.clone());

    repo.insert_credential(
        insert_params(owner, "prod-api"),
        audit(owner, CredentialAuditAction::Register),
    )
    .await?;
    repo.update_credential_mutable_fields(
        UpdateCredentialParams {
            owner_user_id: owner,
            actor_user_id: owner,
            alias: "prod-api".to_owned(),
            category: CredentialCategory::Http,
            description: None,
            env: Some("stage".to_owned()),
            tags: None,
            policy: None,
        },
        CredentialAuditParams {
            actor_user_id: owner,
            actor_role: Some("admin".to_owned()),
            actor_ip: Some("203.0.113.20".to_owned()),
            actor_user_agent: Some("opsgate-test".to_owned()),
            request_id: Some("req-update".to_owned()),
            channel: Some("mcp".to_owned()),
            action: CredentialAuditAction::Update,
            reason: Some("Rotate safely".to_owned()),
            changed_fields: vec!["env".to_owned()],
            detail: serde_json::json!({"changed_fields": ["env"]}),
        },
    )
    .await?;
    repo.soft_delete_credential(
        owner,
        "prod-api",
        owner,
        CredentialAuditParams {
            actor_user_id: owner,
            actor_role: Some("admin".to_owned()),
            actor_ip: Some("203.0.113.20".to_owned()),
            actor_user_agent: Some("opsgate-test".to_owned()),
            request_id: Some("req-delete".to_owned()),
            channel: Some("mcp".to_owned()),
            action: CredentialAuditAction::Delete,
            reason: Some("Retire safely".to_owned()),
            changed_fields: Vec::new(),
            detail: serde_json::json!({"secret_destroyed": true}),
        },
    )
    .await?;

    let actor_columns: (Uuid, Uuid, Option<Uuid>, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT created_by, updated_by, deleted_by, secret_ciphertext, secret_destroyed_at IS NOT NULL \
         FROM credentials WHERE owner_user_id = $1 AND alias = 'prod-api'",
    )
    .bind(owner)
    .fetch_one(&db.pool)
    .await?;
    assert_eq!(actor_columns.0, owner);
    assert_eq!(actor_columns.1, owner);
    assert_eq!(actor_columns.2, Some(owner));
    assert_eq!(actor_columns.3, None);
    assert!(actor_columns.4);

    let history = history_rows(&db.pool, owner, "prod-api").await?;
    assert_eq!(
        history
            .iter()
            .map(|(action, version, _detail)| (action.as_str(), *version))
            .collect::<Vec<_>>(),
        [("register", 1), ("update", 2), ("delete", 3)]
    );
    let history_json = serde_json::to_string(&history)?;
    assert!(!history_json.contains("api.example.test"));
    assert!(!history_json.contains("secret-token"));
    assert!(history_json.contains("Rotate safely"));
    assert!(history_json.contains("Retire safely"));

    let audit_metadata: Vec<AuditMetadataRow> = sqlx::query_as(
        "SELECT actor_role, actor_ip, actor_user_agent, request_id, channel \
             FROM credential_audit_events \
             WHERE owner_user_id = $1 AND alias = 'prod-api' \
             ORDER BY created_at, id",
    )
    .bind(owner)
    .fetch_all(&db.pool)
    .await?;
    let [register, update, delete] = audit_metadata.as_slice() else {
        return Err(format!("expected 3 credential audit rows, got {audit_metadata:?}").into());
    };
    assert_eq!(register.actor_role.as_deref(), Some("admin"));
    assert_eq!(register.actor_ip.as_deref(), Some("203.0.113.20"));
    assert_eq!(register.actor_user_agent.as_deref(), Some("opsgate-test"));
    assert_eq!(register.request_id.as_deref(), Some("req-credential"));
    assert_eq!(register.channel.as_deref(), Some("mcp"));
    assert_eq!(update.request_id.as_deref(), Some("req-update"));
    assert_eq!(delete.request_id.as_deref(), Some("req-delete"));

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn credential_history_versions_are_per_owner_alias() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let owner_one = insert_user(&db.pool, "owner-one@example.test").await?;
    let owner_two = insert_user(&db.pool, "owner-two@example.test").await?;
    let repo = CredentialRepo::new(db.pool.clone());
    repo.insert_credential(
        insert_params(owner_one, "shared-api"),
        audit(owner_one, CredentialAuditAction::Register),
    )
    .await?;
    repo.insert_credential(
        insert_params(owner_two, "shared-api"),
        audit(owner_two, CredentialAuditAction::Register),
    )
    .await?;

    let owner_one_history = history_rows(&db.pool, owner_one, "shared-api").await?;
    let owner_two_history = history_rows(&db.pool, owner_two, "shared-api").await?;
    assert_eq!(
        owner_one_history
            .first()
            .map(|(_action, version, _detail)| *version),
        Some(1)
    );
    assert_eq!(
        owner_two_history
            .first()
            .map(|(_action, version, _detail)| *version),
        Some(1)
    );

    db.cleanup().await;
    Ok(())
}

#[tokio::test]
async fn duplicate_alias_maps_to_validation_error() -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = TestDb::setup().await? else {
        return Ok(());
    };

    let owner = insert_user(&db.pool, "owner@example.test").await?;
    let repo = CredentialRepo::new(db.pool.clone());
    repo.insert_credential(
        insert_params(owner, "prod-api"),
        audit(owner, CredentialAuditAction::Register),
    )
    .await?;
    let err = repo
        .insert_credential(
            insert_params(owner, "prod-api"),
            audit(owner, CredentialAuditAction::Register),
        )
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();

    assert!(err.contains("invalid input"));
    assert!(err.contains("already registered"));

    db.cleanup().await;
    Ok(())
}

impl TestDb {
    async fn setup() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let database_url = match std::env::var("OPSGATE_TEST_DATABASE_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                eprintln!(
                    "skipping Postgres credential repo tests; set OPSGATE_TEST_DATABASE_URL to run them"
                );
                return Ok(None);
            }
        };
        let schema = format!("opsgate_credential_repo_{}", Uuid::new_v4().simple());
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
        let mut admin = match sqlx::PgConnection::connect(&self.database_url).await {
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
            .execute(&mut admin)
            .await;
        if let Err(err) = cleanup {
            eprintln!("failed to drop temporary schema {}: {err}", self.schema);
        }
    }
}

async fn insert_user(pool: &PgPool, email: &str) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO users (email, sub, display_name) \
         VALUES ($1, $2, 'Test User') \
         RETURNING id",
    )
    .bind(email)
    .bind(format!("sub-{email}"))
    .fetch_one(pool)
    .await
}

struct SeedCredential<'a> {
    owner: Uuid,
    alias: &'a str,
    category: &'a str,
    provider: &'a str,
    env: &'a str,
    tags: &'a [&'a str],
    description: &'a str,
}

async fn seed_credential(pool: &PgPool, credential: SeedCredential<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO credentials \
         (owner_user_id, created_by, updated_by, category, provider, alias, endpoint, secret_ciphertext, description, env, tags, policy) \
         VALUES ($1, $1, $1, $2, $3, $4, 'https://seed.example.test', $5, $6, $7, $8, '{}'::jsonb)",
    )
    .bind(credential.owner)
    .bind(credential.category)
    .bind(credential.provider)
    .bind(credential.alias)
    .bind(vec![1_u8, 2, 3])
    .bind(credential.description)
    .bind(credential.env)
    .bind(
        credential
            .tags
            .iter()
            .map(|tag| (*tag).to_owned())
            .collect::<Vec<_>>(),
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn assert_aliases(
    repo: &CredentialRepo,
    owner: Uuid,
    q: &str,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let rows = repo
        .list_credentials(CredentialListParams {
            owner_user_id: owner,
            q: Some(q.to_owned()),
            limit: 50,
            ..CredentialListParams::default()
        })
        .await?;
    let aliases = rows
        .into_iter()
        .map(|credential| credential.alias)
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|alias| (*alias).to_owned())
        .collect::<Vec<_>>();
    assert_eq!(aliases, expected);
    Ok(())
}

fn insert_params(owner: Uuid, alias: &str) -> InsertCredentialParams {
    InsertCredentialParams {
        owner_user_id: owner,
        actor_user_id: owner,
        category: CredentialCategory::Http,
        provider: "k8s".to_owned(),
        alias: alias.to_owned(),
        endpoint: "https://api.example.test".to_owned(),
        secret_ciphertext: b"secret-token".to_vec(),
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
        actor_role: Some("admin".to_owned()),
        actor_ip: Some("203.0.113.20".to_owned()),
        actor_user_agent: Some("opsgate-test".to_owned()),
        request_id: Some("req-credential".to_owned()),
        channel: Some("mcp".to_owned()),
        action,
        reason: None,
        changed_fields: Vec::new(),
        detail: serde_json::json!({}),
    }
}

async fn history_rows(
    pool: &PgPool,
    owner: Uuid,
    alias: &str,
) -> Result<Vec<(String, i64, Value)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT action, version, detail \
         FROM credential_history \
         WHERE owner_user_id = $1 AND alias = $2 \
         ORDER BY version",
    )
    .bind(owner)
    .bind(alias)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get("action"), row.get("version"), row.get("detail")))
        .collect())
}
