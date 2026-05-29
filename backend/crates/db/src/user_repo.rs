use chrono::{DateTime, Utc};
use opsgate_core::{Error, Result};
use opsgate_domain::{Role, User, UserStore};
use sqlx::FromRow;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserRepo {
    pool: PgPool,
}

impl UserRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, FromRow)]
struct UserRow {
    id: Uuid,
    sub: String,
    email: String,
    display_name: String,
    role: String,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    fn into_user(self) -> Result<User> {
        let role = Role::from_db(&self.role)
            .ok_or_else(|| Error::internal(format!("unknown user role {:?}", self.role)))?;
        Ok(User {
            id: self.id,
            sub: self.sub,
            email: self.email,
            display_name: self.display_name,
            role,
            is_active: self.is_active,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl UserStore for UserRepo {
    async fn upsert_by_sub(&self, sub: &str, email: &str, name: &str) -> Result<User> {
        let user = sqlx::query_as::<_, UserRow>(
            r#"
            INSERT INTO users (sub, email, display_name)
            VALUES ($1, $2, $3)
            ON CONFLICT (sub) DO UPDATE
                SET display_name = EXCLUDED.display_name,
                    updated_at = now()
            RETURNING id, sub, email, display_name, role, is_active, created_at, updated_at
            "#,
        )
        .bind(sub)
        .bind(email)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?
        .into_user()?;
        Ok(user)
    }

    async fn find_by_sub(&self, sub: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, sub, email, display_name, role, is_active, created_at, updated_at
            FROM users
            WHERE sub = $1
            "#,
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        row.map(UserRow::into_user).transpose()
    }
}

fn map_sqlx_error(error: sqlx::Error) -> Error {
    Error::internal(format!("user repository query failed: {error}"))
}
