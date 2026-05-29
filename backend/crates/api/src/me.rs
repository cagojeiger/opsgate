use opsgate_domain::Caller;
use schemars::JsonSchema;
use serde::Serialize;

use crate::auth::bearer::AuthenticatedCaller;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct MeOutput {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub is_admin: bool,
}

pub fn build_me(caller: &Caller, admin_email: &str) -> MeOutput {
    MeOutput {
        id: caller.user.id.to_string(),
        sub: caller.user.sub.clone(),
        email: caller.user.email.clone(),
        name: caller.user.display_name.clone(),
        role: caller.role.as_str().to_owned(),
        is_admin: caller.user.email == admin_email,
    }
}

pub async fn me(
    AuthenticatedCaller(caller): AuthenticatedCaller,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<MeOutput> {
    axum::Json(build_me(&caller, &state.config.admin_email))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::{Caller, Channel, Role, User};
    use uuid::Uuid;

    use super::build_me;

    #[test]
    fn build_me_uses_exact_identity_shape() {
        let now = Utc::now();
        let user = User {
            id: Uuid::nil(),
            sub: "sub-1".to_owned(),
            email: "admin@example.test".to_owned(),
            display_name: "Admin User".to_owned(),
            role: Role::Viewer,
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let caller = Caller {
            user,
            channel: Channel::Api,
            role: Role::Admin,
        };
        let out = build_me(&caller, "admin@example.test");
        assert_eq!(out.id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(out.name, "Admin User");
        assert_eq!(out.role, "admin");
        assert!(out.is_admin);
    }
}
