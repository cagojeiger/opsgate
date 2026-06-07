use axum::extract::Extension;
use axum::routing::get;
use axum::{Json, Router};
use opsgate_model::Caller;
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub(crate) struct MeResponse {
    pub(crate) id: String,
    pub(crate) sub: String,
    pub(crate) email: String,
    pub(crate) name: String,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/me", get(get_me))
}

async fn get_me(Extension(caller): Extension<Caller>) -> Json<MeResponse> {
    Json(build_me(&caller))
}

fn build_me(caller: &Caller) -> MeResponse {
    MeResponse {
        id: caller.user.id.to_string(),
        sub: caller.user.sub.clone(),
        email: caller.user.email.clone(),
        name: caller.user.display_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_model::{Caller, Channel, User};
    use uuid::Uuid;

    use super::build_me;

    #[test]
    fn build_me_uses_exact_identity_shape() {
        let now = Utc::now();
        let user = User {
            id: Uuid::nil(),
            sub: "sub-1".to_owned(),
            email: "user@example.test".to_owned(),
            display_name: "Test User".to_owned(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let caller = Caller {
            user,
            channel: Channel::Api,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        };
        let out = build_me(&caller);
        assert_eq!(out.id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(out.sub, "sub-1");
        assert_eq!(out.email, "user@example.test");
        assert_eq!(out.name, "Test User");
    }
}
