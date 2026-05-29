use opsgate_domain::Caller;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
pub struct MeOutput {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub name: String,
}

pub fn build_me(caller: &Caller) -> MeOutput {
    MeOutput {
        id: caller.user.id.to_string(),
        sub: caller.user.sub.clone(),
        email: caller.user.email.clone(),
        name: caller.user.display_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::{Caller, Channel, User};
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
        };
        let out = build_me(&caller);
        assert_eq!(out.id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(out.sub, "sub-1");
        assert_eq!(out.email, "user@example.test");
        assert_eq!(out.name, "Test User");
    }
}
