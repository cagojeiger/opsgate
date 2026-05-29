use std::fmt;
use std::future::Future;

use opsgate_core::Error;

use crate::{Caller, Channel, Role, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAttrs {
    pub sub: String,
    pub email: String,
    pub name: String,
}

pub trait UserStore: Clone + Send + Sync + 'static {
    fn upsert_by_sub(
        &self,
        sub: &str,
        email: &str,
        name: &str,
    ) -> impl Future<Output = opsgate_core::Result<User>> + Send;

    fn find_by_sub(
        &self,
        sub: &str,
    ) -> impl Future<Output = opsgate_core::Result<Option<User>>> + Send;
}

#[derive(Debug)]
pub enum IdentityError {
    NotAdmin,
    NotRegistered,
    Inactive,
    Store(Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAdmin => f.write_str("email not on admin allowlist"),
            Self::NotRegistered => f.write_str("user not registered"),
            Self::Inactive => f.write_str("user is inactive"),
            Self::Store(error) => write!(f, "identity store error: {error}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<Error> for IdentityError {
    fn from(error: Error) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug, Clone)]
pub struct Resolver<S> {
    users: S,
    admin_email: String,
}

impl<S> Resolver<S>
where
    S: UserStore,
{
    pub fn new(users: S, admin_email: impl Into<String>) -> Self {
        Self {
            users,
            admin_email: admin_email.into(),
        }
    }

    pub async fn resolve_browser(&self, attrs: ResolveAttrs) -> Result<Caller, IdentityError> {
        if attrs.email != self.admin_email {
            return Err(IdentityError::NotAdmin);
        }
        let user = self
            .users
            .upsert_by_sub(&attrs.sub, &attrs.email, &attrs.name)
            .await?;
        self.caller_for_user(user, Channel::Browser)
    }

    pub async fn resolve_api(&self, attrs: ResolveAttrs) -> Result<Caller, IdentityError> {
        self.resolve_registered(attrs, Channel::Api).await
    }

    pub async fn resolve_mcp(&self, attrs: ResolveAttrs) -> Result<Caller, IdentityError> {
        self.resolve_registered(attrs, Channel::Mcp).await
    }

    async fn resolve_registered(
        &self,
        attrs: ResolveAttrs,
        channel: Channel,
    ) -> Result<Caller, IdentityError> {
        let user = self
            .users
            .find_by_sub(&attrs.sub)
            .await?
            .ok_or(IdentityError::NotRegistered)?;
        self.caller_for_user(user, channel)
    }

    fn caller_for_user(&self, user: User, channel: Channel) -> Result<Caller, IdentityError> {
        if !user.is_active {
            return Err(IdentityError::Inactive);
        }
        let role = self.derive_role(&user);
        Ok(Caller {
            user,
            channel,
            role,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        })
    }

    fn derive_role(&self, user: &User) -> Role {
        if user.email == self.admin_email {
            Role::Admin
        } else {
            user.role
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryUsers {
        user: Arc<Mutex<Option<User>>>,
    }

    impl UserStore for MemoryUsers {
        async fn upsert_by_sub(
            &self,
            sub: &str,
            email: &str,
            name: &str,
        ) -> opsgate_core::Result<User> {
            let mut guard = self
                .user
                .lock()
                .map_err(|error| Error::internal(format!("test lock failed: {error}")))?;
            let existing = guard.take();
            let user = existing.map_or_else(
                || user(sub, email, name, Role::Viewer, true),
                |mut existing| {
                    existing.display_name = name.to_owned();
                    existing
                },
            );
            *guard = Some(user.clone());
            Ok(user)
        }

        async fn find_by_sub(&self, sub: &str) -> opsgate_core::Result<Option<User>> {
            let guard = self
                .user
                .lock()
                .map_err(|error| Error::internal(format!("test lock failed: {error}")))?;
            Ok(guard.as_ref().filter(|user| user.sub == sub).cloned())
        }
    }

    fn user(sub: &str, email: &str, name: &str, role: Role, is_active: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            sub: sub.to_owned(),
            email: email.to_owned(),
            display_name: name.to_owned(),
            role,
            is_active,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn api_requires_registered_active_user() {
        let resolver = Resolver::new(MemoryUsers::default(), "admin@example.test");
        let err = resolver
            .resolve_api(ResolveAttrs {
                sub: "missing".to_owned(),
                email: "user@example.test".to_owned(),
                name: "User".to_owned(),
            })
            .await
            .err();
        assert!(matches!(err, Some(IdentityError::NotRegistered)));
    }

    #[tokio::test]
    async fn inactive_user_rejected() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users
                .user
                .lock()
                .map_err(|error| Error::internal(format!("test lock failed: {error}")))?;
            *guard = Some(user("s1", "user@example.test", "User", Role::Viewer, false));
        }
        let resolver = Resolver::new(users, "admin@example.test");
        let err = resolver
            .resolve_mcp(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "user@example.test".to_owned(),
                name: "User".to_owned(),
            })
            .await
            .err();
        assert!(matches!(err, Some(IdentityError::Inactive)));
        Ok(())
    }

    #[tokio::test]
    async fn browser_login_upserts_authenticated_user() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        let resolver = Resolver::new(users.clone(), "admin@example.test");
        let caller = resolver
            .resolve_browser(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "admin@example.test".to_owned(),
                name: "Admin".to_owned(),
            })
            .await
            .map_err(Error::internal)?;
        assert_eq!(caller.user.email, "admin@example.test");
        assert_eq!(caller.channel, Channel::Browser);
        assert_eq!(caller.role, Role::Admin);
        Ok(())
    }

    #[tokio::test]
    async fn browser_login_rejects_non_admin_email() {
        let resolver = Resolver::new(MemoryUsers::default(), "admin@example.test");
        let err = resolver
            .resolve_browser(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "user@example.test".to_owned(),
                name: "User".to_owned(),
            })
            .await
            .err();
        assert!(matches!(err, Some(IdentityError::NotAdmin)));
    }

    #[tokio::test]
    async fn registered_user_resolves_for_api() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users
                .user
                .lock()
                .map_err(|error| Error::internal(format!("test lock failed: {error}")))?;
            *guard = Some(user(
                "s1",
                "operator@example.test",
                "Operator",
                Role::Operator,
                true,
            ));
        }
        let resolver = Resolver::new(users, "admin@example.test");
        let caller = resolver
            .resolve_api(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "ignored@example.test".to_owned(),
                name: "Ignored".to_owned(),
            })
            .await
            .map_err(Error::internal)?;
        assert_eq!(caller.channel, Channel::Api);
        assert_eq!(caller.role, Role::Operator);
        Ok(())
    }

    #[tokio::test]
    async fn admin_email_overrides_stored_role_for_api() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users
                .user
                .lock()
                .map_err(|error| Error::internal(format!("test lock failed: {error}")))?;
            *guard = Some(user(
                "s1",
                "admin@example.test",
                "Admin",
                Role::Viewer,
                true,
            ));
        }
        let resolver = Resolver::new(users, "admin@example.test");
        let caller = resolver
            .resolve_api(ResolveAttrs {
                sub: "s1".to_owned(),
                email: String::new(),
                name: String::new(),
            })
            .await
            .map_err(Error::internal)?;
        assert_eq!(caller.role, Role::Admin);
        Ok(())
    }
}
