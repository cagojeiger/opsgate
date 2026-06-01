use std::fmt;
use std::future::Future;

use opsgate_core::Error;

use crate::{Caller, Channel, User};

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
    NotRegistered,
    Inactive,
    Store(Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
}

impl<S> Resolver<S>
where
    S: UserStore,
{
    pub fn new(users: S) -> Self {
        Self { users }
    }

    pub async fn resolve_browser(&self, attrs: ResolveAttrs) -> Result<Caller, IdentityError> {
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
        Ok(Caller {
            user,
            channel,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        })
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
            let mut guard = self.user.lock().map_err(|_| Error::internal("poisoned"))?;
            let user = guard
                .clone()
                .unwrap_or_else(|| user(sub, email, name, true));
            *guard = Some(user.clone());
            Ok(user)
        }

        async fn find_by_sub(&self, sub: &str) -> opsgate_core::Result<Option<User>> {
            let guard = self.user.lock().map_err(|_| Error::internal("poisoned"))?;
            Ok(guard.clone().filter(|user| user.sub == sub))
        }
    }

    fn attrs() -> ResolveAttrs {
        ResolveAttrs {
            sub: "s1".to_owned(),
            email: "user@example.test".to_owned(),
            name: "User".to_owned(),
        }
    }

    fn user(sub: &str, email: &str, name: &str, is_active: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            sub: sub.to_owned(),
            email: email.to_owned(),
            display_name: name.to_owned(),
            is_active,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn browser_login_upserts_authenticated_user() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        let resolver = Resolver::new(users.clone());

        let caller = resolver
            .resolve_browser(attrs())
            .await
            .map_err(|error| Error::internal(error.to_string()))?;

        assert_eq!(caller.channel, Channel::Browser);
        assert_eq!(caller.user.sub, "s1");
        assert!(users.find_by_sub("s1").await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn inactive_user_rejected() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users.user.lock().map_err(|_| Error::internal("poisoned"))?;
            *guard = Some(user("s1", "user@example.test", "User", false));
        }
        let resolver = Resolver::new(users);

        let err = resolver.resolve_mcp(attrs()).await.err();

        assert!(matches!(err, Some(IdentityError::Inactive)));
        Ok(())
    }

    #[tokio::test]
    async fn api_requires_registered_active_user() {
        let resolver = Resolver::new(MemoryUsers::default());

        let err = resolver.resolve_api(attrs()).await.err();

        assert!(matches!(err, Some(IdentityError::NotRegistered)));
    }

    #[tokio::test]
    async fn registered_user_resolves_for_api() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users.user.lock().map_err(|_| Error::internal("poisoned"))?;
            *guard = Some(user("s1", "user@example.test", "User", true));
        }
        let resolver = Resolver::new(users);

        let caller = resolver
            .resolve_api(attrs())
            .await
            .map_err(|error| Error::internal(error.to_string()))?;

        assert_eq!(caller.channel, Channel::Api);
        assert_eq!(caller.user.email, "user@example.test");
        Ok(())
    }
}
