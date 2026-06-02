use std::fmt;
use std::future::Future;
use std::sync::Arc;

use opsgate_core::{Error, Result as CoreResult};
use regex::Regex;

use crate::{Caller, Channel, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAttrs {
    pub sub: String,
    pub email: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BrowserSignupPolicy {
    allow_all: bool,
    allowed_email_patterns: Arc<[Regex]>,
}

impl BrowserSignupPolicy {
    pub fn from_patterns(patterns: &[String]) -> CoreResult<Self> {
        let allow_all = patterns.iter().any(|pattern| pattern == "*");
        patterns
            .iter()
            .enumerate()
            .filter(|(_index, pattern)| pattern.as_str() != "*")
            .map(|(index, pattern)| {
                if pattern.is_empty() {
                    return Err(Error::validation(format!(
                        "empty signup allowed email regex at index {index}"
                    )));
                }
                let anchored = format!("^(?:{pattern})$");
                Regex::new(&anchored).map_err(|_error| {
                    Error::validation(format!(
                        "invalid signup allowed email regex at index {index}"
                    ))
                })
            })
            .collect::<CoreResult<Vec<_>>>()
            .map(|patterns| Self {
                allow_all,
                allowed_email_patterns: Arc::from(patterns.into_boxed_slice()),
            })
    }

    pub fn allows(&self, email: &str) -> bool {
        !email.is_empty()
            && (self.allow_all
                || self
                    .allowed_email_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(email)))
    }
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
    SignupNotAllowed,
    Inactive,
    Store(Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegistered => f.write_str("user not registered"),
            Self::SignupNotAllowed => f.write_str("signup is not allowed for this email"),
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
    browser_signup: BrowserSignupPolicy,
}

impl<S> Resolver<S>
where
    S: UserStore,
{
    pub fn new(users: S, browser_signup: BrowserSignupPolicy) -> Self {
        Self {
            users,
            browser_signup,
        }
    }

    pub async fn resolve_browser(
        &self,
        attrs: ResolveAttrs,
    ) -> std::result::Result<Caller, IdentityError> {
        let registered = self.users.find_by_sub(&attrs.sub).await?.is_some();
        if !registered && !self.browser_signup.allows(&attrs.email) {
            return Err(IdentityError::SignupNotAllowed);
        }

        let user = self
            .users
            .upsert_by_sub(&attrs.sub, &attrs.email, &attrs.name)
            .await?;
        self.caller_for_user(user, Channel::Browser)
    }

    pub async fn resolve_api(
        &self,
        attrs: ResolveAttrs,
    ) -> std::result::Result<Caller, IdentityError> {
        self.resolve_registered(attrs, Channel::Api).await
    }

    pub async fn resolve_mcp(
        &self,
        attrs: ResolveAttrs,
    ) -> std::result::Result<Caller, IdentityError> {
        self.resolve_registered(attrs, Channel::Mcp).await
    }

    async fn resolve_registered(
        &self,
        attrs: ResolveAttrs,
        channel: Channel,
    ) -> std::result::Result<Caller, IdentityError> {
        let user = self
            .users
            .find_by_sub(&attrs.sub)
            .await?
            .ok_or(IdentityError::NotRegistered)?;
        self.caller_for_user(user, channel)
    }

    fn caller_for_user(
        &self,
        user: User,
        channel: Channel,
    ) -> std::result::Result<Caller, IdentityError> {
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
            let mut user = guard
                .clone()
                .unwrap_or_else(|| user(sub, email, name, true));
            user.display_name = name.to_owned();
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

    fn allow_no_signup() -> CoreResult<BrowserSignupPolicy> {
        BrowserSignupPolicy::from_patterns(&[])
    }

    fn allow_example_signup() -> CoreResult<BrowserSignupPolicy> {
        BrowserSignupPolicy::from_patterns(&["^[^@]+@example\\.test$".to_owned()])
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

    #[test]
    fn signup_policy_wildcard_allows_any_email() -> opsgate_core::Result<()> {
        let policy = BrowserSignupPolicy::from_patterns(&["*".to_owned()])?;

        assert!(policy.allows("anyone@example.test"));
        Ok(())
    }

    #[test]
    fn signup_policy_patterns_are_full_email_matches() -> opsgate_core::Result<()> {
        let policy = BrowserSignupPolicy::from_patterns(&["example\\.com".to_owned()])?;

        assert!(policy.allows("example.com"));
        assert!(!policy.allows("attacker@example.com.evil.test"));
        assert!(!policy.allows("prefix-example.com"));
        Ok(())
    }

    #[test]
    fn signup_policy_rejects_invalid_regex() {
        let err = BrowserSignupPolicy::from_patterns(&["[".to_owned()]).err();

        assert!(err.is_some());
    }

    #[test]
    fn signup_policy_rejects_empty_pattern() {
        let err = BrowserSignupPolicy::from_patterns(&[String::new()]).err();

        assert!(err.is_some());
    }

    #[tokio::test]
    async fn browser_login_upserts_authenticated_user() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        let resolver = Resolver::new(users.clone(), allow_example_signup()?);

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
        let resolver = Resolver::new(users, allow_no_signup()?);

        let err = resolver.resolve_mcp(attrs()).await.err();

        assert!(matches!(err, Some(IdentityError::Inactive)));
        Ok(())
    }

    #[tokio::test]
    async fn browser_signup_rejects_email_without_matching_pattern() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        let policy = BrowserSignupPolicy::from_patterns(&["^[^@]+@example\\.test$".to_owned()]);
        let resolver = match policy {
            Ok(policy) => Resolver::new(users, policy),
            Err(error) => return Err(error),
        };
        let attrs = ResolveAttrs {
            sub: "s2".to_owned(),
            email: "user@other.test".to_owned(),
            name: "User".to_owned(),
        };

        let err = resolver.resolve_browser(attrs).await.err();

        assert!(matches!(err, Some(IdentityError::SignupNotAllowed)));
        Ok(())
    }

    #[tokio::test]
    async fn existing_browser_user_still_uses_upsert() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users.user.lock().map_err(|_| Error::internal("poisoned"))?;
            *guard = Some(user("s1", "user@other.test", "Old Name", true));
        }
        let resolver = Resolver::new(users, allow_no_signup()?);

        let caller = resolver
            .resolve_browser(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "user@other.test".to_owned(),
                name: "New Name".to_owned(),
            })
            .await
            .map_err(|error| Error::internal(error.to_string()))?;

        assert_eq!(caller.user.display_name, "New Name");
        Ok(())
    }

    #[tokio::test]
    async fn existing_browser_user_ignores_signup_policy() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users.user.lock().map_err(|_| Error::internal("poisoned"))?;
            *guard = Some(user("s1", "user@other.test", "User", true));
        }
        let resolver = Resolver::new(users, allow_no_signup()?);

        let caller = resolver
            .resolve_browser(ResolveAttrs {
                sub: "s1".to_owned(),
                email: "user@other.test".to_owned(),
                name: "User".to_owned(),
            })
            .await
            .map_err(|error| Error::internal(error.to_string()))?;

        assert_eq!(caller.channel, Channel::Browser);
        Ok(())
    }

    #[tokio::test]
    async fn api_requires_registered_active_user() -> opsgate_core::Result<()> {
        let resolver = Resolver::new(MemoryUsers::default(), allow_no_signup()?);

        let err = resolver.resolve_api(attrs()).await.err();

        assert!(matches!(err, Some(IdentityError::NotRegistered)));
        Ok(())
    }

    #[tokio::test]
    async fn registered_user_resolves_for_api() -> opsgate_core::Result<()> {
        let users = MemoryUsers::default();
        {
            let mut guard = users.user.lock().map_err(|_| Error::internal("poisoned"))?;
            *guard = Some(user("s1", "user@example.test", "User", true));
        }
        let resolver = Resolver::new(users, allow_no_signup()?);

        let caller = resolver
            .resolve_api(attrs())
            .await
            .map_err(|error| Error::internal(error.to_string()))?;

        assert_eq!(caller.channel, Channel::Api);
        assert_eq!(caller.user.email, "user@example.test");
        Ok(())
    }
}
