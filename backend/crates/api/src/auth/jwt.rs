use std::sync::Arc;
use std::time::Duration;

use aliri::jwt::{Audiences, BasicClaims, CoreClaims, IssuerRef, SubjectRef};
use aliri::{Jwt, jwa, jwt};
use aliri_oauth2::{Authority, AuthorityError, HasScope, Scope, ScopePolicy};
use opsgate_model::ResolveAttrs;
use serde::Deserialize;

use crate::auth::bearer::AuthError;
use crate::config::Config;

#[derive(Clone)]
pub(crate) struct JwtAuthority {
    inner: Arc<JwtAuthorityInner>,
}

struct JwtAuthorityInner {
    jwks_url: Option<String>,
    validator: jwt::CoreValidator,
    refresh_interval: Duration,
    authority: tokio::sync::OnceCell<Authority>,
}

impl JwtAuthority {
    pub(crate) fn from_url(config: &Config, jwks_url: String) -> Self {
        Self {
            inner: Arc::new(JwtAuthorityInner {
                jwks_url: Some(jwks_url),
                validator: jwt_validator(config),
                refresh_interval: config.jwks_cache_ttl,
                authority: tokio::sync::OnceCell::new(),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_jwks(config: &Config, jwks: aliri::Jwks) -> Self {
        let authority = Authority::new(jwks, jwt_validator(config));
        let cell = tokio::sync::OnceCell::new();
        let _inserted = cell.set(authority);
        Self {
            inner: Arc::new(JwtAuthorityInner {
                jwks_url: None,
                validator: jwt_validator(config),
                refresh_interval: config.jwks_cache_ttl,
                authority: cell,
            }),
        }
    }

    pub(crate) async fn verify(&self, token: &str) -> Result<ResolveAttrs, AuthError> {
        let claims = self.verify_claims(token).await?;
        attrs_from_claims(claims)
    }

    async fn authority(&self) -> Result<&Authority, AuthError> {
        self.inner
            .authority
            .get_or_try_init(|| async {
                let jwks_url = self.inner.jwks_url.clone().ok_or(AuthError::Internal)?;
                let authority = Authority::new_from_url(jwks_url, self.inner.validator.clone())
                    .await
                    .map_err(|_error| AuthError::Internal)?;
                authority.spawn_refresh(self.inner.refresh_interval);
                Ok(authority)
            })
            .await
    }

    async fn verify_claims(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let authority = self.authority().await?;
        let jwt = Jwt::from(token.trim());
        match authority.verify_token::<JwtClaims>(&jwt, &ScopePolicy::allow_any()) {
            Ok(claims) => Ok(claims),
            Err(AuthorityError::UnknownKeyId) => {
                authority
                    .refresh()
                    .await
                    .map_err(|_error| AuthError::InvalidToken)?;
                authority
                    .verify_token::<JwtClaims>(&jwt, &ScopePolicy::allow_any())
                    .map_err(map_authority_error)
            }
            Err(error) => Err(map_authority_error(error)),
        }
    }
}

fn jwt_validator(config: &Config) -> jwt::CoreValidator {
    let resource = config.resource_url.trim_end_matches('/');
    jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::RS256)
        .add_allowed_audience(jwt::Audience::new(resource.to_owned()))
        .add_allowed_audience(jwt::Audience::new(format!("{resource}/")))
        .require_issuer(jwt::Issuer::new(config.authgate_url.clone()))
}

#[derive(Clone, Debug, Deserialize)]
struct JwtClaims {
    #[serde(flatten)]
    basic: BasicClaims,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    scope: Scope,
}

impl CoreClaims for JwtClaims {
    fn nbf(&self) -> Option<aliri_clock::UnixTime> {
        self.basic.nbf()
    }

    fn exp(&self) -> Option<aliri_clock::UnixTime> {
        self.basic.exp()
    }

    fn aud(&self) -> &Audiences {
        self.basic.aud()
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.basic.iss()
    }

    fn sub(&self) -> Option<&SubjectRef> {
        self.basic.sub()
    }
}

impl HasScope for JwtClaims {
    fn scope(&self) -> &Scope {
        &self.scope
    }
}

fn attrs_from_claims(claims: JwtClaims) -> Result<ResolveAttrs, AuthError> {
    let sub = claims
        .sub()
        .ok_or(AuthError::InvalidToken)?
        .as_str()
        .to_owned();
    Ok(ResolveAttrs {
        sub,
        email: claims.email.unwrap_or_default(),
        name: claims.name.unwrap_or_default(),
    })
}

fn map_authority_error(error: AuthorityError) -> AuthError {
    match error {
        AuthorityError::UnknownKeyId | AuthorityError::JwtVerifyError(_) => AuthError::InvalidToken,
        AuthorityError::PolicyDenial(_error) => AuthError::InvalidToken,
    }
}
