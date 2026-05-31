use std::sync::Arc;
use std::time::{Duration, Instant};

use aliri::jwt::{Audiences, BasicClaims, CoreClaims, IssuerRef, SubjectRef};
use aliri::{Jwt, jwa, jwt};
use aliri_oauth2::{Authority, AuthorityError, HasScope, Scope, ScopePolicy};
use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use opsgate_model::{Caller, IdentityError, ResolveAttrs};
use serde::Deserialize;

use crate::auth::bearer::{AuthError, auth_error_response, extract_bearer};
use crate::config::Config;
use crate::identity::CallerResolver;
use crate::request_context::RequestMetadata;
use crate::state::AuthRuntimeState;

#[derive(Clone)]
pub(crate) struct ApiAuthority {
    inner: Arc<ApiAuthorityInner>,
}

struct ApiAuthorityInner {
    jwks_url: Option<String>,
    validator: jwt::CoreValidator,
    refresh_interval: Duration,
    authority: tokio::sync::OnceCell<Authority>,
}

impl ApiAuthority {
    fn lazy(config: &Config, jwks_url: String) -> Self {
        Self {
            inner: Arc::new(ApiAuthorityInner {
                jwks_url: Some(jwks_url),
                validator: api_jwt_validator(config),
                refresh_interval: config.jwks_cache_ttl,
                authority: tokio::sync::OnceCell::new(),
            }),
        }
    }

    #[cfg(test)]
    fn ready(config: &Config, jwks: aliri::Jwks) -> Self {
        let authority = Authority::new(jwks, api_jwt_validator(config));
        let cell = tokio::sync::OnceCell::new();
        let _inserted = cell.set(authority);
        Self {
            inner: Arc::new(ApiAuthorityInner {
                jwks_url: None,
                validator: api_jwt_validator(config),
                refresh_interval: config.jwks_cache_ttl,
                authority: cell,
            }),
        }
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
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ApiClaims {
    #[serde(flatten)]
    basic: BasicClaims,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    scope: Scope,
}

impl CoreClaims for ApiClaims {
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

impl HasScope for ApiClaims {
    fn scope(&self) -> &Scope {
        &self.scope
    }
}

pub(crate) fn api_authority_from_url(config: &Config, jwks_url: String) -> ApiAuthority {
    ApiAuthority::lazy(config, jwks_url)
}

#[cfg(test)]
pub(crate) fn api_authority_from_jwks(config: &Config, jwks: aliri::Jwks) -> ApiAuthority {
    ApiAuthority::ready(config, jwks)
}

pub(crate) fn api_jwt_validator(config: &Config) -> jwt::CoreValidator {
    let resource = config.resource_url.trim_end_matches('/');
    jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::RS256)
        .add_allowed_audience(jwt::Audience::new(resource.to_owned()))
        .add_allowed_audience(jwt::Audience::new(format!("{resource}/")))
        .require_issuer(jwt::Issuer::new(config.authgate_url.clone()))
}

pub async fn require_api_bearer(
    State(state): State<AuthRuntimeState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let metadata = RequestMetadata::from_headers(request.headers());
    let Some(token) = extract_bearer(request.headers()).map(str::to_owned) else {
        return auth_error_response(&state.config, AuthError::MissingToken);
    };

    let caller = match verify_api_bearer(
        &state.auth.api_authority,
        state.auth.resolver.as_ref(),
        &token,
    )
    .await
    {
        Ok(caller) => caller.with_request_metadata(
            metadata.request_id.clone(),
            metadata.remote_ip.clone(),
            metadata.user_agent.clone(),
        ),
        Err(error) => {
            crate::audit::auth::record_auth_denied(
                &state.audit,
                opsgate_model::Channel::Api,
                &metadata,
                &error,
            )
            .await;
            return auth_error_response(&state.config, error);
        }
    };

    let method = request.method().clone();
    let uri = request.uri().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("")
        .to_owned();
    let started = Instant::now();
    let audit_caller = caller.clone();
    request.extensions_mut().insert(caller);
    let response = next.run(request).await;
    let status = response.status().as_u16();
    crate::audit::request::record_api_request(
        &state.audit,
        &audit_caller,
        &method,
        uri.path(),
        &route,
        status,
        started,
    )
    .await;
    response
}

pub(crate) async fn verify_api_bearer(
    authority: &ApiAuthority,
    resolver: &dyn CallerResolver,
    token: &str,
) -> Result<Caller, AuthError> {
    let claims = verify_api_claims(authority, token).await?;
    resolve_api_caller(resolver, attrs_from_claims(claims)?).await
}

pub(crate) async fn resolve_api_caller(
    resolver: &dyn CallerResolver,
    attrs: ResolveAttrs,
) -> Result<Caller, AuthError> {
    resolver
        .resolve_api(attrs)
        .await
        .map_err(map_identity_error)
}

async fn verify_api_claims(authority: &ApiAuthority, token: &str) -> Result<ApiClaims, AuthError> {
    let authority = authority.authority().await?;
    let jwt = Jwt::from(token.trim());
    match authority.verify_token::<ApiClaims>(&jwt, &ScopePolicy::allow_any()) {
        Ok(claims) => Ok(claims),
        Err(AuthorityError::UnknownKeyId) => {
            authority
                .refresh()
                .await
                .map_err(|_error| AuthError::InvalidToken)?;
            authority
                .verify_token::<ApiClaims>(&jwt, &ScopePolicy::allow_any())
                .map_err(map_authority_error)
        }
        Err(error) => Err(map_authority_error(error)),
    }
}

fn attrs_from_claims(claims: ApiClaims) -> Result<ResolveAttrs, AuthError> {
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

fn map_identity_error(error: IdentityError) -> AuthError {
    match error {
        IdentityError::NotRegistered => AuthError::NotRegistered,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
