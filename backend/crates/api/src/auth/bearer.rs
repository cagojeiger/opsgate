use opsgate_domain::{Caller, IdentityError, ResolveAttrs};

use crate::auth::bearer_error::AuthError;
use crate::state::AppState;

pub struct RequestMeta;

pub async fn verify_bearer(
    state: &AppState,
    token: &str,
    meta: RequestMeta,
) -> Result<Caller, AuthError> {
    verify_bearer_api(state, token, meta).await
}

pub async fn verify_bearer_api(
    state: &AppState,
    token: &str,
    _meta: RequestMeta,
) -> Result<Caller, AuthError> {
    let claims = state
        .jwks
        .verify(token)
        .await
        .map_err(|error| match error {
            crate::auth::jwks::JwksError::InvalidToken => AuthError::InvalidToken,
            crate::auth::jwks::JwksError::FetchFailed => AuthError::Internal,
        })?;
    state
        .resolver
        .resolve_api(attrs_from_claims(claims))
        .await
        .map_err(map_identity_error)
}

pub async fn verify_bearer_mcp(
    state: &AppState,
    token: &str,
    _meta: RequestMeta,
) -> Result<Caller, AuthError> {
    let claims = state
        .jwks
        .verify(token)
        .await
        .map_err(|error| match error {
            crate::auth::jwks::JwksError::InvalidToken => AuthError::InvalidToken,
            crate::auth::jwks::JwksError::FetchFailed => AuthError::Internal,
        })?;
    state
        .resolver
        .resolve_mcp(attrs_from_claims(claims))
        .await
        .map_err(map_identity_error)
}

fn attrs_from_claims(claims: crate::auth::jwks::Claims) -> ResolveAttrs {
    ResolveAttrs {
        sub: claims.sub,
        email: claims.email.unwrap_or_default(),
        name: claims.name.unwrap_or_default(),
    }
}

fn map_identity_error(error: IdentityError) -> AuthError {
    match error {
        IdentityError::NotRegistered => AuthError::NotRegistered,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
