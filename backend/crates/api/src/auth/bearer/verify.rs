use opsgate_domain::{Caller, IdentityError, ResolveAttrs};

use crate::auth::bearer::AuthError;
use crate::auth::jwks::{Claims, JwksError};
use crate::state::AppState;

pub async fn verify_bearer(state: &AppState, token: &str) -> Result<Caller, AuthError> {
    let attrs = authenticate(state, token).await?;
    state
        .resolver
        .resolve_api(attrs)
        .await
        .map_err(map_identity_error)
}

pub async fn verify_bearer_mcp(state: &AppState, token: &str) -> Result<Caller, AuthError> {
    let attrs = authenticate(state, token).await?;
    state
        .resolver
        .resolve_mcp(attrs)
        .await
        .map_err(map_identity_error)
}

/// Verify the bearer JWT against JWKS and extract identity attributes.
/// Shared by the REST and MCP paths, which differ only in how they resolve
/// the verified attributes into a `Caller`.
async fn authenticate(state: &AppState, token: &str) -> Result<ResolveAttrs, AuthError> {
    let claims = state.jwks.verify(token).await.map_err(map_jwks_error)?;
    Ok(attrs_from_claims(claims))
}

fn map_jwks_error(error: JwksError) -> AuthError {
    match error {
        JwksError::InvalidToken => AuthError::InvalidToken,
        JwksError::FetchFailed => AuthError::Internal,
    }
}

fn attrs_from_claims(claims: Claims) -> ResolveAttrs {
    ResolveAttrs {
        sub: claims.sub,
        email: claims.email.unwrap_or_default(),
        name: claims.name.unwrap_or_default(),
    }
}

fn map_identity_error(error: IdentityError) -> AuthError {
    match error {
        IdentityError::NotAdmin => AuthError::InsufficientRole,
        IdentityError::NotRegistered => AuthError::NotRegistered,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
