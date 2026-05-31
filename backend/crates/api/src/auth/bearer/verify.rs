use opsgate_model::{Caller, IdentityError, ResolveAttrs};

use crate::auth::bearer::AuthError;
use crate::auth::jwks::{Claims, JwksCache, JwksError};
use crate::identity::CallerResolver;
use crate::state::AuthState;

pub(crate) async fn verify_bearer_mcp(auth: &AuthState, token: &str) -> Result<Caller, AuthError> {
    let attrs = verify_token_attrs(&auth.jwks, token).await?;
    resolve_mcp_caller(auth.resolver.as_ref(), attrs).await
}

/// Verify the MCP bearer JWT against JWKS and extract identity attributes.
/// API bearer verification is intentionally separate in `auth::api`.
pub(crate) async fn verify_token_attrs(
    jwks: &JwksCache,
    token: &str,
) -> Result<ResolveAttrs, AuthError> {
    let claims = jwks.verify(token).await.map_err(map_jwks_error)?;
    Ok(attrs_from_claims(claims))
}

pub(crate) async fn resolve_mcp_caller(
    resolver: &dyn CallerResolver,
    attrs: ResolveAttrs,
) -> Result<Caller, AuthError> {
    resolver
        .resolve_mcp(attrs)
        .await
        .map_err(map_identity_error)
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
        IdentityError::NotRegistered => AuthError::NotRegistered,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
