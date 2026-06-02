use opsgate_model::{Caller, IdentityError, ResolveAttrs};

use crate::auth::bearer::AuthError;
use crate::identity::CallerResolver;
use crate::state::AuthState;

pub(crate) async fn verify_bearer_mcp(auth: &AuthState, token: &str) -> Result<Caller, AuthError> {
    let attrs = auth.jwt.verify(token).await?;
    resolve_mcp_caller(auth.resolver.as_ref(), attrs).await
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

fn map_identity_error(error: IdentityError) -> AuthError {
    match error {
        IdentityError::NotRegistered => AuthError::NotRegistered,
        // Browser signup policy is not part of API/MCP bearer verification.
        IdentityError::SignupNotAllowed => AuthError::Internal,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
