pub(crate) mod error;
pub(crate) mod extractor;
pub(crate) mod middleware;
mod verify;

pub(crate) use error::{
    AuthError, auth_error_body, auth_error_response, shared_scoped_challenge_header,
    status_for_error,
};
pub(crate) use extractor::extract_bearer;
pub(crate) use middleware::require_bearer;
#[cfg(test)]
pub(crate) use verify::{resolve_api_caller, verify_token_attrs};
pub(crate) use verify::{verify_bearer, verify_bearer_mcp};
