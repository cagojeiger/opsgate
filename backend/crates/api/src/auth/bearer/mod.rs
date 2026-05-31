pub(crate) mod error;
pub(crate) mod extractor;
pub(crate) mod verify;

#[cfg(test)]
pub(crate) use crate::auth::api::resolve_api_caller;
pub(crate) use error::{
    AuthError, auth_error_body, auth_error_response, shared_scoped_challenge_header,
    status_for_error,
};
pub(crate) use extractor::extract_bearer;
pub(crate) use verify::verify_bearer_mcp;
