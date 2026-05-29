pub mod error;
pub mod extractor;
pub mod middleware;
mod verify;

pub use error::{
    AuthError, auth_error_body, auth_error_response, shared_challenge_header, status_for_error,
};
pub use extractor::extract_bearer;
pub use middleware::require_bearer;
pub use verify::{RequestMeta, verify_bearer, verify_bearer_mcp};
