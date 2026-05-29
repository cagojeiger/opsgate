use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::metadata::{challenge_header, protected_resource_metadata_url};
use crate::state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing or malformed bearer token")]
    MissingToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("user not registered")]
    NotRegistered,
    #[error("insufficient role")]
    InsufficientRole,
    #[error("user is inactive")]
    Inactive,
    #[error("upstream/internal failure")]
    Internal,
}

pub fn auth_error_body(state: &AppState, error: &AuthError) -> serde_json::Value {
    let code = code_for_error(error);
    match error {
        AuthError::NotRegistered => serde_json::json!({
            "error": code,
            "message": message_for_error(error),
            "login_url": login_url(state),
            "mcp_url": mcp_url(state),
        }),
        _ => serde_json::json!({
            "error": code,
            "message": message_for_error(error),
        }),
    }
}

pub fn auth_error_response(state: &AppState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    let code = code_for_error(&error);
    tracing::warn!(
        event = "auth.denied",
        error = code,
        status = status.as_u16()
    );
    let body = Json(auth_error_body(state, &error));
    let mut response = (status, body).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            shared_challenge_header(&state.config.resource_url),
        );
    }
    response
}

pub fn shared_challenge_header(resource_url: &str) -> HeaderValue {
    let meta = protected_resource_metadata_url(resource_url);
    challenge_header(&meta.full_url)
}

pub fn status_for_error(error: &AuthError) -> StatusCode {
    match error {
        AuthError::MissingToken | AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
        AuthError::NotRegistered | AuthError::InsufficientRole | AuthError::Inactive => {
            StatusCode::FORBIDDEN
        }
        AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn login_url(state: &AppState) -> String {
    format!("{}/login", state.config.opsgate_public_url)
}

fn mcp_url(state: &AppState) -> String {
    state.config.resource_url.clone()
}

fn code_for_error(error: &AuthError) -> &'static str {
    match error {
        AuthError::MissingToken => "missing_token",
        AuthError::InvalidToken => "invalid_token",
        AuthError::NotRegistered => "not_registered",
        AuthError::InsufficientRole => "insufficient_role",
        AuthError::Inactive => "inactive_user",
        AuthError::Internal => "internal_error",
    }
}

fn message_for_error(error: &AuthError) -> &'static str {
    match error {
        AuthError::MissingToken => "missing or malformed bearer token",
        AuthError::InvalidToken => "invalid token",
        AuthError::NotRegistered => {
            "This authgate account is authenticated but not registered in opsgate yet. Open login_url once, then reconnect your MCP client."
        }
        AuthError::InsufficientRole => "insufficient role",
        AuthError::Inactive => "inactive user",
        AuthError::Internal => "internal server error",
    }
}
