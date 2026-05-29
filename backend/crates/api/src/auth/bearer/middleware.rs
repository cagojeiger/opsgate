use axum::body::Body;
use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, Request};
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::bearer::{AuthError, auth_error_response, extract_bearer, verify_bearer};
use crate::state::AppState;

pub async fn require_bearer(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(request.headers()).map(str::to_owned) else {
        return auth_error_response(&state, AuthError::MissingToken);
    };
    let request_id = request_id(request.headers());
    let remote_ip = remote_ip(request.headers());
    let user_agent = user_agent(request.headers());

    let caller = match verify_bearer(&state, &token).await {
        Ok(caller) => caller.with_request_metadata(request_id, remote_ip, user_agent),
        Err(error) => return auth_error_response(&state, error),
    };

    request.extensions_mut().insert(caller);
    next.run(request).await
}

fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn remote_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
