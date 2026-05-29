use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
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

    let caller = match verify_bearer(&state, &token).await {
        Ok(caller) => caller,
        Err(error) => return auth_error_response(&state, error),
    };

    request.extensions_mut().insert(caller);
    next.run(request).await
}
