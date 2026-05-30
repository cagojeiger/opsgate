use std::time::Instant;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use opsgate_domain::Channel;

use crate::auth::bearer::{AuthError, auth_error_response, extract_bearer, verify_bearer};
use crate::request_context::RequestMetadata;
use crate::state::AppState;

pub async fn require_bearer(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let metadata = RequestMetadata::from_headers(request.headers());
    let Some(token) = extract_bearer(request.headers()).map(str::to_owned) else {
        return auth_error_response(&state, AuthError::MissingToken);
    };

    let caller = match verify_bearer(&state, &token).await {
        Ok(caller) => caller.with_request_metadata(
            metadata.request_id.clone(),
            metadata.remote_ip.clone(),
            metadata.user_agent.clone(),
        ),
        Err(error) => {
            crate::audit::auth::record_auth_denied(&state.audit, Channel::Api, &metadata, &error)
                .await;
            return auth_error_response(&state, error);
        }
    };

    let method = request.method().clone();
    let uri = request.uri().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("")
        .to_owned();
    let started = Instant::now();
    let audit_caller = caller.clone();
    request.extensions_mut().insert(caller);
    let response = next.run(request).await;
    let status = response.status().as_u16();
    crate::audit::request::record_api_request(
        &state.audit,
        &audit_caller,
        &method,
        uri.path(),
        &route,
        status,
        started,
    )
    .await;
    response
}
