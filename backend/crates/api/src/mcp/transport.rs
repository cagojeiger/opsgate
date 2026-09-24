//! rmcp 1.7.0 A1 adapter decision:
//! - Streamable HTTP server is `rmcp::transport::streamable_http_server::StreamableHttpService`.
//! - Axum integration is via the tower `Service`/`handle` API; this module wraps it in an axum
//!   handler so Bearer verification can run before rmcp consumes the body.
//! - rmcp injects raw `http::request::Parts` into each request's MCP extensions. We insert the
//!   verified domain `Caller` into the HTTP parts' `extensions` before calling rmcp; tools read
//!   that request-scoped `Caller` through `Extension<Parts>`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRef, State};
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::auth::bearer::{
    AuthError, auth_error_body, extract_bearer, shared_scoped_challenge_header, status_for_error,
};
use crate::auth::mcp::verify_bearer_mcp;
use crate::request_context::RequestMetadata;
use crate::state::{AppState, AuthRuntimeState};

use super::server::{AdminMcpServer, RuntimeMcpServer};

pub(crate) async fn mcp_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    let auth_state = AuthRuntimeState::from_ref(&state);
    let request = match verify_mcp_request(&auth_state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&auth_state, error),
    };
    let config = streamable_config();
    let manager = Arc::new(NeverSessionManager::default());
    let service_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(RuntimeMcpServer::new(service_state.clone())),
        manager,
        config,
    );
    let response = service.handle(request).await;
    response.map(Body::new).into_response()
}

pub(crate) async fn mcp_admin_handler(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let auth_state = AuthRuntimeState::from_ref(&state);
    let request = match verify_mcp_request(&auth_state, request).await {
        Ok(request) => request,
        Err(error) => return mcp_auth_response(&auth_state, error),
    };
    let config = streamable_config();
    let manager = Arc::new(NeverSessionManager::default());
    let service_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(AdminMcpServer::new(service_state.clone())),
        manager,
        config,
    );
    let response = service.handle(request).await;
    response.map(Body::new).into_response()
}

async fn verify_mcp_request(
    state: &AuthRuntimeState,
    request: Request<Body>,
) -> Result<Request<Body>, AuthError> {
    let (mut parts, body) = request.into_parts();
    let Some(token) = extract_bearer(&parts.headers).map(str::to_owned) else {
        return Err(AuthError::MissingToken);
    };
    let metadata = RequestMetadata::from_headers(&parts.headers);
    let caller = match verify_bearer_mcp(&state.auth, &token).await {
        Ok(caller) => caller.with_request_metadata(
            metadata.request_id.clone(),
            metadata.remote_ip.clone(),
            metadata.user_agent.clone(),
        ),
        Err(error) => {
            crate::audit::auth::record_auth_denied(
                &state.audit,
                opsgate_model::Channel::Mcp,
                &metadata,
                &error,
            )
            .await;
            return Err(error);
        }
    };
    parts.extensions.insert(caller);
    Ok(Request::from_parts(parts, body))
}

fn streamable_config() -> StreamableHttpServerConfig {
    StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts()
}

fn mcp_auth_response(state: &AuthRuntimeState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    mcp_auth_response_with_status(state, error, status)
}

fn mcp_auth_response_with_status(
    state: &AuthRuntimeState,
    error: AuthError,
    status: StatusCode,
) -> Response {
    tracing::warn!(event = "mcp.auth.denied", error = %error, status = status.as_u16());
    let mut response = (status, axum::Json(auth_error_body(&state.config, &error))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            shared_scoped_challenge_header(&state.config.resource_url),
        );
    }
    response
}
