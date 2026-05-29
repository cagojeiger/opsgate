//! rmcp 1.7.0 A1 adapter decision:
//! - Streamable HTTP server is `rmcp::transport::streamable_http_server::StreamableHttpService`.
//! - Axum integration is via the tower `Service`/`handle` API; this module wraps it in an axum
//!   handler so Bearer verification can run before rmcp consumes the body.
//! - rmcp injects raw `http::request::Parts` into each request's MCP extensions. We insert the
//!   verified domain `Caller` into the HTTP parts' `extensions` before calling rmcp; the `me` tool
//!   reads that request-scoped `Caller` through `Extension<Parts>`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ServerHandler, tool_handler, tool_router};

use crate::auth::bearer::{AuthError, auth_error_body, extract_bearer, request_meta_from_parts, shared_challenge_header, status_for_error, verify_bearer_mcp};
use crate::state::AppState;

#[allow(dead_code)]
#[derive(Clone)]
pub struct McpServer {
    pub state: AppState,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpServer {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(Implementation::new("opsgate", env!("CARGO_PKG_VERSION")).with_title("opsgate"))
            .with_instructions("Identity tools for opsgate.")
    }
}

pub async fn mcp_handler(State(state): State<AppState>, mut request: Request<Body>) -> Response {
    let (mut parts, body) = request.into_parts();
    let Some(token) = extract_bearer(&parts.headers).map(str::to_owned) else {
        return mcp_auth_response(&state, AuthError::MissingToken);
    };
    let meta = request_meta_from_parts(&parts);
    let caller = match verify_bearer_mcp(&state, &token, meta).await {
        Ok(caller) => caller,
        Err(error) => return mcp_auth_response(&state, error),
    };
    parts.extensions.insert(caller);
    request = Request::from_parts(parts, body);

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts();
    let manager = Arc::new(NeverSessionManager::default());
    let service = StreamableHttpService::new(
        {
            let state = state.clone();
            move || Ok(McpServer::new(state.clone()))
        },
        manager,
        config,
    );
    let response = service.handle(request).await;
    response.map(Body::new).into_response()
}

fn mcp_auth_response(state: &AppState, error: AuthError) -> Response {
    let status = status_for_error(&error);
    tracing::warn!(event = "mcp.auth.denied", error = %error, status = status.as_u16());
    let mut response = (
        status,
        axum::Json(auth_error_body(state, &error)),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            shared_challenge_header(&state.config.resource_url),
        );
    }
    response
}
