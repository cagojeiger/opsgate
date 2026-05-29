//! Router assembly and HTTP handlers.

use std::time::Duration;

use axum::extract::{MatchedPath, State};
use axum::http::Request;
use axum::http::header::HeaderName;
use axum::routing::{any, get};
use axum::{Json, Router};
use serde::Serialize;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing::{Span, info, info_span};

use crate::auth::metadata::{protected_resource_metadata, protected_resource_metadata_url};
use crate::auth::oauth::{callback, login};
use crate::error::ApiError;
use crate::mcp::server::mcp_handler;
use crate::me::me;
use crate::state::AppState;

pub fn app(state: AppState) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");
    let metadata_path = protected_resource_metadata_url(&state.config.resource_url).route_path;

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/api/v1/me", get(me))
        .route("/mcp", any(mcp_handler))
        .route(&metadata_path, get(protected_resource_metadata))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(
                    x_request_id.clone(),
                    MakeRequestUuid,
                ))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(make_request_span)
                        .on_response(log_request_end),
                )
                .layer(PropagateRequestIdLayer::new(x_request_id)),
        )
}

/// Liveness: the process is up. No dependency checks.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Readiness: verify the database is reachable before reporting ready.
async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|error| {
            tracing::error!(event = "ready.db_unreachable", %error);
            ApiError::internal("database unreachable")
        })?;

    Ok(Json(HealthResponse { status: "ready" }))
}

fn log_request_end<B>(response: &axum::http::Response<B>, latency: Duration, _span: &Span) {
    info!(
        event = "request.end",
        status = response.status().as_u16(),
        latency_ms = latency.as_millis() as u64,
    );
}

fn make_request_span<B>(req: &Request<B>) -> Span {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("");
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    info_span!(
        "request",
        method = %req.method(),
        route,
        request_id,
    )
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}
