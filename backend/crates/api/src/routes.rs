//! Router assembly and HTTP handlers.

use std::time::Duration;

use crate::config::Config;
use axum::extract::{FromRef, MatchedPath, State};
use axum::http::Request;
use axum::http::header::HeaderName;
use axum::middleware::from_fn_with_state;
use axum::routing::{any, get};
use axum::{Json, Router};
use opsgate_db::PgPool;
use serde::Serialize;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing::{Span, info, info_span};

use crate::auth::api::require_api_bearer;
use crate::auth::metadata::{
    authorization_server_metadata, protected_resource_metadata, protected_resource_metadata_url,
};
use crate::auth::oauth::{callback, login};
use crate::error::ApiError;
use crate::mcp::server::{mcp_admin_handler, mcp_handler};
use crate::state::{AppState, AuthRuntimeState};

pub fn app(state: AppState) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .merge(system_routes())
        .merge(auth_routes())
        .merge(metadata_routes(&state.config))
        .merge(openapi_routes(&state.config))
        .nest("/api", rest_api_routes(state.clone()))
        .route("/mcp", any(mcp_handler))
        .route("/mcp/admin", any(mcp_admin_handler))
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

fn openapi_routes(config: &Config) -> Router<AppState> {
    if config.openapi_enabled {
        crate::openapi::routes()
    } else {
        Router::new()
    }
}

fn system_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
}

fn metadata_routes(config: &Config) -> Router<AppState> {
    let metadata_path = protected_resource_metadata_url(&config.resource_url).route_path;
    let wildcard_path = format!("{metadata_path}/{{*path}}");
    let router = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        );

    if metadata_path == "/.well-known/oauth-protected-resource" {
        router.route(&wildcard_path, get(protected_resource_metadata))
    } else {
        router
            .route(&metadata_path, get(protected_resource_metadata))
            .route(&wildcard_path, get(protected_resource_metadata))
    }
}

fn rest_api_routes(state: AppState) -> Router<AppState> {
    let auth_state = AuthRuntimeState::from_ref(&state);
    Router::new()
        .merge(crate::rest::api_call::routes())
        .merge(crate::rest::credentials::routes())
        .merge(crate::rest::mcp_connect::routes())
        .merge(crate::rest::me::routes())
        .merge(crate::rest::observability::routes())
        .merge(crate::rest::sql_query::routes())
        .merge(crate::rest::sql_schema::routes())
        .fallback(api_not_found)
        .layer(from_fn_with_state(auth_state, require_api_bearer))
}

/// Liveness: the process is up. No dependency checks.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Readiness: verify the database is reachable before reporting ready.
async fn ready(State(db): State<PgPool>) -> Result<Json<HealthResponse>, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&db)
        .await
        .map_err(|error| {
            tracing::error!(event = "ready.db_unreachable", %error);
            ApiError::internal("database unreachable")
        })?;

    Ok(Json(HealthResponse { status: "ready" }))
}

async fn api_not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
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
