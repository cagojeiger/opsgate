//! Router assembly and HTTP handlers.

use std::time::Duration;

use crate::config::Config;
use crate::request_context::RequestMetadata;
use axum::extract::{FromRef, MatchedPath, State};
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_LENGTH, HeaderName};
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

const SERVICE_NAME: &str = "opsgate-api";
const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn app(state: AppState) -> Router {
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .merge(system_routes())
        .merge(auth_routes())
        .merge(metadata_routes(&state.config))
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
        .merge(crate::rest::me::routes())
        .merge(crate::rest::sql_query::routes())
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

fn log_request_end<B>(response: &axum::http::Response<B>, latency: Duration, span: &Span) {
    let status = response.status();
    if successful_probe(span, status) {
        return;
    }
    info!(
        log = "access",
        event = "request.end",
        schema_version = 1_u8,
        service = SERVICE_NAME,
        version = SERVICE_VERSION,
        status = status.as_u16(),
        duration_ms = latency.as_millis() as u64,
        bytes_out = response_content_length(response),
    );
}

fn response_content_length<B>(response: &axum::http::Response<B>) -> Option<u64> {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn successful_probe(span: &Span, status: StatusCode) -> bool {
    if !status.is_success() {
        return false;
    }
    span.metadata()
        .map(|metadata| metadata.name() == "health-check")
        .unwrap_or(false)
}

fn make_request_span<B>(req: &Request<B>) -> Span {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("");
    let metadata = RequestMetadata::from_headers(req.headers());
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let request_path = req.uri().path();
    let remote_ip = metadata.remote_ip.as_deref().unwrap_or("");
    let user_agent = metadata.user_agent.as_deref().unwrap_or("");
    if matches!(request_path, "/health" | "/ready") {
        info_span!(
            "health-check",
            method = %req.method(),
            route,
            path = request_path,
            request_id,
            remote_ip,
            user_agent,
        )
    } else {
        info_span!(
            "request",
            method = %req.method(),
            route,
            path = request_path,
            request_id,
            remote_ip,
            user_agent,
        )
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[cfg(test)]
mod tests {
    use axum::http::Response;
    use axum::http::StatusCode;
    use tracing::info_span;

    use super::{response_content_length, successful_probe};

    #[test]
    fn successful_probe_suppresses_only_successful_health_spans() {
        let probe = info_span!("health-check");
        assert!(successful_probe(&probe, StatusCode::OK));
        assert!(!successful_probe(&probe, StatusCode::INTERNAL_SERVER_ERROR));

        let request = info_span!("request");
        assert!(!successful_probe(&request, StatusCode::OK));
    }

    #[test]
    fn response_content_length_reads_valid_header() -> Result<(), Box<dyn std::error::Error>> {
        let response = Response::builder()
            .header("content-length", "42")
            .body(())?;

        assert_eq!(response_content_length(&response), Some(42));
        Ok(())
    }

    #[test]
    fn response_content_length_ignores_invalid_header() -> Result<(), Box<dyn std::error::Error>> {
        let response = Response::builder()
            .header("content-length", "not-a-number")
            .body(())?;

        assert_eq!(response_content_length(&response), None);
        Ok(())
    }
}
