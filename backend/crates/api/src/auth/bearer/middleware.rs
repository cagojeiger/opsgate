use std::time::Instant;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::extract::State;
use axum::http::{Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use opsgate_db::{AuditLogParams, AuditRepo};
use opsgate_domain::Caller;

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
            crate::auth::audit::record_auth_denied(&state.audit, "api", &metadata, &error).await;
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
    record_api_request(
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

async fn record_api_request(
    audit: &AuditRepo,
    caller: &Caller,
    method: &Method,
    path: &str,
    route: &str,
    status: u16,
    started: Instant,
) {
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Err(error) = audit
        .append(api_request_audit_params(
            caller, method, path, route, status, latency_ms,
        ))
        .await
    {
        tracing::error!(event = "api.request.audit_failed", detail = %error);
    }
}

fn api_request_audit_params(
    caller: &Caller,
    method: &Method,
    path: &str,
    route: &str,
    status: u16,
    latency_ms: u64,
) -> AuditLogParams {
    let target_key = if route.is_empty() { path } else { route };
    let detail = serde_json::json!({
        "schema_version": 1,
        "method": method.as_str(),
        "route": route,
        "path": path,
        "status": status,
        "dur_ms": latency_ms,
    });
    AuditLogParams {
        action: "api.request".to_owned(),
        channel: "api".to_owned(),
        outcome: "ok".to_owned(),
        severity: "info".to_owned(),
        actor_user_id: Some(caller.user.id),
        actor_role: Some(caller.role.as_str().to_owned()),
        actor_ip: caller.remote_ip.clone(),
        actor_user_agent: caller.user_agent.clone(),
        target_type: Some("route".to_owned()),
        target_id: None,
        target_key: Some(target_key.to_owned()),
        request_id: caller.request_id.clone(),
        purpose: None,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use chrono::Utc;
    use opsgate_domain::{Channel, Role, User};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn api_request_audit_params_carries_route_and_request_metadata() {
        let now = Utc::now();
        let caller = Caller {
            user: User {
                id: Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                role: Role::Operator,
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: Channel::Api,
            role: Role::Operator,
            request_id: Some("req-api".to_owned()),
            remote_ip: Some("203.0.113.8".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        };

        let params =
            api_request_audit_params(&caller, &Method::GET, "/api/v1/me", "/api/v1/me", 200, 9);

        assert_eq!(params.action, "api.request");
        assert_eq!(params.channel, "api");
        assert_eq!(params.target_type.as_deref(), Some("route"));
        assert_eq!(params.target_key.as_deref(), Some("/api/v1/me"));
        assert_eq!(params.request_id.as_deref(), Some("req-api"));
        assert_eq!(params.actor_ip.as_deref(), Some("203.0.113.8"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert_eq!(params.detail.get("method"), Some(&serde_json::json!("GET")));
        assert_eq!(params.detail.get("status"), Some(&serde_json::json!(200)));
    }
}
