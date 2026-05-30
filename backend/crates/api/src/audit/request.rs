use std::time::Instant;

use axum::http::Method;
use opsgate_db::AuditRepo;
use opsgate_domain::{Caller, Channel};

use super::actor::caller_actor;
use super::{AuditEvent, AuditOutcome, AuditTarget, append_event};

pub(crate) async fn record_api_request(
    audit: &AuditRepo,
    caller: &Caller,
    method: &Method,
    path: &str,
    route: &str,
    status: u16,
    started: Instant,
) {
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let event = api_request_event(caller, method, path, route, status, latency_ms);
    append_event(audit, event, "api.request.audit_failed").await;
}

pub(crate) fn api_request_event(
    caller: &Caller,
    method: &Method,
    path: &str,
    route: &str,
    status: u16,
    latency_ms: u64,
) -> AuditEvent {
    let target_key = if route.is_empty() { path } else { route };
    let detail = serde_json::json!({
        "schema_version": 1,
        "method": method.as_str(),
        "route": route,
        "path": path,
        "status": status,
        "dur_ms": latency_ms,
    });
    AuditEvent::new("api.request", Channel::Api, outcome_for_status(status))
        .actor(caller_actor(caller))
        .target(AuditTarget::route(target_key))
        .detail(detail)
}

fn outcome_for_status(status: u16) -> AuditOutcome {
    match status {
        100..=399 => AuditOutcome::Ok,
        400..=499 => AuditOutcome::Denied,
        _ => AuditOutcome::Error,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use chrono::Utc;
    use opsgate_domain::{Channel, User};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn api_request_event_carries_route_and_request_metadata() {
        let now = Utc::now();
        let caller = Caller {
            user: User {
                id: Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: Channel::Api,
            request_id: Some("req-api".to_owned()),
            remote_ip: Some("203.0.113.8".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        };

        let params = api_request_event(&caller, &Method::GET, "/api/v1/me", "/api/v1/me", 200, 9)
            .into_params();

        assert_eq!(params.action, "api.request");
        assert_eq!(params.channel, "api");
        assert_eq!(params.outcome, "ok");
        assert_eq!(params.target_type.as_deref(), Some("route"));
        assert_eq!(params.target_key.as_deref(), Some("/api/v1/me"));
        assert_eq!(params.request_id.as_deref(), Some("req-api"));
        assert_eq!(params.actor_ip.as_deref(), Some("203.0.113.8"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert_eq!(params.detail.get("method"), Some(&serde_json::json!("GET")));
        assert_eq!(params.detail.get("status"), Some(&serde_json::json!(200)));
    }

    #[test]
    fn api_request_event_maps_error_status_to_outcome() {
        let now = Utc::now();
        let caller = Caller {
            user: User {
                id: Uuid::nil(),
                sub: "sub".to_owned(),
                email: "user@example.test".to_owned(),
                display_name: "User".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: Channel::Api,
            request_id: None,
            remote_ip: None,
            user_agent: None,
        };

        assert_eq!(
            api_request_event(&caller, &Method::GET, "/x", "/x", 403, 1)
                .into_params()
                .outcome,
            "denied"
        );
        assert_eq!(
            api_request_event(&caller, &Method::GET, "/x", "/x", 500, 1)
                .into_params()
                .outcome,
            "error"
        );
    }
}
