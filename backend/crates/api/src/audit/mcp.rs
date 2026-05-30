use std::future::Future;
use std::time::Instant;

use axum::http::request::Parts;
use opsgate_db::AuditRepo;
use opsgate_domain::{Caller, Channel};
use rmcp::{ErrorData, Json};
use serde_json::Value;

use super::actor::caller_actor;
use super::{AuditEvent, AuditOutcome, AuditTarget, append_event};

pub(crate) async fn record_tool<T, Fut>(
    audit: &AuditRepo,
    parts: &Parts,
    tool: &'static str,
    call: Fut,
) -> Result<Json<T>, ErrorData>
where
    Fut: Future<Output = Result<Json<T>, ErrorData>>,
{
    let started = Instant::now();
    let result = call.await;
    record_tool_result(audit, parts, tool, started, result.is_err()).await;
    result
}

async fn record_tool_result(
    audit: &AuditRepo,
    parts: &Parts,
    tool: &str,
    started: Instant,
    is_error: bool,
) {
    let caller = parts.extensions.get::<Caller>();
    let event = tool_event(caller, tool, started, is_error);
    append_event(audit, event, "mcp.tool.audit_failed").await;
}

pub(crate) async fn record_admin_denied(audit: &AuditRepo, caller: &Caller) {
    append_event(audit, admin_denied_event(caller), "mcp.auth.audit_failed").await;
}

pub(crate) fn admin_denied_event(caller: &Caller) -> AuditEvent {
    let detail = serde_json::json!({
        "schema_version": 1,
        "denial_reason": "required_role",
        "required_role": "admin",
        "actor_role": caller.role.as_str(),
        "sub": caller.user.sub.clone(),
    });
    AuditEvent::new("mcp.auth.denied", Channel::Mcp, AuditOutcome::Denied)
        .actor(caller_actor(caller))
        .target(AuditTarget::identity(
            Some(caller.user.id.to_string()),
            Some(caller.user.sub.clone()),
        ))
        .detail(detail)
}

fn tool_event(caller: Option<&Caller>, tool: &str, started: Instant, is_error: bool) -> AuditEvent {
    let outcome = if is_error {
        AuditOutcome::Error
    } else {
        AuditOutcome::Ok
    };
    let mut event = AuditEvent::new("mcp.tool.call", Channel::Mcp, outcome)
        .target(AuditTarget::tool(tool.to_owned()))
        .detail(tool_detail(tool, started, is_error));
    if let Some(caller) = caller {
        event = event.actor(caller_actor(caller));
    }
    event
}

fn tool_detail(tool: &str, started: Instant, is_error: bool) -> Value {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("tool".to_owned(), serde_json::json!(tool));
    detail.insert(
        "dur_ms".to_owned(),
        serde_json::json!(started.elapsed().as_millis()),
    );
    if is_error {
        detail.insert("is_error".to_owned(), serde_json::json!(true));
    }
    Value::Object(detail)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::{Channel, Role, User};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn tool_detail_does_not_record_error_message_or_inputs() {
        let detail = tool_detail("api.call", Instant::now(), true);
        let serialized = detail.to_string();
        assert!(serialized.contains("api.call"));
        assert!(serialized.contains("is_error"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("input"));
        assert!(!serialized.contains("body"));
        assert!(!serialized.contains("error_message"));
    }

    #[test]
    fn tool_event_carries_request_metadata_without_inputs() {
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
            channel: Channel::Mcp,
            role: Role::Operator,
            request_id: Some("req-tool".to_owned()),
            remote_ip: Some("203.0.113.11".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        };

        let params = tool_event(Some(&caller), "me", Instant::now(), true).into_params();

        assert_eq!(params.action, "mcp.tool.call");
        assert_eq!(params.outcome, "error");
        assert_eq!(params.request_id.as_deref(), Some("req-tool"));
        assert_eq!(params.actor_ip.as_deref(), Some("203.0.113.11"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert_eq!(params.target_key.as_deref(), Some("me"));
        let serialized = params.detail.to_string();
        assert!(serialized.contains("is_error"));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("input"));
    }
}
