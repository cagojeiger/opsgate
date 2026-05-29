use std::time::Instant;

use axum::http::request::Parts;
use opsgate_db::AuditLogParams;
use opsgate_domain::Caller;
use rmcp::{ErrorData, Json};
use serde_json::Value;

use crate::state::AppState;

pub async fn record_tool_result<T>(
    state: &AppState,
    parts: &Parts,
    tool: &str,
    started: Instant,
    result: &Result<Json<T>, ErrorData>,
) {
    let caller = parts.extensions.get::<Caller>();
    let params = tool_audit_params(caller, tool, started, result.is_err());
    if let Err(error) = state.audit.append(params).await {
        tracing::error!(event = "mcp.tool.audit_failed", detail = %error);
    }
}

fn tool_audit_params(
    caller: Option<&Caller>,
    tool: &str,
    started: Instant,
    is_error: bool,
) -> AuditLogParams {
    let outcome = if is_error { "error" } else { "ok" };
    AuditLogParams {
        action: "mcp.tool.call".to_owned(),
        channel: "mcp".to_owned(),
        outcome: outcome.to_owned(),
        severity: severity_for_outcome(outcome).to_owned(),
        actor_user_id: caller.map(|caller| caller.user.id),
        actor_role: caller.map(|caller| caller.role.as_str().to_owned()),
        actor_ip: caller.and_then(|caller| caller.remote_ip.clone()),
        actor_user_agent: caller.and_then(|caller| caller.user_agent.clone()),
        target_type: Some("tool".to_owned()),
        target_id: None,
        target_key: Some(tool.to_owned()),
        request_id: caller.and_then(|caller| caller.request_id.clone()),
        purpose: None,
        detail: tool_detail(tool, started, is_error),
    }
}

fn severity_for_outcome(outcome: &str) -> &'static str {
    if outcome == "ok" { "info" } else { "warning" }
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
    fn tool_audit_params_carry_request_metadata_without_inputs() {
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

        let params = tool_audit_params(Some(&caller), "me", Instant::now(), true);

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
