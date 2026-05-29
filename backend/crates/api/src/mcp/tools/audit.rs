use std::time::Instant;

use axum::http::request::Parts;
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
    let outcome = if result.is_ok() { "ok" } else { "error" };
    let params = opsgate_db::AuditLogParams {
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
        detail: tool_detail(tool, started, result.is_err()),
    };
    if let Err(error) = state.audit.append(params).await {
        tracing::error!(event = "mcp.tool.audit_failed", detail = %error);
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
}
