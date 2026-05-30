use opsgate_domain::Caller;
use serde_json::Value;

use super::actor::caller_actor;
use super::event::channel_str;
use super::{AuditEvent, AuditOutcome, AuditTarget};

pub(crate) fn tool_event(
    caller: &Caller,
    tool: &'static str,
    outcome: &str,
    credential_id: Option<String>,
    credential_alias: String,
    purpose: Option<String>,
    detail: Value,
) -> AuditEvent {
    let channel = caller.channel;
    let mut event = AuditEvent::new(
        format!("{}.{}", channel_str(channel), tool),
        channel,
        AuditOutcome::from_str(outcome),
    )
    .actor(caller_actor(caller))
    .target(AuditTarget::credential(credential_id, credential_alias))
    .detail(detail);
    if let Some(purpose) = purpose {
        event = event.purpose(purpose);
    }
    event
}

pub(crate) fn pre_input_denial_event(
    caller: &Caller,
    tool: &'static str,
    alias: &str,
    reason: &str,
    extra_detail: Option<(&'static str, Value)>,
) -> AuditEvent {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("denial_reason".to_owned(), serde_json::json!(reason));
    if let Some((key, value)) = extra_detail {
        detail.insert(key.to_owned(), value);
    }
    tool_event(
        caller,
        tool,
        "denied",
        None,
        alias.to_owned(),
        None,
        Value::Object(detail),
    )
}
